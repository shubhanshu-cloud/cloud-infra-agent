"""guardrail.py — the deterministic gate between "the agent wrote something" and "a human
is asked to approve it". No LLM anywhere in this file.

WHY it exists (agentic-AI concept: guardrails / the agent does not grade its own work):
    The agent is an LLM. It can skip a tag, misread a region, or say "validated!" when it
    wasn't. So this node trusts NOTHING the agent said. It takes only the HCL text and
    re-derives every fact itself, from the same policies.yaml the agent was steered by:

      1. terraform validate      -> run_validate   (is it well-formed?)
      2. static policy checks    -> python-hcl2    (region, tags, encryption, network, IAM)
      3. security scanners       -> run_scan       (Checkov + Trivy)
      4. cost estimate           -> run_estimate   (Infracost, INR, vs the ceiling)

    Then it makes ONE decision, and a plain function routes on it (a conditional edge with
    three exits):

        approve -> approval_gate      everything passed
        retry   -> agent              failed, agent can fix it, retries left: it is sent
                                      the exact violations as feedback
        drop    -> audit_log          failed and cannot/should not be retried

FAIL CLOSED: a scanner that crashed or an estimate that is unavailable is a failure,
not a pass. Those are NOT retryable, because the agent can't fix a broken scanner.

KNOWN LIMITS:
  - Static checks read the HCL text. Values coming from variables WITHOUT defaults cannot
    be resolved. That is why every variable must have a default (from the request or the
    organisation defaults), and why an unresolvable Environment is a violation.
  - The IAM wildcard check is a coarse text match on the policy document.
  - 80/443 open to the internet is allowed on any security group; we can't tell which
    ones front a load balancer.
"""

import re
from datetime import datetime, timezone

import yaml
from langchain_core.messages import HumanMessage

from cloud_infra_agent.cost_tools import run_estimate
from cloud_infra_agent.loader import DEFAULT_KB_DIR
from cloud_infra_agent.scan_tools import run_scan
from cloud_infra_agent.state import AgentState, AuditEvent, GuardrailVerdict
from cloud_infra_agent.terraform_tools import run_validate

MAX_RETRIES = 3  # the manual loop guard from the architecture: retry_count is capped here
MAX_SCAN_LINES = 10

# Resource types that accept tags. Anything not listed here is not tag-checked.
TAGGABLE_TYPES = {
    "aws_s3_bucket", "aws_instance", "aws_db_instance", "aws_vpc", "aws_subnet",
    "aws_security_group", "aws_iam_role", "aws_ebs_volume", "aws_internet_gateway",
    "aws_nat_gateway", "aws_eip", "aws_route_table",
}
PUBLIC_ACLS = {"public-read", "public-read-write"}
IAM_POLICY_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}


# ----------------------------------------------------------------------------------------
# Small helpers. python-hcl2 returns expressions as strings like "${var.region}" and
# nested blocks as lists of dicts, so everything is normalised through these.
# ----------------------------------------------------------------------------------------
def _clean(v):
    """'"dev"' -> dev,  '${var.region}' -> var.region,  anything else unchanged."""
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("${") and s.endswith("}") and s.count("${") == 1:
            s = s[2:-1].strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1]
        return s
    return v


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _flat(v) -> list:
    out = []
    for item in _as_list(v):
        out += _flat(item) if isinstance(item, list) else [_clean(item)]
    return out


def _truthy(v) -> bool:
    v = _clean(v)
    return v is True or (isinstance(v, str) and v.lower() == "true")


def _to_int(v):
    try:
        return int(_clean(v))
    except (TypeError, ValueError):
        return None


def _resolve(v, variables: dict):
    """Follow `var.name` to that variable's default. Returns None if it has no default."""
    v = _clean(v)
    if isinstance(v, str):
        m = re.fullmatch(r"var\.(\w+)", v)
        if m:
            return _clean(variables.get(m.group(1)))
    return v


def _ref_name(value, rtype: str):
    """'aws_s3_bucket.this.id' -> 'this' (if it points at that resource type)."""
    m = re.fullmatch(rf"{rtype}\.(\w+)\.(?:id|bucket|arn)", str(_clean(value)))
    return m.group(1) if m else None


def _labeled(parsed: dict, section: str, labels: int) -> list:
    """Flatten hcl2's [{type: {name: body}}] shape into (type, name, body) tuples
    (or (name, body) for sections with one label, like variable and provider)."""
    out = []
    for item in _as_list(parsed.get(section)):
        for l1, inner in item.items():
            if str(l1).startswith("__"):
                continue
            if labels == 1:
                out.append((_clean(l1), inner))
            else:
                out += [(_clean(l1), _clean(l2), body) for l2, body in inner.items() if not str(l2).startswith("__")]
    return out


def load_policy() -> dict:
    return yaml.safe_load((DEFAULT_KB_DIR / "policies.yaml").read_text())


class ParseFailure(Exception):
    """python-hcl2 could not read the HCL."""


def parse_hcl(hcl: str) -> dict:
    import io

    import hcl2

    try:
        return hcl2.load(io.StringIO(hcl))
    except Exception as e:  # the library raises several different types
        raise ParseFailure(str(e)[:300]) from e


# ----------------------------------------------------------------------------------------
# Static policy checks: pure functions over the parsed HCL, no network, no tools.
# ----------------------------------------------------------------------------------------
def check_parsed(parsed: dict, policy: dict) -> tuple[list[str], list[str]]:
    """Return (violations, warnings)."""
    violations: list[str] = []
    warnings: list[str] = []

    variables = {}
    for name, body in _labeled(parsed, "variable", 1):
        if isinstance(body, dict) and "default" in body:
            variables[name] = body["default"]
    providers = [b for n, b in _labeled(parsed, "provider", 1) if n == "aws" and isinstance(b, dict)]
    resources = _labeled(parsed, "resource", 2)
    data_blocks = _labeled(parsed, "data", 2)
    by_type = lambda t: [(n, b) for rt, n, b in resources if rt == t]  # noqa: E731

    # ---- Variables: apply runs non-interactively, so every variable needs a default ----
    unset = [n for n, b in _labeled(parsed, "variable", 1) if isinstance(b, dict) and "default" not in b]
    if unset:
        violations.append(
            f"[VARIABLES] no default value for: {', '.join(unset)}. Apply cannot prompt for values, so set each "
            "default (from the request, or from the organisation defaults)"
        )

    # ---- Region ----
    allowed_regions = policy["allowed_regions"]
    if not providers:
        violations.append("[REGION] no aws provider block, so the region cannot be verified")
    for p in providers:
        region = _resolve(p.get("region"), variables)
        if region is None:
            violations.append("[REGION] provider region could not be resolved to a value (give the region variable a default)")
        elif region not in allowed_regions:
            violations.append(f"[REGION] region '{region}' is not allowed. Allowed: {', '.join(allowed_regions)}")

    # ---- Mandatory tags (and the two tags whose VALUE is constrained) ----
    required = policy["mandatory_tags"]
    default_tags: dict = {}
    for p in providers:
        if p.get("alias"):
            continue
        for dt in _as_list(p.get("default_tags")):
            tags = dt.get("tags") if isinstance(dt, dict) else None
            tags = tags[0] if isinstance(tags, list) and tags else tags
            if isinstance(tags, dict):
                default_tags.update({_clean(k): v for k, v in tags.items()})
    seen: set[str] = set()

    def once(msg: str):
        if msg not in seen:
            seen.add(msg)
            violations.append(msg)

    for rtype, name, body in resources:
        if rtype not in TAGGABLE_TYPES or not isinstance(body, dict):
            continue
        res_tags = body.get("tags")
        res_tags = res_tags[0] if isinstance(res_tags, list) and res_tags else res_tags
        effective = {**default_tags, **({_clean(k): v for k, v in res_tags.items()} if isinstance(res_tags, dict) else {})}
        missing = [t for t in required if t not in effective]
        if missing:
            once(f"[TAGS] {rtype}.{name} is missing mandatory tag(s): {', '.join(missing)}")
        if "Environment" in effective:
            env = _resolve(effective["Environment"], variables)
            if env is None:
                once("[TAGS] the Environment tag could not be resolved to a value (give the environment variable a default)")
            elif env not in policy["allowed_environments"]:
                once(f"[TAGS] Environment '{env}' is not one of {policy['allowed_environments']}")
        if "ManagedBy" in effective and _resolve(effective["ManagedBy"], variables) != "terraform":
            once('[TAGS] the ManagedBy tag must be "terraform"')

    # ---- S3: explicit encryption, full public-access block, no public ACL ----
    enc_targets = {_ref_name(b.get("bucket"), "aws_s3_bucket") for _, b in by_type("aws_s3_bucket_server_side_encryption_configuration")}
    pab = {_ref_name(b.get("bucket"), "aws_s3_bucket"): b for _, b in by_type("aws_s3_bucket_public_access_block")}
    for name, body in by_type("aws_s3_bucket"):
        if name not in enc_targets and not body.get("server_side_encryption_configuration"):
            violations.append(f"[ENCRYPTION] aws_s3_bucket.{name} has no explicit server-side encryption configuration")
        block = pab.get(name)
        keys = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        if not block or not all(_truthy(block.get(k)) for k in keys):
            violations.append(f"[PUBLIC-S3] aws_s3_bucket.{name} needs a public access block with all four settings true")
        if _clean(body.get("acl")) in PUBLIC_ACLS:
            violations.append(f"[PUBLIC-S3] aws_s3_bucket.{name} uses a public ACL")
    for name, body in by_type("aws_s3_bucket_acl"):
        if _clean(body.get("acl")) in PUBLIC_ACLS:
            violations.append(f"[PUBLIC-S3] aws_s3_bucket_acl.{name} is a public ACL")

    # ---- RDS / EBS encryption ----
    for name, body in by_type("aws_db_instance"):
        if not _truthy(body.get("storage_encrypted")):
            violations.append(f"[ENCRYPTION] aws_db_instance.{name} must set storage_encrypted = true")
    for name, body in by_type("aws_ebs_volume"):
        if not _truthy(body.get("encrypted")):
            violations.append(f"[ENCRYPTION] aws_ebs_volume.{name} must set encrypted = true")
    for name, body in by_type("aws_instance"):
        roots = _as_list(body.get("root_block_device"))
        if not roots or not all(_truthy(d.get("encrypted")) for d in roots if isinstance(d, dict)):
            violations.append(f"[ENCRYPTION] aws_instance.{name} must declare root_block_device with encrypted = true")
        for d in _as_list(body.get("ebs_block_device")):
            if isinstance(d, dict) and not _truthy(d.get("encrypted")):
                violations.append(f"[ENCRYPTION] aws_instance.{name} has an unencrypted ebs_block_device")

    # ---- Network: 0.0.0.0/0 only on 80/443 ----
    def check_ingress(label, cidrs, lo, hi):
        if not any(c in ("0.0.0.0/0", "::/0") for c in _flat(cidrs)):
            return
        lo_i, hi_i = _to_int(_resolve(lo, variables)), _to_int(_resolve(hi, variables))
        if lo_i is None or hi_i is None or lo_i != hi_i or lo_i not in (80, 443):
            violations.append(f"[NETWORK] {label} allows ingress from the internet on ports {_clean(lo)}-{_clean(hi)}; only 80/443 may be open")

    for name, body in by_type("aws_security_group"):
        for ing in _as_list(body.get("ingress")):
            if isinstance(ing, dict):
                check_ingress(f"aws_security_group.{name}", _as_list(ing.get("cidr_blocks")) + _as_list(ing.get("ipv6_cidr_blocks")),
                              ing.get("from_port"), ing.get("to_port"))
    for name, body in by_type("aws_security_group_rule"):
        if _clean(body.get("type")) == "ingress":
            check_ingress(f"aws_security_group_rule.{name}", _as_list(body.get("cidr_blocks")) + _as_list(body.get("ipv6_cidr_blocks")),
                          body.get("from_port"), body.get("to_port"))
    for name, body in by_type("aws_vpc_security_group_ingress_rule"):
        check_ingress(f"aws_vpc_security_group_ingress_rule.{name}", [body.get("cidr_ipv4"), body.get("cidr_ipv6")],
                      body.get("from_port"), body.get("to_port"))

    # ---- IAM: no Action "*" with Resource "*" ----
    for rtype in IAM_POLICY_TYPES:
        for name, body in by_type(rtype):
            text = str(body.get("policy", ""))
            if re.search(r"Action\W{1,6}\*\W", text) and re.search(r"Resource\W{1,6}\*\W", text):
                violations.append(f"[IAM] {rtype}.{name} grants Action \"*\" on Resource \"*\"")
    for rtype, name, body in data_blocks:
        if rtype != "aws_iam_policy_document":
            continue
        for st in _as_list(body.get("statement")):
            if isinstance(st, dict) and _clean(st.get("effect", "Allow")) != "Deny" \
                    and "*" in _flat(st.get("actions")) and "*" in _flat(st.get("resources")):
                violations.append(f"[IAM] data.aws_iam_policy_document.{name} grants actions \"*\" on resources \"*\"")

    # ---- Free tier: advisory unless policies.yaml says block ----
    ft = policy.get("free_tier", {})
    ft_issues: list[str] = []
    instances = by_type("aws_instance")
    n_instances = sum(_to_int(_resolve(b.get("count", 1), variables)) or 1 for _, b in instances)
    if n_instances > ft.get("ec2", {}).get("max_instances", 1):
        ft_issues.append(f"{n_instances} EC2 instances exceed the free-tier limit of {ft['ec2']['max_instances']}")
    for name, body in instances:
        itype = _resolve(body.get("instance_type"), variables)
        if itype not in ft.get("ec2", {}).get("allowed_instance_types", []):
            ft_issues.append(f"aws_instance.{name} type '{itype}' is not free-tier eligible")
    for name, body in by_type("aws_db_instance"):
        rds = ft.get("rds", {})
        if _resolve(body.get("instance_class"), variables) not in rds.get("allowed_instance_classes", []):
            ft_issues.append(f"aws_db_instance.{name} class '{_resolve(body.get('instance_class'), variables)}' is not free-tier eligible")
        storage = _to_int(_resolve(body.get("allocated_storage"), variables))
        if storage is not None and storage > rds.get("max_storage_gb", 20):
            ft_issues.append(f"aws_db_instance.{name} storage {storage} GB exceeds the free-tier {rds.get('max_storage_gb', 20)} GB")
        if _truthy(_resolve(body.get("multi_az"), variables)):
            ft_issues.append(f"aws_db_instance.{name} uses multi_az, which is not free tier")
    if by_type("aws_nat_gateway"):
        ft_issues.append("a NAT gateway is not free tier (hourly charge)")
    if by_type("aws_eip"):
        ft_issues.append("Elastic IPs are charged when unattached; verify they are attached")
    if policy.get("guardrail", {}).get("free_tier_violations", "warn") == "block":
        violations += [f"[FREE-TIER] {i}" for i in ft_issues]
    else:
        warnings += [f"[FREE-TIER] {i}" for i in ft_issues]

    return violations, warnings


# ----------------------------------------------------------------------------------------
# Full evaluation: static checks + the three external verifiers, run independently.
# ----------------------------------------------------------------------------------------
def _strip_fences(text: str) -> str:
    m = re.search(r"```(?:hcl|terraform)?\n(.*?)```", text or "", re.DOTALL)
    return (m.group(1) if m else text or "").strip()


def evaluate(hcl: str) -> dict:
    """Run every check on the HCL. Returns
    {"passed", "violations", "warnings", "retryable", "evidence"}."""
    hcl = _strip_fences(hcl)
    if not hcl:
        return {"passed": False, "retryable": False, "warnings": [], "evidence": {},
                "violations": ["[OUTPUT] no Terraform was produced (the agent refused or asked a question instead)"]}

    policy = load_policy()
    violations: list[str] = []
    warnings: list[str] = []
    retryable = True
    evidence: dict = {}

    # 1. Is it valid Terraform at all? If not, the other checks would only add noise.
    validation = run_validate(hcl)
    evidence["validation"] = validation
    if not validation.startswith("VALID"):
        if validation.startswith("ERROR"):
            retryable = False  # terraform itself unavailable: not the agent's fault
        violations.append("[VALIDATE] " + validation[:600])
        return {"passed": False, "retryable": retryable, "violations": violations, "warnings": warnings, "evidence": evidence}

    # 2. Static policy checks.
    try:
        static_v, static_w = check_parsed(parse_hcl(hcl), policy)
        violations += static_v
        warnings += static_w
    except ParseFailure as e:
        # terraform accepted it but OUR parser did not: a guardrail limitation, not agent error.
        violations.append(f"[GUARDRAIL] could not parse the HCL for policy checks: {e}")
        retryable = False
    except ImportError:
        violations.append("[GUARDRAIL] python-hcl2 is not installed, so policy checks cannot run")
        retryable = False
    except Exception as e:  # noqa: BLE001
        # An unexpected HCL shape must FAIL CLOSED with a recorded violation. If this raised
        # instead, the graph would crash and the run would leave no audit record at all.
        violations.append(f"[GUARDRAIL] internal error during policy checks ({type(e).__name__}: {str(e)[:150]})")
        retryable = False

    # 3. Security scan (fails closed).
    scan = run_scan(hcl)
    evidence["security_findings"] = scan["findings"]
    evidence["accepted_findings"] = len(scan["suppressed"])
    if not scan["ok"]:
        violations.append("[SCAN] incomplete, cannot confirm the code is secure: " + "; ".join(scan["errors"]))
        retryable = False
    for f in scan["findings"][:MAX_SCAN_LINES]:
        violations.append(f"[SCAN] {f['tool']} {f['id']}: {f['title']} ({f['resource']})")
    if len(scan["findings"]) > MAX_SCAN_LINES:
        violations.append(f"[SCAN] ...and {len(scan['findings']) - MAX_SCAN_LINES} more findings")

    # 4. Cost (fails closed).
    cost = run_estimate(hcl)
    evidence["cost"] = cost
    if not cost["ok"]:
        violations.append("[COST] estimate unavailable, cannot confirm the ceiling: " + "; ".join(cost["errors"]))
        retryable = False
    else:
        if cost["over_ceiling"]:
            violations.append(f"[COST] estimated ₹{cost['monthly_inr']}/month exceeds the ₹{cost['ceiling_inr']}/month ceiling")
        if cost["usage_based_resources"]:
            warnings.append(f"[COST] {cost['usage_based_resources']} resource(s) have usage-based costs that are NOT in this estimate")

    return {"passed": not violations, "retryable": retryable, "violations": violations, "warnings": warnings, "evidence": evidence}


# ----------------------------------------------------------------------------------------
# The LangGraph pieces: the node, and the router that reads its decision.
# ----------------------------------------------------------------------------------------
def guardrail_check(state: AgentState) -> dict:
    """The graph node. Reads the agent's HCL from state, writes the verdict back."""
    result = evaluate(state.get("generated_hcl", ""))
    retry_count = state.get("retry_count", 0)

    if result["passed"]:
        decision = "approve"
    elif result["retryable"] and retry_count < MAX_RETRIES:
        decision = "retry"
    else:
        decision = "drop"

    verdict: GuardrailVerdict = {
        "passed": result["passed"], "violations": result["violations"], "warnings": result["warnings"],
        "retryable": result["retryable"], "decision": decision,
    }
    event: AuditEvent = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node": "guardrail_check",
        "event": f"guardrail_{decision}",
        "detail": "; ".join(result["violations"])[:300],
    }
    evidence = result["evidence"]
    update: dict = {
        "guardrail_result": verdict,
        "audit_trail": [event],
        # The guardrail's OWN results, so the approver sees what was independently verified.
        "validation_result": {"output": evidence.get("validation", "")},
        "security_findings": evidence.get("security_findings", []),
        "cost_estimate": evidence.get("cost", {}),
    }
    if decision == "retry":
        update["retry_count"] = retry_count + 1
        # This message is how the agent learns what was wrong: it lands in the conversation
        # the agent reads on its next turn.
        update["messages"] = [HumanMessage(content=(
            f"The guardrail rejected your Terraform (attempt {retry_count + 1} of {MAX_RETRIES}). "
            "Fix ALL of these, then run validate_terraform, security_scan and cost_estimate "
            "again before giving your final answer:\n" + "\n".join(f"- {v}" for v in result["violations"])
        ))]
    return update


def route_after_guardrail(state: AgentState) -> str:
    """The three-way conditional edge. Pure lookup: the decision was already made above."""
    return {"approve": "approval_gate", "retry": "agent", "drop": "audit_log"}[state["guardrail_result"]["decision"]]


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.guardrail            static checks on good and bad HCL
    # uv run python -m cloud_infra_agent.guardrail dump       print how python-hcl2 parses the template
    # uv run python -m cloud_infra_agent.guardrail full       the complete evaluation (needs all tools)
    import json
    import sys

    module_md = (DEFAULT_KB_DIR / "modules" / "s3_secure_bucket.md").read_text()
    raw_template = re.search(r"```hcl\n(.*?)```", module_md, re.DOTALL).group(1)
    # The template leaves its variables without defaults (the agent supplies them per request).
    demo_defaults = {"project": "demo", "environment": "dev", "owner": "platform-team",
                     "cost_center": "cc-0000", "purpose": "audit-logs"}
    good = raw_template
    for var, val in demo_defaults.items():
        good = re.sub(rf'variable "{var}"\s+\{{ type = string \}}',
                      f'variable "{var}" {{\n  type    = string\n  default = "{val}"\n}}', good)
    assert good.count("default =") >= len(demo_defaults), "test setup error: a variable line was not found"
    mode = sys.argv[1] if len(sys.argv) > 1 else "static"

    def swap(text: str, old: str, new: str) -> str:
        # A test case built with str.replace that matches nothing silently tests the wrong
        # thing. Fail loudly instead.
        assert old in text, f"test setup error: {old!r} not found in the template"
        return text.replace(old, new)

    if mode == "dump":
        print(json.dumps(parse_hcl(good), indent=2, default=str)[:6000])
    elif mode == "full":
        r = evaluate(good)
        print("passed:", r["passed"], "| retryable:", r["retryable"])
        print("violations:", *r["violations"], sep="\n  ")
        print("warnings:", *r["warnings"], sep="\n  ")
    else:
        policy = load_policy()
        no_enc = re.sub(r'resource "aws_s3_bucket_server_side_encryption_configuration" "this" \{.*?\n\}\n', "", good, flags=re.S)
        cases = {
            "good (expect no violations)": good,
            "template as written, no environment default": raw_template,
            "region us-east-1": swap(good, 'default = "ap-south-1"', 'default = "us-east-1"'),
            "missing CostCenter tag": swap(good, "      CostCenter  = var.cost_center\n", ""),
            "environment = prod2": swap(good, 'default = "dev"', 'default = "prod2"'),
            "no encryption resource": no_enc,
            "public access block not fully on": swap(good, "block_public_acls       = true", "block_public_acls       = false"),
            "open SSH + wildcard IAM + big EC2": good + '''
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
resource "aws_instance" "big" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.4xlarge"
}
''',
        }
        for name, code in cases.items():
            v, w = check_parsed(parse_hcl(code), policy)
            print(f"=== {name} ===")
            print("  " + "\n  ".join(v or ["(no violations)"]))
            if w:
                print("  warnings:", *w, sep="\n    ")
            print()
