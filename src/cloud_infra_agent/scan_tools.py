"""scan_tools.py — security scanning of generated Terraform (Checkov + Trivy).

WHY two scanners: they have different rule sets and each catches things the other misses.
Both are deterministic programs, so the verdict does not depend on what the LLM believes.

Two design points:

1. FAIL CLOSED. If a scanner is missing, times out or crashes, the result is "SCAN
   INCOMPLETE", never "no findings". A silent scanner failure looks exactly like a clean
   pass, which is the dangerous mistake in a security control.

2. RISK ACCEPTANCE lives in policies.yaml. Scanners flag things like "no access logging" on
   every bucket. Without a filter the agent tries to satisfy all of them (KMS keys,
   replication...), adding cost and resources nobody asked for. Accepted findings are
   listed with a reason in policies.yaml, hidden from the agent, and counted in the output
   so nothing is suppressed silently.

`run_scan` returns plain data. The @tool wrapper at the bottom turns it into text for the
LLM. The guardrail node will call run_scan DIRECTLY, so it never has to trust the agent's
own report of what the scan said.
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml
from langchain_core.tools import tool

from cloud_infra_agent.loader import DEFAULT_KB_DIR

SCAN_TIMEOUT = 180
MAX_SHOWN = 15  # cap what goes into the LLM's context
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _norm_id(check_id: str) -> str:
    """Trivy ids may or may not carry an 'AVD-' prefix; compare without it."""
    return check_id.upper().removeprefix("AVD-")


def load_accepted() -> dict[str, str]:
    """{normalised check id: reason} from policies.yaml."""
    policy = yaml.safe_load((DEFAULT_KB_DIR / "policies.yaml").read_text())
    entries = policy.get("security_scan", {}).get("accepted_findings", [])
    return {_norm_id(e["id"]): e["reason"] for e in entries}


def parse_checkov(raw: str) -> list[dict]:
    """Checkov JSON -> our common finding shape. (One dict per framework, or a list.)"""
    data = json.loads(raw)
    reports = data if isinstance(data, list) else [data]
    findings = []
    for report in reports:
        for c in report.get("results", {}).get("failed_checks", []):
            line_range = c.get("file_line_range") or [None]
            findings.append(
                {
                    "tool": "checkov",
                    "id": c.get("check_id", "?"),
                    "title": c.get("check_name", ""),
                    # The open-source Checkov usually has no severity; show UNKNOWN.
                    "severity": (c.get("severity") or "UNKNOWN").upper(),
                    "resource": c.get("resource", ""),
                    "line": line_range[0],
                    "fix": c.get("guideline") or "",
                }
            )
    return findings


def parse_trivy(raw: str) -> list[dict]:
    """Trivy JSON -> our common finding shape."""
    data = json.loads(raw)
    findings = []
    for result in data.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            findings.append(
                {
                    "tool": "trivy",
                    "id": m.get("ID", "?"),
                    "title": m.get("Title", ""),
                    "severity": (m.get("Severity") or "UNKNOWN").upper(),
                    "resource": cause.get("Resource", ""),
                    "line": cause.get("StartLine"),
                    "fix": m.get("Resolution") or "",
                }
            )
    return findings


def _run(cmd: list[str], workdir: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=SCAN_TIMEOUT)


def run_scan(hcl: str) -> dict:
    """Scan HCL with both tools. Returns
    {"ok": bool, "findings": [...], "suppressed": [...], "errors": [...]}.
    ok is False if EITHER scanner could not complete."""
    fenced = re.search(r"```(?:hcl|terraform)?\n(.*?)```", hcl, re.DOTALL)
    hcl = (fenced.group(1) if fenced else hcl).strip()

    findings: list[dict] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory() as workdir:
        (Path(workdir) / "main.tf").write_text(hcl)

        # --- Checkov. Exit code 1 just means "found failures", so only >1 is an error. ---
        if not shutil.which("checkov"):
            errors.append("checkov not found on PATH")
        else:
            try:
                p = _run(
                    ["checkov", "-d", workdir, "--framework", "terraform",
                     "-o", "json", "--compact", "--skip-download"],
                    workdir,
                )
                if p.returncode > 1 or not p.stdout.strip():
                    errors.append(f"checkov failed: {(p.stderr or p.stdout)[-500:]}")
                else:
                    findings += parse_checkov(p.stdout)
            except subprocess.TimeoutExpired:
                errors.append("checkov timed out")
            except (json.JSONDecodeError, KeyError) as e:
                errors.append(f"could not read checkov output: {e}")

        # --- Trivy. Exits 0 even with findings unless told otherwise. ---
        if not shutil.which("trivy"):
            errors.append("trivy not found on PATH")
        else:
            try:
                p = _run(["trivy", "config", "--format", "json", "--quiet", workdir], workdir)
                if p.returncode != 0 or not p.stdout.strip():
                    errors.append(f"trivy failed: {(p.stderr or p.stdout)[-500:]}")
                else:
                    findings += parse_trivy(p.stdout)
            except subprocess.TimeoutExpired:
                errors.append("trivy timed out")
            except (json.JSONDecodeError, KeyError) as e:
                errors.append(f"could not read trivy output: {e}")

    accepted = load_accepted()
    kept = [f for f in findings if _norm_id(f["id"]) not in accepted]
    suppressed = [f for f in findings if _norm_id(f["id"]) in accepted]
    kept.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)
    return {"ok": not errors, "findings": kept, "suppressed": suppressed, "errors": errors}


def format_scan(result: dict) -> str:
    """Turn run_scan's data into short text an LLM can act on."""
    lines = []
    if result["errors"]:
        lines.append("SCAN INCOMPLETE: cannot confirm the code is secure.")
        lines += [f"- {e}" for e in result["errors"]]
    n, s = len(result["findings"]), len(result["suppressed"])
    if n == 0 and not result["errors"]:
        return f"PASS: no unresolved security findings ({s} accepted per policy, hidden)."
    if n:
        lines.append(
            f"FINDINGS: {n} unresolved ({s} accepted per policy, hidden). "
            "Fix real problems by adjusting existing resources, then re-run validate_terraform "
            "and security_scan."
        )
        for f in result["findings"][:MAX_SHOWN]:
            where = f"{f['resource']}, line {f['line']}" if f["line"] else f["resource"]
            hint = f" Fix: {f['fix']}" if f["fix"] else ""
            lines.append(f"- [{f['severity']}] {f['tool']} {f['id']}: {f['title']} ({where}).{hint}")
        if n > MAX_SHOWN:
            lines.append(f"... and {n - MAX_SHOWN} more (highest severity shown first).")
    return "\n".join(lines)


# The LLM sees only the name, argument types and this docstring.
@tool
def security_scan(hcl: str) -> str:
    """Scan Terraform for security misconfigurations using Checkov and Trivy.

    Call this AFTER validate_terraform reports VALID and before giving your final answer.
    It lists unresolved findings. Fix genuine problems by changing existing resources. If a
    finding cannot be fixed without adding cost or resources the user did not ask for, leave
    it and mention it in your final note. Findings the organisation has formally accepted
    are already hidden.

    Args:
        hcl: The COMPLETE Terraform configuration as one string, exactly as it would go in main.tf.
    """
    return format_scan(run_scan(hcl))


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.scan_tools
    module_md = (DEFAULT_KB_DIR / "modules" / "s3_secure_bucket.md").read_text()
    good = re.search(r"```hcl\n(.*?)```", module_md, re.DOTALL).group(1)
    bad = '''terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

resource "aws_s3_bucket" "bad" {
  bucket = "definitely-public-bucket"
  acl    = "public-read"
}
'''
    for name, code in [("template as written", good), ("deliberately insecure bucket", bad)]:
        print(f"=== {name} ===")
        print(format_scan(run_scan(code)), "\n")
