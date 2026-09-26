"""cost_tools.py — monthly cost estimate of generated Terraform, via Infracost.

Infracost reads the HCL directly (no `terraform init`, no AWS account), looks up list
prices, and reports a monthly figure in USD. We convert to INR using the rate in
policies.yaml and compare against the ceiling there.

Three things this tool is careful about (each one is a way a cost check quietly lies):

1. FAIL CLOSED, as in scan_tools: a missing binary, missing API key, timeout or unreadable
   output is "ESTIMATE UNAVAILABLE", never "₹0". Zero looks like a pass.

2. USAGE-BASED RESOURCES. An S3 bucket costs nothing until you store things in it, so
   Infracost prices it at 0 unless you give it usage data. A cost check that says "₹0,
   within ceiling" for a bucket would be technically true and practically meaningless. We
   report how many resources are usage-based so nobody mistakes "not priced" for "free".

3. UNSUPPORTED RESOURCES are counted too: a resource Infracost can't price is missing
   from the total, not free.

`run_estimate` returns plain data. The guardrail node will call it directly, so it never
has to trust the agent's own account of what the estimate said.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml
from dotenv import load_dotenv
from langchain_core.tools import tool

from cloud_infra_agent.loader import DEFAULT_KB_DIR

load_dotenv()  # INFRACOST_API_KEY comes from .env; also works when run standalone

INFRACOST_TIMEOUT = 120
MAX_SHOWN = 5


def load_cost_policy() -> dict:
    """{'max_monthly_inr': ..., 'usd_to_inr': ...} from policies.yaml."""
    return yaml.safe_load((DEFAULT_KB_DIR / "policies.yaml").read_text())["cost_ceiling"]


def parse_infracost(raw: str, usd_to_inr: float, ceiling_inr: float) -> dict:
    """Infracost JSON -> a small verdict dict. Pure function: easy to test without Infracost."""
    data = json.loads(raw)
    errors = []
    if data.get("currency", "USD") != "USD":
        # Our conversion assumes USD; refuse to guess otherwise.
        errors.append(f"unexpected currency {data.get('currency')!r}; expected USD")

    # Infracost returns numbers as strings, and null for anything it could not price.
    monthly_usd = float(data.get("totalMonthlyCost") or 0)
    monthly_inr = round(monthly_usd * usd_to_inr)

    resources = []
    for project in data.get("projects", []):
        for r in project.get("breakdown", {}).get("resources", []):
            cost = r.get("monthlyCost")
            if cost is not None and float(cost) > 0:
                resources.append((r.get("name", "?"), round(float(cost) * usd_to_inr)))
    resources.sort(key=lambda item: item[1], reverse=True)

    summary = data.get("summary", {})
    return {
        "ok": not errors,
        "errors": errors,
        "monthly_usd": monthly_usd,
        "monthly_inr": monthly_inr,
        "ceiling_inr": ceiling_inr,
        "over_ceiling": monthly_inr > ceiling_inr,
        "usage_based_resources": summary.get("totalUsageBasedResources", 0),
        "unsupported": summary.get("unsupportedResourceCounts") or {},
        "top_resources": resources[:MAX_SHOWN],
    }


def run_estimate(hcl: str) -> dict:
    """Write the HCL to a temp folder, run Infracost, return the verdict dict."""
    import re

    fenced = re.search(r"```(?:hcl|terraform)?\n(.*?)```", hcl, re.DOTALL)
    hcl = (fenced.group(1) if fenced else hcl).strip()

    policy = load_cost_policy()

    def unavailable(reason: str) -> dict:
        return {"ok": False, "errors": [reason], "ceiling_inr": policy["max_monthly_inr"]}

    if not shutil.which("infracost"):
        return unavailable("infracost not found on PATH")
    if not os.environ.get("INFRACOST_API_KEY"):
        return unavailable("INFRACOST_API_KEY is not set (check your .env)")

    env = {**os.environ, "INFRACOST_SKIP_UPDATE_CHECK": "true"}
    with tempfile.TemporaryDirectory() as workdir:
        (Path(workdir) / "main.tf").write_text(hcl)
        try:
            p = subprocess.run(
                ["infracost", "breakdown", "--path", workdir, "--format", "json", "--no-color"],
                cwd=workdir, env=env, capture_output=True, text=True, timeout=INFRACOST_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return unavailable("infracost timed out")

    if p.returncode != 0 or not p.stdout.strip():
        return unavailable(f"infracost failed: {(p.stderr or p.stdout)[-500:]}")
    try:
        return parse_infracost(p.stdout, policy["usd_to_inr"], policy["max_monthly_inr"])
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return unavailable(f"could not read infracost output: {e}")


def format_estimate(result: dict) -> str:
    """Turn the verdict into short text an LLM can act on."""
    if not result["ok"]:
        return (
            "ESTIMATE UNAVAILABLE: cannot confirm the cost is within the ceiling.\n"
            + "\n".join(f"- {e}" for e in result["errors"])
        )
    inr, ceiling = result["monthly_inr"], result["ceiling_inr"]
    if result["over_ceiling"]:
        lines = [
            f"OVER CEILING: estimated ₹{inr}/month (USD {result['monthly_usd']:.2f}) "
            f"exceeds the ₹{ceiling}/month ceiling by ₹{inr - ceiling}. Choose a cheaper "
            "configuration if the request allows it (smaller instance class, fewer or "
            "smaller resources). If it does not, say so plainly in your final answer instead "
            "of silently changing what the user asked for."
        ]
    else:
        lines = [
            f"WITHIN CEILING: estimated ₹{inr}/month (USD {result['monthly_usd']:.2f}) "
            f"against the ₹{ceiling}/month ceiling."
        ]
    if result["usage_based_resources"]:
        lines.append(
            f"NOTE: Infracost reports {result['usage_based_resources']} resource(s) with "
            "usage-based cost components (storage, requests, data transfer and similar). Those "
            "components count as ₹0 here because no usage data was supplied, so real cost will "
            "vary with usage."
        )
    if result["unsupported"]:
        lines.append(f"NOTE: Infracost could not price these resource types: {result['unsupported']}.")
    for name, cost in result["top_resources"]:
        lines.append(f"- {name}: ₹{cost}/month")
    return "\n".join(lines)


# The LLM sees only the name, argument types and this docstring.
@tool
def cost_estimate(hcl: str) -> str:
    """Estimate the monthly AWS cost (in INR) of Terraform code and compare it to the ceiling.

    Call this AFTER validate_terraform and security_scan pass. If it reports OVER CEILING,
    choose a cheaper configuration where the request allows, then re-check. Include the
    estimated monthly cost in your final answer.

    Args:
        hcl: The COMPLETE Terraform configuration as one string, exactly as it would go in main.tf.
    """
    return format_estimate(run_estimate(hcl))


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.cost_tools
    import re

    module_md = (DEFAULT_KB_DIR / "modules" / "s3_secure_bucket.md").read_text()
    s3 = re.search(r"```hcl\n(.*?)```", module_md, re.DOTALL).group(1)

    def instance(kind: str) -> str:
        return f'''provider "aws" {{
  region = "eu-west-1"
}}

resource "aws_instance" "web" {{
  ami           = "ami-0abcdef1234567890"
  instance_type = "{kind}"
}}
'''

    for name, code in [
        ("S3 template (usage-based)", s3),
        ("one t3.micro", instance("t3.micro")),
        ("one m5.4xlarge (should exceed the ceiling)", instance("m5.4xlarge")),
    ]:
        print(f"=== {name} ===")
        print(format_estimate(run_estimate(code)), "\n")