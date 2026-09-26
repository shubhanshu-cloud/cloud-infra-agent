"""terraform_tools.py — tools that let the agent CHECK its own Terraform.

WHY this tool exists (the point of ReAct):
    LLM-generated HCL can be syntactically invalid, for example a one-line block with two
    arguments (`variable "x" { type = string, default = "dev" }`), even when the prompt
    forbids it. Prompts are guidance, not guarantees. A tool gives the agent an
    OBSERVATION: it writes code, runs validate, reads the error, fixes the code and
    validates again. The loop corrects mistakes instead of relying on a perfect first draft.

    This is a deterministic check: terraform itself, not the LLM, decides whether the code
    is valid.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from langchain_core.tools import tool

# `terraform validate` needs the provider's schema, so `terraform init` must download the
# AWS provider (hundreds of MB). A shared plugin cache means it downloads ONCE and every
# later temp directory reuses it.
PLUGIN_CACHE = Path.home() / ".terraform.d" / "plugin-cache"
INIT_TIMEOUT = 300  # first run downloads the provider
VALIDATE_TIMEOUT = 60

# SECURITY: `terraform validate` loads provider plugin binaries, i.e. it EXECUTES them.
# The HCL comes from an LLM (which reads user requests), so a request could try to make it
# emit `source = "evil/aws"`. We only allow the official AWS provider and no modules.
ALLOWED_PROVIDER_SOURCES = {"hashicorp/aws"}


def _safety_check(hcl: str) -> str | None:
    """Return a refusal message if the HCL asks for anything outside the allowlist."""
    # Modules first: their own `source = ...` line would otherwise trigger the provider
    # message below, which would be confusing.
    if re.search(r'^\s*module\s+"', hcl, re.MULTILINE):
        return "REFUSED: module blocks are not allowed. Write the resources directly."
    for source in re.findall(r'source\s*=\s*"([^"]+)"', hcl):
        if source not in ALLOWED_PROVIDER_SOURCES:
            return (
                f"REFUSED: source '{source}' is not allowed. "
                f"Only these providers may be used: {sorted(ALLOWED_PROVIDER_SOURCES)}."
            )
    return None


def _format_result(result: dict) -> str:
    """Turn terraform's JSON verdict into short text an LLM can act on."""
    diagnostics = result.get("diagnostics", [])
    errors = [d for d in diagnostics if d.get("severity") == "error"]
    if result.get("valid"):
        head = "VALID: terraform validate passed."
    else:
        head = f"INVALID: {len(errors)} error(s). Fix them and call validate_terraform again."
    lines = [head]
    for d in diagnostics:
        line_no = d.get("range", {}).get("start", {}).get("line")
        where = f"line {line_no}: " if line_no else ""
        detail = d.get("detail", "").strip()
        lines.append(f"- {d.get('severity', '?').upper()} {where}{d.get('summary', '')}. {detail}")
    return "\n".join(lines)


def run_validate(hcl: str) -> str:
    """Write the HCL to a temp folder and run terraform init + validate on it."""
    # Models sometimes pass the markdown fence along with the code; strip it.
    fenced = re.search(r"```(?:hcl|terraform)?\n(.*?)```", hcl, re.DOTALL)
    hcl = (fenced.group(1) if fenced else hcl).strip()

    if not shutil.which("terraform"):
        return "ERROR: terraform CLI not found on PATH; cannot validate."
    if refusal := _safety_check(hcl):
        return refusal

    PLUGIN_CACHE.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "TF_PLUGIN_CACHE_DIR": str(PLUGIN_CACHE), "TF_IN_AUTOMATION": "1"}

    # A throwaway folder: nothing is left behind, and runs can't interfere with each other.
    with tempfile.TemporaryDirectory() as workdir:
        (Path(workdir) / "main.tf").write_text(hcl)
        try:
            # -backend=false: we only validate; no state or cloud connection is needed.
            init = subprocess.run(
                ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                cwd=workdir, env=env, capture_output=True, text=True, timeout=INIT_TIMEOUT,
            )
            if init.returncode != 0:
                # Syntax errors are caught here too, because init has to parse the files.
                return "INVALID: terraform init failed (syntax error or network problem):\n" + (
                    init.stderr[-1500:] or init.stdout[-1500:]
                )
            validate = subprocess.run(
                ["terraform", "validate", "-json", "-no-color"],
                cwd=workdir, env=env, capture_output=True, text=True, timeout=VALIDATE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return "ERROR: terraform timed out."

    try:
        return _format_result(json.loads(validate.stdout))
    except json.JSONDecodeError:
        return "ERROR: unexpected terraform output:\n" + (validate.stdout or validate.stderr)[-1500:]


# As with retrieve_patterns, the LLM sees only the name, argument types and this docstring.
@tool
def validate_terraform(hcl: str) -> str:
    """Check Terraform code with `terraform validate` and report any errors.

    Call this after writing Terraform and BEFORE giving your final answer. If it reports
    INVALID, fix the listed errors and call it again. Only finish once it reports VALID.

    Args:
        hcl: The COMPLETE Terraform configuration as one string (every block: terraform,
             variables, provider, resources, outputs), exactly as it would go in main.tf.
    """
    return run_validate(hcl)


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.terraform_tools
    # First run downloads the AWS provider (a few minutes); later runs take seconds.
    from cloud_infra_agent.loader import DEFAULT_KB_DIR

    module_md = (DEFAULT_KB_DIR / "modules" / "s3_secure_bucket.md").read_text()
    good = re.search(r"```hcl\n(.*?)```", module_md, re.DOTALL).group(1)
    # The exact mistake the agent made:
    bad = good.replace(
        'variable "purpose"     { type = string }',
        'variable "purpose"     { type = string, default = "audit-logs" }',
    )
    evil = good.replace('source = "hashicorp/aws"', 'source = "evil/aws"')

    for name, code in [("template as written", good), ("agent's one-line mistake", bad), ("evil provider", evil)]:
        print(f"=== {name} ===")
        print(run_validate(code), "\n")
