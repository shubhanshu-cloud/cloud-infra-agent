"""agent.py — the ReAct agent: an LLM in a loop with tools.

WHY ReAct (agentic-AI concept: Reason + Act):
    A fixed pipeline runs steps in an order decided in advance. A ReAct agent lets the LLM
    decide the order:
        1. REASON  - the LLM reads the conversation and decides what to do next
        2. ACT     - it asks for a tool call (e.g. retrieve_patterns)
        3. OBSERVE - the tool's result is added to the conversation
        ...and it repeats until the LLM answers WITHOUT asking for a tool. That is "done".

    Graph shape (graph.py builds it):

        START -> agent --(wants a tool?)--> tools --+
                   ^                                |
                   +--------------------------------+
                   |
                   +--(no tool call = finished)--> END

    The tools list holds retrieve_patterns, validate_terraform, security_scan and
    cost_estimate. Adding another tool needs no rewiring of the loop.
"""

import re
from datetime import datetime, timezone

import yaml
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI

from cloud_infra_agent.state import AgentState, AuditEvent
from cloud_infra_agent.cost_tools import cost_estimate
from cloud_infra_agent.loader import DEFAULT_KB_DIR
from cloud_infra_agent.scan_tools import security_scan
from cloud_infra_agent.terraform_tools import validate_terraform
from cloud_infra_agent.tools import retrieve_patterns

load_dotenv()  # load local environment configuration

TOOLS = [retrieve_patterns, validate_terraform, security_scan, cost_estimate]

# temperature=0: as deterministic as the model allows. For infrastructure code we want
# the same request to produce the same answer, not creative variation.
llm = ChatOpenAI(model="gpt-4o", temperature=0)

# bind_tools() sends each tool's name, argument types and docstring to the model with
# every request. That is how the LLM knows retrieve_patterns exists and how to call it.
llm_with_tools = llm.bind_tools(TOOLS)

# The system prompt is the agent's job description. It replaces the old parse_intent and
# generate_terraform nodes: the LLM does both inside its own reasoning.
BASE_PROMPT = """You are a cloud infrastructure agent that turns plain-language requests \
into Terraform for AWS.

Workflow:
1. ALWAYS call retrieve_patterns first, before writing any Terraform. Use a query that \
names the resource type and purpose.
2. Adapt the retrieved template to the request. Do not invent structure the template \
does not use, and do not add resources the user did not ask for.
3. Follow the retrieved standards exactly: mandatory tags, naming pattern, encryption, \
and the region allowlist.
4. If the user asks for a region that is not allowed, do NOT generate code. Explain which \
regions are allowed and stop.
5. If retrieve_patterns finds nothing relevant, say so instead of guessing.
6. Every variable must end up with a `default`, because apply runs without prompting. Use \
each value the user states (environment, region, purpose, project name and so on). For values \
the user does not state, use the organisation defaults listed at the end of this prompt. \
Write each variable as a multi-line block (a one-line block cannot hold both `type` and \
`default`). In your final note, list which values came from organisation defaults.
7. Before answering, call validate_terraform with the complete HCL. If it reports errors, \
fix them and validate again. Give your final answer only once it reports VALID, or after \
three failed attempts, in which case say exactly what is still failing.
8. Once validation passes, call security_scan with the complete HCL. Fix real problems by \
adjusting existing resources, then validate and scan again. If a finding cannot be fixed \
without adding cost or resources the user did not ask for, leave it and mention it in your \
final note.
9. Then call cost_estimate with the complete HCL. If it reports OVER CEILING, choose a \
cheaper configuration where the request allows it and re-check; if the request itself \
requires the cost, say so plainly instead of silently changing what was asked.
10. When finished, reply with the complete Terraform in a single ```hcl code block, \
followed by a short note listing any assumptions, any values still needed, and the \
estimated monthly cost in INR from cost_estimate."""


def _load_defaults() -> dict:
    """Organisation defaults from kb/defaults.yaml, overridden by kb/defaults.local.yaml when
    present. The local file is git-ignored, so real values never have to be committed."""
    merged: dict = {}
    for name in ("defaults.yaml", "defaults.local.yaml"):
        path = DEFAULT_KB_DIR / name
        if path.exists():
            merged.update((yaml.safe_load(path.read_text()) or {}).get("defaults") or {})
    return merged


def _defaults_section(defaults: dict) -> str:
    if not defaults:
        return ""
    lines = "\n".join(f"- {name} = {value}" for name, value in defaults.items())
    return f"\n\nOrganisation defaults (use when the request does not state the value):\n{lines}"


# Injected as concrete values: a rule that only says "use the defaults file" gives the
# model nothing to act on.
SYSTEM_PROMPT = BASE_PROMPT + _defaults_section(_load_defaults())


def extract_hcl(text: str) -> str:
    """Pull the Terraform out of the ```hcl ... ``` block in the LLM's final answer."""
    match = re.search(r"```(?:hcl|terraform)?\n(.*?)```", text, re.DOTALL)
    return match.group(1).strip() if match else ""


def agent_node(state: AgentState) -> dict:
    """One turn of the agent: read the conversation, reply.

    The reply is EITHER a tool-call request OR a final answer. We don't decide which:
    the LLM does. We only record what happened.
    """
    # The system prompt is prepended on every call and NOT stored in state, so it can't
    # pile up in the history.
    messages = [SystemMessage(content=SYSTEM_PROMPT), *state["messages"]]
    response = llm_with_tools.invoke(messages)

    # A node returns only the fields it changes; LangGraph merges them using the
    # reducers from state.py.
    update: dict = {"messages": [response]}  # add_messages APPENDS this to the history

    event: AuditEvent = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node": "agent",
        "event": "tool_call_requested" if response.tool_calls else "final_answer",
        "detail": ", ".join(c["name"] for c in response.tool_calls) or "",
    }
    update["audit_trail"] = [event]  # operator.add APPENDS this to the trail

    if not response.tool_calls:
        update["generated_hcl"] = extract_hcl(response.content)
    return update


def should_continue(state: AgentState) -> str:
    """The router: decides which edge to follow after the agent speaks.

    This is a CONDITIONAL EDGE. It reads the state and returns the name of the next
    step. If the LLM asked for a tool, run it. If not, the agent believes it has finished,
    and its work goes to the guardrail, which does not take its word for it.
    """
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "tools"
    return "guardrail_check"
