"""agent.py — the ReAct agent: an LLM in a loop with tools.

WHY ReAct (agentic-AI concept: Reason + Act):
    A fixed pipeline runs steps in an order YOU decided. A ReAct agent lets the LLM
    decide the order:
        1. REASON  - the LLM reads the conversation and decides what to do next
        2. ACT     - it asks for a tool call (e.g. retrieve_patterns)
        3. OBSERVE - the tool's result is added to the conversation
        ...and it repeats until the LLM answers WITHOUT asking for a tool. That is "done".

    Graph shape (this file builds exactly this):

        START -> agent --(wants a tool?)--> tools --+
                   ^                                |
                   +--------------------------------+
                   |
                   +--(no tool call = finished)--> END

    Today `tools` holds one tool. Later we add validate, security_scan, cost_estimate
    to the same list and the loop needs no rewiring.
"""

import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from cloud_infra_agent.state import AgentState, AuditEvent
from cloud_infra_agent.cost_tools import cost_estimate
from cloud_infra_agent.scan_tools import security_scan
from cloud_infra_agent.terraform_tools import validate_terraform
from cloud_infra_agent.tools import retrieve_patterns

load_dotenv()  # reads OPENAI_API_KEY (and the rest) from your .env

TOOLS = [retrieve_patterns, validate_terraform, security_scan, cost_estimate]

# temperature=0: as deterministic as the model allows. For infrastructure code we want
# the same request to produce the same answer, not creative variation.
llm = ChatOpenAI(model="gpt-4o", temperature=0)

# bind_tools() sends each tool's name, argument types and docstring to the model with
# every request. That is how the LLM knows retrieve_patterns exists and how to call it.
llm_with_tools = llm.bind_tools(TOOLS)

# The system prompt is the agent's job description. It replaces the old parse_intent and
# generate_terraform nodes: the LLM does both inside its own reasoning.
SYSTEM_PROMPT = """You are a cloud infrastructure agent that turns plain-language requests \
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
6. For every value the user states (environment, region, purpose, project name and so on), \
set it as that variable's `default` in the HCL. Example: "dev environment" means \
`variable "environment" { type = string, default = "dev" }` written across multiple lines. \
Values the user did NOT state (such as owner or cost_center) stay without a default; list \
them at the end as values still needed.
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
    step. If the LLM asked for a tool, run it. If not, the agent has finished.
    """
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "tools"
    return END


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("agent", agent_node)
    # ToolNode is prebuilt: it looks at the LLM's tool-call request, runs the matching
    # Python function, and appends the result to messages as a ToolMessage.
    graph.add_node("tools", ToolNode(TOOLS))

    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")  # the loop: after a tool runs, the agent sees the result

    return graph.compile()


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.agent
    app = build_graph()
    request = "Create a private S3 bucket for audit logs in the dev environment, in eu-west-1."

    # recursion_limit is a safety net: LangGraph aborts if the loop takes more than this
    # many steps, so a confused agent can't spin forever.
    result = app.invoke(
        {"messages": [("user", request)], "user_request": request},
        config={"recursion_limit": 25},  # room for: lookup, validate, scan, fixes, re-checks
    )

    print("=== Audit trail ===")
    for e in result["audit_trail"]:
        print(f"  {e['node']:<8} {e['event']:<20} {e['detail']}")
    print("\n=== Final HCL ===")
    print(result["generated_hcl"] or "(none extracted)")
    print("\n=== Full final message ===")
    print(result["messages"][-1].content)