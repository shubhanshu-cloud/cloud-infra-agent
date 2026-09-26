"""graph.py — wires the nodes into the full workflow and runs it.

    START -> agent <-> tools            the ReAct loop (agent.py)
                |
                v  (agent has finished)
          guardrail_check               deterministic gate (guardrail.py)
           |       |        |
       approve   retry    drop          a 3-way CONDITIONAL EDGE
           |       |        |
   approval_gate  agent   audit_log     retry loops back, carrying the violations as feedback
           |                |
          END              END

approval_gate and audit_log below are STUBS so the routing can be exercised end to end.
They will be replaced by the real nodes (interrupt() approval, DynamoDB + S3 audit).
"""

import sys
from datetime import datetime, timezone

from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from cloud_infra_agent.agent import TOOLS, agent_node, should_continue
from cloud_infra_agent.guardrail import MAX_RETRIES, guardrail_check, route_after_guardrail
from cloud_infra_agent.state import AgentState, AuditEvent


def _event(node: str, event: str, detail: str = "") -> AuditEvent:
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "node": node, "event": event, "detail": detail}


def approval_gate(state: AgentState) -> dict:
    """STUB: the real node will interrupt() and wait for a human."""
    return {"approval_status": "pending", "audit_trail": [_event("approval_gate", "reached", "stub: would ask a human now")]}


def audit_log(state: AgentState) -> dict:
    """STUB: the real node will write to DynamoDB + S3. Every non-approved path ends here."""
    if not state.get("generated_hcl"):
        outcome = "no_output"  # the agent refused or asked a question
    else:
        outcome = "dropped"
    return {"audit_trail": [_event("audit_log", "run_ended", outcome)]}


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(TOOLS))
    graph.add_node("guardrail_check", guardrail_check)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("audit_log", audit_log)

    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", "guardrail_check": "guardrail_check"})
    graph.add_edge("tools", "agent")
    graph.add_conditional_edges(
        "guardrail_check",
        route_after_guardrail,
        {"approval_gate": "approval_gate", "agent": "agent", "audit_log": "audit_log"},
    )
    graph.add_edge("approval_gate", END)
    graph.add_edge("audit_log", END)
    return graph.compile()


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.graph
    # uv run python -m cloud_infra_agent.graph "Create an S3 bucket for logs in us-east-1"
    app = build_graph()
    request = sys.argv[1] if len(sys.argv) > 1 else (
        "Create a private S3 bucket for audit logs in the dev environment, in eu-west-1."
    )
    result = app.invoke(
        {"messages": [("user", request)], "user_request": request, "retry_count": 0},
        # Every retry re-runs lookup, validate, scan and cost, so leave generous room.
        config={"recursion_limit": 60},
    )

    print("=== Audit trail ===")
    for e in result["audit_trail"]:
        print(f"  {e['node']:<16} {e['event']:<22} {e['detail'][:110]}")

    verdict = result.get("guardrail_result", {})
    print(f"\n=== Guardrail: {verdict.get('decision', '?').upper()} (retries used: {result.get('retry_count', 0)} of {MAX_RETRIES}) ===")
    for v in verdict.get("violations", []):
        print(f"  VIOLATION {v[:160]}")
    for w in verdict.get("warnings", []):
        print(f"  warning   {w[:160]}")

    cost = result.get("cost_estimate") or {}
    if cost.get("ok"):
        print(f"\nEstimated cost: ₹{cost['monthly_inr']}/month (ceiling ₹{cost['ceiling_inr']})")
    print("\n=== Final message from the agent (first 400 chars) ===")
    print(result["messages"][-1].content[:400])
