"""state.py — the shared "whiteboard" every node in the graph reads from and writes to.

WHY typed state (LangGraph concept: StateGraph + TypedDict):
    A LangGraph graph is a set of nodes (plain functions). They don't call each other or
    pass arguments around. Instead each node receives the CURRENT STATE, does its work,
    and returns a small dict of the fields it wants to UPDATE. LangGraph merges that
    update into the state and hands the result to the next node. The TypedDict below is
    the contract: which fields exist and what type they hold.

WHY reducers (Annotated[..., reducer]):
    By default a returned field REPLACES the old value. For some fields we want to
    ACCUMULATE instead. A reducer says how to merge old + new:
      - operator.add    -> list concatenation:  audit_trail grows, nothing is lost
      - add_messages    -> appends messages (and updates one if the id matches)
"""

import operator
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class AuditEvent(TypedDict):
    timestamp: str
    node: str
    event: str
    detail: str


class GuardrailVerdict(TypedDict):
    passed: bool
    violations: list[str]
    warnings: list[str]  # shown to the human approver but don't block
    retryable: bool  # False = the agent can't fix this (scanner down, no code produced)
    decision: Literal["approve", "retry", "drop"]  # what the router will do


class AgentState(TypedDict):
    # --- Conversation history for the ReAct loop. ---
    # The agent and the tools talk to each other through messages: the LLM's replies
    # (including "please call this tool"), and the tool results. Without this field the
    # loop has no memory of what it already asked or learned.
    messages: Annotated[list[AnyMessage], add_messages]

    # --- Workflow fields ---
    user_request: str
    generated_hcl: str
    validation_result: dict
    security_findings: list[dict]
    cost_estimate: dict
    guardrail_result: GuardrailVerdict
    retry_count: int
    approval_status: Literal["pending", "approved", "rejected", "expired"]
    execution_result: dict
    audit_trail: Annotated[list[AuditEvent], operator.add]  # reducer: append, never overwrite
