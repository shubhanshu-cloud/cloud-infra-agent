"""tools.py — the functions the LangGraph agent is allowed to call.

WHY a tool (agentic-AI concept: tool calling / ReAct):
    The agent is an LLM. On its own it can only produce text. A "tool" is a normal
    Python function that we describe to the LLM (name, docstring, argument types).
    When the LLM decides it needs something, it replies "call retrieve_patterns with
    query=...". LangGraph's ToolNode runs the function and feeds the result back, and
    the LLM continues. That reason -> act -> observe loop is what ReAct means.

    Retrieval is a TOOL rather than a fixed pipeline step, so the agent chooses WHEN to
    look things up, and can look again (e.g. after the guardrail rejects its first try).
"""

from langchain_core.tools import tool

from cloud_infra_agent.store import ensure_index, get_chunks, search

N_MODULES = 1  # one template is usually enough; more just adds noise for the LLM
N_STANDARDS = 3  # rules are short, so a few relevant ones are cheap to include

# Vector search ALWAYS returns the nearest neighbours, however far away they are; it has
# no sense of "nothing relevant". So we add one: hits with distance above this are
# dropped. Calibrated on 7 chunks with all-MiniLM-L6-v2 (correct matches scored
# 0.59-0.72, irrelevant ones 0.91-0.96). Recalibrate when templates are added or the
# embedding model changes.
MAX_DISTANCE = 0.85

# Rules that apply to EVERY request, whatever the wording. Similarity search is the wrong
# tool for these: nobody phrases "create a bucket" like "allowed regions", so the regions
# rule ranked last of six in a similarity search (distance 0.847). They are fetched by id
# instead. They are also the rules guardrail_check enforces, so the agent must always see them.
PINNED_STANDARDS = ["standard:tagging", "standard:regions", "standard:security-defaults"]


def retrieve_hits(query: str) -> list[dict]:
    """Three sources, combined.

    1. modules   (similarity) - WHAT do I build? One template, only if close enough.
    2. pinned    (by id)      - rules that ALWAYS apply: tagging, regions, security.
    3. extras    (similarity) - other standards relevant to this query (naming, cost...).

    Searching modules and standards separately means a standards chunk can never crowd
    the template out of the results.
    """
    ensure_index()
    # Returning nothing is better than returning noise the LLM might try to use.
    modules = [
        h for h in search(query, N_MODULES, chunk_type="module") if h["distance"] <= MAX_DISTANCE
    ]
    pinned = get_chunks(PINNED_STANDARDS)
    # Ask for extra results because some will be pinned ones we already have.
    candidates = search(query, N_STANDARDS + len(PINNED_STANDARDS), chunk_type="standard")
    extras = [h for h in candidates if h["id"] not in PINNED_STANDARDS and h["distance"] <= MAX_DISTANCE]
    return modules + pinned + extras[:N_STANDARDS]


# The @tool decorator turns the function into something an LLM can call. The LLM sees
# ONLY the function name, the argument types and THIS DOCSTRING, so the docstring is
# effectively a prompt: write it for the model, not for humans.
@tool
def retrieve_patterns(query: str) -> str:
    """Look up approved Terraform templates and infrastructure standards.

    Call this BEFORE writing any Terraform, and again if a guardrail check fails and
    you need to re-check a rule. Returns one vetted module template plus the most
    relevant standards (tagging, naming, regions, security, cost).

    Args:
        query: What you need, in plain words, e.g. "private S3 bucket for audit logs"
               or "required tags". Mention the resource type for best results.
    """
    hits = retrieve_hits(query)
    if not any(h["id"].startswith("module:") for h in hits):
        note = "NOTE: no matching module template was found for this query. Do not guess a template; say so or try rephrasing.\n\n---\n\n"
    else:
        note = ""
    # The tool must return a STRING: that is what goes back into the LLM's context.
    # Pinned standards are labelled so the LLM treats them as mandatory.
    body = "\n\n---\n\n".join(
        f"[{h['id']}]{' (MANDATORY)' if h['id'] in PINNED_STANDARDS else ''}\n{h['text']}"
        for h in hits
    )
    return note + body


if __name__ == "__main__":
    # uv run python -m cloud_infra_agent.tools
    for question in [
        "I need somewhere to store audit logs",
        "what tags are required?",
        "can I deploy in us-east-1?",
    ]:
        print(f"Q: {question}")
        for h in retrieve_hits(question):
            dist = "pinned" if h["distance"] is None else f"{h['distance']:.3f}"
            print(f"   {dist:>6}  {h['id']}")
        print()
    # .invoke() is how LangChain calls a tool, the same way ToolNode does.
    print("--- what the agent actually receives (first 400 chars) ---")
    print(retrieve_patterns.invoke({"query": "private S3 bucket for audit logs"})[:400])
