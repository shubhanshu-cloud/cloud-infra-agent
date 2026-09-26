"""store.py — embeds chunks, stores them in Chroma, and searches them.

Three jobs, in the order they happen:

  1. EMBED   (sentence-transformers): text -> vector ("fingerprint of meaning").
             Similar meaning = nearby vectors. This is the ONLY place a model is used.
  2. STORE   (Chroma): keeps [vector + full text + metadata] together on disk.
  3. SEARCH  (Chroma): embed the question, find the nearest stored vectors, and hand
             back the stored full text.

Note who does what: the embedding model only makes fingerprints. It never returns text.
Chroma does the comparing and returns the "book" we stored next to each fingerprint.
"""

from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

from cloud_infra_agent.loader import load_all_chunks

DB_DIR = Path(__file__).resolve().parents[2] / ".chroma"  # rebuildable, keep out of git
COLLECTION_NAME = "infra_knowledge"

# Small (~90 MB), runs on CPU, downloads once and is cached. Limit: ~256 tokens per
# input, which is exactly why we embed the short search_text and not the full HCL.
MODEL_NAME = "all-MiniLM-L6-v2"

# Loading the model takes a couple of seconds, so do it once and reuse it.
_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def _get_collection(reset: bool = False):
    """A Chroma 'collection' is like a table: vectors + text + metadata."""
    client = chromadb.PersistentClient(path=str(DB_DIR))
    if reset:
        try:
            client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass  # nothing to delete on the first run
    # cosine distance: 0 = identical meaning, larger = less similar.
    return client.get_or_create_collection(COLLECTION_NAME, metadata={"hnsw:space": "cosine"})


def build_index() -> int:
    """(Re)build the whole index from the kb/ files. Cheap at this size, so we always
    rebuild from scratch: the index can never drift out of sync with the files."""
    chunks = load_all_chunks()
    if not any(c.metadata["type"] == "module" for c in chunks):
        # Fail loudly: a silently missing module means the agent quietly knows less.
        raise RuntimeError("No module chunks found. Is kb/modules/ populated?")

    collection = _get_collection(reset=True)
    # EMBED the short card...
    vectors = _get_model().encode([c.search_text for c in chunks]).tolist()
    # ...but STORE the full book next to it (documents=).
    collection.add(
        ids=[c.id for c in chunks],
        embeddings=vectors,
        documents=[c.text for c in chunks],
        metadatas=[c.metadata for c in chunks],
    )
    return len(chunks)


def ensure_index() -> None:
    """Build the index only if it doesn't exist yet. Note: if you edit files in kb/,
    rebuild with `uv run python -m cloud_infra_agent.store` (this check can't see edits)."""
    if _get_collection().count() == 0:
        build_index()


def get_chunks(ids: list[str]) -> list[dict]:
    """Fetch specific chunks by id: a direct lookup, no similarity search involved.
    Used for rules that must ALWAYS reach the agent whatever the query says."""
    result = _get_collection().get(ids=ids)
    found = {
        id_: (doc, meta)
        for id_, doc, meta in zip(result["ids"], result["documents"], result["metadatas"])
    }
    # distance=None marks "not from a similarity search"; keeps the requested order.
    return [
        {"id": i, "distance": None, "text": found[i][0], "metadata": found[i][1]}
        for i in ids
        if i in found
    ]


def search(query: str, n_results: int = 3, chunk_type: str | None = None) -> list[dict]:
    """Find the chunks whose meaning is closest to the query.

    chunk_type: optionally restrict to "module" or "standard" (uses the metadata).
    """
    collection = _get_collection()
    query_vector = _get_model().encode([query]).tolist()
    result = collection.query(
        query_embeddings=query_vector,
        n_results=n_results,
        where={"type": chunk_type} if chunk_type else None,
    )
    # Chroma returns parallel lists (one inner list per query); we sent one query.
    return [
        {"id": id_, "distance": round(dist, 3), "text": doc, "metadata": meta}
        for id_, dist, doc, meta in zip(
            result["ids"][0],
            result["distances"][0],
            result["documents"][0],
            result["metadatas"][0],
        )
    ]


if __name__ == "__main__":
    # Build the index, then try three questions:  uv run python -m cloud_infra_agent.store
    print(f"Indexed {build_index()} chunks\n")
    for question in [
        "I need somewhere to store audit logs",
        "what tags are required?",
        "can I deploy in us-east-1?",
    ]:
        print(f"Q: {question}")
        for hit in search(question, n_results=3):
            print(f"   {hit['distance']:.3f}  {hit['id']}")
        print()