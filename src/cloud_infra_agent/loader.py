"""loader.py — turns the kb/ markdown files into chunks ready for embedding.

WHY this step exists (RAG concept: chunking):
    An embedding model turns text into ONE vector. If we embedded a whole 200-line
    document as one vector, that vector would be a blurry average of everything in it,
    and a question about "tagging" would match weakly. If we cut it into pieces where
    each piece is about ONE topic, each vector is sharp and retrieval returns exactly
    the relevant piece.

    Our chunking rules (deliberately simple):
      - modules/*.md   -> ONE chunk per file. A Terraform template is only useful whole;
                          half a template is worse than none.
      - standards.md   -> ONE chunk per "## " heading (Tagging, Naming, Regions, ...).
                          Headings already mark topic boundaries, so we reuse them.

    This module is plain string handling; embedding happens in store.py.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml

# Default location of the knowledge base: <repo>/kb  (this file is <repo>/src/cloud_infra_agent/)
DEFAULT_KB_DIR = Path(__file__).resolve().parents[2] / "kb"


@dataclass
class Chunk:
    """One retrievable piece of knowledge.

    search_text -> the "catalog card": short text that gets EMBEDDED (fingerprinted).
                   Embedding models only read ~256 tokens, so this must be short and
                   describe what the chunk is FOR.
    text        -> the "book": full content handed back to the agent after a match.
    metadata    -> labels stored next to the vector; lets us filter later
                   (e.g. "only give me modules") and cite the source.
    id          -> unique key so re-indexing replaces a chunk instead of duplicating it

    For short chunks (standards) search_text == text. For long chunks (modules) the
    card is a short description while the book is the full Terraform.
    """

    id: str
    text: str
    search_text: str
    metadata: dict


def _split_frontmatter(raw: str) -> tuple[dict, str]:
    """Split a markdown file into (frontmatter dict, body).

    Frontmatter is the block between two '---' lines at the top of the file:

        ---
        resource: s3
        ---
        # body starts here

    Files without frontmatter (like standards.md) return ({}, whole file).
    """
    if not raw.startswith("---"):
        return {}, raw
    # split into at most 3 parts: '' | frontmatter | body
    _, fm, body = raw.split("---", 2)
    return yaml.safe_load(fm) or {}, body.strip()


def load_module_chunks(kb_dir: Path) -> list[Chunk]:
    """One chunk per file in kb/modules/."""
    chunks = []
    for path in sorted((kb_dir / "modules").glob("*.md")):
        meta, body = _split_frontmatter(path.read_text())
        # Chroma metadata values must be str/int/float/bool, so lists become
        # comma-separated strings.
        clean = {k: ", ".join(v) if isinstance(v, list) else v for k, v in meta.items()}
        clean.update({"type": "module", "source": path.name})
        # The catalog card = everything BEFORE the "## Terraform" heading (title, "Use for",
        # "When to pick this pattern") plus the tags_covered keywords from frontmatter.
        # The HCL itself is deliberately left out of the card.
        description = body.split("## Terraform")[0].strip()
        search_text = f"{description}\nCovers: {clean.get('tags_covered', '')}"
        chunks.append(
            Chunk(id=f"module:{path.stem}", text=body, search_text=search_text, metadata=clean)
        )
    return chunks


def _policy_facts(kb_dir: Path) -> dict[str, str]:
    """Concrete values from policies.yaml, keyed by the standards section they belong to.

    WHY: standards.md says "only regions in policies.yaml are allowed" but never lists
    them, so the agent had a rule with no values and guessed (it refused a valid region).
    We inject the values at index time instead of copying them into standards.md, so
    policies.yaml stays the single source of truth and the two can never drift apart.
    """
    policy = yaml.safe_load((kb_dir / "policies.yaml").read_text())
    return {
        "Regions": "Allowed regions: "
        + ", ".join(policy["allowed_regions"])
        + ". Any region not in this list is NOT allowed.",
        "Cost": f"Monthly cost ceiling: INR {policy['cost_ceiling']['max_monthly_inr']}.",
    }


def load_standards_chunks(kb_dir: Path) -> list[Chunk]:
    """One chunk per '## ' section of standards.md."""
    raw = (kb_dir / "standards.md").read_text()
    facts = _policy_facts(kb_dir)
    chunks = []
    # Splitting on "\n## " drops that marker from each piece; we put "## " back below.
    # Piece 0 is everything before the first "## " (title + intro), so we skip it.
    for section in raw.split("\n## ")[1:]:
        heading, _, body = section.partition("\n")
        heading = heading.strip()
        # Keep the heading INSIDE the text: "Tagging" is exactly the word a user's
        # question is likely to contain, so it helps the embedding match.
        text = f"## {heading}\n{body.strip()}"
        if heading in facts:
            text += f"\n- {facts[heading]}"
        chunks.append(
            Chunk(
                id=f"standard:{heading.lower().replace(' ', '-')}",
                text=text,
                search_text=text,  # already short, so card == book
                metadata={"type": "standard", "source": "standards.md", "section": heading},
            )
        )
    return chunks


def load_all_chunks(kb_dir: Path = DEFAULT_KB_DIR) -> list[Chunk]:
    """Everything the agent can retrieve from."""
    return load_module_chunks(kb_dir) + load_standards_chunks(kb_dir)


if __name__ == "__main__":
    # Quick look at what the loader produces:  uv run python -m cloud_infra_agent.loader
    for c in load_all_chunks():
        print(f"{c.id:<28} card={len(c.search_text):>4} chars  book={len(c.text):>4} chars")
