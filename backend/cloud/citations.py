"""Citation verification for forensics reports.

A citation is only accepted when the referenced file and line exist *and* the
quoted excerpt actually appears on that line. This is the guard against an LLM
inventing a log line to look convincing.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Citation, CitationCheck


def _normalize(text: str) -> str:
    return " ".join(text.split()).lower()


def read_line(path: Path, line: int) -> str | None:
    if line < 1:
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, content in enumerate(handle, start=1):
                if index == line:
                    return content.rstrip("\n")
    except (OSError, UnicodeError):
        return None
    return None


def excerpt_matches(line_text: str, excerpt: str) -> bool:
    normalized_line = _normalize(line_text)
    normalized_excerpt = _normalize(excerpt)
    if not normalized_excerpt:
        return False
    if "..." in normalized_excerpt:
        parts = [part.strip() for part in normalized_excerpt.split("...") if part.strip()]
        cursor = 0
        for part in parts:
            found = normalized_line.find(part, cursor)
            if found == -1:
                return False
            cursor = found + len(part)
        return True
    return normalized_excerpt in normalized_line


def verify_citation(citation: Citation, root: Path) -> CitationCheck:
    candidate = Path(citation.log_file)
    path = candidate if candidate.is_absolute() else root / candidate
    line_text = read_line(path, citation.line)
    if line_text is None:
        return CitationCheck(
            citation=citation,
            exists=False,
            excerpt_matches=False,
            detail=f"file or line not found: {path}:{citation.line}",
        )
    matches = excerpt_matches(line_text, citation.excerpt)
    return CitationCheck(
        citation=citation,
        exists=True,
        excerpt_matches=matches,
        detail="ok" if matches else f"excerpt not found on line: {line_text[:160]!r}",
    )


def verify_citations(citations: list[Citation], root: Path) -> list[CitationCheck]:
    return [verify_citation(citation, root) for citation in citations]
