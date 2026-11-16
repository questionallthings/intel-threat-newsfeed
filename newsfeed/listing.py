"""Generate newsfeed-list.txt, the plain-text source list.

The file lives at the repository root so it is easy to find without digging
through docs/, and it is **generated** from ``sources.py`` rather than
maintained by hand. A hand-written list of fourteen URLs drifts the first time
someone changes a feed address and forgets the second copy; a generated one
cannot, and ``tests/test_listing.py`` fails if the committed file is stale.
"""

from __future__ import annotations

from pathlib import Path

from .sources import SOURCES

HEADER = """THREAT INTELLIGENCE NEWSFEED - SOURCE LIST
==========================================

The {count} sources this tool aggregates, with the site to visit and the feed it
reads. Ids are what `--source` takes, for polling one feed at a time.

Generated from newsfeed/sources.py. Do not edit by hand -- run:

    python3 run.py --write-list

Licence basis, robots.txt position and full-text status for each source are
recorded in docs/SOURCES.md. Nothing is fetched that is not documented there.
"""

FOOTER = """
RETENTION
---------

Headline, publisher, publication date, link and a ~300 character excerpt only.
Full article text is never stored, even where a feed provides it. Everything is
deleted after 30 days, measured from an article's publication date.

Content remains the copyright of the publisher. This tool links to the original.
"""


def render_listing() -> str:
    """Return the full text of the source list."""
    lines = [HEADER.format(count=len(SOURCES))]

    for index, source in enumerate(SOURCES, start=1):
        lines.append(f"{index:>2}. {source.name}")
        lines.append(f"    Website  {source.site_url or '(none recorded)'}")
        lines.append(f"    Feed     {source.url}")
        detail = source.id
        if source.full_text_feed:
            # Worth stating: these are the feeds where truncation is doing real
            # work rather than being a no-op.
            detail += "   (ships full article text; excerpts are truncated)"
        lines.append(f"    Id       {detail}")
        lines.append("")

    lines.append(FOOTER.rstrip())
    lines.append("")
    return "\n".join(lines)


def write_listing(path: Path) -> Path:
    """Write the source list. Newlines are forced to LF to match .gitattributes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_listing())
    return path
