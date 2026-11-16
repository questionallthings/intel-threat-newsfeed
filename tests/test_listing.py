"""Tests for the generated source list.

The important one is test_committed_listing_is_current: it is what stops
newsfeed-list.txt silently drifting away from sources.py after someone changes a
feed URL. Without it, the file is just a second copy of the truth that nobody
remembers to update.
"""

from pathlib import Path

from newsfeed import listing
from newsfeed.sources import SOURCES

ROOT = Path(__file__).resolve().parent.parent
COMMITTED = ROOT / "newsfeed-list.txt"


def test_every_source_has_a_website_recorded():
    missing = [s.id for s in SOURCES if not s.site_url]
    assert missing == [], f"sources without site_url: {missing}"


def test_website_urls_are_https():
    """A threat intelligence tool should not send readers to plain HTTP."""
    bad = [s.id for s in SOURCES if not s.site_url.startswith("https://")]
    assert bad == [], f"sources with a non-HTTPS site_url: {bad}"


def test_listing_contains_every_source():
    text = listing.render_listing()
    for source in SOURCES:
        assert source.name in text, f"{source.name} missing from the listing"
        assert source.site_url in text, f"{source.id} website missing"
        assert source.url in text, f"{source.id} feed URL missing"
        assert source.id in text, f"{source.id} id missing"


def test_listing_numbers_every_source():
    text = listing.render_listing()
    for index in range(1, len(SOURCES) + 1):
        assert f"{index:>2}. " in text


def test_listing_states_the_source_count():
    assert str(len(SOURCES)) in listing.render_listing()


def test_listing_marks_full_text_feeds():
    text = listing.render_listing()
    full_text = [s for s in SOURCES if s.full_text_feed]
    assert full_text, "fixture assumption: at least one feed ships full text"
    assert text.count("ships full article text") == len(full_text)


def test_committed_listing_is_current():
    """Fails when newsfeed-list.txt is stale. Regenerate with --write-list."""
    assert COMMITTED.exists(), "newsfeed-list.txt is missing from the repository root"
    on_disk = COMMITTED.read_text(encoding="utf-8")
    assert on_disk == listing.render_listing(), (
        "newsfeed-list.txt does not match sources.py.\n"
        "Regenerate it with:  python3 run.py --write-list"
    )


def test_write_listing_uses_lf_newlines(tmp_path):
    """.gitattributes normalises the repository to LF; the writer must match."""
    path = listing.write_listing(tmp_path / "list.txt")
    assert b"\r\n" not in path.read_bytes()
