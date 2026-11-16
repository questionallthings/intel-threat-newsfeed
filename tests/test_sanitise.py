"""Tests for XML illegal-byte removal and the rendered page.

Both exist because of problems found in live feeds, not hypotheticals: the
SOCRadar feed carries a literal vertical tab inside a code sample, which made an
otherwise valid 277 KB feed unparseable.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from newsfeed import render
from newsfeed.feed import _strip_illegal_bytes, parse
from newsfeed.sources import Source

SOURCE = Source(id="test", name="Test Source", url="https://example.test/feed")


def _rss(description: bytes) -> bytes:
    # The date has to be recent: parse() drops anything already outside the
    # 30-day retention window, so a hardcoded date makes this test rot.
    published = format_datetime(datetime.now(timezone.utc) - timedelta(hours=1))
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<rss version=\"2.0\"><channel><item>"
        b"<title>A headline</title>"
        b"<link>https://example.test/article</link>"
        b"<pubDate>" + published.encode("ascii") + b"</pubDate>"
        b"<description>" + description + b"</description>"
        b"</item></channel></rss>"
    )


def test_vertical_tab_is_removed():
    """0x0B is what actually broke the SOCRadar feed."""
    cleaned, removed = _strip_illegal_bytes(b"cmd /\x0balias add")
    assert cleaned == b"cmd /alias add"
    assert removed == 1


def test_tab_newline_and_carriage_return_are_preserved():
    """These three are the only C0 characters XML 1.0 permits."""
    raw = b"a\tb\nc\r\nd"
    cleaned, removed = _strip_illegal_bytes(raw)
    assert cleaned == raw
    assert removed == 0


def test_every_illegal_control_byte_is_removed():
    illegal = bytes(b for b in range(0x20) if b not in (0x09, 0x0A, 0x0D))
    cleaned, removed = _strip_illegal_bytes(b"x" + illegal + b"y")
    assert cleaned == b"xy"
    assert removed == len(illegal)


def test_printable_and_multibyte_content_is_untouched():
    raw = "ASCII, accents: Zoë, CJK: 日本語, emoji: 🙂".encode("utf-8")
    cleaned, removed = _strip_illegal_bytes(raw)
    assert cleaned == raw
    assert removed == 0


def test_a_feed_with_an_illegal_byte_still_parses():
    articles = parse(SOURCE, _rss(b"Run cmd /\x0balias to continue"))
    assert len(articles) == 1
    assert articles[0].title == "A headline"


def test_sanitising_does_not_alter_a_valid_feed():
    valid = _rss(b"Nothing unusual here")
    assert parse(SOURCE, valid)[0].excerpt == "Nothing unusual here"


class _FakeConn:
    """Stands in for a connection; render only reads through store.query_recent."""


def test_embedded_data_escapes_angle_brackets(monkeypatch):
    """A title containing </script> must not break out of the data block.

    Titles are third-party text. Without escaping, one containing a closing
    script tag would end the element early and the rest would be parsed as
    markup.
    """
    hostile = '</script><img src=x onerror=alert(1)>'
    monkeypatch.setattr(
        render.store,
        "query_recent",
        lambda conn, days=30, limit=500: [
            {
                "id": "x",
                "source_id": "test",
                "source_name": "Test",
                "title": hostile,
                "link": "https://example.test/a",
                "excerpt": "",
                "severity": "medium",
                "severity_signals": [],
                "published_at": "2025-11-05T12:00:00+00:00",
            }
        ],
    )

    document = render.build_document(_FakeConn())
    embedded = render._embed(document)

    assert "</script" not in embedded.lower()
    assert "\\u003c" in embedded
    # The data must still be intact once parsed -- escaping, not mangling.
    assert json.loads(embedded)["articles"][0]["title"] == hostile


def test_rendered_page_is_self_contained(tmp_path, monkeypatch):
    monkeypatch.setattr(
        render.store, "query_recent", lambda conn, days=30, limit=500: []
    )
    path, count = render.write_html(_FakeConn(), tmp_path / "out.html")
    html = path.read_text(encoding="utf-8")

    assert count == 0
    # No external stylesheets, scripts, images or fonts: the page must work
    # offline and must not phone home.
    external = [
        url
        for url in re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
        if "github.com/questionallthings" not in url
    ]
    assert external == [], f"page references external resources: {external}"
    assert "__FEED_DATA__" not in html, "placeholder was not substituted"
