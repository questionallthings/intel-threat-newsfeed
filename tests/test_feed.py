"""Tests for feed parsing.

Weighted towards the two properties that carry real consequences: excerpts must
never contain a full article, and the same article from two sources must dedupe
to one row.
"""

from datetime import datetime, timedelta, timezone

import pytest

from newsfeed.feed import (
    EXCERPT_CHARS,
    FeedError,
    _clean,
    article_id,
    canonical_url,
    parse,
)
from newsfeed.sources import Source

SOURCE = Source(id="test", name="Test Source", url="https://example.com/feed")

LONG_BODY = "Attackers exploited the flaw. " * 200  # ~6000 chars


def rss(items: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Test</title>
    {items}
  </channel>
</rss>""".encode()


def rss_item(
    title="Critical flaw in widget",
    link="https://example.com/post",
    pub_date=None,
    description="A short summary of the advisory.",
    content=None,
) -> str:
    pub_date = pub_date or _rfc822(datetime.now(timezone.utc))
    content_el = f"<content:encoded><![CDATA[{content}]]></content:encoded>" if content else ""
    return f"""<item>
      <title>{title}</title>
      <link>{link}</link>
      <pubDate>{pub_date}</pubDate>
      <description><![CDATA[{description}]]></description>
      {content_el}
    </item>"""


def _rfc822(moment: datetime) -> str:
    return moment.strftime("%a, %d %b %Y %H:%M:%S +0000")


# --- the copyright-critical behaviour ------------------------------------


def test_excerpt_is_truncated_even_when_feed_ships_full_text():
    raw = rss(rss_item(description=LONG_BODY, content=LONG_BODY))
    (article,) = parse(SOURCE, raw)

    assert len(article.excerpt) <= EXCERPT_CHARS + 1  # +1 for the ellipsis
    assert len(article.excerpt) < len(LONG_BODY)
    assert article.excerpt.endswith("…")


def test_summary_is_preferred_over_full_content():
    raw = rss(rss_item(description="Short summary.", content=LONG_BODY))
    (article,) = parse(SOURCE, raw)

    assert article.excerpt == "Short summary."


def test_excerpt_strips_markup():
    raw = rss(rss_item(description="<p>Hello <b>world</b></p><script>alert(1)</script>"))
    (article,) = parse(SOURCE, raw)

    assert "<" not in article.excerpt
    assert "script" not in article.excerpt.lower()
    assert "Hello world" in article.excerpt


def test_clean_truncates_on_a_word_boundary():
    result = _clean("alpha beta gamma delta", limit=12)
    assert result == "alpha beta…"


def test_platform_boilerplate_is_stripped_from_excerpts():
    raw = rss(
        rss_item(
            description=(
                "Identity-based attacks drive most incidents. "
                "The post Inside the Modern SOC appeared first on Unit 42."
            )
        )
    )
    (article,) = parse(SOURCE, raw)

    assert "appeared first on" not in article.excerpt
    assert article.excerpt == "Identity-based attacks drive most incidents."


def test_boilerplate_is_stripped_before_truncation():
    # The tail must be removed first, or it eats into the excerpt budget and
    # the reader loses real content to platform noise.
    body = "Real content. " * 15  # ~210 chars
    raw = rss(rss_item(description=f"{body}The post X appeared first on Y."))
    (article,) = parse(SOURCE, raw)

    assert "appeared first on" not in article.excerpt
    assert article.excerpt.count("Real content.") == 15


def test_titles_keep_their_wording():
    # Boilerplate stripping applies to excerpts only; a title that happens to
    # contain similar phrasing must not be mangled.
    raw = rss(rss_item(title="Continue reading is a bad UX pattern"))
    (article,) = parse(SOURCE, raw)

    assert article.title == "Continue reading is a bad UX pattern"


# --- deduplication --------------------------------------------------------


def test_canonical_url_strips_tracking_parameters():
    assert (
        canonical_url("https://Example.com/post/?utm_source=twitter&id=7&fbclid=xyz")
        == "https://example.com/post?id=7"
    )


def test_same_article_with_different_tracking_gets_one_id():
    a = article_id(canonical_url("https://example.com/post?utm_campaign=a"))
    b = article_id(canonical_url("https://example.com/post/?utm_campaign=b"))
    assert a == b


def test_non_http_schemes_are_rejected():
    assert canonical_url("javascript:alert(1)") is None
    assert canonical_url("ftp://example.com/x") is None


# --- retention ------------------------------------------------------------


def test_articles_older_than_retention_window_are_dropped():
    old = _rfc822(datetime.now(timezone.utc) - timedelta(days=45))
    raw = rss(rss_item(pub_date=old))
    assert parse(SOURCE, raw) == []


def test_ttl_is_derived_from_publication_not_ingestion():
    published = datetime.now(timezone.utc) - timedelta(days=10)
    raw = rss(rss_item(pub_date=_rfc822(published)))
    (article,) = parse(SOURCE, raw)

    # Expiry must be 30 days after publication, so re-ingesting an article that
    # keeps appearing in the feed cannot extend its life indefinitely.
    assert (article.expires_at - article.published_at) == timedelta(days=30)
    assert article.expires_at < datetime.now(timezone.utc) + timedelta(days=21)


# --- robustness against hostile or broken input ---------------------------


def test_one_bad_entry_does_not_lose_the_feed():
    good = rss_item(title="Good", link="https://example.com/good")
    broken = "<item><title>No link or date</title></item>"
    articles = parse(SOURCE, rss(good + broken))

    assert [a.title for a in articles] == ["Good"]


def test_malformed_xml_raises_feed_error():
    with pytest.raises(FeedError):
        parse(SOURCE, b"<rss><channel><item>unclosed")


def test_unrecognised_document_raises_feed_error():
    with pytest.raises(FeedError):
        parse(SOURCE, b"<html><body>not a feed</body></html>")


def test_atom_entries_are_parsed():
    now = datetime.now(timezone.utc).isoformat()
    raw = f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Test</title>
  <entry>
    <title>Atom post</title>
    <link rel="alternate" href="https://example.com/atom-post"/>
    <published>{now}</published>
    <summary>Summary text.</summary>
  </entry>
</feed>""".encode()

    (article,) = parse(SOURCE, raw)
    assert article.title == "Atom post"
    assert article.link == "https://example.com/atom-post"
    assert article.excerpt == "Summary text."
