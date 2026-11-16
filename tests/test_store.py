"""Tests for the SQLite store.

The retention guarantees are the point here. In the hosted version DynamoDB
enforced expiry itself; locally it is this module's job, so the rules that were
previously the database's responsibility need covering explicitly.
"""

from datetime import datetime, timedelta, timezone

import pytest

from newsfeed import store
from newsfeed.feed import Article


def _article(article_id="a1", *, published=None, title="Title", severity="medium"):
    return Article(
        id=article_id,
        source_id="cisa",
        source_name="CISA Advisories",
        title=title,
        link=f"https://example.test/{article_id}",
        excerpt="An excerpt.",
        published_at=published or datetime.now(timezone.utc),
        severity=severity,
        severity_signals=("kev",),
    )


@pytest.fixture()
def conn(tmp_path):
    connection = store.connect(tmp_path / "test.db")
    yield connection
    connection.close()


def test_schema_is_created_on_connect(conn):
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"articles", "source_state"} <= tables


def test_connect_creates_missing_parent_directory(tmp_path):
    nested = tmp_path / "does" / "not" / "exist" / "feed.db"
    connection = store.connect(nested)
    try:
        assert nested.exists()
    finally:
        connection.close()


def test_reingesting_the_same_article_does_not_duplicate_it(conn):
    store.put_articles(conn, (_article("dup"),))
    store.put_articles(conn, (_article("dup"),))
    assert store.article_count(conn) == 1


def test_reingesting_updates_mutable_fields(conn):
    store.put_articles(conn, (_article("x", title="Original"),))
    store.put_articles(conn, (_article("x", title="Corrected"),))
    row = conn.execute("SELECT title FROM articles WHERE id='x'").fetchone()
    assert row["title"] == "Corrected"


def test_expiry_is_derived_from_publication_not_ingestion(conn):
    """Re-ingesting must not extend an article's life.

    A feed carries the same items on every poll, so an article is written many
    times. If expiry were derived from the write time, anything still in a feed
    would live forever and the 30-day promise would quietly break.
    """
    published = datetime.now(timezone.utc) - timedelta(days=29)
    store.put_articles(conn, (_article("old", published=published),))
    first = conn.execute("SELECT expires_at FROM articles WHERE id='old'").fetchone()[0]

    store.put_articles(conn, (_article("old", published=published),))
    second = conn.execute("SELECT expires_at FROM articles WHERE id='old'").fetchone()[0]

    assert first == second
    assert second == (published + timedelta(days=30)).isoformat()


def test_purge_expired_removes_only_expired_rows(conn):
    fresh = datetime.now(timezone.utc) - timedelta(days=1)
    stale = datetime.now(timezone.utc) - timedelta(days=31)
    store.put_articles(conn, (_article("fresh", published=fresh),
                              _article("stale", published=stale)))

    removed = store.purge_expired(conn)

    assert removed == 1
    assert store.article_count(conn) == 1
    assert conn.execute("SELECT id FROM articles").fetchone()["id"] == "fresh"


def test_query_recent_hides_expired_rows_even_without_a_purge(conn):
    """Filtering on read is not redundant with purging.

    It keeps the boundary exact for a reader even if a purge was skipped -- for
    example when the tool is run with --no-fetch after a long gap.
    """
    stale = datetime.now(timezone.utc) - timedelta(days=31)
    store.put_articles(conn, (_article("stale", published=stale),))

    assert store.article_count(conn) == 1
    assert store.query_recent(conn) == []


def test_query_recent_returns_newest_first(conn):
    now = datetime.now(timezone.utc)
    store.put_articles(conn, (
        _article("older", published=now - timedelta(hours=5)),
        _article("newest", published=now - timedelta(hours=1)),
        _article("middle", published=now - timedelta(hours=3)),
    ))
    assert [a["id"] for a in store.query_recent(conn)] == ["newest", "middle", "older"]


def test_query_recent_respects_limit(conn):
    now = datetime.now(timezone.utc)
    store.put_articles(
        conn,
        tuple(_article(f"a{i}", published=now - timedelta(hours=i)) for i in range(10)),
    )
    assert len(store.query_recent(conn, limit=4)) == 4


def test_severity_signals_round_trip_as_a_list(conn):
    store.put_articles(conn, (_article("sig"),))
    assert store.query_recent(conn)[0]["severity_signals"] == ["kev"]


def test_malformed_signals_column_costs_the_explanation_not_the_article(conn):
    store.put_articles(conn, (_article("bad"),))
    with conn:
        conn.execute("UPDATE articles SET severity_signals='not json' WHERE id='bad'")

    articles = store.query_recent(conn)

    assert len(articles) == 1
    assert articles[0]["severity_signals"] == []


def test_source_state_round_trip(conn):
    assert store.get_source_state(conn, "cisa") == (None, None)

    store.put_source_state(
        conn, "cisa", 'W/"abc"', "Wed, 01 Jan 2025 00:00:00 GMT",
        status="ok", articles_written=3,
    )

    assert store.get_source_state(conn, "cisa") == (
        'W/"abc"', "Wed, 01 Jan 2025 00:00:00 GMT",
    )


def test_source_state_is_updated_not_duplicated(conn):
    for tag in ('W/"1"', 'W/"2"'):
        store.put_source_state(
            conn, "cisa", tag, None, status="ok", articles_written=1
        )

    rows = conn.execute("SELECT COUNT(*) FROM source_state").fetchone()[0]
    assert rows == 1
    assert store.get_source_state(conn, "cisa")[0] == 'W/"2"'


def test_source_state_is_not_subject_to_retention(conn):
    """ETag and Last-Modified are HTTP metadata, not article-derived data.

    They are what keeps polling cheap and polite, so a purge must not clear
    them -- losing them would mean refetching every feed in full.
    """
    store.put_source_state(
        conn, "cisa", 'W/"keep"', None, status="ok", articles_written=0
    )
    stale = datetime.now(timezone.utc) - timedelta(days=31)
    store.put_articles(conn, (_article("stale", published=stale),))

    store.purge_expired(conn)

    assert store.get_source_state(conn, "cisa")[0] == 'W/"keep"'
