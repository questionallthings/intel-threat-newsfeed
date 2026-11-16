"""SQLite persistence for articles and per-source HTTP state.

This replaces a DynamoDB table in the hosted version of this tool. The schema is
deliberately flatter: DynamoDB needed day-bucketed partition keys to keep "the
last N days" cheap, whereas SQLite answers that with an index on one table.

Two tables:

    articles      one row per article, keyed by the content-derived id
    source_state  one row per source, holding ETag and Last-Modified

Source state is HTTP metadata about a request, not data derived from article
content, so it is not subject to the 30-day retention rule.

**Retention is enforced here, not by the database.** DynamoDB deletes expired
items on its own once ``ttl`` passes; SQLite has no such mechanism, so
``purge_expired`` has to be called on every run. ``query_recent`` *also* filters
on ``expires_at``, which is not redundant: it means a reader never sees an
expired article even if a purge was missed, and it keeps the 30-day boundary
exact rather than approximate.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import severity as severity_rules
from .feed import Article

logger = logging.getLogger(__name__)

RETENTION_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id                     TEXT PRIMARY KEY,
    source_id              TEXT NOT NULL,
    source_name            TEXT NOT NULL,
    title                  TEXT NOT NULL,
    link                   TEXT NOT NULL,
    excerpt                TEXT NOT NULL DEFAULT '',
    severity               TEXT NOT NULL,
    severity_signals       TEXT NOT NULL DEFAULT '[]',
    severity_rules_version INTEGER NOT NULL,
    published_at           TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    fetched_at             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_articles_published ON articles (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_articles_expires   ON articles (expires_at);

CREATE TABLE IF NOT EXISTS source_state (
    source_id             TEXT PRIMARY KEY,
    etag                  TEXT,
    last_modified         TEXT,
    last_polled_at        TEXT NOT NULL,
    last_status           TEXT NOT NULL,
    last_articles_written INTEGER NOT NULL DEFAULT 0
);
"""


def connect(path: Path) -> sqlite3.Connection:
    """Open the database, creating it and its schema if absent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Write-ahead logging so a long fetch does not block a reader, and so an
    # interrupted run (Ctrl-C, closed laptop) cannot leave a torn database.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def put_articles(conn: sqlite3.Connection, articles: tuple[Article, ...]) -> int:
    """Insert or replace articles. Returns the number written.

    Re-ingesting is normal: a feed carries the same 15 items on every poll, so
    most of these writes replace an identical row.

    Overwriting stays safe for retention because ``expires_at`` is derived from
    ``published_at``, never from the current time. Re-ingesting an article a
    hundred times cannot push its expiry past the original 30 days. If this ever
    changed to ``fetched_at``, an article present in every poll would live
    forever.
    """
    rows = [
        (
            article.id,
            article.source_id,
            article.source_name,
            article.title,
            article.link,
            article.excerpt,
            article.severity,
            json.dumps(list(article.severity_signals)),
            severity_rules.RULES_VERSION,
            article.published_at.isoformat(),
            article.expires_at.isoformat(),
            _now().isoformat(),
        )
        for article in articles
    ]

    with conn:
        conn.executemany(
            """
            INSERT INTO articles (
                id, source_id, source_name, title, link, excerpt,
                severity, severity_signals, severity_rules_version,
                published_at, expires_at, fetched_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                source_name            = excluded.source_name,
                title                  = excluded.title,
                link                   = excluded.link,
                excerpt                = excluded.excerpt,
                severity               = excluded.severity,
                severity_signals       = excluded.severity_signals,
                severity_rules_version = excluded.severity_rules_version,
                fetched_at             = excluded.fetched_at
            """,
            rows,
        )

    return len(rows)


def get_source_state(
    conn: sqlite3.Connection, source_id: str
) -> tuple[str | None, str | None]:
    """Return (etag, last_modified) for a source, or (None, None) if unseen."""
    row = conn.execute(
        "SELECT etag, last_modified FROM source_state WHERE source_id = ?",
        (source_id,),
    ).fetchone()
    if row is None:
        return None, None
    return row["etag"], row["last_modified"]


def put_source_state(
    conn: sqlite3.Connection,
    source_id: str,
    etag: str | None,
    last_modified: str | None,
    *,
    status: str,
    articles_written: int,
) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO source_state (
                source_id, etag, last_modified,
                last_polled_at, last_status, last_articles_written
            ) VALUES (?,?,?,?,?,?)
            ON CONFLICT(source_id) DO UPDATE SET
                etag                  = excluded.etag,
                last_modified         = excluded.last_modified,
                last_polled_at        = excluded.last_polled_at,
                last_status           = excluded.last_status,
                last_articles_written = excluded.last_articles_written
            """,
            (
                source_id,
                etag,
                last_modified,
                _now().isoformat(),
                status,
                articles_written,
            ),
        )


def purge_expired(conn: sqlite3.Connection) -> int:
    """Delete articles past their 30 days. Returns how many were removed.

    This is the local stand-in for DynamoDB's TTL. It must be called on every
    run: without it the database grows without bound and the retention promise
    in the README becomes false.
    """
    with conn:
        cursor = conn.execute(
            "DELETE FROM articles WHERE expires_at <= ?", (_now().isoformat(),)
        )
    return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0


def query_recent(
    conn: sqlite3.Connection, days: int = RETENTION_DAYS, limit: int = 500
) -> list[dict]:
    """Return recent, unexpired articles, newest first."""
    cutoff = (_now() - timedelta(days=days)).isoformat()
    rows = conn.execute(
        """
        SELECT * FROM articles
        WHERE published_at >= ? AND expires_at > ?
        ORDER BY published_at DESC
        LIMIT ?
        """,
        (cutoff, _now().isoformat(), limit),
    ).fetchall()

    articles = []
    for row in rows:
        item = dict(row)
        try:
            item["severity_signals"] = json.loads(item["severity_signals"])
        except (TypeError, ValueError):
            # A malformed signals column should cost the explanation, not the
            # article.
            item["severity_signals"] = []
        articles.append(item)
    return articles


def source_status(conn: sqlite3.Connection) -> list[dict]:
    """Per-source polling state, for the run summary."""
    rows = conn.execute(
        """
        SELECT s.source_id, s.last_polled_at, s.last_status,
               s.last_articles_written,
               (SELECT COUNT(*) FROM articles a WHERE a.source_id = s.source_id)
                   AS stored
        FROM source_state s
        ORDER BY s.source_id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def article_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]


def _now() -> datetime:
    return datetime.now(timezone.utc)
