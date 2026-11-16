"""Run one ingestion cycle: poll every source, store, purge, render.

Ported from the Lambda handler in the hosted version. The structure is the same;
what changed is that there is no event payload, no EventBridge retry to reason
about, and the output is a local file rather than an S3 object.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import render, store
from .feed import FeedError, fetch
from .sources import SOURCES, SOURCES_BY_ID

logger = logging.getLogger(__name__)


@dataclass
class SourceResult:
    source_id: str
    source_name: str
    status: str
    written: int = 0
    error: str | None = None


@dataclass
class RunSummary:
    results: list[SourceResult] = field(default_factory=list)
    purged: int = 0
    article_count: int = 0
    output_path: Path | None = None

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == "error")

    @property
    def written(self) -> int:
        return sum(r.written for r in self.results)

    @property
    def not_modified(self) -> int:
        return sum(1 for r in self.results if r.status == "not_modified")


def run(
    db_path: Path,
    output_path: Path,
    *,
    only: str | None = None,
    skip_fetch: bool = False,
    write_json_to: Path | None = None,
    on_result=None,
) -> RunSummary:
    """Poll sources and regenerate the page.

    A failing source is logged and skipped rather than aborting the run. One
    publisher having an outage must not stop the other thirteen from updating.
    """
    sources = _requested_sources(only)
    summary = RunSummary()
    conn = store.connect(db_path)

    try:
        if not skip_fetch:
            for index, source in enumerate(sources):
                if index:
                    # Spread our own outbound requests across the run rather
                    # than firing them all at once. See Source.spacing_seconds
                    # for why this is not robots.txt Crawl-delay compliance.
                    time.sleep(source.spacing_seconds)

                result = _poll(conn, source)
                summary.results.append(result)

                # Reported as each source finishes rather than before it starts,
                # so the line can carry the outcome instead of being overwritten.
                if on_result:
                    on_result(index + 1, len(sources), result)

        # Local stand-in for DynamoDB's TTL, which deleted expired items on its
        # own. Without this the database grows without bound and the 30-day
        # retention promise becomes false.
        summary.purged = store.purge_expired(conn)

        # Regenerate unconditionally, even when nothing new arrived. Articles
        # leave the feed by expiring, not only by being superseded, so a run
        # that writes zero articles can still change what the page should show.
        path, count = render.write_html(conn, output_path)
        summary.output_path = path
        summary.article_count = count

        if write_json_to is not None:
            render.write_json(conn, write_json_to)
    finally:
        conn.close()

    return summary


def _poll(conn, source) -> SourceResult:
    etag, last_modified = store.get_source_state(conn, source.id)

    try:
        result = fetch(source, etag, last_modified)
    except FeedError as exc:
        logger.error("source=%s failed: %s", source.id, exc)
        store.put_source_state(
            conn, source.id, etag, last_modified, status="error", articles_written=0
        )
        return SourceResult(source.id, source.name, "error", error=str(exc))
    except Exception as exc:  # noqa: BLE001 - one bad source must not end the run
        logger.exception("source=%s unexpected failure", source.id)
        store.put_source_state(
            conn, source.id, etag, last_modified, status="error", articles_written=0
        )
        return SourceResult(
            source.id, source.name, "error", error=f"{type(exc).__name__}: {exc}"
        )

    if result.not_modified:
        store.put_source_state(
            conn,
            source.id,
            etag,
            last_modified,
            status="not_modified",
            articles_written=0,
        )
        return SourceResult(source.id, source.name, "not_modified")

    written = store.put_articles(conn, result.articles)
    store.put_source_state(
        conn,
        source.id,
        result.etag,
        result.last_modified,
        status="ok",
        articles_written=written,
    )
    return SourceResult(source.id, source.name, "ok", written=written)


def _requested_sources(only: str | None):
    """Resolve an optional single-source filter.

    Only ids already present in SOURCES are accepted. A command-line argument is
    not a way to introduce a feed that has not been through the terms review in
    docs/SOURCES.md.
    """
    if not only:
        return SOURCES
    source = SOURCES_BY_ID.get(only)
    if source is None:
        known = ", ".join(sorted(SOURCES_BY_ID))
        raise SystemExit(f"Unknown source {only!r}.\nKnown sources: {known}")
    return (source,)
