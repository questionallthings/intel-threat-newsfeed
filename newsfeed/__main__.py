"""Command line interface.

The default run needs no arguments: fetch every source, update the database,
regenerate the page, open it. Flags exist for the cases where that is not what
you want, not because the common case needs them.
"""

from __future__ import annotations

import argparse
import logging
import sys
import webbrowser
from pathlib import Path

from . import __version__

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "newsfeed.db"
DEFAULT_OUT = ROOT / "newsfeed.html"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="newsfeed",
        description=(
            "Aggregate threat intelligence reporting from 14 vetted sources "
            "into one local, self-contained HTML page."
        ),
        epilog="Run with no arguments to fetch everything and open the page.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        metavar="PATH",
        help=f"HTML file to write (default: {DEFAULT_OUT.name})",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        metavar="PATH",
        help="SQLite database holding the last 30 days (default: data/newsfeed.db)",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        metavar="PATH",
        help="also write the raw feed document as JSON, for other tooling",
    )
    parser.add_argument(
        "--source",
        metavar="ID",
        help="poll only this source id, for debugging one feed",
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="list the source ids and exit",
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="skip the network entirely and rebuild the page from the database",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not open a browser (use this when running from cron or Task Scheduler)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only print errors")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # This tool's own log records are silenced unless --debug, because the
    # printed output below already reports every source outcome. With both
    # enabled, log lines interleaved with progress output and produced an
    # unreadable run-on line.
    if not args.debug:
        logging.getLogger("newsfeed").setLevel(logging.CRITICAL)

    # Imported here rather than at module scope so that --help and
    # --list-sources stay instant and cannot fail on an import error.
    from . import pipeline
    from .sources import SOURCES

    if args.list_sources:
        width = max(len(s.id) for s in SOURCES)
        for source in SOURCES:
            full = " (full text)" if source.full_text_feed else ""
            print(f"  {source.id:<{width}}  {source.name}{full}")
        return 0

    def say(message: str = "") -> None:
        if not args.quiet:
            print(message)

    labels = {"ok": "ok", "not_modified": "unchanged", "error": "FAILED"}

    def on_result(done: int, total: int, result) -> None:
        """One finished line per source.

        Printed as each source completes rather than before it starts, so the
        line can carry the outcome instead of being overwritten.
        """
        if args.quiet:
            return
        if result.status == "ok":
            detail = f"{result.written} articles"
        elif result.status == "error":
            detail = result.error or "unknown error"
        else:
            detail = ""
        print(
            f"  [{done:>2}/{total}] {result.source_name:<34} "
            f"{labels.get(result.status, result.status):<9} {detail}",
            flush=True,
        )

    if not args.no_fetch:
        say(f"Fetching {len(SOURCES) if not args.source else 1} source(s)...")

    try:
        summary = pipeline.run(
            db_path=args.db,
            output_path=args.out,
            only=args.source,
            skip_fetch=args.no_fetch,
            write_json_to=args.json,
            on_result=None if args.no_fetch else on_result,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    say()
    _report(summary, say)

    if summary.output_path is not None:
        say("")
        say(f"  Page: {summary.output_path}")
        if not args.no_open:
            webbrowser.open(summary.output_path.resolve().as_uri())

    # A run where every source failed is a failure, even though the page was
    # still regenerated from whatever the database already held. Anything less
    # than total is a success with warnings -- that is the whole point of not
    # letting one publisher's outage stop the others.
    if summary.results and summary.errors == len(summary.results):
        print("\nEvery source failed. Check your network connection.", file=sys.stderr)
        return 1
    return 0


def _report(summary, say) -> None:
    # Per-source outcomes were already printed as they happened, so this is the
    # roll-up only.
    parts = []
    if summary.results:
        parts.append(f"{summary.written} articles written")
        if summary.not_modified:
            parts.append(f"{summary.not_modified} unchanged")
        if summary.errors:
            parts.append(f"{summary.errors} failed")
    if summary.purged:
        parts.append(f"{summary.purged} expired and removed")

    if parts:
        say("  " + ", ".join(parts) + ".")
    say(f"  {summary.article_count} articles in the last 30 days.")


if __name__ == "__main__":
    sys.exit(main())
