"""Fetching and parsing RSS/Atom feeds.

Two rules drive everything here:

1. **Never keep full article text.** Several feeds ship the whole article in
   ``content:encoded``. Truncation happens at parse time, so a reproduction
   never reaches the caller, let alone the database.
2. **Treat feed content as hostile.** It is third-party text we do not control.
   XML is parsed with defusedxml, sizes are bounded, and markup is stripped
   before storage.
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from defusedxml import ElementTree

from . import severity as severity_rules
from .sources import Source

logger = logging.getLogger(__name__)

USER_AGENT = (
    "intel-threat-newsfeed/1.0 "
    "(+https://github.com/questionallthings/intel-threat-newsfeed)"
)

#: Excerpt length in characters. Long enough to be useful in a list view, short
#: enough that it is plainly an excerpt rather than a substitute for the article.
EXCERPT_CHARS = 300

#: Refuse to buffer more than this from any one feed. CISA is ~1.9 MB and
#: Project Zero ~13 MB, so the ceiling is generous -- it exists to stop a
#: misbehaving or hostile origin from exhausting memory, not to be tight.
MAX_FEED_BYTES = 32 * 1024 * 1024

REQUEST_TIMEOUT_SECONDS = 20

RETENTION_DAYS = 30

_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc": "http://purl.org/dc/elements/1.1/",
}

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

#: Promotional tails that publishing platforms append to feed summaries. These
#: are the platform's boilerplate rather than the author's words, and they eat
#: into an already short excerpt -- "The post ... appeared first on ..." alone
#: can be a third of the 300 characters.
_BOILERPLATE_RE = re.compile(
    r"(?:"
    r"\s*The post .+? appeared first on .+?\.?\s*$"
    r"|\s*Continue reading .*?$"
    r"|\s*Read more( about this)?\s*(?:→|&rarr;|\.{3}|…)?\s*$"
    r"|\s*\[\s*read more\s*\]\s*$"
    r")",
    re.IGNORECASE | re.DOTALL,
)


class FeedError(Exception):
    """Raised when a feed cannot be fetched or parsed."""


@dataclass(frozen=True)
class Article:
    id: str
    source_id: str
    source_name: str
    title: str
    link: str
    excerpt: str
    published_at: datetime

    #: Heuristic triage rating -- see ingest/severity.py. Not a vendor severity.
    severity: str = severity_rules.DEFAULT_SEVERITY

    #: Labels of the rules that produced the rating, so it can be explained
    #: rather than merely asserted. Empty means nothing matched.
    severity_signals: tuple[str, ...] = ()

    @property
    def expires_at(self) -> datetime:
        return self.published_at + timedelta(days=RETENTION_DAYS)


@dataclass(frozen=True)
class FetchResult:
    """Outcome of polling one source."""

    not_modified: bool
    articles: tuple[Article, ...] = ()
    etag: str | None = None
    last_modified: str | None = None


def fetch(source: Source, etag: str | None, last_modified: str | None) -> FetchResult:
    """Poll a source, using conditional headers when we have them.

    A 304 means nothing changed and the whole body transfer is skipped. Given
    CISA alone is ~1.9 MB per fetch, this is the difference between a few KB and
    tens of GB of egress per month -- a correctness and cost requirement, not an
    optimisation.
    """
    request = urllib.request.Request(source.url, method="GET")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml")
    request.add_header("Accept-Encoding", "gzip")
    if etag:
        request.add_header("If-None-Match", etag)
    if last_modified:
        request.add_header("If-Modified-Since", last_modified)

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            raw = _read_body(response)
            new_etag = response.headers.get("ETag")
            new_last_modified = response.headers.get("Last-Modified")
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            logger.info("source=%s unchanged (304)", source.id)
            return FetchResult(not_modified=True, etag=etag, last_modified=last_modified)
        raise FeedError(f"{source.id}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"{source.id}: {exc.reason}") from exc

    articles = parse(source, raw)
    logger.info("source=%s fetched bytes=%d articles=%d", source.id, len(raw), len(articles))
    return FetchResult(
        not_modified=False,
        articles=tuple(articles),
        etag=new_etag,
        last_modified=new_last_modified,
    )


def _read_body(response) -> bytes:
    """Read a bounded, possibly gzipped, response body."""
    data = response.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise FeedError(f"feed exceeded {MAX_FEED_BYTES} bytes")
    if response.headers.get("Content-Encoding") == "gzip":
        import gzip

        data = gzip.decompress(data)
    return data


#: XML 1.0 forbids the C0 control characters outright -- even escaped --
#: apart from tab, newline and carriage return. Publishers do emit them: the
#: SOCRadar feed carries a literal vertical tab (0x0B) inside a code sample,
#: and a single one makes an otherwise valid feed unparseable.
#:
#: Built from a range rather than written as a regex character class, because
#: a bytes.translate delete-set is both faster and impossible to get subtly
#: wrong through escaping.
_XML_LEGAL_CONTROL = frozenset((0x09, 0x0A, 0x0D))
_ILLEGAL_XML_BYTES = bytes(
    b for b in range(0x20) if b not in _XML_LEGAL_CONTROL
)
_KEEP_ALL = bytes.maketrans(b"", b"")


def _strip_illegal_bytes(raw: bytes) -> tuple[bytes, int]:
    """Remove bytes that are not legal XML 1.0 characters.

    This is a spec-conformance repair, not a parser relaxation. These bytes
    cannot appear in a well-formed XML document under any encoding or escaping,
    so removing them cannot change the meaning of a valid feed -- it only
    rescues an invalid one. Parsing still goes through defusedxml, so the
    entity-expansion protections are untouched.
    """
    cleaned = raw.translate(_KEEP_ALL, _ILLEGAL_XML_BYTES)
    return cleaned, len(raw) - len(cleaned)


def parse(source: Source, raw: bytes) -> list[Article]:
    """Parse RSS 2.0 or Atom into articles, discarding everything else."""
    raw, removed = _strip_illegal_bytes(raw)
    if removed:
        logger.warning(
            "source=%s stripped %d XML-illegal control byte(s) from the feed",
            source.id,
            removed,
        )

    try:
        root = ElementTree.fromstring(raw)
    except Exception as exc:  # defusedxml raises several types
        raise FeedError(f"{source.id}: malformed XML: {exc}") from exc

    entries = root.findall("./channel/item")
    if entries:
        return _parse_entries(source, entries, rss=True)

    entries = root.findall("atom:entry", _NS) or root.findall("entry")
    if entries:
        return _parse_entries(source, entries, rss=False)

    raise FeedError(f"{source.id}: neither RSS items nor Atom entries found")


def _parse_entries(source: Source, entries: list, *, rss: bool) -> list[Article]:
    articles: list[Article] = []
    for entry in entries:
        try:
            article = _parse_entry(source, entry, rss=rss)
        except Exception:
            # One malformed entry must not lose the rest of the feed.
            logger.warning("source=%s skipping unparseable entry", source.id, exc_info=True)
            continue
        if article is not None:
            articles.append(article)
    return articles


def _parse_entry(source: Source, entry, *, rss: bool) -> Article | None:
    title = _text(entry, "title" if rss else "atom:title")
    link = _link(entry, rss=rss)
    if not title or not link:
        return None

    published = _published(entry, rss=rss)
    if published is None:
        return None

    # Drop anything already outside the retention window rather than writing an
    # item that TTL would immediately reap.
    if published < _now() - timedelta(days=RETENTION_DAYS):
        return None

    clean_title = _clean(title, limit=500)
    excerpt = _excerpt(entry, rss=rss)

    # Rated at ingestion rather than render time, so the rating is computed once,
    # is testable, and travels with the article into the published JSON.
    rating = severity_rules.rate(clean_title, excerpt)

    return Article(
        id=article_id(link),
        source_id=source.id,
        source_name=source.name,
        title=clean_title,
        link=link,
        excerpt=excerpt,
        published_at=published,
        severity=rating.severity,
        severity_signals=rating.signals,
    )


def _excerpt(entry, *, rss: bool) -> str:
    """Build a short plain-text excerpt.

    Deliberately prefers the *summary* field and falls back to the full-content
    field only when no summary exists -- and truncates either way. This is the
    single most important function for staying on the right side of copyright.
    """
    candidates = (
        ["description", "{http://purl.org/rss/1.0/modules/content/}encoded"]
        if rss
        else ["atom:summary", "atom:content"]
    )
    for path in candidates:
        value = _text(entry, path)
        if value:
            return _clean(value, limit=EXCERPT_CHARS, strip_boilerplate=True)
    return ""


def _clean(value: str, *, limit: int, strip_boilerplate: bool = False) -> str:
    """Strip markup, collapse whitespace, truncate on a word boundary."""
    text = _TAG_RE.sub(" ", value)
    text = html.unescape(text)
    text = _WS_RE.sub(" ", text).strip()
    if strip_boilerplate:
        # Before truncating, so removing the tail leaves room for real content
        # rather than the excerpt ending mid-boilerplate.
        text = _BOILERPLATE_RE.sub("", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if " " in cut:
        cut = cut[: cut.rindex(" ")]
    return cut.rstrip(".,;:- ") + "…"


def _text(entry, path: str) -> str | None:
    node = entry.find(path, _NS) if ":" in path else entry.find(path)
    if node is None:
        return None
    return "".join(node.itertext()) if len(node) else (node.text or None)


def _link(entry, *, rss: bool) -> str | None:
    if rss:
        raw = _text(entry, "link")
    else:
        # An Element's truth value is deprecated and an element with no children
        # is currently falsy, so `a or b` would silently skip a valid link.
        node = entry.find("atom:link[@rel='alternate']", _NS)
        if node is None:
            node = entry.find("atom:link", _NS)
        raw = node.get("href") if node is not None else None
    return canonical_url(raw) if raw else None


def canonical_url(url: str) -> str | None:
    """Normalise a URL so the same article from two feeds dedupes to one row.

    Strips tracking parameters and fragments, lowercases the host, and drops a
    trailing slash. Rejects anything that is not http(s) -- a feed is untrusted
    input, and ``javascript:`` in an href is a real thing.
    """
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None

    query = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith(("utm_", "mc_"))
        and key.lower() not in {"fbclid", "gclid", "ref", "source"}
    ]
    path = parts.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc.lower(), path, urllib.parse.urlencode(query), "")
    )


def article_id(link: str) -> str:
    """Stable id derived from the canonical URL, so re-ingestion is idempotent."""
    return hashlib.sha256(link.encode("utf-8")).hexdigest()[:32]


def _published(entry, *, rss: bool) -> datetime | None:
    for path in (["pubDate", "dc:date"] if rss else ["atom:published", "atom:updated"]):
        raw = _text(entry, path)
        if not raw:
            continue
        parsed = _parse_date(raw.strip())
        if parsed:
            return parsed
    return None


def _parse_date(raw: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(raw)  # RFC 822, used by RSS
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))  # ISO 8601, Atom
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)
