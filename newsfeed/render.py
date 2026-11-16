"""Render the newsfeed as one self-contained HTML file.

The hosted version of this tool publishes JSON to S3 and has a separate web
front end fetch it. That does not work locally: a page opened from ``file://``
cannot ``fetch`` a sibling file -- browsers treat every ``file://`` document as
its own opaque origin, so the request is blocked by CORS with no way to allow it
short of running a web server.

So the data is **embedded** in the page instead. One file, no server, no build
step: open it and it works, including from a USB stick or an email attachment.

Everything in the page is inline -- no CDN, no web fonts, no external requests
of any kind. A tool for reading threat intelligence should not phone home, and
it should keep working on an air-gapped machine.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from . import severity as severity_rules
from . import store
from .sources import SOURCES

logger = logging.getLogger(__name__)

RETENTION_DAYS = 30

#: Upper bound on articles in the rendered page. Thirty days of fourteen sources
#: is a few hundred, so this is a safety rail against an unexpectedly chatty
#: feed bloating the file, not a limit we expect to reach.
MAX_ARTICLES = 500


def build_document(conn) -> dict:
    """Assemble the feed document. Same shape as the hosted JSON."""
    items = store.query_recent(conn, days=RETENTION_DAYS, limit=MAX_ARTICLES)

    articles = sorted(
        (
            {
                "id": item["id"],
                "source_id": item["source_id"],
                "source_name": item["source_name"],
                "title": item["title"],
                "link": item["link"],
                "excerpt": item.get("excerpt", ""),
                "severity": item.get("severity", severity_rules.DEFAULT_SEVERITY),
                "severity_signals": list(item.get("severity_signals", [])),
                "published_at": item["published_at"],
            }
            for item in items
        ),
        key=lambda article: article["published_at"],
        reverse=True,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "retention_days": RETENTION_DAYS,
        "article_count": len(articles),
        "sources": [{"id": s.id, "name": s.name} for s in SOURCES],
        # Most severe first, so the page builds its filter without hardcoding
        # the levels or their order.
        "severities": list(severity_rules.SEVERITY_ORDER),
        "severity_rules_version": severity_rules.RULES_VERSION,
        "articles": articles,
    }


def _embed(document: dict) -> str:
    """Serialise the document for safe inclusion inside a <script> element.

    Escaping ``<``, ``>`` and ``&`` is the point. Article titles are third-party
    text from feeds we do not control, and a title containing ``</script>``
    would otherwise close the element early and let the remainder of the title
    be parsed as markup. These escapes are valid inside JSON strings, so the
    data is unchanged once parsed.
    """
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def write_html(conn, path: Path) -> tuple[Path, int]:
    """Write the page. Returns (path, article count)."""
    document = build_document(conn)
    html = _TEMPLATE.replace("__FEED_DATA__", _embed(document))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

    logger.info("wrote %s articles=%d", path, document["article_count"])
    return path, document["article_count"]


def write_json(conn, path: Path) -> tuple[Path, int]:
    """Write the raw feed document, for piping into other tooling."""
    document = build_document(conn)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return path, document["article_count"]


# The page. Ported from the hosted Astro version, with the data embedded rather
# than fetched and the TypeScript reduced to plain JavaScript.
_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Threat Intelligence Newsfeed</title>
<style>
  :root {
    --bg: #ffffff;
    --bg-subtle: #f6f7f9;
    --border: #e2e5ea;
    --text: #1a1d23;
    --text-muted: #5c636e;
    --accent: #0b5cad;
    --radius: 8px;
    --font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
      "Helvetica Neue", Arial, sans-serif;

    /* Severity colours. Light-theme values are darkened well past the "pure"
       hue so each clears 4.5:1 against the card background -- plain yellow and
       orange are the usual accessibility failures in a scheme like this. */
    --sev-critical: #b3261e;
    --sev-high: #9a4a00;
    --sev-medium: #7a5c00;
    --sev-low: #1b5e20;
    --sev-informational: #0b4f9e;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14171c;
      --bg-subtle: #1c2027;
      --border: #2c313a;
      --text: #e7eaee;
      --text-muted: #9aa3b0;
      --accent: #6cb0f5;

      --sev-critical: #ff8a80;
      --sev-high: #ffb26b;
      --sev-medium: #e8cf6a;
      --sev-low: #86e29a;
      --sev-informational: #93c6f8;
    }
  }

  *, *::before, *::after { box-sizing: border-box; }

  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 1rem;
    line-height: 1.6;
  }

  .wrap { max-width: 60rem; margin: 0 auto; padding: 2rem 1rem 4rem; }

  h1 { font-size: 1.6rem; margin: 0 0 0.5rem; }
  a { color: var(--accent); }

  .lede { color: var(--text-muted); margin: 0 0 1.5rem; max-width: 68ch; }

  .feed-controls { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1.5rem 0; }

  .feed-controls input, .feed-controls select {
    font: inherit;
    padding: 0.5rem 0.65rem;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }

  .feed-controls input { flex: 1 1 18rem; }

  .feed-status { color: var(--text-muted); font-size: 0.9rem; }

  /* Collapsed by default: discoverable without pushing the feed below the fold
     for people who already know what the badges mean. */
  .feed-legend {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.6rem 0.9rem;
    margin-bottom: 1rem;
    font-size: 0.9rem;
  }

  .feed-legend summary { cursor: pointer; color: var(--text-muted); font-size: 0.875rem; }
  .feed-legend p { margin: 0.75rem 0; color: var(--text-muted); }

  .feed-legend ul {
    list-style: none;
    padding: 0;
    margin: 0.75rem 0 0.25rem;
    display: grid;
    gap: 0.55rem;
  }

  .feed-legend li {
    display: grid;
    grid-template-columns: 7.5rem 1fr;
    gap: 0.7rem;
    align-items: start;
    color: var(--text-muted);
    line-height: 1.5;
  }

  @media (max-width: 34rem) {
    .feed-legend li { grid-template-columns: 1fr; gap: 0.25rem; }
  }

  .feed-list { list-style: none; padding: 0; margin: 1rem 0 0; display: grid; gap: 0.85rem; }

  .feed-item {
    border: 1px solid var(--border);
    /* Colour is a redundant cue only. The badge carries the text label, per
       WCAG 1.4.1 -- red-for-critical against green-for-low is exactly the pair
       a red-green colour blind reader cannot separate. */
    border-left: 4px solid var(--sev-medium);
    border-radius: var(--radius);
    padding: 1rem 1.1rem;
    background: var(--bg-subtle);
  }

  .feed-item[data-severity='critical']      { border-left-color: var(--sev-critical); }
  .feed-item[data-severity='high']          { border-left-color: var(--sev-high); }
  .feed-item[data-severity='medium']        { border-left-color: var(--sev-medium); }
  .feed-item[data-severity='low']           { border-left-color: var(--sev-low); }
  .feed-item[data-severity='informational'] { border-left-color: var(--sev-informational); }

  .sev-badge {
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 0.1rem 0.45rem;
    border-radius: 4px;
    border: 1px solid currentColor;
    white-space: nowrap;
    color: var(--sev-medium);
  }

  .sev-badge[data-severity='critical']      { color: var(--sev-critical); }
  .sev-badge[data-severity='high']          { color: var(--sev-high); }
  .sev-badge[data-severity='medium']        { color: var(--sev-medium); }
  .sev-badge[data-severity='low']           { color: var(--sev-low); }
  .sev-badge[data-severity='informational'] { color: var(--sev-informational); }

  /* Nothing matched, so the rating is a default rather than a judgement. Said
     quietly in the UI rather than presented with the same confidence. */
  .sev-badge[data-undetermined='true'] { opacity: 0.65; border-style: dashed; }

  .feed-item h2 { margin: 0 0 0.35rem; font-size: 1.05rem; line-height: 1.35; }
  .feed-item h2 a { text-decoration: none; }
  .feed-item h2 a:hover { text-decoration: underline; }

  .feed-meta {
    display: flex;
    flex-wrap: wrap;
    /* The dot does the separating, so the gap either side stays tight -- a wide
       gap would read as two disconnected groups. */
    gap: 0.25rem 0.45rem;
    font-size: 0.8rem;
    color: var(--text-muted);
    margin: 0 0 0.5rem;
  }

  .feed-excerpt { margin: 0; font-size: 0.925rem; color: var(--text-muted); max-width: 70ch; }

  .feed-empty {
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    padding: 1.5rem 1.1rem;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.925rem;
  }

  .feed-footnote { margin-top: 2rem; font-size: 0.85rem; color: var(--text-muted); max-width: 70ch; }

  .visually-hidden {
    position: absolute; width: 1px; height: 1px;
    overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>Threat Intelligence Newsfeed</h1>

  <p class="lede">
    Reporting from vendor research, CERT advisories, and security news, in one
    timeline. Headlines and excerpts only &mdash; follow the link for the full article.
  </p>

  <div class="feed-controls">
    <label class="visually-hidden" for="feed-search">Search headlines</label>
    <input id="feed-search" type="search" placeholder="Search headlines and excerpts&hellip;" autocomplete="off" />

    <label class="visually-hidden" for="feed-source">Filter by source</label>
    <select id="feed-source"><option value="">All sources</option></select>

    <label class="visually-hidden" for="feed-range">Filter by date range</label>
    <select id="feed-range">
      <option value="">All (30 days)</option>
      <option value="168">Last 7 days</option>
      <option value="24">Last 24 hours</option>
    </select>

    <label class="visually-hidden" for="feed-severity">Filter by severity</label>
    <select id="feed-severity"><option value="">All severities</option></select>
  </div>

  <details class="feed-legend">
    <summary>What do the severity labels mean?</summary>
    <p>
      Ratings are a <strong>heuristic triage aid</strong>, derived from keywords in the
      headline and excerpt. They are not vendor severity ratings. Hover any badge to see
      which signals produced it.
    </p>
    <ul>
      <li><span class="sev-badge" data-severity="critical">Critical</span>
        Evidence of real-world exploitation &mdash; actively exploited, in CISA's KEV
        catalog, an emergency directive, or CVSS 9.0+.</li>
      <li><span class="sev-badge" data-severity="high">High</span>
        A severe class of flaw, or a reported intrusion &mdash; RCE, authentication
        bypass, ransomware, a breach, or an attack on a named victim.</li>
      <li><span class="sev-badge" data-severity="medium">Medium</span>
        Ordinary vulnerability and threat reporting.</li>
      <li><span class="sev-badge" data-severity="low">Low</span>
        Guidance, hardening advice, programmes and training.</li>
      <li><span class="sev-badge" data-severity="informational">Informational</span>
        Not about a live threat &mdash; podcasts, videos, events, newsletters, published
        reports and product news.</li>
      <li><span class="sev-badge" data-severity="medium" data-undetermined="true">Medium</span>
        <strong>A dashed, faded badge means undetermined</strong> &mdash; no rule matched,
        so it defaults to Medium. Sitting in the middle is safer than filing something as
        Informational and burying it.</li>
    </ul>
  </details>

  <p id="feed-status" class="feed-status">Loading&hellip;</p>
  <ol id="feed-list" class="feed-list"></ol>

  <p class="feed-footnote">
    <strong>Severity is a heuristic.</strong> It is derived from keywords in the headline
    and excerpt &mdash; not a vendor rating, and not a substitute for reading the
    advisory. Articles with no matching signals are shown as Medium rather than
    Informational, so nothing gets buried.
  </p>

  <p class="feed-footnote">
    Articles are retained for 30 days. Content is the copyright of the publisher;
    this page links to the original. Generated locally by
    <a href="https://github.com/questionallthings/intel-threat-newsfeed" target="_blank" rel="noopener noreferrer">intel-threat-newsfeed</a>.
  </p>
</div>

<script id="feed-data" type="application/json">__FEED_DATA__</script>
<script>
// Everything below builds DOM with textContent rather than innerHTML. Titles
// and excerpts are third-party text from feeds we do not control, so they are
// treated as data, never as markup. Links are additionally checked for an
// http(s) scheme -- the ingestion side rejects anything else, but this page
// should not depend on that remaining true.
(function () {
  'use strict';

  var statusEl   = document.getElementById('feed-status');
  var listEl     = document.getElementById('feed-list');
  var searchEl   = document.getElementById('feed-search');
  var sourceEl   = document.getElementById('feed-source');
  var rangeEl    = document.getElementById('feed-range');
  var severityEl = document.getElementById('feed-severity');

  if (!(statusEl && listEl && searchEl && sourceEl && rangeEl && severityEl)) return;

  var DEFAULT_SEVERITY = 'medium';
  var data = { articles: [], sources: [], severities: [] };

  try {
    data = JSON.parse(document.getElementById('feed-data').textContent);
  } catch (error) {
    statusEl.textContent = 'Could not read the embedded feed data. Re-run the tool to regenerate this page.';
    return;
  }

  var articles = Array.isArray(data.articles) ? data.articles : [];

  function titleCase(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  var relativeTime = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  var absoluteDate = new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric'
  });

  function describeAge(iso) {
    var then = new Date(iso);
    if (isNaN(then.getTime())) return '';
    var hours = Math.round((then.getTime() - Date.now()) / 36e5);
    if (Math.abs(hours) < 24) return relativeTime.format(hours, 'hour');
    return relativeTime.format(Math.round(hours / 24), 'day');
  }

  function safeHref(url) {
    try {
      var parsed = new URL(url);
      return (parsed.protocol === 'https:' || parsed.protocol === 'http:') ? parsed.href : null;
    } catch (error) {
      return null;
    }
  }

  function render() {
    var query = searchEl.value.trim().toLowerCase();
    var selectedSource = sourceEl.value;
    var selectedSeverity = severityEl.value;
    var rangeHours = Number(rangeEl.value);

    // Computed once per render rather than per article, and only when a range
    // is actually selected.
    var cutoff = (isFinite(rangeHours) && rangeHours > 0)
      ? Date.now() - rangeHours * 36e5
      : null;

    var matches = articles.filter(function (article) {
      if (selectedSource && article.source_id !== selectedSource) return false;
      if (selectedSeverity && (article.severity || DEFAULT_SEVERITY) !== selectedSeverity) return false;

      if (cutoff !== null) {
        var published = new Date(article.published_at).getTime();
        // An unparseable date is kept rather than silently dropped -- losing an
        // article to a date-format quirk is worse than showing it.
        if (!isNaN(published) && published < cutoff) return false;
      }

      if (!query) return true;
      return article.title.toLowerCase().indexOf(query) !== -1 ||
             (article.excerpt || '').toLowerCase().indexOf(query) !== -1;
    });

    listEl.replaceChildren();

    matches.forEach(function (article) {
      var href = safeHref(article.link);
      if (!href) return;

      var severity = article.severity || DEFAULT_SEVERITY;
      var signals = article.severity_signals || [];

      var item = document.createElement('li');
      item.className = 'feed-item';
      item.dataset.severity = severity;

      var heading = document.createElement('h2');
      var link = document.createElement('a');
      link.href = href;
      link.textContent = article.title;
      // Open in a new tab so the feed, and any filters applied to it, survive
      // reading an article. rel is noopener/noreferrer, which is what makes
      // target="_blank" safe -- without it the opened page can reach back
      // through window.opener.
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      heading.appendChild(link);

      var meta = document.createElement('p');
      meta.className = 'feed-meta';

      // The badge carries the label as text, so severity is never conveyed by
      // colour alone. Its title explains the rating rather than asserting it.
      var badge = document.createElement('span');
      badge.className = 'sev-badge';
      badge.dataset.severity = severity;
      badge.textContent = titleCase(severity);
      if (signals.length) {
        badge.title = 'Heuristic rating. Signals: ' + signals.join(', ');
      } else {
        badge.dataset.undetermined = 'true';
        badge.title = 'Heuristic rating. No severity signals matched, so this defaults to Medium rather than being buried as Informational.';
      }

      var sourceName = document.createElement('span');
      sourceName.textContent = article.source_name;

      // Decoration rather than content, so it is hidden from screen readers,
      // which would otherwise announce a meaningless "middle dot".
      var separator = document.createElement('span');
      separator.textContent = '\\u00b7';
      separator.setAttribute('aria-hidden', 'true');

      var when = document.createElement('time');
      when.dateTime = article.published_at;
      var published = new Date(article.published_at);
      when.textContent = absoluteDate.format(published) + ' \\u00b7 ' + describeAge(article.published_at);

      meta.appendChild(badge);
      meta.appendChild(sourceName);
      meta.appendChild(separator);
      meta.appendChild(when);
      item.appendChild(heading);
      item.appendChild(meta);

      if (article.excerpt) {
        var excerpt = document.createElement('p');
        excerpt.className = 'feed-excerpt';
        excerpt.textContent = article.excerpt;
        item.appendChild(excerpt);
      }

      listEl.appendChild(item);
    });

    var filtered = Boolean(query || selectedSource || selectedSeverity || cutoff !== null);
    statusEl.textContent = filtered
      ? matches.length + ' of ' + articles.length + ' articles'
      : articles.length + ' articles from the last 30 days';

    // These sources publish a few times a week, so "Last 24 hours" is
    // legitimately empty much of the time. An unexplained blank list reads as a
    // broken page, so say what happened and what to try.
    if (matches.length === 0) {
      var empty = document.createElement('li');
      empty.className = 'feed-empty';
      empty.textContent = (cutoff !== null && !query && !selectedSource)
        ? 'No articles published in this period. These sources publish a few times a week \\u2014 try a wider range.'
        : 'No articles match these filters.';
      listEl.appendChild(empty);
    }
  }

  (data.sources || []).forEach(function (source) {
    var option = document.createElement('option');
    option.value = source.id;
    option.textContent = source.name;
    sourceEl.appendChild(option);
  });

  // Ordered most severe first by the generator, so the filter does not hardcode
  // the levels or need to know their ranking.
  (data.severities || []).forEach(function (severity) {
    var option = document.createElement('option');
    option.value = severity;
    option.textContent = titleCase(severity);
    severityEl.appendChild(option);
  });

  searchEl.addEventListener('input', render);
  sourceEl.addEventListener('change', render);
  rangeEl.addEventListener('change', render);
  severityEl.addEventListener('change', render);
  render();
})();
</script>
</body>
</html>
"""
