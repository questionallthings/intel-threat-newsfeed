# Newsfeed Sources

Sources included in the Threat Intelligence Newsfeed, with the terms review that
approved each one. Nothing is ingested before it appears here.

## What we store

For every article, only:

| Field | Notes |
| ----- | ----- |
| Headline | As published |
| Publisher | Source name |
| Publication date | From the feed |
| Link | To the original article |
| Excerpt | Truncated to ~300 characters |

**We never store full article text**, even when the feed provides it. Three of the
feeds surveyed ship the complete article in `content:encoded`; ingestion truncates
at write time rather than at render time, so a reproduction never reaches the
database in the first place.

## Retention

**All articles and any data derived from them are deleted after 30 days**,
enforced by an expiry timestamp derived from each article's publication date,
purged on every run. This keeps
storage flat regardless of how long the project runs, and means the service is a
current-awareness feed rather than an archive.

Per-source HTTP state (`ETag`, `Last-Modified`) is not derived from article
content and is retained, since it is what keeps polling cheap and polite.

## Approved sources

### CISA Cybersecurity Advisories

| | |
| --- | --- |
| Feed | `https://www.cisa.gov/cybersecurity-advisories/all.xml` |
| Format | RSS, ~30 items |
| Feed content | Summary only |
| `robots.txt` | Permits fetching for `User-agent: *` |
| Terms basis | Work of the US federal government — public domain under 17 U.S.C. §105 |

No copyright restriction applies. The safest source available.

Note the feed is ~1.9 MB per fetch, which makes conditional requests a
requirement rather than an optimisation.

**Access note.** This feed currently returns HTTP 403 from some networks,
regardless of User-Agent — including with no User-Agent at all. That is CISA's
access control, not a parsing problem, and this tool does not attempt to work
around it. The run reports the failure and continues.

### NCSC UK

| | |
| --- | --- |
| Feed | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` |
| Format | RSS, ~20 items |
| Feed content | Summary only |
| `robots.txt` | `User-agent: *` → `Allow: /` |
| Terms basis | Open Government Licence v3.0 — reuse permitted with attribution |

Attribution requirement is satisfied by displaying the publisher name and linking
to the original.

NCSC publishes several feeds. `report-rss-feed` was used initially and produced
zero articles: it is live and parses cleanly but has not published since May
2025, so every item fell outside the 30-day window. **When adding a source, check
the newest `pubDate`, not just that the feed responds** — a stale feed looks
identical to a working one until you notice nothing is being ingested.

### Unit 42 (Palo Alto Networks)

| | |
| --- | --- |
| Feed | `https://unit42.paloaltonetworks.com/feed/` |
| Format | RSS, ~15 items |
| Feed content | Summary only |
| `robots.txt` | Permits fetching |
| Terms basis | Standard corporate copyright, no explicit reuse grant |

Included on the basis that headline-plus-link-plus-excerpt is the conventional
scope of a feed reader and drives traffic to the publisher. Their terms of use
page has **not** been read in full — worth doing before the site is public.

### Canadian Centre for Cyber Security (CCCS)

| | |
| --- | --- |
| Feed | `https://www.cyber.gc.ca/webservice/en/rss/alerts` |
| Format | RSS, ~50 items, current |
| Feed content | Summary only |
| `robots.txt` | None published (404), so no crawl restrictions |
| Terms basis | Government of Canada publication |

Extends the government tier alongside CISA and NCSC. Largest item count of any
source, so it contributes materially to daily volume.

### Cisco Talos

| | |
| --- | --- |
| Feed | `https://blog.talosintelligence.com/rss/` |
| Format | RSS, ~15 items |
| Feed content | **Full article text** in `content:encoded` |
| `robots.txt` | Permits fetching |
| Terms basis | Standard corporate copyright, no explicit reuse grant |

Included deliberately as the first full-text feed, so truncation is proven from
the start rather than retrofitted. Same caveat as Unit 42 on the terms page.

### SANS Internet Storm Center

| | |
| --- | --- |
| Feed | `https://isc.sans.edu/rssfeed_full.xml` |
| Format | RSS, ~10 items |
| Feed content | **Full article text** |
| `robots.txt` | Several paths disallowed for `*`, but not the feed |
| Terms basis | Community handler diaries; standard copyright, no explicit reuse grant |

Daily handler diaries, consistently high signal. Truncated like any other
full-text feed.

### Krebs on Security

| | |
| --- | --- |
| Feed | `https://krebsonsecurity.com/feed/` |
| Format | RSS, ~10 items |
| Feed content | **Full article text** |
| `robots.txt` | Permits fetching; declares `Crawl-Delay: 35` |
| Terms basis | Standard copyright, no explicit reuse grant |

Originally deferred over the declared `Crawl-Delay: 35`. That was a
misreading: crawl-delay governs the interval between successive requests to the
*same host*, and a scheduled run polls each host once every six hours — inside the declared
value by more than two orders of magnitude. The full-text feed is not a barrier
either, since excerpts are truncated regardless of source.

### BleepingComputer

| | |
| --- | --- |
| Feed | `https://www.bleepingcomputer.com/feed/` |
| Format | RSS, ~15 items |
| Feed content | Summary only |
| `robots.txt` | Permits fetching; `Crawl-delay: 1` |
| Terms basis | Standard copyright, no explicit reuse grant |

The most current source in the set — typically publishing the same day. Terms of
use page was not located at the expected URL; the position is the same as the
other commercial publishers here.

### The Hacker News

| | |
| --- | --- |
| Feed | `https://thehackernews.com/feeds/posts/default` |
| Format | 50 items, current to within hours |
| Feed content | Summary only |
| `robots.txt` | `Disallow:` (empty) for `*` — everything permitted |
| Terms basis | Standard copyright, no explicit reuse grant |

The publisher's own feed rather than their FeedBurner address: identical content
with one less third party in the path.

### Dark Reading

| | |
| --- | --- |
| Feed | `https://www.darkreading.com/rss.xml` |
| Format | 50 items |
| Feed content | Summary only |
| `robots.txt` | Several paths disallowed for `*`, but not the feed |
| Terms basis | Standard copyright, no explicit reuse grant |

Newest item was ~3 days old at review, against a 50-item window — depth is good,
cadence is less frequent than The Hacker News or BleepingComputer.

### SOCRadar

| | |
| --- | --- |
| Feed | `https://socradar.io/feed/` |
| Format | ~10 items |
| Feed content | **Full article text** |
| `robots.txt` | Admin and content paths disallowed for `*`, but not the feed |
| Terms basis | Standard corporate copyright, no explicit reuse grant |

### Google Threat Intelligence (Mandiant)

| | |
| --- | --- |
| Feed | `https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v` |
| Format | ~20 items, ~1.1 MB |
| Feed content | Summary only |
| `robots.txt` | Feed path permitted |
| Terms basis | Standard corporate copyright, no explicit reuse grant |

The documented `cloud.google.com/blog/topics/threat-intelligence/rss` returns
HTTP 200 with a JavaScript-rendered page rather than a feed. The FeedBurner
address is the one that actually serves RSS.

### Help Net Security

| | |
| --- | --- |
| Feed | `https://www.helpnetsecurity.com/feed/` |
| Format | ~10 items, current to within the hour |
| Feed content | Summary only |
| `robots.txt` | `Disallow:` (empty) for `*` — everything permitted |
| Terms basis | Standard copyright, no explicit reuse grant |

### Dark Web Informer

| | |
| --- | --- |
| Feed | `https://darkwebinformer.com/rss/` |
| Format | ~15 items |
| Feed content | **Full article text** |
| `robots.txt` | Some paths disallowed for `*`, but not the feed |
| Terms basis | Standard copyright, no explicit reuse grant |

Feed path found via autodiscovery: `/feed/` redirects and `/rss.xml` 404s.

**TLS note.** This host fails certificate verification from Python on Windows
("unable to get local issuer certificate") while `curl` connects cleanly, which
points at the local trust store rather than a broken chain. Verification is
never disabled to work around this — a man-in-the-middle on a threat feed would
let an attacker choose what our readers see.

## Rejected candidates

| Source | Why |
| ------ | --- |
| Aviation Business News | **No usable feed.** The autodiscovery link points at `feed.rss`, which 404s; `?feed=rss2` returns HTML. It is also an aviation trade publication rather than a security source, so it would dilute the feed. |

## Deferred candidates

| Source | Why deferred |
| ------ | ------------ |
| The Record | Feed carries only 5 items, so stories published between polls could be missed permanently |
| Google Project Zero | 12.9 MB per fetch for infrequent posts; needs per-source poll frequency first |
| Microsoft MSRC blog | Feed returns 200 but no parseable items; format needs investigating |
| Google Threat Intelligence | Same — 200 with no detectable items |
| ACSC (Australia) | Feed request timed out on evaluation |

## Removal requests

If you publish a source listed here and want it removed, open an issue and it
will be taken out. No justification needed.

## Adding a source

Add it to `newsfeed/sources.py` and record its review here first — licence
basis, `robots.txt` position, whether it ships full text, and the newest
`pubDate` you observed. A feed that returns HTTP 200 can still be years stale;
checking only that it responds is how a dead source gets added unnoticed.

Use `<link rel="alternate">` autodiscovery rather than guessing feed URLs. Two
of the sources above were found that way after a guessed path returned 200 with
a JavaScript-rendered page instead of XML.
