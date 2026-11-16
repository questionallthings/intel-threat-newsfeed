# intel-threat-newsfeed

Threat intelligence reporting from **14 vetted sources** — vendor research, CERT
advisories and security journalism — aggregated into one local, self-contained
HTML page with severity triage, search and filtering.

Runs entirely on your own machine. No account, no API key, no server, no cloud.

## Quick start

```bash
python3 run.py
```

That is the whole thing. It fetches every source, stores the last 30 days in a
local SQLite database, writes `newsfeed.html`, and opens it in your browser.

On Windows, use `python run.py`.

**Requirements:** Python 3.9 or newer. Nothing else — there is no `pip install`
step. The one third-party dependency (`defusedxml`) ships in `vendor/`, and a
pip-installed copy is preferred automatically if you have one.

First run takes about a minute, mostly waiting on fourteen web servers. Later
runs are faster because unchanged feeds return `304 Not Modified` and skip the
download entirely.

## What you get

A single HTML file, around 180 KB, that works offline and can be copied
anywhere — a USB stick, a network share, an email attachment. It contains:

- **Severity triage** — Critical, High, Medium, Low, Informational, from keyword
  rules tuned against a live corpus. Hover any badge to see which signals
  produced the rating.
- **Search** across headlines and excerpts.
- **Filters** by source, by severity, and by date range (all 30 days / last 7
  days / last 24 hours).
- **A legend** explaining what each level means and why some badges are dashed.

Severity is a **heuristic triage aid**, not a vendor rating. It is derived from
keywords in the headline and excerpt, and it is not a substitute for reading the
advisory. Articles where no rule matched are shown as Medium rather than
Informational, deliberately: sitting in the middle is safer than burying
something.

## Sources

Fourteen feeds across three tiers — government and national CERTs, vendor and
community research, and independent journalism.

**[newsfeed-list.txt](newsfeed-list.txt)** in this folder lists every source
with its website and feed URL, in plain text. It is generated from
`newsfeed/sources.py`, so it cannot drift — a test fails if it is stale.
Regenerate with `python3 run.py --write-list`.

Or from the command line:

```bash
python3 run.py --list-sources
```

Every source has a recorded terms review in [docs/SOURCES.md](docs/SOURCES.md)
covering its licence basis, its `robots.txt` position, and whether it ships full
article text. **Nothing is fetched that is not documented there.** If you add a
source, do the review first.

## What it stores, and for how long

| Field | Notes |
| ----- | ----- |
| Headline | As published |
| Publisher | Source name |
| Publication date | From the feed |
| Link | To the original article |
| Excerpt | Truncated to ~300 characters |

**Full article text is never stored**, even when a feed provides it — and five
of these do. Truncation happens at parse time rather than at render time, so a
reproduction never reaches the database in the first place.

**Everything is deleted after 30 days.** Expiry is derived from an article's
publication date, never from when it was fetched, so re-ingesting an article
that is still in a feed cannot extend its life. Expired rows are purged on every
run, and reads filter on expiry as well, so the boundary is exact even if you do
not run the tool for a while.

Content remains the copyright of the publisher. The page links to the original;
it is not a replacement for visiting it.

## Running it on a schedule

The tool is a plain command, so use whatever your OS already has. Pass
`--no-open` so it does not try to launch a browser from a background job.

**Linux / macOS** — `crontab -e`, every six hours:

```bash
0 */6 * * * cd /path/to/intel-threat-newsfeed && /usr/bin/python3 run.py --no-open --quiet
```

**Windows** — Task Scheduler, or from an elevated PowerShell:

```powershell
schtasks /create /tn "Threat Newsfeed" /tr "python C:\path\to\intel-threat-newsfeed\run.py --no-open --quiet" /sc hourly /mo 6
```

Six hours matches how often these publishers actually post. Polling more often
mostly collects `304` responses.

## Options

```
python3 run.py --help
```

| Flag | Purpose |
| ---- | ------- |
| `--no-open` | Do not launch a browser. Use this for scheduled runs. |
| `--no-fetch` | Rebuild the page from the database without touching the network. |
| `--source ID` | Poll one feed only, for debugging. |
| `--list-sources` | Show the source ids. |
| `--write-list` | Regenerate `newsfeed-list.txt` from `sources.py`. |
| `--out PATH` | Write the HTML somewhere else. |
| `--db PATH` | Use a different database location. |
| `--json PATH` | Also write the raw feed document, for piping into other tooling. |
| `--quiet` | Errors only. |
| `--debug` | Verbose logging, including per-source detail. |

`--json` is the integration point if you want to feed this into something else —
a SIEM, a dashboard, a Slack digest. The document is the same shape the page
embeds.

## Known issues

**CISA returns HTTP 403 from some networks.** At the time of writing, the CISA
advisories feed rejects requests from certain IP ranges regardless of
User-Agent — including no User-Agent at all. This is their access control, not a
bug here, and it is not something this tool tries to work around. The run
reports the failure and continues with the other thirteen sources. It may work
fine from your network; try `python3 run.py --source cisa --debug`.

**Dark Web Informer may fail TLS verification on Windows.** Some Python installs
report `unable to get local issuer certificate` for this host while `curl` on the
same machine succeeds, which points at the local trust store rather than a broken
site. The run continues without it.

The supported fix is to repair your trust store — on macOS run the
`Install Certificates.command` that ships with Python, and on Windows upgrade to
a current python.org build or `pip install --upgrade certifi`. **Do not disable
certificate verification.** A man-in-the-middle on a threat feed would let an
attacker choose what you read, which is a worse outcome than missing one source.

A source failing never stops the run. One publisher's outage must not cost you
the other thirteen.

## How it works

```
run.py → newsfeed/pipeline.py
           ├── feed.py      fetch (conditional GET), parse RSS/Atom, excerpt, dedupe
           ├── severity.py  keyword triage rules
           ├── store.py     SQLite: upsert, purge expired
           └── render.py    one self-contained HTML file
```

Three details worth knowing if you intend to modify it:

- **Conditional requests.** Each source's `ETag` and `Last-Modified` are stored
  and sent back on the next poll. CISA's feed alone is ~1.9 MB, so this is the
  difference between a few KB and tens of GB of transfer per month.
- **Untrusted XML.** Feeds are parsed through `defusedxml`, not the standard
  library, because `xml.etree.ElementTree` is vulnerable to entity-expansion
  attacks where a few hundred bytes expand to gigabytes in memory. Bytes that
  XML 1.0 forbids outright are stripped before parsing — one live feed carries a
  literal vertical tab inside a code sample, which would otherwise make the
  whole document unparseable.
- **Untrusted text.** The page builds every element with `textContent`, never
  `innerHTML`. Article titles and excerpts are third-party text, so they are
  treated as data and never as markup. Links are additionally checked for an
  `http(s)` scheme before being rendered.

The data is **embedded** in the HTML rather than fetched from a sibling file,
because a page opened from `file://` cannot fetch its neighbours — browsers treat
each `file://` document as its own opaque origin. Embedding is what makes a
single file work with no web server.

Nothing in the page loads from a CDN or a web font service. A tool for reading
threat intelligence should not phone home, and should keep working on an
air-gapped machine.

## Development

```bash
pip install pytest
python -m pytest tests/ -q
```

90 tests, no network access required.

## Provenance

Extracted from the hosted newsfeed at
[questionallthings.com/ir-tools](https://www.questionallthings.com/ir-tools/),
where the same fetching, parsing and severity logic runs on AWS Lambda against
DynamoDB. This version replaces that storage with SQLite and that web front end
with a generated file, so it needs no cloud account.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).

Bundles [defusedxml](https://github.com/tiran/defusedxml) 0.7.1 by Christian
Heimes, licensed to the PSF under a contributor agreement. See
[vendor/README.md](vendor/README.md).
