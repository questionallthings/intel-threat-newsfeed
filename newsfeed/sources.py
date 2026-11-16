"""Approved newsfeed sources.

Every entry here has a terms review recorded in docs/SOURCES.md. Nothing is
ingested that is not listed in both places.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    """A feed we are permitted to poll."""

    id: str
    name: str

    #: The feed itself.
    url: str

    #: The publication's human-readable home page -- where a reader should go to
    #: browse the source rather than consume its XML. Kept here rather than in a
    #: separate document so the two cannot drift apart; newsfeed-list.txt is
    #: generated from this field and a test asserts it is current.
    site_url: str = ""

    #: Seconds to pause before fetching this source, so a run does not fire
    #: every request at once.
    #:
    #: This is NOT robots.txt Crawl-delay compliance. Crawl-delay governs the
    #: interval between successive requests to the *same host*, and we make one
    #: request per host per hour -- orders of magnitude inside even the
    #: strictest declared value (Krebs asks for 35 seconds). This field exists
    #: only to spread our own outbound requests across the run.
    spacing_seconds: int = 1

    #: True when the feed ships the whole article in its content field. Purely
    #: informational -- excerpts are truncated regardless, because relying on a
    #: per-source flag to prevent storing full text is exactly the kind of thing
    #: that silently breaks when someone adds a source and forgets to set it.
    full_text_feed: bool = False


SOURCES: tuple[Source, ...] = (
    # --- Government and national CERTs -----------------------------------
    # The legally cleanest tier: public domain or an explicit open licence,
    # with no copyright ambiguity to manage.
    Source(
        id="cisa",
        site_url="https://www.cisa.gov/cybersecurity-advisories",
        name="CISA Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ),
    Source(
        id="ncsc-uk",
        site_url="https://www.ncsc.gov.uk/",
        name="NCSC UK",
        # all-rss-feed, not report-rss-feed. The latter is live and parses fine
        # but has not published since May 2025, so every item falls outside the
        # 30-day window and ingestion silently yields nothing. Checking a feed
        # is reachable is not the same as checking it is current.
        url="https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    ),
    Source(
        id="cccs",
        site_url="https://www.cyber.gc.ca/en/alerts-advisories",
        name="Canadian Centre for Cyber Security",
        url="https://www.cyber.gc.ca/webservice/en/rss/alerts",
    ),
    # --- Vendor and community research -----------------------------------
    Source(
        id="unit42",
        site_url="https://unit42.paloaltonetworks.com/",
        name="Unit 42",
        url="https://unit42.paloaltonetworks.com/feed/",
    ),
    Source(
        id="talos",
        site_url="https://blog.talosintelligence.com/",
        name="Cisco Talos",
        url="https://blog.talosintelligence.com/rss/",
        full_text_feed=True,
    ),
    Source(
        id="sans-isc",
        site_url="https://isc.sans.edu/",
        name="SANS Internet Storm Center",
        url="https://isc.sans.edu/rssfeed_full.xml",
        full_text_feed=True,
    ),
    Source(
        id="socradar",
        site_url="https://socradar.io/blog/",
        name="SOCRadar",
        url="https://socradar.io/feed/",
        full_text_feed=True,
    ),
    Source(
        id="google-ti",
        site_url="https://cloud.google.com/blog/topics/threat-intelligence",
        name="Google Threat Intelligence",
        # cloud.google.com/blog/topics/threat-intelligence/rss returns 200 with
        # a JavaScript-rendered page rather than a feed. This FeedBurner address
        # is the one that actually serves RSS.
        url="https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    ),
    # --- Independent journalism ------------------------------------------
    Source(
        id="krebs",
        site_url="https://krebsonsecurity.com/",
        name="Krebs on Security",
        url="https://krebsonsecurity.com/feed/",
        full_text_feed=True,
    ),
    Source(
        id="bleepingcomputer",
        site_url="https://www.bleepingcomputer.com/",
        name="BleepingComputer",
        url="https://www.bleepingcomputer.com/feed/",
    ),
    Source(
        id="thehackernews",
        site_url="https://thehackernews.com/",
        name="The Hacker News",
        # The publisher's own domain rather than their FeedBurner address.
        # Identical content, one less third party in the path.
        url="https://thehackernews.com/feeds/posts/default",
    ),
    Source(
        id="darkreading",
        site_url="https://www.darkreading.com/",
        name="Dark Reading",
        url="https://www.darkreading.com/rss.xml",
    ),
    Source(
        id="helpnetsecurity",
        site_url="https://www.helpnetsecurity.com/",
        name="Help Net Security",
        url="https://www.helpnetsecurity.com/feed/",
    ),
    Source(
        id="darkwebinformer",
        site_url="https://darkwebinformer.com/",
        name="Dark Web Informer",
        # Feed path found by autodiscovery; /feed/ 301s and /rss.xml 404s.
        #
        # Note: this host fails certificate verification on some Python
        # installs, Windows especially ("unable to get local issuer
        # certificate"), while curl on the same machine succeeds. That points at
        # the local trust store rather than a broken site.
        #
        # If it happens, this source reports an error and the run continues with
        # the other thirteen. Do NOT "fix" it by disabling verification: a
        # man-in-the-middle on a threat feed would let an attacker choose what
        # you read. See the README for the supported fix.
        url="https://darkwebinformer.com/rss/",
        full_text_feed=True,
    ),
)

SOURCES_BY_ID = {source.id: source for source in SOURCES}
