"""Heuristic severity scoring for newsfeed articles.

**This is a triage aid, not a severity rating.** We have a headline and a
300-character excerpt, not the article, so this is pattern matching over a
fragment of text. It is deliberately transparent: every article carries the list
of signals that produced its rating, so a reader can see the reasoning and
discount it when it is wrong.

Three design choices worth understanding:

*Content type is decided before severity.* A podcast about an actively exploited
flaw is still a podcast -- there is nothing in it to action. Format therefore
short-circuits the severity ladder. Without this, generic vocabulary swallows
these: "Unpacking the Unit 42 2026 Incident Response Report" matches "incident"
long before reaching any rule about reports.

*Undetermined defaults to MEDIUM, not INFORMATIONAL.* Under-calling is the
dangerous direction -- an unusually worded critical advisory that silently lands
in "Informational" is worse than a routine post rated one level too high.

*Rules are ordered most-severe first and stop at the first match.* A post about
an actively exploited flaw should read CRITICAL even though it also matches the
generic "vulnerability" rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFORMATIONAL = "informational"

#: Most severe first. The site orders its filter with this.
SEVERITY_ORDER: tuple[str, ...] = (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)

#: Bumped when the rules change, so a stored rating can be traced to the logic
#: that produced it. Articles are re-scored on re-ingestion, not retroactively.
#:
#: v2: content-type rules added ahead of the severity ladder; vocabulary widened
#: for both active-compromise reporting and non-actionable formats.
RULES_VERSION = 2

DEFAULT_SEVERITY = MEDIUM


@dataclass(frozen=True)
class Rule:
    severity: str
    #: Short label shown to readers as the reason for the rating.
    label: str
    pattern: re.Pattern[str]


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _rx_cs(pattern: str) -> re.Pattern[str]:
    """Case-sensitive, for acronyms that are ordinary words in lower case.

    ``RAT`` is the motivating example: matched case-insensitively it fires on
    the ordinary word "rat".
    """
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# Content type. Evaluated first; a match short-circuits the severity ladder.
#
# These identify the *format* of a post rather than the danger it describes.
# ---------------------------------------------------------------------------
CONTENT_TYPE_RULES: tuple[Rule, ...] = (
    # Note the missing trailing \b on "podcast". SANS ISC titles carry a bare
    # URL containing "podcastdetail", and \bpodcast\b does not match that --
    # which silently left six daily podcast episodes rated Medium.
    Rule(INFORMATIONAL, "podcast", _rx(r"\bpodcast|\bstormcast\b|\bwebcast\b")),
    Rule(INFORMATIONAL, "video", _rx(r"\[\s*video\s*\]|\bvideo\s*:")),
    Rule(INFORMATIONAL, "event", _rx(
        r"\bwebinar\b|\bconference\b|\bregister\s+(?:now|for|here)\b|\bjoin\s+us\b"
        r"|\bblack\s+hat\b|\bdef\s?con\b|\brsa\s+conference\b|\bkeynote\b|\bbooth\b"
    )),
    Rule(INFORMATIONAL, "newsletter or roundup", _rx(
        r"\bnewsletter\b|\bround[- ]?up\b|\brecap\b|\bthis\s+week\s+in\b"
        r"|\bin\s+review\b|\bdigest\b"
    )),
    Rule(INFORMATIONAL, "published report", _rx(
        # "2026 Global Incident Response Report", "annual threat report" -- an
        # announcement of a publication, not an advisory.
        #
        # A bare year was originally part of this alternation and filed genuine
        # threat analysis ("Two H1 2026 attack chains") as Informational. Years
        # appear all over real reporting; the qualifier words do not.
        r"\b(?:annual|global|quarterly|half[- ]year)\s+(?:\w+\s+){0,3}report\b"
        r"|\b(?:releases?|publishes|published|unveils)\s+(?:its\s+|our\s+|the\s+)?(?:\w+\s+){0,4}report\b"
        r"|\breport\s+(?:is\s+)?(?:now\s+)?(?:available|out|published)\b"
    )),
    Rule(INFORMATIONAL, "product announcement", _rx(
        r"\brolls?\s+out\b|\bnow\s+(?:generally\s+)?available\b|\bintroducing\b"
        r"|\blaunch(?:es|ing)\b|\bgeneral\s+availability\b|\bnew\s+feature\b"
    )),
)


# ---------------------------------------------------------------------------
# Severity ladder, most severe first.
# ---------------------------------------------------------------------------
SEVERITY_RULES: tuple[Rule, ...] = (
    # --- Critical: evidence of real-world exploitation or emergency action ---
    Rule(CRITICAL, "actively exploited", _rx(r"\b(activel[y]?\s+exploit|exploited\s+in\s+the\s+wild|in[- ]the[- ]wild\s+exploit|under\s+active\s+(attack|exploitation)|being\s+exploited)")),
    Rule(CRITICAL, "known exploited catalog", _rx(r"\bknown\s+exploited\s+vulnerabilit|\bKEV\b")),
    Rule(CRITICAL, "emergency directive", _rx(r"\bemergency\s+(directive|patch)|\bout[- ]of[- ]band\s+(patch|update)")),
    Rule(CRITICAL, "zero-day", _rx(r"\bzero[- ]day\b|\b0[- ]day\b")),
    Rule(CRITICAL, "CVSS 9.0+", _rx(r"\bCVSS[^0-9]{0,12}(?:9\.\d|10(?:\.0)?)\b")),

    # --- High: a severe flaw class, or a real intrusion being reported -------
    Rule(HIGH, "CVSS 7.0-8.9", _rx(r"\bCVSS[^0-9]{0,12}(?:7\.\d|8\.\d)\b")),
    Rule(HIGH, "remote code execution", _rx(r"\bremote\s+code\s+execution\b|\bRCE\b")),
    Rule(HIGH, "authentication bypass", _rx(r"\bauth(?:entication)?\s+bypass\b|\bbypass\s+authentication\b|\bbypass(?:es|ed)?\s+\w+\s+(?:fixes|mitigations|protections)\b")),
    Rule(HIGH, "privilege escalation", _rx(r"\bprivilege\s+escalation\b|\belevation\s+of\s+privilege\b")),
    Rule(HIGH, "unauthenticated flaw", _rx(r"\bunauthenticated\b")),
    Rule(HIGH, "ransomware", _rx(r"\bransomware\b")),
    # Reporting of an actual intrusion. These were the largest group of
    # under-called articles in the first audit -- "hackers stole", "cyberattack",
    # "extortion" and similar carried no signal at all.
    # A *reported* intrusion, not the topic of intrusions in general.
    #
    # The bare phrase "cyber attack" was too loose: it rated NCSC's recovery
    # guidance ("When cyber attacks happen: helping organisations recover") as
    # High. Requiring a reporting verb nearby, or a concrete consequence,
    # separates "X was attacked" from "attacks, a discussion of".
    Rule(HIGH, "cyberattack reported", _rx(
        r"\b(?:confirms?|confirmed|says?|said|discloses?|disclosed|hit\s+by|suffered"
        r"|victim\s+of|targeted\s+in|claims?\s+responsibility)\b[^.]{0,60}?\bcyber[- ]?attack"
        r"|\bcyber[- ]?attacks?\b[^.]{0,60}?\b(?:disrupt|stole|stolen|breach|extortion|ransom)"
        r"|\bhackers?\s+(?:stole|breached|hacked)\b"
        r"|\bdata[- ]theft\b|\bstole\s+(?:corporate\s+)?data\b|\bextortion\b|\bespionage\b"
    )),
    Rule(HIGH, "malware implant or C2", _rx(r"\bcommand[- ]and[- ]control\b|\bC2\b|\bimplant\b|\binfo[- ]?stealer\b|\bstealer\b|\bworm\b|\bexfiltrat")),
    # Case-sensitive: "RAT" the trojan, not "rat" the rodent.
    Rule(HIGH, "remote access trojan", _rx_cs(r"\bRATs?\b|\bremote\s+access\s+[Tt]rojan\b")),
    Rule(HIGH, "supply chain compromise", _rx(r"\bsupply[- ]chain\s+(attack|compromise)|\bmalicious\s+(package|npm|pypi)")),
    Rule(HIGH, "data breach", _rx(r"\bdata\s+breach\b|\bbreach(?:ed)?\s+(?:millions|thousands)")),
    Rule(HIGH, "active targeting", _rx(r"\b(?:activity|actors?|campaign)\s+targeting\b|\btargeting\s+(?:critical|industrial|government)\b")),
    # "critical" only counts when it is plainly a severity judgement.
    Rule(HIGH, "rated critical", _rx(
        r"\bcritical[- ](?:vulnerabilit|flaw|bug|defect|severity|rce|cve|patch|update|advisor)"
        r"|\b(?:rated|rates|rate|deemed|marked|scored|classified)\b[^.]{0,20}?\bcritical\b"
        r"(?!\s+(?:infrastructure|sector|systems?|services?))"
        r"|\bcritical\s+(?:zero[- ]day|remote\s+code)"
    )),

    # --- Medium: ordinary vulnerability and threat reporting ----------------
    Rule(MEDIUM, "vulnerability advisory", _rx(r"\bvulnerabilit|\bCVE-\d{4}-\d+|\badvisory\b|\bsecurity\s+update\b|\bpatch(?:es|ed)?\b")),
    Rule(MEDIUM, "malware or intrusion", _rx(r"\bmalware\b|\bbackdoor\b|\bbotnet\b|\bphishing\b|\btrojan\b|\bspyware\b|\bthreat\s+actor\b|\bAPT\d*\b|\bintrusion\b")),
    Rule(MEDIUM, "incident or compromise", _rx(r"\bincidents?\b|\bcompromis(?:e|ed|ing)\b|\bleak(?:ed|s)?\b|\bcredential\b|\bpersistence\b|\battack\s+surface\b|\battacks?\b")),

    # --- Low: guidance and programmes, nothing to action urgently -----------
    Rule(LOW, "guidance", _rx(r"\bguidance\b|\bbest\s+practice|\brecommendations?\b|\bhardening\b|\bhow\s+to\b|\bframework\b|\bchecklist\b|\bprinciples\b")),
    Rule(LOW, "programme or workshop", _rx(r"\bworkshop\b|\bconsultancy\b|\btraining\b|\bcourse\b|\bprogramme\b|\bcurriculum\b|\bmigration\s+report\b")),
)


@dataclass(frozen=True)
class Rating:
    severity: str
    #: Labels of every rule that matched, most severe first. Empty when nothing
    #: matched and the default was used.
    signals: tuple[str, ...]

    @property
    def undetermined(self) -> bool:
        return not self.signals


def rate(title: str, excerpt: str = "") -> Rating:
    """Rate an article from its headline and excerpt.

    Content type is checked first and short-circuits. Otherwise the severity of
    the first (most severe) matching rule wins, and every matching label is
    returned so the rating can be explained rather than merely asserted.
    """
    text = f"{title} {excerpt}".strip()
    if not text:
        return Rating(DEFAULT_SEVERITY, ())

    for rule in CONTENT_TYPE_RULES:
        if rule.pattern.search(text):
            return Rating(rule.severity, (rule.label,))

    matched = [rule for rule in SEVERITY_RULES if rule.pattern.search(text)]
    if not matched:
        return Rating(DEFAULT_SEVERITY, ())

    severity = matched[0].severity

    seen: set[str] = set()
    signals: list[str] = []
    for rule in matched:
        if rule.label not in seen:
            seen.add(rule.label)
            signals.append(rule.label)

    return Rating(severity, tuple(signals))
