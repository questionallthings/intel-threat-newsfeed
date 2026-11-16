"""Tests for heuristic severity scoring.

Weighted towards false positives and under-calling, which are the two failure
modes that matter: a wrong CRITICAL causes alarm fatigue, and a wrong
INFORMATIONAL buries something that needed attention.
"""

import pytest

from newsfeed.severity import (
    CRITICAL,
    DEFAULT_SEVERITY,
    HIGH,
    INFORMATIONAL,
    LOW,
    MEDIUM,
    SEVERITY_ORDER,
    rate,
)


# --- critical -------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "Flaw is being actively exploited in attacks",
        "Zero-day in widget exploited in the wild",
        "CISA adds one Known Exploited Vulnerability to catalog",
        "Emergency directive issued for federal agencies",
        "Vendor ships out-of-band patch for severe flaw",
    ],
)
def test_exploitation_evidence_rates_critical(title):
    assert rate(title).severity == CRITICAL


def test_cvss_nine_or_above_is_critical():
    assert rate("Widget flaw carries CVSS 9.8 score").severity == CRITICAL
    assert rate("Rated CVSS 10.0 by the vendor").severity == CRITICAL


# --- high -----------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "Unauthenticated remote code execution in appliance",
        "Authentication bypass found in gateway",
        "Ransomware group claims attack on manufacturer",
        "Malicious npm package steals credentials",
        "Privilege escalation flaw patched",
    ],
)
def test_severe_flaw_classes_rate_high(title):
    assert rate(title).severity == HIGH


def test_cvss_seven_to_eight_is_high():
    assert rate("Issue rated CVSS 7.5").severity == HIGH
    assert rate("Issue rated CVSS 8.1").severity == HIGH


# --- the false positive that would otherwise dominate ---------------------


def test_critical_infrastructure_is_not_a_severity_signal():
    # Government advisories say "critical infrastructure" constantly. Treating
    # that as a severity word would rate most of CISA and CCCS as High.
    rating = rate("CISA urges critical infrastructure owners to review guidance")
    assert rating.severity != HIGH
    assert "rated critical" not in rating.signals


@pytest.mark.parametrize(
    "phrase",
    [
        "protecting critical infrastructure sectors",
        "advice for critical systems operators",
        "guidance for critical services providers",
        # Ordinary prose. An earlier rule matched the bare word and rated
        # unrelated commentary as High.
        "How AI exposed a browser security gap enterprises cannot ignore, a critical gap",
        "mission critical workloads in the enterprise",
        "it is critical that teams review their logging",
    ],
)
def test_critical_as_ordinary_prose_does_not_inflate(phrase):
    assert "rated critical" not in rate(phrase).signals


@pytest.mark.parametrize(
    "phrase",
    [
        "Vendor rates the flaw critical",
        "A critical vulnerability in the gateway",
        "critical severity issue disclosed",
        "critical flaw patched this week",
    ],
)
def test_critical_as_severity_still_matches(phrase):
    assert "rated critical" in rate(phrase).signals


# --- lower bands ----------------------------------------------------------


def test_ordinary_vulnerability_reporting_is_medium():
    assert rate("Vendor patches CVE-2026-1234 in its product").severity == MEDIUM


def test_guidance_is_low():
    assert rate("New guidance on password best practices published").severity == LOW


@pytest.mark.parametrize(
    "title",
    [
        "[Webinar] Tales from the frontlines",
        "Threat roundup for the week",
        "Black Hat special: rewind and revisit",
    ],
)
def test_events_and_roundups_are_informational(title):
    assert rate(title).severity == INFORMATIONAL


# --- defaults and explainability -----------------------------------------


def test_no_signals_defaults_to_medium_not_informational():
    # Under-calling is the dangerous direction. An article we cannot classify
    # should sit in the middle, not be buried in Informational.
    #
    # Note the wording: an earlier version used "Company announces quarterly
    # results", which legitimately matched the announcement rule and so never
    # exercised the default at all.
    rating = rate("A profile of the team behind the project")
    assert rating.severity == DEFAULT_SEVERITY == MEDIUM
    assert rating.undetermined


def test_empty_input_is_undetermined():
    rating = rate("", "")
    assert rating.severity == MEDIUM
    assert rating.undetermined


def test_most_severe_rule_wins_over_generic_ones():
    # Mentions exploitation *and* the generic word "vulnerability". The former
    # must decide the rating.
    rating = rate("Vulnerability actively exploited in the wild, patch available")
    assert rating.severity == CRITICAL
    assert rating.signals[0] == "actively exploited"


def test_signals_are_reported_for_explainability():
    rating = rate("Unauthenticated remote code execution flaw, CVSS 9.8, exploited in the wild")
    assert rating.severity == CRITICAL
    assert len(rating.signals) > 1
    assert not rating.undetermined


def test_excerpt_contributes_to_the_rating():
    rating = rate("Advisory published", "The flaw is being actively exploited.")
    assert rating.severity == CRITICAL


def test_signals_are_deduplicated():
    rating = rate("Ransomware ransomware ransomware attack")
    assert rating.signals.count("ransomware") == 1


# --- content type wins over severity keywords ----------------------------


@pytest.mark.parametrize(
    "title",
    [
        # The regex bug that filed six daily episodes as Medium: these titles
        # carry a bare URL containing "podcastdetail", which \bpodcast\b misses.
        "ISC Stormcast For Monday, August 10th, 2026 https://isc.sans.edu/podcastdetail/10044",
        "[Video] Where protection starts: Talos Intelligence Integrations",
        "Threat roundup for the week",
        "OpenAI rolls out a major ChatGPT upgrade",
        "Unpacking the Unit 42 2026 Global Incident Response Report",
    ],
)
def test_content_type_is_informational(title):
    assert rate(title).severity == INFORMATIONAL


def test_content_type_beats_severity_vocabulary():
    # A podcast about an actively exploited flaw is still a podcast -- there is
    # nothing in it to action. Without the content-type pass this would be
    # CRITICAL.
    rating = rate("ISC Stormcast: zero-day actively exploited in the wild")
    assert rating.severity == INFORMATIONAL
    assert rating.signals == ("podcast",)


# --- reported intrusions vs. talking about intrusions ---------------------


@pytest.mark.parametrize(
    "title",
    [
        "Levi Strauss & Co. says hackers stole corporate data in cyberattack",
        "North Carolina Ports confirms cyberattack disrupting operations",
        "Hedge fund attacks tied to a linked extortion group",
        "Russian global webmail espionage",
        "Atomic macOS stealer infection spreading",
        "Inside a self-propagating npm worm",
        "Actor deploys novel RAT and bespoke C2 implant",
    ],
)
def test_reported_intrusions_rate_high(title):
    assert rate(title).severity == HIGH


def test_guidance_about_attacks_is_not_a_reported_attack():
    # NCSC recovery guidance. An earlier rule matched the bare phrase "cyber
    # attacks" and rated this High.
    rating = rate("When cyber attacks happen: helping organisations recover")
    assert rating.severity != HIGH
    assert "cyberattack reported" not in rating.signals


def test_year_in_title_does_not_make_analysis_a_report():
    # Genuine threat analysis. A bare-year pattern in the "published report"
    # rule filed this as Informational, which is the dangerous direction.
    rating = rate("Real emails, hijacked payments: Two H1 2026 attack chains")
    assert rating.severity != INFORMATIONAL


def test_rat_acronym_is_case_sensitive():
    # "RAT" the trojan, not "rat" the rodent.
    assert "remote access trojan" in rate("Actor deploys a new RAT").signals
    assert "remote access trojan" not in rate("a rat in the server room").signals


def test_programmes_and_workshops_are_low():
    assert rate("Post-quantum cryptography migration workshop report").severity == LOW
    assert rate("Helping small businesses with free, hands-on consultancy").severity == LOW


def test_every_rated_severity_is_a_known_level():
    for title in ["exploited in the wild", "webinar", "guidance", "CVE-2026-1", "unknown text"]:
        assert rate(title).severity in SEVERITY_ORDER
