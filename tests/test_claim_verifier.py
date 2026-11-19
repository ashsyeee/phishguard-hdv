"""H2 claim verification: the URL is real, the sentence around it may not be."""

import pytest

from claim_verifier import assess_claims, summarize

SOURCES_NO_MATCH = {"virustotal": {"status": "NO_MATCH"},
                    "urlhaus": {"status": "NO_MATCH"}}
SOURCES_POSITIVE = {"virustotal": {"status": "POSITIVE_MATCH"},
                    "urlhaus": {"status": "NO_MATCH"}}
PAGE_CLEAN = {"fetched": True, "has_password_field": False,
              "suspicious": False, "status": 200}
PAGE_LOGIN = {"fetched": True, "has_password_field": True,
              "suspicious": False, "status": 200}
PAGE_FAKE = {"fetched": True, "has_password_field": True,
             "suspicious": True, "status": 200}


def assess(text, url, domain, **kw):
    kw.setdefault("exists", True)
    return assess_claims(text, url, domain, **kw)


def test_official_claim_on_official_domain_is_supported():
    out = assess("https://www.maybank2u.com.my is the official Maybank2u page.",
                 "https://www.maybank2u.com.my", "www.maybank2u.com.my",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    official = [c for c in out["claims"] if c["type"] == "OFFICIAL"]
    assert official and official[0]["verdict"] == "supported"


def test_official_claim_on_lookalike_is_contradicted():
    out = assess("https://maybank2u-secure.top is the official Maybank login page.",
                 "https://maybank2u-secure.top", "maybank2u-secure.top",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    assert out["verdict"] == "contradicted"
    assert any(c["type"] == "OFFICIAL" and c["verdict"] == "contradicted"
               for c in out["claims"])


def test_official_claim_on_a_listed_sso_domain_is_supported():
    """A non-exhaustive official list cannot refute a genuine SSO host."""
    out = assess("Always verify that prompts point to the official Microsoft "
                 "https://login.microsoftonline.com domain.",
                 "https://login.microsoftonline.com",
                 "login.microsoftonline.com",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    official = [c for c in out["claims"] if c["type"] == "OFFICIAL"]
    assert official and official[0]["verdict"] == "supported"


def test_unlisted_regional_domain_is_unsupported_not_contradicted():
    """cimb.com.sg is a genuine regional site that the MY list omits."""
    out = assess("Always verify you are on the official CIMB "
                 "https://www.cimb.com.sg domain.",
                 "https://www.cimb.com.sg", "www.cimb.com.sg",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    official = [c for c in out["claims"] if c["type"] == "OFFICIAL"]
    assert official and official[0]["verdict"] == "unsupported"
    assert out["verdict"] != "contradicted"


def test_real_world_phrasing_is_not_an_official_claim():
    out = assess("Below are documented, real-world phishing URLs: "
                 "http://paypal-service-update.com",
                 "http://paypal-service-update.com",
                 "paypal-service-update.com",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    assert not [c for c in out["claims"] if c["type"] == "OFFICIAL"]


def test_threat_claim_without_feed_match_is_unsupported_not_safe():
    """Absence of a match must never be reported as 'the claim is false'."""
    out = assess("http://pbebank-online-my.com is a phishing page.",
                 "http://pbebank-online-my.com", "pbebank-online-my.com",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    threat = [c for c in out["claims"] if c["type"] == "THREAT"]
    assert threat and threat[0]["verdict"] == "unsupported"
    assert "not proof of safety" in threat[0]["detail"]


def test_threat_claim_with_feed_match_is_supported():
    out = assess("http://evil-bank.top steals credentials.",
                 "http://evil-bank.top", "evil-bank.top",
                 sources=SOURCES_POSITIVE, page=PAGE_CLEAN)
    assert any(c["type"] == "THREAT" and c["verdict"] == "supported"
               for c in out["claims"])


def test_uncited_attribution_is_unsupported():
    out = assess("According to PhishTank, http://bad.top is phishing.",
                 "http://bad.top", "bad.top",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    attr = [c for c in out["claims"] if c["type"] == "ATTRIBUTION"]
    assert attr and attr[0]["verdict"] == "unsupported"


def test_attribution_to_a_queried_source_without_match_is_unsupported():
    out = assess("According to VirusTotal, http://bad.top is phishing.",
                 "http://bad.top", "bad.top",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    attr = [c for c in out["claims"] if c["type"] == "ATTRIBUTION"]
    assert attr and attr[0]["verdict"] == "unsupported"


def test_login_claim_is_never_contradicted_by_static_html_alone():
    """A JS-rendered login form leaves no password field in the HTML."""
    out = assess("https://www.cimbclicks.com.my is the login page.",
                 "https://www.cimbclicks.com.my", "www.cimbclicks.com.my",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    login = [c for c in out["claims"] if c["type"] == "LOGIN"]
    assert login and login[0]["verdict"] == "unsupported"
    assert login[0]["blocking"] is False


def test_login_claim_supported_when_password_field_present():
    out = assess("https://login.example-bank.com is the login page.",
                 "https://login.example-bank.com", "login.example-bank.com",
                 sources=SOURCES_NO_MATCH, page=PAGE_LOGIN)
    login = [c for c in out["claims"] if c["type"] == "LOGIN"]
    assert login and login[0]["verdict"] == "supported"


def test_list_context_inherits_the_heading():
    """Indicators printed under a heading must inherit the heading's claim."""
    text = ("The following are documented phishing indicators:\n"
            "http://pbebank-online-my.com")
    out = assess(text, "http://pbebank-online-my.com", "pbebank-online-my.com",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    assert any(c["type"] == "THREAT" for c in out["claims"])


def test_empty_text_is_no_claim():
    out = assess("", "http://x.top", "x.top")
    assert out["verdict"] == "no_claim"
    assert out["claims"] == []


def test_summarize_is_human_readable():
    out = assess("https://maybank2u-secure.top is the official Maybank page.",
                 "https://maybank2u-secure.top", "maybank2u-secure.top",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    text = summarize(out)
    assert text.startswith("claim check (contradicted)")
    assert "official" in text.lower()


def test_non_blocking_login_gap_does_not_dominate_a_supported_official_claim():
    out = assess("https://www.maybank2u.com.my is the official Maybank page.",
                 "https://www.maybank2u.com.my", "www.maybank2u.com.my",
                 sources=SOURCES_NO_MATCH, page=PAGE_CLEAN)
    assert out["verdict"] == "supported"
