"""Phantom squatting: a domain judged not to exist earlier is remembered."""
import db


def _log(path, url, domain, exists, label, reason=None):
    db.log_result({"url": url, "domain": domain, "stage_reached": "A" if not exists else "B",
                   "exists": exists, "final_label": label, "reason": reason}, db_path=path)


def test_earlier_hallucination_is_found_for_the_same_domain(tmp_path):
    p = tmp_path / "h.db"
    _log(p, "https://made-up-bank-login.com/x", "made-up-bank-login.com", False, "Hallucination")
    assert len(db.previous_hallucinations("made-up-bank-login.com", p)) == 1


def test_real_domain_has_no_earlier_hallucination(tmp_path):
    p = tmp_path / "h.db"
    _log(p, "https://www.bnm.gov.my/", "bnm.gov.my", True, "Likely Safe")
    assert db.previous_hallucinations("bnm.gov.my", p) == []


def test_other_domains_are_not_mixed_up(tmp_path):
    p = tmp_path / "h.db"
    _log(p, "https://made-up-bank-login.com/x", "made-up-bank-login.com", False, "Hallucination")
    assert db.previous_hallucinations("other-site.com", p) == []


def test_empty_domain_returns_nothing(tmp_path):
    assert db.previous_hallucinations("", tmp_path / "h.db") == []


def test_page_level_404_is_not_treated_as_phantom_squatting(tmp_path):
    # The domain resolved and WHOIS confirmed it; only the web page 404'd
    # (or a WAF blocked it). That is not evidence that the domain was invented.
    p = tmp_path / "h.db"
    _log(p, "https://www.ftc.gov/", "www.ftc.gov", False, "Hallucination",
         reason=("DNS resolves to a live A/AAAA record; this exact page returns "
                 "HTTP 404 (not found); HTTP probe: page is GONE (status 404). "
                 "-> likely fabricated"))
    assert db.previous_hallucinations("www.ftc.gov", p) == []


def test_domain_level_hallucination_still_triggers_phantom_squatting(tmp_path):
    p = tmp_path / "h.db"
    _log(p, "https://invented-bank.example/", "invented-bank.example", False,
         "Hallucination", reason="DNS returns NXDOMAIN (no such host). "
                                 "-> likely fabricated")
    assert len(db.previous_hallucinations("invented-bank.example", p)) == 1
