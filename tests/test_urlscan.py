"""urlscan.io check: parsing and no-key behaviour (no network)."""
import verification_engine as ve
from verification_engine import VerificationEngine


def _engine(key):
    eng = VerificationEngine(urlscan_api_key=key)
    eng.urlscan_key = key
    return eng


def test_no_key_is_unavailable_not_a_verdict():
    assert _engine("")._urlscan("example.com")["status"] == "UNAVAILABLE"


def test_malicious_scan_is_positive(monkeypatch):
    eng = _engine("k")
    payload = {"results": [{"verdicts": {"overall": {"malicious": True}}},
                           {"verdicts": {"overall": {"malicious": False}}}]}
    monkeypatch.setattr(eng, "_get_with_backoff", lambda url, headers: (payload, "ok"))
    assert eng._urlscan("example.com")["status"] == "POSITIVE_MATCH"


def test_no_scans_is_no_match_not_safe(monkeypatch):
    eng = _engine("k")
    monkeypatch.setattr(eng, "_get_with_backoff", lambda url, headers: ({"results": []}, "ok"))
    res = eng._urlscan("example.com")
    assert res["status"] == "NO_MATCH"
    assert "NOT proof of safety" in res["note"]


def test_only_searches_never_submits(monkeypatch):
    eng = _engine("k")
    seen = {}

    def fake_get(url, headers):
        seen["url"] = url
        seen["headers"] = headers
        return ({"results": []}, "ok")

    monkeypatch.setattr(eng, "_get_with_backoff", fake_get)
    eng._urlscan("example.com")
    assert seen["url"].startswith(ve.URLSCAN_SEARCH_API)
    assert "apikey" not in seen["url"].lower()
    assert seen["headers"]["API-Key"] == "k"
