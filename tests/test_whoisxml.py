"""WhoisXML age lookup: parsing and no-key behaviour (no network)."""
import types

import verification_engine as ve
from verification_engine import VerificationEngine


def test_no_key_returns_none():
    eng = VerificationEngine(whoisxml_api_key="")
    eng.whoisxml_key = ""
    assert eng.domain_age_days("example.com") is None


def test_parses_normalised_date_with_utc_suffix(monkeypatch):
    eng = VerificationEngine(whoisxml_api_key="k")
    fake = types.SimpleNamespace(
        status_code=200,
        json=lambda: {"WhoisRecord": {"createdDateNormalized": "2010-01-01 04:00:00 UTC"}})
    monkeypatch.setattr(ve.requests, "post", lambda *a, **kw: fake)
    age = eng.domain_age_days("example.com")
    assert age is not None and age > 5000


def test_key_is_sent_in_body_not_url(monkeypatch):
    eng = VerificationEngine(whoisxml_api_key="k")
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen["url"] = url
        seen["json"] = json
        return types.SimpleNamespace(status_code=403, json=lambda: {})

    monkeypatch.setattr(ve.requests, "post", fake_post)
    eng.domain_age_days("example.com")
    assert "apiKey" not in seen["url"]
    assert seen["json"]["apiKey"] == "k"
