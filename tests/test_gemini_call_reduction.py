"""Gemini call-reduction tests.

Confirms ONE user submission maps to ONE Gemini HTTP request:
  * the SDK's default HTTP retry (5 attempts, 429 included) is disabled
    (attempts=1);
  * automatic function calling is disabled (no tools are ever used);
  * analyze_threat makes exactly one generate_content call and never retries;
  * the request lifecycle is logged (START / COMPLETE / FAILED) without keys.
"""
import logging
import types

import pytest

from google.genai import errors as genai_errors

from modules.llm_analyzer import GeminiAnalyzer


class _FakeModels:
    def __init__(self, text="hello", raises=None):
        self.calls = 0
        self.configs = []
        self._text = text
        self._raises = raises

    def generate_content(self, model, contents, config):
        self.calls += 1
        self.configs.append(config)
        if self._raises is not None:
            raise self._raises
        return types.SimpleNamespace(text=self._text)


class _FakeClient:
    def __init__(self, models):
        self.models = models


def _wire(monkeypatch, an, fm):
    monkeypatch.setattr(an, "_get_client", lambda: _FakeClient(fm))


def _rate_limited():
    return genai_errors.ClientError(
        429, {"error": {"status": "RESOURCE_EXHAUSTED", "message": "quota"}})


# ---------------------------------------------------------------------------
# SDK retry + AFC are disabled
# ---------------------------------------------------------------------------

def test_client_disables_sdk_http_retries(monkeypatch):
    captured = {}

    class _CaptureClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import google.genai as genai_mod
    monkeypatch.setattr(genai_mod, "Client", _CaptureClient)

    GeminiAnalyzer(api_key="k")._get_client()
    http_options = captured.get("http_options")
    assert http_options is not None
    assert http_options.retry_options.attempts == 1  # no SDK-level retries


def test_config_disables_afc(monkeypatch):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels()
    _wire(monkeypatch, an, fm)
    an.analyze_threat("q")
    cfg = fm.configs[0]
    assert cfg.automatic_function_calling is not None
    assert cfg.automatic_function_calling.disable is True


# ---------------------------------------------------------------------------
# Exactly one request per submission; no retry loop on 429
# ---------------------------------------------------------------------------

def test_one_submission_makes_exactly_one_request(monkeypatch):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels()
    _wire(monkeypatch, an, fm)
    res = an.analyze_threat("q", reason="unit")
    assert res["success"] is True
    assert fm.calls == 1
    assert res["request_id"]


def test_429_is_not_retried_by_our_code(monkeypatch):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels(raises=_rate_limited())
    _wire(monkeypatch, an, fm)
    res = an.analyze_threat("q")
    assert res["success"] is False
    assert res["error_category"] == "rate_limit"
    assert fm.calls == 1  # one attempt, surfaced to the user - no retry loop


# ---------------------------------------------------------------------------
# Request lifecycle logging (+ no secrets)
# ---------------------------------------------------------------------------

def test_request_lifecycle_logged_on_success(monkeypatch, caplog):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels()
    _wire(monkeypatch, an, fm)
    with caplog.at_level(logging.INFO, logger="phishguard.llm"):
        res = an.analyze_threat("q", reason="unit-reason")
    text = caplog.text
    assert "GEMINI REQUEST START" in text
    assert "Reason: unit-reason" in text
    assert f"Model: {an.model_id}" in text
    assert "GEMINI REQUEST COMPLETE" in text
    assert res["request_id"] in text


def test_request_failure_logged_with_status(monkeypatch, caplog):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels(raises=_rate_limited())
    _wire(monkeypatch, an, fm)
    with caplog.at_level(logging.INFO, logger="phishguard.llm"):
        an.analyze_threat("q")
    assert "GEMINI REQUEST FAILED" in caplog.text
    assert "Status: 429" in caplog.text


def test_request_logs_never_contain_api_key(monkeypatch, caplog):
    secret = "AIzaSyTESTONLYSECRET123456789012"
    an = GeminiAnalyzer(api_key=secret)
    fm = _FakeModels()
    _wire(monkeypatch, an, fm)
    with caplog.at_level(logging.INFO, logger="phishguard.llm"):
        an.analyze_threat("q")
    assert secret not in caplog.text


def test_validation_does_not_issue_a_request(monkeypatch):
    an = GeminiAnalyzer(api_key="k")
    fm = _FakeModels()
    _wire(monkeypatch, an, fm)
    res = an.analyze_threat("   ")
    assert res["success"] is False
    assert res["error_category"] == "validation"
    assert fm.calls == 0  # nothing sent to Gemini
