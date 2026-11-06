"""Gemini error-handling tests.

Verifies that:
  * errors are classified per-category instead of assumed to be quota/rate
    limiting;
  * the ORIGINAL exception (type + message + status code) is logged to the
    terminal in the required format;
  * API keys / raw exception detail never reach the returned UI payload or the
    logs;
  * a failed request never fabricates model text (success=False, text="").

No network calls are made: the Gemini client is monkeypatched to raise.
"""
import logging

import pytest

from google.genai import errors as genai_errors

from modules.llm_analyzer import (GeminiAnalyzer, classify_gemini_error,
                                  _redact)

RATE_LIMIT_MSG = ("⚠️ Gemini is temporarily unavailable due to an API usage "
                  "limit. Please try again later.")
UNEXPECTED_MSG = "⚠️ Gemini encountered an unexpected error. Please try again."


def _api_error(code, status, message):
    return genai_errors.ClientError(
        code, {"error": {"status": status, "message": message}})


def _analyzer_raising(monkeypatch, exc, api_key="test-key"):
    an = GeminiAnalyzer(api_key=api_key)

    def _boom():
        raise exc

    monkeypatch.setattr(an, "_get_client", _boom)
    return an


# ---------------------------------------------------------------------------
# Classification is based on the real exception, not a blanket assumption
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc,expected", [
    (_api_error(429, "RESOURCE_EXHAUSTED", "Quota exceeded"), "rate_limit"),
    (_api_error(401, "UNAUTHENTICATED", "API key not valid"), "auth"),
    (_api_error(403, "PERMISSION_DENIED", "caller has no permission"), "auth"),
    (_api_error(404, "NOT_FOUND", "models/gemini-x is not found"),
     "model_unavailable"),
    (TimeoutError("connection timed out"), "network"),
    (ConnectionError("network is unreachable"), "network"),
    (RuntimeError("something completely unexpected"), "unexpected"),
])
def test_error_classification(exc, expected):
    assert classify_gemini_error(exc)["category"] == expected


def test_generic_error_is_not_assumed_to_be_quota():
    # The old handler treated many failures as quota - it must not anymore.
    info = classify_gemini_error(ValueError("invalid contents payload"))
    assert info["category"] == "unexpected"


def test_status_code_extracted_when_available():
    info = classify_gemini_error(_api_error(429, "RESOURCE_EXHAUSTED", "x"))
    assert info["status_code"] == 429
    # A plain Python error has no status code.
    assert classify_gemini_error(RuntimeError("boom"))["status_code"] is None


def test_user_messages_are_category_specific():
    assert classify_gemini_error(
        _api_error(429, "RESOURCE_EXHAUSTED", "x"))["user_message"] == RATE_LIMIT_MSG
    assert classify_gemini_error(
        RuntimeError("boom"))["user_message"] == UNEXPECTED_MSG


# ---------------------------------------------------------------------------
# analyze_threat: structured result, no fabrication, logging, no leakage
# ---------------------------------------------------------------------------

def test_failed_request_never_fabricates_text(monkeypatch):
    an = _analyzer_raising(
        monkeypatch, _api_error(429, "RESOURCE_EXHAUSTED", "Quota exceeded"))
    res = an.analyze_threat("q")
    assert res["success"] is False
    assert res["text"] == ""
    assert res["error_category"] == "rate_limit"
    assert res["error"] == RATE_LIMIT_MSG


def test_original_exception_is_logged_to_terminal(monkeypatch, caplog):
    exc = _api_error(503, "UNAVAILABLE", "The model is overloaded")
    an = _analyzer_raising(monkeypatch, exc)
    with caplog.at_level(logging.ERROR, logger="phishguard.llm"):
        an.analyze_threat("q")
    assert "GEMINI API ERROR" in caplog.text
    assert "Error type: ClientError" in caplog.text
    assert "Error message: The model is overloaded" in caplog.text
    assert "HTTP status code: 503" in caplog.text
    assert "API status: UNAVAILABLE" in caplog.text


def test_api_key_never_leaks_to_payload_or_logs(monkeypatch, caplog):
    secret = "AIzaSyTESTONLYSECRET123456789012"
    an = _analyzer_raising(
        monkeypatch,
        RuntimeError(f"401 UNAUTHENTICATED x-goog-api-key: {secret}"),
        api_key=secret)
    with caplog.at_level(logging.ERROR, logger="phishguard.llm"):
        res = an.analyze_threat("q")
    assert res["error_category"] == "auth"
    assert secret not in caplog.text
    assert secret not in str(res)
    assert "***" in caplog.text


def test_raw_exception_detail_never_reaches_payload(monkeypatch):
    an = _analyzer_raising(
        monkeypatch, RuntimeError("INTERNAL detail that must not reach the UI"))
    res = an.analyze_threat("q")
    assert "INTERNAL detail" not in str(res)


def test_missing_key_is_auth_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    res = GeminiAnalyzer(api_key="").analyze_threat("q")
    assert res["success"] is False
    assert res["error_category"] == "auth"
    # The env var NAME/value must not be echoed into the UI message.
    assert "GEMINI_API_KEY" not in (res["error"] or "")


def test_empty_prompt_is_validation(monkeypatch):
    res = GeminiAnalyzer(api_key="k").analyze_threat("   ")
    assert res["success"] is False
    assert res["error_category"] == "validation"


def test_redact_helper_removes_keys():
    assert "AIzaSyABCDEFGHIJKLMNOP" not in _redact(
        "key=AIzaSyABCDEFGHIJKLMNOP", "AIzaSyABCDEFGHIJKLMNOP")
    assert "***" in _redact("x-goog-api-key: AIzaSyABCDEFGHIJ", "")
