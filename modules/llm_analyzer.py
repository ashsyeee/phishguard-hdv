"""
llm_analyzer.py - Gemini integration (AI Threat Intelligence page).

Responsibilities:
  * accept a user cybersecurity question
  * send it to Gemini
  * return the response in a clean structure
  * handle API errors gracefully (never crash the app)
  * NEVER hard-code or expose the API key (loaded from .env)
  * classify failures into DISTINCT categories instead of assuming every
    Gemini exception is a quota / rate-limit problem

The system NEVER trusts Gemini's output - every URL it produces goes through
the independent verification pipeline downstream.

ERROR HANDLING
--------------
Every failed request is classified as one of:

    rate_limit        HTTP 429 / RESOURCE_EXHAUSTED / explicit quota error
    auth              401/403 / UNAUTHENTICATED / PERMISSION_DENIED / bad key
    model_unavailable 404 / NOT_FOUND / model no longer available
    network           timeout / connection / DNS / TLS failure
    unexpected        anything else

The ORIGINAL exception is logged to the TERMINAL (never the UI) as:

    GEMINI API ERROR
    Error type: <exception class>
    Error message: <original exception message>
    HTTP status code: <code>          # only when available
    API status: <status>              # only when available
    Category: <category>

The UI only ever receives a safe, category-specific message. API keys,
credentials, stack traces and other sensitive configuration are never placed
in the returned payload - diagnostic detail stays in the terminal log.

MODEL NOTE: the FYP brief specified "gemini-2.5-flash". Google retired that
model for new accounts (September 2026) and replaced it with gemini-3.6-flash.
The report should state that the deployed model is gemini-3.6-flash (the
project contribution is the verification layer, not a specific model).
"""
from __future__ import annotations

import logging
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

logger = logging.getLogger("phishguard.llm")
logger.setLevel(logging.INFO)
if not logging.getLogger().handlers:
    # Plain script / non-Streamlit run: guarantee diagnostics reach the
    # terminal. Under Streamlit logging is already configured, so leave it.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

MODEL_ID = "gemini-3.6-flash"
MODEL_ID_DOCUMENTED = "gemini-3.6-flash (replaces retired gemini-2.5-flash)"

SYSTEM_INSTRUCTION = (
    "You are a defensive cybersecurity threat-intelligence analyst. "
    "Report real phishing threats and campaigns in plain text. "
    "Always include the relevant full URL(s) in your answer whenever the "
    "question concerns a website, brand, bank, organisation, advisory, "
    "campaign, or threat. When you are confident of the correct address - for "
    "example an organisation's well-known official site - write it out. "
    "Whenever you describe or mention a specific phishing campaign, URL, or "
    "domain, ALWAYS write the exact indicator as a complete clickable URL "
    "with an explicit scheme (e.g. 'https://example-login.com'), one URL per "
    "line, and give at least one relevant URL when one exists. "
    "NEVER invent, guess, or fabricate URLs, and never use placeholder names "
    "such as 'example.com' as if they were real: only include URLs you "
    "believe actually exist and are relevant. If you genuinely do not know a "
    "URL, say so instead of making one up. State clearly when information is "
    "uncertain or unverified."
)

# ---------------------------------------------------------------------------
# Safe, category-specific user messages. These are the ONLY error text the UI
# ever sees; they never contain exception details, keys or configuration.
# {p} is the provider name ("Gemini", "OpenRouter", ...).
# ---------------------------------------------------------------------------
_MESSAGE_TEMPLATES = {
    "rate_limit":
        "⚠️ {p} is temporarily unavailable due to an API usage limit. "
        "Please try again later.",
    "auth":
        "⚠️ {p} authentication failed. Check that the API key is "
        "configured correctly.",
    "model_unavailable":
        "⚠️ The configured {p} model is unavailable. Check the model name "
        "in the configuration.",
    "network":
        "⚠️ {p} could not be reached due to a temporary connection "
        "problem. Please try again.",
    "unexpected":
        "⚠️ {p} encountered an unexpected error. Please try again.",
    "validation":
        "⚠️ Please enter a question before generating.",
}


def user_message(category: str, provider: str = "Gemini") -> str:
    """Safe, category-specific UI message for a provider."""
    template = _MESSAGE_TEMPLATES.get(category, _MESSAGE_TEMPLATES["unexpected"])
    return template.format(p=provider)


# Gemini defaults (kept for backward compatibility / direct references).
USER_MESSAGES = {c: user_message(c) for c in _MESSAGE_TEMPLATES}


# ===========================================================================
# Error classification (pure functions - unit tested without any network)
# ===========================================================================

# Transport-level failures. requests/httpx are optional imports so this module
# still loads if only the base SDK is installed.
_NETWORK_EXC: tuple = (TimeoutError, ConnectionError)
try:  # requests is used elsewhere in the project, but stay defensive.
    import requests as _requests
    _NETWORK_EXC += (_requests.exceptions.RequestException,)
except Exception:  # pragma: no cover
    pass
try:  # the google-genai SDK is httpx-based.
    import httpx as _httpx
    _NETWORK_EXC += (_httpx.HTTPError,)
except Exception:  # pragma: no cover
    pass

_RATE_LIMIT_MARKERS = (
    "resource exhausted", "resource_exhausted", "rate limit", "rate_limit",
    "rate-limit", "ratelimit", "quota", "too many requests",
)
_AUTH_MARKERS = (
    "unauthenticated", "permission denied", "permission_denied", "forbidden",
    "api key", "api_key", "apikey", "invalid authentication",
    "credentials", "not authorized", "unauthorized",
)
_MODEL_MARKERS = (
    "not found", "not_found", "does not exist", "not available", "no longer",
    "unsupported", "decommissioned", "unknown model", "invalid model",
)
_NETWORK_MARKERS = (
    "timeout", "timed out", "connection", "network", "dns", "unreachable",
    "ssl", "eof", "reset by peer", "temporarily unavailable",
)

# Secrets must never reach the UI or the database. Redact them from anything
# written to the terminal too, while keeping the message otherwise intact.
_KEY_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{10,}"),
    re.compile(r"(?i)(x-goog-api-key|api[_-]?key|key|token)(\s*[=:]\s*)"
               r"([^&\s,;\"']+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"),
)


def _redact(text: str, api_key: str = "") -> str:
    """Remove API keys / credentials from a diagnostic string."""
    out = str(text or "")
    if api_key:
        out = out.replace(api_key, "***")
    out = re.sub(r"AIza[0-9A-Za-z_\-]{10,}", "AIza***", out)
    out = re.sub(
        r"(?i)(x-goog-api-key|api[_-]?key|key|token)(\s*[=:]\s*)([^&\s,;\"']+)",
        r"\1\2***", out)
    out = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", out)
    return out


def _extract_status_code(exc: Exception) -> Optional[int]:
    """Best-effort HTTP status code from the exception (None if unavailable)."""
    code = getattr(exc, "code", None)
    if code is None:
        response = getattr(exc, "response", None)
        code = getattr(response, "status_code", None)
    if code is None:
        code = getattr(exc, "status_code", None)  # httpx.RequestError style
    # google.api_core uses a grpc StatusCode enum; unwrap its int value.
    if code is not None and not isinstance(code, (int, str)):
        value = getattr(code, "value", None)
        if isinstance(value, (list, tuple)) and value:
            code = value[0]
    try:
        return int(code)
    except (TypeError, ValueError):
        return None


def _extract_status_string(exc: Exception) -> Optional[str]:
    """Best-effort API status string, e.g. RESOURCE_EXHAUSTED."""
    status = getattr(exc, "status", None)
    if status is None:
        status = getattr(getattr(exc, "code", None), "name", None)
    return str(status).upper() if status else None


def classify_gemini_error(exc: Exception, api_key: str = "",
                          provider: str = "Gemini") -> Dict:
    """Map an LLM-provider exception to a category + safe user message.

    Returns a dict with the category, the safe user message, and the raw
    diagnostic fields (for terminal logging only - callers must NOT put the
    raw fields in the UI or database). `provider` only affects the wording of
    the user message (e.g. "Gemini" vs "OpenRouter").
    """
    code = _extract_status_code(exc)
    status = _extract_status_string(exc)
    message = getattr(exc, "message", None) or str(exc) or ""
    haystack = f"{status or ''} {message}".lower()

    if (code == 429
            or (status or "") in ("RESOURCE_EXHAUSTED", "TOO_MANY_REQUESTS")
            or any(m in haystack for m in _RATE_LIMIT_MARKERS)):
        category = "rate_limit"
    elif (code in (401, 403)
            or (status or "") in ("UNAUTHENTICATED", "PERMISSION_DENIED")
            or any(m in haystack for m in _AUTH_MARKERS)):
        category = "auth"
    elif (code == 404 or (status or "") == "NOT_FOUND"
            or ("model" in haystack
                and any(m in haystack for m in _MODEL_MARKERS))):
        category = "model_unavailable"
    elif (isinstance(exc, _NETWORK_EXC)
            or any(m in haystack for m in _NETWORK_MARKERS)):
        category = "network"
    else:
        category = "unexpected"

    return {
        "category": category,
        "user_message": user_message(category, provider),
        "status_code": code,
        "status": status,
        "message": str(message),
        "error_type": type(exc).__name__,
    }


def _log_api_error(provider: str, exc: Exception, info: Dict,
                   api_key: str = "") -> None:
    """Log the ORIGINAL exception to the terminal (never to the UI)."""
    lines = [
        f"{provider} API ERROR",
        f"Error type: {info.get('error_type') or type(exc).__name__}",
        f"Error message: {_redact(info.get('message') or str(exc), api_key)}",
    ]
    if info.get("status_code") is not None:
        lines.append(f"HTTP status code: {info['status_code']}")
    if info.get("status"):
        lines.append(f"API status: {info['status']}")
    lines.append(f"Category: {info.get('category')}")
    logger.error("\n".join(lines))


def _log_gemini_error(exc: Exception, info: Dict, api_key: str = "") -> None:
    """Backward-compatible Gemini-specific wrapper."""
    _log_api_error("GEMINI", exc, info, api_key)


def _friendly_error(exc: Exception) -> str:
    """Backward-compatible helper: the safe user message for an exception."""
    return classify_gemini_error(exc)["user_message"]


# ---------------------------------------------------------------------------
# Request lifecycle logging (one START / COMPLETE or FAILED per HTTP request).
# Never logs the API key or any sensitive configuration.
# ---------------------------------------------------------------------------

def _log_request_start(request_id: str, reason: str, model: str,
                       provider: str = "GEMINI") -> None:
    logger.info(
        "%s REQUEST START\nRequest ID: %s\nReason: %s\nModel: %s",
        provider, request_id, reason, model)


def _log_request_complete(request_id: str, model: str, elapsed: float,
                          provider: str = "GEMINI") -> None:
    logger.info(
        "%s REQUEST COMPLETE\nRequest ID: %s\nModel: %s\nElapsed: %.2fs",
        provider, request_id, model, elapsed)


def _log_request_failed(request_id: str, info: Dict, elapsed: float,
                        provider: str = "GEMINI") -> None:
    status = info.get("status_code")
    logger.error(
        "%s REQUEST FAILED\nRequest ID: %s\nStatus: %s\nCategory: %s\n"
        "Elapsed: %.2fs",
        provider, request_id, status if status is not None else "n/a",
        info.get("category"), elapsed)


# ===========================================================================
# Gemini wrapper
# ===========================================================================


class GeminiAnalyzer:
    """Thin, safe wrapper around the Gemini generative model."""

    def __init__(self, api_key: Optional[str] = None, model_id: str = MODEL_ID) -> None:
        self.api_key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
        self.model_id = model_id
        self._client = None
        self.available = bool(self.api_key)

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.available:
            raise RuntimeError("GEMINI_API_KEY is not set. Copy .env.example to "
                               ".env and add your key.")
        from google import genai

        # ONE user submission must map to ONE Gemini HTTP request. The SDK
        # retries 429/5xx up to 5 times by default, which amplifies a quota
        # problem, so disable SDK-level retries (attempts=1 -> no retry) and
        # surface the 429 to the user instead.
        http_options = None
        try:
            http_options = genai.types.HttpOptions(
                retry_options=genai.types.HttpRetryOptions(attempts=1))
        except Exception:  # pragma: no cover - older SDK without retry options
            http_options = None

        client = genai.Client(api_key=self.api_key, http_options=http_options)
        self._client = client
        return client

    def analyze_threat(self, prompt: str, temperature: float = 0.4,
                       reason: str = "user_submission") -> Dict[str, object]:
        """Send a threat-intelligence prompt to Gemini with ONE request.

        `reason` labels the request in the terminal log (e.g. "streamlit:
        Generate & Verify") and never contains secrets.

        Returns:
            {
              "success": bool,
              "text": generated response (or ""),
              "model": model id,
              "error": safe, category-specific user message (when failed),
              "error_category": rate_limit|auth|model_unavailable|network|unexpected|validation,
              "status_code": HTTP status code when available (else None),
              "request_id": short id correlating the terminal log lines,
              "prompt": echo of the request,
            }

        On failure the diagnostic detail is logged to the terminal only; the
        returned payload never contains stack traces, keys or configuration,
        and never contains fabricated model text.
        """
        if not str(prompt or "").strip():
            return {"success": False, "text": "", "model": self.model_id,
                    "error": USER_MESSAGES["validation"],
                    "error_category": "validation", "status_code": None,
                    "request_id": None, "prompt": prompt}

        request_id = uuid.uuid4().hex[:12]
        _log_request_start(request_id, reason, self.model_id)
        started = time.time()

        try:
            client = self._get_client()
            from google import genai

            config_kwargs = dict(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=float(temperature),
                max_output_tokens=2048,
            )
            # AFC is NOT needed: the model is never given tools to call, so the
            # SDK default (AFC on, up to 10 remote calls) is disabled to keep
            # exactly one generation request.
            try:
                config_kwargs["automatic_function_calling"] = (
                    genai.types.AutomaticFunctionCallingConfig(disable=True))
            except Exception:  # pragma: no cover
                pass

            response = client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=genai.types.GenerateContentConfig(**config_kwargs),
            )
            text = getattr(response, "text", "") or ""
            _log_request_complete(request_id, self.model_id,
                                  time.time() - started)
            return {"success": True, "text": text, "model": self.model_id,
                    "error": None, "error_category": None,
                    "status_code": None, "request_id": request_id,
                    "provider": "gemini", "prompt": prompt}
        except Exception as exc:
            info = classify_gemini_error(exc, api_key=self.api_key)
            _log_gemini_error(exc, info, api_key=self.api_key)
            _log_request_failed(request_id, info, time.time() - started)
            return {"success": False, "text": "", "model": self.model_id,
                    "error": info["user_message"],
                    "error_category": info["category"],
                    "status_code": info["status_code"],
                    "request_id": request_id, "provider": "gemini",
                    "prompt": prompt}


def get_llm_analyzer() -> GeminiAnalyzer:
    """Factory used by the dashboard: Gemini (the only LLM provider)."""
    return GeminiAnalyzer()


if __name__ == "__main__":
    import json

    prompt = "What phishing threats are targeting Malaysian banking users?"
    result = get_llm_analyzer().analyze_threat(prompt)
    print(json.dumps({"success": result["success"], "model": result["model"],
                      "provider": result.get("provider"),
                      "fallback_used": result.get("fallback_used", False),
                      "error": result["error"],
                      "error_category": result["error_category"],
                      "text_preview": result["text"][:300]}, indent=2))
