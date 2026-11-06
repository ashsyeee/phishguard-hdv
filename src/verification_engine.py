"""
verification_engine.py - Step 4: STAGE B. Maliciousness signal - real URLs only.

The pipeline ONLY calls this module for URLs whose existence Stage A already
confirmed (exists=True). Ask the wrong question here and the hallucination-
detector/classifier separation collapses - so this file never performs (or
touches the result of) an existence check.

WHAT IT DOES
------------
Wraps two independent maliciousness feeds behind ONE interface:

    * VirusTotal  - domain reputation endpoint: real-world antivirus verdicts
    * Google Safe Browsing - phishing and malware URL lists

Each service returns a per-service score in [0, 1] (higher = MORE evidence of
maliciousness). The engine averages only the services that actually produced a
verdict; a service with no verdict (no key, offline, rate limited past the
backoff budget) contributes 0.5 and is marked in the `sources` dict so the
dashboard can say "this signal is missing", never silently pretend it ran.

OFFLINE / MOCK MODE IS THE DEFAULT
----------------------------------
If no API key is present, the service runs in MOCK mode: it logs a warning and
returns a CLEARLY FLAGGED neutral 0.5 with `offline=True`. The whole pipeline
is therefore runnable end-to-end with zero keys - live keys only upgrade the
trust of Stage B, they are never required.

OTHER HARD REQUIREMENTS (per brief)
-----------------------------------
* request caching (in-memory, TTL)   - repeated lookups of the same URL do not
  hit the vendors a second time (respects their quotas and our latency)
* exponential backoff on 429/5xx     - vendors throttle aggressively; we retry
  1s, 2s, 4s ... honouring the Retry-After header when present
* keys ONLY from .env                - loaded with python-dotenv, never inline
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote_plus, urlencode

import requests

logger = logging.getLogger("phishguard.stage_b.verification")

# Make `from ...` imports resolve regardless of entry point.
_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
from hallucination_detector import normalise_domain

# ---------------------------------------------------------------------------
# Service configuration
# ---------------------------------------------------------------------------
ROOT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"  # POST host
URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"    # POST url
GSB_LOOKUP_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
WHOISXML_API = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
URLSCAN_SEARCH_API = "https://urlscan.io/api/v1/search/"

NEUTRAL = 0.5  # score used when a service has no verdict (flagged, not silent)

# Human-readable reason for a source that produced no verdict (CHANGE 8).
# A missing feed is UNAVAILABLE/ERROR/RATE_LIMITED - never a safety verdict.
_TAG_NOTES = {
    "UNAVAILABLE": "unavailable (no API key / mock mode)",
    "RATE_LIMITED": "rate limited past the retry budget - recheck later",
    "http_error": "HTTP error after retries - no verdict",
    "network_error": "network/DNS/TLS failure - no verdict",
}


def _tag_note(api: str, tag: str) -> str:
    return f"{api}: {_TAG_NOTES.get(tag, tag)} - missing evidence is NOT proof of safety"

DEFAULT_SETTINGS = {
    "cache_ttl": 300.0,     # seconds a cached lookup stays valid
    "timeout": 10.0,        # per HTTP request
    "max_retries": 3,       # exponential backoff attempts
    "backoff_base": 1.0,    # first sleep seconds
}


# ===========================================================================
# Output contract
# ===========================================================================


@dataclass
class VerificationResult:
    """Stage B verification output: score + explainable source breakdown."""
    verification_result: float          # 0..1 maliciousness evidence
    sources: Dict[str, dict] = field(default_factory=dict)
    offline: bool = False
    cached: bool = False
    coverage: float = 0.0               # fraction of expected sources that spoke
    warnings: List[str] = field(default_factory=list)
    reason_parts: List[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return " | ".join(self.reason_parts) if self.reason_parts else "no verdict"

    def to_dict(self) -> Dict:
        return {
            "verification_result": self.verification_result,
            "sources": self.sources,
            "offline": self.offline,
            "cached": self.cached,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "reason": self.reason,
        }


# ===========================================================================
# Engine
# ===========================================================================


class VerificationEngine:
    """Keyed by process scope; caches URL lookups in-memory with a TTL."""

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        urlhaus_auth_key: Optional[str] = None,
        google_safe_browsing_key: Optional[str] = None,
        whoisxml_api_key: Optional[str] = None,
        urlscan_api_key: Optional[str] = None,
        cache_ttl: float = DEFAULT_SETTINGS["cache_ttl"],
        timeout: float = DEFAULT_SETTINGS["timeout"],
        max_retries: int = DEFAULT_SETTINGS["max_retries"],
        backoff_base: float = DEFAULT_SETTINGS["backoff_base"],
    ):
        # Keys load from the environment (.env via python-dotenv) unless the
        # caller injects them (tests) - never hardcoded.
        try:
            from dotenv import load_dotenv
            load_dotenv(ROOT_ENV_PATH)
        except ImportError:
            logger.debug("python-dotenv not installed; reading os.environ only")

        self.vt_key = virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY") or ""
        self.uh_key = urlhaus_auth_key or os.getenv("URLHAUS_AUTH_KEY") or ""
        self.gsb_key = google_safe_browsing_key or os.getenv("GOOGLE_SAFE_BROWSING_KEY") or ""
        self.whoisxml_key = whoisxml_api_key or os.getenv("WHOISXML_API_KEY") or ""
        self.urlscan_key = urlscan_api_key or os.getenv("URLSCAN_API_KEY") or ""
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._cache: Dict[str, tuple] = {}  # key -> (expire_ts, VerificationResult)

    # -- cache -------------------------------------------------------------

    def _cache_get(self, url: str) -> Optional[VerificationResult]:
        item = self._cache.get(url)
        if item and item[0] > time.time():
            res = item[1]
            res.cached = True
            return res
        return None

    def _cache_put(self, url: str, result: VerificationResult) -> None:
        self._cache[url] = (time.time() + self.cache_ttl, result)
        if len(self._cache) > 4096:  # keep memory bounded
            self._cache.pop(next(iter(self._cache)), None)

    # -- HTTP with exponential backoff -------------------------------------

    def _get_with_backoff(self, url: str, headers: Dict):
        return self._http_with_backoff("GET", url, headers=headers)

    def _post_with_backoff(self, url: str, data: Dict, headers: Dict):
        return self._http_with_backoff("POST", url, data=data, headers=headers)

    def _http_with_backoff(self, method: str, url: str, **kw):
        """GET/POST with exponential backoff on 429/5xx + Retry-After.

        Returns (payload_or_None, status_tag). status_tag is the "why did we
        get nothing?" answer (CHANGE 8) so missing evidence is EXPLICIT:
            "ok"            - HTTP 200, payload parsed
            "rate_limited"  - 429 / quota exhausted (even after retries)
            "http_error"    - other non-200 (4xx/5xx) after retries
            "network_error" - RequestException (offline, DNS, TLS, reset)
        A missing payload is therefore never silently treated as a verdict.
        """
        wait = self.backoff_base
        last_tag = "network_error"
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.request(method, url, timeout=self.timeout, **kw)
            except requests.RequestException as exc:
                logger.warning("verification request failed (%s): %s",
                               type(exc).__name__, exc)
                last_tag = "network_error"
                time.sleep(wait)
                wait *= 2
                continue
            if resp.status_code == 200:
                try:
                    return resp.json(), "ok"
                except ValueError:
                    return {"_text": resp.text}, "ok"
            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                sleep = float(retry_after) if retry_after else wait
                logger.warning("verification %s:%s (attempt %d/%d), sleeping %.1fs",
                               resp.status_code, url, attempt + 1,
                               self.max_retries + 1, sleep)
                last_tag = "rate_limited" if resp.status_code == 429 else "http_error"
                time.sleep(min(sleep, 30))
                wait *= 2
                continue
            logger.warning("verification %s: HTTP %s for %s",
                           method, resp.status_code, url)
            return None, "http_error"
        return None, last_tag

    # -- per-service lookups ----------------------------------------------

    def _virustotal(self, domain: str) -> Dict:
        """Domain reputation; score = (malicious + 0.5*suspicious)/total.

        status is one of:
            POSITIVE_MATCH - at least one vendor flagged malicious/suspicious
            NO_MATCH       - service answered, nothing positive found
            UNAVAILABLE    - no key / mock mode
            RATE_LIMITED   - 429 past the backoff budget
            ERROR          - HTTP/network failure past the backoff budget
        NO_MATCH is absence-of-positive-evidence, NEVER proof of safety.
        """
        if not self.vt_key:
            logger.warning("VIRUSTOTAL_API_KEY missing - using mock (neutral) "
                           "verification for %s", domain)
            return {"score": NEUTRAL, "offline": True, "status": "UNAVAILABLE",
                    "note": "no API key - UNAVAILABLE (mock/neutral)",
                    "api": "virustotal"}

        payload, tag = self._get_with_backoff(
            VT_DOMAIN_API.format(domain=quote_plus(domain)),
            headers={"x-apikey": self.vt_key})

        if payload is None:
            return {"score": NEUTRAL, "offline": True, "status": tag,
                    "note": _tag_note("virustotal", tag),
                    "api": "virustotal"}

        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless = int(stats.get("harmless", 0))
        total = malicious + suspicious + undetected + harmless

        if total == 0:
            return {"score": NEUTRAL, "offline": False, "status": "NO_MATCH",
                    "note": "VirusTotal answered but has NO analysis/votes for this "
                            "domain - absence of positive evidence, not proof of safety",
                    "api": "virustotal"}

        score = (malicious + 0.5 * suspicious) / total
        status = "POSITIVE_MATCH" if (malicious + suspicious) > 0 else "NO_MATCH"
        return {"score": round(score, 4), "offline": False, "status": status,
                "note": f"last_analysis: {malicious} malicious, "
                        f"{suspicious} suspicious, {undetected} undetected "
                        f", {harmless} harmless",
                "api": "virustotal", "stats": stats}

    def _urlhaus(self, domain: str) -> Dict:
        """abuse.ch URLhaus host lookup: known malware/phishing hosts.

        URLhaus requires a free Auth-Key (URLHAUS_AUTH_KEY) since 2025; without
        it the source is UNAVAILABLE, never a safety verdict.
        """
        if not self.uh_key:
            return {"score": NEUTRAL, "offline": True, "status": "UNAVAILABLE",
                    "note": "no URLHAUS_AUTH_KEY - UNAVAILABLE (mock/neutral)",
                    "api": "urlhaus"}

        payload, tag = self._post_with_backoff(
            URLHAUS_HOST_API,
            data={"host": domain},
            headers={"Auth-Key": self.uh_key})

        if payload is None:
            return {"score": NEUTRAL, "offline": True, "status": tag,
                    "note": _tag_note("urlhaus", tag), "api": "urlhaus"}

        if payload.get("query_status") == "no_results":
            return {"score": 0.2, "offline": False, "status": "NO_MATCH",
                    "note": "URLhaus answered: host NOT listed - absence is NOT "
                            "proof of safety", "api": "urlhaus"}

        listed = int(payload.get("urls_online") or 0) + int(
            payload.get("urls_offline") or 0)
        if listed > 0:
            return {"score": 1.0, "offline": False, "status": "POSITIVE_MATCH",
                    "note": f"URLhaus lists this host ({listed} malicious URL "
                            f"record(s))", "api": "urlhaus"}
        return {"score": 0.2, "offline": False, "status": "NO_MATCH",
                "note": "URLhaus answered: host NOT listed - absence is NOT "
                        "proof of safety", "api": "urlhaus"}

    def _safe_browsing(self, url: str) -> Dict:
        """Google Safe Browsing v4 Lookup: SOCIAL_ENGINEERING = phishing lists.

        Free API key (GOOGLE_SAFE_BROWSING_KEY). An empty response body means
        the URL is on none of the queried lists - NO_MATCH, not proof of safety.
        """
        if not self.gsb_key:
            return {"score": NEUTRAL, "offline": True, "status": "UNAVAILABLE",
                    "note": "no GOOGLE_SAFE_BROWSING_KEY - UNAVAILABLE (mock/neutral)",
                    "api": "safe_browsing"}

        body = {
            "client": {"clientId": "phishguard-hdv", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        payload, tag = self._http_with_backoff(
            "POST", GSB_LOOKUP_API, json=body,
            headers={"x-goog-api-key": self.gsb_key})

        if payload is None:
            return {"score": NEUTRAL, "offline": True, "status": tag,
                    "note": _tag_note("safe_browsing", tag), "api": "safe_browsing"}

        matches = payload.get("matches") or []
        if not matches:
            return {"score": 0.2, "offline": False, "status": "NO_MATCH",
                    "note": "Google Safe Browsing answered: URL NOT on any "
                            "queried list - absence is NOT proof of safety",
                    "api": "safe_browsing"}
        kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"score": 1.0, "offline": False, "status": "POSITIVE_MATCH",
                "note": f"Google Safe Browsing lists this URL: {', '.join(kinds)}",
                "api": "safe_browsing"}

    def _urlscan(self, domain: str) -> Dict:
        """urlscan.io: search EXISTING scans of the domain. Never submits a URL,
        because submissions are published publicly. A scan judged malicious is a
        positive match; no scans at all is NO_MATCH, not proof of safety.
        """
        if not self.urlscan_key:
            return {"score": NEUTRAL, "offline": True, "status": "UNAVAILABLE",
                    "note": "no URLSCAN_API_KEY - UNAVAILABLE (mock/neutral)",
                    "api": "urlscan"}

        query = urlencode({"q": f"domain:{domain}", "size": 20})
        payload, tag = self._get_with_backoff(
            f"{URLSCAN_SEARCH_API}?{query}", headers={"API-Key": self.urlscan_key})
        if payload is None:
            return {"score": NEUTRAL, "offline": True, "status": tag,
                    "note": _tag_note("urlscan", tag), "api": "urlscan"}

        results = payload.get("results") or []
        if not results:
            return {"score": 0.2, "offline": False, "status": "NO_MATCH",
                    "note": "urlscan.io has no scans of this domain - absence is "
                            "NOT proof of safety", "api": "urlscan"}
        bad = [r for r in results
               if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
        if bad:
            return {"score": 1.0, "offline": False, "status": "POSITIVE_MATCH",
                    "note": f"urlscan.io judged {len(bad)} of {len(results)} scans "
                            f"of this domain malicious", "api": "urlscan"}
        return {"score": 0.2, "offline": False, "status": "NO_MATCH",
                "note": f"urlscan.io: {len(results)} scan(s), none judged malicious",
                "api": "urlscan"}

    def _whoisxml_age(self, domain: str) -> Optional[int]:
        """Domain age in days from WhoisXML (POST, so the key is not in the URL)."""
        if not self.whoisxml_key:
            return None
        try:
            resp = requests.post(
                WHOISXML_API,
                json={"apiKey": self.whoisxml_key, "domainName": domain,
                      "outputFormat": "JSON"},
                timeout=self.timeout)
            if resp.status_code != 200:
                return None
            record = resp.json().get("WhoisRecord") or {}
        except (requests.RequestException, ValueError, AttributeError):
            return None
        created = record.get("createdDateNormalized") or record.get("createdDate")
        if not created:
            return None
        try:
            text = str(created).replace(" UTC", "").replace("Z", "+00:00")
            created_dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created_dt).days)

    def domain_age_days(self, domain: str) -> Optional[int]:
        """Domain age in days from WhoisXML (None when no key or no answer)."""
        return self._whoisxml_age(domain)

    # -- public entry ------------------------------------------------------

    def verify(self, url: str) -> VerificationResult:
        """Interrogate every configured vendor; fuse scores; return verdict.

        Only sources that returned a GENUINE verdict (POSITIVE_MATCH or
        NO_MATCH) participate in the average. UNAVAILABLE / RATE_LIMITED /
        ERROR sources are excluded from the mean AND surfaced verbatim in
        `sources`, `coverage` and `warnings` so missing evidence can never be
        confused with an all-clear (CHANGE 8 / CHANGE 14).
        """
        cached = self._cache_get(url)
        if cached is not None:
            logger.debug("verification cache hit for %s", url)
            return cached

        domain = normalise_domain(url) or url
        sources = {"virustotal": self._virustotal(domain),
                   "urlhaus": self._urlhaus(domain),
                   "safe_browsing": self._safe_browsing(url),
                   "urlscan": self._urlscan(domain)}

        # A source with no API key (UNAVAILABLE) was never set up, so it is
        # not part of the expected set. Only configured sources count toward
        # coverage; a configured source that fails still lowers it.
        configured = [s for s in sources.values() if s["status"] != "UNAVAILABLE"]
        verdict = [s for s in configured
                   if s["status"] in ("POSITIVE_MATCH", "NO_MATCH")]
        missing = [s["api"] for s in configured
                   if s["status"] not in ("POSITIVE_MATCH", "NO_MATCH")]
        coverage = (len(verdict) / len(configured)) if configured else 0.0

        if verdict:
            result_score = sum(s["score"] for s in verdict) / len(verdict)
        else:
            result_score = NEUTRAL  # every source missing -> clearly neutral

        warnings = []
        if not configured:
            warnings.append(
                "No threat-intelligence API keys are configured, so no external "
                "evidence was checked. Missing evidence is NOT treated as proof "
                "of safety.")
        elif missing:
            warnings.append(
                f"{len(missing)}/{len(configured)} configured threat-intelligence "
                f"sources had NO verdict: {', '.join(missing)}. Missing evidence is "
                f"NOT treated as proof of safety.")

        result = VerificationResult(
            verification_result=round(result_score, 4),
            sources=sources,
            offline=bool(any(s["offline"] for s in sources.values())),
            coverage=round(coverage, 4),
            warnings=warnings,
            reason_parts=[s["note"] for s in sources.values()],
        )
        self._cache_put(url, result)
        return result
