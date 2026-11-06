"""
ui/status.py - Presentation mapping layer (plain-English terminology).

Converts the EXISTING backend outputs into simple user-facing labels. It
contains no detection logic, no model calls and no new detection thresholds.

The backend stores internal values that MUST NOT change (final_label =
"Hallucination"/"Malicious"/"Suspicious"/"Likely Safe"/"Unverified"; feed
statuses = POSITIVE_MATCH/NO_MATCH/UNAVAILABLE/RATE_LIMITED/...). This layer
maps those to display labels; it never rewrites the stored values.

Backend inputs consumed (read-only):
  Stage A : result["exists"], result["evidence_stage_a"], result["grounding_score"]
  Stage B : result["stage_reached"], result["classifier_confidence"],
            result["model_disagreement"], result["rf_probability"],
            result["xgb_probability"], result["virustotal_result"],
            result["safe_browsing_result"], result["verification_detail"]
"""
from __future__ import annotations

from typing import Dict, Optional

# --- thresholds REUSED from the existing backend (no new ones invented) -----
try:  # src/classifiers.py is the single source of truth (PHISHING_THRESHOLD)
    from classifiers import PHISHING_THRESHOLD as ML_FLAG_THRESHOLD
except Exception:  # pragma: no cover - defensive; keeps UI importable alone
    ML_FLAG_THRESHOLD = 0.5

# --- tones ------------------------------------------------------------------
TONE_OK = "ok"
TONE_WARN = "warn"
TONE_BAD = "bad"
TONE_MUTED = "muted"

# --- user-facing vocabulary (display only) ----------------------------------
# Stage A
EXIST_NOT_FOUND = "URL Not Found"
EXIST_EXISTS = "URL Exists"
# Stage B
PHISH_NOT_CHECKED = "Not Checked"
PHISH_POSSIBLE = "Possible Phishing Risk"
PHISH_FOUND = "Phishing Evidence Found"
PHISH_NO_EVIDENCE = "No Phishing Evidence Found"
PHISH_UNABLE = "Unable to Verify"

_FEED_POSITIVE = "POSITIVE_MATCH"


# ===========================================================================
# Small numeric helpers
# ===========================================================================

def _f(x) -> Optional[float]:
    try:
        if x is None:
            return None
        v = float(x)
        if v != v:  # NaN -> treat as unavailable (DB NULL read back as NaN)
            return None
        return v
    except (TypeError, ValueError):
        return None


def num(x, digits: int = 3) -> str:
    v = _f(x)
    return "Unavailable" if v is None else f"{v:.{digits}f}"


def pct(x) -> str:
    v = _f(x)
    return "Unavailable" if v is None else f"{round(v * 100)}%"


def source_state(status: Optional[str]) -> str:
    """Threat-intelligence DB state (never 'safe'/'legitimate')."""
    return {
        "POSITIVE_MATCH": "Threat evidence found",
        "NO_MATCH": "No match found",
        "UNAVAILABLE": "Unavailable",
        "RATE_LIMITED": "Rate limited",
        "rate_limited": "Rate limited",
        "ERROR": "Error",
        "http_error": "Error",
        "network_error": "Error",
    }.get(status or "", "Not run")


def model_agreement(disagreement) -> str:
    v = _f(disagreement)
    if v is None:
        return "Unavailable"
    return "Agree" if v < 0.5 else f"Disagree ({v:.2f})"


# ===========================================================================
# Stage A evidence helpers (technical section only)
# ===========================================================================

def dns_text(ev: Dict) -> str:
    resolved = ((ev or {}).get("dns") or {}).get("resolved")
    if resolved is True:
        return "Resolved"
    if resolved is False:
        return "NXDOMAIN"
    return "Inconclusive"


def whois_text(ev: Dict) -> str:
    found = ((ev or {}).get("whois") or {}).get("found")
    if found is True:
        return "Registration found"
    if found is False:
        return "No record"
    return "Inconclusive"


def reference_text(ev: Dict) -> str:
    ref = (ev or {}).get("reference") or {}
    if ref.get("exact_hit"):
        return "Exact match"
    if _f(ref.get("top_similarity")):
        return "Near match"
    return "No match"


def reference_similarity(ev: Dict) -> str:
    ref = (ev or {}).get("reference") or {}
    if ref.get("exact_hit"):
        return "1.00"
    sim = _f(ref.get("top_similarity"))
    return "Unavailable" if sim is None else f"{sim:.2f}"


def _conclusive_existence(ev: Dict) -> bool:
    """True when Stage A had at least one conclusive existence signal."""
    structural = ((ev or {}).get("structural") or {}).get("kind")
    if structural in ("ip", "reserved"):
        return True
    if ((ev or {}).get("dns") or {}).get("resolved") is not None:
        return True
    if ((ev or {}).get("whois") or {}).get("found") is not None:
        return True
    return bool(((ev or {}).get("reference") or {}).get("exact_hit"))


# ===========================================================================
# Threat-intelligence availability
# ===========================================================================

def _feed_positive(r: Dict) -> bool:
    return any(r.get(k) == _FEED_POSITIVE for k in (
        "virustotal_result", "safe_browsing_result",
        "urlhaus_result", "safe_browsing_result", "urlscan_result"))


def _coverage(r: Dict) -> Optional[float]:
    vd = r.get("verification_detail") or {}
    c = _f(vd.get("coverage"))
    if c is None:
        c = _f(r.get("verification_coverage"))
    return c


def _feeds_incomplete(r: Dict) -> bool:
    """True when external threat intelligence was not fully available.

    Any source that produced no verdict means the phishing assessment is
    incomplete - it is never treated as positive OR negative evidence.
    """
    if r.get("stage_reached") != "B":
        return True
    c = _coverage(r)
    return c is None or c < 1.0


def coverage_text(r: Dict) -> str:
    if r.get("stage_reached") != "B":
        return "Not run"
    c = _coverage(r)
    if c is None or c <= 0.0:
        return "Unavailable"
    if c >= 1.0:
        return "All sources"
    return "Partial"


# ===========================================================================
# Stage A - "Does the URL exist?"
# ===========================================================================

def existence(r: Dict) -> Dict[str, str]:
    ev = r.get("evidence_stage_a") or {}
    if not r.get("exists"):
        return {
            "label": EXIST_NOT_FOUND, "tone": TONE_BAD, "icon": "x",
            "description": "The system could not sufficiently verify that the "
                           "AI-generated URL/domain exists.",
            "secondary": "Potential LLM hallucination",
            "technical": "Potential LLM hallucination",
        }
    if not ev:
        technical = "Not hallucinated"
    else:
        technical = ("Not hallucinated" if _conclusive_existence(ev)
                     else "Not hallucinated (limited existence evidence)")
    return {
        "label": EXIST_EXISTS, "tone": TONE_OK, "icon": "check",
        "description": "The system obtained sufficient evidence that the "
                       "URL/domain exists.",
        "secondary": "Not hallucinated",
        "technical": technical,
    }


# ===========================================================================
# Stage B - "Phishing check"
# ===========================================================================

def phishing(r: Dict) -> Dict[str, str]:
    if r.get("stage_reached") != "B":
        return {
            "label": PHISH_NOT_CHECKED, "tone": TONE_MUTED, "icon": "minus",
            "description": "Phishing analysis was not performed because the "
                           "URL's existence could not be verified.",
            "secondary": "Stage B skipped",
            "recommendation": "Verify the URL's existence first.",
        }
    if r.get("known_legit_override") and not _feed_positive(r):
        return {
            "label": PHISH_NO_EVIDENCE, "tone": TONE_OK, "icon": "check",
            "description": "Official domain confirmed by exact allowlist match. "
                           "No phishing indicators found on this verified domain.",
            "secondary": "Verified official domain",
            "recommendation": "This is a known official website.",
        }
    if _feed_positive(r):
        return {
            "label": PHISH_FOUND, "tone": TONE_BAD, "icon": "x",
            "description": "External threat-intelligence sources associate this "
                           "URL with phishing.",
            "secondary": "Threat-intelligence match",
            "recommendation": "Treat this URL as malicious; do not visit it.",
        }

    ml = _f(r.get("classifier_confidence"))
    if ml is not None and ml >= ML_FLAG_THRESHOLD:
        return {
            "label": PHISH_POSSIBLE, "tone": TONE_WARN, "icon": "warn",
            "description": "Some checks detected phishing-like characteristics. "
                           "This does not confirm that the URL is phishing.",
            "secondary": "ML flag",
            "recommendation": "Do not rely on the ML prediction alone.",
        }
    if _feeds_incomplete(r):
        return {
            "label": PHISH_UNABLE, "tone": TONE_MUTED, "icon": "question",
            "description": "External threat-intelligence verification was "
                           "unavailable, so the phishing assessment could not be "
                           "fully verified.",
            "secondary": "External verification incomplete",
            "recommendation": "Re-check later when threat-intelligence feeds are "
                              "available.",
        }
    return {
        "label": PHISH_NO_EVIDENCE, "tone": TONE_OK, "icon": "check",
        "description": "The completed checks did not find strong evidence that "
                       "this URL is associated with phishing.",
        "secondary": "No positive evidence",
        "recommendation": "Stay cautious with unfamiliar links.",
    }


# ===========================================================================
# Overall line + plain-English explanation
# ===========================================================================

def overall(r: Dict, ex: Dict, ph: Dict) -> Dict[str, str]:
    if ex["label"] == EXIST_NOT_FOUND:
        return {"label": "URL Not Found", "tone": TONE_BAD,
                "short": "URL not found · phishing not checked"}
    if ph["label"] == PHISH_FOUND:
        return {"label": "URL Exists — phishing evidence found",
                "tone": TONE_BAD, "short": "Phishing evidence found"}
    if ph["label"] == PHISH_POSSIBLE:
        return {"label": "URL Exists — possible phishing risk",
                "tone": TONE_WARN, "short": "Possible phishing risk"}
    if ph["label"] == PHISH_UNABLE:
        return {"label": "URL Exists — unable to verify phishing",
                "tone": TONE_MUTED, "short": "Unable to verify phishing"}
    if ph["label"] == PHISH_NOT_CHECKED:
        return {"label": "URL Exists — phishing not checked",
                "tone": TONE_MUTED, "short": "Phishing not checked"}
    return {"label": "URL Exists — no phishing evidence found",
            "tone": TONE_OK, "short": "No phishing evidence found"}


def plain_english(r: Dict, ex: Dict, ph: Dict) -> str:
    if ex["label"] == EXIST_NOT_FOUND:
        return ("The AI-generated URL could not be sufficiently verified as "
                "existing, so it may be an LLM hallucination. The phishing "
                "check was not performed.")
    if ph["label"] == PHISH_FOUND:
        return ("The URL exists, and external threat-intelligence sources "
                "associate it with phishing.")
    if ph["label"] == PHISH_POSSIBLE:
        return ("The URL exists, but some checks detected phishing-like "
                "characteristics. This does not confirm that the URL is phishing.")
    if ph["label"] == PHISH_UNABLE:
        return ("The URL exists, but external threat-intelligence verification "
                "was unavailable, so the phishing assessment could not be fully "
                "verified.")
    if ph["label"] == PHISH_NOT_CHECKED:
        return ("Phishing analysis was not performed because the URL's existence "
                "could not be verified.")
    return ("The URL exists, and the completed checks did not find strong "
            "evidence that it is associated with phishing. This does not "
            "guarantee the URL is safe.")


# ===========================================================================
# History page label mapping (display only; internal values untouched)
# ===========================================================================

def history_existence_label(exists) -> str:
    return EXIST_EXISTS if bool(exists) else EXIST_NOT_FOUND


def history_hallucination_label(exists) -> str:
    return "Not hallucinated" if bool(exists) else "Potential LLM hallucination"


def history_phishing_label(final_label: Optional[str]) -> str:
    return {
        "Hallucination": PHISH_NOT_CHECKED,
        "Malicious": PHISH_FOUND,
        "Suspicious": PHISH_POSSIBLE,
        "Likely Safe": PHISH_NO_EVIDENCE,
        "Unverified": PHISH_UNABLE,
    }.get(final_label or "", PHISH_UNABLE)
