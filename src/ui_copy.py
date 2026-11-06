"""
ui_copy.py - Centralised user-facing copy that must stay honest.

Kept separate from app.py so pytest can assert the wording never overclaims
(CHANGE 3/8/9/10), without importing Streamlit:

  * phantom-squatting is a CONSIDERATION, never a classification result;
  * a domain's availability is never asserted as fact (no availability check
    is performed);
  * a threat-intelligence "no match" is never relabelled "safe"/"legitimate".
"""

from __future__ import annotations

# CHANGE 3 - user-facing terminology (internal names stay unchanged).
EXISTENCE_VERIFIED = "VERIFIED"
EXISTENCE_NOT_VERIFIED = "COULD NOT VERIFY"
HALLUCINATION_NO = "NOT HALLUCINATED"
HALLUCINATION_YES = "POTENTIAL HALLUCINATION"
PHISHING_SKIPPED = "SKIPPED"

# CHANGE 8 - phantom squatting. Conditional wording, never a definitive claim
# that a domain is available or that hallucination == phishing.
PHANTOM_SQUATTING_TITLE = "Phantom-Squatting Consideration"
PHANTOM_SQUATTING_TEXT = (
    "If this hallucinated domain is available for registration, it may present "
    "a potential phantom-squatting risk if it is later registered and "
    "weaponized by a malicious actor."
)
PHANTOM_SQUATTING_DISCLAIMER = (
    "This does not mean the domain is currently phishing or malicious."
)

# CHANGE 10 - threat-intelligence DB states. A "no match" is absence of
# positive evidence, never a safety verdict, so "safe"/"legitimate" must not
# appear as a state label.
SOURCE_STATE_LABELS = {
    "POSITIVE_MATCH": "Threat evidence found",
    "NO_MATCH": "No match found",
    "UNAVAILABLE": "Unavailable",
    "RATE_LIMITED": "Rate limited",
    "rate_limited": "Rate limited",
    "ERROR": "Error",
    "http_error": "Error",
    "network_error": "Error",
}

# Internal Stage B label vocabulary -> plain-English phishing assessment.
PHISHING_LABEL = {
    "Hallucination": PHISHING_SKIPPED,
    "Malicious": "MALICIOUS",
    "Suspicious": "SUSPICIOUS",
    "Likely Safe": "LIKELY SAFE",
    "Unverified": "UNVERIFIED",
}


def source_state_text(status: str) -> str:
    """Map a verification-engine status to its honest user-facing label."""
    if not status:
        return "Not run"
    return SOURCE_STATE_LABELS.get(status, str(status).replace("_", " ").title())


def _pct(x) -> str:
    if x is None:
        return "—"
    try:
        return f"{round(float(x) * 100)}%"
    except (TypeError, ValueError):
        return "—"


def build_friendly_explanation(r: dict) -> str:
    """Plain-English explanation for the UI (CHANGE 3/5/9).

    Deliberately avoids the internal vocabulary ("grounded",
    "threat_risk_score", "0.5*verification + 0.5*classifier") and never calls a
    "no match" safe. The technical reason string remains in the database/log
    for audit; this is the non-technical rendering.
    """
    if not r.get("exists"):
        return ("This URL could not be verified as existing, so the phishing "
                "assessment was not performed (Random Forest, XGBoost, "
                "VirusTotal and Google Safe Browsing were not run).")

    ml = (f"The machine-learning models estimated the phishing probability at "
          f"{_pct(r.get('classifier_confidence'))} "
          f"(Random Forest {_pct(r.get('rf_probability'))}, "
          f"XGBoost {_pct(r.get('xgb_probability'))}).")

    vt = source_state_text(r.get("virustotal_result"))
    pt = source_state_text(r.get("safe_browsing_result"))
    vr = r.get("verification_result")
    if vr is not None and vr >= 0.6:
        ext = ("External threat-intelligence sources reported threat evidence "
               f"(VirusTotal: {vt}, Google Safe Browsing: {pt}).")
    else:
        ext = ("External threat-intelligence evidence was limited "
               f"(VirusTotal: {vt}, Google Safe Browsing: {pt}).")

    verdict = {
        "MALICIOUS": ("The URL passed existence verification and the combined "
                      "evidence is strong, so it is assessed as malicious."),
        "SUSPICIOUS": ("The URL passed existence verification. The "
                       "machine-learning models identified strong phishing-like "
                       "characteristics, while external threat-intelligence "
                       "evidence was limited."),
        "LIKELY SAFE": ("The URL passed existence verification. No positive "
                        "phishing evidence was found in the queried sources and "
                        "the machine-learning probability is low - absence of a "
                        "match is not proof of safety."),
        "UNVERIFIED": ("The URL passed existence verification, but one or more "
                       "external sources produced no verdict, so it cannot yet "
                       "be marked likely safe."),
    }.get(PHISHING_LABEL.get(r.get("final_label"), PHISHING_SKIPPED), "")

    return f"{ml} {ext} {verdict}".strip()
