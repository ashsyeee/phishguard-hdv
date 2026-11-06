"""
risk_scoring.py - Stage B scoring. Runs ONLY for URLs that passed Stage A.

THE ARCHITECTURAL RULE THIS MODULE ENFORCES (CHANGE 6/7)
---------------------------------------------------------
grounding_score measures confidence that a URL EXISTS. It says NOTHING about
whether the URL is malicious, so it must NEVER be added to the Stage B threat
score. A domain we are very confident exists gets NO extra threat points for
existing. Grounding's only role is the Stage A gate: a URL that cannot be
grounded is labelled "Hallucination" by pipeline.py and this module is never
reached.

Stage B therefore combines only the two maliciousness families:

    threat_risk_score =
        0.5 * verification_result      (VirusTotal / PhishTank evidence)
      + 0.5 * classifier_confidence    (RF + XGB ensemble phishing probability)

Weights and thresholds are CONFIGURABLE module-level constants. They are a
transparent initial FYP design (equal weight on external threat intel and ML),
NOT statistically optimised - the report documents that calibration against
held-out data is required before production use.

TERMINOLOGY (CHANGE 9): do not confuse these.
    grounding_score       = confidence the URL exists (Stage A)
    rf_probability        = RandomForest phishing-class probability (Stage B)
    xgb_probability       = XGBoost phishing-class probability     (Stage B)
    classifier_confidence = ensemble phishing-class probability    (Stage B)
    verification_result   = external threat-intelligence evidence  (Stage B)
    threat_risk_score     = fused Stage B threat score             (Stage B)
    model_disagreement    = |rf_probability - xgb_probability|     (Stage B)
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Configurable thresholds (FYP baseline parameters - calibrate before release).
# ---------------------------------------------------------------------------
# threat_risk_score >= MALICIOUS_THRESHOLD  -> "Malicious"
# threat_risk_score >= SUSPICIOUS_THRESHOLD -> "Suspicious"
# else (low) -> "Likely Safe" if all external sources answered,
#               "Unverified" if any external evidence was missing.
MALICIOUS_THRESHOLD = 0.70
SUSPICIOUS_THRESHOLD = 0.45

# A verification_result at/above this means GENUINE positive external evidence
# exists (a feed actually flagged something). "Malicious" requires this, so
# high ML suspicion alone can never be overstated as a confirmed attack
# (CHANGE 16: ML-elevated + external-limited -> "Suspicious", not "Malicious").
STRONG_EXTERNAL = 0.60

# verification completeness required before low evidence can earn "Likely
# Safe". Missing/errored/rate-limited sources -> "Unverified" (CHANGE 8/14).
COVERAGE_COMPLETE = 1.0

# Verified-clean rule: "Unverified" may only become "Likely Safe" with proof.
CLEAN_MIN_GENUINE_SOURCES = 2   # independent feeds that gave a real verdict
CLEAN_MIN_AGE_DAYS = 180        # domain must be at least this old
NEW_DOMAIN_DAYS = 30            # younger than this is suspicious on its own
CLEAN_ML_CEILING = 0.5          # ML phishing probability must stay below this

# Stage B fusion weights - documented baseline, not claimed optimal.
W_VERIFICATION = 0.5
W_CLASSIFIER = 0.5


def compute_risk(
    verification_result: float,
    classifier_confidence: float,
) -> Dict[str, float]:
    """Fuse the two Stage B maliciousness signals.

    NOTE: grounding_score is deliberately NOT an argument here (CHANGE 6/7) -
    existence confidence must not inflate threat risk.
    """
    v = _clamp01(verification_result)
    c = _clamp01(classifier_confidence)

    threat_risk_score = W_VERIFICATION * v + W_CLASSIFIER * c

    return {
        "threat_risk_score": threat_risk_score,
        "verification": v,
        "classifier": c,
        "weights": {"verification": W_VERIFICATION, "classifier": W_CLASSIFIER},
    }


def final_label(
    threat_risk_score: float,
    exists: bool,
    verification_result: Optional[float] = None,
    coverage: Optional[float] = None,
) -> str:
    """Map the Stage B score (plus evidence completeness) to a verdict label.

    Label vocabulary (CHANGE 9/14):
        Hallucination  - Stage A could not ground the URL (exists=False)
        Malicious      - genuine positive external evidence AND high fused score
        Suspicious     - elevated evidence, OR high ML with limited external
        Likely Safe    - low evidence AND every external source gave a verdict
        Unverified     - low evidence but some external source was missing
    No verdict claims a URL is definitively "legitimate": absence of a match in
    the queried feeds is reported as 'no positive malicious evidence found'.
    """
    if not exists:
        return "Hallucination"

    risk = _clamp01(threat_risk_score)
    verif = None if verification_result is None else _clamp01(verification_result)
    cov = None if coverage is None else float(coverage)

    if (verif is not None and verif >= STRONG_EXTERNAL
            and risk >= MALICIOUS_THRESHOLD):
        return "Malicious"
    if risk >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    # Low combined evidence: what we say depends on evidence completeness.
    if cov is not None and cov >= COVERAGE_COMPLETE:
        return "Likely Safe"
    return "Unverified"


def apply_clean_rule(
    label: str,
    *,
    genuine_sources: int,
    positive_sources: int,
    ml_confidence: float,
    age_days: Optional[int],
    existence_uncertain: bool,
    brand_impersonation: bool = False,
    page_suspicious: bool = False,
) -> Tuple[str, str]:
    """Decide whether a low-risk verdict may be promoted to "Likely Safe".

    Returns (label, note). Only "Likely Safe" / "Unverified" are reconsidered;
    Malicious / Suspicious / Hallucination pass through untouched.

    * Verified clean  : >=2 independent feeds gave a real NO_MATCH, none
                        positive, domain age >= CLEAN_MIN_AGE_DAYS, ML below
                        CLEAN_ML_CEILING, existence not uncertain.
    * New domain      : domain younger than NEW_DOMAIN_DAYS is at least
                        "Suspicious" - a fresh domain is a phishing signal
                        even when no feed has reported it yet.
    * Otherwise       : "Unverified" (we do not have proof of safety).
    """
    if label not in ("Likely Safe", "Unverified"):
        return label, ""

    if positive_sources > 0:
        return label, "positive threat-intelligence match present"

    if page_suspicious:
        # A login form whose target, redirect, or title points elsewhere is the
        # classic fake-login pattern, whatever the URL and feeds say.
        return "Suspicious", ("login page sends the password to a different "
                              "site, redirects away, or names another brand")

    if brand_impersonation:
        # An old, clean-looking domain can still be a hijacked or lookalike
        # site. A brand name on a domain that is not that brand's official
        # domain is never "Likely Safe", whatever the age or feed results.
        return "Suspicious", ("brand name appears on a domain that is not its "
                              "official domain")

    if age_days is not None and age_days < NEW_DOMAIN_DAYS:
        return "Suspicious", (f"domain is only {age_days} day(s) old "
                              f"(new domains are a phishing signal)")

    proofs = []
    if genuine_sources >= CLEAN_MIN_GENUINE_SOURCES:
        proofs.append(f"{genuine_sources} independent feeds report no threat")
    if age_days is not None and age_days >= CLEAN_MIN_AGE_DAYS:
        proofs.append(f"domain is {age_days} day(s) old")
    if ml_confidence < CLEAN_ML_CEILING:
        proofs.append(f"ML phishing probability {ml_confidence:.0%}")

    complete = (genuine_sources >= CLEAN_MIN_GENUINE_SOURCES
                and age_days is not None and age_days >= CLEAN_MIN_AGE_DAYS
                and ml_confidence < CLEAN_ML_CEILING
                and not existence_uncertain)
    if complete:
        return "Likely Safe", "verified clean: " + "; ".join(proofs)

    missing = []
    if genuine_sources < CLEAN_MIN_GENUINE_SOURCES:
        missing.append(f"only {genuine_sources} feed(s) gave a verdict "
                       f"(need {CLEAN_MIN_GENUINE_SOURCES})")
    if age_days is None:
        missing.append("domain age unknown")
    elif age_days < CLEAN_MIN_AGE_DAYS:
        missing.append(f"domain only {age_days} day(s) old "
                       f"(need {CLEAN_MIN_AGE_DAYS})")
    if ml_confidence >= CLEAN_ML_CEILING:
        missing.append("ML flags phishing-like features")
    if existence_uncertain:
        missing.append("existence not confirmed")
    return "Unverified", "not verified clean: " + "; ".join(missing)


def build_reason(
    threat_risk_score: float,
    label: str,
    verification_result: float,
    classifier_confidence: float,
    verification_note: str = "",
    classifier_breakdown: Optional[Dict] = None,
    coverage: Optional[float] = None,
    warnings: Optional[list] = None,
) -> str:
    """Plain-English explanation of which SIGNAL drove the Stage B label.

    Uses the terminology in CHANGE 9 and never overstates certainty (CHANGE 14):
    a "Likely Safe" URL is described as 'no positive malicious evidence found
    in the queried sources', never as confirmed-safe.
    """
    v = _clamp01(verification_result)
    c = _clamp01(classifier_confidence)
    risk = _clamp01(threat_risk_score)

    parts = []

    # ML evidence - per-model, ensemble, disagreement (CHANGE 3/4/9).
    if classifier_breakdown:
        rf = classifier_breakdown.get("rf_probability")
        xgb = classifier_breakdown.get("xgb_probability")
        ens = classifier_breakdown.get("classifier_confidence")
        disp = classifier_breakdown.get("model_disagreement")
        ml_bits = []
        if rf is not None:
            ml_bits.append(f"Random Forest {rf:.3f}")
        if xgb is not None:
            ml_bits.append(f"XGBoost {xgb:.3f}")
        if ens is not None:
            ml_bits.append(f"ensemble {ens:.3f}")
        if ml_bits:
            ml_line = "ML phishing probability: " + ", ".join(ml_bits)
            if disp is not None:
                ml_line += f" (model disagreement {disp:.3f})"
            parts.append(ml_line + ".")

    # External evidence + completeness (CHANGE 8/14).
    ext_bits = [f"external threat-intelligence evidence {v:.2f}"]
    if coverage is not None:
        ext_bits.append(f"source coverage {coverage:.2f}")
    if warnings:
        ext_bits.append("; ".join(warnings))
    if ext_bits:
        parts.append(" ".join(ext_bits) + ".")
    if verification_note:
        parts.append(f"verification: {verification_note}.")
    parts.append(f"fused threat_risk_score {risk:.3f} "
                 f"(0.5*verification + 0.5*classifier) -> labeled '{label}'.")

    driver = _label_driver(label)
    if driver:
        parts.append(driver)
    return " ".join(parts)


def _label_driver(label: str) -> str:
    """One honest sentence saying WHY a label was chosen (CHANGE 16)."""
    if label == "Malicious":
        return ("Positive malicious evidence was reported by the queried "
                "threat-intelligence sources and the fused score is high.")
    if label == "Suspicious":
        return ("Elevated threat evidence was present but external "
                "confirmation was limited or the fused score did not reach "
                "the Malicious threshold.")
    if label == "Likely Safe":
        return ("No positive malicious evidence was found in the queried "
                "threat-intelligence sources and ML probability is low - "
                "absence of a match is NOT proof the URL is safe.")
    if label == "Unverified":
        return ("The combined evidence is low BUT at least one external "
                "threat-intelligence source produced no verdict, so the URL "
                "cannot yet be marked likely-safe.")
    return ""


def _clamp01(x: float) -> float:
    v = float(x)
    if v != v:  # NaN -> neutral
        return 0.5
    return min(max(v, 0.0), 1.0)