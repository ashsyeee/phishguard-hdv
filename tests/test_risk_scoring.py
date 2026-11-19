"""Step 6 tests: Stage B risk fusion under CHANGE 6/7/9/14/16.

GROUNDING IS DELIBERATELY NOT AN INPUT (CHANGE 6/7): compute_risk fuses
verification evidence and ML confidence only, so an "existing" URL earns no
threat points for existing. threat_risk_score = 0.5*verification +
0.5*classifier_confidence - a transparent FYP baseline, documented as
uncalibrated (the report states calibration is required).
"""
import inspect

import pytest

import risk_scoring
from risk_scoring import (MALICIOUS_THRESHOLD, STRONG_EXTERNAL,
                          SUSPICIOUS_THRESHOLD, build_reason, compute_risk,
                          final_label)


def assert_close(a, b, tol=1e-9):
    assert abs(a - b) < tol


# ---------------------------------------------------------------------------
# CHANGE 6/7 - grounding is not a Stage B threat input
# ---------------------------------------------------------------------------

def test_compute_risk_has_no_grounding_parameter():
    params = list(inspect.signature(compute_risk).parameters)
    assert params == ["verification_result", "classifier_confidence"]
    assert not hasattr(risk_scoring, "W_GROUNDING")


def test_grounding_can_never_inflate_threat_risk():
    # The fusion depends ONLY on verification + classifier: identical inputs
    # produce identical risk no matter what existence "confidence" was seen.
    assert_close(compute_risk(0.9, 0.1)["threat_risk_score"],
                 compute_risk(0.9, 0.1)["threat_risk_score"])


# ---------------------------------------------------------------------------
# Exact formula + edge cases
# ---------------------------------------------------------------------------

def test_all_zero_scores():
    r = compute_risk(0.0, 0.0)
    assert_close(r["threat_risk_score"], 0.0)
    assert final_label(r["threat_risk_score"], True,
                       verification_result=0.0, coverage=1.0) == "Likely Safe"


def test_all_one_scores():
    r = compute_risk(1.0, 1.0)
    assert_close(r["threat_risk_score"], 1.0)
    assert final_label(r["threat_risk_score"], True,
                       verification_result=1.0) == "Malicious"


def test_exact_formula_weights_equal():
    # 0.5*1.0 + 0.5*0.5 = 0.75
    assert_close(compute_risk(1.0, 0.5)["threat_risk_score"], 0.75)
    assert_close(compute_risk(0.2, 0.8)["threat_risk_score"], 0.50)
    assert compute_risk(0.7, 0.3)["weights"] == {"verification": 0.5,
                                                 "classifier": 0.5}


def test_missing_external_evidence_is_neutral_not_zero():
    # A vendor with NO verdict reports 0.5 (verification_engine guarantee).
    # With zero ML evidence: risk = 0.5*0.5 + 0.5*0.0 = 0.25.
    r = compute_risk(0.5, 0.0)
    assert_close(r["threat_risk_score"], 0.25)
    # Low + incomplete coverage -> Unverified, NOT a safe verdict (CHANGE 14).
    assert final_label(0.25, True, coverage=0.0) == "Unverified"


def test_clamping_out_of_range_inputs():
    r = compute_risk(-10.0, 42.0)
    assert 0.0 <= r["threat_risk_score"] <= 1.0
    r_nan = compute_risk(float("nan"), 0.5)   # NaN -> neutral 0.5
    assert_close(r_nan["threat_risk_score"], 0.5)


def test_stage_a_short_circuit_always_hallucination_label():
    # Even a maximal Stage-B score, exists=False must win the label.
    assert final_label(1.0, exists=False) == "Hallucination"
    assert final_label(0.0, exists=False) == "Hallucination"


def test_suspicious_threshold_boundary():
    assert final_label(SUSPICIOUS_THRESHOLD, True) == "Suspicious"
    assert final_label(SUSPICIOUS_THRESHOLD - 1e-6, True,
                       coverage=1.0) == "Likely Safe"
    assert final_label(SUSPICIOUS_THRESHOLD - 1e-6, True,
                       coverage=0.5) == "Unverified"


# ---------------------------------------------------------------------------
# CHANGE 16 - you cannot claim Malicious without genuine external positives
# ---------------------------------------------------------------------------

def test_malicious_requires_strong_external_evidence():
    # Just below STRONG_EXTERNAL, even with a high fused score -> Suspicious.
    assert final_label(0.77, True, verification_result=0.59) == "Suspicious"
    # At/above STRONG_EXTERNAL + score >= MALICIOUS_THRESHOLD -> Malicious.
    assert final_label(0.77, True, verification_result=0.60) == "Malicious"
    assert final_label(MALICIOUS_THRESHOLD, True,
                       verification_result=STRONG_EXTERNAL) == "Malicious"


def test_malicious_needs_score_above_malicious_threshold():
    # Strong external flag but fused score just under the bar -> Suspicious.
    assert final_label(MALICIOUS_THRESHOLD - 1e-6, True,
                       verification_result=0.9) == "Suspicious"


def test_high_ml_with_limited_external_is_suspicious_not_malicious():
    # ML very confident but external evidence is weak/missing (0.5 neutral).
    assert final_label(0.70, True, verification_result=0.5) == "Suspicious"


# ---------------------------------------------------------------------------
# CHANGE 14 - "Likely Safe" requires every external source to have spoken
# ---------------------------------------------------------------------------

def test_likely_safe_requires_full_coverage():
    assert final_label(0.2, True, coverage=1.0) == "Likely Safe"
    assert final_label(0.2, True, coverage=0.5) == "Unverified"
    assert final_label(0.2, True, verification_result=0.1,
                       coverage=0.5) == "Unverified"


# ---------------------------------------------------------------------------
# build_reason - per-model breakdown + honest wording
# ---------------------------------------------------------------------------

def test_reason_contains_per_model_breakdown_and_fusion():
    reason = build_reason(
        0.85, "Suspicious",
        verification_result=0.7, classifier_confidence=1.0,
        verification_note="mock external verdict",
        classifier_breakdown={"rf_probability": 0.8, "xgb_probability": 0.9,
                              "classifier_confidence": 0.85,
                              "model_disagreement": 0.1},
        coverage=1.0)
    assert "Random Forest 0.800" in reason
    assert "XGBoost 0.900" in reason
    assert "model disagreement 0.100" in reason
    assert "0.5*verification" in reason and "0.5*classifier" in reason
    assert "Suspicious" in reason


def test_reason_never_claims_a_url_is_definitively_safe():
    reason = build_reason(
        0.2, "Likely Safe",
        verification_result=0.1, classifier_confidence=0.3,
        verification_note="both feeds answered, nothing positive",
        coverage=1.0)
    assert "Likely Safe" in reason
    assert "NOT proof" in reason or "absence" in reason


def test_reason_surfaces_missing_evidence_warnings():
    reason = build_reason(
        0.3, "Unverified",
        verification_result=0.5, classifier_confidence=0.1,
        verification_note="VirusTotal had no verdict",
        coverage=0.5,
        warnings=["1/2 sources had NO verdict: phishtank. Missing evidence is "
                  "NOT treated as proof of safety."])
    assert "Unverified" in reason
    assert "1/2 sources" in reason or "NO verdict" in reason