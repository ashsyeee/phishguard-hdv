"""Step 11 tests: the two stages are genuinely INDEPENDENT questions.

These two cases are the strongest viva evidence that Stage A answers
EXISTENCE and Stage B answers MALICIOUSNESS, rather than duplicating each
other:

CASE 1 - A URL that EXISTS and the classifier calls MALICIOUS
    -> system must proceed to Stage B and flag it (Malicious when the
       external evidence is also strong, per CHANGE 16).
CASE 2 - A URL that DOES NOT EXIST, even if it looks malicious
    -> system must stop at Hallucination; the classifier is provably never
       called (a spy counts invocations), so whatever the classifier WOULD
       have said is irrelevant.
"""
import types

import pytest

from pipeline import PhishGuardPipeline


class FakeStageA:
    def __init__(self, exists, grounding=0.9, domain="d.com"):
        self._exists = exists
        self._grounding = grounding
        self._domain = domain

    def analyze(self, url):
        return types.SimpleNamespace(
            url=url, domain=self._domain, exists=self._exists,
            grounding_score=self._grounding,
            reason="(fake) 'does it exist' verdict",
            evidence={"structural": {"kind": "valid"}})


class SpyClassifier:
    """A classifier with an opinion - AND a counter that the pipeline
    must not touch when Stage A fails."""
    def __init__(self, confidence):
        self.calls = 0
        self._c = confidence

    def predict_breakdown(self, feats, url=None):
        self.calls += 1
        return {
            "rf_probability": self._c,
            "xgb_probability": self._c,
            "classifier_confidence": self._c,
            "model_disagreement": 0.0,
            "models_available": ["random_forest", "xgboost"],
            "known_legit_override": False,
        }


class SpyVerifier:
    def __init__(self, score):
        self.calls = 0
        self._score = score

    def verify(self, url):
        self.calls += 1
        return types.SimpleNamespace(
            verification_result=self._score, offline=False,
            coverage=1.0, warnings=[],
            reason="mock verdict",
            to_dict=lambda: {"coverage": 1.0, "warnings": []})


# ---------------------------------------------------------------------------
# CASE 1: exists=TRUE, classifier says MALICIOUS + external evidence strong
# ---------------------------------------------------------------------------


def test_case1_exists_but_malicious_proceeds_to_stage_b_and_flags_it():
    clf = SpyClassifier(confidence=0.95)      # thinks it's very malicious
    ver = SpyVerifier(score=0.8)              # external evidence is strong
    pipe = PhishGuardPipeline(
        stage_a=FakeStageA(exists=True, grounding=0.8),
        classifier=clf, verifier=ver)

    out = pipe.analyze_url("https://some-real-domain.com/account/update")

    # Stage A passes (the URL is real), so B runs and CAN flag the threat.
    assert out["stage_reached"] == "B"
    assert out["exists"] is True
    assert clf.calls == 1
    # threat = 0.5*0.8 + 0.5*0.95 = 0.875 ; strong external -> Malicious.
    assert abs(out["threat_risk_score"] - 0.875) < 1e-6
    assert out["final_label"] == "Malicious"


def test_case1b_high_ml_but_weak_external_evidence_stops_short_of_malicious():
    # Same ML suspicion, but external evidence is weak (0.45, below 0.60).
    # CHANGE 16: ML-elevated + external-limited -> Suspicious, never Malicious.
    clf = SpyClassifier(confidence=0.95)
    ver = SpyVerifier(score=0.45)
    pipe = PhishGuardPipeline(
        stage_a=FakeStageA(exists=True, grounding=0.8),
        classifier=clf, verifier=ver)
    out = pipe.analyze_url("https://some-real-domain.com/account/update")
    assert out["stage_reached"] == "B"
    assert out["final_label"] == "Suspicious"


# ---------------------------------------------------------------------------
# CASE 2: exists=FALSE (looks malicious, but fabricated)
# ---------------------------------------------------------------------------


def test_case2_fake_url_stops_at_hallucination_classifier_never_called():
    clf = SpyClassifier(confidence=0.99)   # even a would-be "malicious" verdict
    ver = SpyVerifier(score=0.99)          # and strong vendor "evidence"
    pipe = PhishGuardPipeline(
        stage_a=FakeStageA(exists=False, grounding=0.1),
        classifier=clf, verifier=ver)

    out = pipe.analyze_url("https://paypa1-secure-login.invalid/verify")

    # The fabricated URL is labelled Hallucination at Stage A - full stop.
    assert out["final_label"] == "Hallucination"
    assert out["stage_reached"] == "A"
    assert clf.calls == 0, (
        "classifier was invoked on a non-existent URL - must never happen")
    assert ver.calls == 0, (
        "verification was invoked on a non-existent URL - must never happen")
    # No Stage B value may be fabricated for a hallucination (CHANGE 2/10).
    assert out["risk_score"] is None
    assert out["threat_risk_score"] is None
    assert out["rf_probability"] is None
    assert out["xgb_probability"] is None
    assert out["classifier_confidence"] is None
    assert out["verification_result"] is None


def test_case2_reason_explains_the_stop():
    pipe = PhishGuardPipeline(
        stage_a=FakeStageA(exists=False, grounding=0.1),
        classifier=SpyClassifier(0.99), verifier=SpyVerifier(0.99))
    out = pipe.analyze_url("https://netf1ix-billing.example")
    assert "Hallucination" in out["reason"]
    # The reason must reference the EXISTENCE failure, not a threat verdict.
    assert "existence" in out["reason"].lower() or "stopped at Stage A" in out["reason"]