"""Step 7 tests: SEQUENTIAL, short-circuiting pipeline behaviour.

Core invariant under test: when Stage A says the URL does not exist, Stage B
(classifier AND verification) is provably never invoked, and the output
carries NULL Stage B fields (CHANGE 2 / CHANGE 10).
"""
import types

import pandas as pd
import pytest

from pipeline import PhishGuardPipeline


class FakeStageA:
    def __init__(self, exists=True, grounding=0.8, domain="fake-domain.com",
                 uncertain=False):
        self._exists = exists
        self._grounding = grounding
        self._domain = domain
        self._uncertain = uncertain

    def analyze(self, url):
        return types.SimpleNamespace(
            url=url, domain=self._domain, exists=self._exists,
            uncertain=self._uncertain,
            grounding_score=self._grounding, reason="(fake) existence verdict",
            evidence={"structural": {"kind": "valid"}})


class SpyClassifier:
    """Records every invocation - the core 'never called' assertion.

    CHANGE 3: the pipeline consumes predict_breakdown() (per-model
    probabilities + ensemble), never just a single confidence number.
    """
    def __init__(self, rf=0.1, xgb=None):
        self.calls = 0
        self._rf = rf
        self._xgb = rf if xgb is None else xgb

    def predict_breakdown(self, feats, url=None):
        self.calls += 1
        return {
            "rf_probability": self._rf,
            "xgb_probability": self._xgb,
            "classifier_confidence": round((self._rf + self._xgb) / 2, 4),
            "model_disagreement": round(abs(self._rf - self._xgb), 4),
            "models_available": ["random_forest", "xgboost"],
            "known_legit_override": False,
        }


class SpyVerifier:
    def __init__(self, score=0.5, coverage=1.0):
        self.calls = 0
        self._score = score
        self._coverage = coverage

    def verify(self, url):
        self.calls += 1
        return types.SimpleNamespace(
            verification_result=self._score, offline=True,
            coverage=self._coverage, warnings=[],
            reason="mock verdict",
            to_dict=lambda: {"coverage": self._coverage, "warnings": []})


def make_pipeline(stage_a=None, clf=None, ver=None):
    return PhishGuardPipeline(
        stage_a=stage_a or FakeStageA(),
        classifier=clf or SpyClassifier(),
        verifier=ver or SpyVerifier())


def test_hallucination_short_circuits_stage_b():
    clf = SpyClassifier()
    ver = SpyVerifier()
    pipe = make_pipeline(stage_a=FakeStageA(exists=False), clf=clf, ver=ver)

    out = pipe.analyze_url("https://paypa1-secure.invalid/login")

    assert out["final_label"] == "Hallucination"
    assert out["stage_reached"] == "A"
    assert out["exists"] is False
    # Every Stage B field must be null - nothing was fabricated (CHANGE 2/10).
    assert out["classifier_confidence"] is None
    assert out["rf_probability"] is None
    assert out["xgb_probability"] is None
    assert out["model_disagreement"] is None
    assert out["verification_result"] is None
    assert out["threat_risk_score"] is None
    assert out["risk_score"] is None
    assert "stopped at Stage A" in out["reason"]
    assert clf.calls == 0, "classifier must NEVER run on a hallucination"
    assert ver.calls == 0, "verification must NEVER run on a hallucination"


def test_real_url_reaches_stage_b_and_fuses_scores():
    clf = SpyClassifier(0.3)
    ver = SpyVerifier(0.8)
    pipe = make_pipeline(stage_a=FakeStageA(exists=True, grounding=0.9),
                         clf=clf, ver=ver)

    out = pipe.analyze_url("https://example.com")

    assert out["stage_reached"] == "B"
    assert out["exists"] is True
    assert clf.calls == 1
    assert ver.calls == 1
    # Per-model probabilities and the ensemble travel through the result.
    assert out["rf_probability"] == 0.3
    assert out["xgb_probability"] == 0.3
    assert out["model_disagreement"] == 0.0
    assert out["classifier_confidence"] == 0.3
    assert out["verification_result"] == 0.8
    # 0.5*verification + 0.5*classifier = 0.5*0.8 + 0.5*0.3 = 0.55
    expected = 0.5 * 0.8 + 0.5 * 0.3
    assert abs(out["threat_risk_score"] - expected) < 1e-6
    assert abs(out["risk_score"] - expected) < 1e-6
    assert out["final_label"] == "Suspicious"
    assert "0.5*verification" in out["reason"] and "0.5*classifier" in out["reason"]
    # grounding must NOT appear inside the threat-risk fusion reason.
    assert "Grounding ×" not in out["reason"]


def test_per_model_breakdown_and_disagreement_flow_through():
    clf = SpyClassifier(rf=0.2, xgb=0.9)
    pipe = make_pipeline(stage_a=FakeStageA(exists=True), clf=clf)
    out = pipe.analyze_url("https://example.com")

    assert out["rf_probability"] == 0.2
    assert out["xgb_probability"] == 0.9
    assert out["classifier_confidence"] == 0.55   # mean of available models
    assert out["model_disagreement"] == 0.7       # |rf - xgb|


def test_stage_label_always_in_output():
    for exists in (True, False):
        out = make_pipeline(stage_a=FakeStageA(exists=exists)).analyze_url("http://x.example")
        assert out["stage_reached"] in ("A", "B")


def test_batch_mode_csv():
    import tempfile
    from pathlib import Path

    clf = SpyClassifier()
    ver = SpyVerifier()
    pipe = make_pipeline(stage_a=FakeStageA(exists=True), clf=clf, ver=ver)

    df = pd.DataFrame({"url": ["https://a.example", "https://b.example"]})
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "in.csv"
        df.to_csv(p, index=False)
        out_df = pipe.analyze_csv(str(p))
    assert len(out_df) == 2
    assert out_df["stage_reached"].tolist() == ["B", "B"]
    assert clf.calls == 2


def test_batch_shorts_each_row_independently():
    pipe = make_pipeline(stage_a=FakeStageA(exists=False))
    outs = pipe.analyze_batch(["https://fake1.invalid", "https://fake2.test"])
    assert all(o["final_label"] == "Hallucination" for o in outs)
    assert all(o["stage_reached"] == "A" for o in outs)


def test_uncertain_existence_does_not_short_circuit_to_hallucination():
    """No conclusive Stage A evidence must NOT be labelled a confident
    hallucination - Stage B still runs and the flag is carried through."""
    clf = SpyClassifier(0.1)
    ver = SpyVerifier(0.1)
    pipe = make_pipeline(
        stage_a=FakeStageA(exists=False, grounding=0.5, uncertain=True),
        clf=clf, ver=ver)
    out = pipe.analyze_url("https://unknown-brand-new.com/login")
    assert out["stage_reached"] == "B"
    assert out["existence_uncertain"] is True
    assert out["final_label"] != "Hallucination"
    assert clf.calls == 1 and ver.calls == 1


def test_uncertain_existence_never_reports_likely_safe():
    pipe = make_pipeline(
        stage_a=FakeStageA(exists=False, grounding=0.5, uncertain=True),
        clf=SpyClassifier(0.0), ver=SpyVerifier(0.0))
    out = pipe.analyze_url("https://unknown-brand-new.com/login")
    assert out["final_label"] != "Likely Safe"