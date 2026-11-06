"""UI-contract tests (CHANGE 3/8/9/10/15/17).

These assert the USER-FACING guarantees that must not regress, at the pure
backend / copy level (no Streamlit import needed):

  * Stage A failure -> POTENTIAL HALLUCINATION + Stage B SKIPPED, with no
    fabricated (i.e. zero) classifier/verification/threat values.
  * "No match" is never relabelled "safe"/"legitimate".
  * Phantom-squatting is a CONSIDERATION - conditional wording, never claims a
    domain is available or that hallucination == phishing, and never changes
    the classification.
  * LLM provenance (source / llm_model / original_user_question) is preserved
    end-to-end into the database.
"""
import types

import pytest

import ui_copy as ui
from db import get_recent_results, log_result
from pipeline import PhishGuardPipeline


class FakeStageA:
    def __init__(self, exists, grounding=0.8, domain="d.com"):
        self._exists = exists
        self._grounding = grounding
        self._domain = domain

    def analyze(self, url):
        return types.SimpleNamespace(
            url=url, domain=self._domain, exists=self._exists,
            grounding_score=self._grounding, reason="(fake) existence verdict",
            evidence={"structural": {"kind": "valid"}})


class SpyClassifier:
    def __init__(self, rf=0.2, xgb=0.2):
        self.calls = 0
        self._rf, self._xgb = rf, xgb

    def predict_breakdown(self, feats, url=None):
        self.calls += 1
        return {
            "rf_probability": self._rf, "xgb_probability": self._xgb,
            "classifier_confidence": (self._rf + self._xgb) / 2,
            "model_disagreement": abs(self._rf - self._xgb),
            "models_available": ["random_forest", "xgboost"],
            "known_legit_override": False,
        }


class SpyVerifier:
    def __init__(self, score=0.5, coverage=1.0):
        self.calls = 0
        self._score, self._coverage = score, coverage

    def verify(self, url):
        self.calls += 1
        return types.SimpleNamespace(
            verification_result=self._score, offline=False,
            coverage=self._coverage, warnings=[], reason="mock verdict",
            to_dict=lambda: {
                "coverage": self._coverage,
                "sources": {
                    "virustotal": {"status": "NO_MATCH"},
                    "safe_browsing": {"status": "NO_MATCH"},
                },
                "warnings": [],
            })


def _pipe(exists):
    return PhishGuardPipeline(
        stage_a=FakeStageA(exists=exists),
        classifier=SpyClassifier(),
        verifier=SpyVerifier())


# ---------------------------------------------------------------------------
# CHANGE 17.2 - Stage A failure => skipped, never zero
# ---------------------------------------------------------------------------

def test_stage_a_failure_never_fabricates_zero_values():
    out = _pipe(exists=False).analyze_url("https://fake.invalid/x")
    # Skipped is represented by NULL, not 0.0 (a skipped analysis is not zero).
    for k in ("rf_probability", "xgb_probability", "classifier_confidence",
              "model_disagreement", "verification_result", "threat_risk_score",
              "risk_score", "virustotal_result", "safe_browsing_result"):
        assert out[k] is None, f"{k} must be None (skipped), not a value"
    assert out["stage_reached"] == "A"
    assert out["final_label"] == "Hallucination"
    # Display mapping: hallucination -> potential hallucination + skipped.
    assert ui.PHISHING_LABEL[out["final_label"]] == "SKIPPED"


def test_stage_a_success_exposes_per_source_results():
    out = _pipe(exists=True).analyze_url("https://example.com")
    assert out["stage_reached"] == "B"
    assert out["virustotal_result"] == "NO_MATCH"
    assert out["safe_browsing_result"] == "NO_MATCH"
    assert out["rf_probability"] is not None
    assert out["xgb_probability"] is not None


# ---------------------------------------------------------------------------
# CHANGE 17.4 - "No match" is NOT "safe"
# ---------------------------------------------------------------------------

def test_no_match_state_is_not_safe_or_legitimate():
    assert ui.source_state_text("NO_MATCH") == "No match found"
    for label in ui.SOURCE_STATE_LABELS.values():
        assert "safe" not in label.lower()
        assert "legitimate" not in label.lower()
        assert "trusted" not in label.lower()


# ---------------------------------------------------------------------------
# CHANGE 17.5/6 - phantom-squatting consideration wording + no classification
# ---------------------------------------------------------------------------

def test_phantom_squatting_does_not_claim_availability_or_detection():
    text = (ui.PHANTOM_SQUATTING_TITLE + " " + ui.PHANTOM_SQUATTING_TEXT
            + " " + ui.PHANTOM_SQUATTING_DISCLAIMER)
    # Never a definitive availability claim - it must stay conditional.
    assert "if this hallucinated domain is available" in text.lower()
    assert "phantom squatting detected" not in text.lower()
    assert "domain available for registration" not in text.lower()
    # It is a consideration, not a classification.
    assert "consideration" in text.lower()


def test_phantom_squatting_is_not_a_classification_result():
    # A hallucinated URL is labelled "Hallucination" - never a phantom label.
    out = _pipe(exists=False).analyze_url("https://fake2.invalid/x")
    assert "Phantom" not in out["final_label"]
    assert out["final_label"] == "Hallucination"
    # The whole Stage B label vocabulary contains no phantom-squatting verdict.
    assert set(ui.PHISHING_LABEL.values()) <= {
        "SKIPPED", "MALICIOUS", "SUSPICIOUS", "LIKELY SAFE", "UNVERIFIED"}


# ---------------------------------------------------------------------------
# CHANGE 15 - LLM provenance is preserved end-to-end
# ---------------------------------------------------------------------------

def test_pipeline_carries_llm_provenance_through_both_stages():
    for exists in (True, False):
        out = _pipe(exists=exists).analyze_url(
            "https://example.com",
            source="LLM_GENERATED", llm_model="gemini-3.6-flash",
            original_user_question="threats to banks?")
        assert out["source"] == "LLM_GENERATED"
        assert out["llm_model"] == "gemini-3.6-flash"
        assert out["original_user_question"] == "threats to banks?"


def test_db_persists_llm_provenance_and_per_source_results(tmp_path):
    p = tmp_path / "prov.db"
    log_result({
        "url": "https://example.com", "domain": "example.com",
        "stage_reached": "B", "exists": True, "grounding_score": 0.9,
        "rf_probability": 0.1, "xgb_probability": 0.1,
        "classifier_confidence": 0.1, "model_disagreement": 0.0,
        "verification_result": 0.5, "verification_detail": {"coverage": 1.0},
        "virustotal_result": "NO_MATCH", "safe_browsing_result": "NO_MATCH",
        "threat_risk_score": 0.3, "risk_score": 0.3,
        "final_label": "Unverified", "reason": "ok",
        "source": "LLM_GENERATED", "llm_model": "gemini-3.6-flash",
        "original_user_question": "threats to banks?",
    }, p)
    row = get_recent_results(1, p)[0]
    assert row["source"] == "LLM_GENERATED"
    assert row["llm_model"] == "gemini-3.6-flash"
    assert row["original_user_question"] == "threats to banks?"
    assert row["virustotal_result"] == "NO_MATCH"
    assert row["safe_browsing_result"] == "NO_MATCH"
    assert row["url"] == "https://example.com"  # extracted_indicator preserved


def test_db_hallucination_stage_b_columns_are_null(tmp_path):
    p = tmp_path / "skipped.db"
    log_result({
        "url": "https://fake.invalid/x", "domain": "fake.invalid",
        "stage_reached": "A", "exists": False, "grounding_score": 0.2,
        "rf_probability": None, "xgb_probability": None,
        "classifier_confidence": None, "model_disagreement": None,
        "verification_result": None, "verification_detail": None,
        "virustotal_result": None, "safe_browsing_result": None,
        "threat_risk_score": None, "risk_score": None,
        "final_label": "Hallucination", "reason": "stopped at Stage A",
        "source": "LLM_GENERATED", "llm_model": "gemini-3.6-flash",
        "original_user_question": "q?",
    }, p)
    row = get_recent_results(1, p)[0]
    assert row["stage_reached"] == "A"
    assert row["virustotal_result"] is None
    assert row["safe_browsing_result"] is None
    assert row["threat_risk_score"] is None
    # provenance is still present even for a skipped Stage B
    assert row["source"] == "LLM_GENERATED"


# ---------------------------------------------------------------------------
# CHANGE 3/5/11 - the UI explanation is non-technical and honest
# ---------------------------------------------------------------------------

def test_friendly_explanation_uses_no_internal_vocabulary():
    r = {
        "exists": True, "final_label": "Suspicious",
        "rf_probability": 0.82, "xgb_probability": 0.88,
        "classifier_confidence": 0.85, "verification_result": 0.45,
        "virustotal_result": "POSITIVE_MATCH", "safe_browsing_result": "NO_MATCH",
    }
    text = ui.build_friendly_explanation(r)
    for forbidden in ("grounded", "threat_risk_score", "0.5*verification",
                      "0.5*classifier", "ensemble"):
        assert forbidden not in text.lower(), f"leaked {forbidden!r}: {text}"
    # Matches the CHANGE 5 example style.
    assert "machine-learning" in text
    assert "external threat-intelligence evidence was limited" in text


def test_friendly_explanation_no_match_is_not_safe():
    r = {
        "exists": True, "final_label": "Likely Safe",
        "rf_probability": 0.05, "xgb_probability": 0.05,
        "classifier_confidence": 0.05, "verification_result": 0.1,
        "virustotal_result": "NO_MATCH", "safe_browsing_result": "NO_MATCH",
    }
    text = ui.build_friendly_explanation(r)
    assert "not proof of safety" in text


def test_friendly_explanation_hallucination_is_not_phishing():
    r = {"exists": False, "final_label": "Hallucination"}
    text = ui.build_friendly_explanation(r)
    assert "could not be verified as existing" in text
    assert "not performed" in text
    # No phishing verdict is ever given for a hallucinated URL.
    assert "malicious" not in text.lower()
    assert "suspicious" not in text.lower()
    assert "likely safe" not in text.lower()
