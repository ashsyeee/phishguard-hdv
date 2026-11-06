"""CHANGE-enforcement tests (CHANGE 1/3/4/5/8/11/14).

Covers the architectural rules that must not silently regress:
  * StageBClassifier.predict_breakdown exposes per-model probabilities,
    the ensemble mean, and model_disagreement (None when one model missing).
  * explain() is the same per-model breakdown, never the ensemble-as-RF.
  * make_x_y raises if hallucinated rows leak into Stage B training.
  * VerificationEngine status semantics: UNAVAILABLE/RATE_LIMITED are never
    sold as verdicts; coverage counts only genuine verdicts.
  * src/db migrations add new columns to an existing table without dropping
    history rows.
"""
import sqlite3

import pandas as pd
import pytest

import features as F
from classifiers import StageBClassifier, make_x_y
from db import get_recent_results, init_db, log_result
from hallucination_detector import ReferenceStore
from verification_engine import VerificationEngine


def _zero_feats() -> dict:
    return {name: 0.0 for name in F.FEATURE_NAMES}


# ---------------------------------------------------------------------------
# CHANGE 3/4 - per-model breakdown, ensemble mean, disagreement
# ---------------------------------------------------------------------------

def test_breakdown_with_both_models_is_mean_plus_disagreement():
    clf = StageBClassifier()          # loads the trained RF + XGB once
    rf_p = clf._rf.predict_proba(__import__("numpy").asarray(
        [[0.0] * len(F.FEATURE_NAMES)], dtype="float32"))[0, 1]
    bd = clf.predict_breakdown(_zero_feats())
    assert bd["rf_probability"] == round(float(rf_p), 4)
    assert bd["xgb_probability"] is not None
    expected = round((bd["rf_probability"] + bd["xgb_probability"]) / 2, 4)
    assert bd["classifier_confidence"] == expected
    assert bd["model_disagreement"] == round(
        abs(bd["rf_probability"] - bd["xgb_probability"]), 4)
    assert bd["models_available"] == ["random_forest", "xgboost"]


def test_breakdown_with_one_missing_model_has_no_disagreement_value():
    clf = StageBClassifier()
    clf._xgb = None                    # simulate XGB not being loaded
    bd = clf.predict_breakdown(_zero_feats())
    assert bd["rf_probability"] is not None
    assert bd["xgb_probability"] is None
    assert bd["classifier_confidence"] == bd["rf_probability"]  # only model
    assert bd["model_disagreement"] is None


def test_explain_is_the_real_per_model_breakdown():
    clf = StageBClassifier()
    assert clf.explain(_zero_feats()) == clf.predict_breakdown(_zero_feats())
    assert clf.predict_confidence(_zero_feats()) == \
        clf.predict_breakdown(_zero_feats())["classifier_confidence"]


# ---------------------------------------------------------------------------
# CHANGE 5 - hallucinated rows can never enter Stage B training
# ---------------------------------------------------------------------------

def test_make_x_y_rejects_hallucinated_rows():
    df = pd.DataFrame({
        "url": ["https://paypa1.invalid/x",
                "https://real-example.com",
                "https://phish-example.com/x"],
        "category": ["hallucinated", "real_legitimate", "real_phishing"],
        "is_phishing": [1, 0, 1],
    })
    with pytest.raises(ValueError, match="[Hh]allucinat"):
        make_x_y(df)


def test_make_x_y_accepts_real_rows_only():
    df = pd.DataFrame({
        "url": ["https://real-example.com", "https://phish-example.com/x"],
        "category": ["real_legitimate", "real_phishing"],
        "is_phishing": [0, 1],
    })
    X, y, real = make_x_y(df)
    assert len(y) == 2 and list(real["category"]) == ["real_legitimate",
                                                      "real_phishing"]


# ---------------------------------------------------------------------------
# Stage A reference store: only genuinely-existing domains may ground a URL
# ---------------------------------------------------------------------------

def test_reference_store_excludes_synthetic_categories(tmp_path):
    """hallucinated + real_but_misdescribed rows must NOT ground existence."""
    csv = tmp_path / "train.csv"
    pd.DataFrame({
        "url": ["https://real.com", "https://fake.invalid",
                "https://example.com/claim"],
        "domain": ["real.com", "fake.invalid", "example.com"],
        "category": ["real_legitimate", "hallucinated",
                     "real_but_misdescribed"],
    }).to_csv(csv, index=False)

    store = ReferenceStore(path=csv)
    assert store.query("real.com")["exact_hit"] is True
    assert store.query("fake.invalid")["exact_hit"] is False
    # example.com was only present as a synthetic 'misdescribed' row -> excluded.
    assert store.query("example.com")["exact_hit"] is False


# ---------------------------------------------------------------------------
# CHANGE 8 - verification status semantics + coverage
# ---------------------------------------------------------------------------

def test_no_keys_mock_mode_returns_unavailable_not_a_verdict():
    eng = VerificationEngine()
    eng.vt_key = eng.uh_key = eng.gsb_key = eng.urlscan_key = ""  # force no-key mode
    v = eng.verify("http://example.com")   # no keys -> offline
    assert v.offline is True
    assert v.verification_result == 0.5
    assert v.coverage == 0.0
    assert all(s["status"] == "UNAVAILABLE" for s in v.sources.values())
    assert v.warnings and "NOT treated as proof of safety" in v.warnings[0]


def test_coverage_excludes_rate_limited_source(monkeypatch):
    eng = VerificationEngine()
    monkeypatch.setattr(eng, "_virustotal",
                        lambda domain: {"score": 0.9, "offline": False,
                                        "status": "POSITIVE_MATCH",
                                        "note": "x", "api": "virustotal"})
    monkeypatch.setattr(eng, "_urlhaus",
                        lambda domain: {"score": 0.5, "offline": True,
                                        "status": "UNAVAILABLE",
                                        "note": "z", "api": "urlhaus"})
    monkeypatch.setattr(eng, "_urlscan",
                        lambda domain: {"score": 0.5, "offline": True,
                                        "status": "UNAVAILABLE",
                                        "note": "u", "api": "urlscan"})
    monkeypatch.setattr(eng, "_safe_browsing",
                        lambda url: {"score": 0.5, "offline": True,
                                     "status": "RATE_LIMITED",
                                     "note": "w", "api": "safe_browsing"})
    v = eng.verify("http://a.example")
    assert abs(v.coverage - 1 / 2) < 1e-3  # one of two configured sources answered
    assert v.verification_result == 0.9     # mean over genuine verdicts only
    assert v.warnings                       # missing sources surfaced


def test_coverage_full_when_both_sources_answer(monkeypatch):
    eng = VerificationEngine()
    monkeypatch.setattr(eng, "_virustotal",
                        lambda domain: {"score": 0.2, "offline": False,
                                        "status": "NO_MATCH",
                                        "note": "x", "api": "virustotal"})
    monkeypatch.setattr(eng, "_urlhaus",
                        lambda domain: {"score": 0.2, "offline": False,
                                        "status": "NO_MATCH",
                                        "note": "z", "api": "urlhaus"})
    monkeypatch.setattr(eng, "_urlscan",
                        lambda domain: {"score": 0.5, "offline": True,
                                        "status": "UNAVAILABLE",
                                        "note": "u", "api": "urlscan"})
    monkeypatch.setattr(eng, "_safe_browsing",
                        lambda url: {"score": 1.0, "offline": False,
                                     "status": "POSITIVE_MATCH",
                                     "note": "w", "api": "safe_browsing"})
    v = eng.verify("http://a.example")
    assert v.coverage == 1.0
    assert abs(v.verification_result - (0.2 + 0.2 + 1.0) / 3) < 1e-3
    assert v.warnings == []


# ---------------------------------------------------------------------------
def test_unconfigured_feed_does_not_lower_coverage(monkeypatch):
    eng = VerificationEngine()
    monkeypatch.setattr(eng, "_virustotal",
                        lambda domain: {"score": 0.2, "offline": False,
                                        "status": "NO_MATCH",
                                        "note": "x", "api": "virustotal"})
    monkeypatch.setattr(eng, "_urlhaus",
                        lambda domain: {"score": 0.5, "offline": True,
                                        "status": "UNAVAILABLE",
                                        "note": "z", "api": "urlhaus"})
    monkeypatch.setattr(eng, "_urlscan",
                        lambda domain: {"score": 0.5, "offline": True,
                                        "status": "UNAVAILABLE",
                                        "note": "u", "api": "urlscan"})
    monkeypatch.setattr(eng, "_safe_browsing",
                        lambda url: {"score": 0.2, "offline": False,
                                     "status": "NO_MATCH",
                                     "note": "w", "api": "safe_browsing"})
    v = eng.verify("http://a.example")
    assert v.coverage == 1.0
    assert v.warnings == []


# ---------------------------------------------------------------------------
# CHANGE 11 - DB migration adds columns without dropping history
# ---------------------------------------------------------------------------

def test_db_migration_adds_new_columns(tmp_path):
    p = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(p))
    conn.execute(
        "CREATE TABLE results (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "url TEXT NOT NULL, final_label TEXT NOT NULL)")
    conn.execute("INSERT INTO results (url, final_label) VALUES ('http://old', 'Hallucination')")
    conn.commit()
    conn.close()

    init_db(p)  # must ALTER TABLE the legacy schema in place
    assert get_recent_results(5, p)[0]["url"] == "http://old"  # history kept
    conn = sqlite3.connect(str(p))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(results)")}
    conn.close()
    for c in ("rf_probability", "xgb_probability", "model_disagreement",
              "verification_coverage", "threat_risk_score", "risk_score"):
        assert c in cols, f"migration missing column {c}"


def test_log_result_persists_null_stage_b_for_hallucination(tmp_path):
    p = tmp_path / "halluc.db"
    log_result({
        "url": "https://paypa1.invalid/login", "domain": "paypa1.invalid",
        "stage_reached": "A", "exists": False, "grounding_score": 0.2,
        "rf_probability": None, "xgb_probability": None,
        "classifier_confidence": None, "model_disagreement": None,
        "verification_result": None, "verification_detail": None,
        "threat_risk_score": None, "risk_score": None,
        "final_label": "Hallucination", "reason": "stopped at Stage A",
    }, p)
    row = get_recent_results(1, p)[0]
    assert row["stage_reached"] == "A"
    assert row["threat_risk_score"] is None
    assert row["rf_probability"] is None
    assert row["final_label"] == "Hallucination"