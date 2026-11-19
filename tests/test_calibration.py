"""Probability-calibration tests (isotonic on the validation split)."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import classifiers as C


def _synth(n_per=60, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n_per):
        # Legit: mostly benign lexical signal; Phish: mostly malicious.
        legit_feats = rng.normal(0.0, 0.3)
        phish_feats = rng.normal(3.0, 0.3)
        rows.append({"url": f"https://legit{i}.com", "is_phishing": 0,
                     "category": "real_legitimate"})
        rows.append({"url": f"https://phish{i}.io", "is_phishing": 1,
                     "category": "real_phishing"})
    return pd.DataFrame(rows)


def test_calibrator_written_and_loaded(tmp_path):
    pytest.importorskip("xgboost")
    df = _synth()
    train, val, test = df.iloc[:80], df.iloc[80:100], df.iloc[100:]
    metrics, meta = C.train_classifiers(train, test, val_df=val,
                                        model_dir=tmp_path, n_estimators=25)
    assert (tmp_path / C.CALIBRATOR_NAME).is_file()
    assert meta["evaluation"]["calibration"]["applied"] is True


def test_stage_b_exposes_calibrated_confidence(tmp_path):
    pytest.importorskip("xgboost")
    df = _synth()
    train, val, test = df.iloc[:80], df.iloc[80:100], df.iloc[100:]
    C.train_classifiers(train, test, val_df=val, model_dir=tmp_path,
                        n_estimators=25)
    clf = C.StageBClassifier(model_dir=tmp_path)
    feats = C.F.FEATURE_NAMES
    breakdown = clf.predict_breakdown({k: 0.0 for k in feats})
    assert "calibrated_confidence" in breakdown
    assert breakdown["calibrated_confidence"] is not None
    assert 0.0 <= breakdown["calibrated_confidence"] <= 1.0


def test_ece_and_brier_bounds():
    y = np.array([0, 0, 1, 1])
    p = np.array([0.1, 0.2, 0.8, 0.9])
    assert 0.0 <= C.expected_calibration_error(y, p) <= 1.0
    assert 0.0 <= C.brier_score(y, p) <= 1.0
    # A perfectly calibrated all-0.5 with balanced labels has low ECE.
    assert C.expected_calibration_error(
        np.array([0, 1]), np.array([0.5, 0.5])) < 1e-9


def test_feature_importance_ranks_all_features(tmp_path):
    pytest.importorskip("xgboost")
    import feature_importance as FI

    df = _synth()
    train, val, test = df.iloc[:80], df.iloc[80:100], df.iloc[100:]
    C.train_classifiers(train, test, val_df=val, model_dir=tmp_path,
                        n_estimators=25)
    report = FI.compute_importance(test_df=test, model_dir=tmp_path)
    assert len(report["features"]) == len(C.F.FEATURE_NAMES)
    assert (tmp_path / "feature_importance.json").is_file()
    scores = [f["xgboost_shap_mean_abs"] for f in report["features"]]
    assert scores == sorted(scores, reverse=True)  # ranked descending
