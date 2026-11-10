"""
classifiers.py - Step 5: STAGE B. ML maliciousness signal - REAL URLs ONLY.

The ONLY question trained here: "given a URL that Stage A already confirmed
REAL, is it malicious?" Therefore this module trains on `real_legitimate` and
`real_phishing` rows ONLY:

    * hallucinated rows are excluded - they answer the EXISTENCE question of
      Stage A, not the maliciousness question of Stage B. Training on them
      would teach the classifier to conflate the two questions, exactly the
      mix-up this project exists to prevent.
    * real_but_misdescribed rows are excluded too - the URL is benign, the
      *claim* is false; they describe a different failure mode.

Two learners are trained and both are kept (the weighted risk model fuses
their scores with VirusTotal/PhishTank in risk_scoring.py):

    * RandomForest (scikit-learn)   - strong on tabular/lexical features,
      robust, easy to explain per the report.
    * XGBoost                       - typically the stronger gradient-boosled
      baseline; similar inputs, complementary quirks.

Models are persisted to /models (joblib + xgboost native json) so the
pipeline/dashboard can reload them without retraining.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("phishguard.stage_b.classifier")

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import features as F

ROOT = Path(__file__).resolve().parents[1]
# Set PHISHGUARD_MODEL_DIR to test another model folder (e.g. models_v2/both)
# without replacing the live models/ directory.
MODEL_DIR = Path(os.getenv("PHISHGUARD_MODEL_DIR") or (ROOT / "models"))
PROCESSED_DIR = ROOT / "data" / "processed"

REAL_CATEGORIES = ("real_legitimate", "real_phishing")
RF_MODEL_NAME = "random_forest.pkl"
XGB_MODEL_NAME = "xgboost.json"
FEATURES_NAME = "feature_names.json"
CALIBRATOR_NAME = "calibrator.pkl"

# Single source of truth for the ML decision threshold: a phishing-class
# probability >= this value flags the URL. Imported by ui/status.py so the UI
# and the evaluation metrics can never diverge.
PHISHING_THRESHOLD = 0.50


# ===========================================================================
# Data plumbing
# ===========================================================================


def load_splits(dir_: Path = PROCESSED_DIR, with_val: bool = False):
    """Load processed train/test (and optionally val) csvs.

    Empty DataFrames are returned if Step 1 has not been run.
    """
    def read(name):
        p = dir_ / name
        if not p.is_file():
            logger.error("Missing %s - run `python src/data_prep.py` first", p)
            return pd.DataFrame()
        return pd.read_csv(p)
    if with_val:
        return read("train.csv"), read("val.csv"), read("test.csv")
    return read("train.csv"), read("test.csv")


def _real_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only rows that answer the maliciousness question."""
    return df[df["category"].isin(REAL_CATEGORIES)].reset_index(drop=True)


def make_x_y(df: pd.DataFrame) -> (np.ndarray, np.ndarray):
    """Vectorise URLs -> (feature matrix, phishing labels).

    HARD GUARD (CHANGE 5): hallucinated rows can never enter classifier
    training. `_real_rows` filters them OUT; if a caller passes a DataFrame
    that still contains hallucinated rows, that is a pipeline bug and we raise
    - Stage B must only ever learn "is this EXISTING URL malicious?".
    """
    real = _real_rows(df)
    if real.empty:
        raise ValueError("No real rows (run data_prep.py first)")
    if "hallucinated" in df["category"].astype(str).values:
        raise ValueError(
            "Hallucinated rows leaked into classifier training data - Stage B "
            "must train ONLY on real_legitimate / real_phishing (CHANGE 5).")
    X = F.build_feature_matrix(real).astype(np.float32)
    y = real["is_phishing"].astype(int).values
    return X.values, y, real


# ===========================================================================
# Calibration metrics (probability quality, not just ranking)
# ===========================================================================


def expected_calibration_error(y_true: np.ndarray, proba: np.ndarray,
                               n_bins: int = 10) -> float:
    """Expected Calibration Error: mean |confidence - accuracy| over bins.

    0.0 = perfectly calibrated confidences. Tree ensembles trained with
    class-weight balancing are usually over/under-confident, so reporting ECE
    (and Brier) makes the effect of isotonic calibration visible.
    """
    y_true = np.asarray(y_true, dtype=float)
    proba = np.asarray(proba, dtype=float)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(proba)
    if n == 0:
        return 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (proba > lo) & (proba <= hi)
        if not mask.any():
            continue
        conf = proba[mask].mean()
        acc = y_true[mask].mean()
        ece += (mask.sum() / n) * abs(conf - acc)
    return float(ece)


def brier_score(y_true: np.ndarray, proba: np.ndarray) -> float:
    """Brier score: mean squared error of the probability. Lower is better."""
    y_true = np.asarray(y_true, dtype=float)
    proba = np.asarray(proba, dtype=float)
    if len(proba) == 0:
        return 0.0
    return float(np.mean((proba - y_true) ** 2))


def legit_metrics(y_true: np.ndarray, proba: np.ndarray,
                  threshold: float = PHISHING_THRESHOLD) -> dict:
    """Metrics for BOTH classes, with the LEGIT class made first-class.

    Phishing metrics (precision/recall) answer "did we catch the bad guys".
    These answer the complementary question the user cares about: "when we call
    something legit, how often is it actually legit, and how often do we wrongly
    flag a good site?".

    Terminology (positive class = phishing, y=1):
        specificity / true-negative-rate = recall of the LEGIT class
        false-alarm-rate (FPR)           = legit sites wrongly flagged phishing
        npv                              = precision of the LEGIT class
    """
    y_true = np.asarray(y_true).astype(int)
    pred = (np.asarray(proba) >= threshold).astype(int)
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    tp = int(((pred == 1) & (y_true == 1)).sum())
    n_legit = tn + fp
    n_phish = tp + fn
    return {
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "specificity": (tn / n_legit) if n_legit else 0.0,
        "false_alarm_rate": (fp / n_legit) if n_legit else 0.0,
        "legit_precision_npv": (tn / (tn + fn)) if (tn + fn) else 0.0,
        "phishing_recall": (tp / n_phish) if n_phish else 0.0,
        "n_legit": n_legit, "n_phish": n_phish,
    }


def tune_threshold(
    y_true: np.ndarray,
    proba: np.ndarray,
    target_recall: float = 0.90,
    max_false_alarm: Optional[float] = None,
) -> dict:
    """Pick the ML decision threshold hitting a target phishing recall.

    Sweeps thresholds and chooses the LOWEST threshold whose phishing recall is
    still >= `target_recall` (lowest threshold = most conservative about missing
    phishing, but we still prioritise recall per the project brief). If
    `max_false_alarm` is given, thresholds whose legit false-alarm rate exceeds
    it are discarded first, so legit sites are protected too.

    Returns the chosen threshold plus the full legit/phishing breakdown and a
    compact sweep table for the dissertation.
    """
    y_true = np.asarray(y_true).astype(int)
    proba = np.asarray(proba, dtype=float)
    grid = np.round(np.arange(0.05, 1.00, 0.01), 2)

    sweep = []
    for t in grid:
        m = legit_metrics(y_true, proba, float(t))
        sweep.append({"threshold": float(t),
                      "phishing_recall": m["phishing_recall"],
                      "specificity": m["specificity"],
                      "false_alarm_rate": m["false_alarm_rate"],
                      "fp": m["fp"], "fn": m["fn"]})

    candidates = [s for s in sweep if s["phishing_recall"] >= target_recall]
    if max_false_alarm is not None:
        protected = [s for s in candidates
                     if s["false_alarm_rate"] <= max_false_alarm]
        candidates = protected or candidates

    if candidates:
        chosen = min(candidates, key=lambda s: s["threshold"])
    else:
        chosen = min(sweep, key=lambda s: (s["fn"], s["fp"]))

    m = legit_metrics(y_true, proba, chosen["threshold"])
    return {
        "target_recall": target_recall,
        "chosen_threshold": chosen["threshold"],
        "achieved_phishing_recall": m["phishing_recall"],
        "legit_specificity": m["specificity"],
        "legit_false_alarm_rate": m["false_alarm_rate"],
        "legit_precision_npv": m["legit_precision_npv"],
        "confusion": {"tn": m["tn"], "fp": m["fp"], "fn": m["fn"], "tp": m["tp"]},
        "sweep": sweep,
    }


# ===========================================================================
# Training
# ===========================================================================


def train_classifiers(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    val_df: Optional[pd.DataFrame] = None,
    model_dir: Path = MODEL_DIR,
    n_estimators: int = 200,
    seed: int = 42,
    calibrate: bool = True,
    **xgboost_kw,
) -> Dict[str, dict]:
    """Train RandomForest + XGBoost on real rows; calibrate; evaluate; persist.

    When `val_df` is given and `calibrate` is True, an isotonic regressor maps
    the ensemble's raw p(phishing) to a CALIBRATED probability using the
    held-out validation split (never the test split - that would leak). The
    calibrator is saved to models/calibrator.pkl and loaded by
    StageBClassifier at inference time, so the 0.5 decision threshold becomes
    statistically meaningful.

    Returns a metrics dict keyed by model name for logging/the dashboard.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)
    import numpy as np
    import xgboost as xgb

    logger.info("Building feature matrices on REAL rows only ...")
    # Pass the real-only subset: the split files legitimately contain the
    # synthetic Stage A rows, which make_x_y must reject if they ever reach it.
    X_tr, y_tr, _ = make_x_y(_real_rows(train_df))
    X_te, y_te, _ = make_x_y(_real_rows(test_df))
    X_va = y_va = None
    if val_df is not None and not val_df.empty:
        X_va, y_va, _ = make_x_y(_real_rows(val_df))
    logger.info("train=%d test=%d val=%s (real rows)", len(X_tr), len(X_te),
                len(X_va) if X_va is not None else "none")

    model_dir.mkdir(parents=True, exist_ok=True)

    # --- RandomForest -------------------------------------------------
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_features="sqrt",
        n_jobs=-1,
        random_state=seed,
        class_weight="balanced_subsample",   # mildly imbalanced phish:legit
    )
    logger.info("Training RandomForest (%d trees)...", n_estimators)
    rf.fit(X_tr, y_tr)
    _save_pkl(rf, model_dir / RF_MODEL_NAME)

    # --- XGBoost ------------------------------------------------------
    params = dict(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=400,
        learning_rate=0.08,
        max_depth=7,
        subsample=0.9,
        colsample_bytree=0.9,
        tree_method="hist",
        random_state=seed,
    )
    params.update(xgboost_kw)
    xgbc = xgb.XGBClassifier(**params)
    logger.info("Training XGBoost (%d estimators)...", params["n_estimators"])
    xgbc.fit(X_tr, y_tr)
    xgbc.save_model(model_dir / XGB_MODEL_NAME)

    # --- report metrics ----------------------------------------------
    (model_dir / FEATURES_NAME).write_text(
        json.dumps(list(F.FEATURE_NAMES)), encoding="utf-8")

    def _metrics(y_true, pred, proba) -> dict:
        cm = confusion_matrix(y_true, pred)
        return {
            "accuracy": float(accuracy_score(y_true, pred)),
            "precision": float(precision_score(y_true, pred)),
            "recall": float(recall_score(y_true, pred)),
            "f1": float(f1_score(y_true, pred)),
            "roc_auc": float(roc_auc_score(y_true, proba)),
            "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                                 "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
        }

    # Per-model probability vectors; the ensemble mean is the fused probability.
    rf_proba = rf.predict_proba(X_te)[:, 1]
    xgb_proba = xgbc.predict_proba(X_te)[:, 1]
    ens_proba = (rf_proba + xgb_proba) / 2.0

    metrics: Dict[str, dict] = {}
    for name, proba in (("random_forest", rf_proba), ("xgboost", xgb_proba)):
        pred = (proba >= PHISHING_THRESHOLD).astype(int)
        metrics[name] = _metrics(y_te, pred, proba)
        metrics[name]["ece"] = expected_calibration_error(y_te, proba)
        metrics[name]["brier"] = brier_score(y_te, proba)
        logger.info("%-12s acc=%.4f prec=%.4f rec=%.4f f1=%.4f auc=%.4f",
                    name, metrics[name]["accuracy"], metrics[name]["precision"],
                    metrics[name]["recall"], metrics[name]["f1"],
                    metrics[name]["roc_auc"])

    ens_pred = (ens_proba >= PHISHING_THRESHOLD).astype(int)
    ens_metrics = _metrics(y_te, ens_pred, ens_proba)
    ens_metrics["ece"] = expected_calibration_error(y_te, ens_proba)
    ens_metrics["brier"] = brier_score(y_te, ens_proba)
    logger.info("%-12s acc=%.4f prec=%.4f rec=%.4f f1=%.4f auc=%.4f",
                "ensemble", ens_metrics["accuracy"], ens_metrics["precision"],
                ens_metrics["recall"], ens_metrics["f1"], ens_metrics["roc_auc"])

    # --- Calibration: isotonic ens_proba -> p(phishing) fit on VAL only ----
    calibration_meta = {"applied": False}
    if calibrate and X_va is not None and len(set(y_va.tolist())) > 1:
        from sklearn.isotonic import IsotonicRegression
        rf_va = rf.predict_proba(X_va)[:, 1]
        xgb_va = xgbc.predict_proba(X_va)[:, 1]
        ens_va = (rf_va + xgb_va) / 2.0
        calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        calibrator.fit(ens_va, y_va)
        _save_pkl(calibrator, model_dir / CALIBRATOR_NAME)
        cal_proba = calibrator.predict(ens_proba)
        cal_pred = (cal_proba >= PHISHING_THRESHOLD).astype(int)
        cal_metrics = _metrics(y_te, cal_pred, cal_proba)
        cal_metrics["ece"] = expected_calibration_error(y_te, cal_proba)
        cal_metrics["brier"] = brier_score(y_te, cal_proba)
        logger.info("calibrated  acc=%.4f prec=%.4f rec=%.4f f1=%.4f auc=%.4f "
                    "ece=%.4f (raw ece=%.4f)",
                    cal_metrics["accuracy"], cal_metrics["precision"],
                    cal_metrics["recall"], cal_metrics["f1"], cal_metrics["roc_auc"],
                    cal_metrics["ece"], ens_metrics["ece"])
        calibration_meta = {
            "applied": True,
            "method": "isotonic regression (fit on validation split)",
            "n_val_real_rows": int(len(y_va)),
            "raw_ece": ens_metrics["ece"],
            "calibrated_ece": cal_metrics["ece"],
            "raw_brier": ens_metrics["brier"],
            "calibrated_brier": cal_metrics["brier"],
        }
        ensemble_metrics_out = {**cal_metrics, "calibrated": True,
                                "raw": {k: ens_metrics[k] for k in
                                        ("accuracy", "precision", "recall", "f1",
                                         "roc_auc", "confusion_matrix", "ece",
                                         "brier")}}
    else:
        ensemble_metrics_out = ens_metrics

    # Canonical, reproducible evaluation artefact (mirrors the shape the
    # dissertation cites): per-model + ensemble metrics, calibration quality
    # (ECE/Brier) and the ensemble confusion matrix, written next to the models.
    report = {
        "model_type": "RandomForest + XGBoost ensemble (mean probability)",
        "phishing_threshold": PHISHING_THRESHOLD,
        "n_test_real_rows": int(len(y_te)),
        "label_convention": "PhiUSIIL: 1=legitimate, 0=phishing (mapped to is_phishing)",
        "metrics": {"ensemble": ensemble_metrics_out, **metrics},
        "confusion_matrix": ensemble_metrics_out["confusion_matrix"],
        "per_model": metrics,
        "ensemble": ensemble_metrics_out,
        "calibration": calibration_meta,
        "note": "Recall is prioritised: missing a phishing URL is worse than a "
                "false alert. Held-out split is GROUPED BY DOMAIN (no domain "
                "straddles train/test), so these numbers are leak-free.",
    }
    (model_dir / "evaluation_results.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")

    return metrics, {"X_dim": X_tr.shape[1], "evaluation": report}


def _save_pkl(obj, path: Path) -> None:
    import joblib
    joblib.dump(obj, path)
    logger.info("Saved model -> %s", path)


# ===========================================================================
# Inference (loaded by pipeline + dashboard)
# ===========================================================================


class StageBClassifier:
    """Wraps the two trained models; exposes per-model AND ensemble scores.

    The pipeline and dashboard consume `predict_breakdown(features)`, which
    returns the INDIVIDUAL model probabilities plus the ensemble - so the two
    learners are never hidden behind a single fused number:

        {
          "rf_probability":       0.82,   # straight from RandomForest
          "xgb_probability":      0.88,   # straight from XGBoost
          "classifier_confidence":0.85,   # mean of the AVAILABLE models
          "model_disagreement":   0.06,   # |rf - xgb| (None if one model missing)
          "models_available":     ["random_forest", "xgboost"],
        }

    `predict_confidence(features)` remains for backward compatibility and
    simply returns `classifier_confidence` (CHANGE 3 - it must NEVER be shown
    as either model's individual probability).
    """

    def __init__(self, model_dir: Path = MODEL_DIR,
                 kind: str = "ensemble", seed: int = 42):
        self.model_dir = Path(model_dir)
        self.kind = kind
        self.seed = seed
        self._rf = None
        self._xgb = None
        self._calibrator = None
        self._load()

    def _load(self) -> None:
        import joblib
        import xgboost as xgb

        rf_path = self.model_dir / RF_MODEL_NAME
        xgb_path = self.model_dir / XGB_MODEL_NAME
        cal_path = self.model_dir / CALIBRATOR_NAME
        if rf_path.is_file():
            self._rf = joblib.load(rf_path)
        if xgb_path.is_file():
            self._xgb = xgb.XGBClassifier()
            self._xgb.load_model(str(xgb_path))
        if cal_path.is_file():
            try:
                self._calibrator = joblib.load(cal_path)
            except Exception:  # pragma: no cover - corrupt calibrator is non-fatal
                logger.warning("Could not load calibrator at %s; using raw "
                               "probabilities", cal_path)
                self._calibrator = None
        if self._rf is None and self._xgb is None:
            raise FileNotFoundError(
                "No trained model found. Run `python src/classifiers.py` "
                "to train on Step 1 data first.")

    def _probabilities(self, x: np.ndarray):
        """Individual p(phishing) from each model that exists."""
        rf_p = None
        xgb_p = None
        if self._rf is not None:
            rf_p = float(self._rf.predict_proba(x)[0, 1])
        if self._xgb is not None:
            xgb_p = float(self._xgb.predict_proba(x)[0, 1])
        return rf_p, xgb_p

    def predict_breakdown(self, features, url: object = None) -> Dict:
        """Per-model probabilities + ensemble + disagreement (CHANGE 3/4).

        If `url` is a curated official domain (exact registrable match), the
        result is overridden to verified-legit: the PhiUSIIL-trained model has
        never seen Malaysian banks as legitimate, so a brand on its OWN official
        domain must not be flagged. This is a positive override, applied only on
        an exact match - lookalikes and embedded-host tricks are unaffected.
        """
        if url is not None and F.is_known_legit_domain(url):
            base = {
                "rf_probability": None, "xgb_probability": None,
                "classifier_confidence": 0.0, "calibrated_confidence": 0.0,
                "model_disagreement": None, "models_available": [],
                "known_legit_override": True,
            }
            return base

        x = self._as_vector(features)
        rf_p, xgb_p = self._probabilities(x)

        available = []
        if rf_p is not None:
            available.append("random_forest")
        if xgb_p is not None:
            available.append("xgboost")

        probs = [p for p in (rf_p, xgb_p) if p is not None]
        if probs:
            classifier_confidence = float(np.mean(probs))
        elif self.kind == "random_forest" and rf_p is not None:
            classifier_confidence = rf_p
        elif self.kind == "xgboost" and xgb_p is not None:
            classifier_confidence = xgb_p
        else:
            # No model loaded - neutral, clearly flagged.
            classifier_confidence = 0.5

        model_disagreement = None
        if rf_p is not None and xgb_p is not None:
            model_disagreement = round(abs(rf_p - xgb_p), 4)

        # Calibrated probability: isotonic regression (fit on val) maps the raw
        # ensemble mean to a well-calibrated p(phishing). Exposed ALONGSIDE the
        # raw value; the rest of the system may keep consuming the raw
        # classifier_confidence for backward compatibility.
        calibrated_confidence = None
        if self._calibrator is not None:
            try:
                calibrated_confidence = round(float(
                    np.asarray(self._calibrator.predict(
                        np.asarray([classifier_confidence]))).ravel()[0]), 4)
            except Exception:  # pragma: no cover - defensive
                calibrated_confidence = None

        return {
            "rf_probability": (round(rf_p, 4) if rf_p is not None else None),
            "xgb_probability": (round(xgb_p, 4) if xgb_p is not None else None),
            "classifier_confidence": round(float(classifier_confidence), 4),
            "calibrated_confidence": calibrated_confidence,
            "model_disagreement": model_disagreement,
            "models_available": available,
            "known_legit_override": False,
        }

    def predict_confidence(self, features) -> float:
        """Ensemble p(real url is malicious) in [0,1] (mean of available)."""
        return self.predict_breakdown(features)["classifier_confidence"]

    def _as_vector(self, features) -> np.ndarray:
        if isinstance(features, dict):
            vec = [features.get(k, np.nan) for k in F.FEATURE_NAMES]
            return np.asarray([vec], dtype=np.float32)
        arr = np.asarray(features, dtype=np.float32)
        if arr.ndim == 1:
            return arr.reshape(1, -1)
        return arr

    def explain(self, features) -> Dict:
        """Per-model maliciousness breakdown for the reason string.

        FIXED (CHANGE 3): 'random_forest' previously used predict_confidence()
        (the ensemble mean) when this wrapper ran in ensemble mode, silently
        labelling the AVERAGE as RandomForest. It now returns the RF model's
        OWN probability, the XGBoost model's OWN probability, the ensemble
        classifier_confidence, and the model_disagreement - computed once.
        """
        return self.predict_breakdown(features)


def evaluate_saved_models(
    test_df: Optional[pd.DataFrame] = None,
    model_dir: Path = MODEL_DIR,
) -> Dict:
    """Score the SAVED models on the held-out test split (no retraining).

    Writes models/evaluation_results.json in the same canonical shape as
    train_classifiers, so the dissertation's per-model / ROC-AUC / confusion
    numbers can be reproduced at any time with `python src/classifiers.py eval`.
    """
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)
    import numpy as np

    if test_df is None:
        _, test_df = load_splits()
        if test_df.empty:
            raise ValueError("test split not found - run data_prep first")

    X_te, y_te, _ = make_x_y(_real_rows(test_df))
    clf = StageBClassifier(model_dir=model_dir)
    rf_proba = clf._rf.predict_proba(X_te)[:, 1]
    xgb_proba = clf._xgb.predict_proba(X_te)[:, 1]
    ens_proba = (rf_proba + xgb_proba) / 2.0

    def _metrics(pred, proba) -> dict:
        cm = confusion_matrix(y_te, pred)
        return {
            "accuracy": float(accuracy_score(y_te, pred)),
            "precision": float(precision_score(y_te, pred)),
            "recall": float(recall_score(y_te, pred)),
            "f1": float(f1_score(y_te, pred)),
            "roc_auc": float(roc_auc_score(y_te, proba)),
            "ece": expected_calibration_error(y_te, proba),
            "brier": brier_score(y_te, proba),
            "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                                 "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
        }

    per_model = {
        "random_forest": _metrics((rf_proba >= PHISHING_THRESHOLD).astype(int),
                                  rf_proba),
        "xgboost": _metrics((xgb_proba >= PHISHING_THRESHOLD).astype(int),
                            xgb_proba),
    }
    ensemble = _metrics((ens_proba >= PHISHING_THRESHOLD).astype(int), ens_proba)

    calibration_meta = {"applied": False}
    if clf._calibrator is not None:
        cal_proba = clf._calibrator.predict(ens_proba)
        cal_metrics = _metrics((cal_proba >= PHISHING_THRESHOLD).astype(int),
                               cal_proba)
        calibration_meta = {
            "applied": True,
            "method": "isotonic regression (fit on validation split)",
            "raw_ece": ensemble["ece"],
            "calibrated_ece": cal_metrics["ece"],
            "raw_brier": ensemble["brier"],
            "calibrated_brier": cal_metrics["brier"],
        }
        ensemble = {**cal_metrics, "calibrated": True,
                    "raw": {k: ensemble[k] for k in
                            ("accuracy", "precision", "recall", "f1", "roc_auc",
                             "ece", "brier", "confusion_matrix")}}

    report = {
        "model_type": "RandomForest + XGBoost ensemble (mean probability)",
        "phishing_threshold": PHISHING_THRESHOLD,
        "n_test_real_rows": int(len(y_te)),
        "label_convention": "PhiUSIIL: 1=legitimate, 0=phishing (mapped to is_phishing)",
        "metrics": {"ensemble": ensemble, **per_model},
        "confusion_matrix": ensemble["confusion_matrix"],
        "per_model": per_model,
        "ensemble": ensemble,
        "calibration": calibration_meta,
        "note": "Recall is prioritised. Held-out split is GROUPED BY DOMAIN "
                "(no domain straddles train/test) - leak-free numbers.",
    }
    (model_dir / "evaluation_results.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    return report


def tune_saved_models(
    val_df: Optional[pd.DataFrame] = None,
    model_dir: Path = MODEL_DIR,
    target_recall: float = 0.90,
    max_false_alarm: Optional[float] = None,
) -> Dict:
    """Recommend an ML decision threshold from the VALIDATION split.

    Uses the saved models + calibrator (no retraining). Writes
    models/threshold_recommendation.json and returns the report.
    """
    if val_df is None:
        _, val_df, _ = load_splits(with_val=True)
        if val_df.empty:
            raise ValueError("val split not found - run data_prep first")

    X_va, y_va, _ = make_x_y(_real_rows(val_df))
    clf = StageBClassifier(model_dir=model_dir)
    rf_p = clf._rf.predict_proba(X_va)[:, 1]
    xgb_p = clf._xgb.predict_proba(X_va)[:, 1]
    ens = (rf_p + xgb_p) / 2.0
    if clf._calibrator is not None:
        ens = clf._calibrator.predict(ens)

    report = tune_threshold(y_va, ens, target_recall=target_recall,
                            max_false_alarm=max_false_alarm)
    report["n_val_real_rows"] = int(len(y_va))
    report["note"] = ("Threshold chosen on the val split (never test). Lowering "
                      "the ML threshold raises phishing recall at the cost of "
                      "more legit false alarms - tune to the mission.")
    (model_dir / "threshold_recommendation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    return report


def _fmt_metrics(name: str, m: Dict) -> str:
    return (f"  {name:12s} acc={m['accuracy']:.4f} prec={m['precision']:.4f} "
            f"rec={m['recall']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: python src/classifiers.py [train|eval] (default: train)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    if argv is None:
        argv = sys.argv[1:]
    mode = (argv[0] if argv else "train").lower()

    if mode == "tune":
        try:
            report = tune_saved_models()
        except (ValueError, FileNotFoundError) as exc:
            print(f"ERROR: {exc}")
            return 1
        print("\n=== Threshold tuning (validation split) ===")
        print(f"  target phishing recall : {report['target_recall']:.2f}")
        print(f"  chosen ML threshold    : {report['chosen_threshold']:.2f}")
        print(f"  achieved phish recall  : {report['achieved_phishing_recall']:.4f}")
        print(f"  legit specificity      : {report['legit_specificity']:.4f}")
        print(f"  legit false-alarm rate : {report['legit_false_alarm_rate']:.4f}")
        print(f"  legit precision (NPV)  : {report['legit_precision_npv']:.4f}")
        print(f"  confusion (tn/fp/fn/tp): {report['confusion']}")
        print(f"  -> {MODEL_DIR / 'threshold_recommendation.json'}")
        return 0

    if mode == "eval":
        try:
            report = evaluate_saved_models()
        except (ValueError, FileNotFoundError) as exc:
            print(f"ERROR: {exc}")
            return 1
        print("\n=== Saved-model evaluation (held-out, domain-grouped) ===")
        print(_fmt_metrics("ensemble", report["ensemble"]))
        cal = report.get("calibration", {})
        if cal.get("applied"):
            print(f"  calibration: ECE {cal['raw_ece']:.4f} -> "
                  f"{cal['calibrated_ece']:.4f} | Brier {cal['raw_brier']:.4f} "
                  f"-> {cal['calibrated_brier']:.4f} (isotonic on val)")
        for name, m in report["per_model"].items():
            print(_fmt_metrics(name, m))
        print(f"  n_test_rows: {report['n_test_real_rows']}")
        print(f"  confusion:   {report['confusion_matrix']}")
        return 0

    train_df, val_df, test_df = load_splits(with_val=True)
    if train_df.empty or test_df.empty:
        return 1
    if val_df.empty:
        logger.warning("val.csv missing - training WITHOUT probability "
                       "calibration (val split is required to fit it)")
    try:
        metrics, meta = train_classifiers(train_df, test_df, val_df=val_df)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1
    print("\n=== Step 5 complete: classifier metrics (test split) ===")
    for name, m in metrics.items():
        print(_fmt_metrics(name, m))
    print(f"  ensemble:    " + _fmt_metrics("", meta["evaluation"]["ensemble"]).strip())
    print(f"  feature dim: {meta['X_dim']}  models -> {MODEL_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())