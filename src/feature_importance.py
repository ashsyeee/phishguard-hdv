"""
feature_importance.py - explainability artefact for the Stage B classifiers.

Produces `models/feature_importance.json`: a ranked table of how much each of
the 28 lexical features contributes to the RandomForest and XGBoost decisions.
This is the evidence the dissertation needs to justify *why* the feature set is
what it is (and to spot dead / redundant features).

Two complementary signals, no extra dependencies required:

  * XGBoost SHAP values - `booster.predict(DMatrix, pred_contribs=True)` returns
    exact per-feature TreeSHAP contributions for every row (XGBoost ships this
    natively). We report mean(|SHAP|) as the ranking.
  * RandomForest impurity importance - `feature_importances_` (Gini).

Usage:
    python src/feature_importance.py            # writes JSON + prints ranking
    python src/feature_importance.py --top 15
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("phishguard.stage_b.importance")

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import features as F
from classifiers import (MODEL_DIR, PROCESSED_DIR, StageBClassifier,
                         _real_rows, load_splits, make_x_y)


def compute_importance(
    test_df: Optional[pd.DataFrame] = None,
    model_dir: Path = MODEL_DIR,
    max_rows: int = 20000,
) -> Dict:
    """Rank features by mean|TreeSHAP| (XGBoost) and RF impurity importance."""
    import xgboost as xgb

    if test_df is None:
        _, test_df = load_splits()
        if test_df.empty:
            raise ValueError("test split not found - run data_prep first")

    X, y, _ = make_x_y(_real_rows(test_df))
    if len(X) > max_rows:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), size=max_rows, replace=False)
        X = X[idx]

    clf = StageBClassifier(model_dir=model_dir)

    # --- XGBoost exact TreeSHAP: pred_contribs adds a final bias column ------
    booster = clf._xgb.get_booster()
    dm = xgb.DMatrix(X, feature_names=list(F.FEATURE_NAMES))
    contribs = booster.predict(dm, pred_contribs=True)
    shap_vals = contribs[:, :-1]  # drop the base-value column
    xgb_shap = np.mean(np.abs(shap_vals), axis=0)

    # --- RandomForest impurity importance -----------------------------------
    rf_imp = np.asarray(clf._rf.feature_importances_, dtype=float)

    names = list(F.FEATURE_NAMES)
    rows = []
    for i, name in enumerate(names):
        rows.append({
            "feature": name,
            "xgboost_shap_mean_abs": float(xgb_shap[i]),
            "random_forest_importance": float(rf_imp[i]),
        })

    order = np.argsort(xgb_shap)[::-1]
    ranked = [rows[i] for i in order]
    report = {
        "n_rows_sampled": int(len(X)),
        "method": "XGBoost exact TreeSHAP (pred_contribs) + RandomForest Gini importance",
        "ranked_by": "xgboost_shap_mean_abs",
        "features": ranked,
    }
    (model_dir / "feature_importance.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--top", type=int, default=0,
                    help="print only the top N features (0 = all)")
    args = ap.parse_args(argv)

    try:
        report = compute_importance()
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}")
        return 1

    ranked = report["features"]
    print(f"\n=== Feature importance ({report['n_rows_sampled']} rows) ===")
    print(f"  {'feature':32s} {'xgb mean|SHAP|':>16s} {'rf gini':>10s}")
    show = ranked[: args.top] if args.top else ranked
    for r in show:
        print(f"  {r['feature']:32s} {r['xgboost_shap_mean_abs']:16.5f} "
              f"{r['random_forest_importance']:10.5f}")
    print(f"  -> written to {MODEL_DIR / 'feature_importance.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
