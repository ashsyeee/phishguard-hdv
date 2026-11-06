"""train_v2.py - retrain on LegitPhish + reviewed labels; evaluate on held-out sets.

Writes ONLY to models_v2/. The live models/ directory is never touched; a v2
model replaces the live one only after a person compares the metrics.

Training data : LegitPhish url_features_extracted1.csv (ClassLabel 1=legit, 0=phish)
                + human-reviewed rows from data/review/review_queue.csv
Held out      : phishtrap_full.csv (fresh 2026 feeds), Malaysia hold-out,
                PhiUSIIL test split (data/processed/test.csv)

LEAKAGE GUARD: any registrable domain that appears in a test set is removed
from training, and training is split by domain so a site never sits on both
sides of the split.

Usage:  python src/train_v2.py
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import features as F  # noqa: E402
from data_prep import extract_domain  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("train_v2")

LEGITPHISH = ROOT / "data" / "LegitPhish Dataset" / "LegitPhish Dataset" / "url_features_extracted1.csv"
PHISHTRAP = ROOT / "data" / "phishtrap" / "phishtrap_full.csv"
MALAYSIA = ROOT / "data" / "eval" / "malaysia_holdout.csv"
PHIUSIIL_TEST = ROOT / "data" / "processed" / "test.csv"
REVIEW = ROOT / "data" / "review" / "review_queue.csv"
OUT = ROOT / "models_v2"
SEED = 42


def load_legitphish() -> pd.DataFrame:
    df = pd.read_csv(LEGITPHISH, low_memory=False)
    df = df.dropna(subset=["ClassLabel"])
    df = pd.DataFrame({"url": df["URL"].astype(str),
                       "is_phishing": (df["ClassLabel"] == 0).astype(int)})
    return df.drop_duplicates("url")


def load_reviews() -> pd.DataFrame:
    rows = []
    with REVIEW.open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            lab = (r.get("human_label") or "").strip().lower()
            if lab in ("legitimate", "phishing"):
                rows.append({"url": r["url"], "is_phishing": int(lab == "phishing")})
    return pd.DataFrame(rows, columns=["url", "is_phishing"]).drop_duplicates("url")


def load_phishtrap() -> pd.DataFrame:
    df = pd.read_csv(PHISHTRAP, low_memory=False)
    return pd.DataFrame({"url": df["url"].astype(str),
                         "is_phishing": df["label"].astype(int)})


def load_malaysia() -> pd.DataFrame:
    rows = []
    with MALAYSIA.open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(line for line in fh if not line.startswith("#")):
            lab = (r.get("label") or "").strip().lower()
            if lab in ("legit", "legitimate", "phishing"):
                rows.append({"url": r["url"], "is_phishing": int(lab == "phishing")})
    return pd.DataFrame(rows, columns=["url", "is_phishing"])


UNIMAS_DNS = ROOT / "data" / "Phishing dataset" / "url" / "dns_feature_94k.xlsx"


def load_unimas() -> pd.DataFrame:
    df = pd.read_excel(UNIMAS_DNS)
    df = df.dropna(subset=["label"])
    return pd.DataFrame({"url": df["url"].astype(str),
                         "is_phishing": (df["label"] == "phishing").astype(int)}
                        ).drop_duplicates("url")


REGRESSION = ROOT / "data" / "regression" / "regression_set.csv"


def load_regression() -> pd.DataFrame:
    df = pd.read_csv(REGRESSION)
    return pd.DataFrame({"url": df["url"].astype(str),
                         "is_phishing": (df["truth"] == "phishing").astype(int)})


def load_phiussiil_test() -> pd.DataFrame:
    df = pd.read_csv(PHIUSIIL_TEST, low_memory=False)
    df = df[df["category"].isin(["real_legitimate", "real_phishing"])]
    return pd.DataFrame({"url": df["url"].astype(str),
                         "is_phishing": df["is_phishing"].astype(int)})


def metrics(y: np.ndarray, p: np.ndarray, threshold: float = 0.5) -> dict:
    pred = (p >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    return {
        "n": int(len(y)),
        "phishing_recall": round(tp / max(tp + fn, 1), 4),
        "legit_specificity": round(tn / max(tn + fp, 1), 4),
        "false_alarm_rate": round(fp / max(fp + tn, 1), 4),
        "auc": round(float(roc_auc_score(y, p)), 4) if len(set(y)) > 1 else None,
    }


def featurise(df: pd.DataFrame) -> np.ndarray:
    return F.build_feature_matrix(df, url_col="url").astype(np.float32).values


def main(source: str = "legitphish") -> int:
    sources = {
        "legitphish": lambda: pd.concat([load_legitphish(), load_reviews()], ignore_index=True),
        "phishtrap": load_phishtrap,
        "both": lambda: pd.concat([load_legitphish(), load_reviews(), load_phishtrap()],
                                  ignore_index=True).drop_duplicates("url"),
        "all": lambda: pd.concat([load_legitphish(), load_reviews(), load_unimas()],
                                 ignore_index=True).drop_duplicates("url"),
    }
    train_pool = sources[source]()
    tests = {
        "malaysia_holdout": load_malaysia(),
        "regression_set": load_regression(),
        "phiusiil_test": load_phiussiil_test(),
    }
    if source not in ("phishtrap", "both"):
        tests["phishtrap_2026"] = load_phishtrap()

    for df in [train_pool, *tests.values()]:
        df["domain"] = df["url"].map(extract_domain)

    test_domains = set()
    for name, df in tests.items():
        test_domains |= set(df["domain"])
    before = len(train_pool)
    train_pool = train_pool[~train_pool["domain"].isin(test_domains)].reset_index(drop=True)
    log.info("training pool (%s): %d rows (%d removed - domain also in a test set)",
             source, len(train_pool), before - len(train_pool))

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr_idx, te_idx = next(gss.split(train_pool, groups=train_pool["domain"]))
    train, internal = train_pool.iloc[tr_idx], train_pool.iloc[te_idx]
    log.info("train %d rows | internal test %d rows (domain-grouped)",
             len(train), len(internal))

    X_tr = featurise(train)
    y_tr = train["is_phishing"].values
    log.info("training RandomForest...")
    rf = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=SEED,
                                class_weight="balanced_subsample")
    rf.fit(X_tr, y_tr)
    log.info("training XGBoost...")
    import xgboost as xgb
    xg = xgb.XGBClassifier(n_estimators=400, max_depth=6, learning_rate=0.08,
                           subsample=0.9, colsample_bytree=0.9, tree_method="hist",
                           random_state=SEED, eval_metric="logloss")
    xg.fit(X_tr, y_tr)

    def ensemble(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        X = featurise(df)
        return df["is_phishing"].values, (rf.predict_proba(X)[:, 1]
                                          + xg.predict_proba(X)[:, 1]) / 2

    report = {"training": {"rows": int(len(train)),
                           "phishing_share": round(float(y_tr.mean()), 4),
                           "removed_for_leakage": int(before - len(train_pool))}}
    y, p = ensemble(internal)
    report["internal_domain_grouped"] = metrics(y, p)
    for name, df in tests.items():
        y, p = ensemble(df)
        report[name] = metrics(y, p)
        log.info("%s: %s", name, report[name])

    out = OUT / source
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics_v2.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    xg.save_model(str(out / "xgboost.json"))
    import joblib
    joblib.dump(rf, out / "random_forest.pkl")
    log.info("saved to %s", out)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "legitphish"
    raise SystemExit(main(src))
