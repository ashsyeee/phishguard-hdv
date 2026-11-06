"""regression.py - score a model on the fixed labelled set after every change.

The set (data/regression/regression_set.csv) is NEVER used for training:
train_v2.py removes its domains from the training data.

Default mode scores the ML classifier only: fast, no network, deterministic.
--full runs the whole pipeline (slow, uses API quotas).

Each run is appended to data/regression/history.jsonl so changes can be compared.

Usage:
    python src/regression.py [--model-dir DIR] [--full] [--label NAME]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402

SET_PATH = ROOT / "data" / "regression" / "regression_set.csv"
HISTORY = ROOT / "data" / "regression" / "history.jsonl"
THRESHOLD = 0.5


def load_set() -> list[dict]:
    with SET_PATH.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def score_classifier(urls: list[str], model_dir: Path | None) -> list[float]:
    import features as F
    from classifiers import StageBClassifier

    clf = StageBClassifier(model_dir=model_dir) if model_dir else StageBClassifier()
    return [float(clf.predict_breakdown(F.extract_features(u), url=None)
                  ["classifier_confidence"]) for u in urls]


def score_full(urls: list[str]) -> list[float]:
    from pipeline import PhishGuardPipeline

    pipe = PhishGuardPipeline()
    scores = []
    for u in urls:
        r = pipe.analyze_url(u)
        label = r.get("final_label") or ""
        bad = label in ("Malicious", "Suspicious") or "Suspicious" in label
        scores.append(1.0 if bad else 0.0)
    return scores


def metrics(truth: np.ndarray, p: np.ndarray) -> dict:
    from sklearn.metrics import roc_auc_score

    pred = (p >= THRESHOLD).astype(int)
    pos, neg = truth == 1, truth == 0
    out = {
        "n": int(len(truth)),
        "phishing_recall": round(float((pred[pos] == 1).mean()) if pos.any() else 0.0, 4),
        "legit_specificity": round(float((pred[neg] == 0).mean()) if neg.any() else 0.0, 4),
    }
    out["auc"] = (round(float(roc_auc_score(truth, p)), 4)
                  if len(set(truth.tolist())) > 1 else None)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model-dir", type=Path, default=None,
                    help="model folder to test (default: live models/)")
    ap.add_argument("--full", action="store_true", help="run the full pipeline")
    ap.add_argument("--label", default="", help="name for this run in history")
    args = ap.parse_args(argv)

    rows = load_set()
    urls = [r["url"] for r in rows]
    truth = np.array([1 if r["truth"] == "phishing" else 0 for r in rows])

    scores = score_full(urls) if args.full else score_classifier(urls, args.model_dir)
    p = np.array(scores, dtype=float)
    res = metrics(truth, p)

    misses = []
    for r, t, s in zip(rows, truth, p):
        wrong = (t == 1 and s < THRESHOLD) or (t == 0 and s >= THRESHOLD)
        if wrong:
            misses.append({"url": r["url"], "truth": r["truth"],
                           "score": round(float(s), 3), "source": r["source"]})

    print(json.dumps(res, indent=2))
    print(f"errors: {len(misses)}")
    for m in misses:
        print(f"  {m['truth']:9s} score={m['score']:.3f}  {m['url']}")

    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "time": datetime.now().isoformat(timespec="seconds"),
            "label": args.label or ("full" if args.full else "classifier"),
            "model_dir": str(args.model_dir or "models"),
            "mode": "full" if args.full else "classifier",
            **res, "errors": len(misses)}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
