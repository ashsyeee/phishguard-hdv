"""
eval_malaysia.py - real-world hold-out evaluation for the Malaysian threat model.

PhiUSIIL is an optimistic benchmark; the honest question is "how well does the
system do on the sites a Malaysian user actually cares about?". This script
scores a small LABELLED hold-out set you control and reports the two-class
confusion matrix - especially the numbers that matter to the user:

    * phishing recall       - fraction of real phishing caught
    * legit specificity     - fraction of good sites left alone
    * legit false-alarm rate- fraction of good sites WRONGLY flagged
    * legit precision (NPV) - when we say "no phishing evidence", how often right

INPUT CSV (default data/eval/malaysia_holdout.csv), columns:
    url,label           # label in {legit, phishing}  (aliases accepted)

Usage:
    python src/eval_malaysia.py                       # ML-only (no network)
    python src/eval_malaysia.py --with-verification   # also query VT/PhishTank
    python src/eval_malaysia.py --threshold 0.5
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("phishguard.eval.my")

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import features as F
from classifiers import (MODEL_DIR, PHISHING_THRESHOLD, StageBClassifier,
                         legit_metrics, tune_threshold)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "data" / "eval" / "malaysia_holdout.csv"

_POSITIVE = {"phishing", "phish", "malicious", "1", "true", "bad"}
_NEGATIVE = {"legit", "legitimate", "benign", "safe", "0", "false", "good"}


def _normalise_label(raw: str) -> Optional[int]:
    v = str(raw).strip().lower()
    if v in _POSITIVE:
        return 1
    if v in _NEGATIVE:
        return 0
    return None


def load_holdout(path: Path) -> List[Dict]:
    rows: List[Dict] = []
    with path.open(encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=1):
            url = (row.get("url") or "").strip()
            if not url or url.startswith("#"):
                continue
            label = _normalise_label(row.get("label") or "")
            if label is None:
                logger.warning("Row %d: unrecognised label %r - skipped",
                               i, row.get("label"))
                continue
            rows.append({"url": url, "label": label})
    return rows


def evaluate(
    rows: List[Dict],
    model_dir: Path = MODEL_DIR,
    threshold: float = PHISHING_THRESHOLD,
    with_verification: bool = False,
) -> Dict:
    clf = StageBClassifier(model_dir=model_dir)
    verifier = None
    if with_verification:
        from verification_engine import VerificationEngine
        verifier = VerificationEngine()

    scored = []
    y_true, y_prob = [], []
    for r in rows:
        feats = F.extract_features(r["url"])
        breakdown = clf.predict_breakdown(feats)
        ml = breakdown.get("calibrated_confidence")
        if ml is None:
            ml = breakdown.get("classifier_confidence") or 0.0
        v = None
        if verifier is not None:
            v = float(verifier.verify(r["url"]).verification_result)
        # ML-only fusion unless verification requested; when requested, use the
        # SAME 0.5/0.5 rule the live pipeline uses.
        score = ml if v is None else 0.5 * v + 0.5 * ml
        scored.append({"url": r["url"], "label": r["label"],
                       "score": round(float(score), 4),
                       "ml": round(float(ml), 4),
                       "verification": (round(v, 4) if v is not None else None),
                       "predicted": int(float(score) >= threshold)})
        y_true.append(r["label"])
        y_prob.append(score)

    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob)
    metrics = legit_metrics(y_true, y_prob, threshold=threshold)
    from sklearn.metrics import roc_auc_score
    auc = (float(roc_auc_score(y_true, y_prob))
           if len(set(y_true.tolist())) > 1 else None)

    # Show the misses so the failure modes are visible (not just a number).
    false_neg = [s for s in scored if s["label"] == 1 and not s["predicted"]]
    false_pos = [s for s in scored if s["label"] == 0 and s["predicted"]]
    errors = {
        "false_negatives_phishing_missed": false_neg,
        "false_positives_legit_flagged": false_pos,
    }
    return {
        "n_rows": len(rows),
        "threshold": threshold,
        "with_verification": with_verification,
        "metrics": metrics,
        "roc_auc": auc,
        "errors": errors,
        "per_row": scored,
    }


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--threshold", type=float, default=PHISHING_THRESHOLD)
    ap.add_argument("--with-verification", action="store_true")
    ap.add_argument("--out", type=Path,
                    default=MODEL_DIR / "malaysia_eval.json")
    ap.add_argument("--recall-target", type=float, default=None,
                    help="if set, also print the threshold hitting this recall")
    args = ap.parse_args(argv)

    if not args.csv.is_file():
        print(f"ERROR: hold-out CSV not found: {args.csv}\n"
              f"Create it with columns 'url,label' (label = legit|phishing).")
        return 1

    rows = load_holdout(args.csv)
    if not rows:
        print("ERROR: no usable rows in the CSV.")
        return 1

    report = evaluate(rows, threshold=args.threshold,
                      with_verification=args.with_verification)
    m = report["metrics"]
    print(f"\n=== Malaysian hold-out ({report['n_rows']} URLs) ===")
    print(f"  threshold            : {report['threshold']:.2f}")
    print(f"  phishing recall      : {m['phishing_recall']:.4f}  "
          f"({m['tp']}/{m['n_phish']} caught)")
    print(f"  legit specificity    : {m['specificity']:.4f}  "
          f"({m['tn']}/{m['n_legit']} left alone)")
    print(f"  legit false-alarm    : {m['false_alarm_rate']:.4f}  "
          f"({m['fp']} good sites flagged)")
    print(f"  legit precision (NPV): {m['legit_precision_npv']:.4f}")
    if report["roc_auc"] is not None:
        print(f"  ROC-AUC              : {report['roc_auc']:.4f}")
    if report["errors"]["false_negatives_phishing_missed"]:
        print("  missed phishing:")
        for e in report["errors"]["false_negatives_phishing_missed"]:
            print(f"    - {e['url']} (score {e['score']})")
    if report["errors"]["false_positives_legit_flagged"]:
        print("  legit wrongly flagged:")
        for e in report["errors"]["false_positives_legit_flagged"]:
            print(f"    - {e['url']} (score {e['score']})")

    if args.recall_target is not None:
        rec = tune_threshold(
            np.asarray([r["label"] for r in rows]),
            np.asarray([s["score"] for s in report["per_row"]]),
            target_recall=args.recall_target)
        print(f"  -> to hit recall {args.recall_target:.2f}: use threshold "
              f"{rec['chosen_threshold']:.2f} (FA rate "
              f"{rec['legit_false_alarm_rate']:.4f})")
        report["threshold_for_target_recall"] = rec

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
