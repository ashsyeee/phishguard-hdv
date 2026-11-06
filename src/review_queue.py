"""review_queue.py - export analysed URLs for HUMAN review before any retraining.

Writes data/review/review_queue.csv from the results database. Each row has a
blank `human_label` column (legitimate / phishing / unsure) that a person fills
in. Only rows with human_label filled in are eligible for retraining - the
system never trains on its own verdicts.

Usage:
    python src/review_queue.py [--out PATH]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import db  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "review" / "review_queue.csv"
COLUMNS = [
    "id", "timestamp", "url", "domain", "final_label", "classifier_confidence",
    "verification_coverage", "virustotal_result", "phishtank_result",
    "urlhaus_result", "safe_browsing_result", "reason",
    "human_label", "reviewer_note",
]


def export(out_path: Path = DEFAULT_OUT) -> int:
    rows = [r for r in db.get_all_results() if r.get("stage_reached") == "B"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({**{c: r.get(c, "") for c in COLUMNS},
                             "human_label": "", "reviewer_note": ""})
    return len(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    n = export(args.out)
    print(f"Exported {n} Stage-B rows to {args.out}")
    print("Fill human_label with: legitimate / phishing / unsure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
