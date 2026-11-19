"""
eval_realtime.py - measure the latency claim instead of asserting it.

The dissertation says "real-time". That is only defensible with numbers, so
this script runs the SAME URLs twice through the real pipeline:

    sequential   one worker  - the original behaviour
    concurrent   N workers   - realtime.verify_many

Fairness rules
--------------
* VerificationEngine caches lookups per instance for 300 s, so each mode gets a
  FRESH pipeline. Reusing one would let the second mode read the first mode's
  cache and look artificially fast.
* A warm-up call is made before each timed run so model loading is not counted
  as verification latency.
* The same URL list is used for both modes, in the same order.

Output: docs/fyp/realtime_metrics.json

    python src/eval_realtime.py --urls 8 --workers 6 --rounds 2
"""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import sys

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from pipeline import PhishGuardPipeline  # noqa: E402
from realtime import verify_many  # noqa: E402

URLS_CSV = ROOT / "data" / "llm_output" / "benchmark_urls.csv"
OUT_PATH = ROOT / "docs" / "fyp" / "realtime_metrics.json"


def load_urls(limit: int) -> List[str]:
    """Prefer URLs that exist: the expensive Stage B path is what we measure."""
    import csv

    if not URLS_CSV.exists():
        raise SystemExit(f"Missing {URLS_CSV}. Run the benchmark labelling first.")
    existing, other = [], []
    with URLS_CSV.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            url = row["url"]
            if url in existing or url in other:
                continue
            (existing if row["registered"] == "True" else other).append(url)
    chosen = existing[:limit]
    if len(chosen) < limit:
        chosen += other[: limit - len(chosen)]
    if not chosen:
        raise SystemExit("No URLs found in the benchmark table.")
    return chosen


def run_mode(urls: List[str], workers: int, deadline_s: float) -> Dict:
    pipeline = PhishGuardPipeline()          # fresh cache for this mode
    pipeline.analyze_url(urls[0])            # warm-up, not timed
    out = verify_many(pipeline, urls, max_workers=workers,
                      deadline_s=deadline_s)
    labels = {}
    for r in out["results"]:
        labels[r["final_label"]] = labels.get(r["final_label"], 0) + 1
    return {
        "workers": workers,
        "meta": out["meta"],
        "label_counts": labels,
        "per_url_ms": {r["url"]: r.get("latency_ms") for r in out["results"]},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", type=int, default=8)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--deadline", type=float, default=120.0)
    args = ap.parse_args()

    urls = load_urls(args.urls)
    print(f"Measuring {len(urls)} URLs, {args.rounds} round(s)")

    seq_runs, con_runs = [], []
    for i in range(args.rounds):
        print(f"  round {i + 1}: sequential ...", flush=True)
        seq = run_mode(urls, 1, args.deadline)
        seq_runs.append(seq)
        print(f"    report {seq['meta']['report_latency_ms']} ms")
        print(f"  round {i + 1}: concurrent ({args.workers} workers) ...", flush=True)
        con = run_mode(urls, args.workers, args.deadline)
        con_runs.append(con)
        print(f"    report {con['meta']['report_latency_ms']} ms")

    def median_report(runs):
        return int(statistics.median(r["meta"]["report_latency_ms"] for r in runs))

    def median_p95(runs):
        vals = [r["meta"]["latency_ms"]["p95"] for r in runs
                if r["meta"]["latency_ms"]["p95"] is not None]
        return int(statistics.median(vals)) if vals else None

    def median_p50(runs):
        vals = [r["meta"]["latency_ms"]["p50"] for r in runs
                if r["meta"]["latency_ms"]["p50"] is not None]
        return int(statistics.median(vals)) if vals else None

    seq_report, con_report = median_report(seq_runs), median_report(con_runs)
    payload = {
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_urls": len(urls),
        "rounds": args.rounds,
        "workers": args.workers,
        "deadline_s": args.deadline,
        "urls": urls,
        "sequential": {
            "report_latency_ms_median": seq_report,
            "per_url_p50_ms": median_p50(seq_runs),
            "per_url_p95_ms": median_p95(seq_runs),
            "runs": seq_runs,
        },
        "concurrent": {
            "report_latency_ms_median": con_report,
            "per_url_p50_ms": median_p50(con_runs),
            "per_url_p95_ms": median_p95(con_runs),
            "runs": con_runs,
        },
        "speedup": (round(seq_report / con_report, 2) if con_report else None),
        "note": (
            "Each mode used a fresh pipeline so the verifier's 300 s TTL cache "
            "could not make the second mode look faster. Wall-clock latency "
            "depends on third-party API response times and the local network."
        ),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT_PATH}")
    print(f"sequential median report: {seq_report} ms")
    print(f"concurrent median report: {con_report} ms")
    print(f"speed-up: {payload['speedup']}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
