"""
eval_benchmark.py - H1 detection accuracy on the labelled LLM benchmark.

The benchmark CSV was labelled independently of the system under test: a
domain is "registered" only when two public DNS-over-HTTPS resolvers agree
that it exists. This script runs **Stage A only** over every indicator so the
referential detector is measured against that independent label. Stage B is
deliberately excluded: reputation cannot be part of an existence score.

Usage
-----
    python src/eval_benchmark.py stage-a
    python src/eval_benchmark.py claims

Outputs
-------
    docs/fyp/benchmark_detection.json   confusion matrix + rates
    docs/fyp/benchmark_detection.csv    per-indicator predictions
"""

from __future__ import annotations

import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hallucination_detector import HallucinationDetector  # noqa: E402

BENCH_CSV = ROOT / "data" / "llm_output" / "benchmark_urls.csv"
ANSWERS = ROOT / "data" / "llm_output" / "answers.jsonl"
OUT_JSON = ROOT / "docs" / "fyp" / "benchmark_detection.json"
OUT_CSV = ROOT / "docs" / "fyp" / "benchmark_detection.csv"

WORKERS = 8


def _truth(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _predict(detector: HallucinationDetector, url: str) -> dict:
    started = time.perf_counter()
    try:
        result = detector.analyze(url)
        exists = bool(result.exists)
        uncertain = bool(getattr(result, "uncertain", False))
        if uncertain:
            prediction = "uncertain"
        elif exists:
            prediction = "exists"
        else:
            prediction = "nonexistent"
        evidence = result.evidence or {}
        return {
            "prediction": prediction,
            "reason": result.reason,
            "grounding_score": float(getattr(result, "grounding_score", 0.0)),
            "has_dns": bool((evidence.get("dns") or {}).get("resolved")),
            "has_whois": bool((evidence.get("whois") or {}).get("registered")),
            "http_status": (evidence.get("liveness") or {}).get("status"),
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": None,
        }
    except Exception as exc:  # one failure must not sink the measurement
        return {
            "prediction": "uncertain",
            "reason": f"check failed: {type(exc).__name__}",
            "grounding_score": 0.0,
            "has_dns": False,
            "has_whois": False,
            "http_status": None,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": type(exc).__name__,
        }


def stage_a() -> dict:
    rows = list(csv.DictReader(BENCH_CSV.open(encoding="utf-8")))
    if not rows:
        raise SystemExit(f"no rows in {BENCH_CSV}")

    detector = HallucinationDetector()
    urls = [r["url"] for r in rows]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        predictions = list(pool.map(lambda u: _predict(detector, u), urls))

    out_rows = []
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "abstain": 0}
    by_category: dict = {}

    for row, pred in zip(rows, predictions):
        actual_exists = _truth(row["registered"])
        p = pred["prediction"]
        if p == "uncertain":
            counts["abstain"] += 1
            outcome = "abstain"
        elif p == "nonexistent":
            outcome = "fp" if actual_exists else "tp"
        else:  # exists
            outcome = "tn" if actual_exists else "fn"
        if outcome != "abstain":
            counts[outcome] += 1

        cat = by_category.setdefault(
            row["category"], {"total": 0, "tp": 0, "fp": 0, "tn": 0,
                              "fn": 0, "abstain": 0})
        cat["total"] += 1
        cat[outcome] += 1

        out_rows.append({
            "prompt_id": row["prompt_id"],
            "category": row["category"],
            "url": row["url"],
            "actual_registered": actual_exists,
            "actual_reserved_tld": _truth(row["reserved_tld"]),
            "prediction": p,
            "outcome": outcome,
            "latency_ms": pred["latency_ms"],
            "grounding_score": round(pred["grounding_score"], 4),
            "has_dns": pred["has_dns"],
            "has_whois": pred["has_whois"],
            "http_status": pred["http_status"],
            "error": pred["error"],
            "reason": pred["reason"],
        })

    tp, fp, tn, fn, abstain = (counts["tp"], counts["fp"], counts["tn"],
                               counts["fn"], counts["abstain"])
    conclusive = tp + fp + tn + fn
    metrics = {
        "n_indicators": len(out_rows),
        "n_nonexistent_truth": sum(1 for r in out_rows
                                   if not r["actual_registered"]),
        "n_existing_truth": sum(1 for r in out_rows if r["actual_registered"]),
        "confusion": counts,
        "h1_recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "h1_precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "existing_specificity": round(tn / (tn + fp), 4) if (tn + fp) else None,
        "accuracy_conclusive": round((tp + tn) / conclusive, 4)
        if conclusive else None,
        "abstention_rate": round(abstain / len(out_rows), 4),
        "false_hallucination_rate": round(fp / (tn + fp), 4) if (tn + fp) else None,
        "latency_ms": {
            "p50": _pct([r["latency_ms"] for r in out_rows], 50),
            "p95": _pct([r["latency_ms"] for r in out_rows], 95),
            "max": max(r["latency_ms"] for r in out_rows),
        },
        "by_category": by_category,
        "workers": WORKERS,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(out_rows[0]))
        writer.writeheader()
        writer.writerows(out_rows)
    OUT_JSON.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def _pct(values: list, p: float):
    if not values:
        return None
    values = sorted(values)
    idx = min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))
    return values[idx]


CLAIM_CONTROLS = [
    # (text, url, domain, exists, sources, page, expected (type, verdict))
    ("https://www.maybank2u.com.my is the official Maybank page.",
     "https://www.maybank2u.com.my", "www.maybank2u.com.my", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("OFFICIAL", "supported")),
    ("https://maybank2u-secure.top is the official Maybank login page.",
     "https://maybank2u-secure.top", "maybank2u-secure.top", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("OFFICIAL", "contradicted")),
    ("http://paypal-service-update.com is the official PayPal domain.",
     "http://paypal-service-update.com", "paypal-service-update.com", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("OFFICIAL", "contradicted")),
    ("Always verify you are on the official CIMB https://www.cimb.com.sg domain.",
     "https://www.cimb.com.sg", "www.cimb.com.sg", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("OFFICIAL", "unsupported")),
    ("http://evil-bank.top is a phishing page.",
     "http://evil-bank.top", "evil-bank.top", True,
     {"virustotal": {"status": "POSITIVE_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("THREAT", "supported")),
    ("http://pbebank-online-my.com is a phishing page.",
     "http://pbebank-online-my.com", "pbebank-online-my.com", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("THREAT", "unsupported")),
    ("According to VirusTotal, http://bad.top is phishing.",
     "http://bad.top", "bad.top", True,
     {"virustotal": {"status": "POSITIVE_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("ATTRIBUTION", "supported")),
    ("According to PhishTank, http://bad.top is phishing.",
     "http://bad.top", "bad.top", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("ATTRIBUTION", "unsupported")),
    ("https://login.example-bank.com is the login page.",
     "https://login.example-bank.com", "login.example-bank.com", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": True, "suspicious": False},
     ("LOGIN", "supported")),
    ("https://www.cimbclicks.com.my is the login page.",
     "https://www.cimbclicks.com.my", "www.cimbclicks.com.my", True,
     {"virustotal": {"status": "NO_MATCH"}},
     {"fetched": True, "has_password_field": False, "suspicious": False},
     ("LOGIN", "unsupported")),
]


def claim_controls() -> dict:
    """Constructed sentences with known expected verdicts.

    The real benchmark answers contain no positive contradiction, so the
    contradicted path of the claim checker would otherwise be untested by
    measurement. These cases are synthetic and are labelled as such.
    """
    from claim_verifier import assess_claims

    rows = []
    hits = 0
    for text, url, domain, exists, sources, page, (etype, everdict) in \
            CLAIM_CONTROLS:
        out = assess_claims(text, url, domain, exists=exists, sources=sources,
                            page=page)
        got = [(c["type"], c["verdict"]) for c in out.get("claims", [])]
        ok = (etype, everdict) in got
        hits += int(ok)
        rows.append({"text": text, "expected": f"{etype}/{everdict}",
                     "got": [f"{t}/{v}" for t, v in got], "correct": ok})
    return {"n": len(rows), "correct": hits,
            "accuracy": round(hits / len(rows), 4) if rows else None,
            "cases": rows}


def claims() -> dict:
    """Profile H2 claim checking over the real benchmark answers.

    This is a *behavioural* profile, not an accuracy score: the benchmark does
    not carry human labels for descriptions. It reports what the checker found
    so the reader can see how often each claim type was asserted.
    """
    from claim_verifier import assess_claims

    rows = list(csv.DictReader(BENCH_CSV.open(encoding="utf-8")))
    answers = {}
    for line in ANSWERS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("success"):
            answers[rec["prompt_id"]] = rec.get("text", "")

    type_counts: dict = {}
    verdict_counts: dict = {}
    indicator_verdicts: dict = {}
    claim_rows = []
    per_prompt = []
    for row in rows:
        text = answers.get(row["prompt_id"], "")
        exists = _truth(row["registered"])
        result = assess_claims(text, row["url"], row["domain"], exists=exists)
        for claim in result.get("claims", []):
            type_counts[claim["type"]] = type_counts.get(claim["type"], 0) + 1
            verdict_counts[claim["verdict"]] = (
                verdict_counts.get(claim["verdict"], 0) + 1)
            claim_rows.append({
                "prompt_id": row["prompt_id"],
                "url": row["url"],
                "type": claim["type"],
                "verdict": claim["verdict"],
                "detail": claim.get("detail", ""),
            })
        indicator_verdicts[result["verdict"]] = \
            indicator_verdicts.get(result["verdict"], 0) + 1
        per_prompt.append({
            "prompt_id": row["prompt_id"],
            "url": row["url"],
            "exists": exists,
            "verdict": result["verdict"],
            "n_claims": len(result.get("claims", [])),
        })

    summary = {
        "n_indicators": len(rows),
        "n_answers": len(answers),
        "claim_types": type_counts,
        "verdicts": verdict_counts,
        "indicator_verdicts": indicator_verdicts,
        "claim_rows": claim_rows,
        "n_no_claim": sum(1 for r in per_prompt if r["verdict"] == "no_claim"),
        "controls": claim_controls(),
        "per_indicator": per_prompt,
        "note": ("Claim verdicts here use benchmark existence labels and no "
                 "feed evidence, so THREAT and LOGIN claims are conservatively "
                 "unsupported. This is a detection profile, not an accuracy "
                 "score."),
    }
    out = ROOT / "docs" / "fyp" / "benchmark_claims.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def baseline() -> dict:
    """Single-stage comparator: score every benchmark indicator for phishing.

    A conventional detector has no existence gate, so it must return a
    maliciousness judgement for an indicator that may refer to nothing. This
    measures what that judgement would be on the 83 fabricated indicators.
    """
    from regression import score_classifier

    rows = list(csv.DictReader(BENCH_CSV.open(encoding="utf-8")))
    urls = [r["url"] for r in rows]
    scores = score_classifier(urls, None)

    out_rows = []
    banned = {"fabricated_flagged_phishing": 0, "fabricated_flagged_clean": 0,
              "existing_flagged_phishing": 0, "existing_flagged_clean": 0}
    for row, score in zip(rows, scores):
        exists = _truth(row["registered"])
        flagged = float(score) >= 0.5
        key = ("existing" if exists else "fabricated") + \
            ("_flagged_phishing" if flagged else "_flagged_clean")
        banned[key] += 1
        out_rows.append({"url": row["url"], "exists": exists,
                         "score": round(float(score), 4),
                         "flagged": flagged})

    summary = {
        "n": len(rows),
        **banned,
        "fabricated_receiving_a_threat_judgement": banned[
            "fabricated_flagged_phishing"] + banned[
            "fabricated_flagged_clean"],
        "note": ("A classifier without an existence stage must judge every "
                 "indicator, including the 83 that refer to nothing."),
        "per_indicator": out_rows,
    }
    (ROOT / "docs" / "fyp" / "benchmark_baseline.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "stage-a"
    if mode == "stage-a":
        print(json.dumps(stage_a(), indent=2))
    elif mode == "claims":
        print(json.dumps(claims(), indent=2))
    elif mode == "baseline":
        print(json.dumps(baseline(), indent=2))
    else:
        raise SystemExit("mode must be 'stage-a', 'claims', or 'baseline'")
