"""
realtime.py - concurrent verification with a hard deadline and latency accounting.

The sequential pipeline is correct but not interactive: a five-indicator answer
means five serial Stage A probes, then five serial verification rounds. The
title claims "real-time", so the work has to be concurrent AND the latency has
to be measured rather than asserted.

What this module adds
---------------------
    * fan-out     one worker per URL, so independent lookups overlap
    * deadline    the report returns by a wall-clock limit, always
    * streaming   `on_result` fires as each URL finishes, so the UI can render
                  a verdict before the slowest source answers
    * measurement per-URL latency, time-to-first-verdict, and how many URLs
                  completed inside the deadline

Deadline semantics (deliberately conservative)
----------------------------------------------
A URL that does not finish in time is NOT reported as clean. It is returned
with final_label="Suspicious", deadline_exceeded=True and a reason that says
the verification was incomplete. This follows the project rule that a missing
check must never be read as a pass, while keeping the honest distinction that
"incomplete" is a coverage failure, not evidence of phishing.

Thread safety
-------------
`analyze_url` is stateless with respect to the pipeline instance; the only
shared mutable state is `VerificationEngine._cache` (plain dict reads/writes,
atomic under CPython) and the reference store (read-only queries). Classifier
inference is read-only. Workers are therefore safe to share one pipeline.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("phishguard.realtime")

# Defaults chosen to be defensible in the report, not tuned to a benchmark.
DEFAULT_WORKERS = 6
DEFAULT_DEADLINE_S = 45.0


def _deadline_result(url: str, elapsed_ms: int, error: Optional[str] = None) -> Dict:
    """A result for a URL we could not finish. Never a clean verdict."""
    why = ("the per-report deadline expired before this URL was verified"
           if error is None else f"the check failed: {error}")
    return {
        "url": url,
        "domain": "",
        "stage_reached": None,
        "exists": None,
        "final_label": "Suspicious",
        "deadline_exceeded": error is None,
        "error": error,
        "latency_ms": elapsed_ms,
        "reason": (f"Verification incomplete: {why}. This is a coverage "
                   f"failure, not evidence of phishing - the URL is not "
                   f"reported as clean because a check did not finish."),
        "claim_verdict": None,
    }


def verify_many(
    pipeline,
    urls: List[str],
    claim_text: Optional[str] = None,
    *,
    max_workers: int = DEFAULT_WORKERS,
    deadline_s: float = DEFAULT_DEADLINE_S,
    on_result: Optional[Callable[[Dict], None]] = None,
    **analyze_kwargs,
) -> Dict:
    """Verify many URLs concurrently and return every verdict by the deadline.

    Returns:
        {
          "results": [result, ...],          # input order, never partial
          "meta": {
             "n_urls", "n_completed", "n_deadline_exceeded", "n_failed",
             "deadline_s", "max_workers",
             "report_latency_ms", "time_to_first_verdict_ms",
             "latency_ms": {"p50", "p95", "max"},
          }
        }
    """
    started = time.perf_counter()
    unique = list(dict.fromkeys(u for u in urls if str(u or "").strip()))
    if not unique:
        return {"results": [], "meta": {
            "n_urls": 0, "n_completed": 0, "n_deadline_exceeded": 0,
            "n_failed": 0, "deadline_s": deadline_s, "max_workers": max_workers,
            "report_latency_ms": 0, "time_to_first_verdict_ms": None,
            "latency_ms": {"p50": None, "p95": None, "max": None},
        }}

    results: Dict[str, Dict] = {}
    order: Dict[str, int] = {u: i for i, u in enumerate(unique)}
    first_verdict_ms: Optional[int] = None
    n_exceeded = 0
    n_failed = 0

    def run(url: str) -> Dict:
        t0 = time.perf_counter()
        try:
            res = pipeline.analyze_url(
                url, claim_text=claim_text, **analyze_kwargs)
            res["latency_ms"] = int((time.perf_counter() - t0) * 1000)
            res.setdefault("deadline_exceeded", False)
            return res
        except Exception as exc:  # one bad URL must not sink the report
            logger.exception("verification failed for %s", url)
            return _deadline_result(
                url, int((time.perf_counter() - t0) * 1000),
                error=type(exc).__name__)

    workers = max(1, min(int(max_workers), len(unique)))
    pool = ThreadPoolExecutor(max_workers=workers,
                              thread_name_prefix="verify")
    futures = {pool.submit(run, url): url for url in unique}

    try:
        for future in as_completed(futures, timeout=deadline_s):
            url = futures[future]
            res = future.result()
            results[url] = res
            if res.get("deadline_exceeded"):
                n_exceeded += 1
            if res.get("error"):
                n_failed += 1
            if first_verdict_ms is None:
                first_verdict_ms = int((time.perf_counter() - started) * 1000)
            if on_result is not None:
                try:
                    on_result(res)
                except Exception:  # a UI callback must not break verification
                    logger.exception("on_result callback failed")
    except TimeoutError:
        # `as_completed` raises the builtin TimeoutError on deadline expiry.
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Any URL with no result hit the deadline. Report it honestly.
    for url in unique:
        if url not in results:
            n_exceeded += 1
            res = _deadline_result(
                url, int((time.perf_counter() - started) * 1000))
            results[url] = res
            if on_result is not None:
                try:
                    on_result(res)
                except Exception:
                    logger.exception("on_result callback failed")

    ordered = [results[u] for u in sorted(results, key=lambda u: order[u])]
    latencies = sorted(int(r.get("latency_ms") or 0) for r in ordered)
    report_ms = int((time.perf_counter() - started) * 1000)

    return {
        "results": ordered,
        "meta": {
            "n_urls": len(ordered),
            "n_completed": sum(1 for r in ordered if not r.get("deadline_exceeded")
                               and not r.get("error")),
            "n_deadline_exceeded": n_exceeded,
            "n_failed": n_failed,
            "deadline_s": deadline_s,
            "max_workers": workers,
            "report_latency_ms": report_ms,
            "time_to_first_verdict_ms": first_verdict_ms,
            "latency_ms": {
                "p50": _percentile(latencies, 50),
                "p95": _percentile(latencies, 95),
                "max": latencies[-1] if latencies else None,
            },
        },
    }


def _percentile(sorted_values: List[int], p: float) -> Optional[int]:
    if not sorted_values:
        return None
    idx = min(len(sorted_values) - 1,
              int(round(p / 100 * (len(sorted_values) - 1))))
    return sorted_values[idx]
