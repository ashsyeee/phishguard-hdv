"""Concurrent verification: overlap, deadline honesty, latency accounting."""

import time

import pytest

from realtime import verify_many


class FakePipeline:
    """Stand-in pipeline with controllable per-URL delay and outcome."""

    def __init__(self, delays=None, label="Likely Safe", raise_for=()):
        self.delays = delays or {}
        self.label = label
        self.raise_for = set(raise_for)
        self.calls = []

    def analyze_url(self, url, claim_text=None, **kwargs):
        self.calls.append(url)
        time.sleep(self.delays.get(url, 0.05))
        if url in self.raise_for:
            raise RuntimeError("boom")
        return {
            "url": url,
            "domain": url.split("//")[-1].split("/")[0],
            "stage_reached": "B",
            "exists": True,
            "final_label": self.label,
            "reason": "fake",
        }


def test_all_urls_are_verified_and_returned_in_input_order():
    pipe = FakePipeline()
    out = verify_many(pipe, ["https://b.top", "https://a.top", "https://c.top"])
    assert [r["url"] for r in out["results"]] == \
        ["https://b.top", "https://a.top", "https://c.top"]
    assert out["meta"]["n_completed"] == 3


def test_duplicate_urls_are_verified_once():
    pipe = FakePipeline()
    verify_many(pipe, ["https://a.top", "https://a.top", "https://b.top"])
    assert pipe.calls.count("https://a.top") == 1


def test_checks_overlap_instead_of_running_serially():
    urls = [f"https://{i}.top" for i in range(4)]
    pipe = FakePipeline(delays={u: 0.4 for u in urls})
    started = time.perf_counter()
    verify_many(pipe, urls, max_workers=4)
    elapsed = time.perf_counter() - started
    # Serial would be >= 1.6 s; four workers should finish far sooner.
    assert elapsed < 1.2


def test_deadline_returns_and_flags_incomplete_urls():
    urls = ["https://slow.top", "https://fast.top"]
    pipe = FakePipeline(delays={"https://slow.top": 3.0})
    started = time.perf_counter()
    out = verify_many(pipe, urls, deadline_s=0.4, max_workers=2)
    elapsed = time.perf_counter() - started

    assert elapsed < 1.5
    slow = next(r for r in out["results"] if r["url"] == "https://slow.top")
    assert slow["deadline_exceeded"] is True
    # A missing check is never a clean verdict.
    assert slow["final_label"] == "Suspicious"
    assert "not evidence of phishing" in slow["reason"]
    assert out["meta"]["n_deadline_exceeded"] == 1


def test_a_raising_url_does_not_sink_the_report():
    pipe = FakePipeline(raise_for={"https://bad.top"})
    out = verify_many(pipe, ["https://bad.top", "https://ok.top"])
    bad = next(r for r in out["results"] if r["url"] == "https://bad.top")
    ok = next(r for r in out["results"] if r["url"] == "https://ok.top")
    assert bad["error"] == "RuntimeError"
    assert bad["final_label"] == "Suspicious"
    assert ok["final_label"] == "Likely Safe"
    assert out["meta"]["n_failed"] == 1


def test_latency_meta_is_populated():
    out = verify_many(FakePipeline(), ["https://a.top", "https://b.top"])
    meta = out["meta"]
    assert meta["report_latency_ms"] is not None
    assert meta["time_to_first_verdict_ms"] is not None
    assert meta["latency_ms"]["p50"] is not None
    assert meta["latency_ms"]["p95"] is not None


def test_on_result_streams_each_verdict():
    seen = []
    verify_many(FakePipeline(), ["https://a.top", "https://b.top"],
                on_result=seen.append)
    assert len(seen) == 2
    assert {r["url"] for r in seen} == {"https://a.top", "https://b.top"}


def test_claim_text_is_forwarded_to_every_url():
    captured = {}

    class Recorder(FakePipeline):
        def analyze_url(self, url, claim_text=None, **kwargs):
            captured[url] = claim_text
            return super().analyze_url(url, claim_text=claim_text, **kwargs)

    verify_many(Recorder(), ["https://a.top"], claim_text="the whole answer")
    assert captured["https://a.top"] == "the whole answer"


def test_empty_input_is_safe():
    out = verify_many(FakePipeline(), [])
    assert out["results"] == []
    assert out["meta"]["n_urls"] == 0
