"""Figures for the PhishGuard-HDV dissertation and technical paper."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

NAVY = "#12233f"
BLUE = "#2f6feb"
LIGHT_BLUE = "#dce6f7"
GREEN = "#2e9e5b"
LIGHT_GREEN = "#dff3e6"
AMBER = "#d98b18"
LIGHT_AMBER = "#fdf0d5"
RED = "#c0392b"
LIGHT_RED = "#fbe3e0"
GREY = "#6b7280"
LIGHT_GREY = "#eef1f5"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.edgecolor": "#4b5563",
    "axes.labelcolor": "#111827",
    "text.color": "#111827",
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.08,
})


def _canvas(w=10, h=5.6):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return fig, ax


def _box(ax, x, y, w, h, text, fc=LIGHT_BLUE, ec=BLUE, size=8.5,
         bold=False, radius=1.8):
    patch = FancyBboxPatch((x, y), w, h,
                           boxstyle=f"round,pad=0.25,rounding_size={radius}",
                           linewidth=1.1, edgecolor=ec, facecolor=fc)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=size, fontweight="bold" if bold else "normal",
            wrap=True)
    return patch


def _arrow(ax, x1, y1, x2, y2, color=GREY, style="-|>", lw=1.3,
           connectionstyle="arc3,rad=0"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=12, linewidth=lw,
                                 color=color,
                                 connectionstyle=connectionstyle))


def theoretical_framework(path: Path) -> Path:
    fig, ax = _canvas(10, 6.2)
    ax.text(50, 96, "Evidence-aware URL verification for LLM output",
            ha="center", va="center", fontsize=12, fontweight="bold",
            color=NAVY)

    # Layer 1
    ax.add_patch(Rectangle((2, 70), 96, 20, facecolor=LIGHT_GREY,
                           edgecolor="none"))
    ax.text(4, 87.8, "LAYER 1  EVIDENCE ACQUISITION", fontsize=8.5,
            fontweight="bold", color=GREY)
    labels = [
        "Structural and\nlexical analysis",
        "DNS, WHOIS\nand RDAP",
        "HTTP probe of\nthe exact page",
        "Threat feeds\nand ML model",
    ]
    for i, label in enumerate(labels):
        _box(ax, 5 + i * 23.5, 72.5, 20, 11, label)

    # Layer 2
    ax.add_patch(Rectangle((2, 38), 96, 26, facecolor="#f7f9fc",
                           edgecolor="none"))
    ax.text(4, 61.8, "LAYER 2  EVIDENCE-AWARE DECISION", fontsize=8.5,
            fontweight="bold", color=GREY)
    _box(ax, 5, 46, 26, 11, "Existence gate\n(Stage A)", fc=LIGHT_BLUE)
    _box(ax, 36, 46, 26, 11, "Official allowlist\nand exact page", fc=LIGHT_AMBER,
         ec=AMBER)
    _box(ax, 67, 46, 28, 11, "Fusion and soft-failure\ncount (Stage B)",
         fc=LIGHT_GREEN, ec=GREEN)
    _box(ax, 26, 40, 48, 5.0, "Missing evidence is carried as uncertainty, never as a pass",
         fc="white", ec=GREY, size=8)

    # Layer 3
    ax.add_patch(Rectangle((2, 6), 96, 26, facecolor=LIGHT_GREY,
                           edgecolor="none"))
    ax.text(4, 29.8, "LAYER 3  EXPLANATION AND ACTION", fontsize=8.5,
            fontweight="bold", color=GREY)
    _box(ax, 5, 14, 23, 11, "Five user-facing\nverdicts")
    _box(ax, 31.5, 14, 23, 11, "Plain-language\nreason")
    _box(ax, 58, 14, 18, 11, "Evidence\nchecklist")
    _box(ax, 79, 14, 16, 11, "Audit log\n(SQLite)")

    for x in (15, 45.5, 76.5):
        _arrow(ax, x, 71.8, x, 58.0, color=BLUE)
    for x in (18, 49, 70, 87):
        _arrow(ax, x, 38.5, x, 26.2, color=BLUE)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def project_framework(path: Path) -> Path:
    fig, ax = _canvas(10.5, 5.4)
    ax.text(50, 95, "Agile, evidence-driven project framework",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)

    phases = [
        ("1. Requirements\nand literature", "Research questions,\nscope, sources"),
        ("2. Data\npreparation", "Corpus build,\ndomain-grouped split"),
        ("3. Stage A\nH1 detection", "DNS, WHOIS/RDAP,\nHTTP, reference"),
        ("4. Stage B\nverification", "H2 claims, feeds,\npage, scorer"),
        ("5. Integration\nand testing", "Streamlit, SQLite,\n207 tests"),
        ("6. Evaluation\nand writing", "Three test sets,\nregression harness"),
    ]
    width, height = 14.0, 17.0
    for i, (title, detail) in enumerate(phases):
        col = i % 3
        row = i // 3
        x = 4 + col * 32.0
        y = 58 - row * 34.0
        _box(ax, x, y, width, height, title, fc=LIGHT_BLUE, size=9, bold=True)
        ax.text(x + width / 2, y - 5.0, detail, ha="center", va="top",
                fontsize=7.6, color="#374151")
        if col < 2:
            _arrow(ax, x + width + 0.8, y + height / 2,
                   x + 31.0, y + height / 2, color=BLUE)
        elif row == 0:
            _arrow(ax, x + width / 2, y - 9.0, 4 + width / 2, 41.0,
                   color=BLUE, connectionstyle="arc3,rad=0.12")

    # Iteration loop
    _arrow(ax, 91, 24, 91, 80, color=AMBER, lw=1.4,
           connectionstyle="arc3,rad=-0.35")
    ax.text(96.5, 52, "iterate after every\nevaluation run", rotation=90,
            ha="center", va="center", fontsize=7.5, color=AMBER)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def system_architecture(path: Path) -> Path:
    fig, ax = _canvas(10.6, 6.4)
    ax.text(50, 97, "PhishGuard-HDV system architecture",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)

    # Row 1: input
    _box(ax, 3, 82, 19, 9, "User question\nor pasted URL", fc=LIGHT_GREY, ec=GREY)
    _box(ax, 26, 82, 18, 9, "Gemini LLM\n(one call)", fc=LIGHT_GREY, ec=GREY)
    _box(ax, 48, 82, 18, 9, "URL extractor\nand normaliser", fc=LIGHT_GREY, ec=GREY)
    _box(ax, 70, 82, 26, 9, "Streamlit interface\n(four pages)", fc=LIGHT_GREY, ec=GREY)
    _arrow(ax, 22.5, 86.5, 25.5, 86.5)
    _arrow(ax, 44.5, 86.5, 47.5, 86.5)
    _arrow(ax, 66.5, 86.5, 69.5, 86.5)

    # Stage A
    ax.add_patch(Rectangle((2, 55), 63, 20, facecolor="#f4f8ff",
                           edgecolor=BLUE, linewidth=1.0, linestyle="--"))
    ax.text(3.5, 72.5, "STAGE A  HALLUCINATION DETECTION (H1)", fontsize=8,
            fontweight="bold", color=BLUE)
    a_items = ["Structural\nrules", "DNS", "WHOIS /\nRDAP", "HTTP exact\npage", "Reference\nstore"]
    for i, item in enumerate(a_items):
        _box(ax, 4 + i * 12.1, 58, 10.8, 10, item, fc="white", size=7.6)

    # Stage A decision
    ax.add_patch(plt.Polygon([[74, 66], [83, 72], [92, 66], [83, 60]],
                             closed=True, facecolor=LIGHT_AMBER,
                             edgecolor=AMBER, linewidth=1.1))
    ax.text(83, 66, "Exists?", ha="center", va="center", fontsize=8.5,
            fontweight="bold")

    _arrow(ax, 65.2, 65, 73.5, 65.5, color=BLUE)
    _box(ax, 70, 45, 26, 9, "no: H1 hallucination\nuncertain: coverage gap",
         fc=LIGHT_RED, ec=RED, size=7.4)
    _arrow(ax, 83, 59.6, 83, 54.3, color=RED)
    ax.text(84.8, 57, "no / uncertain", fontsize=7.2, color=RED)

    # Stage B
    ax.add_patch(Rectangle((2, 22), 63, 22, facecolor="#f4fbf6",
                           edgecolor=GREEN, linewidth=1.0, linestyle="--"))
    ax.text(3.5, 41.5, "STAGE B  CLAIM AND THREAT VERIFICATION (H2)",
            fontsize=8, fontweight="bold", color=GREEN)
    b_items = ["Claim check\n(H2)", "30 URL\nfeatures", "Random Forest\n+ XGBoost",
               "Threat feeds\n+ page check", "Domain\nage"]
    for i, item in enumerate(b_items):
        _box(ax, 4 + i * 12.1, 25, 10.8, 12, item, fc="white", size=7.4)

    _arrow(ax, 83, 59.8, 83, 40.0, color=GREEN,
           connectionstyle="arc3,rad=0.0")
    ax.text(85, 51, "yes", fontsize=7.5, color=GREEN)

    # Fusion and output
    _box(ax, 70, 28, 27, 10, "Evidence fusion and\nsoft-failure count", fc=LIGHT_GREEN,
         ec=GREEN, size=8)
    _arrow(ax, 65.2, 33, 69.6, 33, color=GREEN)

    _box(ax, 70, 12, 27, 10, "Verdict + reason\n+ evidence checklist", fc=LIGHT_BLUE,
         ec=BLUE, size=8)
    _arrow(ax, 83.5, 27.8, 83.5, 22.4, color=GREEN)

    _box(ax, 4, 4, 28, 10, "SQLite audit log\nand history page", fc=LIGHT_GREY,
         ec=GREY, size=8)
    _box(ax, 37, 4, 26, 10, "Local Excel review\n(community reports)", fc=LIGHT_AMBER,
         ec=AMBER, size=8)
    _arrow(ax, 70, 15, 63.5, 9, color=GREY)
    _arrow(ax, 37, 9, 32.5, 9, color=GREY)
    _arrow(ax, 63.5, 15, 32.5, 9, color=GREY,
           connectionstyle="arc3,rad=0.18")
    ax.text(47, 17.2, "approved reports only", fontsize=7.2, color=AMBER)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def _decision_diamond(ax, x, y, w, h, text, fc=LIGHT_AMBER, ec=AMBER):
    ax.add_patch(plt.Polygon([[x, y + h / 2], [x + w / 2, y + h],
                              [x + w, y + h / 2], [x + w / 2, y]],
                             closed=True, facecolor=fc, edgecolor=ec,
                             linewidth=1.1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=8)


def stage_a_flow(path: Path) -> Path:
    fig, ax = _canvas(10.2, 6.0)
    ax.text(50, 96, "Stage A: existence verification workflow",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)

    _box(ax, 3, 80, 18, 8, "Input URL\n(normalised)", fc=LIGHT_GREY, ec=GREY)
    _box(ax, 25, 80, 20, 8, "Structural rules\nIP / reserved TLD", fc=LIGHT_BLUE)
    _box(ax, 49, 80, 18, 8, "DNS lookup\nA / AAAA", fc=LIGHT_BLUE)
    _box(ax, 71, 80, 25, 8, "WHOIS, then RDAP\nregistration record", fc=LIGHT_BLUE)
    for x in (21.5, 45.5, 67.5):
        _arrow(ax, x, 84, x + 3.0, 84, color=BLUE)

    _box(ax, 22, 62, 26, 9, "HTTP probe of the exact page\n(HEAD, then GET recheck)",
         fc=LIGHT_BLUE)
    _box(ax, 53, 62, 21, 9, "Reference store\nTF-IDF similarity", fc=LIGHT_BLUE)
    _box(ax, 77, 62, 19, 9, "Grounding score\n(weighted evidence)", fc=LIGHT_GREEN,
         ec=GREEN)
    _arrow(ax, 35, 79.5, 35, 71.3, color=BLUE)
    _arrow(ax, 63.5, 79.5, 63.5, 71.3, color=BLUE)
    _arrow(ax, 83.5, 79.5, 83.5, 71.3, color=BLUE)
    _arrow(ax, 48.2, 66.5, 52.7, 66.5, color=BLUE)
    _arrow(ax, 74.2, 66.5, 76.7, 66.5, color=BLUE)

    _decision_diamond(ax, 37, 41, 26, 12, "Conclusive\nevidence?")
    _arrow(ax, 87, 61.7, 63.5, 47.0, color=GREEN,
           connectionstyle="arc3,rad=0.15")

    _box(ax, 3, 38, 26, 9, "Uncertain: exists = False,\nuncertain = True", fc=LIGHT_AMBER,
         ec=AMBER, size=7.8)
    _arrow(ax, 37, 47, 29.5, 44, color=AMBER)
    ax.text(29.5, 48.5, "no / blocked", fontsize=7, color=AMBER)

    _box(ax, 70, 38, 27, 9, "Exists: continue to\nStage B or allowlist", fc=LIGHT_GREEN,
         ec=GREEN, size=7.8)
    _arrow(ax, 63.5, 47, 69.5, 44, color=GREEN)
    ax.text(65.2, 49.5, "yes", fontsize=7, color=GREEN)

    _decision_diamond(ax, 36, 18, 28, 12, "Exact page\n404 / 410?")
    _arrow(ax, 83, 37.7, 64.5, 26.0, color=GREEN,
           connectionstyle="arc3,rad=-0.12")
    _box(ax, 3, 14, 28, 9, "Hallucination\n(page removed or invented)", fc=LIGHT_RED,
         ec=RED, size=7.8)
    _arrow(ax, 36, 24, 31.3, 19.0, color=RED)
    ax.text(29.5, 26.5, "yes", fontsize=7, color=RED)
    _box(ax, 70, 14, 27, 9, "Page real or blocked:\nDNS/WHOIS still count", fc=LIGHT_GREEN,
         ec=GREEN, size=7.8)
    _arrow(ax, 64, 24, 69.5, 19.0, color=GREEN)
    ax.text(67.5, 26.5, "no / WAF", fontsize=7, color=GREEN)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def stage_b_flow(path: Path) -> Path:
    fig, ax = _canvas(10.2, 5.6)
    ax.text(50, 96, "Stage B: claim and threat verification with decision fusion",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)

    _box(ax, 2, 79, 17, 8, "Existing URL\n(Stage A pass)", fc=LIGHT_GREY, ec=GREY)
    _box(ax, 23, 79, 19, 8, "H2 claim check\n(sentence vs evidence)",
         fc=LIGHT_BLUE, size=7.8)
    _box(ax, 46, 79, 23, 8, "Risk score\n(30 features, RF+XGB)", fc=LIGHT_BLUE,
         size=7.8)
    _box(ax, 73, 79, 24, 8, "Score against\n0.50 threshold", fc=LIGHT_BLUE,
         size=7.8)
    for x in (19.5, 42.5, 69.5):
        _arrow(ax, x, 83, x + 3.0, 83, color=BLUE)

    _box(ax, 23, 59, 22, 9, "Threat intelligence\nVirusTotal, GSB,\nURLhaus, urlscan",
         fc=LIGHT_AMBER, ec=AMBER, size=7.6)
    _box(ax, 49, 59, 20, 9, "Login-page check\n(read-only HTML)", fc=LIGHT_AMBER,
         ec=AMBER, size=7.6)
    _box(ax, 73, 59, 24, 9, "Domain age\nWHOIS / RDAP /\nWhoisXML", fc=LIGHT_AMBER,
         ec=AMBER, size=7.6)
    _arrow(ax, 32.5, 78.5, 34.5, 68.3, color=BLUE)
    _arrow(ax, 59, 78.5, 59, 68.3, color=BLUE)
    _arrow(ax, 85, 78.5, 85, 68.3, color=BLUE)

    _box(ax, 22, 37, 56, 10, "Evidence fusion\nthreat score, risk score, coverage count",
         fc=LIGHT_GREEN, ec=GREEN, size=8)
    for x in (34, 59, 85):
        _arrow(ax, x, 58.5, x, 47.5, color=AMBER)
    _arrow(ax, 85, 58.5, 78.2, 45.0, color=AMBER,
           connectionstyle="arc3,rad=-0.1")

    _decision_diamond(ax, 35, 18, 30, 12, "Count hard and\nsoft failures")
    _arrow(ax, 50, 36.7, 50, 30.5, color=GREEN)
    _box(ax, 2, 14, 28, 10, "Positive feed match or\nsuspicious page -> Phishing",
         fc=LIGHT_RED, ec=RED, size=7.6)
    _box(ax, 36, 2, 28, 9, "One soft failure ->\nPossible phishing", fc=LIGHT_AMBER,
         ec=AMBER, size=7.6)
    _box(ax, 70, 14, 27, 10, "None, with enough proof ->\nNo phishing found\n(limited checks if not)",
         fc=LIGHT_GREEN, ec=GREEN, size=7.4)
    _arrow(ax, 35, 23.5, 29.5, 19.3, color=RED)
    _arrow(ax, 50, 18.2, 50, 11.5, color=AMBER)
    _arrow(ax, 64.5, 23.5, 70.0, 19.3, color=GREEN)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def realtime_execution(path: Path) -> Path:
    fig, ax = _canvas(10.6, 5.8)
    ax.text(50, 96, "Real-time execution model", ha="center", fontsize=12,
            fontweight="bold", color=NAVY)

    _box(ax, 2, 82, 18, 8, "Generated answer\nwith n indicators",
         fc=LIGHT_GREY, ec=GREY, size=7.8)
    _box(ax, 24, 82, 17, 8, "Extractor and\nnormaliser", fc=LIGHT_GREY,
         ec=GREY, size=7.8)
    _box(ax, 45, 82, 17, 8, "Deduplicated\njob queue", fc=LIGHT_GREY,
         ec=GREY, size=7.8)
    for x in (20.5, 41.5):
        _arrow(ax, x, 86, x + 3.0, 86)

    _box(ax, 66, 82, 32, 8, "TTL cache (300 s)\nreuse only within lifetime",
         fc=LIGHT_AMBER, ec=AMBER, size=7.6)
    _arrow(ax, 62.5, 86, 65.5, 86, color=AMBER)

    ax.add_patch(Rectangle((2, 48), 96, 26, facecolor="#f4f8ff",
                           edgecolor=BLUE, linewidth=1.0, linestyle="--"))
    ax.text(4, 71.5, "WORKER POOL  (default 6, one URL per worker)",
            fontsize=8, fontweight="bold", color=BLUE)
    for i in range(6):
        _box(ax, 4.5 + i * 15.5, 53, 13.5, 13,
             f"URL {i + 1}\nStage A \u2192 H2\n\u2192 Stage B",
             fc="white", size=6.9)
    _arrow(ax, 53.5, 81.5, 53.5, 74.8, color=BLUE)

    # deadline band
    ax.plot([2, 98], [44, 44], color=RED, linewidth=1.4, linestyle="--")
    ax.text(2, 40.8, "HARD DEADLINE  report returns even if workers are unfinished",
            fontsize=7.6, color=RED)

    _box(ax, 2, 24, 30, 11, "Result streamed through\non_result as each URL ends",
         fc=LIGHT_GREEN, ec=GREEN, size=7.8)
    _box(ax, 35, 24, 28, 11, "First verdict shown\nbefore the slowest check",
         fc=LIGHT_GREEN, ec=GREEN, size=7.8)
    _box(ax, 66, 24, 32, 11, "Deadline expired:\nSuspicious, coverage gap",
         fc=LIGHT_RED, ec=RED, size=7.8)
    _arrow(ax, 50, 47.7, 18, 35.6, color=GREEN,
           connectionstyle="arc3,rad=0.12")
    _arrow(ax, 50, 47.7, 49, 35.6, color=GREEN)
    _arrow(ax, 50, 47.7, 80, 35.6, color=RED,
           connectionstyle="arc3,rad=-0.12")

    _box(ax, 2, 6, 30, 10, "Audit log: latency, coverage,\ncompleted checks",
         fc=LIGHT_GREY, ec=GREY, size=7.6)
    _box(ax, 35, 6, 28, 10, "p50 / p95 per URL\nand per report",
         fc=LIGHT_GREY, ec=GREY, size=7.6)
    _arrow(ax, 17, 23.5, 17, 16.5, color=GREY)
    _arrow(ax, 49, 23.5, 49, 16.5, color=GREY)

    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def latency_chart(path: Path, data: dict) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.0),
                             gridspec_kw={"width_ratios": [1.0, 1.05]})
    seq = data["sequential"]
    con = data["concurrent"]

    ax = axes[0]
    names = ["Sequential", "Concurrent"]
    report = [seq["report_latency_ms_median"] / 1000.0,
              con["report_latency_ms_median"] / 1000.0]
    bars = ax.bar(names, report, color=[GREY, GREEN], width=0.55)
    for b, v in zip(bars, report):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.6, f"{v:.1f} s",
                ha="center", fontsize=9, fontweight="bold", color=NAVY)
    ax.set_ylabel("Median report latency (s)")
    ax.set_title("(a) Time to verify eight indicators", fontsize=9.5)
    ax.set_ylim(0, max(report) * 1.22)

    ax = axes[1]
    width = 0.36
    xs = [0, 1]
    p50 = [seq["per_url_p50_ms"] / 1000.0, con["per_url_p50_ms"] / 1000.0]
    p95 = [seq["per_url_p95_ms"] / 1000.0, con["per_url_p95_ms"] / 1000.0]
    ax.bar([x - width / 2 for x in xs], p50, width, label="p50", color=BLUE)
    ax.bar([x + width / 2 for x in xs], p95, width, label="p95", color=AMBER)
    for x, v in zip([x - width / 2 for x in xs], p50):
        ax.text(x, v + 0.25, f"{v:.1f}", ha="center", fontsize=8.4, color=NAVY)
    for x, v in zip([x + width / 2 for x in xs], p95):
        ax.text(x, v + 0.25, f"{v:.1f}", ha="center", fontsize=8.4, color=NAVY)
    ax.set_xticks(xs)
    ax.set_xticklabels(names)
    ax.set_ylabel("Per-indicator latency (s)")
    ax.set_title("(b) Per-indicator distribution", fontsize=9.5)
    ax.legend(frameon=False, fontsize=8.5)
    ax.set_ylim(0, max(p95) * 1.28)

    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def dataset_profile(path: Path) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(10.4, 4.3),
                             gridspec_kw={"width_ratios": [1.05, 1.0]})
    ax = axes[0]
    labels = ["Legitimate", "Phishing", "Hallucinated", "Misdescribed"]
    values = [134820, 85257, 200, 3]
    colors = [GREEN, RED, AMBER, GREY]
    bars = ax.bar(labels, values, color=colors, width=0.62)
    ax.set_ylabel("Number of rows")
    ax.set_title("(a) Processed corpus composition", fontsize=9.5)
    ax.set_yscale("log")
    ax.set_ylim(1, 400000)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value * 1.15,
                f"{value:,}", ha="center", va="bottom", fontsize=7.5)
    ax.tick_params(axis="x", labelsize=7.5)
    ax.grid(axis="y", alpha=0.25)

    ax = axes[1]
    splits = ["Training", "Validation", "Test"]
    legit = [94213, 20331, 20276]
    phish = [59841, 12681, 12735]
    other = [139 + 3, 30, 31]
    x = np.arange(len(splits))
    ax.bar(x, legit, 0.58, label="Legitimate", color=GREEN)
    ax.bar(x, phish, 0.58, bottom=legit, label="Phishing", color=RED)
    ax.bar(x, other, 0.58, bottom=np.array(legit) + np.array(phish),
           label="Other", color=AMBER)
    ax.set_xticks(x, splits)
    ax.set_ylabel("Number of rows")
    ax.set_title("(b) Domain-grouped partitions", fontsize=9.5)
    ax.legend(fontsize=7, frameon=False, loc="upper right")
    ax.grid(axis="y", alpha=0.25)
    for i, total in enumerate(np.array(legit) + np.array(phish) + np.array(other)):
        ax.text(i, total + 3500, f"{total:,}", ha="center", fontsize=7.5)

    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def benchmark_profile(path: Path, summary: dict, detection: dict) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(10.4, 4.1),
                             gridspec_kw={"width_ratios": [1.15, 0.85]})

    ax = axes[0]
    order = ["malaysian_banking", "global_brands", "ioc_request"]
    names = {"malaysian_banking": "Malaysian\nbanking",
             "global_brands": "Global\nbrands",
             "ioc_request": "Indicator\nrequests"}
    existing = [summary["by_category"][k]["exists"] for k in order]
    missing = [summary["by_category"][k]["nonexistent"] for k in order]
    ys = np.arange(len(order))[::-1]
    ax.barh(ys, existing, color=GREEN, height=0.55, label="Exists")
    ax.barh(ys, missing, left=existing, color=RED, height=0.55,
            label="Does not exist")
    for y, e, m in zip(ys, existing, missing):
        ax.text(e / 2, y, str(e), ha="center", va="center", fontsize=7.6,
                color="white", fontweight="bold")
        ax.text(e + m / 2, y, str(m), ha="center", va="center", fontsize=7.6,
                color="white", fontweight="bold")
        ax.text(e + m + 1.2, y, f"{m / (e + m) * 100:.0f}% fabricated",
                va="center", fontsize=7.4, color=GREY)
    ax.set_yticks(ys, [names[k] for k in order])
    ax.set_xlim(0, max(np.array(existing) + np.array(missing)) * 1.32)
    ax.set_xlabel("Indicators extracted from the model answers")
    ax.set_title("(a) Benchmark composition, 15 answers", fontsize=9.5)
    ax.legend(fontsize=7.6, frameon=False, loc="lower right")
    ax.grid(axis="x", alpha=0.25)

    ax = axes[1]
    cm = detection["confusion"]
    values = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    ax.imshow(values, cmap="Blues")
    labels = [["Correct: exists", "False accusation"],
              ["Missed fabrication", "Correct: fabricated"]]
    for i in range(2):
        for j in range(2):
            color = "white" if values[i, j] > values.max() / 2 else "#111827"
            ax.text(j, i - 0.13, f"{values[i, j]}", ha="center", va="center",
                    fontsize=16, fontweight="bold", color=color)
            ax.text(j, i + 0.22, labels[i][j], ha="center", va="center",
                    fontsize=6.9, color=color)
    ax.set_xticks([0, 1], ["Predicted\nexists", "Predicted\nfabricated"],
                  fontsize=8)
    ax.set_yticks([0, 1], ["Actually\nexists", "Actually\nfabricated"],
                  fontsize=8)
    ax.set_title("(b) H1 detection on 123 indicators", fontsize=9.5)

    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def claim_profile(path: Path, claims: dict) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(10.4, 3.9),
                             gridspec_kw={"width_ratios": [1.0, 0.8]})

    ax = axes[0]
    types = ["OFFICIAL", "THREAT", "ATTRIBUTION", "LOGIN"]
    display = ["Official", "Threat", "Attribution", "Login"]
    supported = [sum(1 for c in claims["claim_rows"]
                     if c["type"] == t and c["verdict"] == "supported")
                 for t in types]
    unsupported = [sum(1 for c in claims["claim_rows"]
                       if c["type"] == t and c["verdict"] == "unsupported")
                   for t in types]
    contradicted = [sum(1 for c in claims["claim_rows"]
                        if c["type"] == t and c["verdict"] == "contradicted")
                    for t in types]
    xs = np.arange(len(types))
    ax.bar(xs, supported, color=GREEN, width=0.55, label="Supported")
    ax.bar(xs, unsupported, bottom=supported, color=AMBER, width=0.55,
           label="Unsupported")
    ax.bar(xs, contradicted, bottom=np.array(supported) + np.array(unsupported),
           color=RED, width=0.55, label="Contradicted")
    for x, s, u in zip(xs, supported, unsupported):
        if s:
            ax.text(x, s / 2, str(s), ha="center", va="center", fontsize=7.6,
                    color="white", fontweight="bold")
        if u:
            ax.text(x, s + u / 2, str(u), ha="center", va="center",
                    fontsize=7.6, color="white", fontweight="bold")
    ax.set_xticks(xs, display)
    ax.set_ylabel("Claims detected")
    ax.set_title("(a) Claim type and verdict, 43 claims", fontsize=9.5)
    ax.legend(fontsize=7.5, frameon=False)
    ax.grid(axis="y", alpha=0.25)

    ax = axes[1]
    counts = claims["indicator_verdicts"]
    order = [("no_claim", "No checkable claim", GREY),
             ("unsupported", "Unsupported", AMBER),
             ("supported", "Supported", GREEN)]
    left = 0
    total = sum(counts.values())
    for key, label, color in order:
        val = counts.get(key, 0)
        ax.barh([0], [val], left=left, color=color, height=0.5,
                label=f"{label} ({val})")
        if val:
            ax.text(left + val / 2, 0, str(val), ha="center", va="center",
                    fontsize=8.4, color="white", fontweight="bold")
        left += val
    ax.set_xlim(0, total)
    ax.set_ylim(-0.6, 0.6)
    ax.set_yticks([])
    ax.set_xlabel("Indicators (n = 123)")
    ax.set_title("(b) Worst-case claim verdict per indicator", fontsize=9.5)
    ax.legend(fontsize=7.5, frameon=False, loc="upper center",
              bbox_to_anchor=(0.5, -0.28), ncol=1)

    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def results_chart(path: Path, metrics: dict) -> Path:
    names = ["PhiUSIIL\n(33,011)", "Malaysia hold-out\n(28)", "Regression\n(94)"]
    keys = ["phiusiil", "malaysia", "regression"]
    metric_specs = [("recall", "Phishing recall", BLUE),
                    ("specificity", "Legitimate passed", GREEN),
                    ("precision", "Precision", AMBER),
                    ("f1", "F1-score", NAVY)]
    x = np.arange(len(names))
    width = 0.19
    fig, ax = plt.subplots(figsize=(9.6, 4.5))
    for j, (key, label, color) in enumerate(metric_specs):
        vals = [metrics[k][key] * 100 for k in keys]
        bars = ax.bar(x + (j - 1.5) * width, vals, width, label=label,
                      color=color)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, val + 1.2,
                    f"{val:.0f}", ha="center", fontsize=6.8)
    ax.set_xticks(x, names)
    ax.set_ylim(0, 112)
    ax.set_ylabel("Percent (%)")
    ax.set_title("Machine-learning performance on the three evaluation sets",
                 fontsize=10)
    ax.legend(fontsize=7.2, ncol=4, frameon=False, loc="upper center",
              bbox_to_anchor=(0.5, -0.18))
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def confusion_matrix(path: Path, cm: dict) -> Path:
    values = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    fig, ax = plt.subplots(figsize=(5.4, 4.3))
    im = ax.imshow(values, cmap="Blues")
    labels = [["True negative", "False positive"],
              ["False negative", "True positive"]]
    for i in range(2):
        for j in range(2):
            color = "white" if values[i, j] > values.max() / 2 else "#111827"
            ax.text(j, i - 0.12, f"{values[i, j]:,}", ha="center",
                    va="center", fontsize=17, fontweight="bold", color=color)
            ax.text(j, i + 0.22, labels[i][j], ha="center", va="center",
                    fontsize=7.5, color=color)
    ax.set_xticks([0, 1], ["Predicted legit", "Predicted phishing"])
    ax.set_yticks([0, 1], ["Actual legit", "Actual phishing"])
    ax.set_title("Confusion matrix on the PhiUSIIL test set", fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path


def feature_importance(path: Path, importance_path: Path) -> Path:
    data = json.loads(importance_path.read_text(encoding="utf-8"))
    rows = data["features"][:15]
    names = [r["feature"].replace("_", " ") for r in rows][::-1]
    vals = [r["xgboost_shap_mean_abs"] for r in rows][::-1]
    fig, ax = plt.subplots(figsize=(8.6, 5.2))
    bars = ax.barh(names, vals, color=BLUE, height=0.62)
    ax.set_xlabel("Mean absolute XGBoost SHAP contribution")
    ax.set_title("Top 15 URL features by XGBoost SHAP importance", fontsize=10)
    for bar, val in zip(bars, vals):
        ax.text(val + max(vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.2f}", va="center", fontsize=7)
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=220)
    plt.close(fig)
    return path
