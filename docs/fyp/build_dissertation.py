"""Build the PhishGuard-HDV dissertation DOCX and PDF.

Run from the project root:
    python docs/fyp/build_dissertation.py

The script generates the figures, assembles the document in the UTP FYP
format, updates the table of contents and caption fields in Microsoft Word,
exports a PDF, and prints the page counts.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FYP = Path(__file__).resolve().parent
sys.path.insert(0, str(FYP))

import fyp_figures as figs
from fyp_style import (add_footer_page_number, add_section_break,
                       finalize_with_word, page_break, set_page_number_format,
                       setup_document)
import fyp_content as C

FIG_DIR = FYP / "figures"
OUT_DOCX = FYP / "PhishGuard_HDV_Dissertation.docx"
OUT_PDF = FYP / "PhishGuard_HDV_Dissertation.pdf"


def make_figures():
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    figs.theoretical_framework(FIG_DIR / "figure_2_1_theoretical_framework.png")
    figs.project_framework(FIG_DIR / "figure_3_1_project_framework.png")
    figs.system_architecture(FIG_DIR / "figure_3_2_system_architecture.png")
    figs.stage_a_flow(FIG_DIR / "figure_3_3_stage_a_flow.png")
    figs.stage_b_flow(FIG_DIR / "figure_3_4_stage_b_flow.png")
    figs.realtime_execution(FIG_DIR / "figure_3_5_realtime_execution.png")
    detection = json.loads(
        (FYP / "benchmark_detection.json").read_text(encoding="utf-8"))
    claims = json.loads(
        (FYP / "benchmark_claims.json").read_text(encoding="utf-8"))
    figs.benchmark_profile(FIG_DIR / "figure_4_1_benchmark_profile.png",
                           C.BENCHMARK_SUMMARY, detection)
    figs.claim_profile(FIG_DIR / "figure_4_2_claim_profile.png", claims)
    figs.latency_chart(FIG_DIR / "figure_4_3_latency.png",
                       json.loads((FYP / "realtime_metrics.json")
                                  .read_text(encoding="utf-8")))
    figs.feature_importance(
        FIG_DIR / "figure_4_4_feature_importance.png",
        ROOT / "models" / "feature_importance.json")


def build():
    doc = setup_document()

    # ---- Section 1: title page and front matter -------------------------
    # The title page is the first page of the section but its footer is
    # suppressed, so it counts as page i without showing a number. The next
    # page, the certification, is numbered ii.
    C.title_page(doc, C.META)
    page_break(doc)

    sec_front = doc.sections[0]
    set_page_number_format(sec_front, "lowerRoman", 1)
    add_footer_page_number(sec_front, hide_first=True)

    C.certification_approval(doc, C.META)
    page_break(doc)
    C.certification_originality(doc, C.META)
    page_break(doc)
    C.abstract(doc)
    page_break(doc)
    C.acknowledgements(doc)
    page_break(doc)
    C.table_of_contents(doc)
    page_break(doc)
    C.list_of_figures(doc)
    page_break(doc)
    C.list_of_tables(doc)
    page_break(doc)
    C.abbreviations(doc)

    # ---- Section 3: main text and appendices (arabic) -------------------
    sec_main = add_section_break(doc)
    set_page_number_format(sec_main, "decimal", 1)
    add_footer_page_number(sec_main)

    C.chapter1(doc, first=True)
    C.chapter2(doc, FIG_DIR)
    C.chapter3(doc, FIG_DIR)
    C.chapter4(doc, FIG_DIR)
    C.chapter5(doc)
    C.references(doc)
    C.appendices(doc, FIG_DIR, C.META)

    doc.save(OUT_DOCX)
    return OUT_DOCX


def main():
    make_figures()
    build()
    print(f"saved {OUT_DOCX}")
    info = finalize_with_word(OUT_DOCX, OUT_PDF)
    print(json.dumps(info, indent=2))
    print(f"saved {OUT_PDF}")


if __name__ == "__main__":
    main()
