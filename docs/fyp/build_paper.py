"""Build the technical paper (DOCX and PDF).

Formatting follows the UTP FYP Guidelines 2024: one column, Times New Roman
11, 1.5 line spacing, 1-inch margins, abstract under 300 words, six keywords,
IEEE numeric references, at most six pages.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FYP = Path(__file__).resolve().parent
sys.path.insert(0, str(FYP))

from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Cm, Pt, RGBColor

from fyp_style import (add_figure, add_footer_page_number, add_par, add_table,
                       finalize_with_word, set_page_number_format,
                       setup_document)
import fyp_content as C

OUT_DOCX = FYP / "PhishGuard_HDV_Technical_Paper.docx"
OUT_PDF = FYP / "PhishGuard_HDV_Technical_Paper.pdf"
FIG_DIR = FYP / "figures"

CENTER = WD_ALIGN_PARAGRAPH.CENTER
TITLE = ("Real-Time Hallucination Detection and Verification of LLM-Generated "
         "Phishing Threat Intelligence")


def heading(doc, text):
    p = doc.add_heading(text, level=1)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.5
    for run in p.runs:
        run.font.name = "Times New Roman"
        run.font.size = Pt(11)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0, 0, 0)
    return p


def body(doc, text):
    return add_par(doc, text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11,
                   space_after=12)


def sub(doc, text):
    return add_par(doc, text, bold=True, size=11, space_before=4,
                   space_after=3)


def build():
    doc = setup_document(left_margin_cm=2.54, body_size=11,
                         line_spacing=1.5)
    section = doc.sections[0]
    section.top_margin = Cm(2.54)
    section.bottom_margin = Cm(2.54)
    section.right_margin = Cm(2.54)
    set_page_number_format(section, "decimal", 1)
    add_footer_page_number(section)

    # ---- Title block ----------------------------------------------------
    add_par(doc, TITLE, bold=True, size=14, align=CENTER, line_spacing=1.5,
            space_before=0, space_after=8)
    add_par(doc, C.META["student"], bold=True, size=11, align=CENTER,
            space_after=0)
    add_par(doc, f"Student ID: {C.META['student_id']}", size=11, align=CENTER,
            space_after=0)
    add_par(doc, f"Supervisor: {C.META['supervisor']}", size=11,
            align=CENTER, space_after=0)
    add_par(doc, "Department of Computer and Information Sciences", size=11,
            align=CENTER, space_after=0)
    add_par(doc, "Universiti Teknologi PETRONAS, Perak, Malaysia", size=11,
            align=CENTER, space_after=10)

    # ---- Abstract -------------------------------------------------------
    add_par(doc, "Abstract", bold=True, size=11, align=CENTER,
            space_after=4)
    add_par(doc,
         "Large language models (LLMs) are used to summarise phishing "
         "campaigns, yet they can present invented uniform resource locators "
         "(URLs) with the same fluency as genuine ones. Phishing detectors "
         "assume that the URL exists and cannot answer the prior question of "
         "whether it does. This paper presents a real-time framework for two "
         "forms of hallucination: referential hallucination, in which an "
         "indicator refers to nothing, and descriptive hallucination, in which "
         "a genuine indicator is misdescribed. Stage A settles existence by "
         "consensus between two public DNS-over-HTTPS resolvers, supported by "
         "registration records and a reference store, and returns exists, "
         "hallucinated, or uncertain. Stage B checks the claims made about each "
         "surviving indicator, then combines configured threat-intelligence "
         "sources, a read-only page inspection, and an internal risk scorer. "
         "Missing evidence is reported as a coverage gap, never as safety. On "
         "123 indicators extracted from 15 real model answers, 83 of which did "
         "not exist, the existence stage identified every hallucinated indicator "
         "and accepted every existing one, with a median of 1.8 s and a 95th "
         "percentile of 8.2 s per indicator. A single-stage classifier judged "
         "all 83 hallucinated indicators and reported 45 of them as not "
         "phishing. Concurrent verification reduced the time for eight "
         "indicators from 52.1 s to 14.3 s without changing any verdict. The "
         "accuracy figure is partly circular, because the labels and the "
         "detector share public DNS, and the paper states this limitation.",
         align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, line_spacing=1.0,
         space_after=8)
    add_par(doc, "Keywords: DNS-over-HTTPS; existence checking; claim "
                 "checking; URL reputation; explainable security; ensemble "
                 "classifier", size=11,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=10)

    # ---- 1 Introduction -------------------------------------------------
    heading(doc, "1. Introduction")
    body(doc,
         "Hallucination, the generation of fluent content that is not grounded "
         "in evidence, is a documented property of large language models "
         "[1], [2]. Attribution research shows that generated citations are "
         "frequently unsupported or hallucinated [3], [4], and that commercial "
         "tools built on these models are not immune [5]. In security work the "
         "consequence is specific. An analyst who asks a model for current "
         "phishing indicators may receive domains that were never registered. "
         "Such a domain is harmless only until a third party registers it, at "
         "which point the invented link becomes a real and hostile one.")
    body(doc,
         "Phishing remains a leading initial access vector. The Anti-Phishing "
         "Working Group reports a large and persistent volume of attacks [6], "
         "the FBI records phishing among the most reported crimes [7], and "
         "CyberSecurity Malaysia documents banking and e-commerce fraud as "
         "principal targets in Malaysia [8]. A hostile link reported as safe "
         "is therefore far more costly than a cautious false alarm.")
    body(doc,
         "Existing detectors assume that the URL can be examined. Lexical and "
         "content-based classifiers are trained on URLs that exist [9], [10], "
         "and a hallucinated URL cannot be fetched, so such a detector either "
         "fails or treats the missing page as benign. Hallucination research "
         "addresses generated text in general and rarely considers the "
         "existence of named resources [1]. This paper combines the two "
         "concerns. It treats existence as the first question, checks the "
         "descriptions of the indicators that survive, and reports every "
         "verdict with the coverage behind it.")

    # ---- 2 Related Work -------------------------------------------------
    heading(doc, "2. Related Work")
    body(doc,
         "Surveys of hallucination distinguish intrinsic errors, which contradict "
         "a source, from extrinsic errors, which cannot be checked against one "
         "[1], [2]. Detection methods include uncertainty estimation [11], [12], "
         "sampling-based consistency [13], and decomposition into atomic facts "
         "checked against a knowledge source [14]. These methods observe the "
         "model or a corpus. None establishes that a named domain resolves in "
         "the public name system, which is the question that matters for "
         "hallucinated indicators.")
    body(doc,
         "Registration and naming data provide that evidence. WHOIS [15] and the "
         "Registration Data Access Protocol [16] report whether a domain is "
         "registered, and the Domain Name System reports whether it resolves. "
         "Reserved top-level names can never resolve in the public system "
         "[17]. DNS queried over HTTPS [18] allows a resolver to be consulted "
         "without depending on the local network. Threat-intelligence services "
         "such as VirusTotal [19], Google Safe Browsing [20], URLhaus [21], and "
         "urlscan.io [22] provide positive observations. A positive match is "
         "precise, but a negative result means only that a URL was not observed, "
         "which is not proof of safety.")

    # ---- 3 Method -------------------------------------------------------
    heading(doc, "3. Method")
    sub(doc, "3.1 Architecture")
    body(doc,
         "The system has a presentation layer, an orchestration layer, two "
         "verification stages, an evidence layer, and a persistence layer. "
         "Indicators are extracted from an answer, normalised, and routed "
         "through Stage A. Only indicators that exist continue to Stage B. "
         "Every verdict is stored in SQLite with its evidence, coverage, and "
         "timestamp. Figure 1 shows the architecture.")
    add_figure(doc, FIG_DIR / "figure_3_2_system_architecture.png",
               "Figure 1: System architecture", width_cm=12.0)

    sub(doc, "3.2 Stage A: referential hallucination")
    body(doc,
         "Stage A answers whether an indicator refers to an existing resource. "
         "Structural rules reject unsupported schemes, embedded credentials, "
         "IP-literal hosts, and reserved names. Existence is then decided by "
         "consensus between two public resolvers reached over HTTPS, Google and "
         "Cloudflare. If both report that the name does not exist, the "
         "indicator is hallucinated. The operating system resolver is used only "
         "when both public resolvers are unreachable. Registration is checked "
         "through WHOIS and RDAP, and a probe of the exact page distinguishes a "
         "missing page from a site that merely lacks the path.")
    body(doc,
         "The local resolver is not a neutral witness. In the evaluation "
         "environment, two blocked phishing domains resolved to a block-page "
         "address when queried locally, while both public resolvers returned "
         "NXDOMAIN. A single-resolver check therefore reported blocked domains "
         "as existing. The consensus rule removes this error. A single public "
         "negative answer is not enough to accuse a name of hallucination when the "
         "local resolver answers positively.")

    sub(doc, "3.3 Descriptive hallucination: claim checking")
    body(doc,
         "Each indicator is linked to the sentences that mention it. A claim is "
         "classed as official (the indicator is the genuine site of a brand), "
         "threat (the indicator is phishing or malicious), attribution (a named "
         "source reported it), or login (the indicator is a login page). Each "
         "claim is checked against the evidence. Official claims are checked "
         "against a curated list of brand domains. A claim is contradicted only "
         "when the brand is fused into a compound host the brand does not own, "
         "such as paypal-service-update.com. Absence from the list yields "
         "unsupported, because the list is not exhaustive and a genuine regional "
         "domain must not be refuted by omission. Threat and attribution claims "
         "are supported only by a feed match.")

    sub(doc, "3.4 Stage B and real-time execution")
    body(doc,
         "Stage B combines the configured threat sources, a read-only page "
         "inspection that examines the form action, redirects, and brand "
         "conflicts, and an internal risk scorer. The scorer is a Random Forest "
         "and XGBoost ensemble over 30 lexical features [23], [24], with SHAP "
         "used for explanation [25]. It is an implementation component validated "
         "separately; it does not decide existence. A source whose credential is "
         "absent is disabled and excluded from the coverage denominator, and a "
         "source that fails is recorded as a gap. A clean verdict requires "
         "coverage; otherwise the result is reported as no phishing found with "
         "limited checks.")
    body(doc,
         "Real-time verification is interactive per-indicator verification. "
         "Indicators are checked concurrently with a deadline. Each verdict is "
         "streamed when ready, and an unfinished check is never labelled clean. "
         "Results are cached for 300 seconds and the cache is disclosed.")

    # ---- 4 Evaluation ---------------------------------------------------
    heading(doc, "4. Evaluation")
    sub(doc, "4.1 Benchmark of real model output")
    body(doc,
         "Forty threat-intelligence prompts were written across six categories. "
         "The deployed model's free tier allowed fifteen answers, covering three "
         "categories: Malaysian banking, global brands, and indicator requests. "
         "The answers contained 123 unique indicators across 115 domains. "
         "Eighty-three (67.5 per cent) did not resolve, and fourteen of the "
         "fifteen answers contained at least one hallucinated indicator. Labels "
         "were assigned by Google and Cloudflare consensus. A third provider, "
         "AdGuard, which the detector does not use, agreed with all 123 labels. "
         "The sample is small and covers one model on one day, so the rate "
         "describes this prompt condition only.")

    sub(doc, "4.2 Referential detection (H1)")
    body(doc,
         "Stage A classified all 123 indicators without access to the labels. "
         "It identified all 83 hallucinated indicators and accepted all 40 "
         "existing ones, with no abstentions. Table 1 reports the result. The "
         "perfect score is consistent with the label construct but is not an "
         "independent measure of truth, because both use public DNS. The "
         "non-circular evidence is the earlier single-resolver configuration, "
         "which missed two blocked domains and scored 81 of 83 (recall 0.9759). "
         "The consensus rule was introduced in response to that failure.")
    add_par(doc, "Table 1: Measured results on the benchmark and the scorer",
            align=CENTER, size=10, space_after=4)
    add_table(doc, ["Measure", "Result", "Condition"],
              [("H1 recall / precision", "1.0000 / 1.0000",
                "123 indicators; DoH consensus"),
               ("Single-resolver recall (before fix)", "0.9759",
                "81 of 83 hallucinated detected"),
               ("Stage A latency p50 / p95", "1.79 s / 8.24 s",
                "8 workers, per indicator"),
               ("Single-stage: hallucinated judged clean", "45 of 83",
                "Same scorer, no existence stage"),
               ("H2 claims: supported / unsupported / contradicted",
                "8 / 35 / 0", "43 claims on 33 indicators"),
               ("Controlled claim cases correct", "10 of 10",
                "Constructed, labelled as synthetic"),
               ("Eight indicators: sequential / concurrent", "52.1 s / 14.3 s",
                "3.64 speed-up, identical verdicts")],
              font_size=9, widths=[6.2, 3.6, 5.6], first_col_bold=False)
    add_par(doc, "", space_after=4)

    sub(doc, "4.3 Descriptive verification (H2)")
    body(doc,
         "Of the 123 indicators, 33 carried 43 checkable claims. Eight official "
         "claims named genuine brand domains and were supported. The 35 threat "
         "and attribution claims were unsupported, because no feed matched them, "
         "and none was contradicted. Ninety indicators made no checkable claim. "
         "The result shows that the checker operates and that its default under "
         "missing evidence is a gap rather than a pass. Recall and precision for "
         "H2 are not measured: the sample has no independently labelled false "
         "description of a genuine domain. A first version of the official check "
         "contradicted any official claim whose domain was absent from the list. "
         "That produced false contradictions for a genuine single sign-on host, "
         "and the rule was narrowed as described in Section 3.3.")

    sub(doc, "4.4 Real-time behaviour")
    body(doc,
         "Stage A latency is heavy-tailed. The median is 1.79 s, while the 95th "
         "percentile is 8.24 s because registration lookups can be slow. For a "
         "report of eight indicators, concurrent verification completed in 14.3 "
         "s against 52.1 s sequentially, a speed-up of 3.64 times. Time to the "
         "first verdict fell from 7.8 s to between 5.4 and 5.7 s. Both modes "
         "produced identical verdicts.")

    sub(doc, "4.5 Comparison and component validation")
    body(doc,
         "A single-stage classifier has no existence question. Applied to the "
         "same 123 indicators, it judged 38 of the 83 hallucinated indicators as "
         "phishing and 45 as not phishing, and it flagged three of 40 existing "
         "indicators. The two-stage system reported no hallucinated indicator as "
         "clean. Against manual verification, the comparison is analytical: a "
         "person performs the same checks indicator by indicator, and a timed "
         "human baseline was not collected. On the PhiUSIIL test partition the "
         "scorer reached an accuracy of 0.9048 and an AUC of 0.9981, with one "
         "false positive in 20,276 legitimate URLs. On a Malaysian hold-out of "
         "28 URLs its specificity fell to 0.7778, which is the clearest evidence "
         "that a lexical model cannot be trusted alone on local banking domains.")

    # ---- 5 Discussion and Conclusion ------------------------------------
    heading(doc, "5. Discussion and Conclusion")
    body(doc,
         "The results support a single design principle: existence must be "
         "settled before reputation is consulted, and the settling must not rest "
         "on a resolver that the environment can alter. Two limitations bound "
         "the claims. First, the H1 agreement shares its evidence with the "
         "labels, and an independent existence ground truth is needed. Second, "
         "the benchmark is small, covers three of six planned categories, and "
         "uses one model. On 94 URLs the full pipeline gave recall 1.00 and "
         "specificity 0.93, with caveats: recall counts non-resolving links as "
         "flagged, two false positives are mislabelled, and one is a single-vendor "
         "alarm. Future work should complete the benchmark, measure H2 directly "
         "with two annotators, and evaluate how analysts act on the verdicts.")
    body(doc,
         "This paper presented a real-time framework that detects referential "
         "hallucination and verifies descriptive hallucination in LLM-generated "
         "threat intelligence. Missing evidence is reported as uncertainty, not "
         "as safety. On a benchmark of real model output, the framework "
         "identified every hallucinated indicator, verified the claims that could "
         "be verified, and reported the rest as gaps, all within an interactive "
         "delay.")

    # ---- References -----------------------------------------------------
    heading(doc, "References")
    refs = [
        'Z. Ji et al., "Survey of hallucination in natural language generation," ACM Computing Surveys, vol. 55, no. 12, pp. 1-38, 2023.',
        'L. Huang et al., "A survey on hallucination in large language models: Principles, taxonomy, challenges, and open questions," ACM Trans. Inf. Syst., vol. 43, no. 2, pp. 1-55, 2025.',
        'N. F. Liu, T. Zhang, and P. Liang, "Evaluating verifiability in generative search engines," in Findings of EMNLP, 2023, pp. 7001-7025.',
        'W. H. Walters and E. I. Wilder, "Fabrication and errors in the bibliographic citations generated by ChatGPT," Scientific Reports, vol. 13, art. 14045, 2023.',
        'V. Magesh et al., "Hallucination-free? Assessing the reliability of leading AI legal research tools," arXiv:2405.20362, 2024.',
        'Anti-Phishing Working Group, "Phishing activity trends report, 4th quarter 2024," APWG, 2025.',
        'Federal Bureau of Investigation, "Internet crime report 2023," IC3, Washington, DC, USA, 2024.',
        'CyberSecurity Malaysia, "Malaysia cyber incident response centre annual report 2023," Kuala Lumpur, Malaysia, 2024.',
        'A. Aljofey et al., "An effective detection approach for phishing websites using URL and HTML features," Scientific Reports, vol. 12, art. 8842, 2022.',
        'A. Prasad and S. Chandra, "PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning," Computers & Security, vol. 136, art. 103545, 2024.',
        'S. Farquhar et al., "Detecting hallucinations in large language models using semantic entropy," Nature, vol. 630, no. 8017, pp. 625-630, 2024.',
        'L. Kuhn, Y. Gal, and S. Farquhar, "Semantic uncertainty: Linguistic invariances for uncertainty estimation in natural language generation," in Proc. ICLR, 2023.',
        'P. Manakul, A. Liusie, and M. J. F. Gales, "SelfCheckGPT: Zero-resource black-box hallucination detection for generative large language models," in Proc. EMNLP, 2023.',
        'S. Min et al., "FActScore: Fine-grained atomic evaluation of factual precision in long form text generation," in Proc. EMNLP, 2023.',
        'L. Daigle, "WHOIS protocol specification," RFC 3912, 2004.',
        'A. Newton, B. Ellacott, and N. Kong, "Registration Data Access Protocol (RDAP) query format," RFC 7482, 2015.',
        'D. Eastlake and A. Panitz, "Reserved top level DNS names," RFC 2606, 1999; M. Cotton, L. Vegoda, and S. Cheshire, "Special-use domain names," RFC 6761, 2013.',
        'P. Hoffman and P. McManus, "DNS queries over HTTPS (DoH)," RFC 8484, 2018.',
        'VirusTotal, "VirusTotal API v3 documentation," 2025. [Online]. Available: https://developers.virustotal.com/',
        'Google, "Safe Browsing API (v4) documentation," 2025. [Online]. Available: https://developers.google.com/safe-browsing/',
        'abuse.ch, "URLhaus: Malware URL exchange," 2025. [Online]. Available: https://urlhaus.abuse.ch/',
        'urlscan.io, "urlscan.io API documentation," 2025. [Online]. Available: https://urlscan.io/docs/api/',
        'L. Breiman, "Random forests," Machine Learning, vol. 45, no. 1, pp. 5-32, 2001.',
        'T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in Proc. 22nd ACM SIGKDD, 2016, pp. 785-794.',
        'S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in Advances in Neural Information Processing Systems, vol. 30, 2017, pp. 4765-4774.',
    ]
    for i, entry in enumerate(refs, start=1):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.8)
        p.paragraph_format.first_line_indent = Cm(-0.8)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.0
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = p.add_run(f"[{i}] {entry}")
        run.font.size = Pt(9)

    doc.save(OUT_DOCX)
    return OUT_DOCX


def main():
    build()
    print(f"saved {OUT_DOCX}")
    info = finalize_with_word(OUT_DOCX, OUT_PDF)
    print(json.dumps(info, indent=2))
    print(f"saved {OUT_PDF}")


if __name__ == "__main__":
    main()
