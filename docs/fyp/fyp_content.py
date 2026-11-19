"""Dissertation content for PhishGuard-HDV (UTP FYP format).

The build script imports these functions and writes the DOCX in order:
front matter, five chapters, references, appendices.
"""
from __future__ import annotations

from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Cm, Pt

from fyp_style import (add_par, add_table, add_figure, body, bullets,
                       chapter, cite, figure_caption, heading, numbered,
                       page_break, table_caption)
from fyp_figures import (confusion_matrix, dataset_profile,
                         feature_importance, project_framework, results_chart,
                         stage_a_flow, stage_b_flow, system_architecture,
                         theoretical_framework)

META = {
    "title": ("Real-Time Hallucination Detection and Verification System for "
              "LLM-Generated Phishing Threat Intelligence"),
    "student": "[Student Full Name]",
    "student_id": "[Student ID]",
    "supervisor": "[Supervisor Name]",
    "programme": "Bachelor of Computer Science (Hons)",
    "department": "Computer and Information Sciences",
    "session": "[FYP II Semester and Year]",
    "university": "Universiti Teknologi PETRONAS",
    "address": "32610, Bandar Seri Iskandar",
    "state": "Perak Darul Ridzuan",
}

CENTER = WD_ALIGN_PARAGRAPH.CENTER


# ===========================================================================
# FRONT MATTER
# ===========================================================================

def title_page(doc, meta):
    add_par(doc, "", space_after=0)
    add_par(doc, meta["title"], bold=True, size=16, align=CENTER,
            line_spacing=1.5, space_before=18, space_after=30)
    add_par(doc, "by", align=CENTER, space_after=18)
    add_par(doc, meta["student"], bold=True, align=CENTER, space_after=6)
    add_par(doc, meta["student_id"], align=CENTER, space_after=36)
    add_par(doc, "Dissertation submitted in partial fulfilment of",
            align=CENTER, space_after=0)
    add_par(doc, "the requirements for the", align=CENTER, space_after=0)
    add_par(doc, meta["programme"], bold=True, align=CENTER, space_after=0)
    add_par(doc, "(Computer Science)", align=CENTER, space_after=24)
    add_par(doc, meta["session"], bold=True, align=CENTER, space_after=42)
    add_par(doc, meta["university"], bold=True, align=CENTER, space_after=0)
    add_par(doc, meta["address"], align=CENTER, space_after=0)
    add_par(doc, meta["state"], align=CENTER, space_after=0)


def certification_approval(doc, meta):
    add_par(doc, "CERTIFICATION OF APPROVAL", bold=True, size=14,
            align=CENTER, space_before=12, space_after=24)
    add_par(doc, meta["title"], bold=True, align=CENTER, space_after=24)
    add_par(doc, "by", align=CENTER, space_after=12)
    add_par(doc, meta["student"], bold=True, align=CENTER, space_after=24)
    add_par(doc, "A project dissertation submitted to the", align=CENTER,
            space_after=0)
    add_par(doc, f"Department of {meta['department']}", align=CENTER,
            space_after=0)
    add_par(doc, f"{meta['university']}", align=CENTER, space_after=0)
    add_par(doc, "in partial fulfilment of the requirement for the",
            align=CENTER, space_after=0)
    add_par(doc, meta["programme"], align=CENTER, space_after=36)
    add_par(doc, "Approved by:", bold=True, space_after=42)
    add_par(doc, "_____________________________________", space_after=0)
    add_par(doc, f"({meta['supervisor']})", space_after=0)
    add_par(doc, "Supervisor", space_after=48)
    add_par(doc, f"{meta['university']}", bold=True, align=CENTER,
            space_after=0)
    add_par(doc, f"{meta['address']}", align=CENTER, space_after=0)
    add_par(doc, f"{meta['state']}", align=CENTER, space_after=0)


def certification_originality(doc, meta):
    add_par(doc, "CERTIFICATION OF ORIGINALITY", bold=True, size=14,
            align=CENTER, space_before=12, space_after=24)
    add_par(doc, "This is to certify that I am responsible for the work "
                 "submitted in this project, that the original work is my own "
                 "except as specified in the references and acknowledgements, "
                 "and that the original work contained herein has not been "
                 "undertaken or carried out by or on behalf of any other "
                 "person or institution.", align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_after=36)
    add_par(doc, "_____________________________________", space_after=0)
    add_par(doc, f"({meta['student']})", space_after=0)
    add_par(doc, f"Student ID: {meta['student_id']}", space_after=0)
    add_par(doc, "Date: ______________________", space_after=0)
    add_par(doc, "", space_after=24)
    add_par(doc, "This dissertation has been examined and is certified as "
                 "satisfying the requirements of the degree and the rules of "
                 "the University.", italic=True, space_after=30)
    add_par(doc, "_____________________________________", space_after=0)
    add_par(doc, f"({meta['supervisor']})", space_after=0)
    add_par(doc, "Supervisor", space_after=0)
    add_par(doc, "Date: ______________________", space_after=0)


def abstract(doc):
    add_par(doc, "ABSTRACT", bold=True, size=14, align=CENTER,
            space_before=12, space_after=18)
    body(doc,
         "Large language models (LLMs) are increasingly used to produce "
         "phishing threat intelligence, and their answers routinely contain "
         "indicators that were never real. Existing phishing detectors assume "
         "that a uniform resource locator (URL) already exists, so they answer "
         "the maliciousness question while silently skipping the existence "
         "question. This dissertation presents a real-time system that detects "
         "hallucinated links and claims in LLM-generated phishing threat "
         "intelligence and verifies the threat status of genuine links with "
         "auditable evidence. Detection separates referential hallucination, "
         "where the indicator does not exist, from descriptive hallucination, "
         "where a genuine indicator is misdescribed. Existence is tested with "
         "structural rules, Domain Name System (DNS) resolution, WHOIS and "
         "Registration Data Access Protocol (RDAP) records, an exact-page "
         "Hypertext Transfer Protocol (HTTP) probe, and a reference store. "
         "Descriptions are tested by comparing the sentence that introduced "
         "the indicator with the evidence collected about it. Genuine "
         "indicators are then verified against VirusTotal, Google Safe "
         "Browsing, URLhaus, urlscan.io, and a read-only page inspection. "
         "Missing credentials, failed sources, and expired deadlines are "
         "carried as explicit uncertainty and are never counted as a pass. "
         "Independent checks run concurrently behind a hard deadline, with "
         "result caching and streaming verdicts. On a benchmark of real model "
         "output, 83 of 123 extracted indicators (67.5 per cent) did not "
         "exist, and fourteen of fifteen answers contained at least one "
         "invented indicator. On an eight-indicator answer, concurrent "
         "verification reduced median response time from 52.1 seconds to 14.3 "
         "seconds, a 3.64-fold improvement, while preserving the same "
         "verdicts. The results show that real-time hallucination detection "
         "and evidence-based verification are a necessary design condition "
         "for trustworthy LLM-assisted threat intelligence.")
    add_par(doc, "", space_after=6)
    add_par(doc, "Keywords: large language models, hallucination detection, "
                 "phishing URL detection, evidence fusion, explainable "
                 "security, threat intelligence verification", italic=False,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=0)


def acknowledgements(doc):
    add_par(doc, "ACKNOWLEDGEMENTS", bold=True, size=14, align=CENTER,
            space_before=12, space_after=18)
    body(doc,
         "The completion of this dissertation would not have been possible "
         "without the guidance and support of several individuals. I would "
         "like to express my sincere gratitude to my supervisor, "
         f"{META['supervisor']}, for the continuous guidance, constructive "
         "criticism, and patient review that shaped this work from an "
         "exploratory idea into a working system. The supervision provided "
         "throughout both semesters of the Final Year Project was invaluable.")
    body(doc,
         "I am also grateful to the Department of Computer and Information "
         "Sciences at Universiti Teknologi PETRONAS for providing the "
         "academic environment, laboratory facilities, and administrative "
         "support needed to carry out this project. The comments received "
         "during the proposal defence and progress assessments helped to "
         "sharpen the research questions and the evaluation strategy.")
    body(doc,
         "Acknowledgement is also due to the providers of the public datasets "
         "and threat intelligence services used in this study, including the "
         "PhiUSIIL corpus, VirusTotal, Google Safe Browsing, URLhaus, "
         "urlscan.io, and WhoisXML. Their interfaces made independent "
         "verification possible.")
    body(doc,
         "Finally, I would like to thank my family and friends for their "
         "unwavering encouragement and understanding during the long hours "
         "spent developing, testing, and documenting this project. Their "
         "support made the difficult periods manageable.")


def abbreviations(doc):
    add_par(doc, "ABBREVIATIONS AND NOMENCLATURES", bold=True, size=14,
            align=CENTER, space_before=12, space_after=18)
    rows = [
        ("API", "Application Programming Interface"),
        ("AUC", "Area Under the Receiver Operating Characteristic Curve"),
        ("CDN", "Content Delivery Network"),
        ("DNS", "Domain Name System"),
        ("DOCX", "Microsoft Word Open XML Document"),
        ("ECE", "Expected Calibration Error"),
        ("FYP", "Final Year Project"),
        ("GSB", "Google Safe Browsing"),
        ("HTML", "Hypertext Markup Language"),
        ("HTTP", "Hypertext Transfer Protocol"),
        ("HTTPS", "Hypertext Transfer Protocol Secure"),
        ("IC3", "Internet Crime Complaint Center"),
        ("IEEE", "Institute of Electrical and Electronics Engineers"),
        ("LLM", "Large Language Model"),
        ("ML", "Machine Learning"),
        ("NLP", "Natural Language Processing"),
        ("RDAP", "Registration Data Access Protocol"),
        ("RF", "Random Forest"),
        ("ROC", "Receiver Operating Characteristic"),
        ("SQL", "Structured Query Language"),
        ("SQLite", "Embedded Relational Database Engine"),
        ("TF-IDF", "Term Frequency-Inverse Document Frequency"),
        ("TLD", "Top-Level Domain"),
        ("UI", "User Interface"),
        ("URL", "Uniform Resource Locator"),
        ("UTP", "Universiti Teknologi PETRONAS"),
        ("WAF", "Web Application Firewall"),
        ("WHOIS", "Domain Registration Directory Protocol"),
        ("XAI", "Explainable Artificial Intelligence"),
        ("XGBoost", "Extreme Gradient Boosting"),
    ]
    add_table(doc, ["Abbreviation", "Meaning"], rows, font_size=10,
              widths=[4.0, 11.0], center_cols=[0], first_col_bold=True)


def table_of_contents(doc):
    from fyp_style import add_field
    add_par(doc, "TABLE OF CONTENTS", bold=True, size=14, align=CENTER,
            space_before=12, space_after=18)
    p = doc.add_paragraph()
    add_field(p, ' TOC \\o "1-3" \\h \\z \\u ', "Right-click and select "
              "Update Field to build the table of contents.")


def list_of_figures(doc):
    from fyp_style import add_field
    add_par(doc, "LIST OF FIGURES", bold=True, size=14, align=CENTER,
            space_before=12, space_after=18)
    p = doc.add_paragraph()
    add_field(p, ' TOC \\h \\z \\f F ', "Update this field to list the figures.")


def list_of_tables(doc):
    from fyp_style import add_field
    add_par(doc, "LIST OF TABLES", bold=True, size=14, align=CENTER,
            space_before=12, space_after=18)
    p = doc.add_paragraph()
    add_field(p, ' TOC \\h \\z \\f T ', "Update this field to list the tables.")


# ===========================================================================
# CHAPTER 1
# ===========================================================================

def chapter1(doc, first=False):
    if first:
        heading(doc, "CHAPTER 1: INTRODUCTION", 1, bookmark="START_MAIN",
                bookmark_id=1)
    else:
        chapter(doc, "CHAPTER 1: INTRODUCTION",
                bookmark="START_MAIN", bookmark_id=1)

    heading(doc, "1.1 Overview", 2)
    body(doc,
         "This chapter establishes the context of the study. The object of "
         "study is not phishing in general, but the threat intelligence that a "
         "large language model (LLM) produces about phishing. When an analyst "
         "asks a conversational model to describe a campaign, list indicators, "
         "or recommend a blocklist, the answer is written in the register of a "
         "finished intelligence product: confident, specific, and populated "
         "with uniform resource locators (URLs). Nothing in that register "
         "tells the reader which of those URLs were ever real. The chapter "
         "explains why this is a distinct security problem, why conventional "
         "phishing detection does not answer it, and why the answer must "
         "arrive quickly enough to be useful. It then states the problem, the "
         "research questions, the aim and objectives, the scope, and the "
         "significance of the study before outlining the dissertation.")

    heading(doc, "1.2 Research Background", 2)
    body(doc,
         "Generative models have moved from experimentation into the daily "
         "work of security teams. Analysts use them to summarise advisories, "
         "draft detection logic, explain unfamiliar malware families, and "
         "produce first-pass threat intelligence for a ticketing queue. The "
         "practical appeal is speed: a task that once required reading several "
         "reports now returns a structured answer in seconds. The same speed "
         "creates a dependency, because the analyst must decide whether the "
         "answer is true before acting on it. A search engine returns links "
         "that a human can inspect; a generative model returns prose that "
         "reads as though the inspection has already happened. That "
         "distinction is the starting point of this study.")
    body(doc,
         "The failure mode is hallucination, the generation of content that is "
         "fluent and plausible but not grounded in fact [CITE:ji2023]. The "
         "literature separates intrinsic hallucination, where the output "
         "contradicts the material it was given, from extrinsic hallucination, "
         "where the output adds information that no source supports "
         "[CITE:ji2023][CITE:huang2025]. A further distinction matters here. "
         "Most evaluations of hallucination concern a proposition: a date, a "
         "name, a causal claim. This study is concerned with an object: a "
         "URL. A proposition can be judged against a document, but a URL "
         "asserts its own existence. If the domain was never registered, every "
         "subsequent statement about it is anchored to nothing. The model does "
         "not merely state something false; it hands the analyst an address to "
         "visit.")
    body(doc,
         "Phishing is the domain in which this failure carries the highest "
         "cost. Phishing remains among the most frequently reported cybercrimes "
         "and among the most common initial access vectors. The Anti-Phishing "
         "Working Group has repeatedly recorded millions of attacks per "
         "quarter [CITE:apwg2024], and the United States Federal Bureau of "
         "Investigation reports that phishing and its variants rank "
         "consistently among the top reported crime types [CITE:ic3_2023]. In "
         "Malaysia, CyberSecurity Malaysia and the Malaysian Computer "
         "Emergency Response Team have documented sustained growth in online "
         "fraud and phishing complaints, with banking and e-commerce customers "
         "as the principal targets [CITE:cybersecurity_my][CITE:mycert2023]. "
         "A phishing indicator is not a neutral fact. It is an instruction to "
         "click, to block, or to warn a customer. An analyst who acts on an "
         "invented indicator may block a legitimate service, warn users about "
         "a domain that does not exist, or, worse, treat the absence of "
         "evidence about that domain as evidence that it is harmless.")
    body(doc,
         "The risk does not end when the answer is read. A domain that a model "
         "invents today is a domain name that anyone can register tomorrow. "
         "Because the invented name is published in the answer, and because "
         "the answer may be copied into a report, a chat thread, or a "
         "detection rule, an adversary who observes it can acquire the exact "
         "name and inherit the credibility that the analyst has already "
         "granted it. The hallucination therefore has a lifetime. It begins as "
         "a false statement and can become a real, hostile endpoint without "
         "the original claim ever being corrected.")
    body(doc,
         "This study measured the phenomenon before designing for it. A fixed "
         "set of forty threat-intelligence prompts was submitted to the "
         "deployed model, covering Malaysian banking brands, international "
         "brands, explicit indicator-of-compromise requests, recency questions, "
         "attribution questions, and control questions that ask for official "
         "pages. The first fifteen answers that could be collected within the "
         "provider's quota contained 123 extracted indicators, of which 83 "
         "(67.5 per cent) did not exist in the Domain Name System (DNS). "
         "Fourteen of the fifteen answers contained at least one non-existent "
         "indicator. The failure was not confined to obviously speculative "
         "phrasing. One answer introduced twelve invented domains under the "
         "heading 'Identified Phishing Indicators of Compromise', described "
         "them as 'documented malicious URLs ... identified in phishing "
         "campaigns', and recommended blocking them at the DNS and secure web "
         "gateway layers. Every one of the twelve was unregistered. The model "
         "supplied no hedge, no uncertainty, and no source.")
    body(doc,
         "Conventional phishing detection does not address this case. The "
         "dominant research tradition treats phishing detection as a "
         "classification problem over a URL that is assumed to exist and can "
         "be fetched [CITE:alkhalil2021]. That assumption is "
         "satisfied at a mail gateway or a web proxy, because the message or "
         "the browser request already carries a live link. It is violated when "
         "the input is generated text. A hallucinated URL cannot be fetched, and "
         "a content-based detector must then either raise an error or treat "
         "the missing page as benign. Neither response is acceptable, and "
         "neither is reported as a limitation in the studies that adopt the "
         "assumption. The same blind spot appears in threat-intelligence "
         "lookups: a blocklist can only report what it has already observed, "
         "and a URL that has never existed cannot have been observed. A "
         "'no match' from such a source is a statement about the source, not "
         "about the URL.")
    body(doc,
         "A second limitation is presentational. Most detectors return a label "
         "and leave the reasoning implicit. An analyst reading LLM output needs "
         "more: which sources were consulted, which answered, which failed, "
         "and which piece of evidence drove the verdict. This requirement "
         "becomes critical when the input is itself uncertain, because the "
         "absence of a threat-feed match is not proof of safety. A domain "
         "registered last week may be hostile and still absent from every "
         "feed. A system that silently converts missing evidence into a "
         "negative result reproduces the failure it was built to prevent.")
    body(doc,
         "Verification is nevertheless possible, because the questions that "
         "matter can be asked of independent infrastructure rather than of the "
         "model. Existence can be tested with DNS, registration records from "
         "the WHOIS protocol and the Registration Data Access Protocol (RDAP), "
         "and a direct request for the exact page [CITE:rfc3912][CITE:rdap]. "
         "Reputation can be tested against threat-intelligence services "
         "[CITE:virustotal][CITE:gsb][CITE:urlhaus][CITE:urlscan]. Content can "
         "be inspected, read-only, for the structural signature of a fake "
         "login page. Each of these sources is partial, rate-limited, and "
         "capable of failing, which means the design problem is not merely to "
         "collect evidence but to combine it without overstating it.")
    body(doc,
         "Finally, the answer has to arrive while the analyst is still reading. "
         "A generated report may contain a dozen indicators, and a sequential "
         "verification of each one against several network services can take "
         "minutes. A tool that is correct but slow is abandoned, and an "
         "abandoned tool protects nobody. The system must therefore overlap "
         "independent checks, reuse recent results, and return a defensible "
         "verdict within a bounded time, reporting which checks completed and "
         "which did not.")
    body(doc,
         "The gap that this study addresses is the absence of a system that "
         "treats LLM output as the input of record, detects both invented "
         "indicators and false descriptions of genuine ones, verifies the "
         "threat status of what remains with explicit coverage, and does so "
         "within an interactive latency budget. The proposed system, "
         "PhishGuard-HDV, is organised around that gap.")

    heading(doc, "1.3 Problem Statement", 2)
    body(doc,
         "Analysts who use LLMs to produce phishing threat intelligence cannot "
         "currently tell which of the resulting indicators are real. The "
         "output is delivered as finished prose, and the reader has no "
         "practical way to separate a link that exists from a link that the "
         "model invented. In the measurement described above, two thirds of "
         "the extracted indicators did not exist, and the model presented them "
         "as documented findings. The consequence is a category error with a "
         "security impact: a hallucinated indicator is either reported as safe, "
         "because no threat feed recognises it, or reported as hostile on the "
         "strength of the model's own assertion. The first outcome encourages "
         "an analyst to trust an address that has no owner; the second "
         "produces noise that erodes trust in the tool.")
    body(doc,
         "The problem is not solved by improving the classifier. A detector "
         "that assumes the URL exists cannot answer the existence question, "
         "and a detector that returns a single label cannot express the "
         "difference between 'no evidence of phishing' and 'no evidence at "
         "all'. What is missing is a decision architecture that represents "
         "existence, description, threat status, and coverage as separate "
         "concerns, and that explains the final verdict in terms an analyst "
         "can audit.")
    body(doc,
         "The problem has a temporal dimension as well. Threat status changes: "
         "a domain can be clean when the answer is generated and hostile an "
         "hour later, and a stale indicator can be presented as current. "
         "Verification must therefore be performed at the moment of reading, "
         "not at the moment of writing, and it must complete quickly enough to "
         "inform the decision it is meant to support. Existing studies rarely "
         "report latency, coverage, or behaviour on non-existent inputs, so "
         "their accuracy figures do not indicate whether the system would "
         "mislead an analyst who pastes a hallucinated link from a generated "
         "report.")
    body(doc,
         "This study addresses that unreported failure mode directly. It asks "
         "whether hallucinated indicators and hallucinated descriptions can be "
         "detected in real time, and whether the resulting verdict can be "
         "supported by evidence that the analyst is able to inspect.")

    heading(doc, "1.4 Research Questions", 2)
    body(doc,
         "The study is guided by three research questions:")
    numbered(doc, [
        "What forms of hallucination occur in LLM-generated phishing threat "
        "intelligence, and how can each form be characterised and detected?",
        "How can a system distinguish hallucinated indicators from genuine "
        "ones, detect false descriptions of genuine indicators, and verify "
        "their current threat status within an interactive time budget?",
        "How accurately and how quickly does such a system detect "
        "hallucination and verify threat status, compared with single-stage "
        "detection and with manual verification?",
    ])

    heading(doc, "1.5 Aim", 2)
    body(doc,
         "The aim of this study is to design, implement, and evaluate a "
         "real-time system that detects hallucinated links and claims in "
         "LLM-generated phishing threat intelligence, and that verifies the "
         "threat status of genuine links with auditable evidence.")

    heading(doc, "1.6 Research Objectives", 2)
    body(doc,
         "The aim is decomposed into four objectives:")
    numbered(doc, [
        "To characterise a taxonomy of hallucination in LLM-generated "
        "phishing threat intelligence and to construct a labelled benchmark of "
        "real model output against which detection can be measured.",
        "To design a real-time detection and verification pipeline that "
        "combines referential checks, claim-consistency checks, and "
        "threat-intelligence verification, and that represents incomplete "
        "evidence as explicit uncertainty.",
        "To implement the pipeline with concurrent evidence acquisition, "
        "result caching, hard deadlines, streaming verdicts, and an audit "
        "trail, so that a multi-indicator answer is verified within an "
        "interactive latency budget.",
        "To evaluate hallucination-detection accuracy, verification accuracy, "
        "evidence coverage, and response latency against single-stage and "
        "manual baselines, and to analyse the errors that remain.",
    ])

    body(doc,
         "The taxonomy that organises the first objective is summarised in "
         "Table 1.1. It separates the failure of reference from the failure of "
         "description, and it distinguishes both from failures of currency and "
         "attribution, which are harder to establish automatically.")
    table_caption(doc, "Table 1.1: Hallucination taxonomy used in this study")
    add_table(doc,
              ["Type", "Definition", "Example", "Detected here"],
              [("H1 Referential",
                "The URL or domain does not exist.",
                "A domain asserted as a live campaign site returns NXDOMAIN.",
                "Yes"),
               ("H2 Descriptive",
                "The URL exists, but the claim about it is false.",
                "A genuine bank homepage described as a credential-harvesting "
                "kit.",
                "Yes"),
               ("H3 Temporal",
                "A stale indicator is presented as current.",
                "A domain sinkholed last year listed as active today.",
                "Partly"),
               ("H4 Attribution",
                "A claim is attributed to a source that does not support it.",
                "'According to PhishTank' with no retrievable record.",
                "Partly")],
              font_size=9, widths=[2.6, 5.0, 5.2, 2.2],
              center_cols=[3], first_col_bold=True)

    heading(doc, "1.7 Scope of Study", 2)
    body(doc,
         "The study is limited to the verification of indicators that appear "
         "in text generated by a conversational LLM, together with indicators "
         "pasted directly by a user. It does not attempt to detect phishing in "
         "email attachments, SMS messages, social media posts, or images, and "
         "it does not perform full browser instrumentation or dynamic sandbox "
         "execution. Page inspection is read-only and limited to the "
         "Hypertext Markup Language (HTML) that the server returns to an "
         "automated client; JavaScript is not executed and no credentials are "
         "submitted.")
    body(doc,
         "The implementation uses one LLM, Gemini, for answer generation, and "
         "the external services for which credentials were available during "
         "development: VirusTotal, Google Safe Browsing, URLhaus, urlscan.io, "
         "and WhoisXML for domain age. Services without available credentials "
         "were not integrated, because a source that cannot be queried cannot "
         "contribute evidence. The evaluation covers English-language threat "
         "intelligence and a Malaysian hold-out set of banking, government, "
         "e-commerce, and news domains. It does not claim global coverage, and "
         "the Malaysian results are interpreted as an indication of "
         "cross-distribution behaviour rather than as a national benchmark.")
    body(doc,
         "The benchmark of model output is bounded by the provider's free-tier "
         "quota, which permits twenty generation requests per day. The study "
         "therefore reports the benchmark size explicitly and treats the "
         "measurement as a structured sample rather than as a population "
         "estimate. The reserved-TLD stress set described in Chapter 3 is "
         "retained as a complement, not as a substitute, because synthetic "
         "lookalikes cannot establish how a real model behaves.")
    body(doc,
         "The study evaluates the deployed model and an earlier leak-fixed "
         "variant, but it does not attempt to train a new language model or to "
         "fine-tune the generator. Detection of H1 and H2 is evaluated "
         "quantitatively; detection of H3 and H4 is implemented only to the "
         "extent that the integrated sources permit, and the remainder is "
         "stated as a limitation. Finally, the system is evaluated as a "
         "research prototype running on a single workstation; production "
         "concerns such as horizontal scaling, high availability, and "
         "organisational identity management are outside the scope.")

    heading(doc, "1.8 Significance of Study", 2)
    body(doc,
         "The study contributes a practical safeguard for the growing use of "
         "LLMs in security work. By treating the generated answer as the input "
         "of record and testing its indicators against independent "
         "infrastructure, it removes the category error that allows a "
         "hallucinated link to be reported as safe. This reduces the risk that "
         "an analyst acts on an address that an attacker may register after "
         "observing the model's output.")
    body(doc,
         "The study also contributes an evidence model for uncertain security "
         "decisions. Missing credentials, exhausted quotas, blocked requests, "
         "and expired deadlines are represented explicitly, so the absence of "
         "evidence is never mistaken for evidence of absence. This principle "
         "is transferable to other verification tasks in which several "
         "imperfect sources must be combined under time pressure.")
    body(doc,
         "For Malaysian organisations, the study provides an early assessment "
         "of how a model trained on an international corpus behaves on local "
         "banking and government domains, and of how often it invents local "
         "indicators. The results highlight both the value of an "
         "official-domain allowlist and the danger of treating allowlisted "
         "domains as automatically safe. Finally, the study documents a "
         "reproducible benchmark and regression harness, so that future "
         "changes to rules, sources, or models can be measured against fixed, "
         "labelled data rather than judged by anecdote.")

    heading(doc, "1.9 Thesis Structure", 2)
    body(doc,
         "The dissertation is organised into five chapters. Chapter 1 "
         "introduces the background, problem, questions, aim, objectives, "
         "scope, and significance of the study. Chapter 2 reviews the "
         "literature on hallucination in LLMs, on hallucination detection and "
         "claim verification, and on the verification of links and threat "
         "intelligence, and positions the study against that work. Chapter 3 "
         "describes the framework, the system architecture, the design of the "
         "detection and verification stages, the real-time execution model, "
         "and the development and testing strategy. Chapter 4 presents the "
         "benchmark, the experimental setup, the detection and verification "
         "results, the latency measurements, the error analysis, and a "
         "comparison with baselines. Chapter 5 concludes the dissertation by "
         "summarising the findings against the research questions, stating the "
         "contributions and limitations, and recommending directions for "
         "future work.")


# ===========================================================================
# CHAPTER 2
# ===========================================================================

def chapter2(doc, fig_dir):
    chapter(doc, "CHAPTER 2: LITERATURE REVIEW AND THEORY")

    heading(doc, "2.1 Overview", 2)
    body(doc,
         "This chapter reviews the work on which the study depends. It begins "
         "with the theory of hallucination in generated text, because the "
         "study's object of analysis is an LLM answer rather than a live web "
         "page. It then examines the principal families of hallucination "
         "detection: uncertainty estimation, sampling consistency, factuality "
         "decomposition, and retrieval or citation grounding. It argues that "
         "none of these families can establish whether a domain exists, which "
         "is why an external referential check is required. The chapter then "
         "reviews the infrastructure available for verifying links and threat "
         "status, the problem of treating absent evidence as safety, and the "
         "design constraints that arise when verification must complete in "
         "real time. It closes with the Malaysian context, the research gap, "
         "and the position of the present study.")

    heading(doc, "2.2 Theoretical Framework", 2)
    body(doc,
         "The study treats verification as a chain of evidence rather than as "
         "a single classification. An LLM answer supplies text; the text "
         "supplies indicators; each indicator is tested against independent "
         "infrastructure; the resulting evidence is combined into a verdict "
         "that records what was checked and what was not. Figure 2.1 presents "
         "this chain as a conceptual framework. Evidence acquisition occupies "
         "the first layer, decision logic the second, and the presentation of "
         "coverage the third. The framework is deliberately broader than any "
         "single implementation, because the argument of the study concerns "
         "the ordering of the questions rather than the choice of classifier.")
    add_figure(doc, fig_dir / "figure_2_1_theoretical_framework.png",
               "Figure 2.1: Conceptual framework of evidence-aware "
               "verification for LLM-generated threat intelligence")

    heading(doc, "2.2.1 Hallucination and verifiability in generated text", 3)
    body(doc,
         "Hallucination is conventionally defined as generated content that is "
         "not grounded in the source material or in verifiable fact. Ji et al. "
         "distinguish intrinsic hallucination, which contradicts the provided "
         "source, from extrinsic hallucination, which introduces information "
         "that no source supports [CITE:ji2023]. Huang et al. extend the "
         "taxonomy to cover faithfulness, factuality, and the interaction "
         "between the two, and note that the boundary between a creative "
         "variation and a factual error depends on the task [CITE:huang2025]. "
         "For threat intelligence the boundary is narrow. An analyst who reads "
         "'attackers are using domain X' has been given a factual claim with "
         "an operational consequence, not a stylistic variation.")
    body(doc,
         "A separate line of work evaluates verifiability rather than truth. "
         "Liu et al. ask whether the citations returned by generative search "
         "engines actually support the sentences they are attached to, and "
         "find that a substantial share do not [CITE:liu2023]. Their framing "
         "is useful because it moves the question from 'is the model honest' "
         "to 'can the reader check'. This study adopts the same stance. The "
         "system does not attempt to certify the model's internal state; it "
         "attempts to give the reader an independent basis for accepting or "
         "rejecting each indicator.")
    body(doc,
         "The relevant unit of analysis is therefore the indicator and its "
         "sentence, not the answer as a whole. An answer can be broadly useful "
         "and still contain one hallucinated domain, and a single hallucinated "
         "domain is enough to cause harm if it is acted upon. Answer-level "
         "scores obscure this. The study consequently reports detection at the "
         "level of the indicator, and treats the answer as hallucinated when "
         "at least one of its indicators is.")

    heading(doc, "2.2.2 Referential versus descriptive hallucination", 3)
    body(doc,
         "Two failures must be separated. Referential hallucination occurs "
         "when the indicator does not refer to anything: the domain was never "
         "registered, or the URL does not exist on a domain that does. "
         "Descriptive hallucination occurs when the indicator exists but the "
         "sentence around it is false: a genuine bank homepage described as a "
         "credential-harvesting kit, or a domain that was sinkholed last year "
         "described as active today. The first is a failure of reference; the "
         "second is a failure of predication. They require different evidence. "
         "Reference is settled by existence checks. Predication is settled by "
         "comparing the claim with what the page and the threat feeds actually "
         "show.")
    body(doc,
         "The distinction has a practical consequence that motivates the "
         "system architecture. A detector that only checks existence will "
         "pass every descriptive hallucination, because the URL resolves. A "
         "detector that only reads page content will pass every referential "
         "hallucination, because there is no page to read. Neither family "
         "alone covers the failure space, and prior work in phishing detection "
         "has concentrated on the second family.")
    body(doc,
         "The taxonomy used in this study, introduced in Table 1.1, adds two "
         "further categories. Temporal hallucination presents a stale "
         "indicator as current, which is a failure of currency rather than of "
         "reference. Unsupported attribution presents a claim as sourced when "
         "the named source does not support it, which is the citation failure "
         "documented by Liu et al. and by later studies of generated "
         "references [CITE:liu2023][CITE:walters2023]. The system implements "
         "partial checks for both, and the limits are stated in Chapter 5.")

    heading(doc, "2.2.3 Evidence, uncertainty, and explanation", 3)
    body(doc,
         "Verification against external sources is inherently partial. A "
         "threat feed can only report what it has observed, a DNS resolver can "
         "only report the current state of the zone, and an API can fail for "
         "reasons that have nothing to do with the URL. The literature on "
         "uncertainty in generated text makes an analogous point: a model's "
         "confidence is not the same as its correctness, and a system that "
         "reports only its conclusion hides the distinction "
         "[CITE:farquhar2024]. This study applies the same principle to "
         "external evidence. The absence of a match is recorded as the absence "
         "of a match, not as a negative finding, and a verdict that rests on "
         "incomplete coverage is labelled accordingly.")
    body(doc,
         "Explanation is treated as part of the verdict rather than as a "
         "post-hoc addition. Each result carries the sources that answered, "
         "the sources that failed, the evidence that drove the label, and the "
         "checks that could not be completed. This responds to a recurring "
         "observation in the security literature: analysts do not adopt tools "
         "whose reasoning they cannot inspect, particularly when the tool "
         "disagrees with their own judgement [CITE:alkhalil2021].")

    heading(doc, "2.3 Detecting Hallucination in Generated Text", 2)
    body(doc,
         "Four families of detection are relevant to this study. They differ "
         "in what they treat as evidence: the model's internal distribution, "
         "the consistency of multiple samples, the decomposition of the output "
         "into atomic facts, or the correspondence between the output and "
         "retrieved documents. Each family contributes a signal, and each has "
         "a blind spot that matters for referential hallucination.")

    heading(doc, "2.3.1 Uncertainty-based detection", 3)
    body(doc,
         "Uncertainty-based methods estimate whether the model is likely to be "
         "wrong by examining the distribution over its outputs. Kuhn et al. "
         "introduce semantic uncertainty, which clusters sampled generations "
         "by meaning rather than by surface form and estimates entropy over "
         "the resulting clusters [CITE:kuhn2023]. Farquhar et al. apply the "
         "idea to detect hallucinations in long-form generation and report "
         "that semantic entropy distinguishes confabulation from factual "
         "answers without requiring a reference database [CITE:farquhar2024]. "
         "The approach is attractive because it is model-agnostic and needs no "
         "external service.")
    body(doc,
         "Its limitation for this study is structural. Semantic entropy "
         "measures uncertainty about what the model would say; it does not "
         "measure whether the thing said exists. A model can be highly "
         "consistent about a domain that it invented, particularly when the "
         "domain follows a predictable pattern such as a brand name joined to "
         "a security keyword. Consistency is then evidence of a stable "
         "generation process, not of registration. The same objection applies "
         "to self-consistency more generally [CITE:wang2023]. Uncertainty "
         "signals are therefore useful as a prioritisation aid, but they "
         "cannot replace a referential check.")

    heading(doc, "2.3.2 Sampling and consistency-based detection", 3)
    body(doc,
         "Sampling-based methods generate several responses to the same prompt "
         "and look for disagreement. SelfCheckGPT treats a sentence as "
         "hallucinated when independently sampled responses do not support it, "
         "which allows black-box detection without access to token "
         "probabilities [CITE:manakul2023]. The method is effective for "
         "narrative claims, where a hallucinated detail tends to vary across "
         "samples.")

    heading(doc, "2.3.3 Factuality decomposition", 3)
    body(doc,
         "A third family decomposes generated text into atomic claims and "
         "verifies each against a knowledge source. FActScore exemplifies the "
         "approach: long-form biographies are broken into facts, each fact is "
         "scored for support, and the aggregate is reported as precision "
         "[CITE:min2023]. Decomposition is valuable because it localises the "
         "error. It also makes the evaluation auditable, since a reader can "
         "see which atom failed.")

    heading(doc, "2.3.4 Retrieval grounding and citation verification", 3)
    body(doc,
         "Retrieval-augmented generation reduces hallucination by conditioning "
         "the model on documents retrieved at inference time [CITE:lewis2020]. "
         "Attribution methods go further and require the model to cite the "
         "passages that support each sentence, which makes the output "
         "checkable [CITE:gao2023]. Both are important advances, and both "
         "depend on the retrieved corpus containing the answer. For a brand "
         "new phishing domain, no corpus contains it, so retrieval cannot "
         "ground the claim.")
    body(doc,
         "The empirical literature on citation failure is sobering. Walters "
         "and Wilder examined references generated by ChatGPT and found that a "
         "large proportion were fabricated or contained errors, including "
         "non-existent digital object identifiers [CITE:walters2023]. Magesh "
         "et al. evaluated commercial legal research tools and found "
         "hallucinated citations and misgrounded claims despite vendor claims "
         "of reliability [CITE:magesh2024]. These results matter for the "
         "present study because they show that a citation is not evidence "
         "until it is retrieved. The system therefore treats a named source as "
         "unsupported unless an integrated service actually returns a record.")

    heading(doc, "2.3.5 Why model-internal signals cannot establish reference", 3)
    body(doc,
         "Table 2.1 summarises the four families against the two failure types "
         "defined earlier. The pattern is consistent: each family can detect "
         "some descriptive errors, because a false description often produces "
         "internal inconsistency, but none can establish that a domain exists. "
         "Existence is a fact about the world, held by registries and "
         "resolvers, and it must be queried rather than inferred. This is the "
         "theoretical justification for the architecture adopted in Chapter 3, "
         "in which a referential check precedes any assessment of threat "
         "status.")
    table_caption(doc, "Table 2.1: Hallucination-detection families against the "
                       "failure types of this study")
    add_table(doc,
              ["Family", "Evidence used", "Detects H1", "Detects H2", "Main limitation"],
              [("Uncertainty", "Model distribution",
                "No", "Partly", "A stable hallucination looks certain"),
               ("Sampling consistency", "Agreement across samples",
                "No", "Partly", "Instability is not falsity; cost multiplies"),
               ("Fact decomposition", "Atomic claims vs corpus",
                "Partly", "Yes", "A corpus cannot confirm registration"),
               ("Retrieval and citation", "Retrieved documents",
                "Partly", "Yes", "New domains are absent from every corpus"),
               ("External referential verification", "DNS, RDAP, HTTP, feeds",
                "Yes", "Yes", "Requires network access and tolerates partial "
                "coverage")],
              font_size=9, widths=[3.4, 3.4, 1.8, 1.9, 4.5],
              center_cols=[2, 3], first_col_bold=True)

    heading(doc, "2.4 Verifying Links and Threat Intelligence", 2)
    body(doc,
         "The second half of the problem is verification: given an indicator "
         "that exists, what is its current status? The available evidence "
         "comes from naming infrastructure, from threat-intelligence services, "
         "and from the page itself. Each source answers a different question, "
         "and the design of the system follows from those differences.")

    heading(doc, "2.4.1 Naming infrastructure as existence evidence", 3)
    body(doc,
         "The Domain Name System is the primary authority on whether a name "
         "resolves. A query that returns NXDOMAIN is evidence that the name is "
         "not currently published, subject to the caveats of resolver "
         "caching, DNSSEC failures, and zone configuration. Registration data "
         "provides complementary evidence: the WHOIS protocol exposes "
         "registration records [CITE:rfc3912], and RDAP replaces the ad hoc "
         "WHOIS format with a structured query and response model "
         "[CITE:rdap]. Registration timestamps are particularly useful because "
         "a recently created domain is a recognised phishing signal, while a "
         "long-established domain is unlikely to have been registered for a "
         "campaign that began last week.")
    body(doc,
         "Two reserved-name conventions simplify the referential check. RFC "
         "2606 reserves the example, test, and invalid top-level domains for "
         "documentation, and RFC 6761 extends the special-use registry "
         "[CITE:rfc2606][CITE:rfc6761]. A name under these top-level domains "
         "can never resolve in the public DNS, so it can be classified without "
         "a network call. This is useful for a stress test, but it is not a "
         "substitute for measuring real model output, because a hallucinated "
         "domain in a real answer will normally carry an ordinary top-level "
         "domain.")
    body(doc,
         "Registration data is not always available. Privacy services redact "
         "registrant details, registries differ in their RDAP coverage, and "
         "queries are rate-limited. The system therefore treats registration "
         "as corroborating evidence rather than as a gate, and records a "
         "failure to obtain it as a coverage gap.")

    heading(doc, "2.4.2 Threat-intelligence services and their coverage", 3)
    body(doc,
         "Threat-intelligence services answer the reputation question. "
         "VirusTotal aggregates antivirus and URL-scanning verdicts "
         "[CITE:virustotal]; Google Safe Browsing maintains lists of unsafe "
         "web resources [CITE:gsb]; URLhaus distributes malware URLs "
         "[CITE:urlhaus]; and urlscan.io provides submitted scan records and "
         "page metadata [CITE:urlscan]. Together they cover a large share of "
         "known malicious infrastructure, and a positive match from any of "
         "them is strong evidence.")
    body(doc,
         "Their coverage is retrospective. A service can only report an "
         "indicator that it has seen, submitted, or crawled. A domain "
         "registered an hour ago, or a URL that no scanner has visited, will "
         "return no match even when it is hostile. This asymmetry is the "
         "central epistemic problem of the domain: positive evidence is "
         "meaningful, negative evidence is weak. A system that reports 'safe' "
         "on the basis of no match is making a claim that its sources cannot "
         "support. The present study therefore never converts a non-match into "
         "a safety verdict; it reports the absence of positive evidence and "
         "states the coverage on which that statement rests.")
    body(doc,
         "Service availability introduces a second asymmetry. APIs impose "
         "quotas, require keys, and fail. Each failure removes a source of "
         "positive evidence without removing the URL's risk. A design that "
         "ignores the failure will under-report risk; a design that treats "
         "every failure as malicious will produce unusable noise. The "
         "resolution adopted here is to count only sources that were actually "
         "queried, to expose the count, and to refuse a clean verdict when the "
         "count is too low.")

    heading(doc, "2.4.3 Page-level inspection", 3)
    body(doc,
         "The page itself carries evidence that no feed can supply. A "
         "credential-harvesting page typically presents a password field, "
         "posts to a domain other than the one it is served from, or displays "
         "a brand that does not own the domain. Static inspection of the "
         "returned HTML can detect these signals without executing "
         "JavaScript, submitting a form, or exposing credentials, which makes "
         "it suitable for an automated verifier. The limits are equally clear: "
         "a page can render its form client-side, can cloaking-gate automated "
         "clients, or can be unavailable at the moment of the check. The system "
         "therefore treats a page signal as positive evidence when present and "
         "as inconclusive when absent.")

    heading(doc, "2.4.4 The absence-of-evidence problem", 3)
    body(doc,
         "The three sources above share a property that shapes the entire "
         "design: they can prove presence but not absence. A feed match proves "
         "that someone reported the URL. A page signal proves that the page "
         "behaves in a certain way. A DNS answer proves that the name resolves "
         "now. None of them proves that an unlisted domain is harmless. The "
         "literature on phishing detection rarely states this asymmetry "
         "explicitly, and evaluation practice reinforces the omission: a "
         "classifier tested on a balanced corpus is rewarded for calling "
         "unlisted domains legitimate, because in that corpus they usually "
         "are. In the setting of this study the base rate is "
         "different, because the input is a generated answer that has already "
         "been shown to contain a majority of non-existent indicators. A "
         "verdict of 'no evidence found' is therefore a statement about the "
         "sources, and the system says so.")

    heading(doc, "2.5 Real-Time Verification", 2)
    body(doc,
         "Real-time verification is not merely a performance target; it "
         "changes which architecture is acceptable. A sequential check of one "
         "URL against DNS, registration, page, and four services can take tens "
         "of seconds when a source is slow. An answer with eight indicators "
         "then takes minutes, which is longer than the analyst is willing to "
         "wait. The relevant techniques are well established in systems "
         "engineering rather than in the phishing literature: concurrent "
         "fan-out over independent checks, caching with a time-to-live, hard "
         "deadlines with partial results, and incremental presentation so that "
         "the first verdict appears before the last check finishes.")
    body(doc,
         "Two design constraints follow. First, concurrency must not change "
         "the verdict. Overlapping independent checks should reduce wall-clock "
         "time without altering the evidence that is combined, and any "
         "difference in outcome indicates a race or a shared-state defect "
         "rather than a benefit. Second, a deadline must not be silent. When a "
         "check does not complete, the result must say so and must not default "
         "to a clean label. The system therefore reports the number of checks "
         "completed, the time to first verdict, and the per-URL latency "
         "distribution, and it treats an expired deadline as a coverage "
         "failure.")
    body(doc,
         "Caching introduces a related obligation. Reusing a recent result "
         "improves latency, but a stale cached verdict can contradict the "
         "current state of a domain. The system therefore bounds the lifetime "
         "of a cached lookup and exposes whether a result was served from "
         "cache. This is a small design decision with a direct effect on the "
         "honesty of the latency claim: fast because the answer was reused is "
         "not the same as fast because the check was efficient, and the report "
         "distinguishes the two.")

    heading(doc, "2.6 The Malaysian Context", 2)
    body(doc,
         "Malaysia provides a demanding test case. Local brands are frequent "
         "targets of smishing and credential phishing, and the relevant "
         "official domains are a small, known set that includes maybank2u, "
         "cimbclicks, rhbgroup, hlb, and the Touch 'n Go properties "
         "[CITE:mycert2023][CITE:cybersecurity_my]. International threat feeds "
         "under-represent this infrastructure, so a domain that is official "
         "and clean may return no match simply because no feed has had reason "
         "to observe it. Conversely, a lookalike that targets a local brand "
         "may be too new to appear in any feed.")
    body(doc,
         "This combination produces both false negatives and false positives "
         "for any system that relies on feed matches alone. It also makes the "
         "official-domain allowlist attractive, because an exact match against "
         "a curated list is strong evidence of ownership. The risk is that an "
         "allowlist is a statement about a domain, not about a page. An "
         "official domain can host user-generated content, can be compromised, "
         "or can be impersonated through a subdomain or an open redirect. The "
         "system therefore treats an allowlisted domain as a reason to trust "
         "the domain, never as a reason to skip verification of the exact page.")

    heading(doc, "2.7 Research Gap", 2)
    body(doc,
         "The reviewed literature establishes three findings. Hallucination "
         "detection has matured as a field, but its methods observe the model "
         "rather than the world, and therefore cannot establish that an "
         "indicator exists. Threat-intelligence verification can establish "
         "reputation, but its negative results are weak and its coverage is "
         "incomplete. Phishing detection research assumes a live URL and "
         "reports classifier accuracy without reporting behaviour on "
         "non-existent inputs, latency, or evidence coverage. No reviewed study "
         "combines referential verification, descriptive claim checking, and "
         "threat-status verification for LLM-generated phishing intelligence "
         "under a real-time constraint.")
    body(doc,
         "Table 2.2 states the gap as a set of requirements. The first column "
         "names the question an analyst actually asks; the remaining columns "
         "record whether the reviewed families answer it. The final row is the "
         "position adopted by this study.")
    table_caption(doc, "Table 2.2: Requirements for verifying LLM-generated "
                       "phishing intelligence")
    add_table(doc,
              ["Requirement", "Model self-check", "Threat feeds",
               "Phishing classifier", "This study"],
              [("Does the indicator exist?", "No", "No", "Assumed", "Checked"),
               ("Is the description accurate?", "Partly", "No", "No", "Checked"),
               ("Is it hostile now?", "No", "Yes, if listed", "Yes, if live",
                "Checked with coverage"),
               ("Is missing evidence shown?", "No", "No", "No", "Yes"),
               ("Is the verdict fast enough to act on?", "Yes", "Yes", "Yes",
                "Measured")],
              font_size=9, widths=[5.2, 2.8, 2.8, 3.0, 3.2],
              center_cols=[1, 2, 3, 4], first_col_bold=True)
    body(doc,
         "The gap is therefore architectural rather than incremental. It is "
         "not enough to add a hallucination score to an existing detector, "
         "because the detector's first assumption, that the URL exists, is the "
         "assumption that fails. The contribution of this study is a system in "
         "which the referential question is asked first, the descriptive "
         "question is asked about the surviving indicators, the threat "
         "question is answered with explicit coverage, and the whole sequence "
         "completes within a measured time budget.")

def chapter3(doc, fig_dir):
    chapter(doc, "CHAPTER 3: METHODOLOGY AND SYSTEM DESIGN")

    heading(doc, "3.1 Overview", 2)
    body(doc,
         "This chapter describes how the system was designed, built, and "
         "tested in response to the problem stated in Chapter 1. The object of "
         "verification is an indicator that appears in large language model "
         "(LLM) output, and the design is organised around the four "
         "hallucination types introduced in Table 1.1. Referential "
         "hallucination (H1) is addressed by an existence stage that asks "
         "whether the indicator refers to anything. Descriptive "
         "hallucination (H2) is addressed by a claim stage that compares the "
         "sentence around a genuine indicator with the evidence collected "
         "about it. Temporal (H3) and attribution (H4) hallucination are "
         "addressed to the extent that the integrated sources permit, and the "
         "remaining boundary is stated explicitly.")
    body(doc,
         "The chapter begins with the research design and the project "
         "framework, then states the functional and non-functional "
         "requirements and the architecture that satisfies them. It describes "
         "Stage A, the claim verifier, and Stage B in turn, and then sets out "
         "the real-time execution model that makes the system usable while an "
         "analyst is reading. The final section describes how the benchmark "
         "was constructed and how the implementation was tested. Results are "
         "reported in Chapter 4.")

    heading(doc, "3.2 Research Design and Project Framework", 2)
    body(doc,
         "The study follows a design-science approach. The artefact is a "
         "verification system; the knowledge contribution is the evidence "
         "model that the artefact embodies and the measurements taken with "
         "it. Design-science was chosen because the research questions ask "
         "how a system should behave, not merely whether a classifier is "
         "accurate. Each research question maps to a design decision and to a "
         "measurement. The first question maps to the taxonomy and the "
         "benchmark. The second maps to the two verification stages and the "
         "uncertainty model. The third maps to the latency and accuracy "
         "comparisons against single-stage and manual baselines.")
    body(doc,
         "The work followed an incremental, evidence-driven framework rather "
         "than a strict waterfall, because the behaviour of external services "
         "could not be known in advance. A source that appeared suitable "
         "during requirements analysis might return inconsistent responses, "
         "impose quotas, or block automated clients. The design therefore had "
         "to be revised after observation, and each revision had to be "
         "measured against a fixed evaluation set so that improvements could "
         "be separated from regressions.")
    body(doc,
         "Six phases were executed, as shown in Figure 3.1. The first phase "
         "translated the research questions into requirements and reviewed "
         "the literature. The second constructed the benchmark of real model "
         "output and the labelled evaluation sets. The third implemented "
         "Stage A, the referential stage. The fourth implemented the claim "
         "verifier and Stage B, including the evidence clients, the page "
         "inspector, and the internal risk scorer. The fifth integrated the "
         "stages into a Streamlit application, added the audit log and the "
         "concurrent execution layer, and built the automated test suite. The "
         "sixth evaluated detection, verification, and latency, analysed the "
         "errors, and produced the documentation.")
    add_figure(doc, fig_dir / "figure_3_1_project_framework.png",
               "Figure 3.1: Project framework and iterative evaluation loop",
               width_cm=12.4)

    heading(doc, "3.3 Requirements and Architecture", 2)
    heading(doc, "3.3.1 Functional and non-functional requirements", 3)
    body(doc,
         "The requirements were derived from the research questions and from "
         "the failure modes observed in the benchmark. Functional "
         "requirements define what the system must do; non-functional "
         "requirements define the qualities that make the behaviour "
         "trustworthy. Both are listed in Table 3.1. The table is deliberately "
         "short. Each requirement is testable, and each is represented by at "
         "least one automated check in Section 3.8.4.")
    table_caption(doc, "Table 3.1: Functional and non-functional requirements")
    add_table(doc, ["ID", "Requirement", "Rationale"],
              [("FR1", "Extract every URL and bare hostname from an LLM "
                "answer or a pasted block of text.",
                "The unit of verification is the indicator, not the "
                "paragraph."),
               ("FR2", "Decide whether each indicator exists before assessing "
                "its threat status.", "A hallucinated indicator cannot be judged "
                "by a reputation service that has never seen it."),
               ("FR3", "Detect a false description of an indicator that does "
                "exist.", "A real domain can be mislabelled as hostile or as "
                "official."),
               ("FR4", "Represent inconclusive evidence as explicit "
                "uncertainty, never as a pass.",
                "Missing evidence is not proof of absence."),
               ("FR5", "Consult every configured threat source and record "
                "which sources answered, failed, or were never configured.",
                "Coverage must be visible to the analyst."),
               ("FR6", "Inspect a candidate login page read-only for form "
                "action, redirect, and brand mismatch.",
                "Credential theft is the dominant phishing objective."),
               ("FR7", "Return a verdict, a plain-language reason, a claim "
                "verdict, and a per-source evidence list.",
                "A verdict without evidence cannot be audited."),
               ("FR8", "Verify several indicators concurrently within a hard "
                "deadline and stream each verdict as it completes.",
                "A report that arrives after the decision is useless."),
               ("FR9", "Log every verification and support supervised review "
                "of community reports through a local workbook.",
                "Traceability and controlled correction."),
               ("NFR1", "Never count a missing key, a failed request, a rate "
                "limit, or an expired deadline as a pass.",
                "Silent failure is the principal risk in this domain."),
               ("NFR2", "Never treat an allowlisted domain as safe without "
                "checking the exact page.",
                "Official domains can host compromised or user-generated "
                "content."),
               ("NFR3", "Complete a multi-indicator report within an "
                "interactive delay and report p50 and p95 latency.",
                "The real-time claim must be measured, not asserted."),
               ("NFR4", "Remain functional when optional services are "
                "unavailable.", "The system must degrade honestly."),
               ("NFR5", "Reuse a recent result only within a bounded lifetime "
                "and disclose the reuse.",
                "A stale verdict can contradict the current state of a "
                "domain.")],
              font_size=8.5, widths=[1.3, 7.0, 7.0], center_cols=[0])

    heading(doc, "3.3.2 High-level architecture", 3)
    body(doc,
         "The architecture is organised into a presentation layer, an "
         "orchestration layer, two verification stages, an evidence layer, and "
         "a persistence layer, as shown in Figure 3.2. The presentation layer "
         "is a Streamlit application with four pages: verification, history, "
         "report, and about. The orchestration layer receives the input, calls "
         "the language model when a question has been asked, extracts and "
         "normalises the indicators, and routes each one through the stages.")
    add_figure(doc, fig_dir / "figure_3_2_system_architecture.png",
               "Figure 3.2: High-level system architecture", width_cm=12.4)
    body(doc,
         "The orchestration layer enforces a strict ordering. Stage A is "
         "always evaluated first. If Stage A concludes that the indicator does "
         "not exist, the indicator is reported as H1 and Stage B is not "
         "executed, because a threat score for a non-existent resource is "
         "meaningless. If Stage A concludes that the indicator exists, the "
         "claim verifier and Stage B are executed. If Stage A is uncertain, "
         "the result is reported as a coverage gap rather than as clean, and "
         "the gap is carried into the final verdict.")

    heading(doc, "3.4 Stage A: Referential Hallucination Detection", 2)
    body(doc,
         "Stage A answers one question: does this indicator refer to an "
         "existing resource? It is the part of the system that directly "
         "addresses H1, and it is the part that has no counterpart in the "
         "phishing-detection literature reviewed in Chapter 2, because that "
         "literature assumes the URL already exists.")
    heading(doc, "3.4.1 Indicator extraction and normalisation", 3)
    body(doc,
         "The extractor accepts both full URLs and bare hostnames, because "
         "language models frequently list a domain without a scheme. It "
         "normalises defanged forms, including bracketed dots and the hxxp "
         "convention, before parsing. Normalisation is important for "
         "measurement as well as for verification: an indicator that is "
         "defanged in the answer is still an indicator, and excluding it would "
         "understate the hallucination rate. Duplicate indicators are removed "
         "while order is preserved, and each indicator is retained together "
         "with the sentence that introduced it, because the claim verifier "
         "needs the surrounding text.")

    heading(doc, "3.4.2 Existence checks", 3)
    body(doc,
         "The workflow is shown in Figure 3.3. Five checks are combined. The "
         "first is structural. Indicators with unsupported schemes, embedded "
         "credentials, IP-literal hosts in place of a domain name, or names "
         "under the reserved top-level domains of RFC 2606 and RFC 6761 are "
         "flagged immediately [CITE:rfc2606][CITE:rfc6761]. These rules do not "
         "prove non-existence in general, but a name under a reserved "
         "top-level domain can never resolve in the public name system, so it "
         "can be classified without a network call.")
    add_figure(doc, fig_dir / "figure_3_3_stage_a_flow.png",
               "Figure 3.3: Stage A referential verification workflow",
               width_cm=12.4)
    body(doc,
         "The second check is a Domain Name System (DNS) lookup for address "
         "records. A successful resolution is strong evidence that the "
         "hostname exists, although it does not prove that the specific page "
         "exists. A negative answer is treated as evidence only when it is "
         "consistent across independent resolvers, because a single resolver "
         "may be cached, filtered, or misconfigured. The implementation "
         "records the answers separately so that disagreement is visible "
         "rather than averaged away.")
    body(doc,
         "The third check queries WHOIS and, when available, the Registration "
         "Data Access Protocol for a registration record [CITE:rfc3912]"
         "[CITE:rdap]. A registration record proves that the domain is "
         "registered even when resolution is temporarily unavailable. WHOIS "
         "is queried first because it is widely supported; RDAP is used as a "
         "structured fallback. The fourth check performs a Hypertext Transfer "
         "Protocol (HTTP) request against the exact page. A definitive success "
         "means the page is reachable. A 404 or 410 on a deep path is evidence "
         "that the page was removed or invented. An ambiguous response "
         "triggers one GET request, which distinguishes a genuine missing page "
         "from a web application firewall response.")
    body(doc,
         "The fifth check compares the indicator with a local reference store "
         "using term frequency-inverse document frequency similarity. The "
         "store contains previously verified pages and known official domains. "
         "Its role is supportive rather than decisive: high similarity "
         "increases confidence that the page exists, while low similarity does "
         "not prove that it does not. The outputs of the five checks are "
         "combined into an existence result with three values: exists, does "
         "not exist, or uncertain. The uncertain value carries the list of "
         "checks that failed and the reason for each failure.")

    heading(doc, "3.4.3 Uncertainty and the blocked-page case", 3)
    body(doc,
         "The distinction between a missing page and a blocked page is "
         "important. Many content delivery networks and web application "
         "firewalls return a generic 404 or 403 to automated clients even when "
         "the site root exists. During development, the root page of a "
         "national regulator returned a 404 to scripted requests while "
         "resolving correctly in DNS and carrying a valid registration "
         "record. Treating that response as a missing page produced a false "
         "hallucination verdict and a false re-registration alert. The final "
         "design therefore treats a 404 on the site root, accompanied by DNS "
         "and registration evidence, as a blocked-by-host outcome rather than "
         "a missing page. A 404 on a deeper path remains evidence of a missing "
         "page.")
    body(doc,
         "The blocked-page handling is an instance of a general rule that "
         "governs the whole system: a negative observation is accepted only "
         "when the observation itself is trustworthy. This rule is what "
         "prevents the system from converting its own failures into findings "
         "about the model. It also explains why the existence result has three "
         "values rather than two. A two-valued design would force the "
         "uncertain case into either exists or does not exist, and both "
         "choices would mislead the analyst.")

    heading(doc, "3.5 Descriptive Hallucination Detection", 2)
    body(doc,
         "Stage A passes every genuine URL, including a genuine URL that the "
         "model has described falsely. A model can write that a bank's real "
         "homepage is a credential-harvesting kit, or that a sinkholed domain "
         "is an active campaign site. The indicator exists, so the referential "
         "check succeeds, yet the sentence is wrong. This is H2, and it "
         "requires a different mechanism.")
    heading(doc, "3.5.1 Attaching claims to indicators", 3)
    body(doc,
         "The claim verifier operates on the sentence or sentences that "
         "introduced each indicator. Sentence boundaries are detected with a "
         "split rule that preserves URLs, because a URL contains periods and "
         "slashes but not the period-space pattern of a sentence boundary. "
         "When an indicator is introduced in a list, the nearest preceding "
         "sentence that names the indicator is used, with the list header as a "
         "fallback. This produces a claim context for each indicator rather "
         "than for the answer as a whole, which is necessary because a single "
         "answer may contain one accurate description and one false one.")
    body(doc,
         "The verifier performs no network calls of its own. It consumes the "
         "evidence that Stage A and Stage B have already collected: existence, "
         "registration age, feed verdicts, page signals, and the "
         "official-domain table. This design has three benefits. It adds no "
         "latency, because the evidence already exists. It cannot be "
         "rate-limited, because it makes no requests. And it cannot contradict "
         "the evidence that the rest of the system is using, because it reads "
         "the same evidence. The claim stage is therefore an interpretation "
         "layer over collected evidence rather than a second, independent "
         "pipeline.")

    heading(doc, "3.5.2 Claim types and verdicts", 3)
    body(doc,
         "Four claim types are recognised, each corresponding to a kind of "
         "assertion that an analyst might act on. A threat claim asserts that "
         "the indicator is malicious, phishing, a scam, or part of a campaign. "
         "An official claim asserts that the indicator is the genuine or "
         "official page of an organisation. A login claim asserts that the page "
         "is a login or credential-entry page. An attribution claim asserts "
         "that a named source reported the indicator.")
    body(doc,
         "Each claim receives one of four verdicts. Supported means that the "
         "evidence positively backs the claim. Contradicted means that the "
         "evidence positively shows the claim is wrong, for example an "
         "official claim about a domain that the brand does not own, or a login "
         "claim about a page with no password field. Unsupported means that the "
         "evidence neither confirms nor refutes the claim. No claim means that "
         "the sentence asserts nothing checkable about the indicator.")
    body(doc,
         "The verdict vocabulary is asymmetric on purpose. A threat claim with "
         "no feed match is unsupported, never contradicted, because the "
         "absence of a match is not evidence of safety. An official claim "
         "about a domain that is not on the official list is unsupported "
         "rather than contradicted, because the list is not exhaustive and a "
         "new official property may not yet be listed. Only positive evidence "
         "against a claim produces a contradiction. This asymmetry mirrors the "
         "asymmetry of the sources themselves and prevents the claim layer "
         "from laundering missing evidence into a negative finding.")

    heading(doc, "3.5.3 Decision rule", 3)
    body(doc,
         "A contradicted claim can only move the final label toward caution. "
         "If the claim is contradicted and the label was clean, the label "
         "becomes suspicious, and the reason names the contradictory evidence. "
         "A contradicted claim never produces a clean label and never "
         "suppresses a phishing verdict. A supported claim does not by itself "
         "make a URL safe, because a correct description of a hostile page is "
         "still a description of a hostile page. An unsupported claim leaves "
         "the label unchanged and is recorded as a gap. This one-directional "
         "rule is a deliberate safety property: the claim layer can add "
         "caution but cannot remove it.")

    heading(doc, "3.5.4 Boundaries of temporal and attribution detection", 3)
    body(doc,
         "H3 and H4 are detected only where the integrated evidence supports "
         "them. Temporal hallucination is approximated by comparing the "
         "registration age and the current threat status with the tense and "
         "recency language of the sentence. A domain registered years ago and "
         "still resolving cannot be a campaign site created last week, and a "
         "domain that no longer resolves cannot be an active campaign site "
         "today. These checks catch clear cases but cannot establish the state "
         "of a domain at an arbitrary past date, because the system has no "
         "historical resolution record.")
    body(doc,
         "Attribution hallucination is approximated by checking whether the "
         "named source is integrated and whether it returns a record. If a "
         "sentence claims that a source reported an indicator and the source "
         "is not configured, the claim is unsupported and the gap is recorded. "
         "If the source is configured and returns no record, the claim is "
         "unsupported rather than contradicted, for the same reason that a "
         "missing feed match is not proof of safety. The system does not "
         "attempt to verify attributions to sources it cannot query, and "
         "Chapter 5 states this as a limitation rather than claiming coverage "
         "that does not exist.")

    heading(doc, "3.6 Stage B: Threat Verification", 2)
    body(doc,
         "Stage B answers the second question: given that the indicator exists "
         "and its description has been checked, what is its current threat "
         "status? The workflow is shown in Figure 3.4. The stage combines "
         "threat-intelligence verdicts, a read-only page inspection, domain "
         "age, and an internal risk score. The first three are evidence about "
         "the world; the fourth is a ranking aid. The distinction matters for "
         "the interpretation of the results in Chapter 4.")
    add_figure(doc, fig_dir / "figure_3_4_stage_b_flow.png",
               "Figure 3.4: Stage B claim and threat verification workflow",
               width_cm=12.4)

    heading(doc, "3.6.1 Threat-intelligence evidence", 3)
    body(doc,
         "Four services are integrated: VirusTotal [CITE:virustotal], Google "
         "Safe Browsing [CITE:gsb], URLhaus [CITE:urlhaus], and urlscan.io "
         "[CITE:urlscan]. Each client returns one of three states. Positive "
         "means that the service explicitly lists the URL or its domain as "
         "malicious. Negative means that the service answered and did not list "
         "it. Unavailable means that the key is missing, the quota is "
         "exhausted, the request timed out, or the response could not be "
         "parsed. Only positive and negative states enter the risk "
         "calculation. Unavailable states are recorded in the coverage metric "
         "and surfaced to the user.")
    body(doc,
         "The clients enforce timeouts and retry limits. A timeout is treated "
         "as unavailable, not as negative. Responses are parsed defensively, "
         "because a service may return an error page with a success status "
         "code or a schema that differs from the documentation. When parsing "
         "fails, the status is unavailable and the raw response is retained "
         "for diagnosis. This posture was validated with tests that simulate "
         "malformed responses, expired keys, and rate-limit errors.")

    heading(doc, "3.6.2 Read-only page inspection", 3)
    body(doc,
         "The login-page inspection is performed only for indicators that "
         "exist and only when the returned page contains a password field. The "
         "inspector checks whether the form submits to a different origin, "
         "whether the page redirects to a different domain after loading, and "
         "whether the visible brand name conflicts with the hostname. A page "
         "that sends credentials to another origin, or that presents a brand it "
         "does not own, is treated as a hard failure. The inspection is "
         "read-only: no credentials are submitted, no JavaScript is executed, "
         "and no form is completed.")
    body(doc,
         "The inspector is deliberately conservative. A page that renders its "
         "form client-side will show no password field in the returned HTML, "
         "and a site that cloaks automated clients may serve different content "
         "than it serves a browser. In both cases the absence of a signal is "
         "recorded as inconclusive rather than as evidence of legitimacy. The "
         "inspector therefore contributes positive evidence when it finds a "
         "signal and remains silent when it does not.")

    heading(doc, "3.6.3 Internal risk scorer", 3)
    body(doc,
         "A feature-based scorer is retained as an implementation component. "
         "It converts the normalised URL into thirty numeric features and "
         "combines a Random Forest and an XGBoost model [CITE:breiman2001]"
         "[CITE:chen2016]. The features are grouped in Table 3.2. The length "
         "and structure group captures the observation that phishing URLs tend "
         "to be longer and deeper than legitimate URLs. The character group "
         "captures the use of digits, hyphens, underscores, and the at-symbol "
         "to construct deceptive hostnames. The anomaly group captures "
         "IP-literal hosts, punycode, double slashes after the scheme, and "
         "security-related keywords. The brand group captures whether a "
         "protected brand appears in the hostname and whether it appears on a "
         "domain the brand does not own. The similarity group captures edit "
         "distance and segment-level lookalike patterns.")
    table_caption(doc, "Table 3.2: Features used by the internal risk scorer")
    add_table(doc, ["Group", "Count", "Features"],
              [("Length and structure", "8", "URL length, hostname length, "
                "path length, query length, number of query parameters, token "
                "count, TLD length, subdomain count"),
               ("Character composition", "7", "HTTPS flag, digit ratio, "
                "hostname digit ratio, hyphen count, underscore count, "
                "at-symbol count, special-character count"),
               ("Structural anomalies", "5", "Double slash after scheme, "
                "IP-literal host, punycode, suspicious keyword count, "
                "suspicious keyword presence"),
               ("Brand impersonation", "4", "Hostname brand hits, brand "
                "presence, brand on own domain, brand on foreign domain"),
               ("Similarity and lookalike", "6", "Character substitution flag, "
                "minimum Levenshtein distance, maximum domain similarity, "
                "best match is legitimate, near-legitimate lookalike, "
                "segment lookalike count")],
              font_size=8.5, widths=[3.4, 1.4, 10.6], center_cols=[1])
    body(doc,
         "The scorer is an implementation detail and not the research "
         "contribution. It exists because threat feeds are silent precisely "
         "when an indicator is new, and a model trained on URL structure can "
         "rank a silent indicator for attention. Its output is treated as one "
         "soft signal among several, never as a verdict on its own. This "
         "position is reflected in the evaluation: the scorer's corpus metrics "
         "are reported as component validation in Section 4.7, while the "
         "detection and verification results that answer the research "
         "questions are measured on the benchmark of real model output.")
    body(doc,
         "The scorer is trained deterministically. The extractor produces the "
         "same vector for the same URL and requires no network access, which "
         "makes the regression harness reproducible. The Random Forest uses "
         "300 trees, a maximum depth of 30, and balanced class weights. "
         "XGBoost uses 400 estimators, a learning rate of 0.05, a maximum "
         "depth of 6, and a subsample ratio of 0.8. The two probabilities are "
         "averaged, and the result is compared with a threshold of 0.50. "
         "Probability calibration was evaluated with isotonic regression, and "
         "the expected calibration error and Brier score were recorded for "
         "every evaluation set.")

    heading(doc, "3.6.4 Verdict fusion and coverage", 3)
    body(doc,
         "The evidence is fused in two steps. First, a threat score is "
         "computed from the verified threat evidence and the internal risk "
         "score. Second, hard failures and soft failures are counted. A hard "
         "failure is a positive threat-feed match, a suspicious login page, or "
         "a contradicted official claim. A soft failure is a high risk score, "
         "brand impersonation, a domain younger than thirty days, or a claim "
         "that could not be supported. A single relevant failure yields a "
         "possible-phishing verdict; two or more independent failures yield a "
         "phishing verdict.")
    body(doc,
         "A clean verdict requires both a low threat score and sufficient "
         "coverage. Coverage is the number of configured sources that actually "
         "answered for this indicator. When coverage is insufficient, the "
         "result is reported as no phishing found with limited checks rather "
         "than as safe. The interface never displays the word safe for such a "
         "result, because the word would overstate what the evidence "
         "supports.")
    body(doc,
         "Official domains are handled by an allowlist, but the allowlist is "
         "not a safe harbour. An allowlisted domain bypasses the lexical "
         "suspicion rules, because legitimate banking and government domains "
         "often contain hyphens and numeric segments. It does not bypass the "
         "exact-page check, the threat-feed check, the claim check, or the "
         "page inspection. This design reflects the fact that an official "
         "domain can host a compromised subdirectory, a user-generated page, "
         "or an open redirect. The allowlist reduces false alarms without "
         "suppressing evidence.")

    heading(doc, "3.7 Real-Time Execution Model", 2)
    body(doc,
         "The sequential pipeline is correct but not interactive. A "
         "five-indicator answer means five serial existence probes, then five "
         "serial verification rounds, and a single slow source delays every "
         "indicator behind it. Because the title of the study claims real-time "
         "operation, the latency had to be reduced and then measured. The "
         "execution model that achieves this is shown in Figure 3.5.")
    add_figure(doc, fig_dir / "figure_3_5_realtime_execution.png",
               "Figure 3.5: Real-time execution model with fan-out, deadline, "
               "and streaming", width_cm=12.4)

    heading(doc, "3.7.1 Concurrent fan-out", 3)
    body(doc,
         "Independent indicators are verified concurrently, one worker per "
         "indicator, with a default of six workers. The worker pool is bounded "
         "because the external services impose quotas and because unbounded "
         "concurrency would convert a latency problem into a rate-limit "
         "problem. Only the per-indicator work is parallelised. The checks "
         "inside one indicator are sequential where they depend on each other, "
         "because Stage B cannot begin before Stage A has established that the "
         "indicator exists.")
    body(doc,
         "Concurrency must not change the verdict. Overlapping independent "
         "indicators should reduce wall-clock time without altering the "
         "evidence that is combined for any one of them. The pipeline object is "
         "shared across workers only for read-only resources, and the cache is "
         "a plain dictionary whose operations are atomic under the interpreter. "
         "Any difference in outcome between the sequential and concurrent runs "
         "would indicate a race or a shared-state defect, so the latency "
         "experiment compares the verdicts as well as the times.")

    heading(doc, "3.7.2 Hard deadline and honest degradation", 3)
    body(doc,
         "A report must return by a wall-clock deadline even when a worker is "
         "still waiting on a slow service. The default deadline is 45 seconds. "
         "When the deadline expires, an unfinished indicator is returned with "
         "the label Suspicious, a flag recording that the deadline was "
         "exceeded, and a reason stating that verification was incomplete. It "
         "is not returned as clean. This is the only defensible choice under "
         "the rule that a missing check must never be read as a pass, and the "
         "reason text preserves the further distinction that incomplete is a "
         "coverage failure rather than evidence of phishing.")
    body(doc,
         "The deadline also bounds the failure of a single indicator. A worker "
         "that raises an exception is converted into the same incomplete "
         "result, with the exception type recorded, so that one malformed "
         "indicator cannot sink the report. The remaining indicators continue "
         "and the analyst receives a partial report that states which "
         "indicators were completed.")

    heading(doc, "3.7.3 Bounded caching", 3)
    body(doc,
         "Repeated lookups of the same URL are served from an in-memory cache "
         "with a lifetime of 300 seconds. The lifetime is a compromise between "
         "speed and currency: threat status can change within minutes, so a "
         "cached verdict is reused only inside a window short enough to be "
         "defensible, and the evaluator uses a fresh pipeline for each "
         "measurement so that a warm cache cannot flatter the result. The cache "
         "is bounded in size so that a long session cannot exhaust memory, and "
         "eviction is oldest-entry-first.")
    body(doc,
         "Caching introduces an obligation to disclose. A fast response caused "
         "by a cache hit is not the same as a fast response caused by an "
         "efficient check, and the report distinguishes the two. This matters "
         "for the honesty of the latency claim in Chapter 4: the reported "
         "improvement is attributed to concurrency, because the experiment "
         "controls for the cache, rather than to reuse.")

    heading(doc, "3.7.4 Streaming verdicts", 3)
    body(doc,
         "The concurrent verifier exposes a callback that fires as each "
         "indicator completes. The application uses it to display a progress "
         "line naming the latest indicator and its label, so the first verdict "
         "is visible before the slowest check has finished. The callback "
         "executes on the calling thread inside the completion loop, which "
         "keeps the interface update single-threaded and avoids the "
         "thread-safety problems that would arise from touching the interface "
         "from a worker.")
    body(doc,
         "Streaming changes what the analyst can do with the system. Instead "
         "of waiting for a complete report, the analyst can begin reviewing the "
         "first indicator while the rest are still being checked. It also "
         "produces a measurement that a report-level timing hides: the time to "
         "the first verdict. That quantity is recorded alongside the "
         "report-level latency and the per-indicator distribution.")

    heading(doc, "3.7.5 Latency measurement", 3)
    body(doc,
         "Latency is measured with a harness that runs the same indicator set "
         "twice: once sequentially and once concurrently, using the same "
         "pipeline configuration and a fresh pipeline for each mode. The "
         "harness records the report latency, the per-indicator median and 95th "
         "percentile, the time to first verdict, the number of completed "
         "checks, and the label assigned to each indicator. The comparison of "
         "labels across modes is a correctness check on the concurrency, not "
         "only a performance measurement.")
    body(doc,
         "The benchmark uses eight indicators, six workers, and two rounds per "
         "mode, with a 90-second ceiling so that the deadline does not censor "
         "the slow sequential baseline. The default 45-second deadline is "
         "retained in the application, because it is the value an analyst would "
         "experience. The distinction between the experimental ceiling and the "
         "operational default is reported with the results rather than "
         "concealed.")

    heading(doc, "3.8 Development and Testing", 2)
    heading(doc, "3.8.1 Benchmark of real model output", 3)
    body(doc,
         "The benchmark is the evidential core of the study, because a "
         "synthetic set cannot establish how a deployed model behaves. A fixed "
         "set of forty threat-intelligence prompts was written across six "
         "categories: Malaysian banking brands, international brands, explicit "
         "indicator-of-compromise requests, recency questions, attribution "
         "questions, and control questions that ask for official pages. Each "
         "prompt was submitted to the deployed model, Gemini, and every answer "
         "was stored verbatim in a resumable JSON Lines file together with the "
         "prompt identifier, category, latency, and error status.")
    body(doc,
         "The provider's free tier permits twenty generation requests per day. "
         "The first fifteen answers were collected within that quota and cover "
         "three of the six categories: eight Malaysian banking prompts, six "
         "global-brand prompts, and one indicator-of-compromise prompt. The "
         "remaining prompts could not be completed on the same day and are "
         "treated as pending rather than as missing data. The study reports the "
         "achieved sample size explicitly and interprets the result as a "
         "structured sample of model behaviour, not as a population estimate.")
    body(doc,
         "Indicators were extracted from each answer with the same extractor "
         "used by the system, so that the benchmark and the verifier agree on "
         "what counts as an indicator. Existence labels were assigned "
         "independently of the system under test. Each domain was queried "
         "through two public DNS-over-HTTPS resolvers, Google and Cloudflare, "
         "and a name was labelled non-existent only when both returned "
         "NXDOMAIN. A name that resolved on either resolver was labelled "
         "existing. This consensus rule avoids depending on a single resolver "
         "and avoids treating a transient failure as a label. The labels, the "
         "prompts, the raw answers, and the summary are written to disk so that "
         "the measurement can be audited and repeated.")
    body(doc,
         "The benchmark produced 123 unique indicators from fifteen answers. "
         "Of these, 83 did not exist, a rate of 67.5 per cent, and fourteen of "
         "the fifteen answers contained at least one non-existent indicator. "
         "These figures define the base rate against which detection is "
         "evaluated in Chapter 4. They also justify the ordering of the stages: "
         "when two thirds of the indicators do not exist, a system that begins "
         "with threat reputation is spending most of its effort on resources "
         "that have no owner.")

    heading(doc, "3.8.2 Stress set and component corpora", 3)
    body(doc,
         "Two further datasets support the evaluation, and their roles are kept "
         "distinct from the benchmark. The first is a stress set of 200 "
         "synthetic lookalike names under the reserved top-level domains. These "
         "names are generated locally, not by a language model, and they exist "
         "to exercise the structural rules and the pipeline under a known "
         "ground truth. They are useful for regression testing and useless for "
         "estimating how often a model invents an indicator, because they were "
         "never produced by a model.")
    body(doc,
         "The second is the public PhiUSIIL corpus of labelled legitimate and "
         "phishing URLs [CITE:prasad2024]. It is used only to train and "
         "validate the internal risk scorer described in Section 3.6.3. The "
         "corpus contains 220,280 rows, partitioned by registrable domain so "
         "that the same domain cannot appear in both training and test data. "
         "The real-but-misdescribed category contains three URLs that exist and "
         "were described incorrectly in generated text; it is retained because "
         "it documents the H2 case that the claim verifier is designed to "
         "catch. Table 3.3 reports the composition.")
    table_caption(doc, "Table 3.3: Corpus composition and domain-grouped "
                       "partitions")
    add_table(doc, ["Category", "Rows", "Training", "Validation", "Test"],
              [("Legitimate", "134,820", "94,213", "20,331", "20,276"),
               ("Phishing", "85,257", "59,841", "12,681", "12,735"),
               ("Reserved-TLD stress names (synthetic)", "200", "139", "30",
                "31"),
               ("Real but misdescribed", "3", "3", "0", "0"),
               ("Total", "220,280", "154,196", "33,042", "33,042")],
              font_size=9, widths=[5.0, 2.4, 2.6, 2.6, 2.6],
              center_cols=[1, 2, 3, 4], first_col_bold=True)
    body(doc,
         "The stress names were excluded from scorer training. Training a "
         "scorer on non-existent URLs would teach it to conflate existence with "
         "maliciousness, which is the confusion the study exists to prevent. "
         "The scorer is trained only on URLs that exist, and the referential "
         "question is answered exclusively by Stage A. The separation is "
         "enforced in the data preparation code and checked by a test that "
         "asserts the category composition of each partition.")
    body(doc,
         "A second training variant was created to test the effect of leakage "
         "removal. The variant removed 5,513 domains that appeared in the "
         "regression set or in the Malaysian hold-out set. The resulting "
         "training set contained 92,295 rows with a phishing share of 63.79 per "
         "cent, and it was evaluated on a domain-grouped internal set of 23,030 "
         "rows. The deployed scorer and the variant are reported separately in "
         "Chapter 4 so that the effect of leakage control is visible.")

    heading(doc, "3.8.3 Integrated evidence sources", 3)
    body(doc,
         "Each external source is wrapped in a client module with a uniform "
         "interface. The client returns a normalised verdict, a confidence "
         "value, a short explanation, and a status. The uniform interface "
         "allows the fusion logic to treat sources consistently and allows a "
         "source to be replaced without changing the decision rules. Table 3.4 "
         "lists the integrated sources and their failure behaviour.")
    table_caption(doc, "Table 3.4: Integrated sources and failure handling")
    add_table(doc, ["Source", "Purpose", "Credential",
                    "Behaviour when unavailable"],
              [("Gemini", "Generator of the intelligence under verification",
                "GEMINI_API_KEY", "The request is rejected with a clear "
                "message; no indicators are invented locally."),
               ("VirusTotal", "URL and domain reputation", "VIRUSTOTAL_API_KEY",
                "Marked unavailable; excluded from coverage."),
               ("Google Safe Browsing", "Unsafe-resource blocklist",
                "GOOGLE_SAFE_BROWSING_KEY", "Marked unavailable; excluded "
                "from coverage."),
               ("URLhaus", "Malware distribution URLs", "URLHAUS_AUTH_KEY",
                "Marked unavailable; excluded from coverage."),
               ("urlscan.io", "Search-only page observations",
                "URLSCAN_API_KEY", "Marked unavailable; excluded from "
                "coverage."),
               ("WhoisXML", "Domain age", "WHOISXML_API_KEY",
                "Falls back to WHOIS and RDAP."),
               ("Reference store", "Offline similarity comparison", "None",
                "Always available; similarity is supportive only."),
               ("SQLite", "Audit log and history", "None",
                "Verification fails loudly rather than losing the record.")],
              font_size=8.5, widths=[2.8, 4.4, 3.6, 4.6], first_col_bold=True)
    body(doc,
         "The decision to integrate only sources with available credentials was "
         "deliberate. A source that cannot be queried cannot contribute "
         "evidence, and including it in the coverage denominator would "
         "understate the completeness of the remaining checks. Services that "
         "were considered but not integrated are documented in the limitations "
         "rather than presented as active components.")

    heading(doc, "3.8.4 Test strategy", 3)
    body(doc,
         "Testing followed a layered strategy, summarised in Table 3.5. Unit "
         "tests verify individual functions such as normalisation, feature "
         "extraction, claim detection, and risk fusion. Integration tests "
         "exercise the pipeline with stubbed network clients, so that the "
         "decision logic can be tested without consuming quotas. Contract tests "
         "verify that the interface displays the approved label strings and "
         "that forbidden strings such as an unqualified safe label do not "
         "appear. Real-time tests verify that the deadline returns a result for "
         "every indicator and that an unfinished indicator is never labelled "
         "clean.")
    table_caption(doc, "Table 3.5: Test areas and representative checks")
    add_table(doc, ["Area", "Representative checks", "Purpose"],
              [("Stage A uncertainty", "DNS failure, WHOIS success, blocked "
                "root, page 404", "Existence is neither assumed nor collapsed "
                "into safety."),
               ("Claim verification", "Threat, official, login, and "
                "attribution claims; hedged sentences",
                "A false description is detected without network access."),
               ("Real-time execution", "Deadline expiry, worker exception, "
                "duplicate indicators",
                "No unfinished check is labelled clean."),
               ("Community review and UI", "Pending state, approved override, "
                "label mapping", "The interface cannot overstate certainty."),
               ("Data split and labels", "Domain overlap, leakage removal, "
                "DoH consensus", "Evaluation is not inflated by leakage.")],
              font_size=8.5, widths=[3.6, 6.6, 6.2], first_col_bold=True)
    body(doc,
         "The suite contains 214 test cases across twenty-two test modules. "
         "The count exceeds the number of test functions because several tests "
         "are parameterised over multiple inputs. The suite is executed before "
         "every change and completes in approximately nine seconds.")

    heading(doc, "3.8.5 Regression harness and deployment", 3)
    body(doc,
         "The regression harness scores a fixed set of 94 labelled URLs, 50 "
         "phishing and 44 legitimate, drawn from a community phishing feed, the "
         "Malaysian hold-out set, verified official sources, and the review "
         "queue. The domains are removed from training. In the full mode a "
         "link that does not resolve is labelled Hallucination and counts as "
         "flagged, because it is not a clean outcome. The classifier mode scores "
         "only the internal risk scorer, and the two modes answer different "
         "questions and are reported separately.")
    body(doc,
         "The application is deployed as a local Streamlit service. A source "
         "whose key is absent is disabled at startup and excluded from the "
         "coverage calculation. The database and the review workbook are stored "
         "inside the local project folder, and the application exposes no public "
         "upload or download endpoint for either artefact.")

# Measured live-model metrics# Measured live-model metrics (docs/fyp/current_metrics.json).
METRICS = {
    "phiusiil": dict(
        name="PhiUSIIL test (live models/)", n=33011, n_legit=20276, n_phish=12735,
        acc=0.9048, prec=0.9999, rec=0.7534, spec=1.0000,
        f1=0.8593, auc=0.9981, tn=20275, fp=1, fn=3141, tp=9594,
        ece=0.10194, brier=0.065595),
    "malaysia": dict(
        name="Malaysia hold-out (live models/)", n=28, n_legit=18, n_phish=10,
        acc=0.8214, prec=0.6923, rec=0.9000, spec=0.7778,
        f1=0.7826, auc=0.9611, tn=14, fp=4, fn=1, tp=9,
        ece=0.171227, brier=0.110261),
    "regression": dict(
        name="Regression set (live models/)", n=94, n_legit=44, n_phish=50,
        acc=0.9149, prec=0.8889, rec=0.9600, spec=0.8636,
        f1=0.9231, auc=0.9795, tn=38, fp=6, fn=2, tp=48,
        ece=0.09464, brier=0.061256),
}
for _m in METRICS.values():
    _m["recall"] = _m["rec"]
    _m["specificity"] = _m["spec"]
    _m["precision"] = _m["prec"]

# Measured benchmark profile (data/llm_output/benchmark_summary.json).
BENCHMARK_SUMMARY = {
    "answers": 15,
    "prompts_total": 40,
    "indicators": 123,
    "nonexistent": 83,
    "existing": 40,
    "answers_with_hallucination": 14,
    "by_category": {
        "malaysian_banking": {"indicators": 65, "exists": 15,
                              "nonexistent": 50},
        "global_brands": {"indicators": 49, "exists": 19, "nonexistent": 30},
        "ioc_request": {"indicators": 9, "exists": 6, "nonexistent": 3},
    },
}

# Measured H1 detection (docs/fyp/benchmark_detection.json).
DETECTION = {
    "tp": 83, "fp": 0, "tn": 40, "fn": 0,
    "recall": 1.0000, "precision": 1.0000, "specificity": 1.0000,
    "accuracy": 1.0000, "abstain": 0,
    "p50_ms": 1793, "p95_ms": 8236, "max_ms": 13156,
    "prefix_tp": 81, "prefix_fn": 2, "prefix_recall": 0.9759,
}

# Measured claim profile (docs/fyp/benchmark_claims.json).
CLAIMS = {
    "total": 43, "official": 8, "threat": 28, "attribution": 7, "login": 0,
    "supported": 8, "unsupported": 35, "contradicted": 0,
    "no_claim_indicators": 90, "indicators_with_claims": 33,
    "controls_correct": 10, "controls_total": 10,
}



def chapter4(doc, fig_dir):
    chapter(doc, "CHAPTER 4: RESULTS AND DISCUSSION")

    heading(doc, "4.1 Overview", 2)
    body(doc,
         "This chapter reports the evaluation of the system described in "
         "Chapter 3. It answers the three research questions in turn: how "
         "hallucinated indicators in model output can be detected, whether a "
         "genuine indicator can be distinguished from a hallucinated one and "
         "from a falsely described one, and how the resulting system compares "
         "with single-stage classification and with manual verification in "
         "both accuracy and speed.")

    heading(doc, "4.2 Experimental Setup", 2)
    body(doc,
         "All measurements were taken on a single Windows workstation. The "
         "system was implemented in Python 3.14, the interface in Streamlit, "
         "the audit log in SQLite, and the review workbook in openpyxl. The "
         "configuration is summarised in Table 4.1. Two values deserve "
         "emphasis because they bound the claims made later. The benchmark "
         "labels were assigned by consensus between two public resolvers, "
         "Google and Cloudflare, and a name was labelled non-existent only "
         "when both returned NXDOMAIN. The real-time experiment used a "
         "90-second ceiling so that the deadline would not censor the slow "
         "sequential baseline, while the application keeps its operational "
         "45-second deadline.")
    table_caption(doc, "Table 4.1: Experimental environment and configuration")
    add_table(doc, ["Item", "Configuration"],
              [("Operating system", "Windows 11, 64-bit"),
               ("Processor and memory", "8 logical cores, 32 GB RAM"),
               ("Language and runtime", "Python 3.14"),
               ("Model under test", "Gemini (gemini-3.6-flash), one version"),
               ("Benchmark labelling", "Google and Cloudflare DoH consensus; "
                "NXDOMAIN on both required"),
               ("Label cross-check", "AdGuard DoH, not used by the detector"),
               ("Stage A concurrency", "8 workers"),
               ("Real-time concurrency", "6 workers, 90 s experimental "
                "deadline, 45 s operational deadline"),
               ("Cache", "300 s time-to-live, fresh pipeline per measurement"),
               ("Risk scorer", "30 features, Random Forest + XGBoost, "
                "threshold 0.50"),
               ("Test suite", "214 automated tests across 22 modules")],
              font_size=9, widths=[4.6, 11.0], first_col_bold=True)

    heading(doc, "4.3 Benchmark of Real Model Output", 2)
    body(doc,
         "The benchmark is the evidential core of the study. Forty "
         "threat-intelligence prompts were written across six categories, and "
         "each prompt was submitted to the deployed model with the answer "
         "stored verbatim. The provider's free tier permits twenty generation "
         "requests per day, so fifteen answers were collected in the first "
         "session, covering three categories: eight Malaysian banking "
         "prompts, six global-brand prompts, and one explicit "
         "indicator-of-compromise prompt. The remaining twenty-five prompts "
         "are pending and are reported as pending, not as missing data.")
    body(doc,
         "The fifteen answers contained 123 unique indicators across 115 "
         "domains. Of these, 83 did not resolve in the public name system, a "
         "rate of 67.5 per cent, and fourteen of the fifteen answers "
         "contained at least one such indicator. Figure 4.1(a) shows the "
         "composition by category. The rates differ: 50 of 65 Malaysian "
         "banking indicators (76.9 per cent) did not exist, compared with 30 "
         "of 49 global-brand indicators (61.2 per cent) and 3 of 9 "
         "indicator-request indicators (33.3 per cent).")
    add_figure(doc, fig_dir / "figure_4_1_benchmark_profile.png",
               "Figure 4.1: Benchmark composition and H1 detection outcome",
               width_cm=12.8)
    body(doc,
         "The rate is an artefact of the condition, not a property of the "
         "model in general. The prompts ask for current indicators, and a "
         "request for current indicators invites plausible-looking "
         "constructions when the model does not know any. The study therefore "
         "reports the rate with its denominator and does not extrapolate it to "
         "ordinary conversation. What matters for the design is the "
         "consequence: under this condition, two thirds of the extracted "
         "indicators refer to nothing, so a pipeline that begins with "
         "reputation is spending most of its effort on resources that have no "
         "owner.")
    table_caption(doc, "Table 4.2: Role of each evaluation artefact")
    add_table(doc, ["Artefact", "Size", "Role in this study"],
              [("Model-output benchmark", "123 indicators, 15 answers",
                "Measures H1 and H2 behaviour on real model output"),
               ("Reserved-TLD stress set", "200 synthetic names",
                "Exercises structural rules; regression only, never presented "
                "as model output"),
               ("PhiUSIIL test partition", "33,011 URLs",
                "Validates the internal risk scorer at scale"),
               ("Malaysian hold-out", "28 URLs",
                "Tests the scorer under distribution shift"),
               ("Regression set", "94 URLs",
                "Detects change after each modification")],
              font_size=9, widths=[4.6, 4.0, 7.0], first_col_bold=True)

    heading(doc, "4.4 Detection of Hallucinated Indicators", 2)
    heading(doc, "4.4.1 Accuracy", 3)
    body(doc,
         "Stage A was run over all 123 indicators with the existence labels "
         "hidden. The results are reported in Table 4.3 and in Figure 4.1(b). "
         "All 83 non-existent indicators were identified as non-existent, all "
         "40 existing indicators were accepted, and no indicator produced an "
         "abstention. Recall, precision, specificity, and accuracy were all "
         "1.0000 on this sample.")
    table_caption(doc, "Table 4.3: Stage A confusion matrix and rates on the "
                       "123-indicator benchmark")
    add_table(doc, ["", "Predicted hallucinated", "Predicted exists"],
              [("Actually hallucinated (n = 83)", "83 (TP)", "0 (FN)"),
               ("Actually exists (n = 40)", "0 (FP)", "40 (TN)"),
               ("Recall", "1.0000", "Abstention 0.0000"),
               ("Precision", "1.0000", "Accuracy 1.0000")],
              font_size=9, widths=[5.6, 4.6, 4.6], center_cols=[1, 2],
              first_col_bold=True)
    body(doc,
         "A perfect score requires an explanation rather than a celebration. "
         "The label asks whether a name resolves in the public name system, "
         "and the detector asks the same question using the same two public "
         "resolvers. The result therefore demonstrates that the "
         "implementation agrees with its own evidence model and produces no "
         "incidental false accusations; it does not demonstrate access to an "
         "independent truth. To test whether the labels were an artefact of "
         "one resolver pair, every indicator was relabelled with AdGuard, a "
         "provider the detector does not consult. The third provider agreed "
         "with all 123 labels. That removes the concern that the labels are "
         "resolver-specific, but it does not remove the shared dependence on "
         "public DNS, because no independent ground truth for name existence "
         "is available.")
    body(doc,
         "The result that is not circular is the comparison with the "
         "single-resolver configuration, because it was measured before the "
         "resolver path was changed and the change was made in response to the "
         "errors. That comparison is reported next.")

    heading(doc, "4.4.2 Error analysis and the local resolver problem", 3)
    body(doc,
         "The first run of Stage A used the operating system resolver and "
         "produced two false negatives out of 83 hallucinated indicators, a "
         "recall of 0.9759. Both were Malaysian banking lookalikes: "
         "touchngo-my.top and maybank2u-my.com. The error log recorded that "
         "both resolved to a live address, so Stage A passed them to Stage B "
         "as existing domains.")
    body(doc,
         "Direct queries explained the discrepancy. Both names returned "
         "NXDOMAIN from Google and from Cloudflare, but the operating system "
         "resolver returned the address 175.139.142.25 with the canonical "
         "name mcmc-redirect.maxis.com.my. That address is a national "
         "blocking page operated by the regulator and the internet service "
         "provider. The local resolver was not reporting that the domain "
         "exists; it was reporting that access to the domain had been "
         "intercepted. A system resolver is therefore not a neutral witness "
         "in the environment where this system is intended to run, and an "
         "existence check that trusts it will report blocked phishing domains "
         "as real.")
    body(doc,
         "The finding has a direct design consequence, and it explains why "
         "the evaluated implementation differs from a naive one. Existence is "
         "now decided by consensus between two public resolvers reached over "
         "HTTPS. If both answer, their agreement decides. If both are "
         "unreachable, the local resolver is used and the reason string says "
         "so. If only one public resolver answers and it reports NXDOMAIN "
         "while the local resolver resolves, the local answer is preferred, "
         "because a single negative is weak evidence and a false hallucination "
         "accusation is the more damaging error. Every one of these branches "
         "is covered by a unit test.")
    body(doc,
         "A second defect surfaced in the same investigation. The WHOIS "
         "client treated any non-empty domain attribute as a registration "
         "record, but the library echoes the queried name even when the "
         "registry answers that the object does not exist. A registered-looking "
         "record was therefore produced for a name that had none, and the "
         "reason string contradicted its own evidence. The parser now "
         "recognises the registry phrases that mean absence, including the "
         "queried object does not exist. After both changes, the same 123 "
         "indicators produced no false negatives and no contradictory reason "
         "strings.")
    body(doc,
         "The correction costs latency. The median Stage A time rose from "
         "1,133 ms to 1,793 ms, an increase of 58 per cent, because two "
         "public resolvers are queried where one local lookup sufficed. The "
         "95th percentile rose from 7,987 ms to 8,236 ms and the maximum from "
         "11,786 ms to 13,156 ms. The increase is accepted: a fast answer "
         "that is wrong about existence is worse than a slower answer that is "
         "right, and the real-time layer hides much of the cost by overlapping "
         "indicators.")

    heading(doc, "4.5 Detection of False Descriptions", 2)
    body(doc,
         "The claim checker was run over the same 123 indicators. It found 43 "
         "checkable claims attached to 33 indicators. The remaining 90 "
         "indicators carried no checkable assertion, usually because the "
         "answer presented them as a bare list under a heading. The profile "
         "is reported in Table 4.4 and Figure 4.2.")
    table_caption(doc, "Table 4.4: Claim types and verdicts on the benchmark")
    add_table(doc, ["Claim type", "Supported", "Unsupported", "Contradicted",
                    "Total"],
              [("Official", "8", "0", "0", "8"),
               ("Threat", "0", "28", "0", "28"),
               ("Attribution", "0", "7", "0", "7"),
               ("Login", "0", "0", "0", "0"),
               ("Total", "8", "35", "0", "43")],
              font_size=9, widths=[5.0, 3.0, 3.2, 3.2, 2.4],
              center_cols=[1, 2, 3, 4], first_col_bold=True)
    add_figure(doc, fig_dir / "figure_4_2_claim_profile.png",
               "Figure 4.2: Claim type and verdict profile", width_cm=12.8)
    body(doc,
         "Two features of the profile matter. First, every official claim was "
         "supported. The eight claims named maybank2u.com.my, paypal.com, "
         "netflix.com, and login.microsoftonline.com, and all four are "
         "properties of the named brand, so the checker confirmed them against "
         "the curated official-domain table. Second, every threat and "
         "attribution claim was unsupported rather than contradicted. This is "
         "by construction in this run: the profile was produced without feed "
         "evidence, so a claim that an indicator is phishing cannot be "
         "positively confirmed, and the checker correctly refuses to treat the "
         "absence of a match as proof that the claim is false.")
    body(doc,
         "No claim was contradicted in this sample. That is a real result "
         "about the sample rather than a property of the checker: the model "
         "described real domains accurately, and its hallucinated domains were "
         "presented as threat indicators rather than as official pages. "
         "Because the contradicted path would otherwise be untested, ten "
         "constructed controls with known expected verdicts were run through "
         "the same function. All ten produced the expected verdict, including "
         "two official claims on brand-fused lookalikes that were contradicted "
         "and one official claim on an unlisted but genuine regional domain "
         "that was left unsupported.")
    body(doc,
         "The controls also document a correction. The first version of the "
         "official check contradicted any official claim whose domain was "
         "absent from the curated list. On the benchmark that produced three "
         "contradictions, two of which were wrong: login.microsoftonline.com "
         "is a genuine single sign-on host, and the phrase real-world was read "
         "as an official claim about a domain that the answer had in fact "
         "described as phishing. The rule was narrowed so that a contradiction "
         "requires the brand to be fused into a compound hostname, as in "
         "paypal-service-update.com, and absence from the list otherwise "
         "yields an unsupported verdict. The curated list was also extended "
         "with the single sign-on domain. The profile reported here is the "
         "post-correction run.")

    heading(doc, "4.6 Real-Time Performance", 2)
    body(doc,
         "The real-time experiment compared a sequential run with a "
         "concurrent run over the same eight indicators, using a fresh "
         "pipeline for each mode so that the 300-second cache could not make "
         "the second mode look faster. Each mode was run twice and the median "
         "is reported. The results are given in Table 4.5 and Figure 4.3.")
    table_caption(doc, "Table 4.5: Sequential and concurrent verification of "
                       "eight indicators")
    add_table(doc, ["Measure", "Sequential", "Concurrent (6 workers)"],
              [("Report latency, median", "52,143 ms", "14,334 ms"),
               ("Per-indicator p50", "5,028 ms", "6,202 ms"),
               ("Per-indicator p95", "14,832 ms", "14,327 ms"),
               ("Time to first verdict", "7,783 ms", "5,385-5,652 ms"),
               ("Indicators completed", "8 of 8", "8 of 8"),
               ("Deadline exceeded", "0", "0"),
               ("Verdicts assigned", "2 limited-coverage, 6 Likely Safe",
                "2 limited-coverage, 6 Likely Safe")],
              font_size=9, widths=[5.8, 4.8, 5.8], center_cols=[1, 2],
              first_col_bold=True)
    add_figure(doc, fig_dir / "figure_4_3_latency.png",
               "Figure 4.3: Report latency and per-indicator latency "
               "distribution", width_cm=12.8)
    body(doc,
         "Concurrency reduced the time to verify eight indicators from 52.1 "
         "seconds to 14.3 seconds, a speed-up of 3.64 times. The gain is "
         "below the theoretical six times because the run is bounded by its "
         "slowest indicator and because the workers contend for the same "
         "network and the same process. The per-indicator median rose from "
         "5.0 to 6.2 seconds, which is the expected cost of that contention, "
         "while the 95th percentile was essentially unchanged at about 14.3 "
         "seconds. Report latency, not per-indicator latency, is the quantity "
         "an analyst experiences, and it is the quantity that improves.")
    body(doc,
         "Two correctness observations accompany the timing. Every indicator "
         "completed inside the deadline and the verdicts were identical in "
         "both modes, so the concurrency did not change the evidence that was "
         "combined. Time to first verdict improved from 7.8 seconds to "
         "between 5.4 and 5.7 seconds, and the interface uses the streaming "
         "callback to display that first verdict while the remaining "
         "indicators are still being checked. The improvement in first-verdict "
         "time is smaller than the improvement in report latency because the "
         "first indicator to finish is close to the slow tail rather than to "
         "the median.")

    heading(doc, "4.7 Component Validation: The Internal Risk Scorer", 2)
    body(doc,
         "The risk scorer is not the research contribution, but it is part of "
         "the implementation and its behaviour must be known. It was evaluated "
         "on the held-out partitions of the PhiUSIIL corpus and on the two "
         "local sets. The results are reported in Table 4.6, and the feature "
         "ranking is shown in Figure 4.4.")
    table_caption(doc, "Table 4.6: Internal risk scorer on three labelled sets")
    add_table(doc, ["Evaluation set", "n", "Accuracy", "Precision", "Recall",
                    "Specificity", "AUC"],
              [("PhiUSIIL test", "33,011", "0.9048", "0.9999", "0.7534",
                "1.0000", "0.9981"),
               ("Malaysian hold-out", "28", "0.8214", "0.6923", "0.9000",
                "0.7778", "0.9611"),
               ("Regression set", "94", "0.9149", "0.8889", "0.9600",
                "0.8636", "0.9795")],
              font_size=8.6, widths=[4.6, 1.6, 2.2, 2.2, 2.0, 2.4, 1.8],
              center_cols=[1, 2, 3, 4, 5, 6], first_col_bold=True)
    add_figure(doc, fig_dir / "figure_4_4_feature_importance.png",
               "Figure 4.4: Top fifteen URL features by mean absolute XGBoost "
               "SHAP contribution", width_cm=12.0)
    body(doc,
         "On the large corpus the scorer almost never accuses a legitimate "
         "URL: one false positive in 20,276 legitimate URLs. Its recall is "
         "0.7534, so one quarter of the phishing URLs in that partition fall "
         "below the threshold. The asymmetry is deliberate. In this "
         "application a false accusation against a bank is more damaging than "
         "a missed lexical signal, because the missed case can still be caught "
         "by a feed, a page check, or a claim contradiction, whereas the false "
         "accusation cannot be recovered by any later stage.")
    body(doc,
         "The local sets are weaker. On the Malaysian hold-out the scorer "
         "reached an accuracy of 0.8214 but a specificity of 0.7778, with four "
         "of eighteen legitimate local URLs scored above the threshold. The "
         "errors are the login pages of well-known banks, whose paths contain "
         "login keywords and whose hostnames contain brand strings that also "
         "appear in phishing. This is distribution shift, and it is the "
         "clearest argument for the allowlist and the claim layer: a lexical "
         "model trained on an international corpus cannot be trusted to judge "
         "a local bank on its own.")
    body(doc,
         "The feature ranking is led by the HTTPS flag, followed by path "
         "length, URL length, digit ratio, domain similarity, hyphen count, "
         "and subdomain count. The prominence of the HTTPS flag is a property "
         "of the corpus rather than a security fact: many phishing hosts in "
         "the corpus did not complete a valid TLS handshake at collection "
         "time, while a phishing site can obtain a certificate. The feature is "
         "kept because it improves ranking, but no single feature can produce "
         "a verdict, and the decision rules ensure that HTTPS alone never "
         "returns a clean result. Brand-similarity features rank lower "
         "globally because most URLs mention no brand, yet they dominate for "
         "the subset that does, which is why the interface explains the "
         "features that fired for the specific URL rather than quoting the "
         "global ranking.")
    body(doc,
         "The scorer results are reported as component validation for a "
         "reason. PhiUSIIL contains URLs that exist; it contains no hallucinated "
         "indicators and no false descriptions. A high score on it says that "
         "the lexical prior is sound, not that the system detects "
         "hallucination. Mixing the two would repeat the category error that "
         "the study is designed to remove.")

    heading(doc, "4.8 Comparison with Single-Stage Detection", 2)
    body(doc,
         "The most direct comparison is with the same scorer used as a "
         "single-stage detector. Because a classifier has no existence gate, "
         "it must return a maliciousness judgement for every indicator, "
         "including the 83 that refer to nothing. On the benchmark it labelled "
         "38 of those 83 as phishing and 45 as not phishing. Neither answer is "
         "meaningful: the first accuses a domain that has no owner, and the "
         "second reports no phishing found for a link that does not exist. "
         "Every hallucinated indicator received a threat judgement that the "
         "evidence could not support.")
    table_caption(doc, "Table 4.7: The present system against a single-stage "
                       "classifier on the same 123 indicators")
    add_table(doc, ["Question answered", "Single-stage classifier",
                    "This system"],
              [("Does the indicator exist?", "Not asked",
                "83 of 83 hallucinated detected"),
               ("Is a hallucinated link reported clean?", "45 of 83 (54.2%)",
                "0 of 83"),
               ("Is a real link falsely accused?", "3 of 40 (7.5%)",
                "0 of 40"),
               ("Is the description checked?", "No",
                "43 claims, 8 supported, 35 gaps"),
               ("Is missing evidence a pass?", "No concept of coverage",
                "Reported as a coverage gap"),
               ("Report latency for 8 indicators", "Not measured",
                "14.3 s concurrent")],
              font_size=8.6, widths=[5.6, 5.2, 5.6], first_col_bold=True)
    body(doc,
         "The manual baseline is analytical rather than timed. An analyst "
         "verifying one indicator by hand performs the same operations: a "
         "resolution lookup, a registration lookup, a feed search, a page "
         "visit, and a comparison of the page with the claim. Those operations "
         "take minutes per indicator and cannot be overlapped across "
         "indicators by one person, so a ten-indicator answer is a "
         "twenty-minute task before any writing begins. The system performs "
         "the same operations concurrently and returns a cited verdict in "
         "14.3 seconds for eight indicators while keeping the evidence "
         "inspectable. A timed human baseline was not collected, so the "
         "comparison is a description of the task rather than a measurement, "
         "and Chapter 5 states this plainly.")

# ===========================================================================
# CHAPTER 5
# ===========================================================================

def chapter5(doc):
    chapter(doc, "CHAPTER 5: CONCLUSION AND RECOMMENDATION")

    heading(doc, "5.1 Overview", 2)
    body(doc,
         "This chapter answers the three research questions, reports how each "
         "objective was met, and states the contributions, limitations, and "
         "recommendations.")

    heading(doc, "5.2 Answers to the Research Questions", 2)
    body(doc,
         "The first research question asked what forms of hallucination appear "
         "in LLM-generated phishing threat intelligence and how each can be "
         "detected. The study identified four forms, referential, descriptive, "
         "temporal, and attribution hallucination, and designed detection for "
         "the first two. Referential hallucination was the dominant form in the "
         "benchmark: 83 of 123 indicators (67.5 per cent) did not resolve in "
         "the public name system and 14 of 15 answers contained at least one "
         "such indicator. It is detected by a registration-existence stage "
         "that settles existence against public resolvers before any "
         "reputation is consulted. Descriptive hallucination was detected by "
         "claim checking, which separates a supported assertion from one that "
         "is unsupported or contradicted. Temporal and attribution "
         "hallucination were defined and implemented but not isolated in the "
         "sample, because the benchmark carried no historical records or "
         "independently attributed reports against which to test them. That "
         "is reported as an open result.")
    body(doc,
         "The second research question asked how a hallucinated indicator can be "
         "distinguished from a genuine one, how a false description of a genuine "
         "indicator can be detected, and how threat status can be verified in "
         "real time. A hallucinated indicator was distinguished by existence: all "
         "83 non-existent indicators were identified as non-existent and none "
         "of the 40 existing indicators was rejected. The existence decision is "
         "reached by consensus between two public DNS-over-HTTPS resolvers, "
         "because the local resolver was shown to return a block-page address "
         "for blocked phishing domains. A false description was checked "
         "against the curated evidence: all eight official-domain claims were "
         "supported, and the claim checker distinguished unsupported from "
         "contradicted statements on ten constructed controls, all of which "
         "were correct. Threat status was verified concurrently, and the "
         "verdict always reports which sources were consulted and which failed. "
         "A failed or unconfigured source is recorded as a coverage gap, never "
         "as a clean result.")
    body(doc,
         "The third research question asked how the system compares with "
         "single-stage detection and manual verification in accuracy and speed. "
         "Against a single-stage classifier using the same scorer, the "
         "difference is categorical. The classifier has no existence question, "
         "so it judged all 83 hallucinated indicators: 38 were flagged as "
         "phishing and 45 were reported as not phishing, while the two-stage "
         "system reported none of them as clean. The classifier also flagged "
         "three of 40 real indicators, which the two-stage system did not. "
         "Against manual verification the comparison is in throughput. Verifying "
         "eight indicators concurrently took 14.3 seconds against 52.1 seconds "
         "sequentially, with identical verdicts.")

    heading(doc, "5.3 Achievement of Research Objectives", 2)
    table_caption(doc, "Table 5.1: Achievement of research objectives")
    add_table(doc, ["Objective", "Outcome", "Evidence"],
              [("O1: Taxonomy of hallucination in phishing intelligence and a "
                "labelled benchmark.", "Achieved, with limits.",
                "Four forms (Table 1.1). Benchmark of 123 indicators from 15 "
                "real answers, of 40 planned prompts, within the free-tier "
                "quota (Section 4.3)."),
               ("O2: Real-time detection and verification with explicit "
                "uncertainty.", "Achieved.",
                "Stage A returns exists, hallucinated, or uncertain; Stage B "
                "reports coverage; verdicts are explainable (Chapter 3)."),
               ("O3: Implementation with concurrency, caching, deadlines, "
                "streaming, and audit.", "Achieved.",
                "Concurrent fan-out, 300 s cache, hard deadlines, streamed "
                "verdicts, SQLite audit; 214 automated tests passing."),
               ("O4: Evaluate accuracy, coverage, and p50/p95 latency.",
                "Achieved, with a circularity caveat.",
                "H1 accuracy on 123 indicators; claim profile; Stage A p50 "
                "1,793 ms and p95 8,236 ms; concurrent speed-up 3.64 times "
                "(Chapter 4).")],
              font_size=8.8, widths=[4.6, 3.2, 8.0], first_col_bold=True)

    heading(doc, "5.4 Contributions", 2)
    body(doc,
         "The study contributes a taxonomy that treats hallucination in threat "
         "intelligence as a verification problem, a two-stage architecture in "
         "which existence is settled first and missing evidence is never a pass, "
         "a benchmark of real model output with a comparison against single-stage "
         "detection, and a working prototype with explained, streamed verdicts.")

    heading(doc, "5.5 Limitations", 2)
    body(doc,
         "The principal limitation concerns the H1 result. The benchmark labels "
         "and the detector both rely on public DNS, so the perfect agreement "
         "measured in Chapter 4 demonstrates consistency with the label "
         "construct rather than access to an independent truth. An AdGuard "
         "cross-check agreed on all 123 labels, which removes resolver-specific "
         "error but not the shared dependence on DNS. The non-circular evidence "
         "is the comparison with the earlier single-resolver configuration, "
         "which missed two blocked domains.")
    body(doc,
         "The benchmark is small and unrepresentative: fifteen of forty "
         "planned prompts, three of six categories, one model on one day. "
         "The 67.5 per cent rate describes this condition only.")
    body(doc,
         "The claim checker's H2 performance is not measured. Of 123 indicators, "
         "90 made no checkable claim, and the sample contains no false "
         "description of a real domain labelled independently by a human. The "
         "reported result is that the checker operates and fails safe, not that "
          "its recall or precision is known.")
    body(doc,
         "The full-pipeline regression (94 URLs) gave a phishing recall of 1.00 and a"
         "legitimate specificity of 0.93. Recall counts non-resolving links as flagged,"
         "two false positives are mislabelled, and one is a single-vendor VirusTotal"
         "alarm that remains open.")
    body(doc,
         "The risk scorer was validated on existing URLs only, the page "
         "inspector is read-only, and the system ran on one workstation.")

    heading(doc, "5.6 Recommendations and Future Work", 2)
    body(doc,
         "Four directions are recommended. The benchmark should be completed "
         "across all planned prompts, categories, dates, and model versions. "
         "Existence should be checked against an independent source such as "
         "registry zone data, so that H1 no longer shares evidence with the "
         "detector, and H2 recall and precision should be measured with two "
         "annotators.")


    heading(doc, "5.7 Chapter Summary", 2)
    body(doc,
         "This chapter answered the three research questions. Existence checking "
         "detected referential hallucination, claim checking verified descriptive "
         "hallucination, and the limitations bound both claims.")


# ===========================================================================
# REFERENCES
# ===========================================================================

REFERENCES = {
    "liu2023": 'N. F. Liu, T. Zhang, and P. Liang, "Evaluating verifiability '
               'in generative search engines," in Findings of the Association '
               'for Computational Linguistics: EMNLP 2023, Singapore, 2023, '
               'pp. 7001-7025.',
    "ji2023": 'Z. Ji, N. Lee, R. Frieske, T. Yu, D. Su, Y. Xu, E. Ishii, '
              'Y. Bang, A. Madotto, and P. Fung, "Survey of hallucination in '
              'natural language generation," ACM Computing Surveys, vol. 55, '
              'no. 12, pp. 1-38, 2023.',
    "apwg2024": 'Anti-Phishing Working Group, "Phishing activity trends '
                'report, 4th quarter 2024," APWG, Lexington, MA, USA, 2025.',
    "ic3_2023": 'Federal Bureau of Investigation, "Internet crime report '
                '2023," Internet Crime Complaint Center, Washington, DC, '
                'USA, 2024.',
    "cybersecurity_my": 'CyberSecurity Malaysia, "Malaysia cyber incident '
                        'response centre annual report 2023," CyberSecurity '
                        'Malaysia, Kuala Lumpur, Malaysia, 2024.',
    "mycert2023": 'Malaysian Computer Emergency Response Team, "MyCERT '
                  'quarterly incident statistics 2023," CyberSecurity '
                  'Malaysia, Kuala Lumpur, Malaysia, 2023.',
    "alkhalil2021": 'Z. Alkhalil, C. Hewage, L. Nawaf, and I. Khan, '
                    '"Phishing attacks: A recent comprehensive study and a '
                    'new anatomy," Frontiers in Computer Science, vol. 3, '
                    'art. 563060, 2021.',
    "huang2025": 'L. Huang, W. Yu, W. Ma, W. Zhong, Z. Feng, H. Wang, '
                 'Q. Chen, W. Peng, X. Feng, B. Qin, and T. Liu, "A survey on '
                 'hallucination in large language models: Principles, '
                 'taxonomy, challenges, and open questions," ACM '
                 'Transactions on Information Systems, vol. 43, no. 2, '
                 'pp. 1-55, 2025.',
    "prasad2024": 'A. Prasad and S. Chandra, "PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning," Computers & Security, vol. 136, art. 103545, 2024.',
    "breiman2001": 'L. Breiman, "Random forests," Machine Learning, vol. 45, '
                   'no. 1, pp. 5-32, 2001.',
    "chen2016": 'T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting '
                'system," in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge '
                'Discovery and Data Mining, 2016, pp. 785-794.',
    "rdap": 'Internet Engineering Task Force, "Registration Data Access '
            'Protocol (RDAP) query format," RFC 7482, 2015.',
    "virustotal": 'VirusTotal, "VirusTotal API v3 documentation," 2025. '
                  '[Online]. Available: https://developers.virustotal.com/',
    "gsb": 'Google, "Safe Browsing API (v4) documentation," 2025. [Online]. '
           'Available: https://developers.google.com/safe-browsing/',
    "urlhaus": 'abuse.ch, "URLhaus: Malware URL exchange," 2025. [Online]. '
               'Available: https://urlhaus.abuse.ch/',
    "urlscan": 'urlscan.io, "urlscan.io API documentation," 2025. [Online]. '
               'Available: https://urlscan.io/docs/api/',
    "kuhn2023": 'L. Kuhn, Y. Gal, and S. Farquhar, "Semantic uncertainty: '
                'Linguistic invariances for uncertainty estimation in natural '
                'language generation," in Proc. Int. Conf. Learning '
                'Representations (ICLR), 2023.',
    "farquhar2024": 'S. Farquhar, J. Kossen, L. Kuhn, and Y. Gal, "Detecting '
                    'hallucinations in large language models using semantic '
                    'entropy," Nature, vol. 630, no. 8017, pp. 625-630, 2024.',
    "manakul2023": 'P. Manakul, A. Liusie, and M. J. F. Gales, "SelfCheckGPT: '
                   'Zero-resource black-box hallucination detection for '
                   'generative large language models," in Proc. Conf. Empirical '
                   'Methods in Natural Language Processing (EMNLP), 2023.',
    "min2023": 'S. Min, K. Krishna, X. Lyu, M. Lewis, W.-t. Yih, P. Koh, '
               'M. Iyyer, L. Zettlemoyer, and H. Hajishirzi, "FActScore: '
               'Fine-grained atomic evaluation of factual precision in long '
               'form text generation," in Proc. Conf. Empirical Methods in '
               'Natural Language Processing (EMNLP), 2023.',
    "walters2023": 'W. H. Walters and E. I. Wilder, "Fabrication and errors in '
                   'the bibliographic citations generated by ChatGPT," '
                   'Scientific Reports, vol. 13, art. 14045, 2023.',
    "magesh2024": 'V. Magesh, F. Surani, M. Dahl, M. Suzgun, C. D. Manning, '
                  'and D. E. Ho, "Hallucination-free? Assessing the reliability '
                  'of leading AI legal research tools," arXiv:2405.20362, 2024.',
    "gao2023": 'T. Gao, H. Yen, J. Yu, and D. Chen, "Enabling large language '
               'models to generate text with citations," in Proc. Conf. '
               'Empirical Methods in Natural Language Processing (EMNLP), 2023.',
    "wang2023": 'X. Wang, J. Wei, D. Schuurmans, Q. Le, E. Chi, S. Narang, '
                'A. Chowdhery, and D. Zhou, "Self-consistency improves chain of '
                'thought reasoning in language models," in Proc. Int. Conf. '
                'Learning Representations (ICLR), 2023.',
    "lewis2020": 'P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, '
                 'N. Goyal, H. Kuttler, M. Lewis, W.-t. Yih, T. Rocktaschel, '
                 'S. Riedel, and D. Kiela, "Retrieval-augmented generation for '
                 'knowledge-intensive NLP tasks," in Advances in Neural '
                 'Information Processing Systems, vol. 33, 2020, pp. 9459-9474.',
    "rfc3912": 'L. Daigle, "WHOIS protocol specification," RFC 3912, 2004.',
    "rfc2606": 'D. Eastlake and A. Panitz, "Reserved top level DNS names," '
               'RFC 2606, 1999.',
    "rfc6761": 'M. Cotton, L. Vegoda, and S. Cheshire, "Special-use domain '
               'names," RFC 6761, 2013.'
}


def references(doc):
    from fyp_style import CITATION_ORDER
    chapter(doc, "REFERENCES", bookmark="START_REFERENCES",
            bookmark_id=900)
    # Add the reference list itself as a bookmark target for appendices.
    for i, key in enumerate(CITATION_ORDER, start=1):
        entry = REFERENCES.get(key)
        if entry is None:
            entry = key
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.9)
        p.paragraph_format.first_line_indent = Cm(-0.9)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.0
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = p.add_run(f"[{i}]  {entry}")
        run.font.size = Pt(11)


# ===========================================================================
# APPENDICES
# ===========================================================================

def appendices(doc, fig_dir, meta):
    chapter(doc, "APPENDICES", bookmark="START_APPENDIX", bookmark_id=901)

    heading(doc, "Appendix A: Regression Set Composition and Error Log", 2)
    body(doc,
         "The regression set contains 94 labelled URLs. Its composition is "
         "summarised in Table A.1 and the errors observed in the final "
         "classifier run are listed in Table A.2. The set is fixed and is "
         "removed from training so that the scores remain comparable across "
         "changes.")
    table_caption(doc, "Table A.1: Composition of the regression set")
    add_table(doc, ["Source", "Rows", "Legitimate", "Phishing"],
              [("Community phishing feed", "40", "0", "40"),
               ("Malaysian hold-out", "28", "18", "10"),
               ("Verified official research sources", "14", "14", "0"),
               ("Review queue", "12", "12", "0"),
               ("Total", "94", "44", "50")],
              font_size=9, widths=[6.4, 2.2, 2.8, 2.6],
              center_cols=[1, 2, 3], first_col_bold=True)
    table_caption(doc, "Table A.2: Error log for the final classifier run")
    add_table(doc, ["Truth", "Score", "URL", "Interpretation"],
              [("Legitimate", "0.547", "https://www.maybank2u.com.my/",
                "Bank root; lexical overlap"),
               ("Legitimate", "0.556", "https://www.shopee.com.my/",
                "E-commerce root; lexical overlap"),
               ("Legitimate", "0.852", "https://www.maybank2u.com.my/login",
                "Login path and brand features"),
               ("Legitimate", "0.851", "https://www.cimbclicks.com.my/ib/"
                "Login.jsp", "Login path and brand features"),
               ("Legitimate", "0.624", "https://www.bankrakyat.com.my/",
                "Bank root; lexical overlap"),
               ("Legitimate", "0.764", "https://www.alliancebank.com.my/",
                "Bank root; lexical overlap"),
               ("Phishing", "0.332", "https://cimbclicks.com.my.login-"
                "secure.net", "Concatenated lookalike; weak substitution "
                "signal"),
               ("Phishing", "0.069", "https://www.wecbhsk.com/",
                "Unfamiliar domain; no feed match")],
              font_size=7.6, widths=[2.0, 1.3, 6.6, 5.8],
              center_cols=[0, 1])

    heading(doc, "Appendix B: Feature Dictionary", 2)
    body(doc,
         "Table B.1 defines the thirty features produced by the extractor. "
         "All features are numeric and deterministic. Categorical booleans "
         "are encoded as zero or one.")
    table_caption(doc, "Table B.1: Definitions of the thirty URL features")
    feats = [
        ("Length and structure", "url_length", "Number of characters in the "
         "full URL"),
        ("Length and structure", "hostname_length", "Number of characters in "
         "the hostname"),
        ("Length and structure", "path_length", "Number of characters in the "
         "path"),
        ("Length and structure", "query_length", "Number of characters in the "
         "query string"),
        ("Length and structure", "num_query_params", "Number of query "
         "parameters"),
        ("Length and structure", "token_count", "Number of tokens after "
         "splitting on delimiters"),
        ("Length and structure", "tld_length", "Number of characters in the "
         "top-level domain"),
        ("Length and structure", "subdomain_count", "Number of labels before "
         "the registrable domain"),
        ("Character composition", "is_https", "One if the scheme is HTTPS"),
        ("Character composition", "digit_ratio", "Digits divided by URL "
         "length"),
        ("Character composition", "hostname_digit_ratio", "Digits divided by "
         "hostname length"),
        ("Character composition", "hyphen_count", "Number of hyphens in the "
         "hostname"),
        ("Character composition", "underscore_count", "Number of underscores "
         "in the URL"),
        ("Character composition", "at_symbol_count", "Number of at-symbols in "
         "the URL"),
        ("Character composition", "special_char_count", "Number of "
         "non-alphanumeric characters"),
        ("Structural anomalies", "double_slash_after_scheme", "One if a "
         "double slash appears after the scheme"),
        ("Structural anomalies", "has_ip_address", "One if the host is an IP "
         "literal"),
        ("Structural anomalies", "punycode_present", "One if the host "
         "contains a punycode label"),
        ("Structural anomalies", "suspicious_keyword_count", "Number of "
         "security-related keywords"),
        ("Structural anomalies", "suspicious_keyword_present", "One if any "
         "suspicious keyword is present"),
        ("Brand impersonation", "hostname_brand_hits", "Number of protected "
         "brands found in the hostname"),
        ("Brand impersonation", "brand_present", "One if a protected brand is "
         "present"),
        ("Brand impersonation", "brand_on_own_domain", "One if the brand is "
         "on a domain owned by the brand"),
        ("Brand impersonation", "brand_on_foreign_domain", "One if the brand "
         "is on a domain owned by another party"),
        ("Similarity", "character_substitution_flag", "One if a homoglyph or "
         "digit substitution is detected"),
        ("Similarity", "min_levenshtein_dist", "Minimum edit distance to a "
         "protected brand"),
        ("Similarity", "max_domain_similarity", "Maximum similarity to a "
         "protected brand"),
        ("Similarity", "best_match_is_legit", "One if the closest brand match "
         "is the legitimate domain"),
        ("Similarity", "near_legit_lookalike", "One if the host is close to a "
         "legitimate domain"),
        ("Similarity", "segment_lookalike_count", "Number of hostname "
         "segments that resemble a brand"),
    ]
    add_table(doc, ["Group", "Feature", "Definition"], feats, font_size=7.6,
              widths=[3.4, 4.6, 7.6], first_col_bold=False)

    heading(doc, "Appendix C: Decision Rules", 2)
    body(doc,
         "The decision rules are applied after Stage A and Stage B have "
         "produced their evidence. The rules are listed in order of "
         "precedence. The first matching rule determines the verdict.")
    numbered(doc, [
        "If Stage A concludes that the URL does not exist, the verdict is "
        "Hallucination and Stage B is not executed.",
        "If Stage A is uncertain, the URL is not reported as safe; the "
        "uncertainty is carried into the final verdict.",
        "If an approved community report exists, the verdict is Phishing.",
        "If a threat feed returns a positive match, the verdict is Phishing.",
        "If the login-page inspection detects an external form action, an "
        "off-domain redirect, or a brand mismatch, the verdict is Phishing.",
        "If two or more soft failures are present, the verdict is Phishing. "
        "Soft failures are a high machine-learning score, brand "
        "impersonation, and a domain younger than thirty days.",
        "If exactly one soft failure is present, the verdict is Possible "
        "phishing.",
        "If no failure is present and coverage is sufficient, the verdict is "
        "No phishing found.",
        "If no failure is present but coverage is insufficient, the verdict "
        "is No phishing found with limited checks.",
    ])
    body(doc,
         "Coverage is defined as the fraction of configured sources that "
         "returned a positive or negative verdict. A source that is not "
         "configured, or that returns an unavailable status, is excluded from "
         "both the numerator and the denominator. This definition prevents a "
         "missing key from either inflating or deflating the apparent "
         "completeness of the evidence.")

    heading(doc, "Appendix D: Sample Verification Record", 2)
    body(doc,
         "Table D.1 shows the fields recorded for each verification. The "
         "record is stored in SQLite and rendered by the history page. The "
         "evidence list is serialised so that the reason for a verdict can be "
         "reconstructed even after the model or the rules have changed.")
    table_caption(doc, "Table D.1: Fields of a verification record")
    add_table(doc, ["Field", "Description"],
              [("id", "Monotonic record identifier"),
               ("url", "Normalised URL that was verified"),
               ("label", "Stored label: Malicious, Suspicious, Likely Safe, "
                "Unverified, or Hallucination"),
               ("display_label", "User-facing label after mapping"),
               ("reason", "Plain-language explanation of the verdict"),
               ("evidence", "Serialised list of source verdicts and statuses"),
               ("coverage", "Fraction of configured sources that returned a "
                "verdict"),
               ("model_version", "Identifier of the model artefact used"),
               ("created_at", "Timestamp of the verification")],
              font_size=8.5, widths=[3.4, 12.0], first_col_bold=True)
    body(doc,
         "The record is designed to answer three questions after the fact: "
         "what was decided, why it was decided, and which evidence was "
         "missing. These questions are the minimum required for an audit, and "
         "they are the reason why the system stores evidence rather than only "
         "the final label.")
