"""
app.py - PhishGuard-HDV Streamlit dashboard (light theme).

Single source of truth; `dashboard/app.py` is a thin shim that launches this
same script. The detection pipeline is unchanged (see src/):

    Stage A  - does the LLM-generated URL/domain actually exist?
    Stage B  - given it exists, is there phishing evidence? (RF+XGB + VT/Google Safe Browsing)

This file is now a thin presentation shell: all mapping lives in `ui/status.py`,
all styling in `ui/styles.py`, all components in `ui/components.py`.

Pages:
  1. Verify AI Threat Intelligence - question -> Generate & verify -> results
  2. Analysis History             - SQLite audit log (unchanged logic)
  3. About the System             - unchanged logic
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_SRC = ROOT / "src"
for p in (ROOT, _SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

logger = logging.getLogger("phishguard.app")

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="PhishGuard-HDV",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# On a host (e.g. Streamlit Community Cloud) secrets are provided by the
# platform, not a .env file. Mirror st.secrets into the environment so the
# modules that read os.environ keep working unchanged.
# Handles both flat secrets and nested [sections]. Local runs still use .env
# via python-dotenv. Never commit real keys.
def _load_streamlit_secrets(_src=None) -> None:
    try:
        _src = st.secrets if _src is None else _src
        for _k, _v in dict(_src).items():
            if hasattr(_v, "items"):
                _load_streamlit_secrets(_v)          # nested section
            else:
                os.environ.setdefault(str(_k), str(_v))
    except Exception:
        pass


_load_streamlit_secrets()

import db as src_db
from hallucination_detector import normalise_domain
from pipeline import PhishGuardPipeline
from modules.llm_analyzer import get_llm_analyzer
from modules.url_extractor import extract_urls
from ui import components, status, styles

# One-line, key-free diagnostic so deployment problems are obvious in the logs.
logger.info("Secret keys available: %s",
            " ".join(sorted(k for k in ("GEMINI_API_KEY", "OPENROUTER_API_KEY",
                                        "GOOGLE_SAFE_BROWSING_KEY", "VIRUSTOTAL_API_KEY")
                           if os.environ.get(k))) or "(none)")

styles.inject()

SIDEBAR_STEPS = (
    "AI generates threat intelligence",
    "URLs are extracted",
    "URLs are verified (hallucination check)",
    "Verified URLs are assessed for phishing",
    "Results are explained and logged",
)


# ---------------------------------------------------------------------------
# Shared backend handles (unchanged)
# ---------------------------------------------------------------------------

PIPELINE = st.cache_resource(PhishGuardPipeline)


@st.cache_resource
def _llm():
    # Gemini is the only LLM provider (one attempt per request).
    return get_llm_analyzer()


def _run_url(url: str, source: str = None, llm_model: str = None,
             original_user_question: str = None) -> dict:
    domain = normalise_domain(url)
    earlier = src_db.previous_hallucinations(domain)
    r = PIPELINE().analyze_url(
        url, source=source, llm_model=llm_model,
        original_user_question=original_user_question)
    if earlier and r.get("exists"):
        # Phantom squatting: the AI invented this name earlier, and it now
        # resolves. Someone may have registered it since, so never call it
        # Likely Safe or Unverified.
        r["phantom_squat_alert"] = True
        if r.get("final_label") in ("Likely Safe", "Unverified"):
            r["final_label"] = "Suspicious"
        r["reason"] = (f"{r.get('reason', '')} [Phantom-squatting alert: this domain "
                       f"was reported as not existing on {earlier[0]}, and now "
                       f"resolves - it may have been registered since.]")
    src_db.log_result(r)
    return r


def _run_ai(prompt: str, reason: str = "streamlit:Generate & Verify") -> None:
    """Run ONE LLM generation for this submission, then verify its URLs.

    The generated response is stored in st.session_state so subsequent
    Streamlit reruns render the existing result instead of calling the LLM
    again. There is no automatic retry: a failure is surfaced to the user, who
    may retry manually.
    """
    if not prompt.strip():
        st.warning("Enter a cybersecurity question first.")
        return
    try:
        with st.spinner("Generating threat intelligence, then verifying..."):
            gen = _llm().analyze_threat(prompt, reason=reason)
            analyses = []
            if gen.get("success"):
                for url in extract_urls(gen.get("text", "")):
                    r = _run_url(
                        url, source="LLM_GENERATED",
                        llm_model=gen.get("model"),
                        original_user_question=prompt)
                    analyses.append(r)
            st.session_state["last_ai_result"] = {
                **gen, "analyses": analyses, "question": prompt,
            }
    except Exception:  # pragma: no cover
        # Never surface exception detail (could contain credentials) in the UI.
        logger.exception("Unexpected error in the AI threat-intelligence flow")
        st.error("⚠️ The AI verification flow failed unexpectedly. "
                 "Please try again.")


# ---------------------------------------------------------------------------
# PAGE 1 - Verify AI Threat Intelligence
# ---------------------------------------------------------------------------

def page_verify_ai() -> None:
    st.markdown('<div class="page-title">Verify AI Threat Intelligence</div>',
                unsafe_allow_html=True)
    st.markdown(
        '<div class="page-sub">Ask a cybersecurity question. The AI generates '
        'threat intelligence, and any URLs it mentions are independently checked '
        'for hallucination and phishing evidence.</div>',
        unsafe_allow_html=True)

    prompt = st.text_area(
        "Cybersecurity question",
        placeholder="What phishing threats are targeting Malaysian banking users?",
        height=120,
        key="ai_prompt",
    )

    llm = _llm()
    note = f'Model: <span class="mono">{llm.model_id}</span>'
    if getattr(llm, "fallback", None) is not None and llm.fallback.available:
        note += (f' &nbsp;·&nbsp; fallback: '
                 f'<span class="mono">{llm.fallback_model_id}</span>')
    st.markdown(
        f'<div class="model-note">{note} &nbsp;·&nbsp; you are responsible for '
        f'verifying any generated indicators.</div>',
        unsafe_allow_html=True)

    def _clear_all() -> None:
        # Runs as a callback BEFORE the script re-runs, so the question box can
        # be reset (a widget's key cannot be modified after it is instantiated).
        st.session_state.pop("last_ai_result", None)
        st.session_state["ai_prompt"] = ""
        # Reset every technical-evidence / feature toggle for all URL cards.
        for k in [k for k in st.session_state
                  if k.startswith(("tech_", "techbtn_", "feat_"))]:
            del st.session_state[k]

    has_content = bool(prompt.strip()) or bool(st.session_state.get("last_ai_result"))
    col_gen, col_clear, _ = st.columns([2, 1, 3])
    with col_gen:
        generate = st.button("Generate & verify", type="primary",
                             use_container_width=True)
    with col_clear:
        st.button(
            "Clear", on_click=_clear_all, disabled=not has_content,
            help="Clear the question and results to start a fresh analysis.",
            use_container_width=True)

    # One click -> exactly ONE LLM request. The result is stored in
    # st.session_state, so ordinary reruns re-render it WITHOUT calling the LLM.
    if generate:
        _run_ai(prompt, reason="streamlit:Generate & Verify")

    result = st.session_state.get("last_ai_result")
    if not result:
        st.markdown(
            '<div class="empty">Ask a question above and select '
            '<b>Generate &amp; verify</b> to begin.</div>',
            unsafe_allow_html=True)
        return

    # ---- LLM failure: warn, never fabricate, allow a manual retry ----------
    if not result.get("success"):
        message = result.get("error") or "⚠️ The AI service is unavailable. Please try again."
        components.warning_banner(message)
        st.info(f'Your question was preserved: "{result.get("question")}"')
        if st.button("Retry"):
            _run_ai(result.get("question", ""), reason="streamlit:Manual retry")
        return

    analyses = result.get("analyses") or []
    urls = [a.get("url", "") for a in analyses]

    # Pipeline strip is shown ONCE, not per URL.
    components.pipeline_strip()

    # ---- 01 - AI-generated response ----
    components.section_heading("01", "AI-generated response")
    components.ai_answer_card(
        result.get("text", ""), urls, result.get("model"),
        fallback_used=bool(result.get("fallback_used")))

    # ---- 02 - Verification summary ----
    components.section_heading("02", "Verification summary")
    if analyses:
        st.markdown(components.summary_table(analyses), unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty">No URL indicators were found in the '
                    'generated response.</div>', unsafe_allow_html=True)

    # ---- 03 - URL details ----
    if analyses:
        components.section_heading("03", "URL details")
        for n, a in enumerate(analyses, 1):
            components.url_detail(a, n)


# ---------------------------------------------------------------------------
# PAGE 2 - Analysis History (logic unchanged; labels restyled)
# ---------------------------------------------------------------------------

def _truthy(v) -> bool:
    try:
        if v is None:
            return False
        f = float(v)
        if f != f:  # NaN
            return False
        return bool(int(f))
    except (TypeError, ValueError):
        return False


def _skipped(v) -> str:
    f = status._f(v)
    return "Skipped" if f is None else f"{round(f * 100)}%"


def _clean(row: dict) -> dict:
    return {k: (None if (isinstance(v, float) and v != v) else v)
            for k, v in row.items()}


def _history_reason(row: dict) -> str:
    """Plain-English reason for a history row (same wording as the main UI)."""
    r = dict(row)
    r["exists"] = _truthy(row.get("exists"))
    if not r.get("verification_detail"):
        r["verification_detail"] = {"coverage": row.get("verification_coverage")}
    ex = status.existence(r)
    ph = status.phishing(r)
    return status.plain_english(r, ex, ph)


def page_history() -> None:
    st.markdown('<div class="page-title">Analysis History</div>',
                unsafe_allow_html=True)
    st.markdown('<div class="page-sub">Every verification is logged so the '
                'origin of each indicator (and its result) can be reviewed '
                'later.</div>', unsafe_allow_html=True)

    s = src_db.stats()
    c = st.columns(4)
    vals = [
        ("search", "Indicators analysed", s["urls_analysed"], False),
        ("x", "URLs not found", s["hallucinations"], False),
        ("shield", "Phishing evidence found", s["malicious"], True),
        ("warn", "Possible phishing risk", s["suspicious"], False),
    ]
    for i, (ic, label, value, acc) in enumerate(vals):
        with c[i]:
            components.stat_icon(ic, label, str(value), accent=acc)

    rows = src_db.get_all_results()
    if not rows:
        st.info("No analyses have been logged yet. Run an AI verification first.")
        return

    st.markdown("---", unsafe_allow_html=True)

    df = pd.DataFrame(rows)

    def source_text(v):
        return "LLM-generated" if v == "LLM_GENERATED" else (v or "—")

    def page_text(js):
        if not js:
            return "Not checked"
        try:
            d = json.loads(js)
        except (TypeError, ValueError):
            return "Not checked"
        if d.get("suspicious"):
            return "Suspicious login page"
        if d.get("has_password_field"):
            return "Login page (no warning)"
        return "No login form"

    def num_text(v, pct=False):
        if v is None or v != v:
            return "—"
        return f"{round(float(v) * 100)}%" if pct else str(int(v))

    label_filter = st.selectbox(
        "Show", ["All", "Malicious", "Suspicious", "Likely Safe", "Unverified",
                 "Hallucination"], key="hist_filter")
    if label_filter != "All":
        df = df[df["final_label"].astype(str).str.startswith(label_filter)]

    show = pd.DataFrame({
        "id": df["id"],
        "Timestamp": df["timestamp"],
        "URL / Domain": [f"{u}\n({d})" if d else u
                         for u, d in zip(df["url"], df["domain"])],
        "Source": df["source"].apply(source_text),
        "Existence": df["exists"].apply(
            lambda v: status.history_existence_label(_truthy(v))),
        "Hallucination": df["exists"].apply(
            lambda v: status.history_hallucination_label(_truthy(v))),
        "Stage": df["stage_reached"].apply(
            lambda v: "Stage A" if v == "A" else "Stage B"),
        "Random Forest": df["rf_probability"].apply(_skipped),
        "XGBoost": df["xgb_probability"].apply(_skipped),
        "Combined ML": df["classifier_confidence"].apply(_skipped),
        "VirusTotal": df["virustotal_result"].apply(status.source_state),
        "Google Safe Browsing": df["safe_browsing_result"].apply(status.source_state),
        "urlscan.io": df["urlscan_result"].apply(status.source_state),
        "Domain age (days)": df["domain_age_days"].apply(num_text),
        "Login page": df["page_signals"].apply(page_text),
        "Sources answered": df["verification_coverage"].apply(
            lambda v: num_text(v, pct=True)),
        "Phishing assessment": df["final_label"].apply(status.history_phishing_label),
        "Reason": df.apply(lambda r: _history_reason(_clean(r)), axis=1),
        "Your label": df["human_label"].fillna(""),
        "Your note": df["reviewer_note"].fillna(""),
    })
    editable = ["Your label", "Your note"]
    edited = st.data_editor(
        show,
        hide_index=True,
        use_container_width=True,
        disabled=[c for c in show.columns if c not in editable],
        column_config={
            "id": None,
            "Your label": st.column_config.SelectboxColumn(
                options=["", "legitimate", "phishing", "unsure"]),
        },
        key="hist_editor",
    )
    changed = edited[editable].ne(show[editable]).any(axis=1)
    for idx in edited.index[changed]:
        src_db.set_review(int(show.loc[idx, "id"]),
                          edited.loc[idx, "Your label"] or None,
                          edited.loc[idx, "Your note"] or None)
    if changed.any():
        st.rerun()

    st.download_button(
        "Download as CSV",
        show.drop(columns=["id"]).to_csv(index=False).encode("utf-8"),
        file_name="analysis_history.csv",
        mime="text/csv")


# ---------------------------------------------------------------------------
# PAGE 3 - About the System (logic unchanged)
# ---------------------------------------------------------------------------

def page_about() -> None:
    st.markdown('<div class="page-title">About the System</div>',
                unsafe_allow_html=True)
    st.markdown(
        "PhishGuard-HDV independently verifies URL indicators generated by an "
        "LLM during cybersecurity threat-intelligence generation. It does not "
        "trust the LLM: every URL the model mentions is checked for existence, "
        "and only then assessed for phishing evidence.")

    with st.container(border=True):
        st.markdown("**How it works**")
        st.markdown(
            """
```
USER
 ↓
Cybersecurity Question
 ↓
LLM  →  Threat Intelligence
 ↓
URL Extraction
 ↓
STAGE A — Hallucination / URL Existence Verification
 ↓
Can existence be verified?
     /          \\
   NO           YES
   ↓             ↓
Potential      STAGE B
Hallucination  Phishing Assessment
   ↓             ↓
STOP        Random Forest + XGBoost
            VirusTotal + Google Safe Browsing
                ↓
         Threat Assessment
```
""")
        st.markdown(
            "- **Stage A** asks: *\"Can the LLM-generated URL be independently "
            "verified as existing?\"*\n"
            "- **Stage B** asks: *\"If it exists, is there evidence that it is "
            "phishing?\"*\n"
            "- Stage B never runs when Stage A fails. A URL that cannot be "
            "verified as existing is never classified as phishing or safe.")

    with st.container(border=True):
        st.markdown("**Phantom squatting**")
        st.markdown(
            "An LLM may generate a plausible but nonexistent domain. If such a "
            "domain is available and later registered by a malicious actor, it "
            "could potentially be weaponized. PhishGuard treats this as a "
            "security consideration, not proof that every hallucinated domain "
            "is malicious.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

components.header()

PAGES = {
    "Verify AI Threat Intelligence": page_verify_ai,
    "Analysis History": page_history,
    "About the System": page_about,
}

choice = st.sidebar.radio("Navigate", list(PAGES.keys()))

_steps_html = "".join(f"<li>{st_}</li>" for st_ in SIDEBAR_STEPS)
st.sidebar.markdown(
    f'<div class="side-steps"><div class="side-h">HOW PHISHGUARD WORKS</div>'
    f'<ol>{_steps_html}</ol></div>',
    unsafe_allow_html=True,
)

PAGES[choice]()
