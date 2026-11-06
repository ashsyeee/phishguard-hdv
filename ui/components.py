"""
ui/components.py - reusable HTML/Streamlit components for the light UI.

Pure presentation: builds small HTML snippets and Streamlit widgets from data
the backend already produced. No detection logic lives here.
"""
from __future__ import annotations

import html
import re
from typing import Dict, List

import streamlit as st

import features as F
from ui import status

# ---------------------------------------------------------------------------
# Inline stroke SVG icons (Lucide-style). No emoji.
# ---------------------------------------------------------------------------

_SVG_OPEN = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
             'stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" '
             'width="{w}" height="{w}" aria-hidden="true">')

_ICON_PATHS = {
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "warn": ('<path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16'
             'a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>'),
    "x": ('<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/>'
          '<path d="m9 9 6 6"/>'),
    "question": ('<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 '
                 '5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>'),
    "shield": ('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 '
               '4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 '
               '1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'),
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "minus": '<path d="M5 12h14"/>',
}

_TONE_ICON = {"ok": "check", "warn": "warn", "bad": "x", "muted": "question"}


def icon(name: str, size: int = 16) -> str:
    path = _ICON_PATHS.get(name, _ICON_PATHS["question"])
    return _SVG_OPEN.format(w=size) + path + "</svg>"


def pill(label: str, tone: str, icon_name: str) -> str:
    return (f'<span class="pill {tone}">{icon(icon_name, 16)}'
            f'{html.escape(label)}</span>')


def kv(label: str, value: str) -> str:
    return (f'<div class="kv"><span>{html.escape(label)}</span>'
            f'<b class="mono">{html.escape(str(value))}</b></div>')


# ---------------------------------------------------------------------------
# Header + pipeline strip
# ---------------------------------------------------------------------------

def header() -> None:
    st.markdown(
        f"""
        <div class="pg-header">
          <div class="pg-brand">
            <span class="pg-logo">{icon("shield", 26)}</span>
            <span class="pg-title">PhishGuard <span>HDV</span></span>
            <span class="pg-tag">Hallucination Detection &amp; Verification System</span>
          </div>
          <div class="pg-status"><span class="dot"></span>SYSTEM OPERATIONAL</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def pipeline_strip() -> None:
    steps = ["AI response", "URL extraction", "URL verification",
             "Phishing assessment"]
    nodes = [
        f'<span class="pipe-node"><span class="pipe-dot">{icon("check", 13)}'
        f'</span>{html.escape(s)}</span>'
        for s in steps
    ]
    st.markdown('<div class="pipe">' + '<span class="pipe-sep"></span>'.join(nodes)
                + "</div>", unsafe_allow_html=True)


def section_heading(num: str, title: str) -> None:
    st.markdown(
        f'<div class="sec-head"><span class="sec-num">{html.escape(num)}</span>'
        f'<span class="sec-title">{html.escape(title)}</span></div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# 01 - AI answer card with highlighted numbered URL chips
# ---------------------------------------------------------------------------

def highlight_urls(text: str, urls: List[str]) -> str:
    """Wrap each detected URL in a numbered chip, without breaking markdown.

    Uses placeholder tokens so overlapping URLs cannot corrupt each other.
    """
    out = text or ""
    tokens: Dict[str, str] = {}
    for idx, url in sorted(enumerate(urls, 1), key=lambda t: len(t[1]), reverse=True):
        if not url:
            continue
        token = f"\x00{idx}\x00"
        if url in out:
            out = out.replace(url, token)
            tokens[token] = (f'<span class="url-chip">{html.escape(url)}'
                             f'<span class="url-num">{idx}</span></span>')
    for token, chip in tokens.items():
        out = out.replace(token, chip)
    return out


def ai_answer_card(text: str, urls: List[str], model_used,
                   fallback_used: bool = False) -> None:
    with st.container(border=True):
        if text and text.strip():
            st.markdown(highlight_urls(text, urls), unsafe_allow_html=True)
        else:
            st.markdown('<div class="empty">No text was returned.</div>',
                        unsafe_allow_html=True)
        used = html.escape(str(model_used or "unknown"))
        by = f"Generated by {used}" + (" (fallback)" if fallback_used else "")
        n = len(urls)
        st.markdown(
            f'<div class="card-foot"><span>{by}</span>'
            f'<span>{n} URL{"s" if n != 1 else ""} detected</span></div>',
            unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# 02 - verification summary table
# ---------------------------------------------------------------------------

def summary_table(analyses: List[dict]) -> str:
    rows = []
    for i, a in enumerate(analyses, 1):
        ex = status.existence(a)
        ph = status.phishing(a)
        rows.append(
            f'<tr><td class="c">{i}</td>'
            f'<td class="url">{html.escape(str(a.get("url", "")))}</td>'
            f'<td>{pill(ex["label"], ex["tone"], ex["icon"])}</td>'
            f'<td>{pill(ph["label"], ph["tone"], ph["icon"])}</td></tr>')
    return ('<table class="summary"><thead><tr><th>#</th><th>URL</th>'
            '<th>Does the URL exist?</th><th>Phishing check</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')


# ---------------------------------------------------------------------------
# 03 - URL detail card
# ---------------------------------------------------------------------------

_NUM_RE = re.compile(r"^-?[\d.]+%?$")


def possible_future_risk() -> str:
    """Stage A failure only: a potential FUTURE concern, never a verdict."""
    return ('<div class="future-risk"><div class="fr-h">'
            f'{icon("warn", 16)} Possible Future Risk</div>'
            '<div class="fr-b">If this domain is currently unregistered, it '
            'could potentially be registered and misused later. This is known '
            'as phantom squatting.</div></div>')


def _bottom_line(ov: Dict, explanation: str, recommendation: str) -> str:
    """ONE box tinted by the overall tone (replaces overall + plain-English)."""
    rec = (f'<div class="bl-rec"><b>What to do:</b> {html.escape(recommendation)}</div>'
           if recommendation else "")
    return (f'<div class="bottom-line tone-{ov["tone"]}">'
            f'<div class="bl-head">{icon(_TONE_ICON.get(ov["tone"], "question"), 16)}'
            f'<span>{html.escape(ov["label"])}</span></div>'
            f'<div class="bl-body">{html.escape(explanation)}</div>{rec}</div>')


def _tile(title: str, s: Dict, sub: str = "") -> str:
    """Label left, pill right on one line, then one short sentence."""
    sub_html = (f'<div class="tile-sub">{html.escape(sub)}</div>' if sub else "")
    return (f'<div class="tile"><div class="tile-head">'
            f'<span class="tile-title">{html.escape(title)}</span>'
            f'{pill(s["label"], s["tone"], s["icon"])}</div>'
            f'<div class="tile-desc">{html.escape(s["description"])}</div>'
            f'{sub_html}</div>')


def _kv_row(label: str, value: str) -> str:
    v = str(value)
    if v == "Unavailable":
        return (f'<div class="tech-row"><span class="tech-lab">'
                f'{html.escape(label)}</span>'
                f'<span class="chip-unavail">Unavailable</span></div>')
    cls = "tech-val mono" if _NUM_RE.match(v) else "tech-val"
    return (f'<div class="tech-row"><span class="tech-lab">'
            f'{html.escape(label)}</span><span class="{cls}">'
            f'{html.escape(v)}</span></div>')


def _tech_card(title: str, rows: List[tuple]) -> str:
    body = "".join(_kv_row(l, v) for l, v in rows)
    return (f'<div class="tech-card"><div class="tech-card-h">'
            f'{html.escape(title)}</div>{body}</div>')


def feature_table(url: str) -> str:
    try:
        from features import extract_features   # src/features.py (read-only)
        feats = extract_features(url)
    except Exception:  # pragma: no cover
        return ('<div class="feat-wrap"><div class="muted" '
                'style="padding:10px">Features unavailable.</div></div>')
    rows = []
    for k, v in feats.items():
        try:
            val = f"{float(v):.4f}"
        except (TypeError, ValueError):
            val = html.escape(str(v))
        rows.append(f'<tr><td>{html.escape(str(k))}</td>'
                    f'<td class="mono">{val}</td></tr>')
    return (f'<div class="feat-wrap"><table class="feat"><tbody>'
            f'{"".join(rows)}</tbody></table></div>')


def _tech_columns(r: dict) -> str:
    ev = r.get("evidence_stage_a") or {}
    stage_b = r.get("stage_reached") == "B"

    def ml(v):
        return status.pct(v) if stage_b else "Not run"

    def src(v):
        return status.source_state(v) if stage_b else "Not run"

    rf, xgb = r.get("rf_probability"), r.get("xgb_probability")
    ml_rows = [("Random Forest", ml(rf)), ("XGBoost", ml(xgb))]
    # Drop the redundant combined value when it equals both models.
    if not (stage_b and ml(rf) == ml(xgb)):
        ml_rows.append(("Combined ML", ml(r.get("classifier_confidence"))))
    ml_rows.append(("Model disagreement",
                    status.num(r.get("model_disagreement"), 2) if stage_b else "Not run"))

    cards = [
        ("A  ·  URL verification", [
            ("DNS result", status.dns_text(ev)),
            ("WHOIS / RDAP", status.whois_text(ev)),
            ("Reference match", status.reference_text(ev)),
            ("Reference similarity", status.reference_similarity(ev)),
            ("Existence confidence", status.num(r.get("grounding_score"))),
        ]),
        ("B  ·  Machine learning", ml_rows),
        ("C  ·  Threat intelligence", [
            ("VirusTotal", src(r.get("virustotal_result"))),
            ("Google Safe Browsing", src(r.get("safe_browsing_result"))),
            ("urlscan.io", src(r.get("urlscan_result"))),
            ("External verification", status.coverage_text(r)),
        ]),
    ]
    inner = "".join(_tech_card(title, rows) for title, rows in cards)
    return f'<div class="tech-panel"><div class="tech-grid">{inner}</div></div>'


def _gauge(title: str, pct, caption: str) -> str:
    if pct is None:
        return (f'<div class="gauge"><div class="gauge-head"><span>{html.escape(title)}</span>'
                f'<span class="gauge-pct gauge-muted">Not checked</span></div>'
                f'<div class="gauge-track"></div>'
                f'<div class="gauge-cap">{html.escape(caption)}</div></div>')
    width = max(0, min(100, round(pct)))
    tone = "bad" if width >= 60 else ("warn" if width >= 30 else "ok")
    return (f'<div class="gauge"><div class="gauge-head"><span>{html.escape(title)}</span>'
            f'<span class="gauge-pct gauge-{tone}">{width}%</span></div>'
            f'<div class="gauge-track"><div class="gauge-fill gauge-fill-{tone}" '
            f'style="width:{width}%"></div></div>'
            f'<div class="gauge-cap">{html.escape(caption)}</div></div>')


def gauges_html(r: dict) -> str:
    """Two gauges: 'made up' (hallucination) and phishing risk. 0% is safest."""
    grounding = status._f(r.get("grounding_score"))
    if grounding is None:
        hal_pct = None
    else:
        hal_pct = (1 - max(0.0, min(1.0, grounding))) * 100
    threat = status._f(r.get("threat_risk_score"))
    if r.get("stage_reached") != "B" or threat is None:
        ph_pct = None
    elif r.get("known_legit_override") and not status._feed_positive(r):
        ph_pct = 0.0
    else:
        ph_pct = threat * 100
    hal_cap = ("Higher = more likely the link was made up (does not exist). "
               "Lower = the site really exists.")
    ph_cap = status.phishing(r)["label"]
    return ('<div class="gauge-row">'
            + _gauge("Hallucination risk (made-up link)", hal_pct, hal_cap)
            + _gauge("Phishing risk", ph_pct, ph_cap)
            + '</div>')


_CHECK_ICON = {"ok": "✔", "bad": "✖", "unk": "?"}


def _check(state: str, title: str, detail: str) -> str:
    return (f'<div class="check check-{state}"><span class="check-icon">'
            f'{_CHECK_ICON[state]}</span><div><div class="check-title">'
            f'{html.escape(title)}</div><div class="check-detail">'
            f'{html.escape(detail)}</div></div></div>')


def checklist_html(r: dict) -> str:
    """What we checked, one line per check. '?' means the check did not run."""
    rows = []

    exists = r.get("exists")
    if exists is None:
        rows.append(_check("unk", "Website exists", "Not checked"))
    elif exists:
        rows.append(_check("ok", "Website exists", "The domain resolves and answers."))
    else:
        rows.append(_check("bad", "Website exists",
                           "The link could not be confirmed - it may be made up."))

    feeds = {"VirusTotal": r.get("virustotal_result"),
             "Google Safe Browsing": r.get("safe_browsing_result"),
             "URLhaus": r.get("urlhaus_result"),
             "urlscan.io": r.get("urlscan_result")}
    configured = {k: v for k, v in feeds.items() if v not in (None, "UNAVAILABLE")}
    if r.get("stage_reached") != "B":
        rows.append(_check("unk", "Threat feeds", "Not checked"))
    elif any(v == "POSITIVE_MATCH" for v in configured.values()):
        hit = [k for k, v in configured.items() if v == "POSITIVE_MATCH"]
        rows.append(_check("bad", "Threat feeds",
                           f"Reported as a threat by: {', '.join(hit)}."))
    elif len(configured) >= 2 and all(v == "NO_MATCH" for v in configured.values()):
        rows.append(_check("ok", "Threat feeds",
                           f"{len(configured)} feeds found nothing bad. "
                           "Absence is not proof of safety."))
    else:
        rows.append(_check("unk", "Threat feeds",
                           f"Only {len(configured)} feed(s) answered - "
                           "not enough to be sure."))

    ml = status._f(r.get("classifier_confidence"))
    if ml is None or r.get("stage_reached") != "B":
        rows.append(_check("unk", "Machine-learning check", "Not checked"))
    elif ml >= 0.5:
        rows.append(_check("bad", "Machine-learning check",
                           f"Looks phishing-like ({round(ml * 100)}%)."))
    else:
        rows.append(_check("ok", "Machine-learning check",
                           f"Looks normal ({round(ml * 100)}% phishing score)."))

    page = r.get("page_signals") or {}
    if isinstance(page, str):
        try:
            import json as _json
            page = _json.loads(page)
        except ValueError:
            page = {}
    if not page or not page.get("fetched"):
        rows.append(_check("unk", "Login page",
                           "Not checked (page could not be read or was skipped)."))
    elif page.get("suspicious"):
        rows.append(_check("bad", "Login page",
                           "Asks for a password but sends it elsewhere, redirects "
                           "away, or names another brand."))
    elif page.get("has_password_field"):
        rows.append(_check("unk", "Login page",
                           "Has a password form; no warning signs found."))
    else:
        rows.append(_check("ok", "Login page", "No password form found."))

    if r.get("known_legit_override"):
        rows.append(_check("ok", "Brand name", "Verified official domain."))
    else:
        url = str(r.get("url", ""))
        prof = F.brand_profile(url) if url else {}
        if prof.get("impersonation"):
            rows.append(_check("bad", "Brand name",
                               f"'{prof.get('matched_brand')}' appears on a domain "
                               "that is not its official one."))
        else:
            rows.append(_check("ok", "Brand name", "No brand impersonation found."))

    age = r.get("domain_age_days")
    try:
        age = None if age is None or age != age else int(age)
    except (TypeError, ValueError):
        age = None
    if age is None:
        rows.append(_check("unk", "Domain age", "Unknown."))
    elif age < 30:
        rows.append(_check("bad", "Domain age", f"Only {age} day(s) old."))
    elif age < 180:
        rows.append(_check("unk", "Domain age", f"{age} days old - still fairly new."))
    else:
        rows.append(_check("ok", "Domain age", f"{age} days old."))

    return '<div class="checklist">' + "".join(rows) + "</div>"


def url_detail(r: dict, n: int) -> None:
    ex = status.existence(r)
    ph = status.phishing(r)
    ov = status.overall(r, ex, ph)

    with st.expander(f"{n}   {r.get('url', '')} · {ov['short']}", expanded=(n == 1)):
        # ONE bottom-line box (tone-tinted): overall line + explanation + action.
        st.markdown(
            _bottom_line(ov, status.plain_english(r, ex, ph),
                         ph.get("recommendation", "")),
            unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(
                _tile("DOES IT EXIST?", ex,
                      f"Hallucination check: {ex['technical']}"),
                unsafe_allow_html=True)
        with c2:
            st.markdown(_tile("IS IT PHISHING?", ph), unsafe_allow_html=True)

        st.markdown(gauges_html(r), unsafe_allow_html=True)
        st.markdown('<div class="check-head">What we checked</div>',
                    unsafe_allow_html=True)
        st.markdown(checklist_html(r), unsafe_allow_html=True)

        if ex["label"] == status.EXIST_NOT_FOUND:
            st.markdown(possible_future_risk(), unsafe_allow_html=True)

        key = f"tech_{n}"
        open_ = bool(st.session_state.get(key))
        label = "Hide technical evidence" if open_ else "View technical evidence"
        if st.button(label, key=f"techbtn_{n}"):
            st.session_state[key] = not open_
            open_ = not open_
        if open_:
            st.markdown(_tech_columns(r), unsafe_allow_html=True)
            if st.toggle("View extracted URL features", key=f"feat_{n}"):
                st.markdown(feature_table(str(r.get("url", ""))),
                            unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Legacy helpers reused by Analysis History / About (restyled light via CSS)
# ---------------------------------------------------------------------------

def stat_icon(icon_name: str, label: str, value: str,
              accent: bool = False) -> None:
    vcls = "accent-v" if accent else ""
    st.markdown(
        f'<div class="soc-stat"><div class="k">{icon(icon_name, 16)}'
        f'<span>{html.escape(label)}</span></div>'
        f'<div class="v {vcls}">{html.escape(str(value))}</div></div>',
        unsafe_allow_html=True)


def warning_banner(message: str) -> None:
    st.markdown(f'<div class="soc-warn">{html.escape(str(message))}</div>',
                unsafe_allow_html=True)
