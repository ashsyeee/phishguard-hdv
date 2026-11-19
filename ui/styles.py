"""ui/styles.py - one global light-theme CSS block, injected once."""
from __future__ import annotations

import streamlit as st

GLOBAL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root{
  --bg:#070B14; --surface:#0F1726; --surface-alt:#121C2E; --ink:#E6EBF3; --ink-2:#9AA6B8;
  --border:#22304A; --divider:#1C2840; --primary:#2F6FEB; --primary-hover:#1F5BD0;
  --url-chip-bg:#16233A; --header-sub:#7E8AA0; --logo:#4D8DFF; --input-border:#2C3C5C;
  --ok-bg:#0F2A1F; --ok-tx:#4ADE80; --ok-bd:#1F5A3E;
  --warn-bg:#2B2110; --warn-tx:#FBBF24; --warn-bd:#5C4716;
  --bad-bg:#2C1316; --bad-tx:#F87171; --bad-bd:#5E2228;
  --muted-bg:#18212F; --muted-tx:#AAB4C4; --muted-bd:#2C3A52;
}

/* ---------- check-a-URL hero (landing look) ---------- */
.hero{ text-align:center; padding:28px 0 18px; }
.hero h1{ font-family:'Space Grotesk'; font-weight:700; font-size:50px; line-height:1.1;
  color:var(--ink); margin:0 0 14px; letter-spacing:-.01em; }
.hero h1 span{ color:#3B82F6; }
.hero p{ color:var(--ink-2); font-size:17px; line-height:1.6; max-width:640px; margin:0 auto; }
.hero-hint{ text-align:center; color:var(--ink-2); font-size:13px; margin-top:8px; }
.badges{ display:flex; justify-content:center; gap:10px; margin:14px 0 0; flex-wrap:wrap; }
.badge{ font-size:13px; font-weight:600; border-radius:999px; padding:6px 14px; border:1px solid;
  text-decoration:none; }
.badge-ok{ background:var(--ok-bg); color:var(--ok-tx); border-color:var(--ok-bd); }
.badge-info{ background:#0F1F3D; color:#60A5FA; border-color:#1E3A66; }
.badge-bad{ background:transparent; color:var(--bad-tx); border-color:var(--bad-bd); }
/* the input card */
[data-testid="stVerticalBlockBorderWrapper"]{ background:var(--surface)!important;
  border-color:var(--border)!important; border-radius:16px!important; padding:14px 16px; max-width:720px; margin:0 auto; }
[data-testid="stTextInput"] input{ background:#0A1220!important; color:var(--ink)!important;
  border:2px solid #2F6FEB!important; border-radius:12px!important; min-height:52px; font-size:16px; }
[data-testid="stTextInput"] input::placeholder{ color:#6B7A93!important; }

html, body, .stApp, [data-testid="stAppViewContainer"]{ background:var(--bg)!important; color:var(--ink); }
body, .stMarkdown, p, li, label, .stButton button, input, textarea, .stRadio{ font-family:'IBM Plex Sans',sans-serif; }
h1, h2, h3{ font-family:'Space Grotesk',sans-serif; color:var(--ink); }
[data-testid="stHeader"]{ background:transparent; }

/* Hide only the menu / footer / deploy button. DO NOT hide the toolbar:
   it holds the control that re-opens the sidebar when collapsed. */
#MainMenu, footer, [data-testid="stAppDeployButton"],
[data-testid="stStatusWidget"]{ visibility:hidden; height:0; }
[data-testid="stSidebarCollapseButton"]{ visibility:visible !important; }

.block-container{ max-width:1040px; margin:0 auto; padding-top:1.2rem; }

/* ---------- header ---------- */
.pg-header{ display:flex; align-items:center; justify-content:space-between;
  background:var(--surface); border:1px solid var(--border); border-radius:14px;
  padding:16px 24px; margin-bottom:22px; }
.pg-brand{ display:flex; align-items:center; gap:12px; }
.pg-logo{ color:var(--logo); display:inline-flex; }
.pg-title{ font-family:'Space Grotesk'; font-weight:700; font-size:20px; color:var(--ink); }
.pg-title span{ color:var(--primary); }
.pg-tag{ color:var(--ink-2); font-size:14px; margin-left:8px; }
.pg-status{ color:var(--ok-tx); font-size:13px; font-weight:600; letter-spacing:.04em;
  display:flex; align-items:center; gap:8px; }
.pg-status .dot{ width:9px; height:9px; border-radius:50%; background:var(--ok-tx); display:inline-block; }

/* ---------- page intro ---------- */
.page-title{ font-family:'Space Grotesk'; font-size:34px; font-weight:600; color:var(--ink); margin:2px 0; }
.page-sub{ color:var(--ink-2); font-size:16px; line-height:1.6; margin-bottom:18px; }
.model-note{ color:var(--ink-2); font-size:14px; margin:6px 0 14px; }

/* ---------- controls ---------- */
.stButton>button[kind="primary"], [data-testid="baseButton-primary"],
[data-testid="stBaseButton-primary"]{
  background:var(--primary)!important; color:#fff!important; border:none!important;
  border-radius:10px; min-height:52px; padding:0 22px; font-weight:600; font-size:16px; }
.stButton>button[kind="primary"]:hover, [data-testid="baseButton-primary"]:hover,
[data-testid="stBaseButton-primary"]:hover{ background:var(--primary-hover)!important; }
.stButton>button[kind="secondary"], [data-testid="baseButton-secondary"],
[data-testid="stBaseButton-secondary"]{
  background:transparent!important; color:var(--ink)!important;
  border:1px solid var(--input-border)!important; border-radius:10px;
  min-height:40px; padding:0 16px; font-weight:500; font-size:15px; }
.stButton>button[kind="secondary"]:hover, [data-testid="baseButton-secondary"]:hover,
[data-testid="stBaseButton-secondary"]:hover{
  border-color:var(--primary)!important; color:var(--primary)!important; background:transparent!important; }
.stTextArea textarea, .stTextInput input{ background:var(--surface)!important; color:var(--ink)!important;
  border:1px solid var(--input-border)!important; border-radius:10px!important; font-size:16px; }
.stTextArea textarea:focus, .stTextInput input:focus{ border-color:var(--primary)!important; box-shadow:none!important; }

/* ---------- cards ---------- */
[data-testid="stVerticalBlockBorderWrapper"]{ background:var(--surface);
  border:1px solid var(--border)!important; border-radius:14px; padding:22px 26px; }

/* ---------- pills ---------- */
.pill{ display:inline-flex; align-items:center; gap:6px; border-radius:999px;
  padding:5px 12px 5px 10px; font-size:14px; font-weight:600; border:1px solid; line-height:1.2; }
.pill svg{ width:16px; height:16px; }
.pill.ok{ background:var(--ok-bg); color:var(--ok-tx); border-color:var(--ok-bd); }
.pill.warn{ background:var(--warn-bg); color:var(--warn-tx); border-color:var(--warn-bd); }
.pill.bad{ background:var(--bad-bg); color:var(--bad-tx); border-color:var(--bad-bd); }
.pill.muted{ background:var(--muted-bg); color:var(--muted-tx); border-color:var(--muted-bd); }

/* ---------- pipeline strip ---------- */
.pipe{ display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin:8px 0 26px; }
.pipe-node{ display:inline-flex; align-items:center; gap:8px; font-size:14px; color:var(--ink); }
.pipe-dot{ width:22px; height:22px; border-radius:50%; background:#17603F; color:#fff;
  display:inline-flex; align-items:center; justify-content:center; }
.pipe-dot svg{ width:13px; height:13px; }
.pipe-sep{ width:22px; height:2px; background:#BFDCCB; display:inline-block; }

/* ---------- section heading ---------- */
.sec-head{ display:flex; align-items:baseline; gap:12px; margin:26px 0 12px; }
.sec-num{ font-family:'Space Grotesk'; font-size:22px; font-weight:700; color:var(--primary); }
.sec-title{ font-family:'Space Grotesk'; font-size:24px; font-weight:600; color:var(--ink); }

/* ---------- url chips ---------- */
.url-chip{ background:var(--url-chip-bg); color:var(--primary); font-family:'IBM Plex Mono';
  font-size:.9em; border-radius:6px; padding:1px 5px 1px 6px; white-space:nowrap; }
.url-num{ display:inline-block; margin-left:6px; background:var(--primary); color:#fff;
  border-radius:999px; font-size:11px; padding:0 6px; line-height:16px; vertical-align:middle; }
.card-foot{ display:flex; justify-content:space-between; gap:12px; color:var(--ink-2);
  font-size:13px; border-top:1px solid var(--divider); margin-top:16px; padding-top:10px; }

/* ---------- summary table ---------- */
table.summary{ width:100%; border-collapse:separate; border-spacing:0; background:var(--surface);
  border:1px solid var(--border); border-radius:14px; overflow:hidden; font-size:15px; }
table.summary th{ background:var(--surface-alt); text-align:left; color:var(--ink-2);
  font-size:13px; text-transform:uppercase; letter-spacing:.06em; padding:12px 14px;
  border-bottom:1px solid var(--border); font-weight:600; }
table.summary td{ padding:12px 14px; border-bottom:1px solid var(--divider); color:var(--ink); vertical-align:middle; }
table.summary tr:last-child td{ border-bottom:none; }
table.summary td.url{ font-family:'IBM Plex Mono'; font-size:13px; word-break:break-all; }
table.summary td.c{ color:var(--ink-2); }
table.summary tbody tr:hover td{ background:var(--surface-alt); }

/* ---------- expander ---------- */
[data-testid="stExpander"]{ border:1px solid var(--border)!important; border-radius:14px!important;
  background:var(--surface)!important; margin-bottom:12px; overflow:hidden; }
[data-testid="stExpander"] summary{ font-size:15px; color:var(--ink); font-family:'IBM Plex Sans'; }
[data-testid="stExpander"] summary:hover{ color:var(--primary); }
[data-testid="stExpander"] summary svg{ color:var(--primary); }

/* ---------- inner panels ---------- */
.panel{ background:var(--surface-alt); border:1px solid var(--divider); border-radius:12px;
  padding:16px 18px; height:100%; }
.panel-h{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); margin-bottom:10px; }
.panel-d{ color:var(--ink); font-size:15px; line-height:1.5; margin:10px 0; }
.panel-sec{ color:var(--ink-2); font-size:13px; margin-top:8px; }

.future-risk{ background:var(--warn-bg); border:1px solid var(--warn-bd);
  border-left:3px solid var(--warn-bd); border-radius:10px; padding:12px 14px; margin:12px 0; }
.future-risk .fr-h{ display:flex; align-items:center; gap:8px; color:var(--warn-tx);
  font-weight:600; font-size:14px; }
.future-risk .fr-h svg{ width:16px; height:16px; }
.future-risk .fr-b{ color:var(--ink); font-size:14px; line-height:1.5; margin-top:6px; }

.kv{ display:flex; justify-content:space-between; gap:12px; padding:5px 0;
  border-bottom:1px dashed var(--divider); font-size:14px; }
.kv:last-child{ border-bottom:none; }
.kv span{ color:var(--ink-2); }
.kv b{ color:var(--ink); font-weight:600; }

.overall{ display:flex; align-items:center; gap:10px; border-radius:12px; padding:12px 16px;
  margin:14px 0; font-weight:600; font-size:15px; border:1px solid; }
.overall svg{ width:16px; height:16px; }
.overall.pill-ok{ background:var(--ok-bg); color:var(--ok-tx); border-color:var(--ok-bd); }
.overall.pill-warn{ background:var(--warn-bg); color:var(--warn-tx); border-color:var(--warn-bd); }
.overall.pill-bad{ background:var(--bad-bg); color:var(--bad-tx); border-color:var(--bad-bd); }
.overall.pill-muted{ background:var(--muted-bg); color:var(--muted-tx); border-color:var(--muted-bd); }

/* ---------- bottom-line box (tone tinted; NO left border) ---------- */
.bottom-line{ border-radius:12px; padding:14px 16px; margin:0 0 16px 0; border:1px solid; }
.bottom-line .bl-head{ display:flex; align-items:center; gap:8px; font-weight:600; font-size:15px; }
.bottom-line .bl-head svg{ width:16px; height:16px; }
.bottom-line .bl-body{ color:var(--ink); font-size:15px; line-height:1.6; margin-top:6px; }
.bottom-line .bl-rec{ color:var(--ink-2); font-size:14px; margin-top:8px; }
.bottom-line .bl-rec b{ color:var(--ink); font-weight:600; }
.bottom-line.tone-ok{ background:var(--ok-bg); border-color:var(--ok-bd); color:var(--ok-tx); }
.bottom-line.tone-warn{ background:var(--warn-bg); border-color:var(--warn-bd); color:var(--warn-tx); }
.bottom-line.tone-bad{ background:var(--bad-bg); border-color:var(--bad-bd); color:var(--bad-tx); }
.bottom-line.tone-muted{ background:var(--muted-bg); border-color:var(--muted-bd); color:var(--muted-tx); }

/* ---------- two verdict tiles ---------- */
.tile{ background:var(--surface-alt); border:1px solid var(--border); border-radius:12px;
  padding:16px 18px; height:100%; }
.tile-head{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:8px; }
.tile-title{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); }
.tile-desc{ color:var(--ink); font-size:15px; line-height:1.5; }
.tile-sub{ color:var(--ink-2); font-size:13px; margin-top:8px; }

/* ---------- technical evidence panel ---------- */
.tech-panel{ background:var(--bg); border-radius:12px; padding:16px; margin-top:8px; }
.tech-grid{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
.tech-card{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:14px 16px; }
.tech-card-h{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); margin-bottom:4px; }
.tech-row{ display:flex; align-items:center; justify-content:space-between; gap:12px;
  min-height:36px; border-bottom:1px solid #F0EEE9; }
.tech-card .tech-row:last-child{ border-bottom:none; }
.tech-lab{ color:var(--ink-2); font-size:14px; }
.tech-val{ color:var(--ink); font-size:14px; font-weight:500; text-align:right; white-space:nowrap; }
.chip-unavail{ background:#ECEEF1; color:#3F4855; font-size:12px; border-radius:999px; padding:2px 10px; }

.tech-h{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); margin:8px 0; }
.mono{ font-family:'IBM Plex Mono'!important; }
.feat-wrap{ max-height:320px; overflow:auto; margin-top:10px; border:1px solid var(--divider); border-radius:10px; }
table.feat{ width:100%; border-collapse:collapse; font-size:13px; }
table.feat td{ border-bottom:1px solid var(--divider); padding:5px 10px; color:var(--ink); }
table.feat td:last-child{ text-align:right; }

.empty{ color:var(--ink-2); font-size:15px; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"]{ background:var(--surface)!important; border-right:1px solid var(--border)!important; }
[data-testid="stSidebar"] .stRadio [data-testid="stWidgetLabel"] p,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p{
  font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); }
[data-testid="stSidebar"] .stRadio label p{ color:var(--ink)!important; font-size:15px; }
[data-testid="stSidebar"] .stRadio [data-checked="true"] p{ color:var(--primary)!important; }
.side-steps{ padding:2px 4px 0; margin-top:8px; }
.side-h{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink-2); margin-bottom:10px; }
.side-steps ol{ margin:0; padding-left:18px; }
.side-steps li{ color:var(--ink-2); font-size:14px; line-height:1.7; }

/* ---------- legacy classes (Analysis History / About) restyled light ---------- */
.soc-card{ background:var(--surface); border:1px solid var(--border); border-radius:14px;
  padding:24px 28px; color:var(--ink); margin-bottom:18px; }
.soc-card .card-head{ color:var(--primary); font-weight:700; font-size:15px; margin-bottom:12px; }
.soc-stat{ background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:14px 16px; }
.soc-stat .k{ color:var(--ink-2); font-size:12px; text-transform:uppercase; letter-spacing:.05em;
  display:flex; gap:8px; align-items:center; }
.soc-stat .k svg{ width:16px; height:16px; }
.soc-stat .v{ color:var(--ink); font-size:28px; font-weight:800; }
.soc-stat .accent-v{ color:var(--primary); }
.soc-check{ display:flex; gap:10px; padding:7px 0; border-bottom:1px dashed var(--divider);
  color:var(--ink); font-size:14px; }
.soc-check .e-good{ color:var(--ok-tx); } .soc-check .e-warn{ color:var(--warn-tx); }
.soc-check .e-bad{ color:var(--bad-tx); } .soc-check .e-muted{ color:var(--ink-2); }
.soc-warn{ background:var(--warn-bg); border:1px solid var(--warn-bd); border-left:4px solid var(--warn-bd);
  border-radius:10px; padding:10px 14px; color:var(--warn-tx); font-weight:600; margin:10px 0; font-size:15px; }
.soc-label{ color:var(--ink-2); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
.soc-value{ color:var(--ink); font-size:16px; font-weight:600; word-break:break-all; }
.muted{ color:var(--ink-2); font-size:14px; }
.history-wrap{ overflow-x:auto; margin-top:8px; }
.history-wrap table{ border-collapse:collapse; width:100%; font-size:13px; color:var(--ink); }
.history-wrap th, .history-wrap td{ border:1px solid var(--border); padding:6px 9px; text-align:left; vertical-align:top; }
.history-wrap th{ background:var(--surface-alt); color:var(--ink-2); }
.history-wrap td{ background:var(--surface); }

/* ---------- code blocks (About) ---------- */
[data-testid="stCodeBlock"], pre{ background:var(--surface-alt)!important; border:1px solid var(--border);
  border-radius:10px; }
[data-testid="stCodeBlock"] code, pre, pre code{ color:var(--ink)!important; font-family:'IBM Plex Mono'!important; }

/* ---------- dashboard layer: dark navigation sidebar, elevated cards ---------- */
[data-testid="stSidebar"]{ background:#0B1220!important; border-right:none!important; }
[data-testid="stSidebar"] *{ color:#D6DCE6; }
[data-testid="stSidebar"] .stRadio [data-testid="stWidgetLabel"] p,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p{ color:#8A96A8!important; }
[data-testid="stSidebar"] .stRadio label p{ color:#E6EAF0!important; font-size:15px; }
[data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label{
  border-radius:8px; padding:8px 12px; margin:2px 0; }
[data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label:hover{ background:#2A3850; }
[data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label:has(input:checked){
  background:#2E4A78; }
[data-testid="stSidebar"] .stRadio [data-checked="true"] p{ color:#FFFFFF!important; font-weight:600; }
[data-testid="stSidebar"] .side-h{ color:#8A96A8; }
[data-testid="stSidebar"] .side-steps li{ color:#B7C0CE; }
[data-testid="stSidebar"] hr{ border-color:#2F3B52; }
.soc-card, .soc-stat, .card{ box-shadow:0 1px 2px rgba(16,24,40,.06), 0 4px 12px rgba(16,24,40,.04); }

/* ---------- risk gauges (per result) ---------- */
.gauge-row{ display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:14px 0 6px; }
.gauge{ background:var(--surface-alt); border:1px solid var(--border); border-radius:12px; padding:12px 14px; }
.gauge-head{ display:flex; justify-content:space-between; align-items:baseline; gap:10px;
  color:var(--ink); font-weight:600; font-size:14px; }
.gauge-pct{ font-family:'Space Grotesk'; font-size:20px; font-weight:700; }
.gauge-track{ height:10px; border-radius:999px; background:var(--divider); margin:8px 0 6px; overflow:hidden; }
.gauge-fill{ height:100%; border-radius:999px; }
.gauge-fill-ok{ background:#4ADE80; } .gauge-fill-warn{ background:#FBBF24; } .gauge-fill-bad{ background:#F87171; }
.gauge-ok{ color:#4ADE80; } .gauge-warn{ color:#FBBF24; } .gauge-bad{ color:#F87171; }
.gauge-muted{ color:var(--ink-2); font-size:14px; font-weight:600; }
.gauge-cap{ color:var(--ink-2); font-size:12.5px; line-height:1.45; }
@media (max-width: 760px){ .gauge-row{ grid-template-columns:1fr; } }

/* ---------- what we checked ---------- */
.check-head{ font-family:'Space Grotesk'; font-weight:600; color:var(--ink); margin:14px 0 6px; }
.checklist{ border:1px solid var(--border); border-radius:12px; overflow:hidden; background:var(--surface); }
.check{ display:flex; gap:12px; align-items:flex-start; padding:10px 14px; border-bottom:1px solid var(--divider); }
.check:last-child{ border-bottom:none; }
.check-icon{ width:24px; height:24px; border-radius:50%; display:inline-flex; align-items:center;
  justify-content:center; font-weight:700; font-size:13px; flex:0 0 24px; }
.check-ok .check-icon{ background:var(--ok-bg); color:var(--ok-tx); }
.check-bad .check-icon{ background:var(--bad-bg); color:var(--bad-tx); }
.check-unk .check-icon{ background:var(--muted-bg); color:var(--muted-tx); }
.check-title{ color:var(--ink); font-weight:600; font-size:14px; }
.check-detail{ color:var(--ink-2); font-size:13px; line-height:1.45; }
"""


def inject() -> None:
    """Inject the one global stylesheet. Call once, at the top of the app."""
    st.markdown(f"<style>{GLOBAL_CSS}</style>", unsafe_allow_html=True)
