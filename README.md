# PhishGuard-HDV — Real-Time Hallucination Detection & Verification System for LLM-Generated Phishing Threat Intelligence

A Python cybersecurity system that **never blindly trusts the LLM**. Gemini
Flash generates threat intelligence; the system then **independently verifies**
every URL, detects LLM **hallucinations**, fuses ML and external
threat-intelligence evidence into a **threat_risk_score**, and stores everything
in **SQLite** for a **Streamlit** SOC dashboard.

---

## Core design — the two questions stay separate

| Question | Module | Output |
|----------|--------|--------|
| **Stage A** — "Is the URL **grounded** in independent evidence (does it even exist)?" | `src/hallucination_detector.py` | `exists` / `grounding_score` |
| **Stage B** — "Given it is real, is it **malicious**?" | `src/classifiers.py` + `src/verification_engine.py` | `rf_probability` / `xgb_probability` / `classifier_confidence` / `verification_result` / `threat_risk_score` |

These are two different problems and are never merged. A fabricated URL is
labelled **Hallucination at Stage A - full stop** (the classifier and the
VirusTotal/PhishTank lookups provably never run - CHANGE 2). A real URL that
looks malicious proceeds to Stage B and can be flagged. **Grounding never
contributes to the threat score** (CHANGE 6/7): existing is not dangerous.

## Stage B scoring

    threat_risk_score = 0.5 · verification_result + 0.5 · classifier_confidence

- `verification_result` = VirusTotal + PhishTank evidence (a feed that produced
  no verdict - no key / rate-limited / error - is reported as missing, never as
  "safe"; `coverage` records the fraction of sources that actually answered).
- `classifier_confidence` = mean of the RF and XGBoost phishing probabilities
  (`model_disagreement` = |rf - xgb| is surfaced too).
- Labels: **Hallucination** (Stage A) / **Malicious** (needs genuine positive
  external evidence ≥ 0.60 AND threat_risk_score ≥ 0.70) / **Suspicious**
  (≥ 0.45) / **Likely Safe** (low score AND all sources answered) /
  **Unverified** (low score but some source is missing).
- The `0.55·db + 0.30·heuristic + 0.15·consistency` formula and the term
  "Aggregate Confidence" were **removed project-wide** (CHANGE 13).

---

## Pipeline

```
User prompt
  → Gemini Flash (modules/llm_analyzer.py)
  → URL extraction (modules/url_extractor.py)
  → Stage A  existence / grounding  (src/hallucination_detector.py)
      DNS + WHOIS + HTTP liveness + PhiUSIIL reference store
      lookup failure ≠ "does not exist" (errors stay neutral)
  → Stage B  maliciousness, ONLY if exists=True  (src/pipeline.py)
      ML: RandomForest + XGBoost (src/classifiers.py)
      External: VirusTotal + PhishTank (src/verification_engine.py)
  → threat_risk_score = 0.5·verification + 0.5·classifier  (src/risk_scoring.py)
  → SQLite (src/db.py) → Streamlit dashboard (app.py)
```

**Mode 1 — URL Checker:** paste a URL; the system runs Stage A → Stage B. No
LLM required.

**Mode 2 — AI Threat Intelligence:** ask a cybersecurity question; Gemini
answers; every URL in the answer is put through the same independent
Stage A → Stage B pipeline. The LLM is scanned, never trusted.

---

## Setup (Windows)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### API keys

```powershell
Copy-Item .env.example .env
# edit .env: GEMINI_API_KEY (https://aistudio.google.com/app/apikey)
#            VIRUSTOTAL_API_KEY (https://docs.virustotal.com/reference/authentication)
#            PHISHTANK_API_KEY (https://www.phishtank.com/developer_info.php)
```

Without keys the system runs in **offline/neutral mode** — everything works,
and the dashboard/flags clearly show the missing evidence (**UNAVAILABLE**,
`coverage < 1.0`) instead of silently pretending it ran.

> **Model note:** the FYP brief specified `gemini-2.5-flash`, which Google
> retired for new accounts (Sept 2026). The deployed model is
> **`gemini-3.6-flash`** (set in `modules/llm_analyzer.py`). The project
> contribution is the evidence/verification layer, not the model itself.

---

## Run

```powershell
streamlit run app.py
```

Open `http://localhost:8501`. Three pages: **URL Checker**, **AI Threat
Intelligence**, **Analytics**. The panel breaks every result into its Stage A
(existence) and Stage B (threat) evidence, with per-model probabilities,
verification coverage, `threat_risk_score`, and a plain-English reason string.

## Tests

```powershell
python -m pytest tests -q
```
(87 tests - includes CHANGE-enforcement tests for the Stage A/B separation,
the training-data guard, verification status semantics, and DB migration.)

## Model evaluation (already run)

Saved models in `models/` (RandomForest + XGBoost) are evaluated on the
PhiUSIIL held-out test split and the results are written to
`models/evaluation_results.json` (per-model + ensemble metrics, ROC-AUC and the
confusion matrix). **The authoritative numbers are whatever that file
contains** - read them from there rather than from this README, so the two can
never drift.

- Recall is the priority metric: missing a phishing URL is worse than a false
  alert.
- The split is **grouped by registrable domain** (`GroupShuffleSplit`), so no
  domain appears in more than one split. This removes the URL-vs-domain
  leakage that previously inflated held-out scores.

Evaluate the saved models (no retraining): `python src/classifiers.py eval`
Retrain from scratch:            `python src/classifiers.py train`

---

## Repository layout

```
phishguard-hdv/
├── app.py                     # Streamlit dashboard (SOC dark theme, 3 pages)
├── requirements.txt / .env.example / .gitignore
├── src/                       # LIVE pipeline (drives app.py)
│   ├── pipeline.py            # Stage A → Stage B orchestration (short-circuit)
│   ├── hallucination_detector.py  # Stage A: existence / grounding (DNS/WHOIS/RAG)
│   ├── classifiers.py         # Stage B ML: RandomForest + XGBoost, per-model probs
│   ├── verification_engine.py # Stage B external: VirusTotal + PhishTank
│   ├── risk_scoring.py        # threat_risk_score = 0.5·verif + 0.5·classifier
│   ├── features.py            # 30+ lexical/statistical URL features
│   ├── data_prep.py           # PhiUSIIL → stratified train/test splits
│   └── db.py                  # SQLite persistence (migrations kept, history safe)
├── dashboard/app.py           # thin shim → runs app.py
├── modules/                   # RETAINED for AI Threat Intelligence (Gemini) only
│   ├── llm_analyzer.py        # Gemini 3.6 Flash (secrets via .env)
│   ├── url_extractor.py       # LLM text → clean URL list
│   └── ...                    # older single-tree modules kept for the viva "before"
├── static/style.css           # centralized dark SOC theme
├── .streamlit/config.toml     # dark base theme
├── data/
│   ├── raw/                   # PhiUSIIL dataset (git-ignored)
│   ├── processed/             # train/test splits
│   └── llm_generated/         # synthetic hallucinated test URLs
├── models/                    # trained models + evaluation_results.json
├── tests/                     # pytest suite (87 tests)
└── phishguard.db              # created automatically on first analysis
```

## Notes on design honesty

- **Heuristic weights and confidence weights are baselines**, explicitly not
  claimed optimal; the report runs weight-comparison experiments.
- **"Not in PhishTank/OpenPhish" is never proof of hallucination** — a URL can
  simply be new or absent from a feed. The hallucination detector is
  *conservative*: with incomplete evidence it returns `SUSPICIOUS`, not a guess.
- **Threat-feed APIs can fail.** The system continues with whatever evidence is
  available and reports which sources were missing.
- All external traffic is bounded (short timeouts, no private-IP connections).