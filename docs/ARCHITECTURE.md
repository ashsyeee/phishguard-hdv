# PhishGuard-HDV — Architecture & How It Runs

Real-Time Hallucination Detection & Verification System for LLM-Generated
Phishing Threat Intelligence.

This document describes, end to end, how the system is structured and how a
single user submission flows through it. It is written for the FYP report and
the viva.

---

## Table of contents

1. [Core idea](#1-core-idea)
2. [Project map](#2-project-map)
3. [Configuration and secrets](#3-configuration-and-secrets)
4. [High-level runtime flow](#4-high-level-runtime-flow)
5. [Stage A — existence / hallucination check](#5-stage-a--existence--hallucination-check)
6. [Stage B — phishing assessment](#6-stage-b--phishing-assessment)
7. [The result object](#7-the-result-object)
8. [Presentation layer](#8-presentation-layer)
9. [Data and model training](#9-data-and-model-training)
10. [Database](#10-database)
11. [LLM integration, fallback and error handling](#11-llm-integration-fallback-and-error-handling)
12. [Invariants the system guarantees](#12-invariants-the-system-guarantees)
13. [Running and deploying](#13-running-and-deploying)
14. [Limitations](#14-limitations)

---

## 1. Core idea

The system answers **two separate questions**, strictly in order:

- **Stage A — "Does the URL actually exist?"** (hallucination / existence check)
- **Stage B — "Given it exists, is it phishing?"** (ML + threat intelligence)

Stage B **only runs if Stage A passes**. A hallucinated URL is never labelled
"phishing" or "safe". This separation is the central design decision.

---

## 2. Project map

### UI / presentation layer

| File | Role |
|------|------|
| `app.py` | Streamlit app: pages, header, sidebar, controls, `_run_ai`, `_run_url`, `_llm` |
| `dashboard/app.py` | Thin launcher that runs the root `app.py` (single source of truth) |
| `ui/styles.py` | One global light-theme CSS block |
| `ui/components.py` | Header, pipeline strip, AI-answer card, summary table, URL detail cards, pills, icons |
| `ui/status.py` | Mapping layer: backend values -> user-facing statuses |

### Backend pipeline (`src/`, the active tree)

| File | Role |
|------|------|
| `src/pipeline.py` | Orchestrates Stage A -> Stage B (`PhishGuardPipeline.analyze_url`) |
| `src/hallucination_detector.py` | **Stage A** — existence / hallucination |
| `src/features.py` | 28 URL features (lexical/structural + similarity) |
| `src/classifiers.py` | **Stage B ML** — RandomForest + XGBoost |
| `src/verification_engine.py` | **Stage B threat intel** — VirusTotal + PhishTank |
| `src/risk_scoring.py` | Fuse evidence -> `threat_risk_score` + label + reason |
| `src/data_prep.py` | Dataset build (PhiUSIIL + synthetic) and splits |
| `src/db.py` | SQLite logging, history, stats |
| `src/ui_copy.py` | Legacy copy helpers (retained; not used by the active UI) |

### LLM integration and helpers (`modules/`, only two files used by the app)

| File | Role |
|------|------|
| `modules/llm_analyzer.py` | Gemini provider + OpenRouter fallback + error handling |
| `modules/url_extractor.py` | Extract and normalise URLs from LLM text |

### Artifacts

| Path | Contents |
|------|----------|
| `models/` | `random_forest.pkl`, `xgboost.json`, `calibrator.pkl`, `feature_names.json`, `feature_importance.json`, `evaluation_results.json` |
| `data/processed/train.csv` | Reference store used by Stage A |
| `data/raw/` | PhiUSIIL dataset (git-ignored) |
| `phishguard.db` | Runtime log (git-ignored) |

> Note: the older `modules/` pipeline tree is retired. The app drives `src/`.

---

## 3. Configuration and secrets

- **Local runs:** keys are read from `.env` via `python-dotenv`.
- **Hosted runs:** `app.py` mirrors `st.secrets` into `os.environ` (recursively),
  then logs a key-free line: `Secret keys available: ...`.
- Keys used:

| Variable | Used by | Required? |
|----------|---------|-----------|
| `GEMINI_API_KEY` | Primary LLM | Recommended |
| `OPENROUTER_API_KEY` | Fallback LLM | Optional |
| `PHISHTANK_API_KEY` | Stage B threat intel | Optional |
| `VIRUSTOTAL_API_KEY` | Stage B threat intel | Optional |

Missing optional keys never break the app — the affected source is reported as
**Unavailable**.

---

## 4. High-level runtime flow

```
Sidebar navigation
  |- Verify AI Threat Intelligence
  |- Analysis History
  |- About the System

User question (st.text_area)
   -> [Generate & verify]   or   [Clear]
   -> _run_ai(prompt, reason)
        -> _llm().analyze_threat(prompt)      # Gemini, OpenRouter fallback
        -> extract_urls(text)                 # LLM text -> clean URL list
        -> for each URL: _run_url(...)
              -> PhishGuardPipeline.analyze_url   # Stage A -> Stage B
              -> src_db.log_result(result)        # persist
        -> st.session_state["last_ai_result"]     # cache for reruns
   -> render section 01 (AI response), 02 (summary), 03 (URL details)
```

One submission triggers **one** LLM generation, and the result is stored in
session state so ordinary Streamlit reruns never re-call the LLM.

---

## 5. Stage A — existence / hallucination check

File: `src/hallucination_detector.py` -> `HallucinationDetector.analyze(url)`.

### Evidence sources

1. **Structural pattern (no network)**
   - IP literal -> concludes *exists* (by construction).
   - Reserved RFC-2606 TLD (`.invalid`, `.example`, `.test`) -> concludes
     *does not exist*.
   - otherwise valid or malformed hostname.
2. **DNS** (`dnspython`, A/AAAA): resolved / NXDOMAIN / no conclusive answer.
3. **WHOIS then RDAP** (`python-whois`, IANA RDAP bootstrap): registration
   found / no record / no answer. RDAP is tried automatically when the legacy
   WHOIS answer is inconclusive (many registries now block port 43).
4. **HTTP liveness** (HEAD then GET fallback): live / page gone (404/410) /
   DNS failure.
5. **Reference store** (TF-IDF over PhiUSIIL `train.csv` domains): exact hit and
   nearest similarity.

### Grounding score (weighted, base 0.5)

DNS +0.35 / NXDOMAIN -0.40, WHOIS +0.25 / -0.25, IP +0.50, reserved -0.30,
structural valid +0.05, malformed -0.20, exact reference +0.20, similarity
scaled x0.15, HTTP live +0.05 / dead -0.15.

### Decision table (priority order)

```
IP literal             -> exists = True
reserved TLD           -> exists = False
DNS resolved           -> True
DNS NXDOMAIN           -> False
WHOIS found/not found  -> True / False
reference exact hit    -> True
HTTP dns_failed        -> False
no conclusive evidence -> exists=False, uncertain=True
else                   -> grounding_score >= 0.5
```

### Semantics

- A probe **failure** (timeout/offline/blocked) is **neutral** — only definitive
  answers count as negative evidence.
- Reference similarity is only **supporting** evidence, never an existence proof.
- **No-evidence default (fixed):** previously a URL where *every* probe was
  inconclusive fell through to `grounding_score >= 0.5`, and because the base
  score *is* 0.5 it defaulted to `exists=True`. It now reports
  `exists=False, uncertain=True`, and the pipeline carries that to Stage B as
  `existence_uncertain=True` (it does **not** short-circuit to a confident
  "Hallucination", and never labels such a URL "Likely Safe").

Output: `StageAResult(url, domain, exists, grounding_score, reason, evidence,
uncertain)` where `evidence` contains
`{structural, dns, whois, rdap, liveness, reference}`.

---

## 6. Stage B — phishing assessment

Runs **only if `exists = True`**.

### 6a. Features — `src/features.py`

28 numeric features computed from the URL string:

- Lexical/structural: `url_length`, `hostname_length`, `digit_ratio`,
  `hyphen_count`, `has_ip_address`, `punycode_present`,
  `suspicious_keyword_count`, `brand_present`,
  `character_substitution_flagged`, ...
- Domain similarity: `min_levenshtein_dist`, `max_domain_similarity`,
  `near_legit_lookalike`, `segment_lookalike_count` (vs a whitelist of
  well-known legitimate domains).

`FEATURE_NAMES` fixes the column order so training and inference always align.

### 6b. Machine learning — `src/classifiers.py`

`StageBClassifier.predict_breakdown(features)` returns:

- `rf_probability` — RandomForest phishing probability
- `xgb_probability` — XGBoost phishing probability
- `classifier_confidence` — mean of the available models (raw)
- `calibrated_confidence` — isotonic-calibrated probability (see below)
- `model_disagreement` — `|rf - xgb|`

**Probability calibration.** An isotonic regressor is fit on the held-out
*validation* split (never the test split) and maps the raw ensemble mean to a
well-calibrated p(phishing); it is saved to `models/calibrator.pkl` and applied
at inference. `models/evaluation_results.json` reports ECE and Brier before/after
(raw ECE ≈ 0.0012 → calibrated ≈ 0.0004 on the current data), so the 0.5 decision
threshold is statistically meaningful rather than just a ranking cut.

**Feature importance.** `python src/feature_importance.py` writes
`models/feature_importance.json` — exact XGBoost TreeSHAP mean|contribution| plus
RandomForest Gini importance for all 28 features (dissertation justification).

### 6c. Threat intelligence — `src/verification_engine.py`

`verifier.verify(url)` queries:

- **VirusTotal** — domain reputation endpoint
- **PhishTank** — checkurl endpoint

Each source returns a status: `POSITIVE_MATCH` / `NO_MATCH` / `UNAVAILABLE` /
`RATE_LIMITED` / `ERROR`. The engine computes:

- `verification_result` — mean over **genuine verdicts only** (otherwise neutral 0.5)
- `coverage` — fraction of sources that produced a verdict
- `warnings` — explicit list of sources with no verdict

Missing evidence is always explicit and is **never** treated as safe. No API key
=> mock/neutral (`UNAVAILABLE`).

### 6d. Fusion and label — `src/risk_scoring.py`

```
threat_risk_score = 0.5 * verification_result + 0.5 * classifier_confidence
```

Thresholds (documented baseline, not calibrated):

- `MALICIOUS_THRESHOLD = 0.70` (also requires external evidence >= 0.60)
- `SUSPICIOUS_THRESHOLD = 0.45`
- "Likely Safe" requires `coverage == 1.0`, otherwise "Unverified"

Labels: **Hallucination / Malicious / Suspicious / Likely Safe / Unverified**.
Grounding is deliberately **not** an input to threat risk.

---

## 7. The result object

`PhishGuardPipeline.analyze_url` returns a dict with:

```
url, domain,
stage_reached ("A" | "B"), exists, grounding_score,
rf_probability, xgb_probability, classifier_confidence, model_disagreement,
verification_result, verification_offline, verification_detail,
classifier_detail, virustotal_result, phishtank_result,
threat_risk_score, risk_score,
final_label, reason, evidence_stage_a,
source, llm_model, original_user_question
```

If Stage A fails: `stage_reached = "A"` and **all Stage B fields are `None`**
(skipped, never 0).

---

## 8. Presentation layer

`ui/status.py` maps backend outputs to user-facing statuses (display only;
internal values are preserved):

| Internal situation | User status |
|--------------------|-------------|
| `exists = False` | **URL Not Found** |
| `exists = True` | **URL Exists** |
| Stage A failed | **Not Checked** |
| A feed lists the URL | **Phishing Evidence Found** |
| ML >= 0.5, feeds unconfirmed | **Possible Phishing Risk** |
| Feeds incomplete | **Unable to Verify** |
| Otherwise | **No Phishing Evidence Found** |

It also produces the overall line, a plain-English explanation, and a
recommendation.

`ui/components.py` renders:

- **01 AI response** — markdown with detected URLs as numbered chips, plus a
  footer ("Generated by <model> · N URLs detected").
- **02 Verification summary** — table: `# | URL | Does the URL exist? | Phishing check`
  (two pills per row).
- **03 URL details** — one expander per URL:
  - a single tone-tinted **bottom-line box** (verdict + explanation + "What to do")
  - two **tiles**: "Does it exist?" and "Is it phishing?" (label left, pill right)
  - a **Possible Future Risk** box (only for URL Not Found)
  - a ghost **View technical evidence** button -> **A URL verification /
    B Machine learning / C Threat intelligence** cards, plus
    "View extracted URL features".

Other pages:

- **Analysis History** — counts from `src_db.stats()` plus a table of logged rows
  (labels mapped through `ui/status.py`).
- **About the System** — static explanation + phantom-squatting note.

---

## 9. Data and model training

Training is a **one-time, offline** step (`src/data_prep.py` + `src/classifiers.py`):

1. Load **PhiUSIIL** (~235,795 URLs) into `real_legitimate` / `real_phishing`.
2. Generate synthetic `hallucinated` rows (RFC-2606 reserved TLDs) and
   `real_but_misdescribed` rows.
3. De-duplicate and split **70/15/15** (stratified by category) into
   `train.csv / val.csv / test.csv`, **grouped by registrable domain**
   (`GroupShuffleSplit`) so no domain straddles two splits. `clean_and_merge`
   de-duplicates at both URL and domain level; `_assert_no_domain_overlap`
   fails loudly if a domain appears in more than one split.
4. Train **only on real rows** (`make_x_y` hard-guards against hallucinated
   leakage):
   - RandomForest (200 trees, `class_weight="balanced_subsample"`)
   - XGBoost (400 estimators, `max_depth=7`, `tree_method="hist"`)
5. Evaluate on the held-out real test split (35,273 rows) and save models to
   `models/`.

Reference results are stored in `models/evaluation_results.json` (per-model +
ensemble metrics, ROC-AUC, confusion matrix). **Read the numbers from that
file** - they are produced by `python src/classifiers.py eval` and are not
duplicated here, so the docs cannot drift from the artefacts. The held-out
split is **grouped by registrable domain**, so it is leak-free. Recall is
prioritised.

At runtime the system only **loads and predicts** — it never trains.

---

## 10. Database

`src/db.py` uses a SQLite `results` table. Stage A hallucinations store NULL for
all Stage B columns. `init_db` runs `CREATE TABLE IF NOT EXISTS` plus safe
`ALTER TABLE` migrations (history is never dropped). Functions: `log_result`,
`get_recent_results`, `get_all_results`, `clear_results`, `stats`.

Provenance is logged: `source = "LLM_GENERATED"`, `llm_model`, and
`original_user_question`.

---

## 11. LLM integration, fallback and error handling

File: `modules/llm_analyzer.py`.

- **GeminiAnalyzer.analyze_threat(prompt, reason)** builds a
  `GenerateContentConfig` (system instruction, temperature, **AFC disabled**),
  disables **SDK retries** (`attempts=1`), and makes exactly one
  `client.models.generate_content` call.
- **FallbackLLMAnalyzer** — if Gemini fails, it tries **OpenRouterAnalyzer**
  once (OpenAI-compatible chat completions).
- Errors are **classified**: `rate_limit / auth / model_unavailable / network /
  unexpected / validation`, each producing a safe, category-specific message.
- **Logging**: `GEMINI`/`OPENROUTER` `REQUEST START / COMPLETE / FAILED` with a
  request id; the raw exception is logged to the terminal with **keys redacted**.
  The UI never receives stack traces, keys, or configuration.
- The system **never fabricates** LLM output; on failure it shows a warning,
  preserves the question, and offers a **manual** Retry.

---

## 12. Invariants the system guarantees

- Stage B is **never** executed when Stage A fails (structural short-circuit).
- A skipped Stage B is shown as **"Not Checked"**; its technical values show
  **"Not run"** (not 0, not "Unavailable").
- A "no match" from a feed is **never** reported as "safe"; missing evidence is
  **"Unavailable"** and is neither positive nor negative.
- One submission = one LLM generation (plus one OpenRouter request only if
  Gemini fails).
- API keys and credentials never appear in the UI, the database, or the logs.

---

## 13. Running and deploying

### Local

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Keys come from `.env`.

### Streamlit Community Cloud

1. Push the repository to GitHub (branch `main`). The `models/` folder is
   tracked so Stage B works on the host.
2. Create the app on https://share.streamlit.io with **Main file path `app.py`**
   and branch `main`.
3. Add **Secrets**:

   ```toml
   GEMINI_API_KEY = "..."
   OPENROUTER_API_KEY = "..."
   PHISHTANK_API_KEY = "..."
   VIRUSTOTAL_API_KEY = "..."
   ```

4. Deploy. Confirm the log line `Secret keys available: ...` lists the keys.

### Other hosts

A `Dockerfile` running `streamlit run app.py --server.port=8501
--server.address=0.0.0.0` works on Render/Railway/Fly.io/VPS. Provide the keys as
environment variables; mount a volume for SQLite if persistence is needed.

---

## 14. Limitations

### 14.1 LLM / generation

- The system does **not** generate anything — the LLM does. If the LLM refuses
  or returns no URLs, there is nothing to verify (0 indicators).
- It **cannot force or prevent hallucination**; LLM output is probabilistic.
- External dependency with **quotas** (Gemini free tier ~20 requests/day); the
  OpenRouter fallback helps but consumes credits.
- Output quality depends on the model/prompt; a weaker fallback model is more
  conservative and may produce fewer or less precise indicators.

### 14.2 Stage A — existence / hallucination

- **Network-dependent:** DNS/WHOIS/RDAP/HTTP can time out, be blocked, or be
  rate-limited; transient failures are treated as neutral
  ("no evidence" != "does not exist").
- **WHOIS/RDAP is unreliable** for many TLDs (privacy redaction, format
  variance, rate limits); `python-whois` is brittle.
- **NXDOMAIN is not proof a domain never existed** (it may be expired or its DNS
  temporarily down).
- The **reference store is a static snapshot** (PhiUSIIL train domains); a domain
  not in it is unknown, not fake — it only gives weak support.
- **No registration-availability check**, so phantom-squatting remains a
  consideration, never a determination.
- **Latency:** live DNS/WHOIS per URL takes seconds; batches are sequential.

### 14.3 Stage B — machine learning

- Trained **only on PhiUSIIL**; novel phishing, other languages, new TLDs, or
  unrelated brands can be missed (false negatives).
- **URL-string features only (28)** — no page content, HTML/JS, screenshots,
  certificates, or hosting reputation.
- **Brand whitelist** now includes Malaysian banks/brands and the `*.my`
  second-level domains; it is still finite, so unseen brands are not matched.
- A **simple ensemble** (mean of RF + XGBoost) with **isotonic probability
  calibration** (fit on the val split, ECE ≈ 0.0004); the decision threshold
  (0.5) is fixed while the fusion thresholds (0.45 / 0.70) remain hand-set.
- Fusion weights (0.5 verification + 0.5 classifier) are a documented baseline,
  not optimised.
- **Static models** — no automatic retraining; performance can drift over time.

### 14.4 Threat intelligence

- **VirusTotal/PhishTank are optional**; without keys, external evidence is
  "Unavailable" and Stage B falls back to ML only.
- Feeds are **reactive** — a brand-new, unreported URL will not be listed, so
  "No match" does not mean "safe".
- **Rate limits/quotas** (VirusTotal free tier ~4/min, 500/day; PhishTank can be
  flaky).
- **Coverage < 1.0 -> "Unable to Verify"** — honest, but inconclusive.

### 14.5 Scope

- **Only URLs/domains are verified.** IPs, file hashes, CVEs, email addresses,
  phone numbers, and other LLM claims are not checked.
- **No real-time page inspection** — the live phishing page content is not
  fetched and analysed.
- **Only text indicators** — a threat described without a URL yields nothing to
  verify.

### 14.6 Architecture / operational

- **Sequential gate by design:** if a URL is *confirmed* not to resolve, Stage B
  is skipped — a genuinely malicious but non-resolving URL is reported as
  "URL Not Found / Not Checked", not as phishing. (Intentional, but a real-world
  blind spot.) When existence is merely **unverifiable** (every probe blocked),
  the pipeline now continues to Stage B with `existence_uncertain=True` instead
  of skipping it, so external evidence can still speak.
- **SQLite** is single-file with no concurrency scaling; on Streamlit Cloud it is
  **ephemeral** (resets on redeploy), and the free tier sleeps when idle.
- **Single LLM request per submission**, but no cross-run LLM cache (only an
  in-memory TTL cache inside the verification engine, per process).
- **Public dashboard, no authentication**; secrets must be provisioned
  externally.

### 14.7 Evaluation

- **Stage B metrics** are read from `models/evaluation_results.json` and are on
  the PhiUSIIL held-out real rows only; the split is grouped by registrable
  domain (leak-free), so the numbers are lower than the old URL-level-leaky run
  but trustworthy.
- **Stage A** is validated mostly on synthetic reserved-TLD hallucinations plus
  live lookups — not a large labelled existence benchmark.
- **No large-scale ground truth** for "real but misdescribed" URLs.
- **No human usability study.**

### 14.8 Security / ethics

- Probes make outbound DNS/HTTP/WHOIS requests to arbitrary domains; the
  SSRF guard is basic.
- Dataset use is subject to the PhiUSIIL licence.

### 14.9 Summary

PhishGuard-HDV reliably separates **existence** (Stage A) from **maliciousness**
(Stage B) and avoids over-claiming, but it is bounded by what a URL **string**
reveals, by the coverage of two **reactive** threat feeds, and by an explicitly
**sequential** gate that intentionally skips phishing assessment for URLs that
do not resolve.
