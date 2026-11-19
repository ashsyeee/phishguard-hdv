# PhishGuard-HDV — checking whether an LLM's links are made up or phishing

PhishGuard-HDV is a Python system that never blindly trusts an LLM. Gemini
generates cybersecurity threat intelligence, and every URL in the answer is
independently checked in two separate steps:

1. **Stage A — does the link actually exist?** DNS, WHOIS/RDAP, an HTTP check of
   the exact page, and a reference list. If it cannot be confirmed, the result
   is **Hallucination** and Stage B never runs.
2. **Stage B — given that it exists, is it phishing?** A machine-learning model,
   four threat-intelligence sources, a read-only login-page check, and domain
   age. The result is one of **Phishing**, **Possible phishing**, **No phishing
   found**, **No phishing found (limited checks)**, or **Hallucination**.

A missing API key or a feed that fails is never counted as a pass or a fail.
Every result is logged in SQLite and explained in plain language.

---

## What the labels mean

| Label shown in the app | Stored label | When |
|---|---|---|
| **Phishing** | `Malicious` | A threat feed lists the URL, or the login page sends passwords to another site / redirects away / names another brand, or two independent checks fail |
| **Possible phishing** | `Suspicious` | Exactly one check fails (high ML score, brand name on the wrong domain, or domain under 30 days old) |
| **No phishing found** | `Likely Safe` | At least two feeds are clean, domain ≥180 days, ML <0.5, and existence is confirmed. For an official domain, the exact page must also answer |
| **No phishing found (limited checks)** | `Unverified` | Too few checks could run. The missing checks are shown, but never counted as passes |
| **Hallucination** | `Hallucination` | The link or the exact page does not exist (404/410), or existence cannot be confirmed |

The stored names are kept for backward compatibility with the database and the
evaluation scripts. The app, report and slides use the four plain labels above.

---

## Pipeline

```
User question
  -> Gemini (modules/llm_analyzer.py)
  -> URL extraction (modules/url_extractor.py)
  -> Stage A: existence / grounding (src/hallucination_detector.py)
       DNS + WHOIS/RDAP + exact-page HTTP check + reference list
       lookup failure != "does not exist" (errors stay neutral)
  -> Official-domain allowlist: exact registrable match, page must answer
  -> Stage B: phishing (src/pipeline.py)
       ML: RandomForest + XGBoost (src/classifiers.py)
       Feeds: VirusTotal, Google Safe Browsing, URLhaus, urlscan.io
       Domain age: WHOIS/RDAP, then WhoisXML if free lookup fails
       Login-page check: src/page_inspector.py (read-only HTML)
  -> Decision rules (src/risk_scoring.py)
  -> SQLite (src/db.py) -> Streamlit (app.py)
```

`threat_risk_score = 0.5 * verification_result + 0.5 * classifier_confidence`.
Grounding never adds to the threat score: existing is not dangerous.

**Hallucinated-domain re-registration.** A made-up domain is saved as a Hallucination. If the same
domain starts to resolve later, the app raises a re-registration alert and
labels it Possible phishing, because someone may have registered it since.

**Exact page matters.** A plausible path on a trusted domain is not accepted
just because the domain is real. HTTP 404/410 on a page path means
Hallucination. An official domain whose exact page blocks automated requests is
**No phishing found (limited checks)**, not a clean result. Some sites (for
example `www.ftc.gov`) answer a scripted request for their own home page with a
generic 404 from their CDN; that is detected as a block, so the domain's DNS and
WHOIS evidence still count and the page is reported as unconfirmed, not
fabricated.

---

## Pages

1. **Verify AI Threat Intelligence** — ask a question, generate an answer, and
   see every URL checked with gauges, a checklist of what ran, and evidence.
2. **Report a Phishing Site** — anyone can report a suspicious link, anonymously.
   Reports are checked automatically (read-only) and reviewed in an Excel file.
   No admin login is needed. Only **approved** reports change a verdict.
3. **Analysis History** — filter by label, add your own label and note, export CSV.
4. **About the System** — the design and the hallucinated-domain note.

---

## Community reports (Excel review, no login)

Reports are stored in `community_reports` in SQLite and mirrored to
`data/community_reports.xlsx` on the machine that runs the app. The file is
never offered to the public for download, and there is no upload box, so nobody
can inject decisions through the app. To review:

1. Open `data/community_reports.xlsx` directly from the project folder.
2. For each row, choose **Approve**, **Reject** or **Duplicate** in the Decision
   column. Add an Admin note if you want.
3. Save and close the file.
4. Refresh the app page. The app notices the file changed and applies the
   decisions automatically.

Only approved reports affect a verdict: an approved URL is labelled
**Phishing** with the reason "approved community report". Pending, rejected and
duplicate reports never do. The page also limits each session to five reports,
rejects duplicate open reports, and never opens a submitted URL in a browser.

> The Excel file stays on the machine running the app. If you deploy publicly,
> the reviewer needs file access to that machine; the public UI gives them none.

---

## Setup

Windows, easiest path: double-click **`run.bat`**. It finds Python, installs the
requirements, creates `.env` from `.env.example` if needed, and starts the app.

Manual setup:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# edit .env and add the keys you have
streamlit run app.py
```

Open `http://localhost:8501`.

### API keys

All keys are optional. A source without a key is shown as unavailable and is
excluded from the count; it is never treated as clean.

| Key | Used for |
|---|---|
| `GEMINI_API_KEY` | Generating threat intelligence |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain/URL verdicts |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing matches |
| `URLHAUS_AUTH_KEY` | URLhaus malware-host matches |
| `URLSCAN_API_KEY` | Existing urlscan.io scans (search only, never submits) |
| `WHOISXML_API_KEY` | Domain age fallback when free WHOIS/RDAP fails |

PhishTank and the OpenRouter fallback were removed because no keys were
available for them. Gemini is the only LLM provider.

---

## Deploy on Streamlit Community Cloud

1. Push this folder to GitHub as a repository (branch `main`, `app.py` at the root).
2. Open <https://share.streamlit.io> -> **New app** -> pick the repository ->
   branch `main` -> main file path `app.py`.
3. In **Advanced settings**, select **Python 3.14** (the version the models were
   built with).
4. Paste the keys into **Secrets** (TOML, same names as `.env`):

   ```toml
   GEMINI_API_KEY = "..."
   VIRUSTOTAL_API_KEY = "..."
   GOOGLE_SAFE_BROWSING_KEY = "..."
   URLHAUS_AUTH_KEY = "..."
   URLSCAN_API_KEY = "..."
   WHOISXML_API_KEY = "..."
   ```

5. Deploy. `app.py` mirrors `st.secrets` into the environment, so no code
   changes are needed.

Deployment notes:

- **Never commit** `.env`, `api key.txt`, or `.streamlit/secrets.toml`. They are
  git-ignored; keep them only on your machine.
- On Community Cloud the filesystem is ephemeral: `phishguard.db` (analysis
  history) and `data/community_reports.xlsx` are recreated on restart, and the
  Excel review step is not reachable from the hosted app. The verification
  pipeline itself is unaffected.
- First load takes roughly 25-40 s: the Random Forest (~90 MB) and the
  154k-domain reference index are loaded once and cached per process.

---

## Tests

```powershell
python -m pytest tests -q
```

**216 tests pass.** They cover the Stage A/B separation, the training-data guard,
source-status handling, the clean rule, the page check, the allowlist, database
migrations, hallucinated-domain re-registration alerts, and the community report/Excel workflow.

The suite never fetches real pages: `tests/conftest.py` sets
`PHISHGUARD_PAGE_CHECK=0`, and HTML tests call `analyse_html` directly.

---

## Evaluation

- `src/regression.py` runs a fixed regression set against the saved models.
- `data/regression/regression_set.csv` holds the URLs and labels.
- `docs/fyp/build_fyp.py` regenerates the FYP report, slides and chart.
- Models live in `models/`. The split is grouped by registrable domain, so the
  same domain never appears in both training and test sets.

Read the authoritative numbers from the saved evaluation files, not from this
README, so they cannot drift.

---

## Repository layout

```
phishguard-hdv/
├── app.py                      # Streamlit app (4 pages)
├── run.bat                     # one-click launcher for Windows
├── requirements.txt / .env.example / .gitignore
├── src/
│   ├── pipeline.py             # Stage A -> Stage B orchestration
│   ├── hallucination_detector.py
│   ├── classifiers.py          # RandomForest + XGBoost
│   ├── verification_engine.py  # VirusTotal, Safe Browsing, URLhaus, urlscan, WhoisXML
│   ├── page_inspector.py       # read-only login-page signals
│   ├── risk_scoring.py         # labels and clean/possible-phishing rules
│   ├── features.py             # 30 URL features, allowlist, brand domains
│   ├── community.py            # community reports + Excel review
│   ├── db.py                   # SQLite schema, migrations, history
│   ├── regression.py           # fixed regression harness
│   └── train_v2.py             # model training with leakage guard
├── modules/                    # Gemini analyzer + URL extractor
├── ui/                         # status mapping, components, styles
├── data/
│   ├── regression/             # regression set + history
│   └── community_reports.xlsx  # created on first use (git-ignored)
├── models/                     # trained models used at runtime
├── docs/fyp/                   # report, slides, chart, build script
└── tests/                      # pytest suite (186 tests)
```

---

## Design honesty

- **"No match" is not "safe".** A feed with nothing to say is reported as no
  match, not as proof of safety.
- **A missing source is missing.** Coverage counts only configured sources that
  actually answered.
- **The allowlist is not a registry.** It was built by checking page titles and
  links, so a copied page could still get past it.
- **The model is trained mostly on international data**, so Malaysian legitimate
  sites remain the weak point. The allowlist and deterministic rules carry most
  of the weight there.
- **The login-page check reads HTML only.** It never runs scripts, submits forms,
  or opens a suspicious page in a browser.
- **Community reports are only as good as the reviewer.** A wrong approval would
  mark a legitimate site as phishing.
