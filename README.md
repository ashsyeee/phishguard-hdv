# PhishGuard-HDV — Streamlit Cloud deployment

This folder is the trimmed, deployment-ready copy of PhishGuard-HDV. It contains
only what the app needs at runtime:

```
app.py
requirements.txt
.streamlit/config.toml
src/                  # detection pipeline
modules/              # Gemini analyzer + URL extractor
ui/                   # Streamlit presentation layer
models/               # trained RandomForest + XGBoost (required at runtime)
data/processed/train.csv  # reference corpus used by the Stage A grounding store
```

`docs/`, `tests/`, training datasets, `models_v2/`, `models_backup_*/`, the local
database and real keys are intentionally not included.

## 1. Run locally (optional check)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## 2. Push this folder to GitHub

Create an empty GitHub repository (no README, no .gitignore), then from this
folder:

```powershell
git init
git add .
git commit -m "PhishGuard-HDV Streamlit Cloud deployment"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

The largest file is `models/random_forest.pkl` (~90 MB), which is below GitHub's
100 MB per-file limit, so Git LFS is not required.

## 3. Create the Streamlit Cloud app

1. Go to https://share.streamlit.io and sign in with GitHub.
2. Click **Create app** → **Deploy a public app from GitHub**.
3. Fill in:
   - **Repository:** `<your-username>/<repo-name>`
   - **Branch:** `main`
   - **Main file path:** `app.py`
4. Open **Advanced settings** and select **Python 3.13** (3.12 also works).
5. Click **Deploy**.

## 4. Add the API keys as Secrets

In the app dashboard: **Settings → Secrets**, paste this (fill in real values):

```toml
GEMINI_API_KEY = "..."
VIRUSTOTAL_API_KEY = "..."
GOOGLE_SAFE_BROWSING_KEY = "..."
URLHAUS_AUTH_KEY = "..."
URLSCAN_API_KEY = "..."
WHOISXML_API_KEY = "..."
```

All keys are optional: a missing key makes that source show as unavailable and
it is never counted as clean. The app mirrors `st.secrets` into the environment
at startup, so no code change is needed.

Never commit `.env`, `.streamlit/secrets.toml`, or `api key.txt` — they are in
`.gitignore`.

## Cloud behaviour to be aware of

- **Storage is ephemeral.** `phishguard.db` and `data/community_reports.xlsx`
  are recreated when the app restarts/redeploys. Analysis history and community
  reports do not survive a reboot of the cloud instance.
- **Community review file.** The Excel review workflow assumes the reviewer has
  access to the machine running the app. On Streamlit Cloud that file is inside
  the container, so use the app's read-only pages for a demo, or keep community
  reporting for local use.
- **The app is public** by default. Anyone with the URL can use your Gemini and
  threat-intel API keys. Consider adding a password gate or keeping the URL
  private if key usage matters.
