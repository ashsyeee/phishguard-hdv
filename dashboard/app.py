"""
dashboard/app.py - thin launcher for the single-source-of-truth dashboard.

Runs the same script as `streamlit run app.py` from the repo root, so both
entry points always show identical UI. All logic lives in the ROOT app.py.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

_ROOT_APP = Path(__file__).resolve().parent.parent / "app.py"
if str(_ROOT_APP) not in sys.path:
    sys.path.insert(0, str(_ROOT_APP))

runpy.run_path(str(_ROOT_APP), run_name="__main__")