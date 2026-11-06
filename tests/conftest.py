"""Make `src` importable for every test file in this suite."""
import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Tests never fetch real pages; page-inspection tests call analyse_html directly.
os.environ.setdefault("PHISHGUARD_PAGE_CHECK", "0")