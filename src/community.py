"""Community phishing reports, reviewed in a local Excel file.

There is deliberately no admin login and no public download/upload. Reports are
stored in SQLite and mirrored to ``data/community_reports.xlsx`` on the machine
that runs the app. A reviewer opens that file, sets the Decision column
(Approve / Reject / Duplicate), saves it, and the app applies the decisions
automatically when it next sees the file change. Only **approved** reports
affect a verdict; pending reports never do.

Nothing here fetches a URL. The app runs the normal read-only pipeline before
saving a report, and this module only stores and reads the result.
"""
from __future__ import annotations

import datetime as _dt
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

ROOT = Path(__file__).resolve().parents[1]
EXCEL_PATH = ROOT / "data" / "community_reports.xlsx"

DECISION_TO_STATUS = {
    "approve": "approved",
    "approved": "approved",
    "yes": "approved",
    "reject": "rejected",
    "rejected": "rejected",
    "no": "rejected",
    "duplicate": "duplicate",
}
STATUS_TO_DECISION = {
    "approved": "Approve",
    "rejected": "Reject",
    "duplicate": "Duplicate",
}
STATUS_TEXT = {
    "pending": "Waiting for review",
    "approved": "Approved",
    "rejected": "Rejected",
    "duplicate": "Duplicate",
}

COLUMNS = [
    ("Report ID", 10),
    ("Submitted", 19),
    ("URL", 52),
    ("Domain", 26),
    ("Reporter note", 46),
    ("Contact", 24),
    ("Automatic check", 26),
    ("Why", 60),
    ("Status", 20),
    ("Decision", 14),
    ("Admin note", 34),
    ("Reviewed at", 19),
]
_DECISION_COL = [name for name, _ in COLUMNS].index("Decision") + 1


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    import db  # local import keeps this module free of a startup cycle

    return db.init_db(db_path)


def _domain_of(url: str) -> str:
    host = (urlparse(url or "").hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def normalise_url(url: str) -> str:
    """Compare URLs without scheme, query string, fragment or trailing slash."""
    p = urlparse((url or "").strip())
    host = (p.hostname or "").lower()
    path = (p.path or "/").rstrip("/") or "/"
    return f"{host}{path}".lower()


def _path_of(url: str) -> str:
    return (urlparse(url or "").path or "/").rstrip("/") or "/"


def auto_verdict(result: Dict) -> Tuple[str, str]:
    """Turn a pipeline result into a short recommendation for the reviewer."""
    label = str(result.get("final_label") or "")
    reason = str(result.get("reason") or "")
    if label == "Hallucination":
        return "Does not exist", reason
    if label == "Malicious":
        return "Confirmed phishing signal", reason
    if label.startswith("Suspicious"):
        return "Possible phishing", reason
    if label in ("Likely Safe", "Unverified"):
        return "No evidence found", reason
    return "Automatic check failed", reason


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def add_report(url: str, domain: str, note: str = "", contact: str = "",
               auto_label: str = "", auto_reason: str = "",
               db_path: Optional[Path] = None) -> int:
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO community_reports "
            "(url, domain, reporter_note, contact, auto_label, auto_reason) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url.strip(), domain.strip(), (note or "").strip()[:1000],
             (contact or "").strip()[:200], auto_label, auto_reason),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_report(report_id: int,
               db_path: Optional[Path] = None) -> Optional[dict]:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM community_reports WHERE id = ?",
                           (int(report_id),)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_reports(status: Optional[str] = None,
                 db_path: Optional[Path] = None) -> List[dict]:
    conn = _connect(db_path)
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM community_reports WHERE status = ? "
                "ORDER BY id DESC", (status,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM community_reports ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def status_counts(db_path: Optional[Path] = None) -> Dict[str, int]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM community_reports "
            "GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
    finally:
        conn.close()
    for key in STATUS_TEXT:
        counts.setdefault(key, 0)
    return counts


def find_open_report(url: str,
                     db_path: Optional[Path] = None) -> Optional[dict]:
    """An existing pending/approved report for the same URL."""
    target = normalise_url(url)
    for row in list_reports(db_path=db_path):
        if row["status"] not in ("pending", "approved"):
            continue
        if normalise_url(row["url"]) == target:
            return row
    return None


def set_status(report_id: int, decision: str, admin_note: str = "",
               db_path: Optional[Path] = None) -> bool:
    status = DECISION_TO_STATUS.get((decision or "").strip().lower())
    if not status:
        return False
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "UPDATE community_reports SET status = ?, admin_note = ?, "
            "reviewed_at = datetime('now', 'localtime') WHERE id = ?",
            (status, (admin_note or "").strip()[:1000] or None,
             int(report_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def is_approved(url: str, domain: Optional[str] = None,
                db_path: Optional[Path] = None) -> bool:
    """True only when a reviewer approved this exact URL (or a root domain)."""
    target = normalise_url(url)
    host = (domain or _domain_of(url)).lower()
    if host.startswith("www."):
        host = host[4:]
    for row in list_reports(status="approved", db_path=db_path):
        if normalise_url(row["url"]) == target:
            return True
        # A report on the site root covers the whole site, but a report on a
        # single page (e.g. a shared hosting path) does not.
        if _path_of(row["url"]) == "/" and (row.get("domain") or "").lower() == host:
            return True
    return False


# ---------------------------------------------------------------------------
# Excel review file
# ---------------------------------------------------------------------------

def _read_existing_decisions(path: Path) -> Dict[int, Tuple[str, str]]:
    """Preserve decisions the reviewer already typed before re-exporting."""
    if not path.exists():
        return {}
    try:
        wb = openpyxl.load_workbook(path)
        ws = wb["Reports"]
    except Exception:
        return {}
    headers = [c.value for c in ws[1]]
    try:
        id_col = headers.index("Report ID")
        dec_col = headers.index("Decision")
        note_col = headers.index("Admin note")
    except ValueError:
        return {}
    saved: Dict[int, Tuple[str, str]] = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if id_col >= len(row) or row[id_col] is None:
            continue
        try:
            rid = int(row[id_col])
        except (TypeError, ValueError):
            continue
        dec = row[dec_col] if dec_col < len(row) and row[dec_col] else ""
        note = row[note_col] if note_col < len(row) and row[note_col] else ""
        if dec or note:
            saved[rid] = (str(dec), str(note))
    return saved


def export_reports(path: Optional[Path] = None,
                   db_path: Optional[Path] = None) -> Path:
    """Write all reports to the review workbook, keeping typed decisions."""
    path = Path(path) if path is not None else EXCEL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_existing_decisions(path)
    rows = list_reports(db_path=db_path)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Reports"

    header_fill = PatternFill("solid", fgColor="1F3864")
    header_font = Font(bold=True, color="FFFFFF")
    for i, (name, width) in enumerate(COLUMNS, 1):
        cell = ws.cell(row=1, column=i, value=name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(vertical="center", wrap_text=True)
        ws.column_dimensions[cell.column_letter].width = width
    ws.row_dimensions[1].height = 26
    ws.freeze_panes = "A2"

    # Pending first, then the rest, newest first inside each group.
    rows.sort(key=lambda r: (r["status"] != "pending", -int(r["id"])))

    status_fill = {
        "pending": PatternFill("solid", fgColor="FFF2CC"),
        "approved": PatternFill("solid", fgColor="D9EAD3"),
        "rejected": PatternFill("solid", fgColor="F4CCCC"),
        "duplicate": PatternFill("solid", fgColor="E7E6E6"),
    }

    for i, r in enumerate(rows, 2):
        saved = existing.get(int(r["id"]), ("", ""))
        decision = saved[0] or STATUS_TO_DECISION.get(r["status"], "")
        admin_note = saved[1] or (r.get("admin_note") or "")
        values = [
            r["id"], r.get("timestamp", ""), r.get("url", ""),
            r.get("domain", ""), r.get("reporter_note", ""),
            r.get("contact", ""), r.get("auto_label", ""),
            r.get("auto_reason", ""),
            STATUS_TEXT.get(r["status"], r["status"]),
            decision, admin_note, r.get("reviewed_at", ""),
        ]
        for j, value in enumerate(values, 1):
            cell = ws.cell(row=i, column=j, value=value)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        ws.cell(row=i, column=9).fill = status_fill.get(r["status"], PatternFill())
        # Make the editable columns visually obvious.
        for col in (_DECISION_COL, _DECISION_COL + 1):
            ws.cell(row=i, column=col).fill = PatternFill("solid", fgColor="DEEAF6")

    last_data = max(len(rows) + 1, 2)
    ws.auto_filter.ref = f"A1:{ws.cell(row=1, column=len(COLUMNS)).column_letter}{last_data}"

    dv = DataValidation(
        type="list", formula1='"Approve,Reject,Duplicate"', allow_blank=True,
        showDropDown=False,
        error="Choose Approve, Reject or Duplicate.",
        errorTitle="Invalid decision",
    )
    ws.add_data_validation(dv)
    last_validation_row = max(200, last_data + 50)
    dv.add(f"{ws.cell(row=2, column=_DECISION_COL).column_letter}2:"
           f"{ws.cell(row=last_validation_row, column=_DECISION_COL).column_letter}"
           f"{last_validation_row}")

    # A short instruction sheet so the reviewer knows what to do.
    guide = wb.create_sheet("How to review")
    guide.column_dimensions["A"].width = 110
    lines = [
        "HOW TO REVIEW COMMUNITY REPORTS",
        "",
        "1. Go to the Reports sheet.",
        "2. For each URL, type a Decision: Approve, Reject or Duplicate.",
        "   Approve  = confirmed phishing; the main checker will treat it as Phishing.",
        "   Reject   = not phishing; the report is closed.",
        "   Duplicate = already covered by another report.",
        "3. You may add an Admin note.",
        "4. Save and close this file.",
        "5. Refresh the app page. The app reads this file automatically and",
        "   applies the decisions. There is no upload or download button.",
        "",
        "This file stays on the machine that runs the app. Do not share it.",
        "Only APPROVED reports change a verdict. Pending and rejected reports never do.",
        "Do not rename the sheet or the column headers.",
        "The 'Automatic check' column is the system's recommendation, not the final answer.",
    ]
    for i, line in enumerate(lines, 1):
        cell = guide.cell(row=i, column=1, value=line)
        cell.alignment = Alignment(wrap_text=False, vertical="top")
        if i == 1:
            cell.font = Font(bold=True, size=14)
    guide.sheet_view.showGridLines = False

    try:
        wb.save(path)
    except PermissionError as exc:
        raise PermissionError(
            f"Cannot write {path}. Close the Excel file and try again.") from exc
    return path


def _excel_row_count(path: Path) -> int:
    try:
        wb = openpyxl.load_workbook(path)
        ws = wb["Reports"]
        rows = ws.max_row - 1 if ws.max_row else 0
        wb.close()
        return max(rows, 0)
    except Exception:
        return -1


def ensure_excel_current(path: Optional[Path] = None,
                         db_path: Optional[Path] = None) -> Optional[Path]:
    """Create or refresh the local workbook only when it is out of date.

    Returns the path when it was written, otherwise None. This is called on the
    server side; the file is never offered to the public for download.
    """
    path = Path(path) if path is not None else EXCEL_PATH
    total = len(list_reports(db_path=db_path))
    if path.exists() and _excel_row_count(path) == total:
        return None
    return export_reports(path, db_path=db_path)


def sync_decisions(path: Optional[Path] = None,
                   db_path: Optional[Path] = None) -> Dict[str, int]:
    """Read Decisions from the workbook and apply them to the database."""
    path = Path(path) if path is not None else EXCEL_PATH
    applied = {"approved": 0, "rejected": 0, "duplicate": 0, "skipped": 0}
    if not path.exists():
        return applied

    wb = openpyxl.load_workbook(path)
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    try:
        id_col = headers.index("Report ID")
        dec_col = headers.index("Decision")
        note_col = headers.index("Admin note")
    except ValueError as exc:
        raise ValueError("The Excel file is missing one of the columns "
                         "'Report ID', 'Decision' or 'Admin note'.") from exc

    for row in ws.iter_rows(min_row=2, values_only=True):
        if id_col >= len(row) or row[id_col] is None:
            continue
        decision = str(row[dec_col] or "").strip().lower() if dec_col < len(row) else ""
        if not decision:
            continue
        note = str(row[note_col] or "").strip() if note_col < len(row) else ""
        try:
            rid = int(row[id_col])
        except (TypeError, ValueError):
            applied["skipped"] += 1
            continue
        status = DECISION_TO_STATUS.get(decision)
        if not status:
            applied["skipped"] += 1
            continue
        current = get_report(rid, db_path=db_path)
        if (current and current["status"] == status
                and (current.get("admin_note") or "") == note):
            applied[status] += 1
            continue
        if set_status(rid, decision, note, db_path=db_path):
            applied[status] += 1
        else:
            applied["skipped"] += 1

    # Refresh the Status column, keeping the decisions just typed.
    try:
        export_reports(path, db_path=db_path)
    except PermissionError:
        pass
    return applied


# mtime of the last workbook we read, so the app does not re-parse it on every
# Streamlit rerun.
_LAST_SYNC: Dict[str, float] = {}


def sync_if_changed(path: Optional[Path] = None,
                    db_path: Optional[Path] = None) -> Dict[str, int]:
    """Apply decisions automatically after the owner saves the local file.

    The public UI has no review buttons and no upload. The app notices a new
    file mtime and applies the decisions silently.
    """
    path = Path(path) if path is not None else EXCEL_PATH
    empty = {"approved": 0, "rejected": 0, "duplicate": 0, "skipped": 0}
    if not path.exists():
        return empty
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return empty
    key = str(path.resolve())
    if _LAST_SYNC.get(key) == mtime:
        return empty
    applied = sync_decisions(path, db_path=db_path)
    try:
        _LAST_SYNC[key] = path.stat().st_mtime
    except OSError:
        _LAST_SYNC[key] = mtime
    return applied
