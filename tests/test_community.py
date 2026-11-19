"""Community reports: storage, Excel export and decision sync."""
from pathlib import Path

import openpyxl

import community


def _add(db, url="https://evil-login.example/verify", domain="evil-login.example",
         note="Asked for my online banking password"):
    return community.add_report(
        url, domain, note, "", "Possible phishing", "ML model flags phishing-like features",
        db_path=db)


def test_report_is_saved_and_listed(tmp_path):
    db = tmp_path / "community.db"
    rid = _add(db)
    rows = community.list_reports(db_path=db)
    assert len(rows) == 1
    assert rows[0]["id"] == rid
    assert rows[0]["status"] == "pending"
    assert rows[0]["auto_label"] == "Possible phishing"


def test_duplicate_open_report_is_detected(tmp_path):
    db = tmp_path / "community.db"
    _add(db)
    # Same page, different scheme/query/trailing slash.
    assert community.find_open_report(
        "http://evil-login.example/verify/?x=1", db_path=db) is not None
    assert community.find_open_report(
        "https://evil-login.example/other", db_path=db) is None


def test_export_creates_excel_with_decision_dropdown(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    _add(db)
    community.export_reports(xlsx, db_path=db)

    wb = openpyxl.load_workbook(xlsx)
    assert wb.sheetnames == ["Reports", "How to review"]
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    assert headers[:4] == ["Report ID", "Submitted", "URL", "Domain"]
    assert "Decision" in headers
    assert ws.max_row == 2
    # The reviewer's dropdown exists.
    assert len(ws.data_validations.dataValidation) == 1


def test_approve_decision_updates_status_and_blocks_url(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    rid = _add(db)
    community.export_reports(xlsx, db_path=db)

    wb = openpyxl.load_workbook(xlsx)
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    ws.cell(row=2, column=headers.index("Decision") + 1, value="Approve")
    ws.cell(row=2, column=headers.index("Admin note") + 1, value="Confirmed by hand")
    wb.save(xlsx)

    applied = community.sync_decisions(xlsx, db_path=db)
    assert applied["approved"] == 1
    row = community.get_report(rid, db_path=db)
    assert row["status"] == "approved"
    assert row["admin_note"] == "Confirmed by hand"
    assert community.is_approved("https://evil-login.example/verify", db_path=db)
    assert not community.is_approved("https://other.example/", db_path=db)


def test_reject_decision_does_not_block(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    rid = _add(db)
    community.export_reports(xlsx, db_path=db)

    wb = openpyxl.load_workbook(xlsx)
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    ws.cell(row=2, column=headers.index("Decision") + 1, value="Reject")
    wb.save(xlsx)
    community.sync_decisions(xlsx, db_path=db)

    assert community.get_report(rid, db_path=db)["status"] == "rejected"
    assert not community.is_approved("https://evil-login.example/verify", db_path=db)


def test_decisions_survive_a_re_export(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    _add(db)
    community.export_reports(xlsx, db_path=db)

    wb = openpyxl.load_workbook(xlsx)
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    ws.cell(row=2, column=headers.index("Decision") + 1, value="Approve")
    ws.cell(row=2, column=headers.index("Admin note") + 1, value="keep me")
    wb.save(xlsx)

    community.export_reports(xlsx, db_path=db)  # simulate a refresh
    ws = openpyxl.load_workbook(xlsx)["Reports"]
    headers = [c.value for c in ws[1]]
    assert ws.cell(row=2, column=headers.index("Decision") + 1).value == "Approve"
    assert ws.cell(row=2, column=headers.index("Admin note") + 1).value == "keep me"


def test_approved_root_report_covers_the_domain(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    rid = community.add_report(
        "https://bad-bank.example/", "bad-bank.example", "",
        db_path=db)
    community.set_status(rid, "approve", db_path=db)

    assert community.is_approved("https://bad-bank.example/login", db_path=db)
    assert not community.is_approved("https://bad-bank.example.evil.test/", db_path=db)


def test_auto_verdict_mapping():
    assert community.auto_verdict(
        {"final_label": "Malicious"})[0] == "Confirmed phishing signal"
    assert community.auto_verdict(
        {"final_label": "Suspicious"})[0] == "Possible phishing"
    assert community.auto_verdict(
        {"final_label": "Hallucination"})[0] == "Does not exist"
    assert community.auto_verdict(
        {"final_label": "Likely Safe"})[0] == "No evidence found"


def test_status_counts(tmp_path):
    db = tmp_path / "community.db"
    a = _add(db)
    b = _add(db, url="https://second.example/x", domain="second.example")
    community.set_status(a, "approve", db_path=db)
    counts = community.status_counts(db_path=db)
    assert counts["approved"] == 1
    assert counts["pending"] == 1
    assert counts["rejected"] == 0
    assert community.get_report(b, db_path=db)["status"] == "pending"


def test_ensure_excel_current_only_writes_when_out_of_date(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    _add(db)
    assert community.ensure_excel_current(xlsx, db_path=db) == xlsx
    # The workbook now matches the database, so a second call does nothing.
    assert community.ensure_excel_current(xlsx, db_path=db) is None

    # A new report makes it stale again.
    _add(db, url="https://second.example/x", domain="second.example")
    assert community.ensure_excel_current(xlsx, db_path=db) == xlsx
    ws = openpyxl.load_workbook(xlsx)["Reports"]
    assert ws.max_row == 3


def test_sync_if_changed_applies_once_and_then_waits(tmp_path):
    db = tmp_path / "community.db"
    xlsx = tmp_path / "reports.xlsx"
    rid = _add(db)
    community.export_reports(xlsx, db_path=db)

    wb = openpyxl.load_workbook(xlsx)
    ws = wb["Reports"]
    headers = [c.value for c in ws[1]]
    ws.cell(row=2, column=headers.index("Decision") + 1, value="Approve")
    wb.save(xlsx)

    applied = community.sync_if_changed(xlsx, db_path=db)
    assert applied["approved"] == 1
    assert community.get_report(rid, db_path=db)["status"] == "approved"
    # Nothing changed since the last read, so the next rerun is a no-op.
    again = community.sync_if_changed(xlsx, db_path=db)
    assert again["approved"] == 0
