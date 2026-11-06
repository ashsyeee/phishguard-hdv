"""
db.py - SQLite persistence for every analysis result.

The `results` table is both the liveness feed behind the Streamlit dashboard
and the audit log for the FYP report. Columns mirror the pipeline output dict
(see pipeline.analyze_url): Stage A hallucinations carry NULL Stage B columns.

SAFE MIGRATION (CHANGE 11)
--------------------------
init_db runs the CREATE TABLE IF NOT EXISTS schema, THEN checks the live
table's columns with PRAGMA table_info and issues ALTER TABLE ADD COLUMN for
any column added by a later version. Existing rows are never dropped - old
rows keep their values and simply read NULL for fields that did not exist yet.
"""

from __future__ import annotations

import logging
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("phishguard.db")

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "phishguard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp               TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    url                     TEXT    NOT NULL,
    domain                  TEXT,
    stage_reached           TEXT    NOT NULL,
    "exists"                INTEGER,
    grounding_score         REAL,
    rf_probability          REAL,
    xgb_probability         REAL,
    classifier_confidence   REAL,
    model_disagreement      REAL,
    verification_result     REAL,
    verification_coverage   REAL,
    threat_risk_score       REAL,
    risk_score              REAL,
    final_label             TEXT    NOT NULL,
    reason                  TEXT,
    source                  TEXT,
    llm_model               TEXT,
    original_user_question  TEXT,
    virustotal_result       TEXT,
    safe_browsing_result    TEXT,
    urlscan_result          TEXT,
    domain_age_days         INTEGER,
    page_signals            TEXT
);
"""

# Columns a newer schema may add to an older live database. Added via ALTER
# TABLE in _migrate(). Kept in one place so future columns stay auditable.
_NEW_COLUMNS = (
    ("rf_probability", "REAL"),
    ("xgb_probability", "REAL"),
    ("model_disagreement", "REAL"),
    ("verification_coverage", "REAL"),
    ("threat_risk_score", "REAL"),
    ("risk_score", "REAL"),
    ("source", "TEXT"),
    ("llm_model", "TEXT"),
    ("original_user_question", "TEXT"),
    ("virustotal_result", "TEXT"),
    ("safe_browsing_result", "TEXT"),
    ("urlscan_result", "TEXT"),
    ("domain_age_days", "INTEGER"),
    ("page_signals", "TEXT"),
    ("human_label", "TEXT"),
    ("reviewer_note", "TEXT"),
)

_SCHEMA_COLUMNS = (
    "id", "timestamp", "url", "domain", "stage_reached", "exists",
    "grounding_score", "rf_probability", "xgb_probability",
    "classifier_confidence", "model_disagreement", "verification_result",
    "verification_coverage", "threat_risk_score", "risk_score",
    "final_label", "reason", "source", "llm_model",
    "original_user_question", "virustotal_result", "safe_browsing_result",
    "urlscan_result", "domain_age_days", "page_signals",
)


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path if db_path is not None else DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _existing_columns(conn: sqlite3.Connection) -> set:
    return {row["name"] for row in conn.execute("PRAGMA table_info(results)")}


def _migrate(conn: sqlite3.Connection) -> None:
    """Add any missing columns in-place. Never drops data (CHANGE 11)."""
    have = _existing_columns(conn)
    for name, ctype in _NEW_COLUMNS:
        if name not in have:
            conn.execute(f"ALTER TABLE results ADD COLUMN {name} {ctype}")
            logger.info("Migrated results table: added column %s", name)
    conn.commit()


def init_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    conn = get_connection(db_path)
    conn.execute(SCHEMA)
    conn.commit()
    _migrate(conn)
    return conn


def log_result(result: Dict, db_path: Optional[Path] = None) -> int:
    """Persist one pipeline result dict. Returns the new row id."""
    conn = init_db(db_path)
    cur = conn.execute(
        """
        INSERT INTO results
            (url, domain, stage_reached, "exists", grounding_score,
             rf_probability, xgb_probability, classifier_confidence,
             model_disagreement, verification_result, verification_coverage,
             threat_risk_score, risk_score, final_label, reason,
             source, llm_model, original_user_question,
             virustotal_result, safe_browsing_result, urlscan_result,
             domain_age_days, page_signals)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.get("url", ""),
            result.get("domain"),
            result.get("stage_reached"),
            int(result["exists"]) if result.get("exists") is not None else None,
            result.get("grounding_score"),
            result.get("rf_probability"),
            result.get("xgb_probability"),
            result.get("classifier_confidence"),
            result.get("model_disagreement"),
            result.get("verification_result"),
            (result.get("verification_detail") or {}).get("coverage"),
            result.get("threat_risk_score"),
            result.get("risk_score"),
            result.get("final_label", "Unknown"),
            result.get("reason"),
            result.get("source"),
            result.get("llm_model"),
            result.get("original_user_question"),
            result.get("virustotal_result"),
            result.get("safe_browsing_result"),
            result.get("urlscan_result"),
            result.get("domain_age_days"),
            json.dumps(result.get("page_signals"), default=str) if result.get("page_signals") is not None else None,
        ),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_recent_results(n: int = 50, db_path: Optional[Path] = None) -> List[dict]:
    """Most recent n results, newest first."""
    conn = init_db(db_path)
    rows = conn.execute(
        "SELECT * FROM results ORDER BY id DESC LIMIT ?", (int(n),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_results(db_path: Optional[Path] = None) -> List[dict]:
    """Every stored result, newest first (Analytics page)."""
    conn = init_db(db_path)
    rows = conn.execute(
        "SELECT * FROM results ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def previous_hallucinations(domain: str, db_path: Optional[Path] = None) -> List[str]:
    """Timestamps of earlier results for this domain judged NOT to exist.

    Used for phantom-squatting: a domain the AI invented that later resolves
    may have been registered by someone else since.
    """
    if not domain:
        return []
    conn = init_db(db_path)
    rows = conn.execute(
        'SELECT timestamp FROM results WHERE domain = ? AND "exists" = 0 '
        "ORDER BY id DESC", (domain,)).fetchall()
    conn.close()
    return [r["timestamp"] for r in rows]


def set_review(row_id: int, label: Optional[str], note: Optional[str] = None,
               db_path: Optional[Path] = None) -> None:
    """Save a person's label (legitimate / phishing / unsure) for one result."""
    conn = init_db(db_path)
    conn.execute("UPDATE results SET human_label = ?, reviewer_note = ? WHERE id = ?",
                 (label or None, note or None, int(row_id)))
    conn.commit()
    conn.close()


def clear_results(db_path: Optional[Path] = None) -> int:
    """Wipe the table (demo/housekeeping). Returns rows deleted."""
    conn = init_db(db_path)
    cur = conn.execute("DELETE FROM results")
    conn.commit()
    conn.close()
    return cur.rowcount


def stats(db_path: Optional[Path] = None) -> Dict:
    """Aggregate counts for the Analytics page (mirrors the old contract).

    `verified`/`phishing`/`legitimate`/`high_risk`-style keys are kept so any
    legacy reader keeps working, with the new label vocabulary mapped onto
    them; the canonical new counts are expose under the *_label keys.
    """
    rows = get_recent_results(1_000_000, db_path)
    labels = [r["final_label"] for r in rows]
    risks = [r["threat_risk_score"] for r in rows
             if r.get("threat_risk_score") is not None]

    def count(*vals):
        return sum(1 for v in vals if v in labels)

    conn = get_connection(db_path)
    try:
        over_time = [
            dict(r) for r in conn.execute(
                "SELECT date(timestamp) AS day, COUNT(*) AS c "
                "FROM results GROUP BY date(timestamp) ORDER BY day").fetchall()
        ]
    finally:
        conn.close()

    return {
        "total_queries": len(rows),
        "urls_analysed": len({r["url"] for r in rows}),
        "hallucinations": count("Hallucination"),
        "suspicious": count("Suspicious"),
        "malicious": count("Malicious"),
        "unverified": count("Unverified"),
        "likely_safe": count("Likely Safe"),
        # legacy aliases (previous label vocabulary)
        "verified": count("Likely Safe"),
        "phishing": count("Malicious"),
        "legitimate": count("Likely Safe"),
        "high_risk": sum(1 for r in risks if r >= 0.66),
        "medium_risk": sum(1 for r in risks if 0.33 <= r < 0.66),
        "low_risk": sum(1 for r in risks if r < 0.33),
        "label_counts": {lbl: labels.count(lbl) for lbl in sorted(set(labels))},
        "grounding_counts": {lbl: labels.count(lbl) for lbl in sorted(set(labels))},
        "ml_counts": {
            "Malicious": count("Malicious"),
            "Likely Safe": count("Likely Safe"),
        },
        "over_time": over_time,
    }