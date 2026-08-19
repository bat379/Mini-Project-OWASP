"""
database/db_manager.py
-----------------------
Handles SQLite database creation and schema management for stored
scan findings.

Security concept demonstrated:
    Even though this app only *stores* its own scan output (never
    externally-supplied attacker data), we still use parameterized
    queries everywhere (see future scanner/report modules) rather than
    string-formatted SQL. This models OWASP A03:2021 "Injection"
    prevention as a habit, not just a reaction to untrusted input -
    a good defensive-coding practice is to *never* build SQL via
    string interpolation, regardless of the data's source.

    We also default to a local, file-based SQLite DB with no network
    exposure, avoiding any authentication/access-control surface for
    what is a single-user local lab tool.

This module currently only creates the schema. Insert/query helpers
for findings and scan history will be added when the scanner and
report modules are built (later steps), so each module can be
reviewed and tested independently.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

DB_PATH = Path(__file__).resolve().parent / "findings.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    security_score INTEGER,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    owasp_category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    why_it_matters TEXT,
    potential_impact TEXT,
    recommendation TEXT,
    risk_level TEXT CHECK(risk_level IN ('Low', 'Medium', 'High')) NOT NULL,
    evidence TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Columns added after the initial release. Kept as an explicit, logged
# migration step (rather than silently altering the schema above) so it's
# obvious from the code history what changed and why - the same "auditable
# startup" principle described in main.py.
_MIGRATIONS: list[tuple[str, str]] = [
    ("findings", "ALTER TABLE findings ADD COLUMN evidence TEXT DEFAULT ''"),
]


def _apply_migrations(conn: sqlite3.Connection) -> None:
    for table, statement in _MIGRATIONS:
        existing_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        col_name = statement.split("ADD COLUMN")[1].strip().split()[0]
        if col_name not in existing_cols:
            conn.execute(statement)
            logger.info("Applied migration to %s: %s", table, statement)


def get_connection() -> sqlite3.Connection:
    """
    Open a connection to the local findings database.

    Foreign key enforcement is explicitly enabled per-connection, since
    SQLite disables it by default.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Create the database file and required tables if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(_SCHEMA)
        _apply_migrations(conn)
        conn.commit()
    logger.info("Database schema verified at %s", DB_PATH)


def save_scan_result(scan_result) -> int:
    """
    Persist a completed ScanResult (see scanner.models) and all of its
    findings. Uses parameterized queries throughout - see the module
    docstring for why that's a deliberate habit here, not just a
    reaction to untrusted input.

    Args:
        scan_result: A `scanner.models.ScanResult` instance.

    Returns:
        The new scan's database id.
    """
    from datetime import datetime

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (target_url, scan_date, security_score, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result.target_url,
                scan_date,
                scan_result.security_score,
                scan_result.high_count,
                scan_result.medium_count,
                scan_result.low_count,
            ),
        )
        scan_id = cursor.lastrowid

        for finding in scan_result.findings:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_id, owasp_category, title, description,
                    why_it_matters, potential_impact, recommendation, risk_level, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.owasp_category.value,
                    finding.title,
                    finding.description,
                    finding.why_it_matters,
                    finding.potential_impact,
                    finding.recommendation,
                    finding.risk_level.value,
                    finding.evidence,
                ),
            )
        conn.commit()

    logger.info("Saved scan #%d for %s (%d findings)", scan_id, scan_result.target_url, len(scan_result.findings))
    return scan_id


def get_all_findings(risk_level: str | None = None, search: str | None = None) -> list:
    """
    Fetch findings across all scans, newest scan first, optionally
    filtered by risk level and/or a case-insensitive search term
    against the finding title.
    """
    query = """
        SELECT f.*, s.target_url, s.scan_date
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE 1=1
    """
    params: list = []

    if risk_level and risk_level != "All":
        query += " AND f.risk_level = ?"
        params.append(risk_level)

    if search:
        query += " AND LOWER(f.title) LIKE ?"
        params.append(f"%{search.lower()}%")

    query += " ORDER BY s.scan_date DESC, f.risk_level"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return list(rows)


def get_scan_history() -> list:
    """Fetch all scans, most recent first."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY scan_date DESC").fetchall()
    return list(rows)


def get_scan_by_id(scan_id: int):
    """Fetch a single scan row by id, or None if it doesn't exist."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return row


def get_findings_for_scan(scan_id: int) -> list:
    """Fetch all findings belonging to one specific scan (used for Reports
    and for the Learning Center's 'findings from your latest scan' view)."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT f.*, s.target_url, s.scan_date
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE f.scan_id = ?
            ORDER BY
                CASE f.risk_level WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END
            """,
            (scan_id,),
        ).fetchall()
    return list(rows)


def get_latest_scan_id() -> int | None:
    """Return the id of the most recently run scan, or None if there are none."""
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM scans ORDER BY scan_date DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def clear_all_history() -> None:
    """Delete every stored scan and finding. Used by Settings > 'Clear scan data'.

    Findings cascade-delete via the FOREIGN KEY ... ON DELETE CASCADE
    constraint declared in the schema (foreign_keys is enabled per
    connection in get_connection()).
    """
    with get_connection() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
    logger.info("Cleared all stored scans and findings")


# ----------------------------------------------------------------------
# Settings (simple key/value store, e.g. appearance mode, scan timeout)
# ----------------------------------------------------------------------
def get_setting(key: str, default: str | None = None) -> str | None:
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def get_all_settings() -> dict:
    with get_connection() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


def set_setting(key: str, value: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()
