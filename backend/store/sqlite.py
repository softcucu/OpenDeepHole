"""SQLite implementation of ScanStoreBase."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from backend.models import (
    Candidate,
    FeedbackEntry,
    FpReviewJob,
    FpReviewResult,
    FpReviewStatus,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    UserInDB,
    Vulnerability,
)

from .base import ScanStoreBase

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
    scan_id            TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL,
    scan_items         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    created_at         TEXT NOT NULL,
    progress           REAL DEFAULT 0.0,
    total_candidates   INTEGER DEFAULT 0,
    processed_candidates INTEGER DEFAULT 0,
    current_candidate  TEXT,
    error_message      TEXT,
    feedback_ids       TEXT DEFAULT '[]',
    workspace_path     TEXT,
    product            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    idx                 INTEGER NOT NULL,
    file                TEXT NOT NULL,
    line                INTEGER NOT NULL,
    function            TEXT NOT NULL,
    vuln_type           TEXT NOT NULL,
    severity            TEXT NOT NULL,
    description         TEXT NOT NULL,
    ai_analysis         TEXT NOT NULL,
    confirmed           INTEGER NOT NULL,
    function_source     TEXT NOT NULL DEFAULT '',
    function_start_line INTEGER,
    user_verdict        TEXT,
    user_verdict_reason TEXT,
    ticket_submitted    INTEGER NOT NULL DEFAULT 0,
    ticket_id           TEXT NOT NULL DEFAULT '',
    UNIQUE(scan_id, idx)
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    timestamp       TEXT NOT NULL,
    phase           TEXT NOT NULL,
    message         TEXT NOT NULL,
    candidate_index INTEGER
);

CREATE TABLE IF NOT EXISTS processed_keys (
    scan_id   TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    file      TEXT NOT NULL,
    line      INTEGER NOT NULL,
    function  TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    PRIMARY KEY(scan_id, file, line, function, vuln_type)
);

CREATE TABLE IF NOT EXISTS feedback_entries (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    function        TEXT NOT NULL,
    description     TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    ticket_submitted INTEGER NOT NULL DEFAULT 0,
    ticket_id       TEXT NOT NULL DEFAULT '',
    function_source TEXT NOT NULL DEFAULT '',
    function_start_line INTEGER,
    source_scan_id  TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_project ON feedback_entries(project_id);
CREATE INDEX IF NOT EXISTS idx_feedback_project_type ON feedback_entries(project_id, vuln_type);

CREATE TABLE IF NOT EXISTS fp_review_jobs (
    review_id     TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    TEXT NOT NULL,
    total         INTEGER DEFAULT 0,
    processed     INTEGER DEFAULT 0,
    current_vuln_index INTEGER,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS fp_review_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
    vuln_index  INTEGER NOT NULL,
    verdict     TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    reason      TEXT NOT NULL,
    vulnerability_report TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE(review_id, vuln_index)
);

CREATE INDEX IF NOT EXISTS idx_fp_review_scan ON fp_review_jobs(scan_id);

CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    agent_token   TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""


class SqliteScanStore(ScanStoreBase):
    """SQLite-backed scan store using WAL mode for concurrent access."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False
        )
        self._lock = threading.Lock()  # 保护多线程下 execute+commit 的原子性
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add columns that may not exist in older databases."""
        cur = self._conn.execute("PRAGMA table_info(scans)")
        cols = {r[1] for r in cur.fetchall()}
        if "feedback_ids" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN feedback_ids TEXT DEFAULT '[]'")
        if "workspace_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN workspace_path TEXT")
        if "static_total_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_total_files INTEGER DEFAULT 0")
        if "static_scanned_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_scanned_files INTEGER DEFAULT 0")
        if "static_analysis_done" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_analysis_done INTEGER DEFAULT 0")
        if "agent_id" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_id TEXT DEFAULT ''")
        if "agent_name" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_name TEXT DEFAULT ''")
        if "project_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN project_path TEXT DEFAULT ''")
        if "code_scan_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN code_scan_path TEXT DEFAULT ''")
        if "scan_name" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN scan_name TEXT DEFAULT ''")
        if "user_id" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT ''")
        if "product" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN product TEXT NOT NULL DEFAULT ''")
        # vulnerabilities 表迁移
        vuln_cur = self._conn.execute("PRAGMA table_info(vulnerabilities)")
        vuln_cols = {r[1] for r in vuln_cur.fetchall()}
        if "ai_verdict" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ai_verdict TEXT DEFAULT ''"
            )
        if "function_source" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN function_source TEXT DEFAULT ''"
            )
        if "function_start_line" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN function_start_line INTEGER"
            )
        if "ticket_submitted" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ticket_submitted INTEGER NOT NULL DEFAULT 0"
            )
        if "ticket_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ticket_id TEXT NOT NULL DEFAULT ''"
            )

        feedback_cur = self._conn.execute("PRAGMA table_info(feedback_entries)")
        feedback_cols = {r[1] for r in feedback_cur.fetchall()}
        if "function_source" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN function_source TEXT DEFAULT ''"
            )
        if "function_start_line" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN function_start_line INTEGER"
            )
        if "ticket_submitted" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN ticket_submitted INTEGER NOT NULL DEFAULT 0"
            )
        if "ticket_id" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN ticket_id TEXT NOT NULL DEFAULT ''"
            )
        # Ensure users table exists
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user',
                agent_token   TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
        """)
        # Ensure FP review tables exist (created by _SCHEMA on fresh DBs; add for old ones)
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS fp_review_jobs (
                review_id     TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TEXT NOT NULL,
                total         INTEGER DEFAULT 0,
                processed     INTEGER DEFAULT 0,
                current_vuln_index INTEGER,
                error_message TEXT
            );
            CREATE TABLE IF NOT EXISTS fp_review_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
                vuln_index  INTEGER NOT NULL,
                verdict     TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'low',
                reason      TEXT NOT NULL,
                vulnerability_report TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL,
                UNIQUE(review_id, vuln_index)
            );
            CREATE INDEX IF NOT EXISTS idx_fp_review_scan ON fp_review_jobs(scan_id);
        """)
        fp_job_cur = self._conn.execute("PRAGMA table_info(fp_review_jobs)")
        fp_job_cols = {r[1] for r in fp_job_cur.fetchall()}
        if "current_vuln_index" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN current_vuln_index INTEGER"
            )
        fp_cur = self._conn.execute("PRAGMA table_info(fp_review_results)")
        fp_cols = {r[1] for r in fp_cur.fetchall()}
        if "severity" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN severity TEXT NOT NULL DEFAULT 'low'"
            )
        if "vulnerability_report" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN vulnerability_report TEXT NOT NULL DEFAULT ''"
            )
        self._conn.commit()

    # -- helpers --

    def _row_to_scan_status(self, row: sqlite3.Row) -> ScanStatus:
        current = None
        if row["current_candidate"]:
            current = Candidate.model_validate_json(row["current_candidate"])
        return ScanStatus(
            scan_id=row["scan_id"],
            project_id=row["project_id"],
            product=row["product"] if row["product"] is not None else "",
            scan_items=json.loads(row["scan_items"]),
            created_at=row["created_at"],
            status=ScanItemStatus(row["status"]),
            progress=row["progress"],
            total_candidates=row["total_candidates"],
            processed_candidates=row["processed_candidates"],
            vulnerabilities=self.get_vulnerabilities(row["scan_id"]),
            events=self.get_events(row["scan_id"]),
            current_candidate=current,
            error_message=row["error_message"],
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            static_total_files=row["static_total_files"] or 0,
            static_scanned_files=row["static_scanned_files"] or 0,
            static_analysis_done=bool(row["static_analysis_done"]),
        )

    def _row_to_meta(self, row: sqlite3.Row) -> ScanMeta:
        return ScanMeta(
            scan_items=json.loads(row["scan_items"]),
            created_at=row["created_at"],
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            agent_id=row["agent_id"] if row["agent_id"] is not None else "",
            agent_name=row["agent_name"] if row["agent_name"] is not None else "",
            project_path=row["project_path"] if row["project_path"] is not None else "",
            code_scan_path=row["code_scan_path"] if row["code_scan_path"] is not None else "",
            scan_name=row["scan_name"] if row["scan_name"] is not None else "",
            product=row["product"] if row["product"] is not None else "",
            user_id=row["user_id"] if row["user_id"] is not None else "",
        )

    # -- Scan lifecycle --

    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        current_json = (
            scan.current_candidate.model_dump_json()
            if scan.current_candidate
            else None
        )
        with self._lock:
            self._conn.execute(
                """\
                INSERT OR REPLACE INTO scans
                    (scan_id, project_id, scan_items, status, created_at,
                     progress, total_candidates, processed_candidates,
                     current_candidate, error_message, feedback_ids,
                     static_total_files, static_scanned_files, static_analysis_done,
                     user_id, agent_name, agent_id, project_path, code_scan_path, scan_name,
                     product)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id,
                    scan.project_id,
                    json.dumps(meta.scan_items),
                    scan.status.value,
                    meta.created_at,
                    scan.progress,
                    scan.total_candidates,
                    scan.processed_candidates,
                    current_json,
                    scan.error_message,
                    json.dumps(meta.feedback_ids),
                    scan.static_total_files,
                    scan.static_scanned_files,
                    int(scan.static_analysis_done),
                    meta.user_id,
                    meta.agent_name,
                    meta.agent_id,
                    meta.project_path,
                    meta.code_scan_path,
                    meta.scan_name,
                    meta.product,
                ),
            )
            self._conn.commit()

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_scan_status(row), self._row_to_meta(row)

    def _row_to_scan_summary(self, row: sqlite3.Row) -> ScanSummary:
        return ScanSummary(
            scan_id=row["scan_id"],
            project_id=row["project_id"],
            scan_name=row["scan_name"] if row["scan_name"] is not None else "",
            product=row["product"] if row["product"] is not None else "",
            status=ScanItemStatus(row["status"]),
            created_at=row["created_at"],
            progress=row["progress"],
            total_candidates=row["total_candidates"],
            processed_candidates=row["processed_candidates"],
            vulnerability_count=row["vuln_count"],
            scan_items=json.loads(row["scan_items"]),
            user_id=row["user_id"] if row["user_id"] is not None else "",
            username=row["username"] if "username" in row.keys() and row["username"] is not None else "",
            agent_name=row["agent_name"] if row["agent_name"] is not None else "",
        )

    def list_scans(self) -> list[ScanSummary]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT s.*, COUNT(v.id) AS vuln_count, u.username
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
            LEFT JOIN users u ON s.user_id = u.user_id
            GROUP BY s.scan_id
            ORDER BY s.created_at DESC
            """
        )
        return [self._row_to_scan_summary(row) for row in cur.fetchall()]

    def list_scans_by_user(self, user_id: str) -> list[ScanSummary]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT s.*, COUNT(v.id) AS vuln_count, u.username
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
            LEFT JOIN users u ON s.user_id = u.user_id
            WHERE s.user_id = ?
            GROUP BY s.scan_id
            ORDER BY s.created_at DESC
            """,
            (user_id,),
        )
        return [self._row_to_scan_summary(row) for row in cur.fetchall()]

    def update_scan_product(self, scan_id: str, product: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET product = ? WHERE scan_id = ?",
                (product, scan_id),
            )
            self._conn.commit()

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE scan_id = ?", (scan_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count_scans_for_project(self, project_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE project_id = ?",
            (project_id,),
        )
        return cur.fetchone()[0]

    # -- Progress updates --

    def update_scan_progress(
        self,
        scan_id: str,
        *,
        status: ScanItemStatus | None = None,
        progress: float | None = None,
        total_candidates: int | None = None,
        processed_candidates: int | None = None,
        current_candidate: Candidate | None = None,
        clear_current_candidate: bool = False,
        error_message: str | None = None,
        static_total_files: int | None = None,
        static_scanned_files: int | None = None,
        static_analysis_done: bool | None = None,
    ) -> None:
        updates: list[str] = []
        params: list = []

        if status is not None:
            updates.append("status = ?")
            params.append(status.value)
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if total_candidates is not None:
            updates.append("total_candidates = ?")
            params.append(total_candidates)
        if processed_candidates is not None:
            updates.append("processed_candidates = ?")
            params.append(processed_candidates)
        if current_candidate is not None:
            updates.append("current_candidate = ?")
            params.append(current_candidate.model_dump_json())
        elif clear_current_candidate:
            updates.append("current_candidate = NULL")
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if static_total_files is not None:
            updates.append("static_total_files = ?")
            params.append(static_total_files)
        if static_scanned_files is not None:
            updates.append("static_scanned_files = ?")
            params.append(static_scanned_files)
        if static_analysis_done is not None:
            updates.append("static_analysis_done = ?")
            params.append(int(static_analysis_done))

        if not updates:
            return

        params.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?"
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def update_scan_agent(self, scan_id: str, agent_id: str, agent_name: str = "") -> None:
        """Update the agent_id (and optionally agent_name) for a scan."""
        with self._lock:
            if agent_name:
                self._conn.execute(
                    "UPDATE scans SET agent_id = ?, agent_name = ? WHERE scan_id = ?",
                    (agent_id, agent_name, scan_id),
                )
            else:
                self._conn.execute(
                    "UPDATE scans SET agent_id = ? WHERE scan_id = ?",
                    (agent_id, scan_id),
                )
            self._conn.commit()

    def update_scan_feedback_ids(self, scan_id: str, feedback_ids: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET feedback_ids = ? WHERE scan_id = ?",
                (json.dumps(feedback_ids), scan_id),
            )
            self._conn.commit()

    def update_scan_workspace(self, scan_id: str, workspace_path: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET workspace_path = ? WHERE scan_id = ?",
                (workspace_path, scan_id),
            )
            self._conn.commit()

    def get_scan_workspace(self, scan_id: str) -> str | None:
        cur = self._conn.execute(
            "SELECT workspace_path FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    # -- Vulnerabilities --

    def count_vulnerabilities(self, scan_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
        )
        return cur.fetchone()[0]

    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COALESCE(MAX(idx), -1) FROM vulnerabilities WHERE scan_id = ?",
                (scan_id,),
            )
            next_idx = cur.fetchone()[0] + 1

            self._conn.execute(
                """\
                INSERT INTO vulnerabilities
                    (scan_id, idx, file, line, function, vuln_type,
                     severity, description, ai_analysis, confirmed,
                     ai_verdict, user_verdict, user_verdict_reason,
                     ticket_submitted, ticket_id,
                     function_source, function_start_line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    next_idx,
                    vuln.file,
                    vuln.line,
                    vuln.function,
                    vuln.vuln_type,
                    vuln.severity,
                    vuln.description,
                    vuln.ai_analysis,
                    1 if vuln.confirmed else 0,
                    vuln.ai_verdict,
                    vuln.user_verdict,
                    vuln.user_verdict_reason,
                    1 if vuln.ticket_submitted else 0,
                    vuln.ticket_id if vuln.ticket_submitted else "",
                    vuln.function_source,
                    vuln.function_start_line,
                ),
            )
            self._conn.commit()
            return next_idx

    def update_vulnerability(
        self,
        scan_id: str,
        index: int,
        verdict: str,
        reason: str,
        ticket_submitted: bool = False,
        ticket_id: str = "",
    ) -> None:
        normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""
        with self._lock:
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET user_verdict = ?,
                    user_verdict_reason = ?,
                    ticket_submitted = ?,
                    ticket_id = ?
                WHERE scan_id = ? AND idx = ?
                """,
                (
                    verdict,
                    reason,
                    1 if ticket_submitted else 0,
                    normalized_ticket_id,
                    scan_id,
                    index,
                ),
            )
            self._conn.commit()

    def get_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT * FROM vulnerabilities
            WHERE scan_id = ? ORDER BY idx
            """,
            (scan_id,),
        )
        return [
            Vulnerability(
                file=r["file"],
                line=r["line"],
                function=r["function"],
                vuln_type=r["vuln_type"],
                severity=r["severity"],
                description=r["description"],
                ai_analysis=r["ai_analysis"],
                confirmed=bool(r["confirmed"]),
                ai_verdict=r["ai_verdict"] or "",
                user_verdict=r["user_verdict"],
                user_verdict_reason=r["user_verdict_reason"],
                ticket_submitted=bool(r["ticket_submitted"]),
                ticket_id=r["ticket_id"] or "",
                function_source=r["function_source"] or "",
                function_start_line=r["function_start_line"],
            )
            for r in cur.fetchall()
        ]

    # -- Events --

    def add_event(self, scan_id: str, event: ScanEvent) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO events
                    (scan_id, timestamp, phase, message, candidate_index)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    event.timestamp,
                    event.phase,
                    event.message,
                    event.candidate_index,
                ),
            )
            self._conn.commit()

    def get_events(self, scan_id: str) -> list[ScanEvent]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM events WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )
        return [
            ScanEvent(
                timestamp=r["timestamp"],
                phase=r["phase"],
                message=r["message"],
                candidate_index=r["candidate_index"],
            )
            for r in cur.fetchall()
        ]

    # -- Processed keys --

    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT OR IGNORE INTO processed_keys
                    (scan_id, file, line, function, vuln_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, *key),
            )
            self._conn.commit()

    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        cur = self._conn.execute(
            "SELECT file, line, function, vuln_type FROM processed_keys WHERE scan_id = ?",
            (scan_id,),
        )
        return {(r[0], r[1], r[2], r[3]) for r in cur.fetchall()}

    # -- Feedback entries --

    def add_feedback(self, entry: FeedbackEntry) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO feedback_entries
                    (id, project_id, vuln_type, verdict, file, line, function,
                     description, reason, ticket_submitted, ticket_id,
                     function_source, function_start_line,
                     source_scan_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id, entry.project_id, entry.vuln_type, entry.verdict,
                    entry.file, entry.line, entry.function, entry.description,
                    entry.reason,
                    1 if entry.ticket_submitted else 0,
                    entry.ticket_id if entry.ticket_submitted else "",
                    entry.function_source, entry.function_start_line,
                    entry.source_scan_id,
                    entry.created_at, entry.updated_at,
                ),
            )
            self._conn.commit()

    def upsert_feedback_for_report(self, entry: FeedbackEntry) -> FeedbackEntry:
        if not entry.source_scan_id:
            self.add_feedback(entry)
            return entry

        self._conn.row_factory = sqlite3.Row
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT id
                FROM feedback_entries
                WHERE source_scan_id = ?
                  AND project_id = ?
                  AND vuln_type = ?
                  AND file = ?
                  AND line = ?
                  AND function = ?
                  AND description = ?
                ORDER BY created_at ASC, id ASC
                """,
                (
                    entry.source_scan_id,
                    entry.project_id,
                    entry.vuln_type,
                    entry.file,
                    entry.line,
                    entry.function,
                    entry.description,
                ),
            )
            matching_ids = [row["id"] for row in cur.fetchall()]
            if not matching_ids:
                self._conn.execute(
                    """\
                    INSERT INTO feedback_entries
                        (id, project_id, vuln_type, verdict, file, line, function,
                         description, reason, ticket_submitted, ticket_id,
                         function_source, function_start_line,
                         source_scan_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.id, entry.project_id, entry.vuln_type, entry.verdict,
                        entry.file, entry.line, entry.function, entry.description,
                        entry.reason,
                        1 if entry.ticket_submitted else 0,
                        entry.ticket_id if entry.ticket_submitted else "",
                        entry.function_source, entry.function_start_line,
                        entry.source_scan_id,
                        entry.created_at, entry.updated_at,
                    ),
                )
                kept_id = entry.id
            else:
                kept_id = matching_ids[0]
                self._conn.execute(
                    """\
                    UPDATE feedback_entries
                    SET verdict = ?,
                        reason = ?,
                        ticket_submitted = ?,
                        ticket_id = ?,
                        function_source = ?,
                        function_start_line = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        entry.verdict,
                        entry.reason,
                        1 if entry.ticket_submitted else 0,
                        entry.ticket_id if entry.ticket_submitted else "",
                        entry.function_source,
                        entry.function_start_line,
                        entry.updated_at,
                        kept_id,
                    ),
                )
                duplicate_ids = matching_ids[1:]
                if duplicate_ids:
                    placeholders = ", ".join("?" for _ in duplicate_ids)
                    self._conn.execute(
                        f"DELETE FROM feedback_entries WHERE id IN ({placeholders})",
                        duplicate_ids,
                    )
            self._conn.commit()

            cur = self._conn.execute(
                "SELECT * FROM feedback_entries WHERE id = ?",
                (kept_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"feedback entry not found after upsert: {kept_id}")
            return self._row_to_feedback(row)

    def update_feedback(
        self,
        feedback_id: str,
        verdict: str | None,
        reason: str | None,
        ticket_submitted: bool | None = None,
        ticket_id: str | None = None,
    ) -> bool:
        updates: list[str] = []
        params: list = []
        if verdict is not None:
            updates.append("verdict = ?")
            params.append(verdict)
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason)
        if ticket_submitted is not None:
            updates.append("ticket_submitted = ?")
            params.append(1 if ticket_submitted else 0)
            if not ticket_submitted and ticket_id is None:
                updates.append("ticket_id = ?")
                params.append("")
        if ticket_id is not None:
            updates.append("ticket_id = ?")
            params.append(ticket_id.strip() if ticket_submitted is not False else "")
        if not updates:
            return True
        updates.append("updated_at = ?")
        params.append(
            __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
        )
        params.append(feedback_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE feedback_entries SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_feedback(self, feedback_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM feedback_entries WHERE id = ?", (feedback_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def list_feedback(self, vuln_type: str | None = None, project_id: str | None = None) -> list[FeedbackEntry]:
        self._conn.row_factory = sqlite3.Row
        conditions: list[str] = []
        params: list = []
        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)
        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries{where} ORDER BY created_at DESC",
            params,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def list_feedback_by_scan(self, scan_id: str) -> list[FeedbackEntry]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM feedback_entries WHERE source_scan_id = ? ORDER BY created_at DESC",
            (scan_id,),
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def get_feedback_by_ids(self, ids: list[str]) -> list[FeedbackEntry]:
        if not ids:
            return []
        self._conn.row_factory = sqlite3.Row
        placeholders = ", ".join("?" for _ in ids)
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries WHERE id IN ({placeholders})",
            ids,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def _row_to_feedback(self, row: sqlite3.Row) -> FeedbackEntry:
        return FeedbackEntry(
            id=row["id"],
            project_id=row["project_id"],
            vuln_type=row["vuln_type"],
            verdict=row["verdict"],
            file=row["file"],
            line=row["line"],
            function=row["function"],
            description=row["description"],
            reason=row["reason"],
            function_source=row["function_source"] or "",
            function_start_line=row["function_start_line"],
            source_scan_id=row["source_scan_id"],
            ticket_submitted=bool(row["ticket_submitted"]),
            ticket_id=row["ticket_id"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # -- Crash recovery --

    def mark_running_as_error(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE scans SET status = 'error',
                                 error_message = 'Process terminated unexpectedly',
                                 current_candidate = NULL
                WHERE status IN ('pending', 'analyzing', 'auditing')
                  AND (agent_name IS NULL OR agent_name = '')
                """
            )
            self._conn.commit()
            return cur.rowcount

    def mark_agent_scans_cancelled(self, agent_id: str, error_message: str) -> list[str]:
        if not agent_id:
            return []
        running_statuses = ("pending", "analyzing", "auditing")
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT scan_id
                FROM scans
                WHERE agent_id = ?
                  AND status IN (?, ?, ?)
                """,
                (agent_id, *running_statuses),
            )
            scan_ids = [row[0] for row in cur.fetchall()]
            if not scan_ids:
                return []
            placeholders = ", ".join("?" for _ in scan_ids)
            self._conn.execute(
                f"""\
                UPDATE scans
                SET status = 'cancelled',
                    error_message = ?,
                    current_candidate = NULL
                WHERE scan_id IN ({placeholders})
                """,
                (error_message, *scan_ids),
            )
            self._conn.commit()
            return scan_ids

    def mark_fp_reviews_for_agent_error(self, agent_id: str, error_message: str) -> int:
        if not agent_id:
            return 0
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET status = 'error',
                    current_vuln_index = NULL,
                    error_message = ?
                WHERE status IN ('pending', 'running')
                  AND scan_id IN (
                      SELECT scan_id FROM scans WHERE agent_id = ?
                  )
                """,
                (error_message, agent_id),
            )
            self._conn.commit()
            return cur.rowcount

    def mark_fp_reviews_for_scan_error(self, scan_id: str, error_message: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET status = 'error',
                    current_vuln_index = NULL,
                    error_message = ?
                WHERE scan_id = ?
                  AND status IN ('pending', 'running')
                """,
                (error_message, scan_id),
            )
            self._conn.commit()
            return cur.rowcount

    # -- FP Review jobs --

    def create_fp_review_job(self, review_id: str, scan_id: str, total: int, created_at: str) -> None:
        self._conn.execute(
            """\
            INSERT INTO fp_review_jobs (review_id, scan_id, status, created_at, total, processed)
            VALUES (?, ?, 'pending', ?, ?, 0)
            """,
            (review_id, scan_id, created_at, total),
        )
        self._conn.commit()

    def get_fp_review_job(self, review_id: str) -> FpReviewJob | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM fp_review_jobs WHERE review_id = ?", (review_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_fp_review_job(row)

    def get_fp_review_by_scan(self, scan_id: str) -> FpReviewJob | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM fp_review_jobs WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_fp_review_job(row)

    def list_fp_review_results_by_scan(self, scan_id: str) -> list[FpReviewResult]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT r.*
            FROM fp_review_results r
            JOIN fp_review_jobs j ON j.review_id = r.review_id
            WHERE j.scan_id = ?
            ORDER BY j.created_at ASC, r.created_at ASC, r.id ASC
            """,
            (scan_id,),
        )
        return [
            FpReviewResult(
                vuln_index=r["vuln_index"],
                verdict=r["verdict"],
                severity=r["severity"] or "low",
                reason=r["reason"],
                vulnerability_report=r["vulnerability_report"] or "",
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    def _row_to_fp_review_job(self, row: sqlite3.Row) -> FpReviewJob:
        review_id = row["review_id"]
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM fp_review_results WHERE review_id = ? ORDER BY id",
            (review_id,),
        )
        results = [
            FpReviewResult(
                vuln_index=r["vuln_index"],
                verdict=r["verdict"],
                severity=r["severity"] or "low",
                reason=r["reason"],
                vulnerability_report=r["vulnerability_report"] or "",
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]
        return FpReviewJob(
            review_id=review_id,
            scan_id=row["scan_id"],
            status=FpReviewStatus(row["status"]),
            created_at=row["created_at"],
            total=row["total"],
            processed=row["processed"],
            current_vuln_index=row["current_vuln_index"],
            results=results,
            error_message=row["error_message"],
        )

    def update_fp_review_job(
        self,
        review_id: str,
        *,
        status: str | None = None,
        processed: int | None = None,
        current_vuln_index: int | None = None,
        clear_current_vuln_index: bool = False,
        error_message: str | None = None,
    ) -> None:
        updates: list[str] = []
        params: list = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if processed is not None:
            updates.append("processed = ?")
            params.append(processed)
        if clear_current_vuln_index:
            updates.append("current_vuln_index = NULL")
        elif current_vuln_index is not None:
            updates.append("current_vuln_index = ?")
            params.append(current_vuln_index)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if not updates:
            return
        params.append(review_id)
        self._conn.execute(
            f"UPDATE fp_review_jobs SET {', '.join(updates)} WHERE review_id = ?",
            params,
        )
        self._conn.commit()

    def add_fp_review_result(self, review_id: str, result: FpReviewResult) -> None:
        self._conn.execute(
            """\
            INSERT OR REPLACE INTO fp_review_results
                (review_id, vuln_index, verdict, severity, reason, vulnerability_report, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                result.vuln_index,
                result.verdict,
                result.severity,
                result.reason,
                result.vulnerability_report,
                result.created_at,
            ),
        )
        self._conn.commit()

    # -- Users --

    def create_user(
        self, user_id: str, username: str, password_hash: str, role: str, agent_token: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO users (user_id, username, password_hash, role, agent_token, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    password_hash,
                    role,
                    agent_token,
                    __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat(),
                ),
            )
            self._conn.commit()

    def _row_to_user(self, row: sqlite3.Row) -> UserInDB:
        return UserInDB(
            user_id=row["user_id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            agent_token=row["agent_token"],
            created_at=row["created_at"],
        )

    def get_user_by_id(self, user_id: str) -> UserInDB | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> UserInDB | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_agent_token(self, agent_token: str) -> UserInDB | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute("SELECT * FROM users WHERE agent_token = ?", (agent_token,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[UserInDB]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute("SELECT * FROM users ORDER BY created_at")
        return [self._row_to_user(row) for row in cur.fetchall()]

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def update_user_password(self, user_id: str, password_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (password_hash, user_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count_users(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM users")
        return cur.fetchone()[0]

    # -- Cleanup --

    def close(self) -> None:
        self._conn.close()
