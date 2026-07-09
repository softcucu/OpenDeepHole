"""SQLite-backed sink for MCP submit tool payloads.

Serve-mode OpenCode calls identify the task by the OpenCode session. A runtime
OpenCode plugin injects that session into OpenDeepHole submit tool arguments,
so submitted payloads can be persisted without asking the model to pass an
internal result id.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import get_config

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mcp_submitted_results (
    session_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    tool_name  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(session_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_mcp_submitted_results_tool
ON mcp_submitted_results(session_id, tool_name, seq);
"""

_connections: dict[str, sqlite3.Connection] = {}
_lock = threading.Lock()


def _db_path() -> Path:
    return Path(get_config().storage.scans_dir) / "scans.db"


def _connection() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = str(path.resolve())
    with _lock:
        conn = _connections.get(key)
        if conn is None:
            conn = sqlite3.connect(key, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
            _connections[key] = conn
        return conn


def record_submission(session_id: str, tool_name: str, payload: dict[str, Any]) -> int:
    """Persist one MCP submit payload and return its per-session sequence number."""
    normalized_session = str(session_id or "").strip()
    normalized_tool = str(tool_name or "").strip()
    if not normalized_session:
        raise ValueError("missing OpenCode session id")
    if not normalized_tool:
        raise ValueError("missing submit tool name")

    encoded_payload = json.dumps(payload, ensure_ascii=False)
    created_at = datetime.now(timezone.utc).isoformat()
    conn = _connection()
    with _lock:
        row = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM mcp_submitted_results WHERE session_id = ?",
            (normalized_session,),
        ).fetchone()
        seq = int(row["next_seq"] if row is not None else 1)
        conn.execute(
            """\
            INSERT INTO mcp_submitted_results(session_id, seq, tool_name, payload, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (normalized_session, seq, normalized_tool, encoded_payload, created_at),
        )
        conn.commit()
    return seq


def read_submissions(session_id: str, tool_name: str | None = None) -> list[dict[str, Any]]:
    """Return persisted payloads for one session, optionally filtered by submit tool."""
    normalized_session = str(session_id or "").strip()
    if not normalized_session:
        return []
    conn = _connection()
    if tool_name:
        cur = conn.execute(
            """\
            SELECT payload
            FROM mcp_submitted_results
            WHERE session_id = ? AND tool_name = ?
            ORDER BY seq ASC
            """,
            (normalized_session, str(tool_name)),
        )
    else:
        cur = conn.execute(
            """\
            SELECT payload
            FROM mcp_submitted_results
            WHERE session_id = ?
            ORDER BY seq ASC
            """,
            (normalized_session,),
        )
    out: list[dict[str, Any]] = []
    for row in cur.fetchall():
        try:
            item = json.loads(row["payload"] or "{}")
        except Exception:
            item = {}
        if isinstance(item, dict):
            out.append(item)
    return out


def read_submissions_as_result_file(session_id: str, tool_name: str | None = None):
    """Return payloads in the shape expected by the legacy result readers."""
    payloads = read_submissions(session_id, tool_name)
    if not payloads:
        return None
    if len(payloads) == 1:
        return payloads[0]
    return {"results": payloads}
