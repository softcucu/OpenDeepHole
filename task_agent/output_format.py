"""Shared formatting helpers for human-readable OpenCode output."""

from __future__ import annotations

import re
from datetime import datetime


_LOCAL_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])(?:\s|$)"
)
_TASK_OUTPUT_HEADER_RE = re.compile(
    r"^\[[^\]\r\n]+\]\[[^\]\r\n]+\]\[(?:task|session|step)\](?:\s|$)"
)
_TASK_OUTPUT_CATEGORIES = frozenset({"task", "session", "step"})


def task_output_stage(task_type: object) -> str:
    """Return the stable first header segment for one Task Agent task."""
    normalized = str(task_type or "").strip()
    if normalized == "vulnerability_validation":
        return "validation"
    return normalized or "opencode"


def format_task_output(
    stage: object,
    session_id: object,
    category: object,
    message: object,
) -> str:
    """Format one single-line Task Agent console event."""
    normalized_stage = task_output_stage(stage)
    normalized_session = str(session_id or "").strip() or "pending"
    normalized_category = str(category or "").strip().lower()
    if normalized_category not in _TASK_OUTPUT_CATEGORIES:
        raise ValueError(f"Unsupported Task Agent output category: {category!r}")
    content = " ".join(str(message or "").split())
    prefix = f"[{normalized_stage}][{normalized_session}][{normalized_category}]"
    return f"{prefix} {content}".rstrip()


def is_task_output_line(line: object) -> bool:
    return bool(_TASK_OUTPUT_HEADER_RE.match(str(line or "")))


def with_local_timestamp(
    line: str,
    *,
    prefix: str = "",
    now: datetime | None = None,
) -> str:
    """Prefix each physical line with local time and an optional stable label."""
    value = str(line)
    timestamp = (now or datetime.now().astimezone()).strftime("[%Y-%m-%d %H:%M:%S]")
    parts = value.splitlines()
    if not parts:
        parts = [value]

    formatted: list[str] = []
    for part in parts:
        match = _LOCAL_TIMESTAMP_RE.match(part)
        if match:
            line_timestamp = match.group("timestamp")
            content = part[match.end():].lstrip()
        else:
            line_timestamp = timestamp
            content = part
        if prefix and not content.startswith(prefix) and not is_task_output_line(content):
            content = f"{prefix} {content}".rstrip()
        formatted.append(f"{line_timestamp} {content}".rstrip())
    return "\n".join(formatted)
