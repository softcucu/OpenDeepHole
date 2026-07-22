"""Shared formatting helpers for human-readable OpenCode output."""

from __future__ import annotations

import re
from datetime import datetime


_LOCAL_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])(?:\s|$)"
)


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
        if prefix and not content.startswith(prefix):
            content = f"{prefix} {content}".rstrip()
        formatted.append(f"{line_timestamp} {content}".rstrip())
    return "\n".join(formatted)
