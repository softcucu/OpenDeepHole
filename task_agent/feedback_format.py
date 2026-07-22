"""Formatting helpers for selected feedback injected into prompts."""

from __future__ import annotations

from typing import Any, Iterable


def _value(entry: Any, name: str, default: Any = "") -> Any:
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def format_feedback_experience(entries: Iterable[Any]) -> str:
    """Render selected feedback entries as reason text plus function source."""
    chunks: list[str] = []
    for entry in entries:
        reason = str(_value(entry, "reason", "") or "").strip()
        if not reason:
            continue
        source = str(_value(entry, "function_source", "") or "").rstrip()
        chunks.append(f"\n- 用户理由：{reason}\n")
        if source:
            chunks.append("\n```c\n")
            chunks.append(source)
            chunks.append("\n```\n")
    return "".join(chunks)


def build_feedback_section(entries: Iterable[Any], intro: str) -> str:
    body = format_feedback_experience(entries)
    if not body:
        return ""
    return "\n\n## 历史用户经验\n\n" + intro + "\n" + body
