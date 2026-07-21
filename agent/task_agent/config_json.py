"""Shared JSONC parsing and serialization for OpenCode configuration."""

from __future__ import annotations

import json
import re
from typing import Any


_SENSITIVE_CONFIG_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|authorization|cookie|credential|headers?)",
    re.IGNORECASE,
)


def strip_jsonc_comments(text: str) -> str:
    """Remove JSONC comments while preserving line and column positions."""
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            result.extend("  ")
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                result.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            result.extend("  ")
            index += 2
            while index < len(text):
                if index + 1 < len(text) and text[index] == "*" and text[index + 1] == "/":
                    result.extend("  ")
                    index += 2
                    break
                result.append(text[index] if text[index] in "\r\n" else " ")
                index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def strip_jsonc_trailing_commas(text: str) -> str:
    """Remove commas immediately before a closing object or array token."""
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                result.append(" ")
                index += 1
                continue
        result.append(char)
        index += 1
    return "".join(result)


def parse_opencode_jsonc(text: str | None, *, source: str = "OpenCode config") -> dict[str, Any]:
    """Parse one JSONC object, treating an empty value as an empty object."""
    raw = str(text or "")
    if not raw.strip():
        return {}
    cleaned = strip_jsonc_trailing_commas(strip_jsonc_comments(raw))
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{source} JSONC 格式错误（第 {exc.lineno} 行，第 {exc.colno} 列）：{exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"{source} 必须是 JSON 对象")
    return value


def dump_opencode_config(config: dict[str, Any]) -> str:
    """Serialize the resolved runtime config deterministically."""
    return json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def is_sensitive_opencode_config_key(value: object) -> bool:
    """Return whether an OpenCode config key conventionally contains a secret."""
    return bool(_SENSITIVE_CONFIG_KEY_RE.search(str(value)))


def redact_opencode_config_value(value: Any, *, parent_key: str = "") -> Any:
    """Recursively mask secret-bearing fields in parsed OpenCode configuration."""
    if parent_key and is_sensitive_opencode_config_key(parent_key):
        return "***"
    if isinstance(value, dict):
        return {
            key: (
                "***"
                if is_sensitive_opencode_config_key(key)
                else redact_opencode_config_value(item, parent_key=str(key))
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_opencode_config_value(item, parent_key=parent_key) for item in value]
    return value


def redact_opencode_config_content(config_content: str, *, pretty: bool = False) -> str:
    """Mask secrets in serialized OpenCode config without ever echoing invalid input."""
    if not config_content:
        return ""
    try:
        data = json.loads(config_content)
    except Exception:
        return f"<redacted invalid config content bytes={len(config_content.encode('utf-8'))}>"
    redacted = redact_opencode_config_value(data)
    if pretty:
        return json.dumps(redacted, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return json.dumps(redacted, ensure_ascii=False)
