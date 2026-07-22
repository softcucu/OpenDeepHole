"""Extract schema-matching JSON from LLM output."""

from __future__ import annotations

import json
from typing import Any, Callable


class LLMJsonParseError(ValueError):
    """Raised when no JSON value in LLM output matches the expected schema."""


def parse_llm_json(
    text: str,
    schema: Any,
    *,
    allow_extra_keys: bool = True,
) -> Any:
    """
    Extract a JSON value from model output and validate it against schema.

    Schema rules:
    - str/int/float/bool: type checks
    - None: any value
    - {"key": schema}: required object keys
    - [schema]: homogeneous array
    - (schema_a, schema_b): any matching schema/value
    - other values: exact equality
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    normalized = text.strip().lstrip("\ufeff")
    if not normalized:
        raise LLMJsonParseError("LLM output is empty")

    return _select_json_candidate(
        normalized,
        lambda value: _matches_schema(
            value,
            schema,
            allow_extra_keys=allow_extra_keys,
        ),
    )


def parse_llm_json_schema(text: str, schema: dict[str, Any]) -> Any:
    """Extract JSON from model text and validate the supported JSON Schema subset."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(schema, dict):
        raise TypeError("schema must be an object")

    normalized = text.strip().lstrip("\ufeff")
    if not normalized:
        raise LLMJsonParseError("LLM output is empty")
    return _select_json_candidate(
        normalized,
        lambda value: _matches_json_schema(value, schema),
    )


def _select_json_candidate(text: str, matches: Callable[[Any], bool]) -> Any:
    candidates = _extract_json_candidates(text)
    matched = [candidate for candidate in candidates if matches(candidate["value"])]
    if not matched:
        raise LLMJsonParseError(
            f"found {len(candidates)} valid JSON value(s), "
            "but none matched the expected schema"
        )
    matched.sort(
        key=lambda item: (item["length"], item["position"]),
        reverse=True,
    )
    return matched[0]["value"]


def _extract_json_candidates(text: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for start, char in enumerate(text):
        if char not in "{[":
            continue
        end = _matching_json_end(text, start)
        if end is None:
            continue
        raw = text[start:end + 1]
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        candidates.append({
            "value": value,
            "length": len(raw),
            "position": start,
        })
    return candidates


def _matching_json_end(text: str, start: int) -> int | None:
    opening = text[start]
    closing = "}" if opening == "{" else "]"
    stack = [closing]
    in_string = False
    escaped = False

    for index in range(start + 1, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            stack.append("}")
        elif char == "[":
            stack.append("]")
        elif char in "}]":
            if not stack or char != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return index

    return None


def _matches_schema(value: Any, schema: Any, *, allow_extra_keys: bool) -> bool:
    if schema is None:
        return True

    if isinstance(schema, tuple):
        return any(_matches_schema(value, item, allow_extra_keys=allow_extra_keys) for item in schema)

    if schema is str:
        return isinstance(value, str)
    if schema is bool:
        return isinstance(value, bool)
    if schema is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if schema is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    if isinstance(schema, dict):
        if not isinstance(value, dict):
            return False
        schema_keys = set(schema.keys())
        value_keys = set(value.keys())
        if not schema_keys.issubset(value_keys):
            return False
        if not allow_extra_keys and value_keys != schema_keys:
            return False
        return all(
            _matches_schema(value[key], child_schema, allow_extra_keys=allow_extra_keys)
            for key, child_schema in schema.items()
        )

    if isinstance(schema, list):
        if len(schema) != 1 or not isinstance(value, list):
            return False
        return all(_matches_schema(item, schema[0], allow_extra_keys=allow_extra_keys) for item in value)

    return value == schema


def _matches_json_schema(value: Any, schema: Any) -> bool:
    """Match the JSON Schema features used by OpenDeepHole result contracts."""
    if schema is True:
        return True
    if schema is False or not isinstance(schema, dict):
        return False

    if "const" in schema and value != schema["const"]:
        return False
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        return False

    branches = schema.get("allOf")
    if isinstance(branches, list) and not all(
        _matches_json_schema(value, branch) for branch in branches
    ):
        return False
    branches = schema.get("anyOf")
    if isinstance(branches, list) and not any(
        _matches_json_schema(value, branch) for branch in branches
    ):
        return False
    branches = schema.get("oneOf")
    if isinstance(branches, list) and sum(
        _matches_json_schema(value, branch) for branch in branches
    ) != 1:
        return False

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(_matches_json_type(value, item) for item in expected_type):
            return False
    elif expected_type is not None and not _matches_json_type(value, expected_type):
        return False

    if isinstance(value, dict):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        required = schema.get("required")
        if isinstance(required, list) and any(key not in value for key in required):
            return False
        for key, child_schema in properties.items():
            if key in value and not _matches_json_schema(value[key], child_schema):
                return False
        if schema.get("additionalProperties") is False:
            if any(key not in properties for key in value):
                return False

    if isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            return False
        if isinstance(max_items, int) and len(value) > max_items:
            return False
        item_schema = schema.get("items")
        if isinstance(item_schema, (dict, bool)) and not all(
            _matches_json_schema(item, item_schema) for item in value
        ):
            return False

    return True


def _matches_json_type(value: Any, expected_type: Any) -> bool:
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return False
