"""Shared JSON result schema for LLM audit outputs."""

from __future__ import annotations

from typing import Any

from .llm_json import parse_llm_json


VULNERABILITY_RESULT_SCHEMA: dict[str, Any] = {
    "confirmed": bool,
    "severity": str,
    "description": str,
    "ai_analysis": str,
    "vulnerability_report": str,
    "file": str,
    "line": int,
    "function": str,
}

VULNERABILITY_RESULTS_SCHEMA: dict[str, Any] = {
    "results": [VULNERABILITY_RESULT_SCHEMA],
}

AUDITED_VULNERABILITY_RESULT_SCHEMA: dict[str, Any] = {
    **VULNERABILITY_RESULT_SCHEMA,
    "vuln_type": str,
    "call_chain": [str],
}

AUDITED_VULNERABILITY_RESULTS_SCHEMA: dict[str, Any] = {
    "results": [AUDITED_VULNERABILITY_RESULT_SCHEMA],
}

VULNERABILITY_RESULT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "confirmed": {"type": "boolean"},
        "severity": {"type": "string"},
        "description": {"type": "string"},
        "ai_analysis": {"type": "string"},
        "vulnerability_report": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "function": {"type": "string"},
    },
    "required": list(VULNERABILITY_RESULT_SCHEMA),
    "additionalProperties": True,
}

VULNERABILITY_RESULTS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "minItems": 1,
            "items": VULNERABILITY_RESULT_JSON_SCHEMA,
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}

AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        **VULNERABILITY_RESULT_JSON_SCHEMA["properties"],
        "vuln_type": {"type": "string", "minLength": 1},
        "call_chain": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
    },
    "required": list(AUDITED_VULNERABILITY_RESULT_SCHEMA),
    "additionalProperties": True,
}

AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "minItems": 1,
            "items": AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA,
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}

VULNERABILITY_RESULT_JSON_INSTRUCTION = """\
分析完成后，最终回复必须包含且只包含一个符合以下 schema 的 JSON 对象：
{
  "confirmed": true,
  "severity": "high",
  "description": "一句话结论",
  "ai_analysis": "详细分析过程，可包含 Markdown 文本",
  "vulnerability_report": "Markdown 漏洞报告；没有则为空字符串",
  "file": "真实问题文件路径；没有则为空字符串",
  "line": 0,
  "function": "真实问题函数名；没有则为空字符串"
}
`severity` 只使用 "high"、"medium"、"low" 或现有任务明确要求的值；`line` 必须是整数。
"""

VULNERABILITY_RESULTS_JSON_INSTRUCTION = """\
分析完成后，最终回复必须包含且只包含一个符合以下 schema 的 JSON 对象：
{
  "results": [
    {
      "confirmed": true,
      "severity": "high",
      "description": "一句话结论",
      "ai_analysis": "详细分析过程，可包含 Markdown 文本",
      "vulnerability_report": "Markdown 漏洞报告；没有则为空字符串",
      "file": "真实问题文件路径；没有则为空字符串",
      "line": 0,
      "function": "真实问题函数名；没有则为空字符串"
    }
  ]
}
每个真实问题使用一个 results 元素；没有真实问题时仍输出一个 confirmed=false 的元素。
"""

AUDITED_VULNERABILITY_RESULT_JSON_INSTRUCTION = """\
分析完成后，最终回复必须包含且只包含一个符合以下 schema 的 JSON 对象：
{
  "confirmed": true,
  "severity": "high",
  "description": "一句话结论",
  "ai_analysis": "详细分析过程，可包含 Markdown 文本",
  "vulnerability_report": "Markdown 漏洞报告；没有则为空字符串",
  "file": "真实问题文件路径；没有则为空字符串",
  "line": 0,
  "function": "真实问题函数名；没有则为空字符串",
  "vuln_type": "真实漏洞类型",
  "call_chain": ["外部入口函数", "中间函数", "真实问题函数"]
}
`call_chain` 必须按外部可达入口到漏洞函数的顺序填写；第一个函数是验证入口，最后一个函数应为 `function`。
`severity` 只使用 "high"、"medium"、"low" 或现有任务明确要求的值；`line` 必须是整数。
"""

AUDITED_VULNERABILITY_RESULTS_JSON_INSTRUCTION = """\
分析完成后，最终回复必须包含且只包含一个符合以下 schema 的 JSON 对象：
{
  "results": [
    {
      "confirmed": true,
      "severity": "high",
      "description": "一句话结论",
      "ai_analysis": "详细分析过程，可包含 Markdown 文本",
      "vulnerability_report": "Markdown 漏洞报告；没有则为空字符串",
      "file": "真实问题文件路径；没有则为空字符串",
      "line": 0,
      "function": "真实问题函数名；没有则为空字符串",
      "vuln_type": "真实漏洞类型",
      "call_chain": ["外部入口函数", "中间函数", "真实问题函数"]
    }
  ]
}
每个真实问题使用一个 results 元素；没有真实问题时仍输出一个 confirmed=false 的元素。
每个 `call_chain` 必须按外部可达入口到漏洞函数的顺序填写；第一个函数是验证入口，最后一个函数应为 `function`。
"""


def parse_vulnerability_result(text: str) -> dict[str, Any]:
    value = parse_llm_json(text, VULNERABILITY_RESULT_SCHEMA, allow_extra_keys=True)
    if not isinstance(value, dict):
        raise TypeError("parsed vulnerability result is not an object")
    return value


def parse_vulnerability_results(text: str) -> list[dict[str, Any]]:
    value = parse_llm_json(text, VULNERABILITY_RESULTS_SCHEMA, allow_extra_keys=True)
    if not isinstance(value, dict):
        raise TypeError("parsed vulnerability results is not an object")
    results = value.get("results")
    if not isinstance(results, list):
        raise TypeError("parsed vulnerability results has no results array")
    return [item for item in results if isinstance(item, dict)]


def parse_audited_vulnerability_result(text: str) -> dict[str, Any]:
    value = parse_llm_json(text, AUDITED_VULNERABILITY_RESULT_SCHEMA, allow_extra_keys=True)
    if not isinstance(value, dict):
        raise TypeError("parsed audited vulnerability result is not an object")
    return value


def parse_audited_vulnerability_results(text: str) -> list[dict[str, Any]]:
    value = parse_llm_json(text, AUDITED_VULNERABILITY_RESULTS_SCHEMA, allow_extra_keys=True)
    if not isinstance(value, dict):
        raise TypeError("parsed audited vulnerability results is not an object")
    results = value.get("results")
    if not isinstance(results, list):
        raise TypeError("parsed audited vulnerability results has no results array")
    return [item for item in results if isinstance(item, dict)]
