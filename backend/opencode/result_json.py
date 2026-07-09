"""Shared JSON result schema for LLM audit outputs."""

from __future__ import annotations

from typing import Any

from backend.opencode.llm_json import parse_llm_json


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

VULNERABILITY_RESULT_JSON_INSTRUCTION = """\
最终结果返回规则：
不要调用 `submit_result` MCP 工具；如果 SKILL 中仍提到 `submit_result`，以本规则为准。
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
最终结果返回规则：
不要调用 `submit_result` MCP 工具；如果 SKILL 中仍提到 `submit_result`，以本规则为准。
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
