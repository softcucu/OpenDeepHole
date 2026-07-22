"""Integer overflow static analyzer using semgrep for high-risk candidates.

This checker intentionally keeps static analysis shallow: semgrep recalls
syntax-level overflow candidates and opencode/LLM performs the semantic audit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate
from deephole_client.static_analysis.semgrep_locations import (
    function_from_db_location,
    relative_reported_path,
)
from deephole_client.static_analysis.semgrep_runner import DEFAULT_SEMGREP_TIMEOUT_SECONDS, run_semgrep
import logging

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = logging.getLogger(__name__)

_RULE_FILE = Path(__file__).parent / "intoverflow_semgrep.yml"
_SEMGREP_TIMEOUT_SECONDS = DEFAULT_SEMGREP_TIMEOUT_SECONDS
_SEV_LABEL = {"ERROR": "高风险", "WARNING": "中风险", "INFO": "低风险"}


def _clean_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_func_name(name: object) -> str:
    name = _clean_text(name)
    if not name or name == "unknown" or name.startswith("$"):
        return ""
    return name


def _mv(metavars: dict, key: str) -> str:
    if not isinstance(metavars, dict):
        return ""
    raw = metavars.get(key) or metavars.get(f"${key.lstrip('$')}") or {}
    if isinstance(raw, dict):
        value = raw.get("abstract_content", "")
    else:
        value = raw
    return _clean_text(value)


def _rule_source(check_id: str, metadata: dict) -> str:
    source_kind = _clean_text(metadata.get("source_kind"))
    if source_kind:
        return source_kind
    if check_id:
        return check_id.rsplit(".", 1)[-1]
    return "unknown"


def _best_effort_arith_expr(metavars: dict, source: str) -> str:
    arith = _mv(metavars, "$ARITH")
    if arith:
        return arith

    a = _mv(metavars, "$A")
    b = _mv(metavars, "$B")
    size = _mv(metavars, "$SIZE")
    count = _mv(metavars, "$COUNT")
    len_expr = _mv(metavars, "$LEN")
    off = _mv(metavars, "$OFF")

    if a and b:
        op = "+/-/*"
        if "sub" in source or "subtract" in source:
            op = "-"
        elif "add" in source or "sum" in source:
            op = "+"
        elif "multiply" in source or "mul" in source:
            op = "*"
        return f"{a} {op} {b}"
    if count and size:
        return f"{count} * {size}"
    if len_expr and off:
        op = "-" if "sub" in source or "header" in source else "+"
        return f"{len_expr} {op} {off}"
    return ""


def _best_effort_sink_expr(metavars: dict, matched_lines: str) -> str:
    call_name = _mv(metavars, "$CALL")
    if call_name:
        return f"{call_name}(...)"

    array_name = _mv(metavars, "$ARR") or _mv(metavars, "$BASE")
    idx = _mv(metavars, "$IDX") or _mv(metavars, "$ARITH")
    if array_name and idx:
        return f"{array_name}[{idx}]"

    ptr = _mv(metavars, "$PTR") or _mv(metavars, "$P")
    off = _mv(metavars, "$OFF") or _mv(metavars, "$ARITH")
    if ptr and off:
        return f"*({ptr} +/- {off})"

    bound = _mv(metavars, "$BOUND")
    if bound:
        return f"loop bound {bound}"

    return matched_lines.splitlines()[0].strip() if matched_lines else ""


class Analyzer(BaseAnalyzer):
    vuln_type = "intoverflow"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; intoverflow checker skipped")
            return

        result = run_semgrep(
            project_path,
            rule_file=_RULE_FILE,
            checker_name=self.vuln_type,
            timeout=_SEMGREP_TIMEOUT_SECONDS,
        )
        if result is None:
            return

        if result.returncode is not None and result.returncode > 1:
            _log.warning("semgrep exited with rc=%s: %s", result.returncode, result.stderr[:300])
            if not result.stdout or not result.stdout.strip():
                return

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            _log.warning("semgrep output JSON parse error: %s", exc)
            return

        seen: set[tuple[str, int, str, str, str]] = set()

        for match in data.get("results", []):
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {}) or {}
            severity: str = extra.get("severity", "WARNING")
            message: str = _clean_text(extra.get("message"))
            metavars: dict = extra.get("metavars", {}) or {}
            metadata: dict = extra.get("metadata", {}) or {}

            raw_lines = _clean_text(extra.get("lines"))
            matched_lines = "" if "requires login" in raw_lines else raw_lines

            rel_path = relative_reported_path(project_path, abs_path)
            source = _rule_source(check_id, metadata)
            risk_class = _clean_text(metadata.get("risk_class")) or "high-risk integer arithmetic"
            arith_expr = _best_effort_arith_expr(metavars, source)
            sink_expr = _best_effort_sink_expr(metavars, matched_lines)

            dedup_key = (rel_path, start_line, source, arith_expr, sink_expr)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            func_name = "unknown"
            if db is not None:
                func_name = (
                    function_from_db_location(
                        db,
                        project_path,
                        abs_path,
                        start_line,
                        clean_func_name=_clean_func_name,
                    )
                    or "unknown"
                )

            subject = arith_expr or sink_expr or "整数运算"
            parts: list[str] = [
                f"函数 `{func_name}` 中整数运算 `{subject}` 是否存在整数溢出问题，请审计确认。",
                f"规则来源: {source}",
            ]
            if message:
                parts.append(f"Semgrep 说明: {message}")
            if risk_class:
                parts.append(f"风险分类: {risk_class}")

            details: list[str] = []
            if arith_expr:
                details.append(f"可疑整数运算: {arith_expr}")
            if sink_expr:
                details.append(f"危险使用点: {sink_expr}")
            narrow_type = _mv(metavars, "$NARROW_T")
            if narrow_type:
                details.append(f"窄化类型: {narrow_type}")
            target_var = _mv(metavars, "$VAR") or _mv(metavars, "$SIZEVAR")
            if target_var:
                details.append(f"中间变量: {target_var}")
            if details:
                parts.append("相关线索：\n" + "\n".join(details))
            if matched_lines:
                parts.append(f"匹配代码：\n{matched_lines}")
            parts.append("复核重点：确认输入是否外部可控、是否存在有效范围/溢出检查、溢出结果是否可达危险使用点。")

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(part for part in parts if part),
                vuln_type=self.vuln_type,
            )
