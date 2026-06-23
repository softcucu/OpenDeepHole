"""循环变更索引越界静态分析器 — 使用 semgrep 初筛可疑 OOB 访问。

本 checker 只做 semgrep JSON 到 Candidate 的转换，真实越界判断交给
opencode skill。函数名优先从共享 CodeDatabase 按文件+行号解析，避免
checker 内重复做 tree-sitter 兜底。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.analyzers.semgrep_locations import (
    function_from_db_location,
    relative_reported_path,
)
from backend.analyzers.semgrep_runner import DEFAULT_SEMGREP_TIMEOUT_SECONDS, run_semgrep
from backend.logger import get_logger

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = get_logger(__name__)

_RULE_FILE = Path(__file__).parent / "loop_mut_idx_oob_semgrep.yml"
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
    """从 semgrep metavars 中取值，兼容 $-前缀写法。"""
    if not isinstance(metavars, dict):
        return ""
    raw = metavars.get(key) or metavars.get(f"${key.lstrip('$')}") or {}
    if isinstance(raw, dict):
        value = raw.get("abstract_content", "")
    else:
        value = raw
    return _clean_text(value)


def _best_effort_memory_expr(metavars: dict, matched_lines: str) -> str:
    memfunc = _mv(metavars, "$MEMFUNC")
    idx = _mv(metavars, "$IDX")
    base = _mv(metavars, "$BASE")
    ptr = _mv(metavars, "$PTR") or _mv(metavars, "$P")
    field = _mv(metavars, "$FIELD")
    off = _mv(metavars, "$OFF")

    if memfunc:
        return f"{memfunc}(...)"
    if base and idx and off:
        return f"{base}[{idx} +/- {off}]"
    if base and idx:
        return f"{base}[{idx}]"
    if ptr and field and idx:
        return f"({ptr} +/- {idx})->{field}"
    if ptr and field:
        return f"{ptr}->{field}"
    if ptr and idx and off:
        return f"*({ptr} +/- {idx} +/- {off})"
    if ptr and idx:
        return f"*({ptr} +/- {idx})"
    return matched_lines.splitlines()[0].strip() if matched_lines else ""


def _rule_source(check_id: str, metadata: dict) -> str:
    source_kind = _clean_text(metadata.get("source_kind"))
    if source_kind:
        return source_kind
    if "array-access" in check_id:
        return "array"
    if "pointer-access" in check_id:
        return "pointer"
    if "memory-call" in check_id:
        return "memory-call"
    if "derived-pointer" in check_id:
        return "derived-pointer"
    return check_id.rsplit(".", 1)[-1] if check_id else "unknown"


class Analyzer(BaseAnalyzer):
    vuln_type = "loop_mut_idx_oob"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; loop_mut_idx_oob checker skipped")
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
            idx_expr = _mv(metavars, "$IDX")
            cond_expr = _mv(metavars, "$COND")
            step_expr = _mv(metavars, "$STEP")
            bound_expr = _mv(metavars, "$BOUND")
            memory_expr = _best_effort_memory_expr(metavars, matched_lines)
            source = _rule_source(check_id, metadata)

            dedup_key = (rel_path, start_line, source, idx_expr, memory_expr)
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

            idx_subject = idx_expr or "循环索引"
            mem_subject = f"访问 `{memory_expr}` " if memory_expr else ""
            parts: list[str] = [
                f"函数 `{func_name}` 中循环索引 `{idx_subject}` {mem_subject}"
                f"是否存在越界访问问题，请审计确认。"
            ]

            details: list[str] = []
            if idx_expr:
                details.append(f"循环变化索引: {idx_expr}")
            if cond_expr:
                details.append(f"循环条件: {cond_expr}")
            if step_expr:
                details.append(f"索引步长/变化量: {step_expr}")
            if bound_expr:
                details.append(f"局部边界表达式: {bound_expr}")
            if memory_expr:
                details.append(f"内存访问: {memory_expr}")
            if details:
                parts.append("相关线索：\n" + "\n".join(details))
            parts.append("审计要点：严格确认真实边界与可达性。")

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(part for part in parts if part),
                vuln_type=self.vuln_type,
            )
