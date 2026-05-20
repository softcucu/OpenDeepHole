"""安全内存函数越界静态分析器 — 使用 semgrep 扫描高风险 dst/dstsz 误用。

调用外部 semgrep 二进制，使用 checker 内的 YAML 规则扫描项目，
将 JSON 结果映射为 Candidate 流供 AI 做二次语义判断。

本 checker 刻意不使用 tree-sitter；函数名只来自 semgrep 捕获值或规则
message 中的 Function=`...` 标记，捕获不到时保留 unknown。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.analyzers.semgrep_runner import run_semgrep
from backend.logger import get_logger

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = get_logger(__name__)

_RULE_FILE = Path(__file__).parent / "safe_mem_oob_semgrep.yml"
_SEMGREP_TIMEOUT_SECONDS = 15 * 60
_SEV_LABEL = {"ERROR": "高风险", "WARNING": "中风险", "INFO": "低风险"}
_MESSAGE_FUNCTION_RE = re.compile(r"Function=`([^`]+)`")
_LOW_PRIORITY_RULE_SUFFIXES = (
    "identical-size-array-dst",
    "identical-size-member-dst",
    "identical-size-source-named",
)


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


def _func_from_message(message: str) -> str:
    match = _MESSAGE_FUNCTION_RE.search(message)
    if not match:
        return ""
    return _clean_func_name(match.group(1))


def _best_effort_dst_expr(metavars: dict) -> str:
    dst = _mv(metavars, "$DST")
    if dst:
        return dst

    obj = _mv(metavars, "$OBJ")
    ptr = _mv(metavars, "$P")
    field = _mv(metavars, "$FIELD")
    buf = _mv(metavars, "$BUF")
    arr = _mv(metavars, "$ARR")
    off = _mv(metavars, "$OFF")
    idx = _mv(metavars, "$IDX")

    if obj and field and off:
        return f"{obj}.{field} + {off}"
    if ptr and field and off:
        return f"{ptr}->{field} + {off}"
    if obj and field and idx:
        return f"&{obj}.{field}[{idx}]"
    if ptr and field and idx:
        return f"&{ptr}->{field}[{idx}]"
    if obj and field:
        return f"{obj}.{field}"
    if ptr and field:
        return f"{ptr}->{field}"
    if buf and off:
        return f"{buf} + {off}"
    if buf and idx:
        return f"&{buf}[{idx}]"
    if arr and idx:
        return f"{arr}[{idx}]"
    return buf or arr


def _best_effort_dstsz_expr(metavars: dict) -> str:
    dstsz = _mv(metavars, "$DSTSZ")
    if dstsz:
        return dstsz
    same_size = _mv(metavars, "$SZ")
    if same_size:
        return same_size

    obj = _mv(metavars, "$OBJ")
    ptr = _mv(metavars, "$P")
    field = _mv(metavars, "$FIELD")
    buf = _mv(metavars, "$BUF")
    arr = _mv(metavars, "$ARR")
    type_name = _mv(metavars, "$TYPE")

    if obj and field and _mv(metavars, "$OFF"):
        return f"sizeof({obj}.{field})"
    if ptr and field and _mv(metavars, "$OFF"):
        return f"sizeof({ptr}->{field})"
    if buf:
        return f"sizeof({buf})"
    if arr:
        return f"sizeof({arr})"
    if type_name:
        return f"sizeof({type_name})"
    return ""


def _best_effort_count_expr(metavars: dict) -> str:
    return _mv(metavars, "$COUNT") or _mv(metavars, "$SZ")


def _path_variants(path: str, project_path: Path | None = None) -> list[str]:
    normalized = path.replace("\\", "/").strip("/")
    variants = [normalized]

    if project_path is not None:
        project_name = project_path.name.replace("\\", "/").strip("/")
        if normalized.startswith(f"{project_name}/"):
            variants.append(normalized[len(project_name) + 1:])

        try:
            rel = Path(path).resolve().relative_to(project_path.resolve())
            variants.append(rel.as_posix())
        except (OSError, ValueError):
            pass

    result: list[str] = []
    seen: set[str] = set()
    for item in variants:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _relative_reported_path(project_path: Path, reported_path: str) -> str:
    variants = _path_variants(reported_path, project_path)
    return min(variants, key=len) if variants else reported_path.replace("\\", "/")


class Analyzer(BaseAnalyzer):
    vuln_type = "safe_mem_oob"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; safe_mem_oob checker skipped")
            return

        result = run_semgrep(
            project_path,
            rule_file=_RULE_FILE,
            checker_name=self.vuln_type,
            timeout=_SEMGREP_TIMEOUT_SECONDS,
        )
        if result is None:
            return
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr

        # semgrep scan: rc=0 表示进程成功；候选是否存在取决于 JSON results。
        # rc>1 表示工具报错，但可能仍有部分结果。
        if returncode is not None and returncode > 1:
            _log.warning("semgrep exited with rc=%s: %s", returncode, stderr[:300])
            if not stdout or not stdout.strip():
                return

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            _log.warning("semgrep output JSON parse error: %s", exc)
            return

        results = sorted(
            data.get("results", []),
            key=lambda item: _is_low_priority_rule(str(item.get("check_id", ""))),
        )
        seen: set[tuple[str, int, str, str, str]] = set()
        seen_locations: set[tuple[str, int]] = set()

        for match in results:
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {})
            severity: str = extra.get("severity", "WARNING")
            message: str = extra.get("message", "").strip()
            metavars: dict = extra.get("metavars", {}) or {}

            raw_lines = extra.get("lines", "").strip()
            matched_lines = "" if "requires login" in raw_lines else raw_lines
            metadata = extra.get("metadata", {}) or {}

            rel_path = _relative_reported_path(project_path, abs_path)
            rule_category = check_id.split(".")[-1] if check_id else "unknown"
            risk_class = _clean_text(metadata.get("risk_class")) or "high-risk"
            location_key = (rel_path, start_line)
            if _is_low_priority_rule(check_id) and location_key in seen_locations:
                continue

            func_name = (
                _clean_func_name(_mv(metavars, "$FUNC"))
                or _func_from_message(message)
                or "unknown"
            )
            call_name = _mv(metavars, "$CALL")
            dst_expr = _best_effort_dst_expr(metavars)
            dstsz_expr = _best_effort_dstsz_expr(metavars)
            count_expr = _best_effort_count_expr(metavars)
            offset_expr = _mv(metavars, "$OFF") or _mv(metavars, "$IDX")

            dedup_key = (rel_path, start_line, rule_category, dst_expr, dstsz_expr)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            seen_locations.add(location_key)

            sev_label = _SEV_LABEL.get(severity, severity)
            parts: list[str] = [f"[{sev_label}] {rule_category}", message]
            parts.append(f"风险分类: {risk_class}")

            details: list[str] = []
            if call_name:
                details.append(f"安全内存函数: {call_name}")
            if dst_expr:
                details.append(f"dst: {dst_expr}")
            if dstsz_expr:
                details.append(f"dstsz: {dstsz_expr}")
            if count_expr:
                details.append(f"count: {count_expr}")
            if offset_expr:
                details.append(f"偏移/索引: {offset_expr}")
            if details:
                parts.append("\n".join(details))
            if matched_lines:
                parts.append(f"匹配代码:\n{matched_lines}")

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(p for p in parts if p),
                vuln_type=self.vuln_type,
            )


def _is_low_priority_rule(check_id: str) -> bool:
    return check_id.endswith(_LOW_PRIORITY_RULE_SUFFIXES)
