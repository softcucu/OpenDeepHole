"""死循环静态分析器 — 使用 semgrep 扫描 CWE-835 模式。

调用外部 semgrep 二进制，使用已有的 YAML 规则文件扫描项目，
将 JSON 结果映射为 Candidate 流供 AI 做二次语义判断。

semgrep 社区版不返回 metavar 值，函数名通过 tree-sitter 按行号反查兜底。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.analyzers.semgrep_locations import function_from_db_location
from backend.analyzers.semgrep_runner import run_semgrep
from backend.logger import get_logger

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = get_logger(__name__)

_RULE_FILE = Path(__file__).parent / "c_cpp_loop_no_progress_semgrep_with_func.yaml"
_SEMGREP_TIMEOUT_SECONDS = 15 * 60
_SEV_LABEL = {"ERROR": "高风险", "WARNING": "中风险"}
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())
_MESSAGE_FUNCTION_RE = re.compile(r"Function=`([^`]+)`")


# ------------------------------------------------------------------ #
#  tree-sitter 函数名反查（semgrep 社区版 metavar 为空时的兜底）
# ------------------------------------------------------------------ #

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _iter_functions(node):
    if node.type == "function_definition":
        yield node
        return
    for child in node.children:
        yield from _iter_functions(child)


def _func_name_from_node(func_node, source: bytes) -> str:
    decl = func_node.child_by_field_name("declarator")
    if not decl:
        return ""
    for n in _walk(decl):
        if n.type in ("identifier", "qualified_identifier"):
            return source[n.start_byte:n.end_byte].decode("utf-8", "replace")
    return ""


# 文件内容缓存，避免同一次扫描中重复读取和解析
_src_cache: dict[str, bytes] = {}


def _clean_func_name(name: object) -> str:
    if not isinstance(name, str):
        return ""
    name = name.strip()
    if not name or name == "unknown" or name.startswith("$"):
        return ""
    return name


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


def _path_matches(indexed_path: str, reported_path: str, project_path: Path) -> bool:
    indexed_variants = _path_variants(indexed_path, project_path)
    reported_variants = _path_variants(reported_path, project_path)
    for indexed in indexed_variants:
        indexed_cmp = indexed.casefold()
        for reported in reported_variants:
            reported_cmp = reported.casefold()
            if (
                indexed_cmp == reported_cmp
                or indexed_cmp.endswith(f"/{reported_cmp}")
                or reported_cmp.endswith(f"/{indexed_cmp}")
            ):
                return True
    return False


def _relative_reported_path(project_path: Path, reported_path: str) -> str:
    variants = _path_variants(reported_path, project_path)
    return min(variants, key=len) if variants else reported_path.replace("\\", "/")


def _resolve_reported_path(project_path: Path, reported_path: str) -> Path | None:
    normalized = reported_path.replace("\\", "/")
    path = Path(normalized)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(project_path / path)

        parts = path.parts
        if parts and parts[0] == project_path.name:
            candidates.append(project_path.joinpath(*parts[1:]))

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _row_get(row, key: str, default=None):
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        if hasattr(row, "get"):
            return row.get(key, default)
        return default


def _func_at_line(project_path: Path, reported_path: str, line: int) -> str:
    """用 tree-sitter 反查 reported_path 中包含 line（1-based）的函数名。"""
    source_path = _resolve_reported_path(project_path, reported_path)
    if source_path is None:
        return ""

    cache_key = str(source_path)
    src = _src_cache.get(cache_key)
    if src is None:
        try:
            src = source_path.read_bytes()
        except OSError:
            return ""
        _src_cache[cache_key] = src

    try:
        parser = tree_sitter.Parser(_CPP_LANGUAGE)
        tree = parser.parse(src)
    except Exception:
        return ""

    for func in _iter_functions(tree.root_node):
        start = func.start_point[0] + 1
        end = func.end_point[0] + 1
        if start <= line <= end:
            return _func_name_from_node(func, src)
    return ""


def _func_from_db(
    db: "CodeDatabase",
    project_path: Path,
    reported_path: str,
    line: int,
) -> str:
    """从 CodeDatabase 按文件+行号反查函数名。"""
    return function_from_db_location(
        db,
        project_path,
        reported_path,
        line,
        clean_func_name=_clean_func_name,
    )


def _func_from_message(message: str) -> str:
    match = _MESSAGE_FUNCTION_RE.search(message)
    if not match:
        return ""
    return _clean_func_name(match.group(1))


# ------------------------------------------------------------------ #
#  Analyzer
# ------------------------------------------------------------------ #

class Analyzer(BaseAnalyzer):
    vuln_type = "inf_loop"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; inf_loop checker skipped")
            return

        _src_cache.clear()

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
            _log.warning(
                f"semgrep exited with rc={returncode}: {stderr[:300]}"
            )
            if not stdout or not stdout.strip():
                return

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            _log.warning(f"semgrep output JSON parse error: {exc}")
            return

        seen: set[tuple[str, str, str]] = set()

        for match in data.get("results", []):
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {})
            severity: str = extra.get("severity", "WARNING")
            message: str = extra.get("message", "")
            metavars: dict = extra.get("metavars", {})

            # semgrep 社区版 lines 字段受限，过滤掉无意义的提示
            raw_lines = extra.get("lines", "").strip()
            matched_lines = "" if "requires login" in raw_lines else raw_lines

            # 相对路径
            rel_path = _relative_reported_path(project_path, abs_path)

            # 规则类型：取 check_id 最后一段
            rule_category = check_id.split(".")[-1] if check_id else "unknown"

            # 函数名：metavar $F → CodeDB → tree-sitter 逐行反查
            func_name = (
                _clean_func_name(metavars.get("$F", {}).get("abstract_content", ""))
                or _func_from_message(message)
                or (db and _func_from_db(db, project_path, abs_path, start_line))
                or _func_at_line(project_path, abs_path, start_line)
                or "unknown"
            )

            # 循环控制变量（社区版 metavar 为空，从 message 中提取兜底）
            loop_var = metavars.get("$I", {}).get("abstract_content", "")
            if not loop_var:
                # message 格式: "... loop-progress variable `i` is used ..."
                m = re.search(r"variable\s+`([^`]+)`", message)
                if m:
                    loop_var = m.group(1)

            # 去重：同文件 + 同函数 + 同规则类别只报一次
            key = (rel_path, func_name, rule_category)
            if key in seen:
                continue
            seen.add(key)

            # 组装 description
            loop_subject = f"（控制变量 `{loop_var}`）" if loop_var else ""
            parts = [
                f"函数 `{func_name}` 中的循环{loop_subject}是否存在无法退出/死循环问题，请审计确认。"
            ]
            if loop_var:
                parts.append(f"相关线索：循环控制变量 {loop_var}")

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(parts),
                vuln_type=self.vuln_type,
            )
