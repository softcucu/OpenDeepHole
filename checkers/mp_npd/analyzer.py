"""多层指针空指针解引用静态分析器 — 使用 semgrep 扫描 CWE-476 模式。

调用外部 semgrep 二进制，使用已有的 YAML 规则文件扫描项目，
将 JSON 结果映射为 Candidate 流供 AI 做二次语义判断。

semgrep 社区版不返回 metavar 值，函数名通过 tree-sitter 按行号反查兜底。
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.logger import get_logger

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = get_logger(__name__)

_RULE_FILE = Path(__file__).parent / "mp_npd.yaml"
_SEMGREP_TIMEOUT_SECONDS = 15 * 60
_SEV_LABEL = {"ERROR": "高风险", "WARNING": "中风险", "INFO": "低风险"}
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())
_MESSAGE_FUNCTION_RE = re.compile(r"(?:函数|Function)\s+`?([A-Za-z_][A-Za-z0-9_:]*)`?")


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
    try:
        for func in db.get_all_functions():
            fp = _row_get(func, "file_path", "")
            start = _row_get(func, "start_line", 0)
            end = _row_get(func, "end_line", 0)
            if (
                fp
                and _path_matches(str(fp), reported_path, project_path)
                and start <= line <= end
            ):
                return _clean_func_name(_row_get(func, "name", ""))
    except Exception:
        pass
    return ""


def _func_from_message(message: str) -> str:
    match = _MESSAGE_FUNCTION_RE.search(message)
    if not match:
        return ""
    return _clean_func_name(match.group(1))


def _mv(metavars: dict, key: str) -> str:
    """从 semgrep metavars 中取一个值（兼容 $-前缀写法）。"""
    if not isinstance(metavars, dict):
        return ""
    raw = metavars.get(key) or metavars.get(f"${key.lstrip('$')}") or {}
    if isinstance(raw, dict):
        value = raw.get("abstract_content", "")
    else:
        value = raw
    if not isinstance(value, str):
        return ""
    return value.strip()


_MEMBER_ACCESS_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\s*->\s*[A-Za-z_][A-Za-z_0-9]*){2,}")


def _expr_from_lines(matched_lines: str) -> str:
    """从匹配代码片段里提取多层指针表达式（兜底，社区版 metavar 为空时使用）。

    形如 `... ctx->session->buf ...` 取第一段满足 `A->B->C` 形式的子串。
    """
    if not matched_lines:
        return ""
    for line in matched_lines.splitlines():
        m = _MEMBER_ACCESS_RE.search(line)
        if m:
            return m.group(0).replace(" ", "")
    return ""


def _decode_output(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return ""


def _read_semgrep_json(output_path: Path, fallback: object) -> str:
    try:
        if output_path.is_file():
            text = output_path.read_text(encoding="utf-8", errors="replace")
            if text.strip():
                return text
    except OSError:
        pass
    return _decode_output(fallback)


def _run_semgrep(project_path: Path) -> tuple[int | None, str, str] | None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="opendeephole-mp-npd-semgrep-") as tmp:
        output_path = Path(tmp) / "semgrep.json"
        cmd = [
            "semgrep",
            "--config", str(_RULE_FILE),
            "--json",
            f"--json-output={output_path}",
            "--no-git-ignore",
            str(project_path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_SEMGREP_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _read_semgrep_json(
                output_path,
                getattr(exc, "stdout", None) or getattr(exc, "output", None),
            )
            if stdout.strip():
                _log.warning(
                    "semgrep timed out after %s seconds for mp_npd scan; "
                    "using partial JSON output",
                    _SEMGREP_TIMEOUT_SECONDS,
                )
                return None, stdout, _decode_output(getattr(exc, "stderr", None))
            _log.warning(
                "semgrep timed out after %s seconds for mp_npd scan and produced no JSON output",
                _SEMGREP_TIMEOUT_SECONDS,
            )
            return None
        except Exception as exc:
            _log.warning(f"semgrep failed to run: {exc}")
            return None

        stdout = _read_semgrep_json(output_path, proc.stdout)
        return proc.returncode, stdout, proc.stderr


# ------------------------------------------------------------------ #
#  Analyzer
# ------------------------------------------------------------------ #

class Analyzer(BaseAnalyzer):
    vuln_type = "mp_npd"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; mp_npd checker skipped")
            return

        _src_cache.clear()

        result = _run_semgrep(project_path)
        if result is None:
            return
        returncode, stdout, stderr = result

        # semgrep: rc=0 无发现，rc=1 有发现，rc>1 工具报错
        if returncode is not None and returncode > 1:
            _log.warning(
                f"semgrep exited with rc={returncode}: {stderr[:300]}"
            )
            return

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            _log.warning(f"semgrep output JSON parse error: {exc}")
            return

        # 去重键：文件 + 函数 + 规则 + 多层指针表达式 + 根指针
        # 同函数对不同多层成员表达式仍保留独立告警
        seen: set[tuple[str, str, str, str, str]] = set()

        for match in data.get("results", []):
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {})
            severity: str = extra.get("severity", "WARNING")
            message: str = extra.get("message", "").strip()
            metavars: dict = extra.get("metavars", {}) or {}

            # semgrep 社区版 lines 字段受限，过滤掉无意义的提示
            raw_lines = extra.get("lines", "").strip()
            matched_lines = "" if "requires login" in raw_lines else raw_lines

            # 相对路径
            rel_path = _relative_reported_path(project_path, abs_path)

            # 规则类型：取 check_id 最后一段
            rule_category = check_id.split(".")[-1] if check_id else "unknown"

            # 函数名：message → CodeDB → tree-sitter 逐行反查
            func_name = (
                _func_from_message(message)
                or (db and _func_from_db(db, project_path, abs_path, start_line))
                or _func_at_line(project_path, abs_path, start_line)
                or "unknown"
            )

            # 关键 metavar（社区版多半为空）
            root = _mv(metavars, "$ROOT")
            field1 = _mv(metavars, "$F1")
            field2 = _mv(metavars, "$F2")
            field3 = _mv(metavars, "$F3")
            field4 = _mv(metavars, "$F4")
            call_name = _mv(metavars, "$CALL")

            # 还原多层指针表达式：优先使用 metavars 拼接，否则从匹配代码里提取
            mv_chain_parts = [p for p in (root, field1, field2, field3, field4) if p]
            if len(mv_chain_parts) >= 3:
                ptr_expr = "->".join(mv_chain_parts)
            else:
                ptr_expr = _expr_from_lines(matched_lines)

            # 去重
            dedup_key = (
                rel_path, func_name, rule_category,
                ptr_expr,
                root,
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # 组装 description
            sev_label = _SEV_LABEL.get(severity, severity)
            parts: list[str] = [f"[{sev_label}] {rule_category}", message]

            details: list[str] = []
            if ptr_expr:
                details.append(f"多层指针: {ptr_expr}")
            if root:
                details.append(f"根指针: {root}")
            if field1:
                details.append(f"中间层: {root}->{field1}" if root else f"中间层: ->{field1}")
            if call_name:
                details.append(f"被调用函数: {call_name}")
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
