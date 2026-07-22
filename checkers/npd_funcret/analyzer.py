"""NPD-FuncRet 静态分析器 — 函数返回值/参数赋值未判空导致的空指针解引用。

混合方案：
  Phase 1: semgrep 扫描匹配「赋值 → 未判空 → 解引用」模式
  Phase 2: tree-sitter + CodeDatabase 跨函数分析，过滤不可能返回 NULL 的函数

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

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate
from deephole_client.static_analysis.semgrep_locations import function_from_db_location, relative_reported_path
from deephole_client.static_analysis.semgrep_runner import DEFAULT_SEMGREP_TIMEOUT_SECONDS, run_semgrep
import logging
from code_parser.code_utils import find_nodes_by_type

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = logging.getLogger(__name__)

_RULE_FILE = Path(__file__).parent / "npd_funcret_semgrep.yml"
_SEMGREP_TIMEOUT_SECONDS = DEFAULT_SEMGREP_TIMEOUT_SECONDS
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# 规则消息中提取函数名
_MESSAGE_FUNCTION_RE = re.compile(r"Function\s*=\s*`([A-Za-z_][A-Za-z0-9_:]*)`")

# 从匹配代码中提取被调函数名的模式
# 匹配：p = func(...)  或  p = (type *)func(...)  或  type *p = func(...)
_RETVAL_ASSIGN_RE = re.compile(
    r"(?:\w[\w\s*]*\s+\*?\s*)?"  # optional type declaration
    r"\w+\s*=\s*"                # var =
    r"(?:\([^)]*\)\s*)?"         # optional cast
    r"(\w+)\s*\(",               # func_name(
)
# 匹配参数赋值：func(..., &p, ...)
_PARAM_ASSIGN_RE = re.compile(r"(\w+)\s*\([^)]*&\w+")


# 已知可能返回 NULL 的函数
_KNOWN_NULL_RETURNERS: frozenset[str] = frozenset({
    "malloc", "calloc", "realloc", "reallocarray", "aligned_alloc",
    "strdup", "strndup", "wcsdup",
    "mmap",
    "fopen", "fdopen", "freopen", "tmpfile", "fopen64",
    "popen",
    "dlopen", "dlsym",
    "getenv", "secure_getenv",
    "strtok", "strtok_r",
    "bsearch",
    "inet_ntoa",
    "localtime", "gmtime", "ctime", "asctime",
    "localtime_r", "gmtime_r",
    "opendir", "readdir", "readdir_r",
    "tmpnam", "tempnam",
    "getcwd",
    "setlocale",
    # Linux kernel
    "kmalloc", "kzalloc", "kcalloc", "kvmalloc", "kvzalloc",
    "vmalloc", "vzalloc",
    "devm_kmalloc", "devm_kzalloc",
    "krealloc",
    # GLib
    "g_try_malloc", "g_try_malloc0", "g_try_realloc",
    # FFmpeg
    "av_malloc", "av_mallocz", "av_realloc",
    # Samba
    "talloc", "talloc_zero",
})

# 已知不可能返回 NULL 的函数（返回非指针或保证非 NULL）
_KNOWN_NONNULL_RETURNERS: frozenset[str] = frozenset({
    "memset", "memcpy", "memmove", "memchr",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strlen", "wcslen",
    "printf", "fprintf", "vprintf", "vfprintf",
    "puts", "fputs",
    "abort", "exit", "_exit", "_Exit",
    "assert",
    "atoi", "atol", "atoll", "atof",
    "abs", "labs", "llabs",
    "sizeof",
})

# ------------------------------------------------------------------ #
#  集中定义：空指针字面量 & 空指针校验函数
#  在此处统一维护，semgrep 规则负责排除标准模式（if/assert），
#  下方的 _matched_has_null_check() 负责排除自定义宏/函数。
# ------------------------------------------------------------------ #

# 空指针字面量（用于 _can_return_null 的 return 语句检查）
_NULL_LITERALS: frozenset[str] = frozenset({
    "NULL", "nullptr", "0",
    "((void *)0)", "((void*)0)",
    # 项目自定义空指针宏
    "VOS_NULL_PTR",
    "FCA_NULL",
})

# 空指针校验函数/宏（调用这些函数即视为已判空）
_NULL_CHECK_FUNCS: frozenset[str] = frozenset({
    "CHECK_POINTER_RETURN",
    "ADP_6603_CHECK_POINT_VALID_RETURN",
    "IS_PTR_INVALID",
    "RET_IF_NULL_PTR",
    "BREAK_IF_NULL_PTR",
    "FSM_CHECK_PTR_RETURN_PARA",
    "RRFM_EqmJudgeLeoHoIntergrity",
    "SUSRPUSCH_PC_IsQciPwrCtrl",
    "UEM_IsValidOfAllowedBc",
    "CheckMeaPointIsNull",
})

# 构建匹配判空函数/宏的正则（匹配代码中出现这些函数调用即认为已判空）
_NULL_CHECK_FUNCS_RE = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _NULL_CHECK_FUNCS) + r")\s*\("
) if _NULL_CHECK_FUNCS else None

# 匹配代码中的自定义空指针字面量比较（semgrep 只排除 NULL/nullptr，自定义的在此补充）
_CUSTOM_NULL_LITERALS = [n for n in _NULL_LITERALS if n not in ("NULL", "nullptr", "0", "((void *)0)", "((void*)0)")]
_CUSTOM_NULL_CHECK_RE = re.compile(
    r"\b(" + "|".join(re.escape(n) for n in _CUSTOM_NULL_LITERALS) + r")\b"
) if _CUSTOM_NULL_LITERALS else None

# 赋值类型标识
_ASSIGN_TYPE_RETVAL = "return_value"
_ASSIGN_TYPE_PARAM = "param_output"


def _matched_has_null_check(matched_lines: str, ptr_name: str) -> bool:
    """检查 semgrep 匹配的代码片段中是否包含对 ptr_name 的空指针校验。

    semgrep 规则已排除 if(p==NULL)/if(!p)/if(p)/assert(p) 等标准模式，
    此函数补充检查：
      1. 自定义判空函数/宏（如 CHECK_POINTER_RETURN(p)）
      2. 自定义空指针字面量比较（如 if (p == VOS_NULL_PTR)）
    """
    if not matched_lines or not ptr_name:
        return False

    # 检查自定义判空函数是否以 ptr_name 为参数出现
    if _NULL_CHECK_FUNCS_RE:
        for line in matched_lines.splitlines():
            if ptr_name not in line:
                continue
            if _NULL_CHECK_FUNCS_RE.search(line):
                return True

    # 检查自定义空指针字面量是否与 ptr_name 一起出现在 if 条件中
    if _CUSTOM_NULL_CHECK_RE:
        for line in matched_lines.splitlines():
            if ptr_name in line and _CUSTOM_NULL_CHECK_RE.search(line):
                return True

    return False


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


_src_cache: dict[str, bytes] = {}


def _clean_func_name(name: object) -> str:
    if not isinstance(name, str):
        return ""
    name = name.strip()
    if not name or name == "unknown" or name.startswith("$"):
        return ""
    return name


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


def _func_at_line(project_path: Path, reported_path: str, line: int) -> str:
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
    return function_from_db_location(
        db, project_path, reported_path, line,
        clean_func_name=_clean_func_name,
    )


def _func_from_message(message: str) -> str:
    match = _MESSAGE_FUNCTION_RE.search(message)
    if not match:
        return ""
    return _clean_func_name(match.group(1))


def _mv(metavars: dict, key: str) -> str:
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


def _detect_assign_type(check_id: str) -> str:
    """从 semgrep rule id 判断赋值类型。"""
    if "param-assign" in check_id:
        return _ASSIGN_TYPE_PARAM
    return _ASSIGN_TYPE_RETVAL


def _extract_called_func_retval(matched_lines: str) -> str:
    """从匹配代码中提取返回值赋值场景的被调函数名。"""
    m = _RETVAL_ASSIGN_RE.search(matched_lines)
    return m.group(1) if m else ""


def _extract_called_func_param(matched_lines: str) -> str:
    """从匹配代码中提取参数赋值场景的被调函数名。"""
    m = _PARAM_ASSIGN_RE.search(matched_lines)
    return m.group(1) if m else ""


# ------------------------------------------------------------------ #
#  跨函数分析：判断函数是否可能返回 NULL
# ------------------------------------------------------------------ #

def _can_return_null(
    func_name: str,
    db: "CodeDatabase | None",
    visited: set[str] | None = None,
    depth: int = 0,
    max_depth: int = 3,
) -> bool:
    """判断函数是否可能返回 NULL。

    对于已知函数直接查表；对于项目内函数用 tree-sitter 分析 return 语句。
    递归深度限制为 max_depth 层，visited 防止循环。
    """
    if func_name in _KNOWN_NULL_RETURNERS:
        return True
    if func_name in _KNOWN_NONNULL_RETURNERS:
        return False

    if visited is None:
        visited = set()
    if func_name in visited or depth >= max_depth:
        return False
    visited.add(func_name)

    if db is None:
        return True  # 无数据库，保守认为可能返回 NULL

    rows = db.get_functions_by_name(func_name)
    if not rows:
        return True  # 外部函数，保守认为可能返回 NULL

    parser = tree_sitter.Parser(_CPP_LANGUAGE)

    for row in rows:
        body = row["body"] if "body" in row.keys() else ""
        if not body:
            continue

        try:
            tree = parser.parse(body.encode("utf-8", "replace"))
        except Exception:
            continue

        for ret_node in find_nodes_by_type(tree.root_node, "return_statement"):
            if ret_node.child_count < 2:
                continue
            ret_expr = ret_node.children[1]

            # 跳过分号
            if ret_expr.type == ";":
                continue

            ret_text = ret_expr.text.decode("utf-8", "replace").strip().rstrip(";").strip()

            # 直接返回 NULL
            if ret_text in _NULL_LITERALS:
                return True

            # 条件表达式：return cond ? a : NULL
            if ret_expr.type == "conditional_expression":
                for field_name in ("consequence", "alternative"):
                    alt = ret_expr.child_by_field_name(field_name)
                    if alt and alt.text.decode("utf-8", "replace").strip() in _NULL_LITERALS:
                        return True

            # 去掉类型强转后检查
            inner = ret_expr
            while inner.type == "cast_expression":
                val = inner.child_by_field_name("value")
                if val is None:
                    break
                inner = val

            inner_text = inner.text.decode("utf-8", "replace").strip().rstrip(";").strip()
            if inner_text in _NULL_LITERALS:
                return True

            # 返回另一个函数调用的结果 → 递归检查
            if inner.type == "call_expression":
                callee = inner.child_by_field_name("function")
                if callee and callee.type == "identifier":
                    callee_name = callee.text.decode("utf-8", "replace").strip()
                    if _can_return_null(callee_name, db, visited, depth + 1, max_depth):
                        return True

    return False


# ------------------------------------------------------------------ #
#  Analyzer
# ------------------------------------------------------------------ #

class Analyzer(BaseAnalyzer):
    vuln_type = "npd_funcret"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; npd_funcret checker skipped")
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

        if result.returncode is not None and result.returncode > 1:
            _log.warning(f"semgrep exited with rc={result.returncode}: {result.stderr[:300]}")
            if not result.stdout or not result.stdout.strip():
                return

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            _log.warning(f"semgrep output JSON parse error: {exc}")
            return

        # 去重键
        seen: set[tuple[str, str, str, str]] = set()

        for match in data.get("results", []):
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {})
            severity: str = extra.get("severity", "WARNING")
            message: str = extra.get("message", "").strip()
            metavars: dict = extra.get("metavars", {}) or {}

            raw_lines = extra.get("lines", "").strip()
            matched_lines = "" if "requires login" in raw_lines else raw_lines

            rel_path = relative_reported_path(project_path, abs_path)

            # 判断赋值类型
            assign_type = _detect_assign_type(check_id)

            # 提取被调函数名
            called_func = _clean_func_name(_mv(metavars, "$CALL"))
            if not called_func and matched_lines:
                if assign_type == _ASSIGN_TYPE_PARAM:
                    called_func = _extract_called_func_param(matched_lines)
                else:
                    called_func = _extract_called_func_retval(matched_lines)

            # 提取指针名
            ptr_name = _clean_func_name(_mv(metavars, "$P"))

            # Phase 2a: 检查匹配代码中是否包含自定义判空函数/宏
            if ptr_name and _matched_has_null_check(matched_lines, ptr_name):
                continue

            # Phase 2b: 返回值赋值场景做 _can_return_null 过滤
            if assign_type == _ASSIGN_TYPE_RETVAL and called_func:
                if not _can_return_null(called_func, db):
                    continue

            # 所在函数名
            func_name = (
                _clean_func_name(_mv(metavars, "$FUNC"))
                or _func_from_message(message)
                or (db and _func_from_db(db, project_path, abs_path, start_line))
                or _func_at_line(project_path, abs_path, start_line)
                or "unknown"
            )

            # 去重
            dedup_key = (rel_path, func_name, called_func or "", ptr_name or "")
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # 构建描述
            if assign_type == _ASSIGN_TYPE_PARAM:
                assign_desc = f"通过函数 `{called_func or '?'}` 的输出参数赋值（&{ptr_name or '?'}）"
            else:
                assign_desc = f"接收函数 `{called_func or '?'}` 的返回值赋值"

            desc_prefix = (
                f"函数 `{func_name}` 中指针 `{ptr_name or '?'}`（{assign_desc}）"
                f"是否存在空指针解引用问题，请审计确认。"
            )

            parts: list[str] = [desc_prefix]

            detail_lines: list[str] = [f"赋值方式: {assign_desc}"]
            if called_func:
                detail_lines.append(f"赋值来源函数: {called_func}")
            parts.append("相关线索：\n" + "\n".join(detail_lines))

            # related_functions 传递被调函数名，让 AI 可以检查其函数体
            related = [called_func] if called_func else []

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(parts),
                vuln_type=self.vuln_type,
                related_functions=related,
            )
