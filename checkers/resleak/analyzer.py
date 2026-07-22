"""全类型资源泄露静态分析器。

两阶段扫描：
  Phase 1 — cppcheck（memleak / resourceLeak）：
    标准库配置覆盖 malloc/fopen/open/socket/mmap/dlopen/sqlite3 等；
    同时从 custom_allocs.yaml 加载用户自定义分配/释放函数对，
    动态生成临时 cppcheck 库配置文件注入扫描。

  Phase 2 — 轻量正则函数级扫描（补充 cppcheck 不追踪的锁类资源）：
    pthread_mutex_lock/unlock、pthread_rwlock/unlock、
    sem_wait/sem_post、pthread_create/join|detach。

自定义分配函数三种识别方式（custom_allocs.yaml）：
  1. 精确配对：pairs[] 显式指定 alloc/free 函数名
  2. 命名模式：naming.alloc_patterns / free_patterns 正则匹配
  3. 自动推断：auto_infer=true 时从 CodeDatabase 找内部调用 malloc 的包装函数
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate
from deephole_client.static_analysis.source_filter import iter_source_files

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# ------------------------------------------------------------------ #
#  文件收集
# ------------------------------------------------------------------ #

_SRC_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "build", "out", "_build", "cmake-build-debug", "cmake-build-release",
    "node_modules", "vendor", "third_party", "3rdparty", "thirdparty",
    "external", "extern", "deps",
}


def _iter_sources(root: Path) -> Iterator[Path]:
    yield from iter_source_files(root, _SRC_EXTS, skip_dirs=_SKIP_DIRS)


# ------------------------------------------------------------------ #
#  tree-sitter 工具
# ------------------------------------------------------------------ #

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _func_name(func_node, source: bytes) -> str:
    decl = func_node.child_by_field_name("declarator")
    if not decl:
        return ""
    for n in _walk(decl):
        if n.type in ("identifier", "qualified_identifier"):
            return source[n.start_byte:n.end_byte].decode("utf-8", "replace")
    return ""


def _iter_functions(root_node):
    """遍历顶层函数定义（不递归进嵌套函数体）。"""
    if root_node.type == "function_definition":
        yield root_node
        return
    for child in root_node.children:
        yield from _iter_functions(child)


def _func_at_line(source: bytes, target_line: int) -> str:
    """返回包含 target_line（1-based）的函数名，找不到返回空串。"""
    parser = tree_sitter.Parser(_CPP_LANGUAGE)
    tree = parser.parse(source)
    for func in _iter_functions(tree.root_node):
        start = func.start_point[0] + 1
        end   = func.end_point[0]  + 1
        if start <= target_line <= end:
            return _func_name(func, source) or "<anon>"
    return ""


# ------------------------------------------------------------------ #
#  自定义分配函数配置加载
# ------------------------------------------------------------------ #

# 内置已知分配函数（cppcheck 库配置已覆盖，此处用于自动推断的种子集合）
_BUILTIN_ALLOC_FUNCS = {
    "malloc", "calloc", "realloc", "reallocarray",
    "strdup", "strndup", "wcsdup",
    "valloc", "posix_memalign", "aligned_alloc",
    "new",                         # C++ operator（近似）
}

# 内置已知释放函数
_BUILTIN_FREE_FUNCS = {"free", "delete"}


def _load_custom_config(checker_dir: Path) -> dict:
    """
    加载 custom_allocs.yaml，返回：
    {
      "pairs":  [(alloc_name, [free_names], type_str), ...],
      "alloc_patterns": [compiled_regex, ...],
      "free_patterns":  [compiled_regex, ...],
      "auto_infer": bool,
    }
    """
    cfg_path = checker_dir / "custom_allocs.yaml"
    result = {
        "pairs": [],
        "alloc_patterns": [],
        "free_patterns": [],
        "auto_infer": True,
    }
    if not cfg_path.exists():
        return result

    try:
        import yaml  # type: ignore
        with cfg_path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return result

    # 方式一：精确配对
    for item in data.get("pairs") or []:
        alloc = item.get("alloc", "")
        free  = item.get("free", [])
        rtype = item.get("type", "custom resource")
        if alloc:
            frees = [free] if isinstance(free, str) else list(free)
            result["pairs"].append((alloc, frees, rtype))

    # 方式二：命名模式
    naming = data.get("naming") or {}
    for pat in naming.get("alloc_patterns") or []:
        try:
            result["alloc_patterns"].append(re.compile(pat))
        except re.error:
            pass
    for pat in naming.get("free_patterns") or []:
        try:
            result["free_patterns"].append(re.compile(pat))
        except re.error:
            pass

    # 方式三：自动推断开关
    result["auto_infer"] = bool(data.get("auto_infer", True))

    return result


# ------------------------------------------------------------------ #
#  自动推断包装函数（方式三）
# ------------------------------------------------------------------ #

# 匹配函数调用：identifier(
_CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def _infer_wrapper_allocs(project_path: Path, db: "CodeDatabase | None") -> set[str]:
    """
    从 CodeDatabase 或源文件扫描，找出内部调用了已知分配函数的包装函数。
    返回推断出的自定义分配函数名集合。
    """
    wrappers: set[str] = set()

    if db is not None:
        # 利用 CodeDatabase：查询函数体中包含 malloc/calloc/realloc 调用的函数
        try:
            all_funcs = db.get_all_functions()
        except Exception:
            all_funcs = []

        for func in all_funcs:
            body = func["body"] or ""
            name = func["name"] or ""
            if not body or not name:
                continue
            # 跳过已知内置函数自身
            if name in _BUILTIN_ALLOC_FUNCS or name in _BUILTIN_FREE_FUNCS:
                continue
            # 检查函数体内是否有对已知分配函数的调用
            calls = set(_CALL_RE.findall(body))
            if calls & _BUILTIN_ALLOC_FUNCS:
                # 再确认函数签名：返回值含指针（heuristic：函数体中有 return 且非 void）
                # CodeDatabase 不直接给 return type，用函数名启发：
                # 排除明显不是分配器的（含 free/destroy/check/is/has/get_count 等）
                lower = name.lower()
                if any(kw in lower for kw in ("free", "destroy", "release", "cleanup",
                                               "check", "verify", "print", "dump",
                                               "is_", "has_", "get_count", "get_size")):
                    continue
                wrappers.add(name)
        return wrappers

    # 无 CodeDatabase 时，扫描源文件（较慢，但保证可用）
    parser = tree_sitter.Parser(_CPP_LANGUAGE)
    for file_path in _iter_sources(project_path):
        try:
            source = file_path.read_bytes()
        except OSError:
            continue
        try:
            tree = parser.parse(source)
        except Exception:
            continue

        for func_node in _iter_functions(tree.root_node):
            name = _func_name(func_node, source)
            if not name or name in _BUILTIN_ALLOC_FUNCS:
                continue
            body = func_node.child_by_field_name("body")
            if body is None:
                continue
            body_text = source[body.start_byte:body.end_byte].decode("utf-8", "replace")
            calls = set(_CALL_RE.findall(body_text))
            if not (calls & _BUILTIN_ALLOC_FUNCS):
                continue
            lower = name.lower()
            if any(kw in lower for kw in ("free", "destroy", "release", "cleanup",
                                           "check", "verify", "print", "dump",
                                           "is_", "has_")):
                continue
            wrappers.add(name)

    return wrappers


# ------------------------------------------------------------------ #
#  cppcheck 动态库配置生成
# ------------------------------------------------------------------ #

_CPPCHECK_ALLOC_TEMPLATE = """\
<function name="{name}">
  <alloc init="false"/>
  <returnValue type="void *"/>
</function>
"""

_CPPCHECK_FREE_TEMPLATE = """\
<function name="{name}">
  <dealloc/>
  <arg nr="1"/>
</function>
"""


def _build_custom_cfg(
    explicit_pairs: list[tuple[str, list[str], str]],
    extra_allocs: set[str],
    extra_frees: set[str],
) -> str:
    """
    生成一个 cppcheck XML 库配置文件内容，包含所有自定义分配/释放函数。

    explicit_pairs: [(alloc_name, [free_names], type)] 精确配对
    extra_allocs:   通过命名模式或自动推断发现的分配函数（无明确配对）
    extra_frees:    通过命名模式发现的释放函数（无明确配对）
    """
    lines = ['<?xml version="1.0"?>', "<def>", "  <memory>"]

    # 精确配对：一个 <memory> 块 = 一组 alloc/dealloc
    for alloc_name, free_names, _ in explicit_pairs:
        lines.append(f"    <alloc>{alloc_name}</alloc>")
        for fn in free_names:
            lines.append(f"    <dealloc>{fn}</dealloc>")

    # 无配对的分配函数：单独的 <alloc>，dealloc 用 free 作兜底
    for name in sorted(extra_allocs):
        if any(name == p[0] for p in explicit_pairs):
            continue  # 已在精确配对中
        lines.append(f"    <alloc>{name}</alloc>")
        lines.append("    <dealloc>free</dealloc>")

    lines.append("  </memory>")

    # 命名模式发现的释放函数：告诉 cppcheck 它们是 dealloc
    for name in sorted(extra_frees):
        lines.append(f"""  <function name="{name}">
    <dealloc/>
    <arg nr="1"/>
  </function>""")

    lines.append("</def>")
    return "\n".join(lines)


# ------------------------------------------------------------------ #
#  Phase 1 — cppcheck
# ------------------------------------------------------------------ #

_CPPCHECK_BIN: str | None = None


def _get_cppcheck() -> str | None:
    global _CPPCHECK_BIN
    if _CPPCHECK_BIN is not None:
        return _CPPCHECK_BIN or None
    try:
        from cppcheck import get_cppcheck_dir
        candidate = str(get_cppcheck_dir() / "cppcheck")
        r = subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
        if r.returncode == 0:
            _CPPCHECK_BIN = candidate
            return _CPPCHECK_BIN
    except Exception:
        pass
    import shutil
    found = shutil.which("cppcheck")
    _CPPCHECK_BIN = found or ""
    return found


_ETYPE_DESC = {
    "memleak":              "堆内存泄露",
    "resourceLeak":         "资源句柄泄露",
    "leakReturnValNotUsed": "资源获取返回值未保存",
}
_WANT_SEVERITY = {"error", "warning"}


def _run_cppcheck(
    project_path: Path,
    bin_path: str,
    extra_lib_path: str | None = None,
) -> Iterator[tuple]:
    """运行 cppcheck，yield (rel_file, abs_file, line, symbol, eid, msg)。"""
    source_files = sorted(_iter_sources(project_path))
    if not source_files:
        return

    libs = "posix,gnu,sqlite3"
    cmd = [
        bin_path,
        "--enable=warning",
        f"--library={libs}",
        "--xml", "--xml-version=2",
        "--suppress=missingInclude",
        "--suppress=missingIncludeSystem",
        "--suppress=unusedFunction",
        "--max-ctu-depth=0",
    ]
    if extra_lib_path:
        cmd.append(f"--library={extra_lib_path}")

    file_list = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".files",
        delete=False,
        prefix="resleak_cppcheck_",
        encoding="utf-8",
    )
    try:
        try:
            file_list.write("\n".join(path.as_posix() for path in source_files) + "\n")
        finally:
            file_list.close()
        cmd.append(f"--file-list={file_list.name}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
        except Exception:
            return
    finally:
        try:
            os.unlink(file_list.name)
        except OSError:
            pass

    try:
        root = ET.fromstring(proc.stderr)
    except ET.ParseError:
        return

    for error in root.findall(".//error"):
        eid = error.get("id", "")
        if eid not in _ETYPE_DESC:
            continue
        if error.get("severity", "") not in _WANT_SEVERITY:
            continue
        loc = error.find("location")
        if loc is None:
            continue
        abs_file = loc.get("file", "")
        line_str = loc.get("line", "0")
        sym_node = error.find("symbol")
        symbol   = sym_node.text if sym_node is not None else "?"
        msg      = error.get("msg", "")
        try:
            rel_file = str(Path(abs_file).relative_to(project_path))
        except ValueError:
            rel_file = abs_file
        yield rel_file, abs_file, int(line_str), symbol, eid, msg


# ------------------------------------------------------------------ #
#  Phase 2 — 锁类资源轻量扫描
# ------------------------------------------------------------------ #

_LOCK_PATTERNS: list[tuple[str, str, str]] = [
    (r'\bpthread_mutex_lock\s*\(',    r'\bpthread_mutex_unlock\b',   "互斥锁(mutex_lock)"),
    (r'\bpthread_mutex_trylock\s*\(', r'\bpthread_mutex_unlock\b',   "互斥锁(mutex_trylock)"),
    (r'\bpthread_rwlock_rdlock\s*\(', r'\bpthread_rwlock_unlock\b',  "读写锁(rdlock)"),
    (r'\bpthread_rwlock_wrlock\s*\(', r'\bpthread_rwlock_unlock\b',  "读写锁(wrlock)"),
    (r'\bsem_wait\s*\(',              r'\bsem_post\b',               "信号量(sem_wait)"),
    (r'\bsem_timedwait\s*\(',         r'\bsem_post\b',               "信号量(sem_timedwait)"),
    (r'\bpthread_create\s*\(',        r'\bpthread_(?:join|detach)\b',"线程句柄"),
]

_MIN_RETURNS = 2


def _scan_lock_leaks(project_path: Path) -> Iterator[tuple]:
    """yield (rel_file, line, func_name, resource_types_str)"""
    parser = tree_sitter.Parser(_CPP_LANGUAGE)

    for file_path in _iter_sources(project_path):
        try:
            source = file_path.read_bytes()
        except OSError:
            continue
        try:
            tree = parser.parse(source)
        except Exception:
            continue
        try:
            rel = str(file_path.relative_to(project_path))
        except ValueError:
            rel = str(file_path)

        for func_node in _iter_functions(tree.root_node):
            body = func_node.child_by_field_name("body")
            if body is None:
                continue
            func_text = source[body.start_byte:body.end_byte].decode("utf-8", "replace")

            ret_count = len(re.findall(r'\breturn\b', func_text))
            if ret_count < _MIN_RETURNS:
                continue

            flagged: list[str] = []
            for acq_pat, rel_pat, rtype in _LOCK_PATTERNS:
                if not re.search(acq_pat, func_text):
                    continue
                if not re.search(rel_pat, func_text):
                    flagged.append(rtype + "（无释放调用）")
                else:
                    flagged.append(rtype)

            if not flagged:
                continue

            name = _func_name(func_node, source)
            line = func_node.start_point[0] + 1
            yield rel, line, name or "<anon>", ", ".join(dict.fromkeys(flagged))


# ------------------------------------------------------------------ #
#  Analyzer
# ------------------------------------------------------------------ #

class Analyzer(BaseAnalyzer):
    """全类型资源泄露检测器。

    Phase 1: cppcheck（内存/文件/套接字/mmap/dlopen/sqlite3 + 自定义分配函数）
    Phase 2: 正则扫描（锁/信号量/线程句柄）
    """

    vuln_type = "resleak"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        seen: set[tuple[str, str]] = set()
        checker_dir = Path(__file__).parent

        # ---- 加载自定义分配函数配置 ----
        custom_cfg = _load_custom_config(checker_dir)
        artifact_allocs: set[str] = set()
        artifact_frees: set[str] = set()
        try:
            from deephole_client.static_analysis.memory_api_artifact import load_memory_api_artifact
            artifact = load_memory_api_artifact(project_path)
            for item in artifact.get("allocators") or []:
                if isinstance(item, dict) and item.get("name"):
                    artifact_allocs.add(str(item["name"]))
            for item in artifact.get("deallocators") or []:
                if isinstance(item, dict) and item.get("name"):
                    artifact_frees.add(str(item["name"]))
            existing_pairs = {(alloc, free_name) for alloc, frees, _ in custom_cfg["pairs"] for free_name in frees}
            for item in artifact.get("pairs") or []:
                if not isinstance(item, dict):
                    continue
                alloc = str(item.get("allocator") or "").strip()
                free_name = str(item.get("deallocator") or "").strip()
                if alloc and free_name and (alloc, free_name) not in existing_pairs:
                    custom_cfg["pairs"].append((alloc, [free_name], "heap memory"))
                    existing_pairs.add((alloc, free_name))
        except Exception:
            pass

        # 方式三：自动推断
        inferred_allocs: set[str] = set()
        if custom_cfg["auto_infer"]:
            inferred_allocs = _infer_wrapper_allocs(project_path, db)

        # 命名模式匹配：扫描 CodeDatabase 或源文件中的函数名
        pattern_allocs: set[str] = set()
        pattern_frees: set[str] = set()
        if custom_cfg["alloc_patterns"] or custom_cfg["free_patterns"]:
            all_names = _collect_function_names(project_path, db)
            for name in all_names:
                if any(p.search(name) for p in custom_cfg["alloc_patterns"]):
                    pattern_allocs.add(name)
                if any(p.search(name) for p in custom_cfg["free_patterns"]):
                    pattern_frees.add(name)

        # 合并所有额外分配函数
        extra_allocs = inferred_allocs | pattern_allocs | artifact_allocs
        pattern_frees |= artifact_frees

        # ---- Phase 1: cppcheck ----
        cppcheck = _get_cppcheck()
        if cppcheck:
            extra_lib_path: str | None = None
            has_custom = bool(custom_cfg["pairs"] or extra_allocs or pattern_frees)

            if has_custom:
                cfg_content = _build_custom_cfg(
                    custom_cfg["pairs"], extra_allocs, pattern_frees
                )
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".cfg", delete=False, prefix="resleak_"
                )
                tmp.write(cfg_content)
                tmp.close()
                extra_lib_path = tmp.name

            src_cache: dict[str, bytes] = {}
            processed = 0
            files_list = sorted(_iter_sources(project_path))
            total = len(files_list)

            try:
                for rel, abs_file, line, symbol, eid, msg in _run_cppcheck(
                    project_path, cppcheck, extra_lib_path
                ):
                    if abs_file not in src_cache:
                        try:
                            src_cache[abs_file] = Path(abs_file).read_bytes()
                        except OSError:
                            continue
                    func_name = _func_at_line(src_cache[abs_file], line) or "<unknown>"

                    key = (rel, func_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    # 判断是否命中了自定义分配函数（用于丰富描述）
                    custom_hint = ""
                    if symbol in extra_allocs:
                        custom_hint = "（自动推断的自定义分配函数）"
                    elif any(symbol == p[0] for p in custom_cfg["pairs"]):
                        custom_hint = "（custom_allocs.yaml 配置的自定义函数）"

                    desc_type = _ETYPE_DESC.get(eid, eid)
                    yield Candidate(
                        file=rel,
                        line=line,
                        function=func_name,
                        description=(
                            f"函数 `{func_name}` 中变量 `{symbol}` 是否存在"
                            f"{desc_type}问题{custom_hint}，请审计确认。"
                            f"请检查所有退出路径是否正确释放。"
                        ),
                        vuln_type="resleak",
                    )

                    processed += 1
                    if self.on_file_progress:
                        self.on_file_progress(min(processed, total), total)
            finally:
                if extra_lib_path:
                    try:
                        os.unlink(extra_lib_path)
                    except OSError:
                        pass
        else:
            import logging
            logging.getLogger(__name__).warning("cppcheck not found; Phase 1 skipped for resleak")

        # ---- Phase 2: 锁类资源正则扫描 ----
        files2 = sorted(_iter_sources(project_path))
        total2 = len(files2)
        for idx, (rel, line, func_name, res_types) in enumerate(
            _scan_lock_leaks(project_path), 1
        ):
            key = (rel, func_name)
            if key in seen:
                continue
            seen.add(key)

            yield Candidate(
                file=rel,
                line=line,
                function=func_name,
                description=(
                    f"函数 `{func_name}` 中 {res_types} 是否存在资源泄漏问题，请审计确认。"
                    f"该函数存在 {res_types} 的获取操作且有多处 return 出口，"
                    f"请检查是否所有路径均有对应释放操作。"
                ),
                vuln_type="resleak",
            )

            if self.on_file_progress:
                self.on_file_progress(idx, total2)


# ------------------------------------------------------------------ #
#  辅助：收集项目中所有函数名（用于命名模式匹配）
# ------------------------------------------------------------------ #

def _collect_function_names(project_path: Path, db: "CodeDatabase | None") -> set[str]:
    if db is not None:
        try:
            return {f["name"] for f in db.get_all_functions() if f["name"]}
        except Exception:
            pass

    # 无 DB 时用正则从源文件快速提取函数名
    names: set[str] = set()
    func_def_re = re.compile(
        r'^\s*(?:(?:static|inline|extern|virtual|explicit)\s+)*'
        r'(?:[\w:*&<> ]+\s+)+\*?([A-Za-z_][A-Za-z0-9_:]*)\s*\(',
        re.MULTILINE,
    )
    for file_path in _iter_sources(project_path):
        try:
            text = file_path.read_text(errors="replace")
        except OSError:
            continue
        for m in func_def_re.finditer(text):
            names.add(m.group(1))
    return names
