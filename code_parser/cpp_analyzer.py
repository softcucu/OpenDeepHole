"""C/C++ source code analyzer backed by Universal Ctags and tree-sitter.

Universal Ctags provides source definitions for functions, structs/classes,
typedef structs, and global variables.  tree-sitter walks the ctags-discovered
function bodies for call and global-variable reference locations.  Dormant
cscope helpers are kept for possible future reuse, but the normal index path no
longer invokes cscope.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

from .code_database import CodeDatabase

INDEXER_VERSION = CodeDatabase.INDEXER_VERSION

_C_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}

_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "third_party", "3rdparty", "thirdparty",
    "external", "extern", "deps",
    "build", "cmake-build-debug", "cmake-build-release",
    "out", "output", "_build", ".build",
    "__pycache__", ".venv", "venv",
}
_SKIP_DIR_PREFIXES = (".opendeephole-index-",)

_FUNCTION_KINDS = {"function", "func", "f", "method"}
_STRUCT_KINDS = {"struct", "class", "union", "s", "c", "u"}
_TYPEDEF_KINDS = {"typedef", "t"}
_GLOBAL_VAR_KINDS = {"variable", "externvar", "var", "v", "x"}
_TOOL_POPEN_TEXT_KWARGS = {"text": True, "encoding": "utf-8", "errors": "replace"}
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

IndexProgressCallback = Callable[[int, int], None]
IndexStageProgressCallback = Callable[[str, int, int], None]


class CodeIndexToolError(RuntimeError):
    """Raised when indexing tools are missing or unusable."""


def _decode_tool_output(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return ""


@dataclass(frozen=True)
class _IndexedFunction:
    function_id: int
    name: str
    short_name: str
    file_path: str
    start_line: int
    end_line: int
    body: str


@dataclass(frozen=True)
class _IndexedGlobalVariable:
    global_var_id: int
    name: str
    file_path: str
    start_line: int
    end_line: int
    is_static: bool


@dataclass(frozen=True)
class _CscopeCall:
    file_path: str
    caller_name: str
    line: int
    text: str


class _CscopeLineQuerySession:
    """Reusable cscope line-mode process for caller lookups."""

    _COUNT_RE = re.compile(r"cscope:\s*(\d+)\s+lines\b")

    def __init__(self, project_root: Path, cscope_db: Path) -> None:
        self.project_root = project_root
        self._proc = subprocess.Popen(
            [
                "cscope",
                "-d",
                "-l",
                "-f",
                CppAnalyzer._relative_path(project_root, cscope_db),
            ],
            cwd=project_root,
            **_TOOL_POPEN_TEXT_KWARGS,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )

    def query_callers(self, symbol: str) -> list[_CscopeCall]:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise CodeIndexToolError("cscope line-oriented 查询进程未正确启动。")
        if self._proc.poll() is not None:
            raise CodeIndexToolError("cscope line-oriented 查询进程已退出。")

        self._proc.stdin.write(f"3{symbol}\n")
        self._proc.stdin.flush()

        count = self._read_result_count()
        if count < 0:
            return []
        calls: list[_CscopeCall] = []
        for _ in range(count):
            call = self._parse_call_line(self._readline())
            if call:
                calls.append(call)
        return calls

    def close(self) -> None:
        if self._proc.stdin is not None:
            try:
                self._proc.stdin.close()
            except OSError:
                pass
        if self._proc.poll() is not None:
            return
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()

    def _readline(self) -> str:
        if self._proc.stdout is None:
            raise CodeIndexToolError("cscope line-oriented 查询没有 stdout。")
        line = self._proc.stdout.readline()
        if line:
            return line
        message = "cscope line-oriented 查询提前结束。"
        if self._proc.poll() is not None and self._proc.stderr is not None:
            stderr = self._proc.stderr.read().strip()
            if stderr:
                message += " " + stderr
        raise CodeIndexToolError(message)

    def _read_result_count(self) -> int:
        while True:
            line = self._readline()
            if "Unable to search database" in line:
                return -1
            match = self._COUNT_RE.search(line)
            if match:
                return int(match.group(1))
            if line.strip().strip(">"):
                raise CodeIndexToolError(
                    "cscope line-oriented 查询返回了无法解析的计数行: "
                    + line.strip()
                )

    @staticmethod
    def _parse_call_line(line: str) -> _CscopeCall | None:
        parts = line.split(maxsplit=3)
        if len(parts) < 4:
            return None
        file_path, caller_name, line_no, text = parts
        try:
            line_int = int(line_no)
        except ValueError:
            return None
        return _CscopeCall(
            file_path=file_path.replace("\\", "/"),
            caller_name=caller_name,
            line=line_int,
            text=text.rstrip("\n"),
        )


class CppAnalyzer:
    def __init__(self, db: CodeDatabase) -> None:
        self.db = db
        self._functions: list[_IndexedFunction] = []
        self._functions_by_name: dict[str, list[_IndexedFunction]] = defaultdict(list)
        self._functions_by_short: dict[str, list[_IndexedFunction]] = defaultdict(list)
        self._global_variables: list[_IndexedGlobalVariable] = []
        self._global_variables_by_name: dict[str, list[_IndexedGlobalVariable]] = defaultdict(list)
        self._parser = Parser(_CPP_LANGUAGE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_directory(
        self,
        directory: Path,
        on_progress: IndexProgressCallback | None = None,
        cancel_check: Callable[[], bool] | None = None,
        on_stage_progress: IndexStageProgressCallback | None = None,
    ) -> None:
        """Index all C/C++ files under *directory* using ctags and tree-sitter."""
        project_root = Path(directory).resolve()
        files = self._collect_source_files(project_root)
        total = len(files)

        if not files:
            if on_progress:
                on_progress(0, 0)
            self.db.set_metadata("indexer", INDEXER_VERSION)
            self.db.commit()
            return

        self._ensure_tools_available()

        source_cache: dict[str, list[str]] = {}
        for idx, filepath in enumerate(files):
            if cancel_check and cancel_check():
                return
            rel_path = self._relative_path(project_root, filepath)
            self.db.get_or_create_file(rel_path)
            source_cache[rel_path] = filepath.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if on_progress and (idx % 10 == 0 or idx == total - 1):
                on_progress(idx + 1, total)

        with self._project_temp_dir(project_root) as tmp:
            work_dir = Path(tmp)
            if on_stage_progress:
                on_stage_progress("ctags scan", 0, 1)
            ctags_entries = self._run_ctags_json(project_root, files, work_dir)
            if on_stage_progress:
                on_stage_progress("ctags scan", 1, 1)
            if cancel_check and cancel_check():
                return

            self._index_ctags_entries(
                project_root,
                source_cache,
                ctags_entries,
                cancel_check=cancel_check,
                on_stage_progress=on_stage_progress,
            )
            self.db.commit()

        if cancel_check and cancel_check():
            return
        self._index_tree_sitter_references(
            source_cache,
            cancel_check=cancel_check,
            on_stage_progress=on_stage_progress,
        )

        self.db.set_metadata("indexer", INDEXER_VERSION)
        self.db.commit()

    def analyze_file(self, rel_path: str, source: bytes) -> None:
        """Index a single in-memory file.

        This compatibility path still uses ctags/tree-sitter.  Callers that need
        deterministic unit tests should monkeypatch the runner methods instead
        of depending on tree-sitter behavior.
        """
        with tempfile.TemporaryDirectory(prefix="odh-index-file-") as tmp:
            root = Path(tmp)
            target = root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source)
            self.analyze_directory(root)

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_tools_available() -> None:
        if shutil.which("ctags") is None:
            raise CodeIndexToolError(
                "代码索引依赖缺失: ctags。请安装 Universal Ctags 后重新扫描。"
            )

        version = subprocess.run(
            ["ctags", "--version"],
            capture_output=True,
            check=False,
        )
        if version.returncode != 0 or "Universal Ctags" not in _decode_tool_output(version.stdout):
            raise CodeIndexToolError(
                "ctags 必须是 Universal Ctags，当前 ctags 不支持所需的 JSON 输出。"
            )

        if not CppAnalyzer._ctags_supports_json_output():
            raise CodeIndexToolError(
                "ctags 必须支持 JSON 输出。请安装带 JSON 输出支持的 Universal Ctags。"
            )

    @staticmethod
    def _ctags_supports_json_output() -> bool:
        with tempfile.TemporaryDirectory(prefix="odh-ctags-probe-") as tmp:
            source_path = Path(tmp) / "probe.c"
            source_path.write_text(
                "int odh_ctags_json_probe(void) { return 0; }\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["ctags", "--output-format=json", "-o", "-", str(source_path)],
                capture_output=True,
                check=False,
            )

        if proc.returncode != 0:
            return False
        for line in _decode_tool_output(proc.stdout).splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("_type", "tag") == "tag":
                return True
        return False

    @staticmethod
    def _project_temp_dir(project_root: Path) -> tempfile.TemporaryDirectory:
        try:
            return tempfile.TemporaryDirectory(
                prefix=".opendeephole-index-",
                dir=project_root,
            )
        except OSError as exc:
            raise CodeIndexToolError(
                "无法在源码目录创建代码索引中间目录，请确认源码目录可写: "
                + str(exc)
            ) from exc

    def _run_ctags_json(
        self,
        project_root: Path,
        files: list[Path],
        work_dir: Path,
    ) -> list[dict]:
        list_path = work_dir / "ctags.files"
        list_path.write_text(
            "\n".join(self._relative_path(project_root, path) for path in files) + "\n",
            encoding="utf-8",
        )

        cmd = [
            "ctags",
            "--output-format=json",
            "--fields=+n+e+S+K+Z+s+t",
            "--languages=C,C++",
            "-f",
            "-",
            "-L",
            self._relative_path(project_root, list_path),
        ]
        proc = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            check=False,
        )

        stdout = _decode_tool_output(proc.stdout)
        stderr = _decode_tool_output(proc.stderr)
        if proc.returncode != 0:
            raise CodeIndexToolError(
                "ctags 代码索引失败: " + (stderr.strip() or stdout.strip())
            )

        if proc.stdout is None:
            raise CodeIndexToolError(
                "ctags 代码索引失败: 无法读取 ctags 输出，请检查 ctags 输出编码或安装是否正常。"
            )

        entries: list[dict] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("_type", "tag") == "tag":
                entries.append(payload)
        return entries

    def _index_cscope_calls(
        self,
        project_root: Path,
        files: list[Path],
        work_dir: Path,
        *,
        cancel_check: Callable[[], bool] | None = None,
        on_stage_progress: IndexStageProgressCallback | None = None,
    ) -> None:
        if not self._functions:
            return

        if on_stage_progress:
            on_stage_progress("cscope database", 0, 1)
        cscope_db = self._build_cscope_database(project_root, files, work_dir)
        if on_stage_progress:
            on_stage_progress("cscope database", 1, 1)
        symbols = sorted(
            {func.short_name for func in self._functions if func.short_name}
            | {func.name for func in self._functions if "::" in func.name}
        )
        total_symbols = len(symbols)
        if on_stage_progress:
            on_stage_progress("cscope symbols", 0, total_symbols)
        seen: set[tuple[str, str, int, int | None]] = set()
        session = self._open_cscope_query_session(cscope_db, project_root)
        try:
            for idx, symbol in enumerate(symbols, start=1):
                if cancel_check and cancel_check():
                    return
                for call in session.query_callers(symbol):
                    callee_name = symbol
                    caller = self._select_caller_function(call)
                    file_id = self.db.get_or_create_file(call.file_path)
                    col = max(call.text.find(self._short_name(symbol)), 0)
                    key = (callee_name, call.file_path, call.line, caller.function_id if caller else None)
                    if key in seen:
                        continue
                    seen.add(key)
                    callee_id = self._select_callee_id(callee_name)
                    self.db.insert_function_call(
                        caller_function_id=caller.function_id if caller else None,
                        callee_name=callee_name,
                        file_id=file_id,
                        line=call.line,
                        column=col,
                        callee_function_id=callee_id,
                    )
                if on_stage_progress and (idx % 25 == 0 or idx == total_symbols):
                    on_stage_progress("cscope symbols", idx, total_symbols)
        finally:
            session.close()

    def _build_cscope_database(
        self,
        project_root: Path,
        files: list[Path],
        temp_dir: Path,
    ) -> Path:
        files_list = temp_dir / "cscope.files"
        db_path = temp_dir / "cscope.out"
        files_list.write_text(
            "\n".join(self._relative_path(project_root, path) for path in files) + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [
                "cscope",
                "-b",
                "-q",
                "-k",
                "-i",
                self._relative_path(project_root, files_list),
                "-f",
                self._relative_path(project_root, db_path),
            ],
            cwd=project_root,
            capture_output=True,
            check=False,
        )
        stdout = _decode_tool_output(proc.stdout)
        stderr = _decode_tool_output(proc.stderr)
        if proc.returncode != 0:
            raise CodeIndexToolError(
                "cscope 调用关系索引失败: " + (stderr.strip() or stdout.strip())
            )
        return db_path

    def _query_cscope_callers(
        self,
        cscope_db: Path,
        symbol: str,
        project_root: Path,
    ) -> list[_CscopeCall]:
        session = self._open_cscope_query_session(cscope_db, project_root)
        try:
            return session.query_callers(symbol)
        finally:
            session.close()

    def _open_cscope_query_session(
        self,
        cscope_db: Path,
        project_root: Path,
    ) -> _CscopeLineQuerySession:
        return _CscopeLineQuerySession(project_root, cscope_db)

    # ------------------------------------------------------------------
    # Ctags indexing
    # ------------------------------------------------------------------

    def _index_ctags_entries(
        self,
        project_root: Path,
        source_cache: dict[str, list[str]],
        entries: list[dict],
        *,
        cancel_check: Callable[[], bool] | None = None,
        on_stage_progress: IndexStageProgressCallback | None = None,
    ) -> None:
        total_entries = len(entries)
        if on_stage_progress:
            on_stage_progress("ctags entries", 0, total_entries)
        for idx, entry in enumerate(entries, start=1):
            if cancel_check and cancel_check():
                return
            kind = self._kind(entry)
            rel_path = self._entry_path(project_root, entry)
            if not rel_path or rel_path not in source_cache:
                if on_stage_progress and (idx % 500 == 0 or idx == total_entries):
                    on_stage_progress("ctags entries", idx, total_entries)
                continue
            lines = source_cache[rel_path]

            if kind in _FUNCTION_KINDS:
                self._insert_function_entry(entry, rel_path, lines)
            elif kind in _STRUCT_KINDS:
                self._insert_struct_entry(entry, rel_path, lines)
            elif kind in _TYPEDEF_KINDS and self._typedef_is_struct(entry, lines):
                self._insert_struct_entry(entry, rel_path, lines)
            elif kind in _GLOBAL_VAR_KINDS:
                self._insert_global_variable_entry(entry, rel_path, lines)
            if on_stage_progress and (idx % 500 == 0 or idx == total_entries):
                on_stage_progress("ctags entries", idx, total_entries)

    def _insert_function_entry(self, entry: dict, rel_path: str, lines: list[str]) -> None:
        name = self._qualified_name(entry)
        if not name:
            return
        start_line = self._entry_line(entry)
        if start_line <= 0:
            return
        end_line = self._entry_end(entry)
        if end_line < start_line:
            end_line = self._find_block_end(lines, start_line)
        body = self._slice_lines(lines, start_line, end_line)
        if "{" not in body:
            return

        file_id = self.db.get_or_create_file(rel_path)
        signature = entry.get("signature") or self._first_line(body).strip()
        is_static = self._is_file_scope(entry, body)
        function_id = self.db.insert_function(
            name=name,
            signature=signature,
            return_type=self._return_type(entry),
            file_id=file_id,
            start_line=start_line,
            end_line=end_line,
            is_static=is_static,
            linkage="static" if is_static else "extern",
            body=body,
        )
        record = _IndexedFunction(
            function_id=function_id,
            name=name,
            short_name=self._short_name(name),
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            body=body,
        )
        self._functions.append(record)
        self._functions_by_name[name].append(record)
        self._functions_by_short[record.short_name].append(record)

    def _insert_struct_entry(self, entry: dict, rel_path: str, lines: list[str]) -> None:
        name = self._qualified_name(entry)
        if not name:
            return
        start_line = self._entry_line(entry)
        if start_line <= 0:
            return
        end_line = self._entry_end(entry)
        if end_line < start_line:
            end_line = self._find_definition_end(lines, start_line)
        definition = self._slice_lines(lines, start_line, end_line)
        file_id = self.db.get_or_create_file(rel_path)
        self.db.insert_struct(
            name=name,
            file_id=file_id,
            start_line=start_line,
            end_line=end_line,
            definition=definition,
        )

    def _insert_global_variable_entry(self, entry: dict, rel_path: str, lines: list[str]) -> None:
        name = str(entry.get("name") or "").strip()
        if not name:
            return
        start_line = self._entry_line(entry)
        if start_line <= 0:
            return
        end_line = self._entry_end(entry)
        if end_line < start_line:
            end_line = self._find_statement_end(lines, start_line)
        definition = self._slice_lines(lines, start_line, end_line)
        if "(" in self._first_line(definition):
            return
        file_id = self.db.get_or_create_file(rel_path)
        is_static = self._is_file_scope(entry, definition)
        global_var_id = self.db.insert_global_variable(
            name=name,
            file_id=file_id,
            start_line=start_line,
            end_line=end_line,
            is_extern=self._first_line(definition).lstrip().startswith("extern "),
            is_static=is_static,
            definition=definition,
        )
        record = _IndexedGlobalVariable(
            global_var_id=global_var_id,
            name=name,
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            is_static=is_static,
        )
        self._global_variables.append(record)
        self._global_variables_by_name[name].append(record)

    def _index_tree_sitter_references(
        self,
        source_cache: dict[str, list[str]],
        *,
        cancel_check: Callable[[], bool] | None = None,
        on_stage_progress: IndexStageProgressCallback | None = None,
    ) -> None:
        total_functions = len(self._functions)
        if on_stage_progress:
            on_stage_progress("tree-sitter refs", 0, total_functions)
        if not self._functions:
            return

        indexed_globals = {
            global_var.name
            for global_var in self._global_variables
            if global_var.name.startswith("g_")
        }
        seen_calls: set[tuple[int, str, int, int]] = set()
        seen_globals: set[tuple[int, str, int, int]] = set()

        for idx, function in enumerate(self._functions, start=1):
            if cancel_check and cancel_check():
                return
            if function.body:
                tree = self._parser.parse(function.body.encode("utf-8", errors="replace"))
                self._index_tree_sitter_function_references(
                    function,
                    tree.root_node,
                    source_cache,
                    indexed_globals,
                    seen_calls,
                    seen_globals,
                )
            if on_stage_progress and (idx % 100 == 0 or idx == total_functions):
                on_stage_progress("tree-sitter refs", idx, total_functions)

    def _index_tree_sitter_function_references(
        self,
        function: _IndexedFunction,
        root: Node,
        source_cache: dict[str, list[str]],
        indexed_globals: set[str],
        seen_calls: set[tuple[int, str, int, int]],
        seen_globals: set[tuple[int, str, int, int]],
    ) -> None:
        file_id = self.db.get_or_create_file(function.file_path)
        local_declarations = self._collect_local_declarations(root)
        for node in self._walk_tree(root):
            if node.type == "call_expression":
                self._insert_tree_sitter_call(function, file_id, node, seen_calls)
            elif node.type == "identifier":
                self._insert_tree_sitter_global_reference(
                    function,
                    file_id,
                    node,
                    source_cache,
                    indexed_globals,
                    seen_globals,
                    local_declarations,
                )

    def _insert_tree_sitter_call(
        self,
        caller: _IndexedFunction,
        file_id: int,
        node: Node,
        seen_calls: set[tuple[int, str, int, int]],
    ) -> None:
        function_node = node.child_by_field_name("function")
        if function_node is None:
            return
        callee_name = self._callee_name_from_node(function_node)
        if not callee_name:
            return
        callee = self._select_callee(callee_name)
        stored_callee_name = callee.name if callee else callee_name

        line = caller.start_line + node.start_point[0]
        column = node.start_point[1]
        key = (caller.function_id, stored_callee_name, line, column)
        if key in seen_calls:
            return
        seen_calls.add(key)

        self.db.insert_function_call(
            caller_function_id=caller.function_id,
            callee_name=stored_callee_name,
            file_id=file_id,
            line=line,
            column=column,
            callee_function_id=callee.function_id if callee else None,
        )

    def _insert_tree_sitter_global_reference(
        self,
        function: _IndexedFunction,
        file_id: int,
        node: Node,
        source_cache: dict[str, list[str]],
        indexed_globals: set[str],
        seen_globals: set[tuple[int, str, int, int]],
        local_declarations: dict[str, list[int]],
    ) -> None:
        name = self._node_text(node)
        if name not in indexed_globals:
            return
        if self._identifier_is_declarator(node):
            return
        if any(line <= node.start_point[0] for line in local_declarations.get(name, [])):
            return
        candidates = self._global_variables_by_name.get(name, [])
        if not candidates:
            return

        line = function.start_line + node.start_point[0]
        column = node.start_point[1]
        global_var = self._select_global_variable(name, function.file_path)
        if global_var is None:
            return
        key = (function.function_id, name, line, column)
        if key in seen_globals:
            return
        seen_globals.add(key)

        lines = source_cache.get(function.file_path, [])
        line_text = lines[line - 1] if 0 < line <= len(lines) else ""
        self.db.insert_global_variable_reference(
            global_var_id=global_var.global_var_id,
            variable_name=name,
            file_id=file_id,
            function_id=function.function_id,
            line=line,
            column=column,
            context=line_text.strip(),
            access_type=self._global_access_type(name, line_text),
        )

    def _index_global_variable_references(
        self,
        source_cache: dict[str, list[str]],
        *,
        cancel_check: Callable[[], bool] | None = None,
        on_stage_progress: IndexStageProgressCallback | None = None,
    ) -> None:
        rows = [row for row in self.db.get_all_global_variables() if row["name"].startswith("g_")]
        total_rows = len(rows)
        if on_stage_progress:
            on_stage_progress("global refs", 0, total_rows)
        for idx, row in enumerate(rows, start=1):
            if cancel_check and cancel_check():
                return
            name = row["name"]
            pattern = re.compile(r"\b" + re.escape(name) + r"\b")
            for rel_path, lines in source_cache.items():
                file_id = self.db.get_or_create_file(rel_path)
                for line_no, line_text in enumerate(lines, start=1):
                    if not pattern.search(line_text):
                        continue
                    function = self._select_function_by_location(rel_path, line_no)
                    self.db.insert_global_variable_reference(
                        global_var_id=row["global_var_id"],
                        variable_name=name,
                        file_id=file_id,
                        function_id=function.function_id if function else None,
                        line=line_no,
                        column=max(line_text.find(name), 0),
                        context=line_text.strip(),
                        access_type=self._global_access_type(name, line_text),
                    )
            if on_stage_progress and (idx % 10 == 0 or idx == total_rows):
                on_stage_progress("global refs", idx, total_rows)

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def _select_caller_function(self, call: _CscopeCall) -> _IndexedFunction | None:
        by_location = self._select_function_by_location(call.file_path, call.line)
        if by_location:
            return by_location

        candidates = self._functions_by_name.get(call.caller_name) or self._functions_by_short.get(call.caller_name)
        for candidate in candidates or []:
            if candidate.file_path == call.file_path:
                return candidate
        return candidates[0] if candidates else None

    def _select_function_by_location(self, rel_path: str, line: int) -> _IndexedFunction | None:
        for func in self._functions:
            if func.file_path == rel_path and func.start_line <= line <= func.end_line:
                return func
        return None

    def _select_callee_id(self, callee_name: str) -> int | None:
        candidate = self._select_callee(callee_name)
        return candidate.function_id if candidate else None

    def _select_callee(self, callee_name: str) -> _IndexedFunction | None:
        candidates = self._functions_by_name.get(callee_name)
        if not candidates:
            candidates = self._functions_by_short.get(self._short_name(callee_name))
        if candidates and len(candidates) == 1:
            return candidates[0]
        return None

    def _select_global_variable(
        self,
        name: str,
        function_file_path: str,
    ) -> _IndexedGlobalVariable | None:
        candidates = self._global_variables_by_name.get(name, [])
        if not candidates:
            return None
        file_scope = [
            candidate
            for candidate in candidates
            if candidate.is_static and candidate.file_path == function_file_path
        ]
        if file_scope:
            return file_scope[0]
        external = [candidate for candidate in candidates if not candidate.is_static]
        if external:
            return external[0]
        return candidates[0]

    # ------------------------------------------------------------------
    # tree-sitter helpers
    # ------------------------------------------------------------------

    @classmethod
    def _walk_tree(cls, root: Node):
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    @classmethod
    def _callee_name_from_node(cls, node: Node) -> str:
        if node.type in {"identifier", "field_identifier"}:
            return cls._node_text(node)
        if node.type in {"qualified_identifier", "scoped_identifier"}:
            return cls._node_text(node).replace("::template ", "::")
        if node.type == "template_function":
            name = node.child_by_field_name("name")
            return cls._callee_name_from_node(name) if name is not None else cls._node_text(node)
        if node.type == "field_expression":
            field = node.child_by_field_name("field")
            if field is not None:
                return cls._callee_name_from_node(field)
        if node.type == "parenthesized_expression" and node.named_child_count == 1:
            return cls._callee_name_from_node(node.named_children[0])
        return ""

    @staticmethod
    def _node_text(node: Node) -> str:
        return node.text.decode("utf-8", errors="replace").strip()

    @classmethod
    def _collect_local_declarations(cls, root: Node) -> dict[str, list[int]]:
        declarations: dict[str, list[int]] = defaultdict(list)
        for node in cls._walk_tree(root):
            if node.type not in {"parameter_declaration", "init_declarator"}:
                continue
            declarator = node.child_by_field_name("declarator")
            identifier = cls._declarator_identifier(declarator)
            if identifier is not None:
                declarations[cls._node_text(identifier)].append(node.start_point[0])
        return declarations

    @classmethod
    def _identifier_is_declarator(cls, node: Node) -> bool:
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "function_declarator":
            return parent.child_by_field_name("declarator") == node
        if parent.type in {"parameter_declaration", "init_declarator"}:
            return cls._declarator_identifier(parent.child_by_field_name("declarator")) == node
        return False

    @classmethod
    def _declarator_identifier(cls, node: Node | None) -> Node | None:
        if node is None:
            return None
        if node.type == "identifier":
            return node
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            found = cls._declarator_identifier(declarator)
            if found is not None:
                return found
        for child in node.children:
            found = cls._declarator_identifier(child)
            if found is not None:
                return found
        return None

    # ------------------------------------------------------------------
    # Source helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_source_files(directory: Path) -> list[Path]:
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [
                d
                for d in dirnames
                if d not in _SKIP_DIRS
                and not d.startswith(_SKIP_DIR_PREFIXES)
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                if path.suffix in _C_CPP_EXTS:
                    files.append(path)
        return sorted(files)

    @staticmethod
    def _relative_path(project_root: Path, filepath: Path) -> str:
        return str(filepath.resolve().relative_to(project_root)).replace("\\", "/")

    @staticmethod
    def _slice_lines(lines: list[str], start_line: int, end_line: int) -> str:
        if not lines:
            return ""
        start = max(start_line - 1, 0)
        end = min(max(end_line, start_line), len(lines))
        return "\n".join(lines[start:end])

    @staticmethod
    def _first_line(text: str) -> str:
        return text.splitlines()[0] if text else ""

    @staticmethod
    def _find_statement_end(lines: list[str], start_line: int) -> int:
        for idx in range(max(start_line - 1, 0), len(lines)):
            if ";" in lines[idx]:
                return idx + 1
        return start_line

    @classmethod
    def _find_definition_end(cls, lines: list[str], start_line: int) -> int:
        block_end = cls._find_block_end(lines, start_line)
        if block_end != start_line:
            return block_end
        return cls._find_statement_end(lines, start_line)

    @staticmethod
    def _find_block_end(lines: list[str], start_line: int) -> int:
        depth = 0
        seen_open = False
        for idx in range(max(start_line - 1, 0), len(lines)):
            line = lines[idx]
            pos = 0
            while pos < len(line):
                ch = line[pos]
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
                    if seen_open and depth <= 0:
                        return idx + 1
                pos += 1
        return start_line

    # ------------------------------------------------------------------
    # Ctags field helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _kind(entry: dict) -> str:
        return str(entry.get("kind") or "").lower()

    @classmethod
    def _qualified_name(cls, entry: dict) -> str:
        name = str(entry.get("name") or "").strip()
        if not name:
            return ""
        scope = str(entry.get("scope") or "").strip()
        if scope and "::" not in name:
            return f"{scope}::{name}"
        return name

    @staticmethod
    def _short_name(name: str) -> str:
        return name.rsplit("::", 1)[-1]

    def _entry_path(self, project_root: Path, entry: dict) -> str:
        raw = str(entry.get("path") or "")
        if not raw:
            return ""
        path = Path(raw)
        if path.is_absolute():
            try:
                return str(path.resolve().relative_to(project_root)).replace("\\", "/")
            except ValueError:
                return ""
        return raw.replace("\\", "/")

    @staticmethod
    def _entry_line(entry: dict) -> int:
        try:
            return int(entry.get("line") or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _entry_end(entry: dict) -> int:
        try:
            return int(entry.get("end") or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _return_type(entry: dict) -> str:
        typeref = str(entry.get("typeref") or "")
        if ":" in typeref:
            return typeref.split(":", 1)[1]
        return typeref

    @staticmethod
    def _is_file_scope(entry: dict, definition: str) -> bool:
        extras = entry.get("extras") or []
        if isinstance(extras, str):
            extras = [extras]
        return "fileScope" in extras or CppAnalyzer._first_line(definition).lstrip().startswith("static ")

    @staticmethod
    def _typedef_is_struct(entry: dict, lines: list[str]) -> bool:
        typeref = str(entry.get("typeref") or "").lower()
        start_line = CppAnalyzer._entry_line(entry)
        end_line = CppAnalyzer._entry_end(entry)
        if end_line < start_line:
            end_line = CppAnalyzer._find_definition_end(lines, start_line)
        definition = CppAnalyzer._slice_lines(lines, start_line, end_line).lower()
        return any(token in typeref or token in definition for token in ("struct", "class", "union"))

    @staticmethod
    def _global_access_type(name: str, line_text: str) -> str:
        assignment = re.compile(
            r"\b"
            + re.escape(name)
            + r"\s*(?:\[.*?\]\s*)?(?:[-+*/%&|^]?=|\+\+|--)"
        )
        prefix_update = re.compile(r"(?:\+\+|--)\s*\b" + re.escape(name) + r"\b")
        return "write" if assignment.search(line_text) or prefix_update.search(line_text) else "read"
