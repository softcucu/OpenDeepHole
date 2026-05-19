"""C/C++ source code analyzer backed by Universal Ctags and cscope.

Universal Ctags provides source definitions for functions, structs/classes,
typedef structs, and global variables.  cscope provides function reference
locations.  The public ``CppAnalyzer`` name is kept so existing scan, upload,
MCP, and checker-test paths can use the same entry point.
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

IndexProgressCallback = Callable[[int, int], None]
IndexStageProgressCallback = Callable[[str, int, int], None]


class CodeIndexToolError(RuntimeError):
    """Raised when ctags/cscope are missing or unusable."""


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
        """Index all C/C++ files under *directory* using ctags and cscope."""
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
            self._index_cscope_calls(
                project_root,
                files,
                work_dir,
                cancel_check=cancel_check,
                on_stage_progress=on_stage_progress,
            )
        self._index_global_variable_references(
            source_cache,
            cancel_check=cancel_check,
            on_stage_progress=on_stage_progress,
        )

        self.db.set_metadata("indexer", INDEXER_VERSION)
        self.db.commit()

    def analyze_file(self, rel_path: str, source: bytes) -> None:
        """Index a single in-memory file.

        This compatibility path still uses ctags/cscope.  Callers that need
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
        missing = [tool for tool in ("ctags", "cscope") if shutil.which(tool) is None]
        if missing:
            raise CodeIndexToolError(
                "代码索引依赖缺失: "
                + ", ".join(missing)
                + "。请安装 Universal Ctags 和 cscope 后重新扫描。"
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

        cscope_version = subprocess.run(
            ["cscope", "-V"],
            capture_output=True,
            check=False,
        )
        if cscope_version.returncode != 0:
            raise CodeIndexToolError("cscope 不可用，请安装 cscope 后重新扫描。")

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
        self.db.insert_global_variable(
            name=name,
            file_id=file_id,
            start_line=start_line,
            end_line=end_line,
            is_extern=self._first_line(definition).lstrip().startswith("extern "),
            is_static=is_static,
            definition=definition,
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
        candidates = self._functions_by_name.get(callee_name)
        if not candidates:
            candidates = self._functions_by_short.get(self._short_name(callee_name))
        if candidates and len(candidates) == 1:
            return candidates[0].function_id
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
            r"\b" + re.escape(name) + r"\s*(?:\[.*?\]\s*)?=(?!=)"
        )
        return "write" if assignment.search(line_text) else "read"
