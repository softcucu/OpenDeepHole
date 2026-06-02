"""内存泄漏静态分析器 — 检测 C/C++ 异常分支中的未释放内存。

检测规则:
  1. 错误分支 (return/goto) 前未释放，但函数其他路径释放了
  2. 循环中 continue 前未释放，但非 continue 路径释放了

设计原则: 召回优先（precision 可放低），报告作为 LLM 复审的输入。

移植自独立脚本 c_memleak_scanner.py，适配 BaseAnalyzer 接口。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# ============================================================
# 释放函数识别
# ============================================================

_FREE_KEYWORDS = [
    "free", "release", "destroy", "cleanup", "clean_up", "clean",
    "clear", "reset", "unref", "dispose", "deinit", "finalize",
    "fini", "close",
]


def _build_keyword_regex(keyword: str) -> re.Pattern:
    pattern = (
        r"(?:^|_|(?<=[a-z]))"
        + f"(?i:{keyword})"
        + r"(?=$|_|[A-Z])"
    )
    return re.compile(pattern)


FREE_FUNC_PATTERNS = [_build_keyword_regex(k) for k in _FREE_KEYWORDS] + [
    re.compile(r"^put_[A-Za-z0-9_]+$"),
]


def is_free_func(name: str) -> bool:
    if not name:
        return False
    return any(p.search(name) for p in FREE_FUNC_PATTERNS)


# ============================================================
# NULL 常量识别
# ============================================================

_NULL_KEYWORDS = ["null", "nil"]


def _build_null_regex() -> re.Pattern:
    parts = []
    for kw in _NULL_KEYWORDS:
        parts.append(
            r"(?:^|_|(?<=[a-z]))"
            + f"(?i:{kw})"
            + r"(?=$|_|[A-Z])"
        )
    return re.compile("|".join(parts))


_NULL_PATTERN = _build_null_regex()


def is_null_literal(text: str) -> bool:
    if not text:
        return False
    t = text.strip()
    if t in ("0", "0L", "0l", "0UL", "0ul", "nullptr", "NULL"):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", t) and _NULL_PATTERN.search(t):
        return True
    return False


# ============================================================
# 内部数据结构
# ============================================================

@dataclass
class FreeSite:
    var_name: str
    raw_arg: str
    func_name: str
    node: object
    line: int
    is_noarg: bool = False


@dataclass
class Issue:
    kind: str
    func: str
    func_start_line: int
    line: int
    leaked: list
    free_lines: dict
    hint: str
    free_func_names: set = field(default_factory=set)


@dataclass
class PathState:
    freed: set[str] = field(default_factory=set)
    transferred: set[str] = field(default_factory=set)
    null_vars: set[str] = field(default_factory=set)
    non_null_vars: set[str] = field(default_factory=set)

    def copy(self) -> "PathState":
        return PathState(
            freed=set(self.freed),
            transferred=set(self.transferred),
            null_vars=set(self.null_vars),
            non_null_vars=set(self.non_null_vars),
        )


# ============================================================
# 核心检测器
# ============================================================

class MemLeakDetector:
    def __init__(self, source: bytes):
        self.source = source
        self.parser = tree_sitter.Parser(_CPP_LANGUAGE)
        self.tree = self.parser.parse(source)
        self.issues: list[Issue] = []
        self._issue_keys: set[tuple] = set()

    def text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte].decode("utf8", "replace")

    def line(self, node) -> int:
        return node.start_point[0] + 1

    def walk(self, node, visit):
        if visit(node) is False:
            return
        for child in node.children:
            self.walk(child, visit)

    @staticmethod
    def _normalize_arg(raw: str) -> str:
        s = raw.strip()
        while True:
            prev = s
            if s.startswith("&") or s.startswith("*"):
                s = s[1:].lstrip()
                continue
            m = re.match(r"^\(\s*[^()]+?\s*\)\s*(.+)$", s)
            if m:
                s = m.group(1).strip()
                continue
            if s == prev:
                break
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[.*\]$", s)
        if m:
            s = m.group(1)
        return s

    @staticmethod
    def _base_var(raw: str) -> str:
        s = MemLeakDetector._normalize_arg(raw)
        return re.split(r"\s*(?:->|\.)\s*", s, maxsplit=1)[0].strip()

    @staticmethod
    def _contains_identifier(text: str, name: str) -> bool:
        return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text))

    def _identifier_texts(self, node) -> list[str]:
        result: list[str] = []

        def visit(n):
            if n.type in ("identifier", "field_identifier"):
                result.append(self.text(n))
            return True

        self.walk(node, visit)
        return result

    # ---------- 释放调用识别 ----------

    def _extract_callee_name(self, func_node):
        if func_node.type == "identifier":
            return self.text(func_node)
        if func_node.type == "qualified_identifier":
            name_node = func_node.child_by_field_name("name")
            if name_node is not None:
                return self._extract_callee_name(name_node)
        if func_node.type == "field_expression":
            field = func_node.child_by_field_name("field")
            if field is not None:
                return self.text(field)
        if func_node.type == "template_function":
            name = func_node.child_by_field_name("name")
            if name is not None:
                return self._extract_callee_name(name)
        return None

    def as_free_site(self, node):
        if node.type != "call_expression":
            return None
        func_node = node.child_by_field_name("function")
        if func_node is None:
            return None
        fname = self._extract_callee_name(func_node)
        if not fname or not is_free_func(fname):
            return None
        args = node.child_by_field_name("arguments")
        if args is None:
            return None

        raw_arg = None
        for c in args.children:
            if c.type in ("(", ")", ","):
                continue
            raw_arg = self.text(c).strip()
            break

        if not raw_arg:
            return FreeSite(
                var_name=f"<no-arg>:{fname}",
                raw_arg="",
                func_name=fname,
                node=node, line=self.line(node),
                is_noarg=True,
            )

        return FreeSite(
            var_name=self._normalize_arg(raw_arg),
            raw_arg=raw_arg,
            func_name=fname,
            node=node, line=self.line(node),
            is_noarg=False,
        )

    # ---------- 判空分支分析 ----------

    def _parse_null_check(self, cond_node):
        if cond_node is None:
            return None
        node = self._unwrap_parens(cond_node)

        if node.type == "binary_expression":
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op_node is None or left is None or right is None:
                return None
            op = self.text(op_node)
            if op not in ("==", "!="):
                return None
            left_txt = self.text(self._unwrap_parens(left)).strip()
            right_txt = self.text(self._unwrap_parens(right)).strip()
            left_is_null = is_null_literal(left_txt) or bool(_NULL_PATTERN.search(left_txt))
            right_is_null = is_null_literal(right_txt) or bool(_NULL_PATTERN.search(right_txt))
            if left_is_null and not right_is_null:
                var = self._normalize_arg(right_txt)
                if not var:
                    return None
                return (var, op == "==")
            if right_is_null and not left_is_null:
                var = self._normalize_arg(left_txt)
                if not var:
                    return None
                return (var, op == "==")
            return None

        if node.type == "unary_expression":
            op_node = node.child_by_field_name("operator")
            arg = node.child_by_field_name("argument")
            if op_node is not None and arg is not None and self.text(op_node) == "!":
                arg_txt = self.text(self._unwrap_parens(arg)).strip()
                var = self._normalize_arg(arg_txt)
                if var:
                    return (var, True)
            return None

        if node.type in ("identifier", "field_expression", "pointer_expression",
                         "subscript_expression"):
            txt = self.text(node).strip()
            if txt.startswith("&"):
                return None
            var = self._normalize_arg(txt)
            if var:
                return (var, False)

        return None

    def _unwrap_parens(self, node):
        wrapper_types = {"parenthesized_expression", "condition_clause"}
        while node is not None and node.type in wrapper_types:
            inner = None
            for c in node.children:
                if c.type not in ("(", ")"):
                    inner = c
                    break
            if inner is None:
                break
            node = inner
        return node

    def _is_dead_null_free(self, free_site) -> bool:
        if free_site.is_noarg:
            return False
        var = free_site.var_name

        cur = free_site.node
        while cur is not None and cur.parent is not None:
            parent = cur.parent
            if parent.type == "if_statement":
                cond = parent.child_by_field_name("condition")
                consequence = parent.child_by_field_name("consequence")
                alternative = parent.child_by_field_name("alternative")
                parsed = self._parse_null_check(cond)
                if parsed is not None:
                    checked_var, then_is_null = parsed
                    if checked_var == var:
                        if consequence is not None and self._contains(consequence, free_site.node):
                            if then_is_null:
                                return True
                        elif alternative is not None and self._contains(alternative, free_site.node):
                            if not then_is_null:
                                return True
            cur = parent
        return False

    def _contains(self, ancestor, descendant) -> bool:
        n = descendant
        while n is not None:
            if n == ancestor:
                return True
            n = n.parent
        return False

    # ---------- 收集释放 / 函数 / 参数 ----------

    def collect_frees_in(self, scope_node, skip_types=None):
        frees: list[FreeSite] = []
        skip = skip_types or set()

        def visit(n):
            if n is not scope_node and n.type in skip:
                return False
            fs = self.as_free_site(n)
            if fs and not self._is_dead_null_free(fs):
                frees.append(fs)
            return True

        self.walk(scope_node, visit)
        return frees

    def find_functions(self):
        funcs = []

        def visit(n):
            if n.type == "function_definition":
                funcs.append(n)
            return True

        self.walk(self.tree.root_node, visit)
        return funcs

    def function_name(self, func_node) -> str:
        decl = func_node.child_by_field_name("declarator")
        result = {"name": "<anon>"}

        def visit(n):
            if n.type in ("identifier", "field_identifier",
                          "qualified_identifier", "destructor_name",
                          "operator_name"):
                if result["name"] == "<anon>":
                    result["name"] = self.text(n).replace("\n", " ")
                    return False
            return True

        if decl:
            self.walk(decl, visit)
        return result["name"]

    def function_params(self, func_node) -> set[str]:
        decl = func_node.child_by_field_name("declarator")
        params = set()
        if decl is None:
            return params

        def visit(n):
            if n.type == "parameter_declaration":
                names = self._identifier_texts(n)
                if names:
                    params.add(names[-1])
                return False
            return True

        self.walk(decl, visit)
        return params

    @staticmethod
    def _display_name(var_name: str) -> str:
        if var_name.startswith("<no-arg>:"):
            return var_name[len("<no-arg>:"):] + "()"
        return var_name

    def _block_children(self, node) -> list:
        if node is None:
            return []
        return [c for c in node.children if c.type not in {"{", "}", ";"}]

    def _else_body(self, if_node):
        alternative = if_node.child_by_field_name("alternative")
        if alternative is None:
            return None
        if alternative.type == "else_clause":
            children = [c for c in alternative.children if c.type != "else"]
            return children[0] if children else None
        return alternative

    def _return_value_vars(self, exit_node) -> set:
        result: set = set()
        if exit_node.type != "return_statement":
            return result
        for c in exit_node.children:
            if c.type in ("return", ";"):
                continue
            txt = self.text(c).strip()
            if not txt:
                continue
            norm = self._normalize_arg(txt)
            if norm and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", norm):
                result.add(norm)
        return result

    def _apply_statement_effects(
        self,
        node,
        state: PathState,
        resource_vars: set[str],
        params: set[str],
    ) -> PathState:
        next_state = state.copy()

        def visit(n):
            fs = self.as_free_site(n)
            if fs and not self._is_dead_null_free(fs):
                next_state.freed.add(fs.var_name)
                next_state.transferred.discard(fs.var_name)
                return False

            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and right is not None:
                    left_txt = self.text(left).strip()
                    right_txt = self.text(right).strip()
                    for var in resource_vars:
                        if var in right_txt and any(
                            self._contains_identifier(left_txt, param)
                            for param in params
                        ):
                            next_state.transferred.add(var)
                            next_state.freed.discard(var)
            return True

        self.walk(node, visit)
        return next_state

    def _apply_null_fact(
        self,
        state: PathState,
        var: str,
        is_null: bool,
    ) -> PathState:
        next_state = state.copy()
        if is_null:
            next_state.null_vars.add(var)
            next_state.non_null_vars.discard(var)
        else:
            next_state.non_null_vars.add(var)
            next_state.null_vars.discard(var)
        return next_state

    def _is_null_for(self, var: str, state: PathState) -> bool:
        return var in state.null_vars or self._base_var(var) in state.null_vars

    def _record_exit_issue(
        self,
        *,
        kind: str,
        exit_node,
        state: PathState,
        resource_vars: set[str],
        all_frees: list[FreeSite],
        func_name: str,
        func_start_line: int,
    ) -> None:
        missing = set(resource_vars) - state.freed - state.transferred
        missing = {v for v in missing if not self._is_null_for(v, state)}

        if exit_node.type == "return_statement":
            missing -= self._return_value_vars(exit_node)

        if not missing:
            return

        details = []
        free_funcs = set()
        for var in sorted(missing):
            matching_frees = [f for f in all_frees if f.var_name == var]
            free_lines = sorted({f.line for f in matching_frees})
            if not free_lines:
                continue
            free_funcs.update(f.func_name for f in matching_frees)
            details.append((var, free_lines))

        if not details:
            return

        key = (
            kind,
            self.line(exit_node),
            tuple((var, tuple(lines)) for var, lines in details),
        )
        if key in self._issue_keys:
            return
        self._issue_keys.add(key)

        if kind == "continue_leak":
            prefix = "循环中 continue 前未释放"
        else:
            exit_kind = {
                "return_statement": "return",
                "goto_statement": "goto",
            }.get(exit_node.type, "退出点")
            prefix = f"{exit_kind} 前未释放"

        hint = "; ".join(
            f"{self._display_name(var)}（其他路径在第 {lines} 行释放）"
            for var, lines in details
        )
        self.issues.append(Issue(
            kind=kind,
            func=func_name,
            func_start_line=func_start_line,
            line=self.line(exit_node),
            leaked=[self._display_name(var) for var, _ in details],
            free_lines={self._display_name(var): lines for var, lines in details},
            hint=f"{prefix}: {hint}",
            free_func_names=free_funcs,
        ))

    def _analyze_statement(
        self,
        node,
        states: list[PathState],
        *,
        resource_vars: set[str],
        all_frees: list[FreeSite],
        params: set[str],
        func_name: str,
        func_start_line: int,
        in_loop: bool,
    ) -> list[PathState]:
        if not states:
            return []
        if node.type in {"comment", "{", "}", ";"}:
            return states

        if node.type == "compound_statement":
            return self._analyze_statements(
                self._block_children(node),
                states,
                resource_vars=resource_vars,
                all_frees=all_frees,
                params=params,
                func_name=func_name,
                func_start_line=func_start_line,
                in_loop=in_loop,
            )

        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = self._else_body(node)
            parsed = self._parse_null_check(cond)
            then_states: list[PathState] = []
            else_states: list[PathState] = []
            for state in states:
                if parsed is None:
                    then_states.append(state.copy())
                    else_states.append(state.copy())
                    continue
                checked_var, then_is_null = parsed
                then_states.append(self._apply_null_fact(state, checked_var, then_is_null))
                else_states.append(self._apply_null_fact(state, checked_var, not then_is_null))

            after_then = self._analyze_statement(
                consequence,
                then_states,
                resource_vars=resource_vars,
                all_frees=all_frees,
                params=params,
                func_name=func_name,
                func_start_line=func_start_line,
                in_loop=in_loop,
            ) if consequence is not None else then_states

            after_else = self._analyze_statement(
                alternative,
                else_states,
                resource_vars=resource_vars,
                all_frees=all_frees,
                params=params,
                func_name=func_name,
                func_start_line=func_start_line,
                in_loop=in_loop,
            ) if alternative is not None else else_states

            return after_then + after_else

        if node.type in {"for_statement", "while_statement", "do_statement", "for_range_loop"}:
            loop_body = node.child_by_field_name("body") or node
            loop_input = [state.copy() for state in states]
            self._analyze_statement(
                loop_body,
                loop_input,
                resource_vars=resource_vars,
                all_frees=all_frees,
                params=params,
                func_name=func_name,
                func_start_line=func_start_line,
                in_loop=True,
            )
            after_states = [state.copy() for state in states]
            loop_frees = self.collect_frees_in(
                loop_body,
                skip_types={"function_definition", "lambda_expression"},
            )
            for state in after_states:
                for free_site in loop_frees:
                    state.freed.add(free_site.var_name)
            return after_states

        if node.type in {"return_statement", "goto_statement"}:
            for state in states:
                self._record_exit_issue(
                    kind="error_path_leak",
                    exit_node=node,
                    state=state,
                    resource_vars=resource_vars,
                    all_frees=all_frees,
                    func_name=func_name,
                    func_start_line=func_start_line,
                )
            return []

        if node.type == "continue_statement":
            if in_loop:
                for state in states:
                    self._record_exit_issue(
                        kind="continue_leak",
                        exit_node=node,
                        state=state,
                        resource_vars=resource_vars,
                        all_frees=all_frees,
                        func_name=func_name,
                        func_start_line=func_start_line,
                    )
            return []

        return [
            self._apply_statement_effects(node, state, resource_vars, params)
            for state in states
        ]

    def _analyze_statements(
        self,
        statements: list,
        states: list[PathState],
        *,
        resource_vars: set[str],
        all_frees: list[FreeSite],
        params: set[str],
        func_name: str,
        func_start_line: int,
        in_loop: bool,
    ) -> list[PathState]:
        current = states
        for stmt in statements:
            current = self._analyze_statement(
                stmt,
                current,
                resource_vars=resource_vars,
                all_frees=all_frees,
                params=params,
                func_name=func_name,
                func_start_line=func_start_line,
                in_loop=in_loop,
            )
            if not current:
                break
        return current

    # ============================================================
    # 路径敏感规则: return / goto / continue 前未释放
    # ============================================================
    def check_function(self, func_node):
        body = func_node.child_by_field_name("body")
        if body is None:
            return
        all_frees = self.collect_frees_in(
            body, skip_types={"function_definition", "lambda_expression"}
        )
        if not all_frees:
            return

        fname = self.function_name(func_node)
        func_start_line = self.line(func_node)
        params = self.function_params(func_node)
        initial = PathState()
        self._analyze_statement(
            body,
            [initial],
            resource_vars={f.var_name for f in all_frees},
            all_frees=all_frees,
            params=params,
            func_name=fname,
            func_start_line=func_start_line,
            in_loop=False,
        )

    def run(self) -> list[Issue]:
        for func in self.find_functions():
            self.check_function(func)
        self.issues.sort(key=lambda x: (x.line, x.kind))
        return self.issues


# ============================================================
# 文件收集
# ============================================================

_SOURCE_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}


_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "third_party", "3rdparty", "thirdparty",
    "external", "extern", "deps",
    "build", "cmake-build-debug", "cmake-build-release",
    "out", "output", "_build", ".build",
    "__pycache__", ".venv", "venv",
}


def _collect_source_files(root: Path) -> list[Path]:
    import os
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in _SOURCE_EXTS:
                files.append(Path(dirpath) / fname)
    return sorted(files)


# ============================================================
# Analyzer — BaseAnalyzer 实现
# ============================================================

KIND_DESC = {
    "error_path_leak": "异常分支 (return/goto) 前未释放",
    "continue_leak": "循环中 continue 前未释放",
}


class Analyzer(BaseAnalyzer):
    """C/C++ 异常分支内存泄漏检测器。"""

    vuln_type = "memleak"

    def __init__(self) -> None:
        self.on_file_progress: Callable[[int, int], None] | None = None

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        """逐文件扫描，按函数合并后 yield 候选漏洞点。"""
        files = _collect_source_files(project_path)
        total = len(files)

        for idx, file_path in enumerate(files, 1):
            if self.on_file_progress and (idx % 20 == 0 or idx == total or idx == 1):
                self.on_file_progress(idx, total)

            try:
                raw = file_path.read_bytes()
            except Exception:
                continue

            try:
                detector = MemLeakDetector(raw)
                issues = detector.run()
            except Exception:
                continue

            if not issues:
                continue

            # 将相对路径作为 file 字段
            try:
                rel_path = str(file_path.relative_to(project_path))
            except ValueError:
                rel_path = str(file_path)

            groups: dict[tuple[str, int], list[Issue]] = {}
            for issue in issues:
                key = (issue.func, issue.func_start_line)
                groups.setdefault(key, []).append(issue)

            for (_func, _start_line), group in groups.items():
                group.sort(key=lambda item: (item.line, item.kind))
                first = group[0]
                related_functions = sorted({
                    name
                    for issue in group
                    for name in issue.free_func_names
                })

                detail_lines = []
                for index, issue in enumerate(group, 1):
                    kind_desc = KIND_DESC.get(issue.kind, issue.kind)
                    leaked_str = ", ".join(issue.leaked)
                    detail_lines.append(
                        f"{index}. 第 {issue.line} 行 [{kind_desc}] "
                        f"变量 {leaked_str} 在退出点前未释放。{issue.hint}"
                    )

                yield Candidate(
                    file=rel_path,
                    line=first.line,
                    function=first.func,
                    description=(
                        f"函数 '{first.func}' 中发现 {len(group)} 个疑似内存泄漏点，"
                        "请在一次审计中统一判断并只提交一个结果。\n"
                        + "\n".join(detail_lines)
                    ),
                    vuln_type="memleak",
                    related_functions=related_functions,
                )
