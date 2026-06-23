"""NPD (Null Pointer Dereference) static analyzer.

Logic:
1. For each indexed function, parse the body with tree-sitter.
2. Collect every pointer variable that is dereferenced via:
     ptr->field   *ptr   *(ptr +/- x)   ptr[i]
   plus g_xxx identifiers used as function pointers (call_expression where
   the callee name starts with g_ and is not a known function).
3. Filter out variables that already have a null-guard in the function body.
4. Emit one Candidate per unguarded (function, variable) pair, with enough
   context for the AI skill to make the final verdict.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from code_parser.code_utils import (
    find_nodes_by_type,
    get_child_node_by_type,
)

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# Null-guard patterns for a variable named VAR
_NULL_CHECK_TEMPLATES = [
    r"if\s*\(\s*!\s*{v}\b",                                  # if (!ptr)
    r"if\s*\(\s*{v}\s*==\s*(?:NULL|nullptr|0)\s*[)&|]",      # if (ptr == NULL)
    r"if\s*\(\s*(?:NULL|nullptr|0)\s*==\s*{v}\b",             # if (NULL == ptr)
    r"if\s*\(\s*{v}\s*!=\s*(?:NULL|nullptr|0)\s*[)&|]",       # if (ptr != NULL)
    r"assert\s*\(\s*{v}\b",                                   # assert(ptr)
    r"assert\s*\(\s*{v}\s*!=",                                # assert(ptr != NULL)
    r"\bif\s*\(\s*{v}\s*\)",                                  # if (ptr)
]

# Variables that are almost never actual pointers we care about
_SKIP_VARS: frozenset[str] = frozenset({
    "this", "NULL", "nullptr", "true", "false", "void",
})


class Analyzer(BaseAnalyzer):
    """Find unguarded pointer dereferences as NPD candidates."""

    vuln_type = "npd"

    def __init__(self) -> None:
        self._parser = Parser(_CPP_LANGUAGE)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        for func_row in db.get_all_functions():
            body: str = func_row["body"] or ""
            if not body:
                continue

            func_name: str = func_row["name"]
            file_path: str = func_row["file_path"]
            start_line: int = func_row["start_line"]

            deref_vars = self._find_dereferenced_pointers(body.encode("utf-8", errors="replace"), db)
            for var_name in deref_vars:
                if self._has_null_guard(body, var_name):
                    continue
                deref_line = self._first_deref_line(body, var_name, start_line)
                candidates.append(
                    Candidate(
                        file=file_path,
                        line=deref_line,
                        function=func_name,
                        description=(
                            f"函数 `{func_name}` 中指针变量 `{var_name}` 是否存在"
                            f"空指针解引用问题，请审计确认。\n"
                            f"相关线索：指针变量 `{var_name}` 在该函数中被解引用。"
                        ),
                        vuln_type="npd",
                    )
                )
        return candidates

    # ------------------------------------------------------------------
    # Dereference extraction (mirrors the reference script's logic)
    # ------------------------------------------------------------------

    def _find_dereferenced_pointers(
        self, func_body: bytes, db: "CodeDatabase"
    ) -> list[str]:
        """Return sorted unique list of pointer variable names dereferenced in func_body."""
        tree = self._parser.parse(func_body)
        root = tree.root_node
        names: list[str] = []

        # ptr->field
        for node in find_nodes_by_type(root, "field_expression"):
            arg = node.child_by_field_name("argument")
            op = node.child_by_field_name("operator")
            if op and op.text == b"->" and arg:
                names.append(arg.text.decode("utf-8", errors="replace"))

        # *ptr  /  *(ptr +/- x)
        for node in find_nodes_by_type(root, "pointer_expression"):
            text = node.text.decode("utf-8", errors="replace").strip()
            if not text.startswith("*"):
                continue  # skip & (address-of)
            arg = node.child_by_field_name("argument")
            if arg is None:
                continue
            if arg.type == "identifier":
                names.append(arg.text.decode("utf-8", errors="replace"))
            elif arg.type == "parenthesized_expression":
                # *(ptr)
                id_node = get_child_node_by_type(arg, ["identifier"])
                if id_node:
                    names.append(id_node.text.decode("utf-8", errors="replace"))
                # *(ptr +/- x)  or  *(x +/- ptr)
                bin_node = get_child_node_by_type(arg, ["binary_expression"])
                if bin_node:
                    for field in ("left", "right"):
                        side = bin_node.child_by_field_name(field)
                        if side and side.type == "identifier":
                            names.append(side.text.decode("utf-8", errors="replace"))

        # ptr[i]
        for node in find_nodes_by_type(root, "subscript_expression"):
            arg = node.child_by_field_name("argument")
            if arg:
                names.append(arg.text.decode("utf-8", errors="replace"))

        # g_xxx used as a function pointer (call_expression where callee is not a known function)
        for node in find_nodes_by_type(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if func_node is None:
                continue
            callee = func_node.text.decode("utf-8", errors="replace").strip()
            # strip member access qualifiers
            base = callee.split("->")[-1].split(".")[-1].split("::")[-1]
            if base.startswith("g_") and len(db.get_functions_by_name(base)) == 0:
                names.append(base)

        # Clean up: drop empty strings and obvious non-pointer keywords
        cleaned = [
            n.strip() for n in names
            if n.strip() and n.strip() not in _SKIP_VARS
        ]
        return sorted(set(cleaned))

    # ------------------------------------------------------------------
    # Null-guard detection
    # ------------------------------------------------------------------

    def _has_null_guard(self, func_body: str, var_name: str) -> bool:
        """Return True if func_body contains a null-check for var_name."""
        v = re.escape(var_name)
        for tmpl in _NULL_CHECK_TEMPLATES:
            pattern = tmpl.replace("{v}", v)
            if re.search(pattern, func_body):
                return True
        return False

    # ------------------------------------------------------------------
    # Line-number helper
    # ------------------------------------------------------------------

    def _first_deref_line(
        self, func_body: str, var_name: str, func_start_line: int
    ) -> int:
        """Return absolute line number of the first dereference of var_name."""
        v = re.escape(var_name)
        patterns = [
            rf"{v}\s*->",    # ptr->
            rf"\*\s*{v}\b",  # *ptr
            rf"{v}\s*\[",    # ptr[
            rf"\b{v}\s*\(",  # g_fp(
        ]
        for i, line in enumerate(func_body.splitlines()):
            for p in patterns:
                if re.search(p, line):
                    return func_start_line + i
        return func_start_line
