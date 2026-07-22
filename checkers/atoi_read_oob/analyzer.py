"""atoi read-OOB static analyzer.

Finds direct ``atoi`` call sites and lets the AI audit whether the argument can
make ``atoi`` read past the valid buffer before it reaches a NUL byte.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate, scoped_functions
from code_parser.code_utils import find_nodes_by_type

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())


def _node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()


def _callee_text(call_node: Node, source: bytes) -> str:
    return _node_text(call_node.child_by_field_name("function"), source)


def _is_atoi_callee(callee: str) -> bool:
    compact = "".join(callee.split())
    if compact == "atoi":
        return True
    if compact in {"::atoi", "std::atoi"}:
        return True
    return compact.endswith("::atoi") and "." not in compact and "->" not in compact


def _argument_texts(call_node: Node, source: bytes) -> list[str]:
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [
        _node_text(child, source)
        for child in args_node.named_children
        if _node_text(child, source)
    ]


def _first_line(text: str) -> str:
    return text.splitlines()[0].strip() if text else ""


class Analyzer(BaseAnalyzer):
    """Find ``atoi`` calls as candidates for AI read-boundary analysis."""

    vuln_type = "atoi_read_oob"

    def __init__(self) -> None:
        self._parser = Parser(_CPP_LANGUAGE)

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        seen: set[tuple[str, int, int, str]] = set()
        functions = scoped_functions(db, project_path)
        total = len(functions)

        for idx, func_row in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)

            body = str(func_row["body"] or "")
            if not body:
                continue

            source = body.encode("utf-8", errors="replace")
            tree = self._parser.parse(source)
            func_name = str(func_row["name"] or "unknown")
            file_path = str(func_row["file_path"] or "")
            start_line = int(func_row["start_line"] or 1)

            for call_node in find_nodes_by_type(tree.root_node, "call_expression"):
                callee = _callee_text(call_node, source)
                if not _is_atoi_callee(callee):
                    continue

                call_line = start_line + call_node.start_point[0]
                call_column = call_node.start_point[1]
                args = _argument_texts(call_node, source)
                arg_expr = args[0] if args else ""
                key = (file_path, call_line, call_column, arg_expr)
                if key in seen:
                    continue
                seen.add(key)

                call_expr = _node_text(call_node, source)
                call_summary = _first_line(call_expr)
                subject = arg_expr or call_summary or "atoi 参数"
                details = [
                    f"调用表达式: {call_summary or 'atoi(...)'}",
                ]
                if arg_expr:
                    details.append(f"参数表达式: {arg_expr}")

                candidates.append(
                    Candidate(
                        file=file_path,
                        line=call_line,
                        function=func_name,
                        description=(
                            f"函数 `{func_name}` 中 `atoi` 调用读取参数 `{subject}` "
                            f"是否存在读越界问题，请审计确认。\n"
                            "相关线索：\n"
                            + "\n".join(details)
                            + "\n审计要点：确认参数指针是否可达、是否指向有效内存，"
                            "以及从该位置开始是否保证在合法边界内遇到 NUL 终止符。"
                        ),
                        vuln_type=self.vuln_type,
                        metadata={
                            "subject": subject,
                            "problem": "atoi 参数读越界",
                            "call": call_summary,
                            "argument": arg_expr,
                        },
                    )
                )

        return candidates
