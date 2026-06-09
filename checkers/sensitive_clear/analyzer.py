"""敏感信息未清零检测 — 分组静态分析器。

本分析器只枚举函数名与变量名，不做敏感关键词或清零启发式过滤。
按函数长度将 10-20 个函数组成一个审计分组，每组交由一次 Agent 调用处理。
"""

from __future__ import annotations

from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from code_parser.code_utils import find_nodes_by_type

CPP_LANGUAGE = Language(tree_sitter_cpp.language())

TARGET_GROUP_LINES = 800
MAX_GROUP_LINES = 1200
MIN_FUNCTIONS_PER_GROUP = 10
MAX_FUNCTIONS_PER_GROUP = 20


def _node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _identifier_name(node) -> str:
    ids = find_nodes_by_type(node, "identifier")
    if not ids:
        return ""
    return _node_text(ids[-1]).strip()


def _declarator_name(node) -> str:
    ids = find_nodes_by_type(node, "identifier")
    if not ids:
        return ""
    return _node_text(ids[0]).strip()


def _extract_parameters(root) -> list[dict]:
    variables: list[dict] = []
    for node_type in ("parameter_declaration", "optional_parameter_declaration"):
        for param in find_nodes_by_type(root, node_type):
            name = _identifier_name(param)
            if not name:
                continue
            variables.append(
                {
                    "name": name,
                    "kind": "parameter",
                    "line": param.start_point[0] + 1,
                }
            )
    return variables


def _extract_local_variables(root) -> list[dict]:
    variables: list[dict] = []
    for decl in find_nodes_by_type(root, "declaration"):
        if any(c.type == "function_declarator" for c in decl.children):
            continue
        for child in decl.children:
            if child.type in {
                "init_declarator",
                "pointer_declarator",
                "array_declarator",
                "reference_declarator",
                "identifier",
            }:
                name = _declarator_name(child)
                if not name:
                    continue
                variables.append(
                    {
                        "name": name,
                        "kind": "local",
                        "line": child.start_point[0] + 1,
                    }
                )

    for decl in find_nodes_by_type(root, "for_range_declaration"):
        name = _identifier_name(decl)
        if name:
            variables.append(
                {
                    "name": name,
                    "kind": "local",
                    "line": decl.start_point[0] + 1,
                }
            )
    return variables


def _extract_variables(body_source: str) -> list[dict]:
    parser = Parser(CPP_LANGUAGE)
    tree = parser.parse(body_source.encode("utf-8"))
    root = tree.root_node

    variables: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in _extract_parameters(root) + _extract_local_variables(root):
        key = (item["kind"], item["name"])
        if key in seen:
            continue
        seen.add(key)
        variables.append(item)
    return variables


def _row_value(row, key: str, default=None):
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        value = getattr(row, key, default)
    return default if value is None else value


def _function_line_count(func: dict) -> int:
    try:
        start = int(_row_value(func, "start_line", 0) or 0)
        end = int(_row_value(func, "end_line", start) or start)
    except (TypeError, ValueError):
        body = str(_row_value(func, "body", "") or "")
        return max(1, body.count("\n") + 1)
    return max(1, end - start + 1)


def _should_flush_group(group: list[dict], next_func: dict) -> bool:
    if not group:
        return False
    group_lines = sum(int(item["line_count"]) for item in group)
    next_lines = int(next_func["line_count"])
    if len(group) >= MAX_FUNCTIONS_PER_GROUP:
        return True
    if len(group) >= MIN_FUNCTIONS_PER_GROUP and group_lines + next_lines > TARGET_GROUP_LINES:
        return True
    if group_lines + next_lines > MAX_GROUP_LINES:
        return True
    return False


def _build_group_candidate(group: list[dict], group_index: int) -> Candidate:
    first = group[0]
    group_id = f"sensitive-clear-group-{group_index:04d}"
    pairs: list[dict] = []
    functions: list[dict] = []
    for func_idx, func in enumerate(group, 1):
        functions.append(
            {
                "function_name": func["function_name"],
                "file": func["file"],
                "start_line": func["start_line"],
                "end_line": func["end_line"],
                "line_count": func["line_count"],
            }
        )
        for var_idx, variable in enumerate(func["variables"], 1):
            pair_id = f"{group_id}-f{func_idx:02d}-v{var_idx:03d}"
            pairs.append(
                {
                    "pair_id": pair_id,
                    "function_name": func["function_name"],
                    "variable_name": variable["name"],
                    "variable_kind": variable["kind"],
                    "file": func["file"],
                    "function_start_line": func["start_line"],
                    "variable_line": variable["line"],
                }
            )

    metadata = {
        "kind": "sensitive_clear_group",
        "group_id": group_id,
        "functions": functions,
        "pairs": pairs,
    }
    description = (
        f"敏感信息未清零分组审计 {group_id}: "
        f"{len(functions)} 个函数, {len(pairs)} 个变量。"
    )
    return Candidate(
        file=str(first["file"]),
        line=int(first["start_line"]),
        function="__project__",
        description=description,
        vuln_type="sensitive_clear",
        metadata=metadata,
    )


class Analyzer(BaseAnalyzer):
    """按函数组生成敏感信息未清零审计候选。"""

    vuln_type = "sensitive_clear"

    def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        functions = db.get_all_functions()
        group: list[dict] = []
        group_index = 1

        total = len(functions)
        for idx, func in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)

            body = func["body"] or ""
            if not body:
                continue

            variables = _extract_variables(body)
            if not variables:
                continue

            item = {
                "function_name": func["name"],
                "file": func["file_path"],
                "start_line": int(func["start_line"]),
                "end_line": int(func["end_line"]),
                "line_count": _function_line_count(func),
                "variables": variables,
            }
            if _should_flush_group(group, item):
                candidates.append(_build_group_candidate(group, group_index))
                group_index += 1
                group = []
            group.append(item)

        if group:
            candidates.append(_build_group_candidate(group, group_index))

        return candidates
