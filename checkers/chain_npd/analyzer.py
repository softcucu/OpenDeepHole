"""链式指针空指针解引用静态分析器 (CWE-476)。

基于 tree-sitter AST 遍历检测链式指针解引用（如 arr[i]->field、ctx->a->b->c->d）
中间层指针未判空的问题。

与已有检查器的去重策略：
- npd：只检测根指针，本检查器只报中间层复合表达式
- mp_npd：semgrep 覆盖纯 -> 二三层链，本检查器覆盖含 [] 的混合链和 4 层以上深链

每个函数最多产生 1 个 Candidate。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from code_parser.code_utils import find_nodes_by_type

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

_SKIP_VARS: frozenset[str] = frozenset({
    "this", "NULL", "nullptr", "true", "false", "void",
})

# sizeof / typeof / offsetof 等不产生实际解引用
_SIZEOF_TYPES: frozenset[str] = frozenset({
    "sizeof_expression", "alignof_expression",
})

# 判空模板 — {e} 将被替换为 re.escape(expr)，其中 -> 会被展开为允许可选空白
_CHAIN_NULL_CHECK_TEMPLATES = [
    r"if\s*\(\s*!\s*{e}\s*[)&|,]",
    r"if\s*\(\s*{e}\s*==\s*(?:NULL|nullptr|0)\s*[)&|,]",
    r"if\s*\(\s*(?:NULL|nullptr|0)\s*==\s*{e}\s*[)&|,]",
    r"if\s*\(\s*{e}\s*!=\s*(?:NULL|nullptr|0)\s*[)&|,]",
    r"assert\s*\(\s*{e}\b",
    r"assert\s*\(\s*{e}\s*!=",
    r"\bif\s*\(\s*{e}\s*\)",
    r"\bif\s*\(\s*{e}\s*&&",
    r"!\s*{e}\s*\|\|",
    r"if\s*\(\s*{e}\s*[)&|]",
]


def _normalize_expr(text: str) -> str:
    """规范化表达式文本：去除多余空白，压缩 -> 和 [] 周围空格。"""
    s = text.strip()
    s = re.sub(r"\s*->\s*", "->", s)
    s = re.sub(r"\s*\[\s*", "[", s)
    s = re.sub(r"\s*\]\s*", "]", s)
    s = re.sub(r"\s+", " ", s)
    return s


def _escape_expr_for_regex(expr: str) -> str:
    """将表达式转为正则，其中 -> 允许可选空白。"""
    escaped = re.escape(expr)
    # re.escape 会把 -> 转为 \-\>，替换为允许可选空白的模式
    escaped = escaped.replace(r"\-\>", r"\s*->\s*")
    # [] 内容也允许可选空白
    escaped = escaped.replace(r"\[", r"\s*\[\s*")
    escaped = escaped.replace(r"\]", r"\s*\]\s*")
    return escaped


def _is_inside_sizeof(node) -> bool:
    """检查节点是否在 sizeof/alignof/typeof 表达式内。"""
    parent = node.parent
    while parent is not None:
        if parent.type in _SIZEOF_TYPES:
            return True
        # typeof 在 tree-sitter 中可能表示为 type_descriptor 里的表达式
        if parent.type == "type_descriptor":
            return True
        parent = parent.parent
    return False


def _unwrap(node):
    """解包 parenthesized_expression 和 cast_expression。"""
    while node is not None:
        if node.type == "parenthesized_expression" and node.child_count > 0:
            # 取括号内的实际表达式（跳过 ( 和 )）
            for child in node.children:
                if child.type not in ("(", ")"):
                    node = child
                    break
            else:
                break
        elif node.type == "cast_expression":
            value = node.child_by_field_name("value")
            if value:
                node = value
            else:
                break
        else:
            break
    return node


def _chain_depth_and_has_subscript(node) -> tuple[int, bool]:
    """计算链的总深度和是否包含 [] 下标访问。

    深度定义：每个 -> 或 [] 操作计为一层。
    例：ctx->session->buf = 深度 2
        arr[i]->field->sub = 深度 3（1个[]，2个->）
    """
    depth = 0
    has_subscript = False
    current = node
    while current is not None:
        current = _unwrap(current)
        if current.type == "field_expression":
            op = current.child_by_field_name("operator")
            if op and op.text == b"->":
                depth += 1
                current = current.child_by_field_name("argument")
            elif op and op.text == b".":
                # . 操作不算解引用深度，但继续向下遍历
                current = current.child_by_field_name("argument")
            else:
                break
        elif current.type == "subscript_expression":
            depth += 1
            has_subscript = True
            current = current.child_by_field_name("argument")
        else:
            break
    return depth, has_subscript


def _collect_intermediate_exprs(node) -> list[tuple[str, int]]:
    """从链式解引用节点中提取需要判空的中间层子表达式。

    对 a->b->c->d：
      - a->b->c 被 -> 解引用来访问 d → 需判空
      - a->b 被 -> 解引用来访问 c → 需判空
      - a 是根指针 → 由 npd 检查器覆盖，跳过

    返回 [(expr_text, line), ...] 从外层到内层。
    """
    results: list[tuple[str, int]] = []
    current = _unwrap(node)

    while current is not None:
        if current.type == "field_expression":
            op = current.child_by_field_name("operator")
            arg = current.child_by_field_name("argument")
            if op and op.text == b"->" and arg:
                arg = _unwrap(arg)
                # arg 本身必须是链的一部分（field_expression 或 subscript_expression）
                # 才算中间层；如果 arg 是 identifier，则是根指针（npd 覆盖）
                if arg.type in ("field_expression", "subscript_expression"):
                    expr_text = _normalize_expr(
                        arg.text.decode("utf-8", errors="replace")
                    )
                    line = arg.start_point[0]
                    results.append((expr_text, line))
                current = arg
            elif op and op.text == b".":
                # . 操作不产生解引用，继续向下
                current = current.child_by_field_name("argument")
                if current:
                    current = _unwrap(current)
            else:
                break
        elif current.type == "subscript_expression":
            arg = current.child_by_field_name("argument")
            if arg:
                arg = _unwrap(arg)
                if arg.type in ("field_expression", "subscript_expression"):
                    expr_text = _normalize_expr(
                        arg.text.decode("utf-8", errors="replace")
                    )
                    line = arg.start_point[0]
                    results.append((expr_text, line))
                current = arg
            else:
                break
        else:
            break

    return results


class Analyzer(BaseAnalyzer):
    """检测链式指针解引用中间层未判空的候选。"""

    vuln_type = "chain_npd"

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
        for func_row in db.get_all_functions():
            body: str = func_row["body"] or ""
            if not body:
                continue

            func_name: str = func_row["name"]
            file_path: str = func_row["file_path"]
            start_line: int = func_row["start_line"]

            result = self._find_first_unguarded(body, start_line)
            if result is None:
                continue

            expr_text, abs_line = result
            candidates.append(
                Candidate(
                    file=file_path,
                    line=abs_line,
                    function=func_name,
                    description=(
                        f"函数 '{func_name}' 中链式指针 '{expr_text}' "
                        f"存在空指针解引用风险"
                    ),
                    vuln_type=self.vuln_type,
                )
            )

        return candidates

    def _find_first_unguarded(
        self, func_body: str, func_start_line: int
    ) -> tuple[str, int] | None:
        """在函数体中查找第一个未判空的链式中间层表达式。

        返回 (expr_text, absolute_line) 或 None。
        """
        body_bytes = func_body.encode("utf-8", errors="replace")
        tree = self._parser.parse(body_bytes)
        root = tree.root_node

        # 收集所有 field_expression (带 ->) 和 subscript_expression 作为链顶节点
        chain_tops: list = []
        for node in find_nodes_by_type(root, "field_expression"):
            op = node.child_by_field_name("operator")
            if op and op.text == b"->":
                chain_tops.append(node)
        for node in find_nodes_by_type(root, "subscript_expression"):
            chain_tops.append(node)

        # 按代码位置排序，保证先遇到的先报
        chain_tops.sort(key=lambda n: (n.start_point[0], n.start_point[1]))

        seen_exprs: set[str] = set()

        for node in chain_tops:
            if _is_inside_sizeof(node):
                continue

            # 计算整条链的深度和是否含下标
            total_depth, has_subscript = _chain_depth_and_has_subscript(node)

            # 提取中间层
            intermediates = _collect_intermediate_exprs(node)
            if not intermediates:
                continue

            for expr_text, rel_line in intermediates:
                if expr_text in seen_exprs:
                    continue
                seen_exprs.add(expr_text)

                # 根指针提取 — 跳过
                root_var = expr_text.split("->")[0].split("[")[0].strip()
                if root_var in _SKIP_VARS:
                    continue

                # 去重过滤：跳过 mp_npd 已覆盖的模式
                # mp_npd semgrep 覆盖纯 -> 二三层链（总深度 <= 3 且不含 []）
                if not has_subscript and total_depth <= 3:
                    continue

                # 检查是否有判空保护
                if self._has_null_guard_for_expr(func_body, expr_text):
                    continue

                abs_line = func_start_line + rel_line
                return (expr_text, abs_line)

        return None

    def _has_null_guard_for_expr(self, func_body: str, expr_text: str) -> bool:
        """检查函数体中是否存在对复合表达式的判空。"""
        escaped = _escape_expr_for_regex(expr_text)
        for tmpl in _CHAIN_NULL_CHECK_TEMPLATES:
            pattern = tmpl.replace("{e}", escaped)
            try:
                if re.search(pattern, func_body):
                    return True
            except re.error:
                continue
        return False
