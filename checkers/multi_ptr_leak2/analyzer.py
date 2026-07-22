"""Static pre-filter for outer-pointer-only release candidates.

The checker looks for release/free call sites where the released argument is a
struct/class/union object with pointer fields.  Ownership is left to the
opencode skill because static filtering cannot prove it reliably.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Iterator

import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate, in_scope as _in_scope, scope_prefix as _scope_prefix
from deephole_client.static_analysis.source_filter import iter_source_files

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

_C_CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    "vendor",
    "third_party",
    "3rdparty",
    "thirdparty",
    "external",
    "extern",
    "deps",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "out",
    "output",
    "_build",
    ".build",
    ".venv",
    "venv",
}

# 与 checkers/memleak/analyzer.py 保持一致；C++ `delete` / `delete[]` 由
# tree-sitter 的 `delete_expression` 路径单独处理，不出现在此关键字列表里。
_FREE_KEYWORDS = [
    "free",
    "release",
    "destroy",
    "cleanup",
    "clean_up",
    "clean",
    "clear",
    "reset",
    "unref",
    "dispose",
    "deinit",
    "finalize",
    "fini",
    "close",
]


def _build_keyword_regex(keyword: str) -> re.Pattern[str]:
    return re.compile(
        r"(?:^|_|(?<=[a-z]))" + f"(?i:{keyword})" + r"(?=$|_|[A-Z])"
    )


_KEYWORD_REGEXES = {keyword: _build_keyword_regex(keyword) for keyword in _FREE_KEYWORDS}
_PUT_PREFIX_RE = re.compile(r"^put_[A-Za-z0-9_]+$")
_FREE_FUNC_PATTERNS = list(_KEYWORD_REGEXES.values()) + [_PUT_PREFIX_RE]

# 解析前的廉价文本预筛：函数体若不含任一释放语义 token（释放关键字 / `delete`
# / `put_`），就不可能命中 release site，直接跳过 tree-sitter 解析。
# 召回安全性：任何 release site 都要求 callee 短名属于 release_func_names
# （其非标准成员必经 `_is_free_func`，即含关键字）、或标准 free（含 "free"）、
# 或 method 释放（名字含关键字/前缀）、或 delete_expression（含 "delete"），
# 因此命中点的函数体一定包含下列某个 token，预筛不会漏报。
_RELEASE_HINT_RE = re.compile(
    r"(?i)(?:" + "|".join(_FREE_KEYWORDS + ["delete", "put_"]) + r")"
)
_STANDARD_RELEASE_FUNCS = {
    "free",
    "cfree",
    "kfree",
    "vfree",
}

# `obj->reset()` / `obj->close()` 这类方法调用极易误命中关键字。
# 方法调用只有当短名以这些前缀开头（或本身在 _STANDARD_RELEASE_FUNCS 中
# 或是 _STRONG_RELEASE_BASE_NAMES 里的裸名）时才被视作释放，避免静态阶段炸出
# 大量假候选。
_METHOD_RELEASE_PREFIXES = (
    "free_",
    "destroy_",
    "release_",
    "cleanup_",
    "clean_up_",
    "dispose_",
    "deinit_",
    "fini_",
    "finalize_",
    "put_",
    "unref_",
)

# 裸名"强释放"集合：method 名等于这些词时，receiver 大概率就是被释放对象
# （例如 `obj->destroy()` / `ctx->Release()`）。
# 选取标准：在 C/C++ 代码中几乎只用作"释放"语义、极少用作业务方法的词。
# 故意排除 reset / close / clear / clean / fini —— 这些常作业务方法。
_STRONG_RELEASE_BASE_NAMES = frozenset({
    "free",
    "destroy",
    "release",
    "cleanup",
    "clean_up",
    "dispose",
    "deinit",
    "finalize",
    "unref",
})


@dataclass(frozen=True)
class TypeRef:
    name: str
    is_pointer: bool = False


@dataclass
class StructInfo:
    name: str
    aliases: set[str] = field(default_factory=set)
    pointer_fields: dict[str, TypeRef] = field(default_factory=dict)
    file: str = ""
    line: int = 0


@dataclass
class FunctionInfo:
    name: str
    file: str
    node: Node
    source: bytes
    line_base: int = 0


@dataclass(frozen=True)
class ReleaseSite:
    callee: str
    arg_text: str
    arg_type: TypeRef
    struct_info: StructInfo
    line: int
    # 调用形式: function_call | method_call | delete_expression
    call_form: str = "function_call"
    # 静态分析的实际实参: first_argument | receiver | delete_operand
    analysis_target: str = "first_argument"
    # 仅 method_call 时填充；记录 receiver 表达式文本，方便 LLM 在
    # description 里读到"被分析的不是显式参数，而是 receiver"
    receiver_text: str = ""


def _short_name(name: str) -> str:
    return name.rsplit("::", 1)[-1] if name else ""


def _is_free_func(name: str) -> bool:
    short = _short_name(name)
    if not short:
        return False
    return (
        short in _STANDARD_RELEASE_FUNCS
        or any(pattern.search(short) for pattern in _FREE_FUNC_PATTERNS)
    )


def _is_strong_release_name(name: str) -> bool:
    """Method 名是否是"裸名强释放词"（destroy / release / free / ...）。

    用来支持 `obj->destroy()` / `ctx->Release()` 这种 receiver 即释放对象的
    模式 —— 这些写法不带 `_` 后缀，所以不能依赖 `_METHOD_RELEASE_PREFIXES`。
    """
    return _short_name(name).lower() in _STRONG_RELEASE_BASE_NAMES


def _is_method_release_name(name: str) -> bool:
    short = _short_name(name)
    if not short:
        return False
    if short in _STANDARD_RELEASE_FUNCS:
        return True
    if _is_strong_release_name(short):
        return True
    return any(short.startswith(prefix) for prefix in _METHOD_RELEASE_PREFIXES)


def _matched_release_keyword(name: str) -> str:
    short = _short_name(name)
    if not short:
        return ""
    if short in _STANDARD_RELEASE_FUNCS:
        return short
    for keyword, pattern in _KEYWORD_REGEXES.items():
        if pattern.search(short):
            return keyword
    if _PUT_PREFIX_RE.match(short):
        return "put_*"
    return ""


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _collect_source_files(project_path: Path) -> list[Path]:
    return sorted(iter_source_files(project_path, _C_CPP_EXTS, skip_dirs=_SKIP_DIRS))


def _first_named_child(node: Node, types: Iterable[str]) -> Node | None:
    wanted = set(types)
    for child in node.children:
        if child.type in wanted:
            return child
    return None


def _extract_type_name(type_node: Node | None, source: bytes) -> str:
    if type_node is None:
        return ""
    if type_node.type in {
        "type_identifier",
        "primitive_type",
        "sized_type_specifier",
        "auto",
    }:
        return _text(source, type_node).strip()
    if type_node.type in {
        "struct_specifier",
        "class_specifier",
        "union_specifier",
        "enum_specifier",
    }:
        name_node = _first_named_child(type_node, {"type_identifier"})
        return _text(source, name_node).strip()
    if type_node.type == "qualified_identifier":
        name = type_node.child_by_field_name("name")
        if name is not None:
            return _extract_type_name(name, source)
    if type_node.type == "template_type":
        name = type_node.child_by_field_name("name")
        if name is not None:
            return _extract_type_name(name, source)
    return _text(source, type_node).strip()


def _base_type_from_decl(node: Node, source: bytes) -> str:
    candidates: list[Node] = []
    for child in node.children:
        if child.type in {
            "type_identifier",
            "primitive_type",
            "sized_type_specifier",
            "struct_specifier",
            "class_specifier",
            "union_specifier",
            "qualified_identifier",
            "template_type",
        }:
            candidates.append(child)
    if not candidates:
        return ""
    return _extract_type_name(candidates[-1], source)


def _declarator_name_and_pointer(node: Node, source: bytes) -> tuple[str, bool]:
    if node.type in {"identifier", "field_identifier"}:
        return _text(source, node).strip(), False
    if node.type in {"pointer_declarator", "reference_declarator"}:
        for child in reversed(node.children):
            name, _is_pointer = _declarator_name_and_pointer(child, source)
            if name:
                return name, True
        return "", True
    if node.type == "init_declarator":
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            return _declarator_name_and_pointer(declarator, source)
    if node.type in {
        "array_declarator",
        "parenthesized_declarator",
        "function_declarator",
        "qualified_identifier",
    }:
        for child in node.children:
            name, is_pointer = _declarator_name_and_pointer(child, source)
            if name:
                return name, is_pointer
    return "", False


def _declared_vars(node: Node, source: bytes) -> list[tuple[str, TypeRef]]:
    base_type = _base_type_from_decl(node, source)
    if not base_type:
        return []

    result: list[tuple[str, TypeRef]] = []
    for child in node.children:
        if child.type in {
            "identifier",
            "field_identifier",
            "pointer_declarator",
            "reference_declarator",
            "init_declarator",
            "array_declarator",
            "parenthesized_declarator",
        }:
            name, is_pointer = _declarator_name_and_pointer(child, source)
            if name:
                result.append((name, TypeRef(base_type, is_pointer=is_pointer)))
    return result


def _typedef_aliases_for_struct(struct_node: Node, source: bytes) -> set[str]:
    parent = struct_node.parent
    if parent is None or parent.type != "type_definition":
        return set()

    aliases: set[str] = set()
    seen_struct = False
    for child in parent.children:
        if child == struct_node:
            seen_struct = True
            continue
        if not seen_struct:
            continue
        if child.type == "type_identifier":
            aliases.add(_text(source, child).strip())
        elif child.type in {
            "pointer_declarator",
            "reference_declarator",
            "init_declarator",
            "parenthesized_declarator",
        }:
            name, _is_pointer = _declarator_name_and_pointer(child, source)
            if name:
                aliases.add(name)
    return {alias for alias in aliases if alias}


def _collect_structs_from_tree(
    root: Node,
    source: bytes,
    rel_path: str,
) -> list[StructInfo]:
    structs: list[StructInfo] = []
    # 单趟遍历同时处理两类节点：
    #   1) "前向 typedef" 别名（`typedef struct X X_t;`）—— 其 struct_specifier
    #      没有 field_declaration_list，会被结构体收集分支跳过；这里抓进
    #      forward_aliases，遍历结束后再合并到对应 StructInfo.aliases。
    #   2) 带 field_declaration_list 的 struct/class/union 定义。
    forward_aliases: dict[str, set[str]] = {}
    for node in _walk(root):
        if node.type == "type_definition":
            struct_node = None
            for child in node.children:
                if child.type in {"struct_specifier", "class_specifier", "union_specifier"}:
                    struct_node = child
                    break
            if struct_node is None:
                continue
            if _first_named_child(struct_node, {"field_declaration_list"}) is not None:
                continue
            struct_name = _extract_type_name(struct_node, source)
            if not struct_name:
                continue
            aliases = _typedef_aliases_for_struct(struct_node, source)
            if aliases:
                forward_aliases.setdefault(struct_name, set()).update(aliases)
            continue

        if node.type not in {"struct_specifier", "class_specifier", "union_specifier"}:
            continue
        body = _first_named_child(node, {"field_declaration_list"})
        if body is None:
            continue

        explicit_name = _extract_type_name(node, source)
        aliases = _typedef_aliases_for_struct(node, source)
        name = explicit_name or next(iter(sorted(aliases)), "")
        if not name:
            continue

        info = StructInfo(
            name=name,
            aliases={name, *aliases},
            file=rel_path,
            line=_line(node),
        )
        for field_decl in body.children:
            if field_decl.type != "field_declaration":
                continue
            base_type = _base_type_from_decl(field_decl, source)
            for field_name, field_type in _declared_vars(field_decl, source):
                if field_type.is_pointer:
                    info.pointer_fields[field_name] = TypeRef(
                        base_type,
                        is_pointer=True,
                    )
        if info.pointer_fields:
            structs.append(info)

    for info in structs:
        for known_name in (info.name, *list(info.aliases)):
            extra = forward_aliases.get(known_name)
            if extra:
                info.aliases |= extra
    return structs


def _function_name(func_node: Node, source: bytes) -> str:
    declarator = func_node.child_by_field_name("declarator")
    if declarator is None:
        return ""
    for node in _walk(declarator):
        if node.type in {
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "operator_name",
            "destructor_name",
        }:
            return _text(source, node).strip()
    return ""


def _collect_functions_from_tree(
    root: Node,
    source: bytes,
    rel_path: str,
    line_base: int = 0,
) -> list[FunctionInfo]:
    functions: list[FunctionInfo] = []
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        name = _function_name(node, source)
        if not name:
            continue
        functions.append(
                FunctionInfo(
                    name=name,
                    file=rel_path,
                    node=node,
                    source=source,
                    line_base=line_base,
            )
        )
    return functions


def _extract_callee_name(call_node: Node, source: bytes) -> str:
    func_node = call_node.child_by_field_name("function")
    if func_node is None:
        return ""
    if func_node.type in {"identifier", "field_identifier"}:
        return _text(source, func_node).strip()
    if func_node.type == "qualified_identifier":
        name = func_node.child_by_field_name("name")
        return _extract_callee_name_from_node(name, source)
    if func_node.type == "field_expression":
        field = func_node.child_by_field_name("field")
        return _text(source, field).strip()
    if func_node.type == "template_function":
        name = func_node.child_by_field_name("name")
        return _extract_callee_name_from_node(name, source)
    return _extract_callee_name_from_node(func_node, source)


def _extract_callee_name_from_node(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "field_identifier", "operator_name", "destructor_name"}:
        return _text(source, node).strip()
    if node.type == "qualified_identifier":
        name = node.child_by_field_name("name")
        if name is not None:
            return _extract_callee_name_from_node(name, source)
    for child in node.children:
        name = _extract_callee_name_from_node(child, source)
        if name:
            return name
    return ""


def _call_arguments(call_node: Node) -> list[Node]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return [
        child
        for child in args.children
        if child.type not in {"(", ")", ","}
    ]


def _unwrap_expression(node: Node) -> Node:
    current = node
    while current.type in {"parenthesized_expression", "parenthesized_declarator"}:
        named_children = [child for child in current.children if child.is_named]
        if len(named_children) != 1:
            break
        current = named_children[0]
    if current.type == "cast_expression":
        named_children = [child for child in current.children if child.is_named]
        if named_children:
            return _unwrap_expression(named_children[-1])
    return current


def _symbol_name_from_expr(node: Node, source: bytes) -> str:
    node = _unwrap_expression(node)
    if node.type == "identifier":
        return _text(source, node).strip()
    if node.type == "pointer_expression":
        named_children = [child for child in node.children if child.is_named]
        if named_children:
            return _symbol_name_from_expr(named_children[-1], source)
    return ""


def _field_type_from_expr(
    node: Node,
    source: bytes,
    symbols: dict[str, TypeRef],
    structs_by_name: dict[str, StructInfo],
) -> TypeRef | None:
    # 仅识别 identifier / *ptr / obj.field / obj->field 这几种最常见的释放实参。
    # subscript_expression（`arr[i]`）、address-of（`&obj`）、多层嵌套 cast 是
    # 当前静态阶段的已知召回缺口 —— 不会产出 candidate，LLM 阶段也拿不到。
    # 如果未来要覆盖，需扩展本函数并在 SCENARIOS.md 的已知限制里同步更新。
    node = _unwrap_expression(node)
    if node.type == "identifier":
        return symbols.get(_text(source, node).strip())
    if node.type == "pointer_expression":
        named_children = [child for child in node.children if child.is_named]
        if named_children:
            return _field_type_from_expr(named_children[-1], source, symbols, structs_by_name)
    if node.type != "field_expression":
        return None

    object_node = node.child_by_field_name("argument")
    field_node = node.child_by_field_name("field")
    if object_node is None or field_node is None:
        return None

    object_type = _field_type_from_expr(object_node, source, symbols, structs_by_name)
    if object_type is None:
        return None
    struct_info = structs_by_name.get(object_type.name)
    if struct_info is None:
        return None
    return struct_info.pointer_fields.get(_text(source, field_node).strip())


def _symbols_for_function(func: FunctionInfo) -> dict[str, TypeRef]:
    symbols: dict[str, TypeRef] = {}
    declarator = func.node.child_by_field_name("declarator")
    if declarator is not None:
        for node in _walk(declarator):
            if node.type == "parameter_declaration":
                for name, type_ref in _declared_vars(node, func.source):
                    symbols[name] = type_ref

    body = func.node.child_by_field_name("body")
    if body is not None:
        for node in _walk(body):
            if node.type == "declaration":
                for name, type_ref in _declared_vars(node, func.source):
                    symbols[name] = type_ref
    return symbols


def _struct_for_type(
    type_ref: TypeRef | None,
    structs_by_name: dict[str, StructInfo],
) -> StructInfo | None:
    if type_ref is None or not type_ref.name:
        return None
    return structs_by_name.get(type_ref.name)


def _delete_expression_callee(node: Node) -> str:
    """`delete x` vs `delete[] x` 判定：扫子节点是否存在匿名 `[` token。"""
    for child in node.children:
        if not child.is_named and child.type == "[":
            return "delete[]"
    return "delete"


def _resolve_struct_for_expr(
    arg: Node,
    source: bytes,
    symbols: dict[str, TypeRef],
    structs_by_name: dict[str, StructInfo],
) -> tuple[TypeRef, StructInfo] | None:
    """把一个表达式解析成 (TypeRef, StructInfo)，解析不出来返回 None。"""
    type_ref = _field_type_from_expr(arg, source, symbols, structs_by_name)
    if type_ref is None:
        symbol = _symbol_name_from_expr(arg, source)
        type_ref = symbols.get(symbol)
    struct_info = _struct_for_type(type_ref, structs_by_name)
    if type_ref is None or struct_info is None:
        return None
    return type_ref, struct_info


def _find_release_sites(
    func: FunctionInfo,
    release_func_names: set[str],
    structs_by_name: dict[str, StructInfo],
) -> list[ReleaseSite]:
    symbols = _symbols_for_function(func)
    sites: list[ReleaseSite] = []

    for node in _walk(func.node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            callee = _extract_callee_name(node, func.source)
            short_callee = _short_name(callee)
            is_method_call = (
                func_node is not None and func_node.type == "field_expression"
            )
            args = _call_arguments(node)

            if is_method_call:
                # 方法调用：严格判定 callee 是否是释放语义。
                if not _is_method_release_name(short_callee):
                    continue
                receiver_node = func_node.child_by_field_name("argument")
                receiver_text = _text(func.source, receiver_node).strip()

                # 策略（与 debate.md 收敛结论一致）：
                # 1) 无显式参数 → 直接分析 receiver。
                # 2) 有显式参数 → 优先分析第一个显式参数。
                # 3) 第一个显式参数不可解析为含指针成员的 struct，且 method 名
                #    是 _STRONG_RELEASE_BASE_NAMES 里的裸名（destroy/release/...）
                #    → fallback 到 receiver；这样能补 `obj->destroy()` 的漏报，
                #    又不会把 `pool->release(resource)` 改成分析 `pool`。
                if not args:
                    if receiver_node is None:
                        continue
                    resolved = _resolve_struct_for_expr(
                        receiver_node, func.source, symbols, structs_by_name
                    )
                    if resolved is None:
                        continue
                    type_ref, struct_info = resolved
                    sites.append(
                        ReleaseSite(
                            callee=short_callee,
                            arg_text=receiver_text,
                            arg_type=type_ref,
                            struct_info=struct_info,
                            line=func.line_base + _line(node),
                            call_form="method_call",
                            analysis_target="receiver",
                            receiver_text=receiver_text,
                        )
                    )
                    continue

                arg = args[0]
                resolved = _resolve_struct_for_expr(
                    arg, func.source, symbols, structs_by_name
                )
                if resolved is not None:
                    type_ref, struct_info = resolved
                    sites.append(
                        ReleaseSite(
                            callee=short_callee,
                            arg_text=_text(func.source, arg).strip(),
                            arg_type=type_ref,
                            struct_info=struct_info,
                            line=func.line_base + _line(node),
                            call_form="method_call",
                            analysis_target="first_argument",
                            receiver_text=receiver_text,
                        )
                    )
                    continue

                # 第一个显式参数不可解析；只有 method 名是强释放词时
                # 才考虑 receiver 兜底（避免 pool->release(t) 这类误改）。
                if not _is_strong_release_name(short_callee):
                    continue
                if receiver_node is None:
                    continue
                resolved = _resolve_struct_for_expr(
                    receiver_node, func.source, symbols, structs_by_name
                )
                if resolved is None:
                    continue
                type_ref, struct_info = resolved
                sites.append(
                    ReleaseSite(
                        callee=short_callee,
                        arg_text=receiver_text,
                        arg_type=type_ref,
                        struct_info=struct_info,
                        line=func.line_base + _line(node),
                        call_form="method_call",
                        analysis_target="receiver",
                        receiver_text=receiver_text,
                    )
                )
                continue

            # 普通函数调用：沿用原逻辑（短名 + 关键字 + 项目内 wrapper 集合）
            if (
                short_callee not in release_func_names
                and not _is_free_func(short_callee)
            ):
                continue
            if not args:
                continue
            arg = args[0]
            resolved = _resolve_struct_for_expr(
                arg, func.source, symbols, structs_by_name
            )
            if resolved is None:
                continue
            type_ref, struct_info = resolved
            sites.append(
                ReleaseSite(
                    callee=short_callee,
                    arg_text=_text(func.source, arg).strip(),
                    arg_type=type_ref,
                    struct_info=struct_info,
                    line=func.line_base + _line(node),
                    call_form="function_call",
                    analysis_target="first_argument",
                )
            )
        elif node.type == "delete_expression":
            named_children = [child for child in node.children if child.is_named]
            if not named_children:
                continue
            arg = named_children[-1]
            resolved = _resolve_struct_for_expr(
                arg, func.source, symbols, structs_by_name
            )
            if resolved is None:
                continue
            type_ref, struct_info = resolved
            sites.append(
                ReleaseSite(
                    callee=_delete_expression_callee(node),
                    arg_text=_text(func.source, arg).strip(),
                    arg_type=type_ref,
                    struct_info=struct_info,
                    line=func.line_base + _line(node),
                    call_form="delete_expression",
                    analysis_target="delete_operand",
                )
            )
    return sites


def _line_excerpt(
    source: bytes,
    line_no: int,
    radius: int = 4,
    line_base: int = 0,
) -> str:
    lines = source.decode("utf-8", "replace").splitlines()
    local_line = line_no - line_base
    start = max(1, local_line - radius)
    end = min(len(lines), local_line + radius)
    width = len(str(line_base + end))
    return "\n".join(
        f"{line_base + idx:>{width}}: {lines[idx - 1]}"
        for idx in range(start, end + 1)
    )


def _row_get(row, key: str, default=None):
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        if hasattr(row, "get"):
            return row.get(key, default)
        return default


def _parse_indexed_structs(db: "CodeDatabase", parser: Parser) -> list[StructInfo]:
    structs: list[StructInfo] = []
    if hasattr(db, "get_all_structs"):
        rows = db.get_all_structs()
    else:
        conn = getattr(db, "_conn", None)
        if conn is None:
            return []
        try:
            rows = conn.execute(
                """SELECT s.*, fi.path as file_path
                   FROM structs s JOIN files fi ON s.file_id = fi.file_id
                   ORDER BY fi.path, s.start_line"""
            ).fetchall()
        except Exception:
            return []

    for row in rows:
        definition = str(_row_get(row, "definition", "") or "")
        if not definition:
            continue
        source = definition.encode("utf-8", "replace")
        try:
            tree = parser.parse(source)
        except Exception:
            continue
        file_path = str(_row_get(row, "file_path", "") or "")
        start_line = int(_row_get(row, "start_line", 1) or 1)
        row_name = str(_row_get(row, "name", "") or "").strip()
        parsed = _collect_structs_from_tree(
            tree.root_node,
            source,
            file_path,
        )
        for info in parsed:
            if row_name:
                info.aliases.add(row_name)
                if not info.name:
                    info.name = row_name
            info.line = start_line + info.line - 1
            structs.append(info)
    return structs


def _iter_indexed_functions(
    parser: Parser,
    func_rows: Iterable,
    scope_prefix: str | None,
) -> Iterator[FunctionInfo]:
    """逐函数流式产出 FunctionInfo。

    与旧的"先 parse 全仓装进列表"不同，这里逐行处理并即时 yield：调用方用完一个
    函数后其 tree-sitter Tree 即可回收，常驻内存从"整仓 N 棵 AST"降到"单函数 1 棵"。
    同时按 scope_prefix 收敛到扫描范围、解析前用 _RELEASE_HINT_RE 预筛，跳过绝大多数
    不可能命中的函数。
    """
    for row in func_rows:
        file_path = str(_row_get(row, "file_path", "") or "")
        if not _in_scope(file_path, scope_prefix):
            continue
        body = str(_row_get(row, "body", "") or "")
        if not body or not _RELEASE_HINT_RE.search(body):
            continue
        source = body.encode("utf-8", "replace")
        try:
            tree = parser.parse(source)
        except Exception:
            continue
        start_line = int(_row_get(row, "start_line", 1) or 1)
        yield from _collect_functions_from_tree(
            tree.root_node,
            source,
            file_path,
            line_base=start_line - 1,
        )


def _is_complete_index(db: "CodeDatabase") -> bool:
    checker = getattr(db, "is_index_complete", None)
    if checker is None:
        return False
    try:
        return bool(checker())
    except Exception:
        return False


class Analyzer(BaseAnalyzer):
    vuln_type = "multi_ptr_leak2"

    def __init__(self) -> None:
        self._parser = Parser(_CPP_LANGUAGE)

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterable[Candidate]:
        structs: list[StructInfo] = []
        # release_func_names 只存 short name，与 _extract_callee_name 返回的
        # callee 名字空间保持一致；否则 `Class::destroy` 与 `obj->destroy()`
        # 永远对不上，第一条快速过滤会失效。项目内释放 wrapper 直接从索引的
        # 函数名列（无需解析函数体）取，覆盖全仓（范围外定义的 wrapper 也可能被
        # 范围内调用）。
        release_func_names = set(_STANDARD_RELEASE_FUNCS)
        use_file_fallback = True
        scope_prefix: str | None = None
        func_rows: list = []

        if db is not None:
            structs.extend(_parse_indexed_structs(db, self._parser))
            func_rows = list(db.get_all_functions())
            for row in func_rows:
                name = str(_row_get(row, "name", "") or "")
                if name and _is_free_func(name):
                    release_func_names.add(_short_name(name))
            use_file_fallback = not _is_complete_index(db)
            scope_prefix = _scope_prefix(db, project_path)

        # 完整索引由上游保证覆盖全仓，避免在大仓库上重复 tree-sitter 扫描。
        # 不完整索引或测试 fake DB 仍与磁盘解析结果合并，保持召回优先。
        file_functions: list[FunctionInfo] = []
        if use_file_fallback:
            file_structs, file_functions = self._parse_project_files(project_path)
            structs.extend(file_structs)
            for func in file_functions:
                if _is_free_func(func.name):
                    release_func_names.add(_short_name(func.name))

        structs_by_name: dict[str, StructInfo] = {}
        for info in structs:
            for alias in info.aliases:
                structs_by_name.setdefault(alias, info)

        seen: set[tuple[str, int, str, str, str]] = set()

        # 索引函数：逐函数流式处理（用完即弃 Tree，常驻内存只剩单函数）。
        if db is not None:
            for func in _iter_indexed_functions(self._parser, func_rows, scope_prefix):
                yield from self._emit_candidates(
                    func, release_func_names, structs_by_name, seen
                )

        # 磁盘 fallback 函数（仅索引不完整 / 测试 fake DB 时）。
        for func in file_functions:
            yield from self._emit_candidates(
                func, release_func_names, structs_by_name, seen
            )

    def _emit_candidates(
        self,
        func: FunctionInfo,
        release_func_names: set[str],
        structs_by_name: dict[str, StructInfo],
        seen: set[tuple[str, int, str, str, str]],
    ) -> Iterator[Candidate]:
        sites = _find_release_sites(func, release_func_names, structs_by_name)
        for site in sites:
            key = (
                func.file,
                site.line,
                func.name,
                site.callee,
                site.arg_text,
            )
            if key in seen:
                continue
            seen.add(key)

            field_list = ", ".join(
                f"{name}: {type_ref.name}*"
                for name, type_ref in sorted(site.struct_info.pointer_fields.items())
            )
            matched_keyword = _matched_release_keyword(site.callee)
            func_start_line = func.line_base + _line(func.node)

            lines = [
                f"函数 `{func.name}` 中释放调用 `{site.callee}({site.arg_text})` "
                f"是否存在结构体指针成员泄漏问题（释放实现可能只释放最外层对象而遗漏成员指针），"
                f"请审计确认。",
                "相关线索：",
                f"所在函数: {func.name} ({func.file}:{func_start_line})",
                f"调用形式: {site.call_form}",
                f"释放实参: {site.analysis_target}",
            ]
            if site.call_form == "method_call":
                lines.append(f"receiver: {site.receiver_text or '(unknown)'}")
            lines.extend([
                f"释放调用: {site.callee}({site.arg_text})",
                f"实参类型: {site.arg_type.name}"
                f"{'*' if site.arg_type.is_pointer else ''}",
                f"结构体: {site.struct_info.name} "
                f"({site.struct_info.file}:{site.struct_info.line})",
                f"指针成员: {field_list}",
                "调用点上下文:",
                _line_excerpt(func.source, site.line, line_base=func.line_base),
            ])
            description = "\n".join(lines)

            yield Candidate(
                file=func.file,
                line=site.line,
                function=func.name,
                description=description,
                vuln_type=self.vuln_type,
                related_functions=[site.callee],
            )

    def _parse_project_files(
        self,
        project_path: Path,
    ) -> tuple[list[StructInfo], list[FunctionInfo]]:
        source_files = _collect_source_files(project_path)
        total_files = len(source_files)
        structs: list[StructInfo] = []
        functions: list[FunctionInfo] = []

        for idx, path in enumerate(source_files, 1):
            if self.on_file_progress and (
                idx == 1 or idx == total_files or idx % 20 == 0
            ):
                self.on_file_progress(idx, total_files)
            try:
                source = path.read_bytes()
            except OSError:
                continue
            try:
                tree = self._parser.parse(source)
            except Exception:
                continue
            try:
                rel_path = path.relative_to(project_path).as_posix()
            except ValueError:
                rel_path = path.as_posix()
            root = tree.root_node
            structs.extend(_collect_structs_from_tree(root, source, rel_path))
            functions.extend(_collect_functions_from_tree(root, source, rel_path))

        return structs, functions
