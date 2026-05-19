"""MCP 工具定义 — 提供源码查询能力。

所有工具通过 project_id 定位项目目录及其代码索引（code_index.db）。
"""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# 按 project_id 缓存 DB 连接，MCP Server 是长驻进程，避免每次重新打开
_db_cache: dict[str, object] = {}


def _get_config():
    from backend.config import get_config
    return get_config()


def _get_db(project_id: str):
    """返回指定项目的 CodeDatabase，不存在则返回 None。

    Agent 模式下，AGENT_PROJECT_DIR 环境变量指向本地索引目录，优先于
    server 模式下的 {projects_dir}/{project_id}/code_index.db 路径。
    """
    from code_parser import CodeDatabase

    # Agent mode: resolve DB path from env var (set by agent/local_mcp.py)
    agent_dir = os.environ.get("AGENT_PROJECT_DIR")
    if agent_dir:
        cache_key = f"agent:{agent_dir}"
        if cache_key in _db_cache:
            return _db_cache[cache_key]
        db_path = Path(agent_dir) / "code_index.db"
        if not db_path.exists():
            return None
        db = CodeDatabase(db_path)
        if not db.is_index_complete():
            db.close()
            return None
        _db_cache[cache_key] = db
        return db

    # Server mode: resolve by project_id
    if project_id in _db_cache:
        return _db_cache[project_id]
    db_path = Path(_get_config().storage.projects_dir) / project_id / "code_index.db"
    if not db_path.exists():
        return None
    db = CodeDatabase(db_path)
    if not db.is_index_complete():
        db.close()
        return None
    _db_cache[project_id] = db
    return db


def _mcp_log(direction: str, tool: str, detail: str) -> None:
    print(f"  [MCP {direction}] {tool} | {detail}", flush=True)


def _preview(text: str, max_chars: int = 120) -> str:
    text = text.replace("\n", "\\n")
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}… ({len(text)} chars)"


def register_tools(mcp: FastMCP) -> None:
    """在 MCP Server 上注册所有源码查询工具。"""

    @mcp.tool()
    def view_function_code(project_id: str, function_name: str, file_path: str = "") -> str:
        """
        根据函数名返回函数体代码。
        file_path 可选，传入可缩小搜索范围。

        参数：
            project_id: 项目标识符（由分析提示中提供）。
            function_name: 要查找的函数名称。
            file_path: 可选，函数所在文件路径。

        返回：
            函数体代码（包含文件路径和行号信息），未找到则返回提示。
        """
        detail = f"function_name={function_name!r}"
        if file_path:
            detail += f", file_path={file_path!r}"
        _mcp_log("▶", "view_function_code", detail)
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_function_code", result)
            return result
        rows = db.get_functions_by_name(function_name, file_path=file_path or None)
        if not rows:
            result = f"未找到函数 '{function_name}'。"
            _mcp_log("◀", "view_function_code", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['body']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_function_code", f"{len(rows)} match(es), {len(result)} chars")
        return result

    @mcp.tool()
    def view_struct_code(project_id: str, struct_name: str) -> str:
        """
        根据结构体名返回结构体定义代码。
        file_path 可选，传入可缩小搜索范围（当前版本暂不使用）。

        参数：
            project_id: 项目标识符。
            struct_name: 要查找的结构体名称。

        返回：
            结构体定义代码（包含文件路径和行号信息），未找到则返回提示。
        """
        _mcp_log("▶", "view_struct_code", f"struct_name={struct_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_struct_code", result)
            return result
        rows = db.get_structs_by_name(struct_name)
        if not rows:
            result = f"未找到结构体 '{struct_name}'。"
            _mcp_log("◀", "view_struct_code", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_struct_code", f"{len(rows)} match(es), {len(result)} chars")
        return result

    @mcp.tool()
    def view_global_variable_definition(project_id: str, global_variable_name: str) -> str:
        """
        根据全局变量名返回其定义。注意：只有 g_ 开头的变量才会被索引为全局变量。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找的全局变量名称。

        返回：
            全局变量定义代码，未找到则返回提示。
        """
        _mcp_log("▶", "view_global_variable_definition", f"name={global_variable_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_global_variable_definition", result)
            return result
        rows = db.get_global_variables_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}'。"
            _mcp_log("◀", "view_global_variable_definition", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_global_variable_definition", f"{len(rows)} match(es), {len(result)} chars")
        return result

    # Kept for future reuse, but intentionally not registered as an MCP tool.
    def find_function_references(project_id: str, function_name: str) -> str:
        """
        查找某个函数在整个项目中所有被调用的位置。

        参数：
            project_id: 项目标识符。
            function_name: 要查找引用的函数名称。

        返回：
            每行一个调用位置，格式为 "调用者函数名  文件路径:行号"。
        """
        _mcp_log("▶", "find_function_references", f"function_name={function_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "find_function_references", result)
            return result
        rows = db.get_call_sites_by_name(function_name)
        short_name_fallback = False
        if not rows and "::" in function_name:
            short_name = function_name.rsplit("::", 1)[-1]
            rows = db.get_call_sites_by_name(short_name)
            short_name_fallback = bool(rows)
        if not rows:
            result = f"未找到函数 '{function_name}' 的引用位置。"
            _mcp_log("◀", "find_function_references", result)
            return result
        lines = []
        if short_name_fallback:
            lines.append(
                f"未找到限定名 '{function_name}' 的精确调用记录，以下为短名匹配结果，可能包含其他类或命名空间中的同名调用。"
            )
        lines.extend(
            f"{row['caller_name'] or '未知'}  {row['file_path']}:{row['line']}"
            for row in rows
        )
        result = "\n".join(lines)
        _mcp_log("◀", "find_function_references", f"{len(rows)} reference(s)")
        return result

    # Kept for future reuse, but intentionally not registered as an MCP tool.
    def find_global_variable_references(project_id: str, global_variable_name: str) -> str:
        """
        查找某个全局变量在整个项目中所有被引用的位置。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找引用的全局变量名称。

        返回：
            每行一个引用，格式为 "引用函数名  文件路径:行号  访问类型  引用代码行"。
        """
        _mcp_log("▶", "find_global_variable_references", f"name={global_variable_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "find_global_variable_references", result)
            return result
        rows = db.get_global_variable_reference_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}' 的引用。"
            _mcp_log("◀", "find_global_variable_references", result)
            return result
        result = "\n".join(
            f"{row['function_name'] or '未知'}  {row['file_path']}:{row['line']}  [{row['access_type']}]  {row['context']}"
            for row in rows
        )
        _mcp_log("◀", "find_global_variable_references", f"{len(rows)} reference(s)")
        return result

    @mcp.tool()
    def submit_result(
        result_id: str,
        confirmed: bool,
        severity: str,
        description: str,
        ai_analysis: str,
    ) -> str:
        """
        提交本次漏洞分析的最终结论。分析完成后必须调用此工具，否则结果将丢失。

        参数：
            result_id: 分析任务标识符（以 "result-" 开头，由分析提示中提供，原样传入，不要修改）。
            confirmed: 是否存在真实漏洞。true 表示确认漏洞，false 表示误报。
            severity: 严重程度，可选值为 "high"、"medium"、"low"（仅 confirmed=true 时有意义）。
            description: 漏洞的一句话摘要。
            ai_analysis: 详细的分析推理过程，需包含具体的代码路径。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_result",
                 f"confirmed={confirmed} severity={severity!r} description={_preview(description)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps({
            "confirmed": confirmed,
            "severity": severity,
            "description": description,
            "ai_analysis": ai_analysis,
        }, ensure_ascii=False), encoding="utf-8")
        _mcp_log("◀", "submit_result", f"saved → {result_path}")
        return f"结果已提交（result_id={result_id}）。"
