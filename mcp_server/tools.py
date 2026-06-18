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


def clear_db_cache():
    """关闭所有缓存的 DB 连接并清空缓存。

    MCP server 停止时调用，防止跨扫描返回失效连接。
    """
    for db in _db_cache.values():
        try:
            db.close()
        except Exception:
            pass
    _db_cache.clear()


def _mcp_log(direction: str, tool: str, detail: str) -> None:
    print(f"  [MCP {direction}] {tool} | {detail}", flush=True)


def _preview(text: str, max_chars: int = 120) -> str:
    text = text.replace("\n", "\\n")
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}… ({len(text)} chars)"


def _append_result_payload(result_path: Path, payload: dict) -> None:
    """Append payload while preserving compatibility with old single-result files."""
    if result_path.exists():
        try:
            current = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            current = None
        if isinstance(current, dict) and isinstance(current.get("results"), list):
            results = [item for item in current["results"] if isinstance(item, dict)]
        elif isinstance(current, list):
            results = [item for item in current if isinstance(item, dict)]
        elif isinstance(current, dict):
            results = [current]
        else:
            results = []
        results.append(payload)
        data = {"results": results}
    else:
        data = payload
    result_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


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
        vulnerability_report: str = "",
        file: str = "",
        line: int = 0,
        function: str = "",
    ) -> str:
        """
        提交本次漏洞分析的最终结论。分析完成后必须调用此工具，否则结果将丢失。

        参数：
            result_id: 分析任务标识符（以 "result-" 开头，由分析提示中提供，原样传入，不要修改）。
            confirmed: 是否存在真实漏洞。true 表示确认漏洞，false 表示误报。
            severity: 严重程度，可选值为 "high"、"medium"、"low"（仅 confirmed=true 时有意义）。
            description: 漏洞的一句话摘要。
            ai_analysis: 详细的分析推理过程，需包含具体的代码路径。
            vulnerability_report: 可选 Markdown 漏洞报告。外部可触发且 severity="high" 时填写。
            file: 可选，真实问题所在文件路径。项目级审计发现问题时必须填写。
            line: 可选，真实问题所在行号。项目级审计发现问题时必须填写。
            function: 可选，真实问题所在函数。项目级审计发现问题时必须填写。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_result",
                 f"confirmed={confirmed} severity={severity!r} description={_preview(description)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        _append_result_payload(result_path, {
            "confirmed": confirmed,
            "severity": severity,
            "description": description,
            "ai_analysis": ai_analysis,
            "vulnerability_report": vulnerability_report,
            "file": file,
            "line": line,
            "function": function,
        })
        _mcp_log("◀", "submit_result", f"saved → {result_path}")
        return f"结果已提交（result_id={result_id}）。"

    @mcp.tool()
    def submit_history_pattern(
        result_id: str,
        security_related: bool,
        pattern: str = "",
        lens_hint: str = "",
        files: str = "",
        rationale: str = "",
    ) -> str:
        """
        提交一条 git 历史提交的安全问题模式判定结论。分析完单条提交后必须调用此工具。

        参数：
            result_id: 分析任务标识符（由分析提示中提供，原样传入，不要修改）。
            security_related: 该提交是否是一次安全修复。
            pattern: 若相关，提炼出的可复用问题模式（根因 + 缺陷类型 + 触发条件的抽象描述，不要只抄提交标题）。
            lens_hint: 安全视角，可选值 memory/integer/race/injection/authn/crypto/dos/infoleak。
            files: 涉及的文件，逗号分隔。
            rationale: 判定理由 + 改动要点摘要。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_history_pattern",
                 f"security_related={security_related} pattern={_preview(pattern)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        file_list = [s.strip() for s in str(files or "").replace("\n", ",").split(",") if s.strip()]
        result_path.write_text(json.dumps({
            "kind": "history_pattern",
            "security_related": bool(security_related),
            "pattern": pattern,
            "lens_hint": lens_hint,
            "files": file_list,
            "rationale": rationale,
        }, ensure_ascii=False), encoding="utf-8")
        _mcp_log("◀", "submit_history_pattern", f"saved → {result_path}")
        return f"历史问题模式已提交（result_id={result_id}）。"

    @mcp.tool()
    def submit_variant_finding(
        result_id: str,
        file: str,
        line: int,
        function: str,
        vuln_type: str,
        description: str,
        rationale: str = "",
    ) -> str:
        """
        提交一处同类变体排查命中的疑似缺陷站点。每核实坐实一处即调用一次（可多次调用累加）。

        参数：
            result_id: 任务标识符（由分析提示中提供，原样传入，不要修改）。
            file: 命中站点所在文件路径（相对项目根）。
            line: 命中站点行号。
            function: 命中站点所在函数。
            vuln_type: 缺陷类型，必须从分析提示给出的可选检查项列表中选一个。
            description: 一句话描述该处缺陷及其与历史问题模式的相似点。
            rationale: 可选，核实推理过程（为何该站点缺少等价校验/存在同类缺陷）。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_variant_finding",
                 f"{file}:{line} vuln_type={vuln_type!r} {_preview(description)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        _append_result_payload(result_path, {
            "kind": "variant_finding",
            "file": file,
            "line": line,
            "function": function,
            "vuln_type": vuln_type,
            "description": description,
            "rationale": rationale,
        })
        _mcp_log("◀", "submit_variant_finding", f"saved → {result_path}")
        return f"变体站点已提交（result_id={result_id}）。"

    @mcp.tool()
    def submit_match_result(
        result_id: str,
        matched: bool,
        match_type: str = "",
        match_reference: str = "",
        description: str = "",
        ai_analysis: str = "",
        vulnerability_report: str = "",
    ) -> str:
        """
        提交去误报「历史/校验匹配」阶段的结论。判断该候选是否能与历史问题模式或其它函数的
        正确校验对应上；若能对应，则直接判定为 high。

        参数：
            result_id: 任务标识符（由分析提示中提供，原样传入，不要修改）。
            matched: 是否成立匹配（true 表示与历史问题或其它函数校验对应上，可直接定为 high）。
            match_type: 匹配类型，"history"（对应历史问题模式）或 "validation"（对应其它函数的正确校验）。
            match_reference: 对应的修复/校验描述：历史模式根因摘要+出处提交，或正确校验站点 path:line + 一句话说明。
            description: 一句话结论摘要。
            ai_analysis: 详细推理（含代码路径与匹配依据）。
            vulnerability_report: 匹配成立时填写的 Markdown 问题报告。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_match_result",
                 f"matched={matched} match_type={match_type!r} ref={_preview(match_reference)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps({
            "kind": "match_result",
            "confirmed": bool(matched),
            "severity": "high" if matched else "low",
            "description": description,
            "ai_analysis": ai_analysis,
            "vulnerability_report": vulnerability_report,
            "match_type": match_type,
            "match_reference": match_reference,
            "file": "",
            "line": 0,
            "function": "",
        }, ensure_ascii=False), encoding="utf-8")
        _mcp_log("◀", "submit_match_result", f"saved → {result_path}")
        return f"匹配结论已提交（result_id={result_id}）。"
