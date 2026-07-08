"""MCP 工具定义 — 提供源码查询能力。

所有工具通过 project_id 定位项目目录及其代码索引（code_index.db）。
"""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP

# 按 DB 路径缓存连接，MCP Server 是长驻进程，避免每次重新打开
_db_cache: dict[str, tuple[object, tuple[int, int, int, int]]] = {}


def _get_config():
    from backend.config import get_config
    return get_config()


def _cache_key_for_path(db_path: Path) -> str:
    return f"path:{db_path.resolve()}"


def _close_cached_db(cache_key: str) -> None:
    entry = _db_cache.pop(cache_key, None)
    if entry is None:
        return
    db = entry[0]
    try:
        db.close()
    except Exception:
        pass


def _db_fingerprint(db_path: Path) -> tuple[int, int, int, int] | None:
    try:
        stat = db_path.stat()
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size)


def _cached_db_is_usable(entry, db_path: Path) -> bool:
    fingerprint = _db_fingerprint(db_path)
    if fingerprint is None or fingerprint != entry[1]:
        return False
    db = entry[0]
    try:
        return bool(db.is_index_complete())
    except Exception:
        return False


def _open_complete_db(cache_key: str, db_path: Path):
    if not db_path.exists():
        return None
    from code_parser import CodeDatabase

    db = None
    try:
        db = CodeDatabase(db_path)
        if not db.is_index_complete():
            db.close()
            return None
        fingerprint = _db_fingerprint(db_path)
        if fingerprint is None:
            db.close()
            return None
        _db_cache[cache_key] = (db, fingerprint)
        return db
    except Exception:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        return None


def _resolve_db_path(project_id: str, project_dir: Path | None = None) -> Path:
    if project_dir is not None:
        return project_dir / "code_index.db"

    agent_dir = os.environ.get("AGENT_PROJECT_DIR")
    if agent_dir:
        return Path(agent_dir) / "code_index.db"

    return Path(_get_config().storage.projects_dir) / project_id / "code_index.db"


def _get_db(project_id: str, project_dir: Path | None = None):
    """返回指定项目的 CodeDatabase，不存在则返回 None。

    Agent 模式下，LocalMCPServer 会显式绑定本地索引目录；AGENT_PROJECT_DIR
    仅作为旧调用路径的兼容兜底。
    """
    db_path = _resolve_db_path(project_id, project_dir)
    cache_key = _cache_key_for_path(db_path)
    cached = _db_cache.get(cache_key)
    if cached is not None:
        if _cached_db_is_usable(cached, db_path):
            return cached[0]
        _close_cached_db(cache_key)
    return _open_complete_db(cache_key, db_path)


def clear_db_cache(project_dir: Path | str | None = None):
    """关闭所有缓存的 DB 连接并清空缓存。

    MCP server 停止时调用，防止跨扫描返回失效连接。传入 project_dir 时
    只清理该本地 MCP 实例绑定的索引连接，避免影响其他并发扫描。
    """
    if project_dir is not None:
        _close_cached_db(_cache_key_for_path(Path(project_dir) / "code_index.db"))
        return
    for db, _fingerprint in _db_cache.values():
        try:
            db.close()
        except Exception:
            pass
    _db_cache.clear()


_MCP_LOG_DETAIL_LIMIT = 500
_MCP_LOG_ARGS_LIMIT = 1_000


def _mcp_log(direction: str, tool: str, detail: str) -> None:
    preview = _preview(detail)
    suffix = f" | {preview}" if preview else ""
    print(f"  [MCP {direction}] {tool}{suffix}", flush=True)


def _mcp_log_call(tool: str, detail: str) -> None:
    _mcp_log("▶", tool, detail)


def _mcp_log_return(tool: str, detail: str) -> None:
    _mcp_log("◀", tool, detail)


def _mcp_result_summary(count_label: str, count: int, result: str) -> str:
    return f"{count} {count_label}, {len(result)} chars"


def _preview(text: object, max_chars: int = _MCP_LOG_DETAIL_LIMIT) -> str:
    text = "" if text is None else str(text)
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}...[truncated {len(text) - max_chars} chars]"


def _summarize_log_value(value: object, *, max_string: int = 180) -> object:
    if isinstance(value, dict):
        return {str(key): _summarize_log_value(item, max_string=max_string) for key, item in value.items()}
    if isinstance(value, list):
        return [_summarize_log_value(item, max_string=max_string) for item in value]
    if isinstance(value, str):
        text = _preview(value, max_string)
        if len(value) > max_string or "\n" in value:
            return f"<chars={len(value)} preview={text}>"
        return text
    return value


def _json_preview(value: object, max_chars: int = _MCP_LOG_ARGS_LIMIT) -> str:
    value = _summarize_log_value(value)
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        text = str(value)
    return _preview(text, max_chars)


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


def _opencode_session_from_context(ctx: Context | None) -> str:
    if ctx is None:
        return ""
    try:
        request_context = ctx.request_context
    except Exception:
        return ""
    candidates = [
        getattr(request_context, "request", None),
        getattr(getattr(request_context, "experimental", None), "request", None),
        getattr(request_context, "meta", None),
    ]
    for name in ("x-opencode-session", "x-opencode-session-id", "x-opencode-sessionid"):
        for source in candidates:
            headers = getattr(source, "headers", None)
            if headers is None and isinstance(source, dict):
                headers = source.get("headers")
            if headers is None:
                continue
            try:
                value = headers.get(name)
            except Exception:
                value = None
            if value:
                return str(value).strip()
    return ""


def _submit_payload(tool_name: str, ctx: Context | None, payload: dict) -> tuple[bool, str]:
    session_id = _opencode_session_from_context(ctx)
    if not session_id:
        return False, "无法提交结果：MCP 请求缺少 x-opencode-session，无法判断 OpenCode session。"
    try:
        from backend.opencode.submit_sink import record_submission

        seq = record_submission(session_id, tool_name, payload)
    except Exception as exc:
        return False, f"无法提交结果：保存 {tool_name} 结果失败：{exc}"
    return True, f"结果已提交（session_id={session_id}, tool={tool_name}, seq={seq}）。"


def register_tools(mcp: FastMCP, project_dir: Path | str | None = None) -> None:
    """在 MCP Server 上注册所有源码查询工具。"""
    bound_project_dir = Path(project_dir).resolve() if project_dir is not None else None

    @mcp.tool()
    def view_function_code(
        project_id: str,
        function_name: str,
        file_path: str = "",
    ) -> str:
        """
        根据函数名返回函数体代码。
        file_path 可选，传入可缩小搜索范围。
        需要阅读函数源码时优先使用本 deephole-code MCP 工具；仅在索引不可用、
        未命中或需要目录级枚举/文本搜索时，再回退内置 read/grep/glob。

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
        _mcp_log_call("view_function_code", detail)
        db = _get_db(project_id, bound_project_dir)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log_return("view_function_code", result)
            return result
        rows = db.get_functions_by_name(function_name, file_path=file_path or None)
        if not rows:
            result = f"未找到函数 '{function_name}'。"
            _mcp_log_return("view_function_code", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['body']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log_return("view_function_code", _mcp_result_summary("match(es)", len(rows), result))
        return result

    @mcp.tool()
    def view_struct_code(project_id: str, struct_name: str) -> str:
        """
        根据结构体名返回结构体定义代码。
        需要阅读结构体定义时优先使用本 deephole-code MCP 工具；仅在索引不可用、
        未命中或需要目录级枚举/文本搜索时，再回退内置 read/grep/glob。

        参数：
            project_id: 项目标识符。
            struct_name: 要查找的结构体名称。

        返回：
            结构体定义代码（包含文件路径和行号信息），未找到则返回提示。
        """
        _mcp_log_call("view_struct_code", f"struct_name={struct_name!r}")
        db = _get_db(project_id, bound_project_dir)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log_return("view_struct_code", result)
            return result
        rows = db.get_structs_by_name(struct_name)
        if not rows:
            result = f"未找到结构体 '{struct_name}'。"
            _mcp_log_return("view_struct_code", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log_return("view_struct_code", _mcp_result_summary("match(es)", len(rows), result))
        return result

    @mcp.tool()
    def view_global_variable_definition(
        project_id: str,
        global_variable_name: str,
    ) -> str:
        """
        根据全局变量名返回其定义。注意：只有 g_ 开头的变量才会被索引为全局变量。
        需要阅读全局变量定义时优先使用本 deephole-code MCP 工具；仅在索引不可用、
        未命中或需要目录级枚举/文本搜索时，再回退内置 read/grep/glob。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找的全局变量名称。

        返回：
            全局变量定义代码，未找到则返回提示。
        """
        _mcp_log_call("view_global_variable_definition", f"name={global_variable_name!r}")
        db = _get_db(project_id, bound_project_dir)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log_return("view_global_variable_definition", result)
            return result
        rows = db.get_global_variables_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}'。"
            _mcp_log_return("view_global_variable_definition", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log_return(
            "view_global_variable_definition",
            _mcp_result_summary("match(es)", len(rows), result),
        )
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
        _mcp_log_call("find_function_references", f"function_name={function_name!r}")
        db = _get_db(project_id, bound_project_dir)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log_return("find_function_references", result)
            return result
        rows = db.get_call_sites_by_name(function_name)
        short_name_fallback = False
        if not rows and "::" in function_name:
            short_name = function_name.rsplit("::", 1)[-1]
            rows = db.get_call_sites_by_name(short_name)
            short_name_fallback = bool(rows)
        if not rows:
            result = f"未找到函数 '{function_name}' 的引用位置。"
            _mcp_log_return("find_function_references", result)
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
        _mcp_log_return("find_function_references", _mcp_result_summary("reference(s)", len(rows), result))
        return result

    # Kept for future reuse, but intentionally not registered as an MCP tool.
    def find_global_variable_references(
        project_id: str,
        global_variable_name: str,
    ) -> str:
        """
        查找某个全局变量在整个项目中所有被引用的位置。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找引用的全局变量名称。

        返回：
            每行一个引用，格式为 "引用函数名  文件路径:行号  访问类型  引用代码行"。
        """
        _mcp_log_call("find_global_variable_references", f"name={global_variable_name!r}")
        db = _get_db(project_id, bound_project_dir)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log_return("find_global_variable_references", result)
            return result
        rows = db.get_global_variable_reference_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}' 的引用。"
            _mcp_log_return("find_global_variable_references", result)
            return result
        result = "\n".join(
            f"{row['function_name'] or '未知'}  {row['file_path']}:{row['line']}  [{row['access_type']}]  {row['context']}"
            for row in rows
        )
        _mcp_log_return(
            "find_global_variable_references",
            _mcp_result_summary("reference(s)", len(rows), result),
        )
        return result

    @mcp.tool()
    def submit_result(
        confirmed: bool,
        severity: str,
        description: str,
        ai_analysis: str,
        vulnerability_report: str = "",
        file: str = "",
        line: int = 0,
        function: str = "",
        ctx: Context | None = None,
    ) -> str:
        """
        提交本次漏洞分析的最终结论。分析完成后必须调用此工具，否则结果将丢失。

        参数：
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
        payload = {
            "confirmed": confirmed,
            "severity": severity,
            "description": description,
            "ai_analysis": ai_analysis,
            "vulnerability_report": vulnerability_report,
            "file": file,
            "line": line,
            "function": function,
        }
        session_id = _opencode_session_from_context(ctx)
        _mcp_log_call("submit_result", _json_preview({
            "session_id": session_id,
            **payload,
        }))
        ok, message = _submit_payload("submit_result", ctx, payload)
        _mcp_log_return("submit_result", message)
        return message

    @mcp.tool()
    def submit_history_pattern(
        security_related: bool,
        pattern: str = "",
        lens_hint: str = "",
        files: str = "",
        rationale: str = "",
        ctx: Context | None = None,
    ) -> str:
        """
        提交一条 git 历史提交的安全问题模式判定结论。分析完单条提交后必须调用此工具。

        参数：
            security_related: 该提交是否是一次安全修复。
            pattern: 若相关，提炼出的可复用问题模式（根因 + 缺陷类型 + 触发条件的抽象描述，不要只抄提交标题）。
            lens_hint: 安全视角，可选值 memory/integer/race/injection/authn/crypto/dos/infoleak。
            files: 涉及的文件，逗号分隔。
            rationale: 判定理由 + 改动要点摘要。

        返回：
            提交成功的确认消息。
        """
        file_list = [s.strip() for s in str(files or "").replace("\n", ",").split(",") if s.strip()]
        payload = {
            "kind": "history_pattern",
            "security_related": bool(security_related),
            "pattern": pattern,
            "lens_hint": lens_hint,
            "files": file_list,
            "rationale": rationale,
        }
        session_id = _opencode_session_from_context(ctx)
        _mcp_log_call("submit_history_pattern", _json_preview({
            "session_id": session_id,
            "security_related": security_related,
            "pattern": pattern,
            "lens_hint": lens_hint,
            "files": files,
            "rationale": rationale,
        }))
        ok, message = _submit_payload("submit_history_pattern", ctx, payload)
        _mcp_log_return("submit_history_pattern", message)
        return message

    @mcp.tool()
    def submit_variant_finding(
        file: str,
        line: int,
        function: str,
        vuln_type: str,
        description: str,
        rationale: str = "",
        ctx: Context | None = None,
    ) -> str:
        """
        提交一处同类变体排查命中的疑似缺陷站点。每核实坐实一处即调用一次（可多次调用累加）。

        参数：
            file: 命中站点所在文件路径（相对项目根）。
            line: 命中站点行号。
            function: 命中站点所在函数。
            vuln_type: 缺陷类型，必须从分析提示给出的可选检查项列表中选一个。
            description: 一句话描述该处缺陷及其与历史问题模式的相似点。
            rationale: 可选，核实推理过程（为何该站点缺少等价校验/存在同类缺陷）。

        返回：
            提交成功的确认消息。
        """
        payload = {
            "kind": "variant_finding",
            "file": file,
            "line": line,
            "function": function,
            "vuln_type": vuln_type,
            "description": description,
            "rationale": rationale,
        }
        session_id = _opencode_session_from_context(ctx)
        _mcp_log_call("submit_variant_finding", _json_preview({
            "session_id": session_id,
            **payload,
        }))
        ok, message = _submit_payload("submit_variant_finding", ctx, payload)
        _mcp_log_return("submit_variant_finding", message)
        return message

    @mcp.tool()
    def submit_match_result(
        matched: bool,
        match_type: str = "",
        match_reference: str = "",
        description: str = "",
        ai_analysis: str = "",
        vulnerability_report: str = "",
        ctx: Context | None = None,
    ) -> str:
        """
        提交去误报「历史/校验匹配」阶段的结论。判断该候选是否能与历史问题模式或其它函数的
        正确校验对应上；若能对应，则直接判定为 high。

        参数：
            matched: 是否成立匹配（true 表示与历史问题或其它函数校验对应上，可直接定为 high）。
            match_type: 匹配类型，"history"（对应历史问题模式）或 "validation"（对应其它函数的正确校验）。
            match_reference: 对应的修复/校验描述：历史模式根因摘要+出处提交，或正确校验站点 path:line + 一句话说明。
            description: 一句话结论摘要。
            ai_analysis: 详细推理（含代码路径与匹配依据）。
            vulnerability_report: 匹配成立时填写的 Markdown 问题报告。

        返回：
            提交成功的确认消息。
        """
        payload = {
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
        }
        session_id = _opencode_session_from_context(ctx)
        _mcp_log_call("submit_match_result", _json_preview({
            "session_id": session_id,
            "matched": matched,
            "match_type": match_type,
            "match_reference": match_reference,
            "description": description,
            "ai_analysis": ai_analysis,
            "vulnerability_report": vulnerability_report,
        }))
        ok, message = _submit_payload("submit_match_result", ctx, payload)
        _mcp_log_return("submit_match_result", message)
        return message
