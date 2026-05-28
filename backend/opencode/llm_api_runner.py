"""LLM API 直调模式 — 通过 OpenAI 兼容 API + function calling 进行漏洞审计。

作为 opencode CLI 模式的替代方案，直接调用 LLM API 并通过 function calling
让模型查询代码、提交分析结果。结果文件格式与 MCP submit_result 完全一致。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from uuid import uuid4

from backend.config import get_config
from backend.logger import get_logger
from backend.models import Candidate, Vulnerability

logger = get_logger(__name__)


class LLMApiUnavailableError(RuntimeError):
    """Raised when the configured LLM API cannot be used."""


_api_health_cache: dict[tuple[str, str, str, float], tuple[bool, str]] = {}
_api_health_lock = threading.Lock()

# 按 project 缓存 DB 连接，避免每次 _get_db() 都创建新 SQLite 连接导致 FD 泄漏
_db_cache: dict[str, object] = {}


def _cfg_value(obj, name: str, default):
    return getattr(obj, name, default)


def _api_config_key(llm_cfg) -> tuple[str, str, str, float]:
    api_key = _cfg_value(llm_cfg, "api_key", "") or ""
    api_key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest() if api_key else ""
    timeout = float(_cfg_value(llm_cfg, "timeout", 300) or 300)
    return (
        _cfg_value(llm_cfg, "base_url", "") or "",
        api_key_hash,
        _cfg_value(llm_cfg, "model", "gpt-4o-mini") or "gpt-4o-mini",
        timeout,
    )


def _client_kwargs(llm_cfg, *, timeout_override: float | None = None) -> dict:
    kwargs: dict = {}
    base_url = _cfg_value(llm_cfg, "base_url", "") or ""
    api_key = _cfg_value(llm_cfg, "api_key", "") or ""
    timeout = timeout_override if timeout_override is not None else _cfg_value(llm_cfg, "timeout", 300)
    if base_url:
        kwargs["base_url"] = base_url
    if api_key:
        kwargs["api_key"] = api_key
    if timeout:
        kwargs["timeout"] = timeout
    return kwargs


def _create_openai_client(llm_cfg, *, timeout_override: float | None = None):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise LLMApiUnavailableError("openai SDK 未安装，无法使用 API 直调模式") from exc

    try:
        return OpenAI(**_client_kwargs(llm_cfg, timeout_override=timeout_override))
    except Exception as exc:
        raise LLMApiUnavailableError(f"LLM API 客户端初始化失败: {exc}") from exc


def mark_llm_api_unavailable(reason: str) -> None:
    """Remember that the current LLM API configuration failed in this process."""
    llm_cfg = get_config().llm_api
    with _api_health_lock:
        _api_health_cache[_api_config_key(llm_cfg)] = (False, reason)


def _probe_llm_api(llm_cfg) -> tuple[bool, str]:
    model = _cfg_value(llm_cfg, "model", "gpt-4o-mini") or "gpt-4o-mini"
    timeout = float(_cfg_value(llm_cfg, "timeout", 300) or 300)
    probe_timeout = max(1.0, min(timeout, 10.0))

    try:
        client = _create_openai_client(llm_cfg, timeout_override=probe_timeout)
        client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "health check"},
                {"role": "user", "content": "ok"},
            ],
            temperature=0,
            max_tokens=1,
        )
    except LLMApiUnavailableError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)

    return True, ""


def probe_llm_api_config(llm_cfg) -> tuple[bool, str]:
    """Validate an explicit LLM API config without using the global app config."""
    return _probe_llm_api(llm_cfg)


async def ensure_llm_api_available(on_output=None) -> None:
    """Check that the configured LLM API can answer a minimal request."""
    llm_cfg = get_config().llm_api
    key = _api_config_key(llm_cfg)

    with _api_health_lock:
        cached = _api_health_cache.get(key)
    if cached is not None:
        available, reason = cached
        if available:
            return
        raise LLMApiUnavailableError(reason)

    if on_output:
        on_output("[API] 正在检测 API 配置可用性...")

    available, reason = _probe_llm_api(llm_cfg)
    with _api_health_lock:
        _api_health_cache[key] = (available, reason)

    if not available:
        raise LLMApiUnavailableError(reason)

    if on_output:
        on_output("[API] API 配置可用")


def _emit_initial_api_prompt(on_output, messages: list[dict]) -> None:
    """Print the complete initial prompt sent to the LLM API."""
    if not on_output:
        return

    sections = ["[API] 初始提示词"]
    for message in messages:
        role = message.get("role", "unknown")
        content = message.get("content") or ""
        sections.append(f"--- {role} ---\n{content}")
    on_output("\n".join(sections))


# ---------------------------------------------------------------------------
# System prompt（移植自 llm_reviewer.py，适配 function calling）
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
你是一个专业的 C/C++ 代码审计专家，专门判断静态扫描器报告的漏洞候选是否是真实的 bug。

你会收到一个被扫描出可疑点的函数源码和相关上下文。你可以使用工具查看更多函数定义和结构体定义。

## 判定标准

**判为误报 (false_positive) 的常见情形**：
1. 判空分支里的退出 — 如 `if (p == NULL) return;`，此时 p 本就是 NULL，无需释放
2. 该资源在此条路径上还没被分配/填充
3. 资源所有权已转移 — 如被存入结构体、作为返回值返回给调用者
4. 资源通过消息发送/投递接口转移（SendMsg/PostMsg/Enqueue/Dispatch 等）
5. 已通过其他形式释放（析构函数、智能指针、全局清理函数）
6. 栈上纯值资源，不持有堆内存
7. 测试/桩代码（路径含 dt/stub/test 等）

**判为真实 bug (true_bug) 的条件**：
- 变量在当前路径上确实被分配/填充了资源
- 异常路径的退出前没有调用释放函数，也没有通过其他方式转移所有权
- 函数的其他路径上有明确的释放调用作为对照

## 工作流程
1. 阅读提供的函数源码和候选信息
2. 如需查看其他函数或结构体定义，调用相应工具
3. 分析完毕后，**必须**调用 submit_result 工具提交结论

注意：分析完成后你 **必须** 调用 submit_result 提交结论，否则结果将丢失。
"""

# ---------------------------------------------------------------------------
# Function calling tools 定义
# ---------------------------------------------------------------------------

SUBMIT_RESULT_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_result",
        "description": "提交漏洞分析的最终结论。分析完成后必须调用此工具。",
        "parameters": {
            "type": "object",
            "properties": {
                "confirmed": {
                    "type": "boolean",
                    "description": "是否存在真实漏洞。true=确认漏洞，false=误报",
                },
                "severity": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                    "description": "严重程度（仅 confirmed=true 时有意义）",
                },
                "description": {
                    "type": "string",
                    "description": "漏洞的一句话摘要",
                },
                "ai_analysis": {
                    "type": "string",
                    "description": "详细的分析推理过程，需包含具体的代码路径",
                },
                "vulnerability_report": {
                    "type": "string",
                    "description": "可选 Markdown 漏洞报告，外部可触发高风险漏洞时填写",
                },
                "file": {
                    "type": "string",
                    "description": "可选，真实问题所在文件路径；项目级审计发现问题时必须填写",
                },
                "line": {
                    "type": "integer",
                    "description": "可选，真实问题所在行号；项目级审计发现问题时必须填写",
                },
                "function": {
                    "type": "string",
                    "description": "可选，真实问题所在函数；项目级审计发现问题时必须填写",
                },
            },
            "required": ["confirmed", "severity", "description", "ai_analysis"],
        },
    },
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "view_function_code",
            "description": "查看指定函数的完整源码。用于查看释放函数或相关调用函数的实现。",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "要查看的函数名",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "可选，函数所在文件路径；用于区分 C++ 同名成员函数",
                    },
                },
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "view_struct_code",
            "description": "查看指定结构体/类的定义。用于了解数据结构的字段和内存布局。",
            "parameters": {
                "type": "object",
                "properties": {
                    "struct_name": {
                        "type": "string",
                        "description": "要查看的结构体或类名",
                    },
                },
                "required": ["struct_name"],
            },
        },
    },
    SUBMIT_RESULT_TOOL,
]

# single_pass 模式：仅提供 submit_result，不提供查询工具
TOOLS_SINGLE_PASS = [SUBMIT_RESULT_TOOL]

# 批量提交工具 — 一次性提交同函数内多个候选的分析结果
SUBMIT_BATCH_RESULT_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_batch_result",
        "description": "批量提交同一函数内多个漏洞候选的分析结论。每个候选用行号标识。",
        "parameters": {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "description": "每个候选的分析结果",
                    "items": {
                        "type": "object",
                        "properties": {
                            "line": {
                                "type": "integer",
                                "description": "候选所在行号",
                            },
                            "confirmed": {
                                "type": "boolean",
                                "description": "是否存在真实漏洞",
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["high", "medium", "low"],
                                "description": "严重程度",
                            },
                            "description": {
                                "type": "string",
                                "description": "漏洞的一句话摘要",
                            },
                            "ai_analysis": {
                                "type": "string",
                                "description": "详细的分析推理过程",
                            },
                        },
                        "required": ["line", "confirmed", "severity", "description", "ai_analysis"],
                    },
                },
            },
            "required": ["results"],
        },
    },
}

# 批量模式工具集
TOOLS_BATCH = [
    {
        "type": "function",
        "function": {
            "name": "view_function_code",
            "description": "查看指定函数的完整源码。用于查看释放函数或相关调用函数的实现。",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "要查看的函数名",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "可选，函数所在文件路径；用于区分 C++ 同名成员函数",
                    },
                },
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "view_struct_code",
            "description": "查看指定结构体/类的定义。用于了解数据结构的字段和内存布局。",
            "parameters": {
                "type": "object",
                "properties": {
                    "struct_name": {
                        "type": "string",
                        "description": "要查看的结构体或类名",
                    },
                },
                "required": ["struct_name"],
            },
        },
    },
    SUBMIT_BATCH_RESULT_TOOL,
]


# ---------------------------------------------------------------------------
# Tool 执行
# ---------------------------------------------------------------------------

def _execute_tool(
    tool_name: str,
    args: dict,
    project_id: str,
    result_id: str,
) -> tuple[str, bool]:
    """执行 function call tool，返回 (结果文本, 是否为 submit_result)。"""
    config = get_config()

    if tool_name == "view_function_code":
        return _tool_view_function(args, project_id), False

    if tool_name == "view_struct_code":
        return _tool_view_struct(args, project_id), False

    if tool_name == "submit_result":
        return _tool_submit_result(args, result_id, config.storage.scans_dir), True

    return f"未知工具: {tool_name}", False


def _get_db(project_id: str):
    """获取项目的 CodeDatabase 实例（缓存复用，避免 FD 泄漏）。"""
    from code_parser import CodeDatabase

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

    cache_key = project_id
    if cache_key in _db_cache:
        return _db_cache[cache_key]
    config = get_config()
    db_path = Path(config.storage.projects_dir) / project_id / "code_index.db"
    if not db_path.exists():
        return None
    db = CodeDatabase(db_path)
    if not db.is_index_complete():
        db.close()
        return None
    _db_cache[cache_key] = db
    return db


def _close_db_cache():
    """关闭所有缓存的 DB 连接。扫描结束时由 scanner.py 调用。"""
    for db in _db_cache.values():
        try:
            db.close()
        except Exception:
            pass
    _db_cache.clear()


def _tool_view_function(args: dict, project_id: str) -> str:
    func_name = args.get("function_name", "")
    if not func_name:
        return "错误: 缺少 function_name 参数"
    file_path = args.get("file_path") or None

    db = _get_db(project_id)
    if db is None:
        return f"无法加载代码索引"

    rows = db.get_functions_by_name(func_name, file_path=file_path)
    if not rows:
        return f"未找到函数 {func_name} 的定义"

    parts = []
    for row in rows[:3]:  # 最多返回 3 个同名函数
        body = row["body"] or "(无函数体)"
        file_path = row["file_path"]
        start_line = row["start_line"]
        # 添加行号
        lines = body.split("\n")
        numbered = "\n".join(
            f"{start_line + i:4d} | {ln}" for i, ln in enumerate(lines)
        )
        parts.append(f"// 文件: {file_path}:{start_line}\n{numbered}")

    return "\n\n".join(parts)


def _tool_view_struct(args: dict, project_id: str) -> str:
    struct_name = args.get("struct_name", "")
    if not struct_name:
        return "错误: 缺少 struct_name 参数"

    db = _get_db(project_id)
    if db is None:
        return f"无法加载代码索引"

    rows = db.get_structs_by_name(struct_name)
    if not rows:
        return f"未找到结构体 {struct_name} 的定义"

    parts = []
    for row in rows[:3]:
        definition = row["definition"] or "(无定义体)"
        file_path = row["file_path"]
        start_line = row["start_line"]
        parts.append(f"// 文件: {file_path}:{start_line}\n{definition}")

    return "\n\n".join(parts)


def _tool_submit_result(args: dict, result_id: str, scans_dir: str) -> str:
    result_path = Path(scans_dir) / f"{result_id}.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "confirmed": args.get("confirmed", False),
        "severity": args.get("severity", "unknown"),
        "description": args.get("description", ""),
        "ai_analysis": args.get("ai_analysis", ""),
        "vulnerability_report": args.get("vulnerability_report", ""),
        "file": args.get("file", ""),
        "line": args.get("line", 0),
        "function": args.get("function", ""),
    }
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
    return f"结果已提交（result_id={result_id}）"


# ---------------------------------------------------------------------------
# User prompt 构建
# ---------------------------------------------------------------------------

def _select_function_row_for_candidate(rows: list, line: int):
    """Pick the indexed function containing the candidate line when possible."""
    for row in rows:
        start_line = row["start_line"] or 0
        end_line = row["end_line"] or 0
        if start_line <= line <= end_line:
            return row
    return rows[0]


def _find_candidate_function_row(db, function_name: str, file_path: str, line: int):
    """Find candidate function source by name first, then by indexed file range."""
    rows = db.get_functions_by_name(function_name, file_path=file_path)
    if rows:
        return _select_function_row_for_candidate(rows, line)
    if file_path:
        return db.get_function_by_location(file_path, line)
    return None


def _append_function_source_section(lines: list[str], row, *, title: str = "函数源码") -> None:
    lines.append(f"## {title}")
    if row is None:
        lines.append("```c")
        lines.append("")
        lines.append("```")
        return

    body = row["body"] or ""
    start_line = row["start_line"]
    file_path = row["file_path"]
    body_lines = body.split("\n")
    numbered = "\n".join(
        f"{start_line + i:4d} | {ln}" for i, ln in enumerate(body_lines)
    )
    lines[-1] = f"## {title} ({file_path}:{start_line})"
    lines.append("```c")
    lines.append(numbered)
    lines.append("```")


def _build_user_prompt(candidate: Candidate, project_id: str) -> str:
    """构建发给 LLM 的用户提示，包含函数源码和候选信息。"""
    lines = []
    lines.append(f"## 被审计的候选漏洞")
    lines.append(f"- 文件: {candidate.file}")
    lines.append(f"- 行号: {candidate.line}")
    lines.append(f"- 函数: {candidate.function}")
    lines.append(f"- 漏洞类型: {candidate.vuln_type}")
    lines.append(f"- 静态分析描述: {candidate.description}")
    lines.append("")

    # 尝试获取函数源码
    db = _get_db(project_id)
    if db is not None:
        row = _find_candidate_function_row(
            db, candidate.function, candidate.file, candidate.line
        )
        _append_function_source_section(lines, row)
    else:
        _append_function_source_section(lines, None)

    # 内嵌相关函数源码（如释放函数），避免 LLM 需要调用查询工具
    if candidate.related_functions and db is not None:
        found_any = False
        for rf_name in candidate.related_functions:
            rf_rows = db.get_functions_by_name(rf_name)
            if rf_rows:
                if not found_any:
                    lines.append("")
                    lines.append("## 相关函数源码")
                    found_any = True
                for rf_row in rf_rows[:2]:  # 同名函数最多展示 2 个
                    rf_body = rf_row["body"] or "(无函数体)"
                    rf_start = rf_row["start_line"]
                    rf_file = rf_row["file_path"]
                    rf_lines = rf_body.split("\n")
                    rf_numbered = "\n".join(
                        f"{rf_start + i:4d} | {ln}" for i, ln in enumerate(rf_lines)
                    )
                    lines.append(f"\n### {rf_name} ({rf_file}:{rf_start})")
                    lines.append("```c")
                    lines.append(rf_numbered)
                    lines.append("```")

    lines.append("")
    lines.append("## 任务")
    # 检查是否 single_pass 模式
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidate.vuln_type)
    if checker_entry and checker_entry.single_pass:
        lines.append(
            f"请根据上面提供的函数源码，分析第 {candidate.line} 行的代码是否存在真实漏洞。"
            f"分析完毕后，**必须**调用 submit_result 提交结论。"
        )
    else:
        lines.append(
            f"请分析第 {candidate.line} 行的代码是否存在真实漏洞。"
            f"如果需要查看其他函数或结构体的定义，请使用相应工具。"
            f"分析完毕后，**必须**调用 submit_result 提交结论。"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 核心：LLM API 调用 + function calling 循环
# ---------------------------------------------------------------------------

async def run_audit_via_api(
    candidate: Candidate,
    project_id: str,
    prompt_path: Path | None = None,
    on_output=None,
    cancel_event=None,
) -> Vulnerability | None:
    """通过 LLM API + function calling 审计单个候选漏洞。"""
    config = get_config()
    llm_cfg = config.llm_api
    result_id = uuid4().hex

    # 检查该 checker 是否为 single_pass 模式（单次 API 调用，仅 submit_result）
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidate.vuln_type)
    single_pass = checker_entry.single_pass if checker_entry else False

    logger.info(
        "LLM API audit: %s:%d (%s) result_id=%s single_pass=%s",
        candidate.file, candidate.line, candidate.vuln_type, result_id, single_pass,
    )

    # 构建 OpenAI 客户端
    client = _create_openai_client(llm_cfg)

    # 加载 system prompt：优先使用 checker 目录下的 prompt.txt
    system_prompt = SYSTEM_PROMPT
    if prompt_path and prompt_path.is_file():
        system_prompt = prompt_path.read_text(encoding="utf-8")

    # 构建初始消息
    user_prompt = _build_user_prompt(candidate, project_id)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    if on_output:
        on_output(f"[API] 开始审计 {candidate.file}:{candidate.line}")
    _emit_initial_api_prompt(on_output, messages)

    # 选择工具集：single_pass 模式仅提供 submit_result
    tools = TOOLS_SINGLE_PASS if single_pass else TOOLS
    # single_pass 模式只需 1 轮（LLM 直接返回 submit_result）
    max_rounds = 1 if single_pass else 10
    submitted = False

    for round_idx in range(max_rounds):
        if cancel_event and cancel_event.is_set():
            return None

        try:
            _cancel_fn = cancel_event.is_set if cancel_event else None
            llm_task = asyncio.create_task(asyncio.to_thread(
                _call_llm, client, llm_cfg.model, messages,
                llm_cfg.temperature, llm_cfg.max_retries, tools,
                cancel_check=_cancel_fn,
                stream=llm_cfg.stream,
            ))
            if cancel_event:
                async def _wait_cancel():
                    while not cancel_event.is_set():
                        await asyncio.sleep(0.2)
                cancel_task = asyncio.create_task(_wait_cancel())
                done, pending = await asyncio.wait(
                    [llm_task, cancel_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
                if cancel_event.is_set():
                    return None
                resp = llm_task.result()
            else:
                resp = await llm_task
        except Exception as e:
            if cancel_event and cancel_event.is_set():
                return None
            logger.error("LLM API 调用失败: %s", e)
            if on_output:
                on_output(f"[API] LLM 调用失败: {e}")
            reason = f"LLM API 调用失败: {e}"
            mark_llm_api_unavailable(reason)
            raise LLMApiUnavailableError(reason) from e

        choice = resp.choices[0]
        message = choice.message

        # 追加 assistant 消息到历史
        messages.append(message.model_dump(exclude_none=True))

        # 始终输出 LLM 的文本内容（分析过程）
        if on_output and message.content:
            on_output(f"[API] {message.content[:200]}")

        # 如果没有 tool_calls，说明 LLM 直接返回了文本
        if not message.tool_calls:
            # 尝试从文本内容中解析 JSON 结果
            if not submitted and message.content:
                submitted = _try_parse_text_result(
                    message.content, result_id, config.storage.scans_dir
                )
            break

        # 处理 tool_calls
        for tool_call in message.tool_calls:
            func_name = tool_call.function.name
            try:
                func_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                func_args = {}

            if on_output:
                on_output(f"[API] 调用工具: {func_name}({json.dumps(func_args, ensure_ascii=False)[:100]})")

            result_text, is_submit = _execute_tool(
                func_name, func_args, project_id, result_id,
            )

            if is_submit:
                submitted = True
                if on_output:
                    on_output(f"[API] 结果已提交")
                break

            # 追加 tool 结果到消息历史
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_text[:4000],  # 限制长度
            })

        if submitted:
            break

    if not submitted:
        logger.warning(
            "LLM 未调用 submit_result: %s:%d (result_id=%s)",
            candidate.file, candidate.line, result_id,
        )
        if on_output:
            on_output(f"[API] 警告: LLM 未提交结果")

    # 读取结果文件（与 opencode 模式共用 _read_result）
    from backend.opencode.runner import _read_result
    return _read_result(result_id, candidate)


def _accumulate_stream(stream_iter, model: str, cancel_check=None):
    """消费流式响应迭代器，累积为完整的 ChatCompletion 对象。"""
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice
    from openai.types.chat.chat_completion_message_tool_call import (
        ChatCompletionMessageToolCall, Function,
    )

    content_parts: list[str] = []
    tool_calls: dict[int, dict] = {}  # index -> {"id", "name", "arguments"}
    finish_reason = None

    for chunk in stream_iter:
        if cancel_check and cancel_check():
            stream_iter.close()
            raise RuntimeError("Cancelled")

        if not chunk.choices:
            continue

        delta = chunk.choices[0].delta

        if delta.content:
            content_parts.append(delta.content)

        if delta.tool_calls:
            for tc_delta in delta.tool_calls:
                idx = tc_delta.index
                if idx not in tool_calls:
                    tool_calls[idx] = {"id": "", "name": "", "arguments": ""}
                if tc_delta.id:
                    tool_calls[idx]["id"] = tc_delta.id
                if tc_delta.function:
                    if tc_delta.function.name:
                        tool_calls[idx]["name"] = tc_delta.function.name
                    if tc_delta.function.arguments:
                        tool_calls[idx]["arguments"] += tc_delta.function.arguments

        if chunk.choices[0].finish_reason:
            finish_reason = chunk.choices[0].finish_reason

    # 构建完整响应对象
    tc_list = None
    if tool_calls:
        tc_list = [
            ChatCompletionMessageToolCall(
                id=tool_calls[idx]["id"],
                type="function",
                function=Function(
                    name=tool_calls[idx]["name"],
                    arguments=tool_calls[idx]["arguments"],
                ),
            )
            for idx in sorted(tool_calls.keys())
        ]

    content = "".join(content_parts) if content_parts else None
    message = ChatCompletionMessage(
        role="assistant",
        content=content,
        tool_calls=tc_list,
    )

    return ChatCompletion(
        id="stream-accumulated",
        choices=[Choice(
            index=0,
            message=message,
            finish_reason=finish_reason or "stop",
        )],
        created=int(time.time()),
        model=model,
        object="chat.completion",
    )


def _call_llm(client, model: str, messages: list, temperature: float, max_retries: int, tools: list | None = None, cancel_check=None, stream: bool = False):
    """同步调用 LLM API（在 asyncio.to_thread 中执行）。"""
    if tools is None:
        tools = TOOLS
    last_err = None
    for attempt in range(max_retries):
        if cancel_check and cancel_check():
            raise RuntimeError("Cancelled")
        try:
            if stream:
                stream_iter = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    temperature=temperature,
                    stream=True,
                )
                return _accumulate_stream(stream_iter, model, cancel_check)
            else:
                return client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    temperature=temperature,
                )
        except Exception as e:
            last_err = e
            if attempt < max_retries - 1:
                if cancel_check and cancel_check():
                    raise RuntimeError("Cancelled")
                time.sleep(2 ** attempt)
    raise RuntimeError(f"LLM API 调用失败（重试 {max_retries} 次）: {last_err}")


def _try_parse_text_result(content: str, result_id: str, scans_dir: str) -> bool:
    """尝试从 LLM 的文本回复中解析 JSON 结果（兜底）。"""
    import re

    # 尝试提取 JSON 块
    json_match = re.search(r'\{[^{}]*"confirmed"\s*:', content)
    if not json_match:
        return False

    # 找到匹配的右括号
    start = json_match.start()
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                try:
                    data = json.loads(content[start:i + 1])
                    _tool_submit_result(data, result_id, scans_dir)
                    return True
                except (json.JSONDecodeError, Exception):
                    return False
    return False


# ---------------------------------------------------------------------------
# 批量审计：同一函数内多个候选一次性发给 LLM
# ---------------------------------------------------------------------------

MAX_BATCH_SIZE = 8  # 单次批量审计最大候选数


def _build_batch_user_prompt(candidates: list[Candidate], project_id: str) -> str:
    """构建批量审计的用户提示，一次函数源码 + 多个候选。"""
    # 所有候选属于同一函数
    func_name = candidates[0].function
    file_path = candidates[0].file
    vuln_type = candidates[0].vuln_type

    lines = []
    lines.append(f"## 被审计的函数")
    lines.append(f"- 文件: {file_path}")
    lines.append(f"- 函数: {func_name}")
    lines.append(f"- 漏洞类型: {vuln_type}")
    lines.append("")

    # 获取函数源码（只取一次）
    db = _get_db(project_id)
    if db is not None:
        row = _find_candidate_function_row(db, func_name, file_path, candidates[0].line)
        _append_function_source_section(lines, row)
    else:
        _append_function_source_section(lines, None)

    lines.append("")
    lines.append(f"## 候选漏洞点（共 {len(candidates)} 个）")
    lines.append("")
    for i, c in enumerate(candidates, 1):
        lines.append(f"### 候选 {i}（第 {c.line} 行）")
        lines.append(f"- 静态分析描述: {c.description}")
        lines.append("")

    lines.append("## 任务")
    lines.append(
        f"请逐一分析上述 {len(candidates)} 个候选漏洞点是否为真实 bug。"
        f"如果需要查看其他函数或结构体的定义，请使用相应工具。"
        f"分析完毕后，**必须**调用 submit_batch_result 一次性提交所有候选的结论，"
        f"results 数组中每个元素的 line 字段对应候选的行号。"
    )

    return "\n".join(lines)


def _execute_batch_tool(
    tool_name: str,
    args: dict,
    project_id: str,
    result_id_map: dict[int, str],
    scans_dir: str,
) -> tuple[str, bool]:
    """执行批量模式下的 function call tool。"""
    if tool_name == "view_function_code":
        return _tool_view_function(args, project_id), False

    if tool_name == "view_struct_code":
        return _tool_view_struct(args, project_id), False

    if tool_name == "submit_batch_result":
        results = args.get("results", [])
        submitted_lines = []
        for item in results:
            line = item.get("line")
            rid = result_id_map.get(line)
            if rid is None:
                # 行号不匹配任何候选，跳过
                continue
            _tool_submit_result(item, rid, scans_dir)
            submitted_lines.append(line)
        return f"已提交 {len(submitted_lines)} 个结果（行号: {submitted_lines}）", True

    return f"未知工具: {tool_name}", False


async def run_batch_audit_via_api(
    candidates: list[Candidate],
    project_id: str,
    prompt_path: Path | None = None,
    on_output=None,
    cancel_event=None,
) -> list[Vulnerability | None]:
    """通过 LLM API + function calling 批量审计同一函数内的多个候选。"""
    config = get_config()
    llm_cfg = config.llm_api

    # 为每个候选生成 result_id，建立 line -> result_id 映射
    result_id_map: dict[int, str] = {}
    candidate_by_line: dict[int, Candidate] = {}
    result_ids: dict[int, str] = {}
    for c in candidates:
        rid = uuid4().hex
        result_id_map[c.line] = rid
        candidate_by_line[c.line] = c
        result_ids[c.line] = rid

    func_name = candidates[0].function
    file_path = candidates[0].file
    logger.info(
        "LLM API batch audit: %s:%s (%d candidates)",
        file_path, func_name, len(candidates),
    )

    # 构建 OpenAI 客户端
    client = _create_openai_client(llm_cfg)

    # 加载 system prompt：优先使用 checker 目录下的 prompt.txt
    system_prompt = SYSTEM_PROMPT
    if prompt_path and prompt_path.is_file():
        system_prompt = prompt_path.read_text(encoding="utf-8")

    # 构建消息
    user_prompt = _build_batch_user_prompt(candidates, project_id)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    if on_output:
        on_output(f"[API] 批量审计 {file_path}:{func_name}（{len(candidates)} 个候选）")
    _emit_initial_api_prompt(on_output, messages)

    submitted = False
    max_rounds = 10

    for round_idx in range(max_rounds):
        if cancel_event and cancel_event.is_set():
            return [None] * len(candidates)

        try:
            llm_task = asyncio.create_task(asyncio.to_thread(
                _call_llm, client, llm_cfg.model, messages,
                llm_cfg.temperature, llm_cfg.max_retries, TOOLS_BATCH,
                cancel_check=cancel_event.is_set if cancel_event else None,
                stream=llm_cfg.stream,
            ))
            if cancel_event:
                async def _wait_cancel():
                    while not cancel_event.is_set():
                        await asyncio.sleep(0.2)
                cancel_task = asyncio.create_task(_wait_cancel())
                done, pending = await asyncio.wait(
                    [llm_task, cancel_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
                if cancel_event.is_set():
                    return [None] * len(candidates)
                resp = llm_task.result()
            else:
                resp = await llm_task
        except Exception as e:
            if cancel_event and cancel_event.is_set():
                return [None] * len(candidates)
            logger.error("LLM API 批量调用失败: %s", e)
            if on_output:
                on_output(f"[API] LLM 调用失败: {e}")
            reason = f"LLM API 批量调用失败: {e}"
            mark_llm_api_unavailable(reason)
            raise LLMApiUnavailableError(reason) from e

        choice = resp.choices[0]
        message = choice.message
        messages.append(message.model_dump(exclude_none=True))

        # 始终输出 LLM 的文本内容（分析过程）
        if on_output and message.content:
            on_output(f"[API] {message.content[:200]}")

        if not message.tool_calls:
            break

        for tool_call in message.tool_calls:
            func_name_tc = tool_call.function.name
            try:
                func_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                func_args = {}

            if on_output:
                on_output(f"[API] 调用工具: {func_name_tc}({json.dumps(func_args, ensure_ascii=False)[:100]})")

            result_text, is_submit = _execute_batch_tool(
                func_name_tc, func_args, project_id,
                result_id_map, config.storage.scans_dir,
            )

            if is_submit:
                submitted = True
                if on_output:
                    on_output(f"[API] 批量结果已提交")
                break

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result_text[:4000],
            })

        if submitted:
            break

    if not submitted:
        logger.warning(
            "LLM 未调用 submit_batch_result: %s:%s",
            file_path, func_name,
        )
        if on_output:
            on_output(f"[API] 警告: LLM 未提交批量结果")

    # 读取各候选的结果文件
    from backend.opencode.runner import _read_result
    results = []
    for c in candidates:
        rid = result_id_map[c.line]
        vuln = _read_result(rid, c)
        results.append(vuln)

    return results
