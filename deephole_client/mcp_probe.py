"""Side-effect-free MCP connectivity and tool-discovery probes."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

_MAX_PROBE_SECONDS = 30
_MAX_ERROR_LENGTH = 2000
_cleanup_tasks: set[asyncio.Task[Any]] = set()
_SECRET_PATTERN = re.compile(
    r"(?i)(authorization|api[-_]?key|access[-_]?token|token|secret|password)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)


def _value(config: dict[str, Any], name: str, default: Any = None) -> Any:
    value = config.get(name, default)
    return default if value is None else value


def _secret_values(config: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for section_name in ("local", "remote"):
        section = config.get(section_name)
        if not isinstance(section, dict):
            continue
        mapping_name = "environment" if section_name == "local" else "headers"
        mapping = section.get(mapping_name)
        if not isinstance(mapping, dict):
            continue
        values.extend(str(value) for value in mapping.values() if str(value))
    return sorted(set(values), key=len, reverse=True)


def _sanitized_error(exc: BaseException, config: dict[str, Any]) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    for value in _secret_values(config):
        message = message.replace(value, "***")
    message = _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}***", message)
    return message[:_MAX_ERROR_LENGTH]


def _finish_cancelled_probe(task: asyncio.Task[Any]) -> None:
    _cleanup_tasks.discard(task)
    try:
        task.exception()
    except BaseException:
        pass


def _cancel_probe_in_background(task: asyncio.Task[Any]) -> None:
    task.cancel()
    _cleanup_tasks.add(task)
    task.add_done_callback(_finish_cancelled_probe)


async def _run_with_timeout(coroutine: Any, timeout: float) -> Any:
    """Return at the deadline while transport shutdown finishes in the background."""
    task = asyncio.create_task(coroutine)
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout)
    except BaseException:
        _cancel_probe_in_background(task)
        raise
    if task in done:
        return await task
    _cancel_probe_in_background(task)
    raise asyncio.TimeoutError


async def _list_tools(read_stream: Any, write_stream: Any) -> list[str]:
    async with ClientSession(read_stream, write_stream) as session:
        await session.initialize()
        result = await session.list_tools()
    return sorted({str(tool.name) for tool in result.tools if str(tool.name).strip()})


def _resolve_local_executable(executable: str) -> str:
    resolved = shutil.which(executable)
    if resolved:
        return resolved
    candidate = Path(executable).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    raise FileNotFoundError(f"MCP executable not found: {executable}")


async def _probe_local(config: dict[str, Any]) -> tuple[str, list[str]]:
    local = config.get("local")
    if not isinstance(local, dict):
        local = {}
    executable = str(_value(local, "executable", "")).strip()
    if not executable:
        raise ValueError("MCP executable is empty")
    args = [str(item) for item in (_value(local, "args", []) or [])]
    configured_environment = _value(local, "environment", {})
    environment = dict(os.environ)
    if isinstance(configured_environment, dict):
        environment.update({str(key): str(value) for key, value in configured_environment.items()})

    from deephole_client.opencode_integration import get_global_opencode_workspace

    parameters = StdioServerParameters(
        command=_resolve_local_executable(executable),
        args=args,
        env=environment,
        cwd=get_global_opencode_workspace(),
    )
    tools: list[str] | None = None
    with open(os.devnull, "w", encoding="utf-8") as error_log:
        async with stdio_client(parameters, errlog=error_log) as (read_stream, write_stream):
            tools = await _list_tools(read_stream, write_stream)
    if tools is None:
        raise asyncio.CancelledError
    return "stdio", tools


async def _probe_streamable_http(url: str, headers: dict[str, str], timeout: float) -> list[str]:
    async with streamablehttp_client(
        url,
        headers=headers or None,
        timeout=timeout,
        sse_read_timeout=timeout,
    ) as (read_stream, write_stream, _):
        return await _list_tools(read_stream, write_stream)


async def _probe_sse(url: str, headers: dict[str, str], timeout: float) -> list[str]:
    async with sse_client(
        url,
        headers=headers or None,
        timeout=timeout,
        sse_read_timeout=timeout,
    ) as (read_stream, write_stream):
        return await _list_tools(read_stream, write_stream)


async def _probe_remote(config: dict[str, Any], timeout: float) -> tuple[str, list[str]]:
    remote = config.get("remote")
    if not isinstance(remote, dict):
        remote = {}
    url = str(_value(remote, "url", "")).strip()
    if not url:
        raise ValueError("MCP remote URL is empty")
    raw_headers = _value(remote, "headers", {})
    headers = (
        {str(key): str(value) for key, value in raw_headers.items()}
        if isinstance(raw_headers, dict)
        else {}
    )
    try:
        return "streamable_http", await _probe_streamable_http(url, headers, timeout)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        streamable_error = _sanitized_error(exc, config)
    try:
        return "sse", await _probe_sse(url, headers, timeout)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        sse_error = _sanitized_error(exc, config)
        raise RuntimeError(
            f"Streamable HTTP failed: {streamable_error}; SSE failed: {sse_error}"
        ) from exc


async def probe_mcp_config(target: str, config: dict[str, Any]) -> dict[str, Any]:
    """Initialize one configured MCP and list its tools without invoking them."""
    timeout = min(
        _MAX_PROBE_SECONDS,
        max(1, int(_value(config, "timeout_seconds", _MAX_PROBE_SECONDS))),
    )
    transport = str(_value(config, "transport", "local") or "local")
    started = time.monotonic()
    try:
        if not bool(_value(config, "enabled", False)):
            raise ValueError("MCP is disabled")
        if transport == "local":
            protocol, tool_names = await _run_with_timeout(_probe_local(config), float(timeout))
        elif transport == "remote":
            protocol, tool_names = await _run_with_timeout(
                _probe_remote(config, float(timeout)), float(timeout)
            )
        else:
            raise ValueError(f"Unsupported MCP transport: {transport}")
        return {
            "target": target,
            "success": True,
            "transport": transport,
            "protocol": protocol,
            "tool_names": tool_names,
            "tool_count": len(tool_names),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "error": "",
        }
    except asyncio.TimeoutError:
        error = RuntimeError(f"MCP probe timed out after {timeout} seconds")
    except Exception as exc:
        error = exc
    return {
        "target": target,
        "success": False,
        "transport": transport,
        "protocol": "",
        "tool_names": [],
        "tool_count": 0,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "error": _sanitized_error(error, config),
    }
