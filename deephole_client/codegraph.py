"""Optional CodeGraph preparation and per-project readiness state."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any, Callable


_ready_projects: set[Path] = set()
_project_locks: dict[Path, asyncio.Lock] = {}


def is_codegraph_mcp_available(config: Any) -> bool:
    """Return whether the configured CodeGraph MCP can actually be started."""
    code_graph = getattr(config, "code_graph", None)
    if code_graph is None or not bool(getattr(code_graph, "enabled", False)):
        return False
    if str(getattr(code_graph, "transport", "local")) == "remote":
        remote = getattr(code_graph, "remote", None)
        return bool(str(getattr(remote, "url", "") or "").strip())
    local = getattr(code_graph, "local", None)
    executable = str(getattr(local, "executable", "") or "codegraph").strip()
    return bool(shutil.which(executable) or Path(executable).is_file())


def is_codegraph_ready(directory: str | Path) -> bool:
    path = Path(directory).resolve()
    if any(path == root or root in path.parents for root in _ready_projects):
        return True
    # Readiness must survive an Agent restart.  Model tasks commonly run from
    # a subdirectory of the indexed project, so walk upward to the graph root.
    for root in (path, *path.parents):
        if (root / ".codegraph" / "codegraph.db").is_file():
            _ready_projects.add(root)
            return True
    return False


async def prepare_codegraph(
    config: Any,
    project_path: Path,
    *,
    emit: Callable[[str], Any] | None = None,
) -> bool:
    code_graph = getattr(config, "code_graph", None)
    if code_graph is None or not bool(getattr(code_graph, "enabled", False)):
        return False
    root = project_path.resolve()
    if str(getattr(code_graph, "transport", "local")) == "remote":
        if not is_codegraph_mcp_available(config):
            await _notify(emit, "CodeGraph 远端 URL 未配置，回退 deephole-code MCP")
            return False
        _ready_projects.add(root)
        return True
    local = getattr(code_graph, "local", None)
    executable = str(getattr(local, "executable", "") or "codegraph").strip()
    resolved = shutil.which(executable)
    if resolved is None and Path(executable).is_file():
        resolved = str(Path(executable).resolve())
    if not resolved:
        await _notify(emit, f"CodeGraph 可执行文件不存在：{executable}，回退 deephole-code MCP")
        return False
    lock = _project_locks.setdefault(root, asyncio.Lock())
    async with lock:
        if is_codegraph_ready(root):
            return True
        local_environment = {
            str(key): str(value)
            for key, value in (getattr(local, "environment", {}) or {}).items()
        }
        graph_dir = str(local_environment.get("CODEGRAPH_DIR") or ".codegraph").strip()
        database = root / graph_dir / "codegraph.db"
        if not database.is_file():
            await _notify(emit, "项目尚未建立 CodeGraph，正在执行 codegraph init -i")
            process_environment = os.environ.copy()
            process_environment.update(local_environment)
            proc = await asyncio.create_subprocess_exec(
                resolved,
                "init",
                "-i",
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=process_environment,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=max(1, int(getattr(code_graph, "timeout_seconds", 300))),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                await _notify(emit, "CodeGraph 初始化超时，回退 deephole-code MCP")
                return False
            if proc.returncode != 0:
                detail = stdout.decode("utf-8", errors="replace").strip()
                await _notify(emit, f"CodeGraph 初始化失败，回退 deephole-code MCP：{detail}")
                return False
        if not database.is_file():
            await _notify(emit, "CodeGraph 未生成 .codegraph/codegraph.db，回退 deephole-code MCP")
            return False
        _ready_projects.add(root)
        await _notify(emit, "CodeGraph 已就绪，模型源码查询切换到 CodeGraph MCP")
        return True


async def _notify(callback: Callable[[str], Any] | None, message: str) -> None:
    if callback is None:
        print(f"[codegraph] {message}", flush=True)
        return
    result = callback(message)
    if hasattr(result, "__await__"):
        await result
