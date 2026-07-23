"""The single public OpenCode task interface used by OpenDeepHole components."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import threading
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass, field
from os import PathLike
from pathlib import Path
from typing import Any, Callable, Literal


_SUPPORTED_TASK_TYPES = frozenset({
    "audit",
    "project_audit",
    "sensitive_clear",
    "report_audit",
    "threat_analysis",
    "threat_audit",
    "fp_review",
    "vulnerability_validation",
    "git_history",
    "variant_hunt",
    "memory_api_discovery",
    "skill_create",
})
_UNSET = object()
_COMPONENT_OWNER_LOOP: ContextVar[asyncio.AbstractEventLoop | None] = ContextVar(
    "task_agent_component_owner_loop",
    default=None,
)


def _standalone_console_output() -> Callable[[str], None]:
    def emit(line: str) -> None:
        text = str(line or "")
        if text:
            print(text, flush=True)

    return emit


@dataclass(frozen=True)
class OpenCodeResult:
    session_id: str
    status: Literal["success", "failure", "timeout"]
    text: str
    structured: Any
    model: str
    output_source: dict[str, Any] = field(default_factory=dict)


async def run_opencode_task(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    invalid_json_retry_prompt: str | None = None,
    session_id: str | None = None,
    config_path: str | PathLike[str] | None = None,
    output: Callable[[str], Any] | None | object = _UNSET,
    cancel_event: Any = _UNSET,
) -> OpenCodeResult:
    """Run one task, dispatching worker-thread calls to the owning event loop."""
    owner_loop = _COMPONENT_OWNER_LOOP.get()
    current_loop = asyncio.get_running_loop()
    coroutine = _run_opencode_task_local(
        task_name=task_name,
        task_type=task_type,
        prompt=prompt,
        required_capability=required_capability,
        output_schema=output_schema,
        invalid_json_retry_count=invalid_json_retry_count,
        invalid_json_retry_prompt=invalid_json_retry_prompt,
        session_id=session_id,
        config_path=config_path,
        output=output,
        cancel_event=cancel_event,
    )
    if owner_loop is None or owner_loop is current_loop:
        return await coroutine
    concurrent_future = asyncio.run_coroutine_threadsafe(coroutine, owner_loop)
    try:
        while not concurrent_future.done():
            await asyncio.sleep(0.01)
        return concurrent_future.result()
    except concurrent.futures.CancelledError as exc:
        raise asyncio.CancelledError from exc
    except BaseException:
        concurrent_future.cancel()
        raise


async def _run_opencode_task_local(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    invalid_json_retry_prompt: str | None = None,
    session_id: str | None = None,
    config_path: str | PathLike[str] | None = None,
    output: Callable[[str], Any] | None | object = _UNSET,
    cancel_event: Any = _UNSET,
) -> OpenCodeResult:
    """Run one OpenCode task using host-bound or standalone file configuration."""
    normalized_name = str(task_name or "").strip()
    normalized_prompt = str(prompt or "")
    if not normalized_name:
        raise ValueError("OpenCode task_name is required")
    if not normalized_prompt.strip():
        raise ValueError("OpenCode prompt is required")
    normalized_task_type = task_type.strip() if isinstance(task_type, str) else ""
    if normalized_task_type not in _SUPPORTED_TASK_TYPES:
        raise ValueError(f"Unsupported OpenCode task_type: {task_type!r}")
    capability = str(required_capability or "").strip().lower()
    if capability not in {"low", "high"}:
        raise ValueError("OpenCode required_capability must be 'low' or 'high'")
    if output_schema is not None and not isinstance(output_schema, dict):
        raise TypeError("OpenCode output_schema must be a dict or None")
    retry_count = int(invalid_json_retry_count)
    if retry_count < 0:
        raise ValueError("OpenCode invalid_json_retry_count cannot be negative")
    if invalid_json_retry_prompt is not None:
        if not isinstance(invalid_json_retry_prompt, str):
            raise TypeError(
                "OpenCode invalid_json_retry_prompt must be a string or None"
            )
        if not invalid_json_retry_prompt.strip():
            raise ValueError("OpenCode invalid_json_retry_prompt cannot be empty")
    if output is not _UNSET and output is not None and not callable(output):
        raise TypeError("OpenCode output must be callable or None")

    from .standalone import ensure_opencode_configuration
    from .task_service import (
        _run_component_task,
        bind_opencode_execution_context,
        get_opencode_execution_context,
    )

    bound_context = get_opencode_execution_context()
    effective_config_path = config_path or bound_context.config_path
    standalone = ensure_opencode_configuration(effective_config_path)

    async def run() -> OpenCodeResult:
        return await _run_component_task(
            task_name=normalized_name,
            task_type=normalized_task_type,
            prompt=normalized_prompt,
            required_capability=capability,
            output_schema=output_schema,
            invalid_json_retry_count=retry_count,
            invalid_json_retry_prompt=invalid_json_retry_prompt,
            session_id=str(session_id or "").strip() or None,
        )

    async def run_with_overrides() -> OpenCodeResult:
        overrides: dict[str, Any] = {}
        if output is not _UNSET:
            overrides["on_output"] = output
        if cancel_event is not _UNSET:
            overrides["cancel_event"] = cancel_event
        if not overrides:
            return await run()
        with bind_opencode_execution_context(**overrides):
            return await run()

    if standalone is None:
        return await run_with_overrides()
    standalone_output = _standalone_console_output() if output is _UNSET else output
    standalone_cancel_event = None if cancel_event is _UNSET else cancel_event
    with bind_opencode_execution_context(
        project_dir=bound_context.project_dir or standalone.project_dir,
        work_dir=bound_context.work_dir or standalone.work_dir,
        task_metadata={"standalone_console": True},
        on_output=standalone_output,
        cancel_event=standalone_cancel_event,
    ):
        return await run()


async def run_sync_component(
    function: Callable[..., Any],
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Run a synchronous component without moving Task Agent work off-loop."""
    if inspect.iscoroutinefunction(function):
        return await function(*args, **kwargs)
    owner_loop = asyncio.get_running_loop()
    token = _COMPONENT_OWNER_LOOP.set(owner_loop)
    outcome: concurrent.futures.Future[Any] = concurrent.futures.Future()
    context = copy_context()

    def invoke() -> None:
        try:
            outcome.set_result(context.run(function, *args, **kwargs))
        except BaseException as exc:
            outcome.set_exception(exc)

    worker = threading.Thread(
        target=invoke,
        name=f"task-agent-component-{getattr(function, '__name__', 'sync')}",
        daemon=True,
    )
    try:
        worker.start()
        while not outcome.done():
            await asyncio.sleep(0.01)
        result = outcome.result()
        if inspect.isawaitable(result):
            return await result
        return result
    finally:
        _COMPONENT_OWNER_LOOP.reset(token)


@contextmanager
def opencode_task_context(
    *,
    project_dir: str | PathLike[str],
    work_dir: str | PathLike[str],
    scan_id: str | None = None,
    feedback_entries: list[dict[str, Any]] | None = None,
    config_path: str | PathLike[str] | None = None,
    skill_paths: list[str | PathLike[str]] | None = None,
    task_metadata: dict[str, Any] | None = None,
    output: Callable[[str], Any] | None = None,
    cancel_event: Any = None,
):
    """Bind generic host context for one or more component task calls."""
    from .task_service import bind_opencode_execution_context

    with bind_opencode_execution_context(
        project_dir=Path(project_dir).expanduser().resolve(),
        work_dir=Path(work_dir).expanduser().resolve(),
        config_path=(
            Path(config_path).expanduser().resolve()
            if config_path is not None
            else None
        ),
        skill_paths=list(skill_paths or []),
        scan_id=None if scan_id is None else str(scan_id or ""),
        feedback_entries=list(feedback_entries or []),
        task_metadata=dict(task_metadata or {}),
        on_output=output,
        cancel_event=cancel_event,
    ):
        yield
