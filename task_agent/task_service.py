"""Internal OpenCode queue, scheduling, session and permission engine."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .api import OpenCodeResult
from .config_json import dump_opencode_config, parse_opencode_jsonc
from .host import (
    OpenCodeInvocationMetadata as OutputSource,
    OpenCodeSessionRuntime as _SessionRuntime,
    get_host_bindings,
)
from .llm_json import (
    LLMJsonParseError,
    parse_llm_json,
    parse_llm_json_schema,
)
from .model_pool import (
    ModelLease,
    NoAvailableModelError,
    acquire_model_lease,
    configured_global_concurrency,
    normalize_priority,
    normalize_requirement,
    release_model_lease,
    update_model_lease_context,
)
from .output_format import format_task_output, task_output_stage
from .serve_client import OpenCodePromptResult, get_serve_manager

logger = logging.getLogger(__name__)

TERMINAL_TASK_STATUSES = {"success", "failure", "timeout", "cancelled"}


def get_config() -> Any:
    """Resolve host configuration through the component boundary."""
    return get_host_bindings().get_config()


def get_global_opencode_workspace() -> Path:
    """Resolve the host-owned OpenCode workspace through its binding."""
    return get_host_bindings().get_workspace()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class OpenCodeExecutionContext:
    """Agent-owned metadata captured when a task is submitted.

    Callers of ``run_task()`` do not supply scan scope or arbitrary task
    context. Scan/validation orchestration binds it once at the execution
    boundary, and every submitted task snapshots that binding.
    """

    scan_id: str = ""
    project_dir: Path | None = None
    work_dir: Path | None = None
    config_path: Path | None = None
    skill_paths: tuple[Path, ...] = ()
    task_metadata: dict[str, Any] = field(default_factory=dict)
    feedback_entries: tuple[dict[str, Any], ...] = ()
    on_output: Callable[[str], Any] | None = field(default=None, compare=False, repr=False)
    on_invocation_metadata: Callable[[OutputSource], Any] | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    cancel_event: Any = field(default=None, compare=False, repr=False)


_execution_context: ContextVar[OpenCodeExecutionContext] = ContextVar(
    "opencode_execution_context",
    default=OpenCodeExecutionContext(),
)
_scan_feedback_entries: dict[str, tuple[dict[str, Any], ...]] = {}
_INHERIT_CONTEXT_VALUE = object()


def _feedback_snapshot(entries: Any) -> tuple[dict[str, Any], ...]:
    snapshot: list[dict[str, Any]] = []
    for entry in entries or ():
        if isinstance(entry, dict):
            snapshot.append(dict(entry))
        elif hasattr(entry, "model_dump"):
            value = entry.model_dump()
            if isinstance(value, dict):
                snapshot.append(dict(value))
        elif dataclasses.is_dataclass(entry):
            value = dataclasses.asdict(entry)
            if isinstance(value, dict):
                snapshot.append(value)
    return tuple(snapshot)


def set_opencode_execution_context(
    *,
    scan_id: str | None = None,
    project_dir: Path | None | object = _INHERIT_CONTEXT_VALUE,
    work_dir: Path | None | object = _INHERIT_CONTEXT_VALUE,
    config_path: Path | None | object = _INHERIT_CONTEXT_VALUE,
    skill_paths: Any = _INHERIT_CONTEXT_VALUE,
    task_metadata: dict[str, Any] | None = None,
    feedback_entries: Any = None,
    on_output: Callable[[str], Any] | None | object = _INHERIT_CONTEXT_VALUE,
    on_invocation_metadata: Callable[[OutputSource], Any] | None | object = _INHERIT_CONTEXT_VALUE,
    cancel_event: Any = _INHERIT_CONTEXT_VALUE,
) -> Token[OpenCodeExecutionContext]:
    """Bind Agent-owned scope for the current async execution tree.

    ``scan_id=None`` inherits the current scope. Paths and runtime hooks inherit
    when omitted and clear when explicitly set to ``None``.
    """
    current = _execution_context.get()
    next_scan_id = current.scan_id if scan_id is None else str(scan_id or "").strip()
    def resolved_path(value: Path | None | object, current_value: Path | None) -> Path | None:
        if value is _INHERIT_CONTEXT_VALUE:
            return current_value
        return None if value is None else Path(value).resolve()

    next_project_dir = resolved_path(project_dir, current.project_dir)
    next_work_dir = resolved_path(work_dir, current.work_dir)
    next_config_path = resolved_path(config_path, current.config_path)
    if skill_paths is _INHERIT_CONTEXT_VALUE:
        next_skill_paths = current.skill_paths
    else:
        next_skill_paths = tuple(
            dict.fromkeys(
                Path(path).expanduser().resolve()
                for path in (skill_paths or ())
            )
        )
    if scan_id is not None and not next_scan_id:
        if project_dir is _INHERIT_CONTEXT_VALUE:
            next_project_dir = None
        if work_dir is _INHERIT_CONTEXT_VALUE:
            next_work_dir = None
    metadata = dict(current.task_metadata)
    if task_metadata:
        metadata.update(task_metadata)
    feedback = (
        current.feedback_entries
        if feedback_entries is None
        else _feedback_snapshot(feedback_entries)
    )
    return _execution_context.set(OpenCodeExecutionContext(
        scan_id=next_scan_id,
        project_dir=next_project_dir,
        work_dir=next_work_dir,
        config_path=next_config_path,
        skill_paths=next_skill_paths,
        task_metadata=metadata,
        feedback_entries=feedback,
        on_output=current.on_output if on_output is _INHERIT_CONTEXT_VALUE else on_output,
        on_invocation_metadata=(
            current.on_invocation_metadata
            if on_invocation_metadata is _INHERIT_CONTEXT_VALUE
            else on_invocation_metadata
        ),
        cancel_event=(
            current.cancel_event if cancel_event is _INHERIT_CONTEXT_VALUE else cancel_event
        ),
    ))


def reset_opencode_execution_context(token: Token[OpenCodeExecutionContext]) -> None:
    _execution_context.reset(token)


def set_scan_feedback_entries(scan_id: str, entries: Any) -> None:
    normalized_scan_id = str(scan_id or "").strip()
    if normalized_scan_id:
        _scan_feedback_entries[normalized_scan_id] = _feedback_snapshot(entries)


def clear_scan_feedback_entries(scan_id: str) -> None:
    _scan_feedback_entries.pop(str(scan_id or "").strip(), None)


def get_opencode_execution_context() -> OpenCodeExecutionContext:
    """Return a defensive snapshot of the currently bound Agent context."""
    return _snapshot_execution_context()


@contextmanager
def bind_opencode_execution_context(**kwargs: Any):
    token = set_opencode_execution_context(**kwargs)
    try:
        yield _execution_context.get()
    finally:
        reset_opencode_execution_context(token)


def _snapshot_execution_context() -> OpenCodeExecutionContext:
    current = _execution_context.get()
    feedback = _scan_feedback_entries.get(current.scan_id, current.feedback_entries)
    return OpenCodeExecutionContext(
        scan_id=current.scan_id,
        project_dir=current.project_dir,
        work_dir=current.work_dir,
        config_path=current.config_path,
        skill_paths=tuple(current.skill_paths),
        task_metadata=dict(current.task_metadata),
        feedback_entries=tuple(dict(entry) for entry in feedback),
        on_output=current.on_output,
        on_invocation_metadata=current.on_invocation_metadata,
        cancel_event=current.cancel_event,
    )


def _required_project_dir(context: OpenCodeExecutionContext) -> Path:
    if context.project_dir is None:
        raise RuntimeError(
            "OpenCode project_dir is not bound; component execution must bind it before calling "
            "run_opencode_task()"
        )
    return context.project_dir.resolve()


def _required_work_dir(context: OpenCodeExecutionContext) -> Path:
    if context.work_dir is None:
        raise RuntimeError(
            "OpenCode work_dir is not bound; component execution must bind it before calling "
            "run_opencode_task()"
        )
    return context.work_dir.resolve()


@dataclass(frozen=True)
class OpenCodeTaskSpec:
    task_name: str
    prompt: str
    directory: Path
    required_capability: str = "low"
    timeout_seconds: int | None = None
    priority: int = 50
    output_schema: dict[str, Any] | None = None
    output_retry_count: int = 2
    output_retry_prompt: str | None = None
    session_id: str | None = None
    attempt: int | None = None


@dataclass(frozen=True)
class OpenCodeTaskResult:
    task_id: str
    session_id: str
    message_id: str
    status: str
    text: str = ""
    structured: Any = None
    model: str = ""
    output_source: OutputSource = field(default_factory=OutputSource)
    error: str = ""
    queued_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    revision: int = 1

    def raise_for_status(self) -> "OpenCodeTaskResult":
        if self.status == "timeout":
            raise asyncio.TimeoutError(self.error or "OpenCode task timed out")
        if self.status == "cancelled":
            raise asyncio.CancelledError(self.error or "OpenCode task cancelled")
        if self.status != "success":
            raise OpenCodeTaskError(self.error or "OpenCode task failed", result=self)
        return self


class OpenCodeTaskError(RuntimeError):
    def __init__(self, message: str, *, result: OpenCodeTaskResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class _InvalidStructuredOutput(RuntimeError):
    """The model completed, but every same-session JSON correction failed."""


class _CombinedCancelEvent:
    def __init__(self, internal: asyncio.Event, external: Any = None) -> None:
        self.internal = internal
        self.external = external

    def is_set(self) -> bool:
        return self.internal.is_set() or bool(
            self.external is not None and self.external.is_set()
        )


@dataclass
class _TaskRecord:
    task_id: str
    spec: OpenCodeTaskSpec
    revision: int
    queued_at: str
    result_future: asyncio.Future[OpenCodeTaskResult]
    session_future: asyncio.Future[str]
    cancel_event: asyncio.Event
    execution_context: OpenCodeExecutionContext
    status: str = "queued"
    started_at: str = ""
    worker: asyncio.Task[None] | None = None
    requeue_requested: bool = False


class OpenCodeTaskHandle:
    def __init__(self, service: "OpenCodeTaskService", record: _TaskRecord) -> None:
        self._service = service
        self._record = record

    @property
    def task_id(self) -> str:
        return self._record.task_id

    @property
    def status(self) -> str:
        return self._record.status

    @property
    def revision(self) -> int:
        return self._record.revision

    async def wait_session_id(self) -> str:
        return await asyncio.shield(self._record.session_future)

    async def result(self) -> OpenCodeTaskResult:
        return await asyncio.shield(self._record.result_future)

    async def cancel(self) -> None:
        await self._service.cancel_task(self.task_id)


class OpenCodeTaskService:
    """Agent-process singleton for all OpenCode model work."""

    def __init__(self) -> None:
        self._records: dict[str, _TaskRecord] = {}
        self._session_directories: dict[str, Path] = {}
        self._session_work_directories: dict[str, Path] = {}
        self._session_runtimes: dict[str, _SessionRuntime] = {}
        self._session_locks: dict[str, asyncio.Lock] = {}
        self._active_session_tasks: dict[str, str] = {}

    @staticmethod
    def _validation_debug_enabled(record: _TaskRecord) -> bool:
        return record.execution_context.task_metadata.get("validation_debug") is True

    @classmethod
    def _task_progress_enabled(cls, record: _TaskRecord) -> bool:
        metadata = record.execution_context.task_metadata
        return (
            cls._validation_debug_enabled(record)
            or metadata.get("standalone_console") is True
        )

    @classmethod
    def _emit_task_progress(
        cls,
        record: _TaskRecord,
        message: str,
        *,
        session_id: str | None = None,
    ) -> None:
        if not cls._task_progress_enabled(record):
            return
        callback = record.execution_context.on_output
        if callback is None:
            return
        stage = task_output_stage(record.execution_context.task_metadata.get("task_type"))
        resolved_session_id = record.spec.session_id if session_id is None else session_id
        try:
            callback(format_task_output(stage, resolved_session_id, "task", message))
        except Exception:
            logger.exception(
                "Failed to emit progress output for OpenCode task %s",
                record.task_id,
            )

    @staticmethod
    def _normalize_spec(spec: OpenCodeTaskSpec) -> OpenCodeTaskSpec:
        task_name = str(spec.task_name or "").strip()
        prompt = str(spec.prompt or "")
        if not task_name:
            raise ValueError("OpenCode task_name is required")
        if not prompt.strip():
            raise ValueError("OpenCode prompt is required")
        directory = Path(spec.directory).resolve()
        timeout = spec.timeout_seconds
        if timeout is not None and int(timeout) <= 0:
            raise ValueError("OpenCode timeout_seconds must be positive")
        output_retry_count = int(spec.output_retry_count)
        if output_retry_count < 0:
            raise ValueError("OpenCode output_retry_count cannot be negative")
        output_retry_prompt = spec.output_retry_prompt
        if output_retry_prompt is not None:
            if not isinstance(output_retry_prompt, str):
                raise TypeError(
                    "OpenCode output_retry_prompt must be a string or None"
                )
            if not output_retry_prompt.strip():
                raise ValueError("OpenCode output_retry_prompt cannot be empty")
        attempt = spec.attempt
        if attempt is not None and int(attempt) < 0:
            raise ValueError("OpenCode attempt cannot be negative")
        return dataclasses.replace(
            spec,
            task_name=task_name,
            prompt=prompt,
            directory=directory,
            required_capability=normalize_requirement(spec.required_capability),
            priority=normalize_priority(spec.priority),
            timeout_seconds=None if timeout is None else int(timeout),
            output_retry_count=output_retry_count,
            output_retry_prompt=output_retry_prompt,
            attempt=None if attempt is None else int(attempt),
            session_id=str(spec.session_id or "").strip() or None,
        )

    def submit_task(self, spec: OpenCodeTaskSpec) -> OpenCodeTaskHandle:
        normalized = self._normalize_spec(spec)
        if normalized.session_id:
            existing = self._session_directories.get(normalized.session_id)
            if existing is not None and existing != normalized.directory:
                raise ValueError(
                    f"OpenCode session {normalized.session_id} is bound to {existing}; "
                    f"continuation directory cannot change to {normalized.directory}"
                )
            work_dir = _required_work_dir(_snapshot_execution_context())
            existing_work_dir = self._session_work_directories.get(normalized.session_id)
            if existing_work_dir is not None and existing_work_dir != work_dir:
                raise ValueError(
                    f"OpenCode session {normalized.session_id} is bound to work directory "
                    f"{existing_work_dir}; continuation work directory cannot change to {work_dir}"
                )
        loop = asyncio.get_running_loop()
        task_id = uuid4().hex
        record = _TaskRecord(
            task_id=task_id,
            spec=normalized,
            revision=1,
            queued_at=_now_iso(),
            result_future=loop.create_future(),
            session_future=loop.create_future(),
            cancel_event=asyncio.Event(),
            execution_context=_snapshot_execution_context(),
        )
        if normalized.session_id:
            record.session_future.set_result(normalized.session_id)
            self._session_directories.setdefault(normalized.session_id, normalized.directory)
            self._session_work_directories.setdefault(
                normalized.session_id,
                _required_work_dir(record.execution_context),
            )
        self._records[task_id] = record
        self._emit_task_progress(
            record,
            f"QUEUED task={task_id} name={normalized.task_name} "
            f"capability={normalized.required_capability} priority={normalized.priority}",
        )
        record.worker = asyncio.create_task(
            self._run_record(record),
            name=f"opencode-task-{task_id[:10]}",
        )
        return OpenCodeTaskHandle(self, record)

    async def run_task(self, spec: OpenCodeTaskSpec) -> OpenCodeTaskResult:
        handle = self.submit_task(spec)
        try:
            return await handle.result()
        except asyncio.CancelledError:
            await asyncio.shield(handle.cancel())
            raise

    def get_task(self, task_id: str) -> OpenCodeTaskHandle:
        record = self._records.get(str(task_id or "").strip())
        if record is None:
            raise KeyError(f"Unknown OpenCode task: {task_id}")
        return OpenCodeTaskHandle(self, record)

    async def update_queued_task(
        self,
        task_id: str,
        spec: OpenCodeTaskSpec | None = None,
        **changes: Any,
    ) -> OpenCodeTaskHandle:
        record = self._records.get(task_id)
        if record is None:
            raise KeyError(f"Unknown OpenCode task: {task_id}")
        if record.status not in {"queued", "blocked"}:
            raise RuntimeError("Only queued or blocked OpenCode tasks can be updated")
        next_spec = spec or dataclasses.replace(record.spec, **changes)
        next_spec = self._normalize_spec(next_spec)
        if next_spec.session_id:
            existing = self._session_directories.get(next_spec.session_id)
            if existing is not None and existing != next_spec.directory:
                raise ValueError(
                    f"OpenCode session {next_spec.session_id} is bound to {existing}; "
                    f"continuation directory cannot change to {next_spec.directory}"
                )
            next_work_dir = _required_work_dir(record.execution_context)
            existing_work_dir = self._session_work_directories.get(next_spec.session_id)
            if existing_work_dir is not None and existing_work_dir != next_work_dir:
                raise ValueError(
                    f"OpenCode session {next_spec.session_id} is bound to work directory "
                    f"{existing_work_dir}; continuation work directory cannot change to {next_work_dir}"
                )
        record.requeue_requested = True
        record.cancel_event.set()
        if record.worker is not None:
            await record.worker
        record.spec = next_spec
        record.revision += 1
        record.queued_at = _now_iso()
        record.started_at = ""
        record.status = "queued"
        record.cancel_event = asyncio.Event()
        record.requeue_requested = False
        record.worker = asyncio.create_task(
            self._run_record(record),
            name=f"opencode-task-{task_id[:10]}-r{record.revision}",
        )
        return OpenCodeTaskHandle(self, record)

    async def cancel_task(self, task_id: str) -> None:
        record = self._records.get(task_id)
        if record is None:
            raise KeyError(f"Unknown OpenCode task: {task_id}")
        if record.status in TERMINAL_TASK_STATUSES:
            return
        record.cancel_event.set()
        if record.worker is not None:
            await record.worker

    async def _run_record(self, record: _TaskRecord) -> None:
        spec = record.spec
        context = record.execution_context
        validation_debug = self._validation_debug_enabled(record)
        combined_cancel = _CombinedCancelEvent(record.cancel_event, context.cancel_event)
        cli_config_source = lambda: _task_cli_config(record.execution_context)
        global_concurrency = lambda: configured_global_concurrency(
            get_config()
        )
        task_policy = _task_model_policy(record.execution_context)
        configured_retry_count = int(
            _cfg_value(_task_cli_config(record.execution_context), "max_retries", 2) or 0
        )
        if task_policy is not None:
            fresh_retry_count = int(_cfg_value(task_policy, "max_retries", 0) or 0)
        else:
            fresh_retry_count = configured_retry_count if spec.attempt is None else int(spec.attempt)
        total_session_attempts = fresh_retry_count + 1
        accumulated_duration = 0.0
        first_session_id = str(spec.session_id or "")
        final_session_id = first_session_id
        last_message_id = ""
        last_text = ""
        last_model = ""
        last_source = OutputSource()

        session_attempt = 1
        while session_attempt <= total_session_attempts:
            lease: ModelLease | None = None
            attempt_started = 0.0
            attempt_outcome = "failure"
            terminal_release = True
            session_id = first_session_id if session_attempt == 1 else ""
            message_id = ""
            text = ""
            structured: Any = None
            source = OutputSource(attempt=session_attempt)
            runtime: _SessionRuntime | None = None
            model = ""
            retry_reason = ""
            try:
                task_context = _model_pool_task_context(
                    record,
                    session_attempt=session_attempt,
                    total_session_attempts=total_session_attempts,
                )
                lease = await acquire_model_lease(
                    cli_config_source,
                    global_concurrency=global_concurrency,
                    required_capability=_effective_required_capability(record.execution_context, spec),
                    prefer_high=False,
                    cancel_event=combined_cancel,
                    stats_scope_id=record.execution_context.scan_id,
                    task_context=task_context,
                    priority=spec.priority,
                    task_id=record.task_id,
                    revision=record.revision,
                    strict_capability=True,
                    prefer_lowest_capability=True,
                    wait_when_unavailable=not validation_debug,
                )
                if lease is None:
                    if record.requeue_requested:
                        return
                    attempt_outcome = "cancelled"
                    self._finish_record(
                        record,
                        status="cancelled",
                        session_id=session_id,
                        source=source,
                        error="OpenCode task cancelled while queued",
                        duration_seconds=accumulated_duration,
                    )
                    return

                if (
                    session_attempt == 1
                    and task_policy is None
                    and spec.attempt is None
                    and lease.option.max_retries is not None
                ):
                    fresh_retry_count = max(0, int(lease.option.max_retries))
                    total_session_attempts = fresh_retry_count + 1

                record.status = "running"
                if not record.started_at:
                    record.started_at = lease.started_at_iso or _now_iso()
                self._emit_task_progress(
                    record,
                    f"START task={record.task_id} "
                    f"model_id={lease.option.id} "
                    f"model={lease.option.model or '<cli-default>'} "
                    f"capability={lease.option.capability}",
                )
                attempt_started = lease.started_at or time.monotonic()
                runtime, model, source = await self._runtime_for_task(
                    record,
                    lease,
                    session_attempt=session_attempt,
                )
                source.attempt = session_attempt
                if context.on_invocation_metadata:
                    context.on_invocation_metadata(source)

                async def record_session(value: str) -> None:
                    nonlocal session_id, final_session_id
                    session_id = str(value or "").strip()
                    final_session_id = session_id
                    if not session_id or runtime is None:
                        return
                    self._session_directories[session_id] = spec.directory
                    self._session_work_directories[session_id] = _required_work_dir(context)
                    self._session_runtimes[session_id] = runtime
                    # Alias a newly-created task lock to its durable session
                    # before exposing it to callers.
                    self._session_locks.setdefault(session_id, session_lock)
                    self._active_session_tasks[session_id] = record.task_id
                    source.serve_session_id = session_id
                    if not record.session_future.done():
                        record.session_future.set_result(session_id)
                    await update_model_lease_context(lease, {
                        "serve_session_id": session_id,
                        "session_attempt": session_attempt,
                    })

                def record_model(value: str) -> None:
                    if value:
                        source.model = str(value)

                system_prompt = _task_system_prompt(record)
                permissions = _task_permissions(record)
                timeout_seconds = (
                    (_cfg_value(task_policy, "timeout_seconds") if task_policy is not None else None)
                    or spec.timeout_seconds
                    or lease.option.timeout
                    or int(_cfg_value(_task_cli_config(record.execution_context), "timeout", 1200))
                )
                lock_key = session_id or f"new:{record.task_id}:{session_attempt}"
                session_lock = self._session_locks.setdefault(lock_key, asyncio.Lock())
                prompt = spec.prompt
                try:
                    async with session_lock:
                        for output_attempt in range(spec.output_retry_count + 1):
                            details = await get_serve_manager().run_prompt(
                                **runtime.kwargs(),
                                prompt=prompt,
                                model=model,
                                timeout=timeout_seconds,
                                on_line=context.on_output,
                                on_session_id=record_session,
                                on_response_model=record_model,
                                cancel_event=combined_cancel,
                                session_id=session_id or None,
                                session_title=spec.task_name,
                                mcp_tools=None,
                                disabled_mcp_tools=_disabled_source_mcp_tools(spec.directory),
                                system_prompt=system_prompt,
                                permissions=permissions,
                                return_details=True,
                                show_serve_status=self._task_progress_enabled(record),
                                log_stage=task_output_stage(
                                    record.execution_context.task_metadata.get("task_type")
                                ),
                            )
                            assert isinstance(details, OpenCodePromptResult)
                            session_id = details.session_id
                            final_session_id = session_id
                            message_id = details.message_id
                            text = details.text or "\n".join(details.lines)
                            structured = _parse_text_json(text, spec.output_schema)
                            if spec.output_schema is None or structured is not None:
                                break
                            if output_attempt >= spec.output_retry_count:
                                raise _InvalidStructuredOutput(
                                    "OpenCode exhausted same-session JSON corrections "
                                    f"({spec.output_retry_count}) without matching the target schema"
                                )
                            prompt = (
                                spec.output_retry_prompt
                                if spec.output_retry_prompt is not None
                                else _json_correction_prompt(spec.output_schema)
                            )
                            self._emit_task_progress(
                                record,
                                f"JSON_CORRECTION {output_attempt + 1}/{spec.output_retry_count} "
                                "requesting schema-compliant JSON in the same session",
                                session_id=session_id,
                            )
                finally:
                    if lock_key.startswith("new:"):
                        self._session_locks.pop(lock_key, None)

                attempt_outcome = "success"
                last_message_id = message_id
                last_text = text
                last_model = source.model or details.model or model
                last_source = source
                active_duration = (
                    max(0.0, time.monotonic() - attempt_started)
                    if attempt_started
                    else 0.0
                )
                self._finish_record(
                    record,
                    status="success",
                    session_id=session_id,
                    message_id=message_id,
                    text=text,
                    structured=structured,
                    model=last_model,
                    source=source,
                    duration_seconds=accumulated_duration + active_duration,
                )
                return
            except asyncio.TimeoutError as exc:
                attempt_outcome = "timeout"
                last_source = source
                self._finish_record(
                    record,
                    status="timeout",
                    session_id=final_session_id or session_id,
                    message_id=message_id or last_message_id,
                    text=text or last_text,
                    model=source.model or model or last_model,
                    source=source,
                    error=str(exc) or "OpenCode task timed out",
                    duration_seconds=accumulated_duration + _elapsed(attempt_started),
                )
                return
            except asyncio.CancelledError:
                if record.requeue_requested:
                    return
                attempt_outcome = "cancelled"
                last_source = source
                self._finish_record(
                    record,
                    status="cancelled",
                    session_id=final_session_id or session_id,
                    message_id=message_id or last_message_id,
                    text=text or last_text,
                    model=source.model or model or last_model,
                    source=source,
                    error="OpenCode task cancelled",
                    duration_seconds=accumulated_duration + _elapsed(attempt_started),
                )
                return
            except NoAvailableModelError as exc:
                attempt_outcome = "failure"
                last_source = source
                self._finish_record(
                    record,
                    status="failure",
                    session_id=final_session_id or session_id,
                    message_id=message_id or last_message_id,
                    text=text or last_text,
                    model=source.model or model or last_model,
                    source=source,
                    error=str(exc),
                    duration_seconds=accumulated_duration + _elapsed(attempt_started),
                )
                return
            except _InvalidStructuredOutput as exc:
                retry_reason = str(exc)
                if message_id:
                    last_message_id = message_id
                if text:
                    last_text = text
                last_model = source.model or model or last_model
                last_source = source
            except Exception as exc:
                retry_reason = str(exc) or type(exc).__name__
                if message_id:
                    last_message_id = message_id
                if text:
                    last_text = text
                last_model = source.model or model or last_model
                last_source = source
                logger.exception(
                    "OpenCode task %s session attempt %d/%d failed",
                    record.task_id,
                    session_attempt,
                    total_session_attempts,
                )
            finally:
                if session_id and self._active_session_tasks.get(session_id) == record.task_id:
                    self._active_session_tasks.pop(session_id, None)
                attempt_duration = _elapsed(attempt_started)
                accumulated_duration += attempt_duration
                # A fresh-session retry is one logical task. Release its model
                # slot now, but append terminal history/outcome only once.
                if retry_reason and session_attempt < total_session_attempts:
                    terminal_release = False
                # Preserve the last session created by this logical task in the
                # terminal model-pool history. A later retry can fail before it
                # creates a replacement session, in which case final_session_id
                # still identifies the most recent usable OpenCode session.
                await update_model_lease_context(lease, {
                    "serve_session_id": final_session_id or session_id,
                    "session_attempt": session_attempt,
                })
                await release_model_lease(
                    lease,
                    outcome=attempt_outcome if terminal_release else None,
                    duration_seconds=attempt_duration if lease is not None else None,
                    record_completion=terminal_release,
                )

            if retry_reason and session_attempt < total_session_attempts:
                record.status = "queued"
                self._emit_task_progress(
                    record,
                    f"RETRY {session_attempt}/{fresh_retry_count} "
                    f"reason={retry_reason} next_session=new",
                    session_id=final_session_id or session_id,
                )
                session_attempt += 1
                continue

            self._finish_record(
                record,
                status="failure",
                session_id=final_session_id or session_id,
                message_id=last_message_id,
                text=last_text,
                model=last_model,
                source=last_source,
                error=retry_reason or "OpenCode task failed",
                duration_seconds=accumulated_duration,
            )
            return

    async def _runtime_for_task(
        self,
        record: _TaskRecord,
        lease: ModelLease,
        *,
        session_attempt: int,
    ) -> tuple[_SessionRuntime, str, OutputSource]:
        """Build a stable serve runtime from the Agent-wide workspace."""
        spec = record.spec
        cli_config = _task_cli_config(record.execution_context)
        runtime = get_host_bindings().build_session_runtime(
            cli_config,
            lease.option,
            spec.directory,
        )
        runtime = _runtime_with_skill_paths(
            runtime,
            record.execution_context.skill_paths,
        )
        model = runtime.model
        source = OutputSource(
            backend="opencode",
            tool=runtime.tool,
            model_id=lease.option.id,
            model=model,
            use_default_model=bool(lease.option.use_default_model),
            capability=lease.option.capability,
            required_capability=_effective_required_capability(record.execution_context, spec),
            task_id=record_task_id(lease),
            attempt=session_attempt,
            started_at=lease.started_at_iso,
            serve_session_id=str(spec.session_id or ""),
        )
        return runtime, model, source

    def _finish_record(
        self,
        record: _TaskRecord,
        *,
        status: str,
        session_id: str,
        source: OutputSource,
        message_id: str = "",
        text: str = "",
        structured: Any = None,
        model: str = "",
        error: str = "",
        duration_seconds: float = 0.0,
    ) -> None:
        record.status = status
        if not record.session_future.done():
            record.session_future.set_result(session_id)
        if record.result_future.done():
            return
        terminal_parts = [
            "FINISHED",
            f"task={record.task_id}",
            f"status={status}",
        ]
        if session_id:
            terminal_parts.append(f"session={session_id}")
        resolved_model = model or source.model
        if resolved_model:
            terminal_parts.append(f"model={resolved_model}")
        if error:
            terminal_parts.append(f"error={re.sub(r'\\s+', ' ', error).strip()}")
        self._emit_task_progress(
            record,
            " ".join(terminal_parts),
            session_id=session_id,
        )
        record.result_future.set_result(OpenCodeTaskResult(
            task_id=record.task_id,
            session_id=session_id,
            message_id=message_id,
            status=status,
            text=text,
            structured=structured,
            model=resolved_model,
            output_source=source,
            error=error,
            queued_at=record.queued_at,
            started_at=record.started_at,
            finished_at=_now_iso(),
            duration_seconds=max(0.0, float(duration_seconds or 0.0)),
            revision=record.revision,
        ))

    def _runtime_for_session(self, session_id: str) -> _SessionRuntime:
        runtime = self._session_runtimes.get(str(session_id or "").strip())
        if runtime is None:
            raise KeyError(
                f"OpenCode session runtime is unknown in this Agent process: {session_id}"
            )
        return runtime

    async def get_session(self, session_id: str) -> Any:
        runtime = self._runtime_for_session(session_id)
        return await get_serve_manager().get_session(session_id, **runtime.kwargs())

    async def get_session_messages(self, session_id: str) -> list[dict[str, Any]]:
        runtime = self._runtime_for_session(session_id)
        return await get_serve_manager().get_session_messages(session_id, **runtime.kwargs())

    async def get_session_result(self, session_id: str) -> OpenCodeTaskResult | None:
        messages = await self.get_session_messages(session_id)
        for message in reversed(messages):
            info = message.get("info") if isinstance(message, dict) else None
            if not isinstance(info, dict) or info.get("role") != "assistant":
                continue
            text_parts = []
            for part in message.get("parts") or []:
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(str(part.get("text") or ""))
            text = "\n".join(text_parts)
            structured = _parse_text_json(text)
            return OpenCodeTaskResult(
                task_id="",
                session_id=session_id,
                message_id=str(info.get("id") or ""),
                status="success",
                text=text,
                structured=structured,
                model=_message_model(info),
                finished_at=_now_iso(),
            )
        return None

    async def delete_session(self, session_id: str, *, force: bool = False) -> Any:
        active_task_id = self._active_session_tasks.get(session_id)
        if active_task_id:
            if not force:
                raise RuntimeError(f"OpenCode session {session_id} is currently running")
            await self.cancel_task(active_task_id)
        runtime = self._runtime_for_session(session_id)
        result = await get_serve_manager().delete_session(session_id, **runtime.kwargs())
        self._session_directories.pop(session_id, None)
        self._session_work_directories.pop(session_id, None)
        self._session_runtimes.pop(session_id, None)
        self._session_locks.pop(session_id, None)
        return result


def _runtime_with_skill_paths(
    runtime: _SessionRuntime,
    skill_paths: tuple[Path, ...],
) -> _SessionRuntime:
    """Merge component-owned skill roots into one task's Serve config."""
    if not skill_paths:
        return runtime
    config = parse_opencode_jsonc(
        runtime.config_content,
        source="OpenCode component runtime config",
    )
    skills = config.get("skills")
    if not isinstance(skills, dict):
        skills = {}
        config["skills"] = skills
    configured = skills.get("paths")
    if isinstance(configured, str):
        configured_paths = [configured]
    elif isinstance(configured, list):
        configured_paths = [str(path) for path in configured if str(path).strip()]
    else:
        configured_paths = []
    skills["paths"] = list(dict.fromkeys([
        *configured_paths,
        *(str(path) for path in skill_paths),
    ]))
    return dataclasses.replace(
        runtime,
        config_content=dump_opencode_config(config),
    )


def _cfg_value(config_obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


def _elapsed(started: float) -> float:
    return max(0.0, time.monotonic() - started) if started else 0.0


def _task_cli_config(context: OpenCodeExecutionContext) -> Any:
    """Select an Agent-owned CLI profile without exposing it on TaskSpec."""
    config = get_config()
    task_type = str(context.task_metadata.get("task_type") or "").strip()
    if task_type == "fp_review" and getattr(config, "fp_review_cli", None) is not None:
        return config.fp_review_cli
    return config.opencode


def _task_model_policy(context: OpenCodeExecutionContext) -> Any | None:
    """Return the authoritative phase policy for a model-backed task."""
    config = get_config()
    task_type = str(context.task_metadata.get("task_type") or "").strip()
    if task_type in {
        "audit",
        "project_audit",
        "sensitive_clear",
        "report_audit",
        "threat_audit",
    }:
        return getattr(config, "vulnerability_mining", None)
    if task_type == "fp_review":
        return getattr(config, "false_positive", None)
    if task_type in {"vulnerability_validation", "validation"}:
        environment = str(context.task_metadata.get("validation_environment") or "").strip()
        validation = getattr(config, "vulnerability_validation", None)
        environments = _cfg_value(validation, "environments", {}) or {}
        env_config = environments.get(environment) if isinstance(environments, dict) else None
        return _cfg_value(env_config, "model_policy") if env_config is not None else None
    # Unclassified tasks intentionally retain per-model/task timeout and retry
    # behavior because the Agent configuration page has no policy for them.
    return None


def _effective_required_capability(
    context: OpenCodeExecutionContext,
    spec: OpenCodeTaskSpec,
) -> str:
    del context
    return spec.required_capability


def _disabled_source_mcp_tools(directory: Path) -> tuple[str, ...]:
    return tuple(get_host_bindings().disabled_source_mcp_tools(directory))


def _model_pool_task_context(
    record: _TaskRecord,
    *,
    session_attempt: int,
    total_session_attempts: int,
) -> dict[str, Any]:
    spec = record.spec
    prompt = spec.prompt
    context = {
        **record.execution_context.task_metadata,
        "task_name": spec.task_name,
        "prompt": prompt,
        "prompt_length": len(prompt),
        "priority": spec.priority,
        "revision": record.revision,
        "session_attempt": session_attempt,
        "retry_ordinal": session_attempt - 1,
        "session_attempts": total_session_attempts,
    }
    # A planned task is consumed once. A fresh-session retry is still the same
    # logical task and must not consume the plan entry again.
    if session_attempt > 1:
        context.pop("planned_task_id", None)
    return context


def _json_correction_prompt(schema: dict[str, Any]) -> str:
    return (
        "你上一次的回复不是符合目标 JSON Schema 的合法 JSON。"
        "现在只修正最终结果：仅返回一个 JSON 值，不要使用 Markdown 代码围栏，"
        "不要附加说明，也不要调用工具。\nJSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, indent=2)
    )


def _task_system_prompt(record: _TaskRecord) -> str:
    from .feedback_format import format_feedback_experience

    sections: list[str] = []
    if "deephole-code" in _disabled_source_mcp_tools(record.spec.directory):
        sections.append(
            "## CodeGraph 项目范围\n\n"
            "当前源码查询使用 CodeGraph MCP。调用支持项目路径参数的 CodeGraph 工具时，"
            f"必须传入 projectPath={record.spec.directory.resolve()}。"
        )
    checker = str(record.execution_context.task_metadata.get("checker") or "").strip()
    if checker:
        matching = [
            entry
            for entry in record.execution_context.feedback_entries
            if str(entry.get("vuln_type") or "").strip() == checker
        ]
        feedback = format_feedback_experience(matching)
        if feedback:
            sections.append(
                "## 已选择的扫描反馈\n\n"
                "以下用户选择的历史经验适用于当前检查项。请将其作为证据和参考，"
                "同时仍需核验当前代码：\n"
                + feedback
            )
    return "\n\n".join(sections)


def _permission_path_patterns(path: Path) -> list[str]:
    normalized = str(path.resolve())
    variants = [normalized]
    for candidate in (normalized.replace("\\", "/"), normalized.replace("/", "\\")):
        if candidate not in variants:
            variants.append(candidate)
    return [pattern for value in variants for pattern in (value, f"{value}/**")]


def _task_permissions(record: _TaskRecord) -> list[dict[str, str]]:
    """Allow project reads and restrict all model writes to the bound work dir."""
    spec = record.spec
    context = record.execution_context
    work_dir = _required_work_dir(context)
    external_roots = [spec.directory, work_dir, get_global_opencode_workspace()]

    rules: list[dict[str, str]] = []

    def add(permission: str, pattern: str, action: str) -> None:
        rules.append({
            "permission": permission,
            "pattern": pattern,
            "action": action,
        })

    for permission in ("read", "list", "glob", "grep"):
        add(permission, "*", "allow")

    add("external_directory", "*", "deny")
    seen_external: set[str] = set()
    for root in external_roots:
        for pattern in _permission_path_patterns(root):
            if pattern not in seen_external:
                add("external_directory", pattern, "allow")
                seen_external.add(pattern)

    add("edit", "*", "deny")
    for pattern in _permission_path_patterns(work_dir):
        add("edit", pattern, "allow")

    add("bash", "*", "deny")
    add("skill", "*", "allow")
    return rules


def _parse_text_json(text: str, schema: dict[str, Any] | None = None) -> Any:
    """Best-effort local JSON extraction; invalid model text stays a normal result."""
    try:
        if schema is not None:
            return parse_llm_json_schema(text, schema)
        return parse_llm_json(text, None)
    except (LLMJsonParseError, TypeError, ValueError):
        return None


def record_task_id(lease: ModelLease) -> str:
    return str(lease.task_id or "")


def _message_model(info: dict[str, Any]) -> str:
    provider = str(info.get("providerID") or "").strip()
    model = str(info.get("modelID") or "").strip()
    if not provider or not model:
        return model
    return model if model.startswith(f"{provider}/") else f"{provider}/{model}"


def _task_priority(task_type: str) -> int:
    if task_type == "vulnerability_validation":
        return 80
    if task_type == "skill_create":
        return 70
    return 50


def _task_timeout_seconds(
    task_type: str,
    context: OpenCodeExecutionContext,
) -> int:
    policy = _task_model_policy(context)
    if policy is not None:
        value = int(_cfg_value(policy, "timeout_seconds", 0) or 0)
        if value > 0:
            return value
    config = get_config()
    if task_type == "memory_api_discovery":
        value = int(
            _cfg_value(
                getattr(config, "memory_api_discovery", None),
                "timeout_seconds",
                0,
            )
            or 0
        )
        if value > 0:
            return value
    return int(_cfg_value(_task_cli_config(context), "timeout", 1200) or 1200)


async def _run_component_task(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: str,
    output_schema: dict[str, Any] | None,
    invalid_json_retry_count: int,
    invalid_json_retry_prompt: str | None,
    session_id: str | None,
) -> OpenCodeResult:
    """Translate the public contract into the internal scheduling record."""
    with bind_opencode_execution_context(task_metadata={"task_type": task_type}):
        context = _snapshot_execution_context()
        project_dir = _required_project_dir(context)
        _required_work_dir(context)
        result = await _get_opencode_task_service().run_task(
            OpenCodeTaskSpec(
                task_name=task_name,
                prompt=prompt,
                directory=project_dir,
                required_capability=required_capability,
                timeout_seconds=_task_timeout_seconds(task_type, context),
                priority=_task_priority(task_type),
                output_schema=output_schema,
                output_retry_count=invalid_json_retry_count,
                output_retry_prompt=invalid_json_retry_prompt,
                session_id=session_id,
                attempt=None,
            )
        )

    output_source = (
        result.output_source.model_dump()
        if hasattr(result.output_source, "model_dump")
        else dict(result.output_source or {})
    )
    if result.status == "cancelled":
        raise asyncio.CancelledError(result.error or "OpenCode task cancelled")
    if result.status == "success":
        return OpenCodeResult(
            session_id=result.session_id,
            status="success",
            text=result.text,
            structured=result.structured if output_schema is not None else None,
            model=result.model,
            output_source=output_source,
        )
    if result.status == "timeout":
        return OpenCodeResult(
            session_id=result.session_id,
            status="timeout",
            text=result.error or "OpenCode task timed out",
            structured=None,
            model=result.model,
            output_source=output_source,
        )
    return OpenCodeResult(
        session_id=result.session_id,
        status="failure",
        text=result.error or result.text or "OpenCode task failed",
        structured=None,
        model=result.model,
        output_source=output_source,
    )


_service: OpenCodeTaskService | None = None


def _get_opencode_task_service() -> OpenCodeTaskService:
    global _service
    if _service is None:
        _service = OpenCodeTaskService()
    return _service


def reset_opencode_task_service() -> None:
    """Discard the lazy task-service singleton after host shutdown."""
    global _service
    _service = None
