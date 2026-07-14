"""Unified OpenCode task queue and durable session facade.

Every model-backed operation in OpenDeepHole is represented by an
``OpenCodeTaskSpec``.  The service owns model scheduling, execution-stage
timeouts, OpenCode session creation/continuation and plain-text output.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from backend.config import get_config
from backend.logger import get_logger
from backend.models import OutputSource
from backend.opencode.llm_json import (
    LLMJsonParseError,
    parse_llm_json,
    parse_llm_json_schema,
)
from backend.opencode.model_pool import (
    ModelLease,
    acquire_model_lease,
    configured_global_concurrency,
    normalize_priority,
    normalize_requirement,
    release_model_lease,
    update_model_lease_context,
)
from backend.opencode.serve_client import OpenCodePromptResult, get_serve_manager

logger = get_logger(__name__)

TERMINAL_TASK_STATUSES = {"success", "failure", "timeout", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class OpenCodeTaskSpec:
    task_name: str
    prompt: str
    directory: Path
    required_capability: str = "low"
    workspace: Path | None = None
    scope_id: str = ""
    task_context: dict[str, Any] = field(default_factory=dict)
    mcp_tools: list[str] | None = None
    skills: list[str | Path] = field(default_factory=list)
    timeout_seconds: int | None = None
    priority: int = 50
    output_schema: dict[str, Any] | None = None
    permissions: list[dict[str, str]] | None = None
    session_id: str | None = None
    writable_paths: list[Path] = field(default_factory=list)
    cli_config: Any = None
    global_concurrency: int | None = None
    attempt: int = 0
    on_output: Callable[[str], Any] | None = field(default=None, compare=False, repr=False)
    on_invocation_metadata: Callable[[OutputSource], Any] | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    cancel_event: Any = field(default=None, compare=False, repr=False)


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
    status: str = "queued"
    started_at: str = ""
    worker: asyncio.Task[None] | None = None
    requeue_requested: bool = False


@dataclass(frozen=True)
class _SessionRuntime:
    directory: Path
    tool: str
    executable: str
    config_workspace: Path | None
    config_content: str | None
    env_overrides: dict[str, str]

    def kwargs(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "executable": self.executable,
            "directory": self.directory,
            "config_workspace": self.config_workspace,
            "config_content": self.config_content,
            "env_overrides": self.env_overrides,
        }


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
        self._session_runtimes: dict[str, _SessionRuntime] = {}
        self._session_locks: dict[str, asyncio.Lock] = {}
        self._active_session_tasks: dict[str, str] = {}

    @staticmethod
    def _normalize_spec(spec: OpenCodeTaskSpec) -> OpenCodeTaskSpec:
        task_name = str(spec.task_name or "").strip()
        prompt = str(spec.prompt or "")
        if not task_name:
            raise ValueError("OpenCode task_name is required")
        if not prompt.strip():
            raise ValueError("OpenCode prompt is required")
        directory = Path(spec.directory).resolve()
        workspace = Path(spec.workspace).resolve() if spec.workspace is not None else directory
        timeout = spec.timeout_seconds
        if timeout is not None and int(timeout) <= 0:
            raise ValueError("OpenCode timeout_seconds must be positive")
        global_concurrency = spec.global_concurrency
        if global_concurrency is not None and int(global_concurrency) <= 0:
            raise ValueError("OpenCode global_concurrency must be positive")
        permissions = _normalize_permissions(spec.permissions)
        return dataclasses.replace(
            spec,
            task_name=task_name,
            prompt=prompt,
            directory=directory,
            workspace=workspace,
            required_capability=normalize_requirement(spec.required_capability),
            priority=normalize_priority(spec.priority),
            timeout_seconds=None if timeout is None else int(timeout),
            global_concurrency=(
                None if global_concurrency is None else int(global_concurrency)
            ),
            permissions=permissions,
            session_id=str(spec.session_id or "").strip() or None,
            writable_paths=[Path(path).resolve() for path in spec.writable_paths],
            skills=list(spec.skills or []),
            mcp_tools=None if spec.mcp_tools is None else list(spec.mcp_tools),
            task_context=dict(spec.task_context or {}),
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
        )
        if normalized.session_id:
            record.session_future.set_result(normalized.session_id)
            self._session_directories.setdefault(normalized.session_id, normalized.directory)
        self._records[task_id] = record
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
        combined_cancel = _CombinedCancelEvent(record.cancel_event, spec.cancel_event)
        config = get_config()
        explicit_cli_config = spec.cli_config is not None
        cli_config_source: Any = spec.cli_config or (lambda: get_config().opencode)
        global_concurrency: Any
        if spec.global_concurrency is not None:
            global_concurrency = spec.global_concurrency
        else:
            global_concurrency = (
                configured_global_concurrency(config)
                if explicit_cli_config
                else (lambda: configured_global_concurrency(get_config()))
            )
        task_context = {
            **spec.task_context,
            "task_name": spec.task_name,
            "prompt": spec.prompt,
            "prompt_length": len(spec.prompt),
            "priority": spec.priority,
            "revision": record.revision,
        }
        lease: ModelLease | None = None
        outcome = "failure"
        started_monotonic = 0.0
        session_id = str(spec.session_id or "")
        message_id = ""
        source = OutputSource()
        try:
            lease = await acquire_model_lease(
                cli_config_source,
                global_concurrency=global_concurrency,
                required_capability=spec.required_capability,
                prefer_high=False,
                cancel_event=combined_cancel,
                stats_scope_id=spec.scope_id,
                task_context=task_context,
                priority=spec.priority,
                task_id=record.task_id,
                revision=record.revision,
                strict_capability=True,
                prefer_lowest_capability=True,
                wait_when_unavailable=True,
            )
            if lease is None:
                if record.requeue_requested:
                    return
                outcome = "cancelled"
                self._finish_record(
                    record,
                    status="cancelled",
                    session_id=session_id,
                    source=source,
                    error="OpenCode task cancelled while queued",
                )
                return

            record.status = "running"
            record.started_at = lease.started_at_iso or _now_iso()
            started_monotonic = lease.started_at or time.monotonic()

            runtime, model, source = await self._runtime_for_task(spec, lease)
            if spec.on_invocation_metadata:
                spec.on_invocation_metadata(source)

            async def record_session(value: str) -> None:
                nonlocal session_id
                session_id = str(value or "").strip()
                self._session_directories[session_id] = spec.directory
                self._session_runtimes[session_id] = runtime
                # Alias a newly-created task lock to its durable session before
                # exposing session_id.  A caller can immediately append another
                # prompt, but it will wait until the creating message finishes.
                self._session_locks.setdefault(session_id, session_lock)
                self._active_session_tasks[session_id] = record.task_id
                source.serve_session_id = session_id
                if not record.session_future.done():
                    record.session_future.set_result(session_id)
                await update_model_lease_context(lease, {"serve_session_id": session_id})

            def record_model(value: str) -> None:
                if value:
                    source.model = str(value)

            system_prompt = _load_skill_system_prompt(
                runtime.config_workspace or spec.workspace or spec.directory,
                spec.skills,
                directory=spec.directory,
            )
            if spec.output_schema is not None:
                result_rule = (
                    "Return the final result as plain JSON text matching the JSON Schema below. "
                    "The final assistant message must contain only that JSON value, without a "
                    "Markdown code fence or surrounding explanation. The application parses the "
                    "assistant text itself; do not call submit_result or any other result-submission "
                    "MCP tool.\nJSON Schema:\n"
                    + json.dumps(spec.output_schema, ensure_ascii=False, indent=2)
                )
                system_prompt = "\n\n".join(
                    section for section in (system_prompt, result_rule) if section
                )
            lock_key = session_id or f"new:{record.task_id}"
            session_lock = self._session_locks.setdefault(lock_key, asyncio.Lock())
            try:
                async with session_lock:
                    details = await get_serve_manager().run_prompt(
                        **runtime.kwargs(),
                        prompt=spec.prompt,
                        model=model,
                        timeout=spec.timeout_seconds or int(_cfg_value(spec.cli_config or get_config().opencode, "timeout", 1200)),
                        on_line=spec.on_output,
                        on_session_id=record_session,
                        on_response_model=record_model,
                        cancel_event=combined_cancel,
                        session_id=session_id or None,
                        session_title=spec.task_name,
                        mcp_tools=spec.mcp_tools,
                        system_prompt=system_prompt,
                        permissions=spec.permissions,
                        return_details=True,
                    )
            finally:
                if lock_key.startswith("new:"):
                    self._session_locks.pop(lock_key, None)
            assert isinstance(details, OpenCodePromptResult)
            session_id = details.session_id
            message_id = details.message_id
            text = details.text or "\n".join(details.lines)
            structured = _parse_text_json(text, spec.output_schema)
            outcome = "success"
            self._finish_record(
                record,
                status="success",
                session_id=session_id,
                message_id=message_id,
                text=text,
                structured=structured,
                model=source.model or details.model or model,
                source=source,
                started_monotonic=started_monotonic,
            )
        except asyncio.TimeoutError as exc:
            outcome = "timeout"
            self._finish_record(
                record,
                status="timeout",
                session_id=session_id,
                message_id=message_id,
                source=source,
                error=str(exc) or f"OpenCode task timed out after {spec.timeout_seconds}s",
                started_monotonic=started_monotonic,
            )
        except asyncio.CancelledError:
            if record.requeue_requested:
                return
            outcome = "cancelled"
            self._finish_record(
                record,
                status="cancelled",
                session_id=session_id,
                message_id=message_id,
                source=source,
                error="OpenCode task cancelled",
                started_monotonic=started_monotonic,
            )
        except Exception as exc:
            outcome = "failure"
            logger.exception("OpenCode task %s failed", record.task_id)
            self._finish_record(
                record,
                status="failure",
                session_id=session_id,
                message_id=message_id,
                source=source,
                error=str(exc),
                started_monotonic=started_monotonic,
            )
        finally:
            if session_id and self._active_session_tasks.get(session_id) == record.task_id:
                self._active_session_tasks.pop(session_id, None)
            duration = (
                max(0.0, time.monotonic() - started_monotonic)
                if started_monotonic
                else None
            )
            await release_model_lease(lease, outcome=outcome, duration_seconds=duration)

    async def _runtime_for_task(
        self,
        spec: OpenCodeTaskSpec,
        lease: ModelLease,
    ) -> tuple[_SessionRuntime, str, OutputSource]:
        # Imported lazily to keep runner's compatibility facade free of an
        # import cycle while the lower-level workspace helpers are migrated.
        from backend.opencode import runner as runtime_helpers

        cli_config = spec.cli_config or get_config().opencode
        effective = runtime_helpers._effective_cli_config(cli_config, lease.option)
        tool = runtime_helpers._normalize_tool(effective)
        if tool not in {"opencode", "nga"}:
            raise ValueError(f"Unsupported OpenCode serve tool: {tool}")
        if runtime_helpers._invocation_mode(effective) != "serve":
            raise ValueError("OpenCode tasks require serve invocation mode")
        executable = runtime_helpers._resolve_cli_executable(effective)
        model = str(_cfg_value(effective, "model", "") or "")
        workspace = spec.workspace or spec.directory
        cwd = runtime_helpers._select_cli_cwd(
            workspace,
            tool,
            spec.directory,
            runtime_namespace=runtime_helpers._serve_runtime_namespace(workspace),
        )
        config_workspace = runtime_helpers._prepare_cli_workspace(
            workspace,
            tool,
            runtime_cwd=cwd,
            writable_paths=spec.writable_paths,
        )
        serve_env = runtime_helpers._build_cli_env(
            config_workspace,
            tool,
            writable_paths=spec.writable_paths,
            project_dir=spec.directory,
            executable=executable,
            cli_config=effective,
        )
        runtime = _SessionRuntime(
            directory=spec.directory,
            tool=tool,
            executable=executable,
            config_workspace=config_workspace,
            config_content=serve_env.get("OPENCODE_CONFIG_CONTENT"),
            env_overrides=runtime_helpers._opencode_process_env_overrides(serve_env),
        )
        source = OutputSource(
            backend="opencode",
            tool=tool,
            model_id=lease.option.id,
            model=model,
            use_default_model=bool(lease.option.use_default_model),
            capability=lease.option.capability,
            required_capability=spec.required_capability,
            task_id=record_task_id(lease),
            attempt=spec.attempt,
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
        started_monotonic: float = 0.0,
    ) -> None:
        record.status = status
        if not record.session_future.done():
            record.session_future.set_result(session_id)
        if record.result_future.done():
            return
        record.result_future.set_result(OpenCodeTaskResult(
            task_id=record.task_id,
            session_id=session_id,
            message_id=message_id,
            status=status,
            text=text,
            structured=structured,
            model=model or source.model,
            output_source=source,
            error=error,
            queued_at=record.queued_at,
            started_at=record.started_at,
            finished_at=_now_iso(),
            duration_seconds=(
                max(0.0, time.monotonic() - started_monotonic)
                if started_monotonic
                else 0.0
            ),
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
        self._session_runtimes.pop(session_id, None)
        self._session_locks.pop(session_id, None)
        return result


def _cfg_value(config_obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


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


def _normalize_permissions(
    permissions: list[dict[str, str]] | None,
) -> list[dict[str, str]] | None:
    if permissions is None:
        return None
    normalized: list[dict[str, str]] = []
    for rule in permissions:
        if not isinstance(rule, dict):
            raise ValueError("OpenCode permission rules must be objects")
        permission = str(rule.get("permission") or "").strip()
        pattern = str(rule.get("pattern") or "").strip()
        action = str(rule.get("action") or "").strip().lower()
        if not permission or not pattern or action not in {"allow", "deny", "ask"}:
            raise ValueError(f"Invalid OpenCode permission rule: {rule!r}")
        normalized.append({
            "permission": permission,
            "pattern": pattern,
            "action": action,
        })
    return normalized


def _load_skill_system_prompt(
    workspace: Path,
    skills: list[str | Path],
    *,
    directory: Path | None = None,
) -> str:
    if not skills:
        return ""
    sections: list[str] = []
    search_bases = [workspace]
    if directory is not None and directory.resolve() != workspace.resolve():
        search_bases.append(directory.resolve())
    roots = [
        root
        for base in search_bases
        for root in (
            base / ".opencode" / "skills",
            base / ".agents" / "skills",
            base / "skills",
        )
    ]
    for raw in skills:
        candidate = Path(raw)
        skill_file: Path | None = None
        if candidate.is_absolute() or candidate.exists():
            if candidate.is_dir():
                candidate = candidate / "SKILL.md"
            if candidate.is_file():
                skill_file = candidate.resolve()
        else:
            name = str(raw).strip()
            for root in roots:
                resolved = root / name / "SKILL.md"
                if resolved.is_file():
                    skill_file = resolved.resolve()
                    break
        if skill_file is None:
            raise ValueError(f"OpenCode SKILL not found: {raw}")
        content = skill_file.read_text(encoding="utf-8", errors="replace")
        sections.append(
            f"## Task SKILL: {skill_file.parent.name}\n"
            f"Skill root: {skill_file.parent}\n\n{content.strip()}"
        )
    return (
        "The following SKILL instructions are explicitly selected for this task. "
        "Follow them for this message and resolve referenced resources relative to each skill root.\n\n"
        + "\n\n".join(sections)
    )


_service: OpenCodeTaskService | None = None


def get_opencode_task_service() -> OpenCodeTaskService:
    global _service
    if _service is None:
        _service = OpenCodeTaskService()
    return _service
