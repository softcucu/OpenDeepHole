"""Agent command handlers — invoked by the WebSocket message loop in main.py."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import re
import shutil
import threading
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.opencode.output_format import with_local_timestamp

# Module-level globals injected by agent/main.py before connection starts
_config = None       # AgentConfig
_reporter = None     # Reporter
_task_manager = None  # TaskManager
_agent_id: Optional[str] = None  # Assigned by server on WebSocket connect
_fp_review_tasks: dict[str, asyncio.Task] = {}
_fp_review_cancel_events: dict[str, threading.Event] = {}
_fp_review_scan_ids: dict[str, str] = {}
_fp_review_queues: dict[str, deque["_FpReviewQueueItem"]] = {}
_fp_review_active_items: set[tuple[str, int]] = set()
_validation_tasks: dict[tuple[str, int], asyncio.Task] = {}
_validation_cancel_events: dict[tuple[str, int], threading.Event] = {}
_validation_queues: dict[str, deque["_ValidationQueueItem"]] = {}
_validation_workers: dict[str, asyncio.Task] = {}


@dataclass
class _ValidationQueueItem:
    config: Any
    reporter: Any
    scan_id: str
    vuln_index: int
    project_path: str
    code_scan_path: str
    product: str
    validation_environment: str
    vulnerability: dict
    report_markdown: str
    cancel_event: threading.Event


@dataclass
class _FpReviewQueueItem:
    config: Any
    reporter: Any
    scan_id: str
    review_id: str
    project_path: str
    vulnerability: dict
    feedback_entries: list[dict]
    cancel_event: threading.Event
    processed_offset: int = 0
    planned_task_id: str = ""


def active_fp_review_snapshots() -> list[dict]:
    """Snapshot of FP reviews still running in this agent (for hello reattach)."""
    return [
        {"scan_id": scan_id, "review_id": review_id}
        for review_id, scan_id in _fp_review_scan_ids.items()
        if review_id in _fp_review_tasks
    ]


def active_validation_snapshots() -> list[dict]:
    """Snapshot of vulnerability validations still queued or running in this agent."""
    return [
        {"scan_id": scan_id, "vuln_index": vuln_index}
        for (scan_id, vuln_index), task in _validation_tasks.items()
        if not task.done()
    ]
_SKILL_CREATOR_NAME = "deephole-skill-creator"


async def _run(task, is_resume: bool) -> None:
    """Run a scan task, refreshing config from server first."""
    if _reporter is not None and _agent_id is not None:
        try:
            from agent.config import apply_network_env, apply_remote_config
            remote_cfg = await _reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(_config, remote_cfg)
                apply_network_env(_config)
        except Exception:
            pass

    from agent.scanner import run_scan
    try:
        await run_scan(
            config=_config,
            project_path=task.project_path,
            code_scan_path=task.code_scan_path,
            reporter=_reporter,
            scan_name=task.scan_name,
            scan_mode=task.scan_mode,
            product=task.product,
            validation_environment=task.validation_environment,
            checker_names=task.checkers,
            scan_id=task.scan_id,
            cancel_event=task.cancel_event,
            feedback_entries=task.feedback_entries,
            checker_packages=task.checker_packages,
            is_resume=is_resume,
            retry_candidates=task.retry_candidates,
            retry_total_candidates=task.retry_total_candidates,
            retry_processed_offset=task.retry_processed_offset,
            resume_threat_analysis=task.resume_threat_analysis,
            retry_threat_audit_task_ids=task.retry_threat_audit_task_ids,
        )
    finally:
        _task_manager.remove(task.scan_id)


async def handle_task(
    scan_id: str,
    project_path: str,
    code_scan_path: str | None,
    checkers: list[str],
    scan_name: str,
    scan_mode: str = "full",
    product: str = "",
    validation_environment: str = "",
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
) -> None:
    """Handle a 'task' command — start a new scan."""
    if _task_manager is None:
        print(f"Warning: task_manager not initialized, ignoring task {scan_id}")
        return

    existing = _task_manager.get(scan_id)
    if existing is not None:
        print(f"Warning: task {scan_id} already exists, ignoring duplicate")
        return

    task = _task_manager.create(
        scan_id=scan_id,
        project_path=project_path,
        code_scan_path=code_scan_path,
        checkers=checkers,
        scan_name=scan_name,
        scan_mode=scan_mode,
        product=product,
        validation_environment=validation_environment,
        feedback_entries=feedback_entries,
        checker_packages=checker_packages,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=False))
    print(f"Started task {scan_id}")


async def handle_stop(scan_id: str) -> None:
    """Handle a 'stop' command — cancel a running scan."""
    if _task_manager is None:
        return
    stopped = _task_manager.stop(scan_id)
    if stopped:
        print(f"Stopping task {scan_id}")
    else:
        print(f"Warning: task {scan_id} not found for stop")


async def handle_resume(
    scan_id: str,
    project_path: Optional[str] = None,
    code_scan_path: Optional[str] = None,
    checkers: Optional[list[str]] = None,
    scan_name: Optional[str] = None,
    scan_mode: Optional[str] = None,
    product: Optional[str] = None,
    validation_environment: Optional[str] = None,
    feedback_entries: Optional[list[dict]] = None,
    checker_packages: Optional[list[dict]] = None,
    retry_candidates: Optional[list[dict]] = None,
    retry_total_candidates: Optional[int] = None,
    retry_processed_offset: int = 0,
    resume_threat_analysis: bool = False,
    retry_threat_audit_task_ids: Optional[list[str]] = None,
) -> None:
    """Handle a 'resume' command — resume a stopped scan."""
    if _task_manager is None:
        return

    task = _task_manager.resume(scan_id)
    if task is None:
        if project_path is None:
            print(f"Warning: task {scan_id} not found and project_path not provided")
            return
        task = _task_manager.create(
            scan_id=scan_id,
            project_path=project_path,
            code_scan_path=code_scan_path,
            checkers=checkers or [],
            scan_name=scan_name or "",
            scan_mode=scan_mode or "full",
            product=product or "",
            validation_environment=validation_environment or "",
            feedback_entries=feedback_entries,
            checker_packages=checker_packages,
            retry_candidates=retry_candidates,
            retry_total_candidates=retry_total_candidates,
            retry_processed_offset=retry_processed_offset,
            resume_threat_analysis=resume_threat_analysis,
            retry_threat_audit_task_ids=retry_threat_audit_task_ids,
        )
    else:
        if project_path:
            task.project_path = Path(project_path)
        if code_scan_path:
            task.code_scan_path = Path(code_scan_path)
        elif project_path:
            task.code_scan_path = Path(project_path)
        if checkers is not None:
            task.checkers = checkers
        if scan_name is not None:
            task.scan_name = scan_name
        if scan_mode is not None:
            task.scan_mode = scan_mode
        if product is not None:
            task.product = product
        if validation_environment is not None:
            task.validation_environment = validation_environment
        if feedback_entries is not None:
            task.feedback_entries = feedback_entries
        if checker_packages is not None:
            task.checker_packages = checker_packages
        task.retry_candidates = retry_candidates
        task.retry_total_candidates = retry_total_candidates
        task.retry_processed_offset = retry_processed_offset
        task.resume_threat_analysis = resume_threat_analysis
        task.retry_threat_audit_task_ids = retry_threat_audit_task_ids

    if task.asyncio_task and not task.asyncio_task.done():
        task.asyncio_task.cancel()
        try:
            await task.asyncio_task
        except (asyncio.CancelledError, Exception):
            pass

    task.asyncio_task = asyncio.create_task(_run(task, is_resume=True))
    print(f"Resumed task {scan_id}")


async def handle_fp_review(
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
    feedback_entries: list[dict] | None = None,
    processed_offset: int = 0,
) -> None:
    """Handle an 'fp_review' command — queue AI false-positive review items."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return
    for offset, vulnerability in enumerate(vulnerabilities):
        await enqueue_fp_review(
            scan_id=scan_id,
            review_id=review_id,
            project_path=project_path,
            vulnerability=vulnerability,
            feedback_entries=feedback_entries or [],
            processed_offset=processed_offset + offset,
        )
    print(f"Queued {len(vulnerabilities)} FP review item(s) for scan {scan_id}")


async def enqueue_fp_review(
    *,
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerability: dict,
    feedback_entries: list[dict] | None = None,
    processed_offset: int = 0,
    config: Any | None = None,
    reporter: Any | None = None,
) -> bool:
    """Queue one vulnerability for an existing scan-level FP review job."""
    effective_config = config or _config
    effective_reporter = reporter or _reporter
    if effective_config is None or effective_reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return False
    try:
        vuln_index = int(vulnerability["index"])
    except (KeyError, TypeError, ValueError):
        print(f"Warning: FP review {review_id} item missing vulnerability index")
        return False
    item_key = (review_id, vuln_index)
    if item_key in _fp_review_active_items:
        print(f"Warning: FP review {review_id} vuln[{vuln_index}] already queued/running")
        return False

    cancel_event = _fp_review_cancel_events.get(review_id)
    if cancel_event is None:
        cancel_event = threading.Event()
        _fp_review_cancel_events[review_id] = cancel_event
    _fp_review_scan_ids[review_id] = scan_id
    _fp_review_active_items.add(item_key)
    queue = _fp_review_queues.setdefault(review_id, deque())
    queue.append(_FpReviewQueueItem(
        config=effective_config,
        reporter=effective_reporter,
        scan_id=scan_id,
        review_id=review_id,
        project_path=project_path,
        vulnerability=vulnerability,
        feedback_entries=feedback_entries or [],
        cancel_event=cancel_event,
        processed_offset=max(0, int(processed_offset or 0)),
        planned_task_id="",
    ))
    worker = _fp_review_tasks.get(review_id)
    if worker is None or worker.done():
        worker = asyncio.create_task(_run_fp_review_worker(review_id))
        _fp_review_tasks[review_id] = worker
    print(f"Queued FP review {review_id} vuln[{vuln_index}] for scan {scan_id}")
    return True


async def _run_fp_review_worker(review_id: str) -> None:
    """Run queued FP review items for one scan-level review job."""
    processed_offset = 0
    terminal_status = "complete"
    terminal_error: str | None = None
    try:
        while True:
            queue = _fp_review_queues.get(review_id)
            if not queue:
                break
            item = queue.popleft()
            scan_id = item.scan_id
            vuln_index = int(item.vulnerability["index"])
            processed_offset = max(processed_offset, item.processed_offset)
            try:
                if item.cancel_event.is_set():
                    if item.planned_task_id:
                        from backend.opencode.model_pool import clear_planned_task
                        await clear_planned_task(item.planned_task_id)
                    terminal_status = "cancelled"
                    terminal_error = "用户手动停止"
                    break
                processed = await _run_single_fp_review_item(item, processed_offset)
                processed_offset += max(0, processed)
            except Exception as exc:
                terminal_status = "error"
                terminal_error = str(exc)
                print(f"[fp_review] Unhandled error in review {review_id}: {exc}")
                break
            finally:
                _fp_review_active_items.discard((review_id, vuln_index))
    finally:
        queue = _fp_review_queues.pop(review_id, None)
        if queue is not None:
            for queued in queue:
                try:
                    _fp_review_active_items.discard((review_id, int(queued.vulnerability["index"])))
                except (KeyError, TypeError, ValueError):
                    pass
                if queued.planned_task_id:
                    try:
                        from backend.opencode.model_pool import clear_planned_task
                        await clear_planned_task(queued.planned_task_id)
                    except Exception:
                        pass
        scan_id = _fp_review_scan_ids.get(review_id, "")
        reporter = _reporter
        if reporter is not None and scan_id:
            try:
                await reporter.finish_fp_review(scan_id, review_id, terminal_status, terminal_error)
            except Exception:
                pass
        _fp_review_tasks.pop(review_id, None)
        _fp_review_cancel_events.pop(review_id, None)
        _fp_review_scan_ids.pop(review_id, None)


async def _run_single_fp_review_item(item: _FpReviewQueueItem, processed_offset: int) -> int:
    from agent.config import apply_network_env, apply_remote_config
    from agent.fp_reviewer import run_fp_review
    from backend.opencode.model_pool import clear_planned_task

    if item.planned_task_id:
        await clear_planned_task(item.planned_task_id)

    if item.reporter is not None and _agent_id is not None:
        try:
            remote_cfg = await item.reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(item.config, remote_cfg)
                apply_network_env(item.config)
        except Exception:
            pass
    return await run_fp_review(
        config=item.config,
        reporter=item.reporter,
        scan_id=item.scan_id,
        review_id=item.review_id,
        project_path=item.project_path,
        vulnerabilities=[item.vulnerability],
        feedback_entries=item.feedback_entries,
        cancel_event=item.cancel_event,
        processed_offset=processed_offset,
        finish_on_complete=False,
    )


async def handle_fp_review_stop(scan_id: str, review_id: str) -> None:
    """Handle an 'fp_review_stop' command — cancel a running FP review."""
    cancel_event = _fp_review_cancel_events.get(review_id)
    if cancel_event is not None:
        cancel_event.set()
        print(f"Stopping FP review {review_id} for scan {scan_id}")
        return
    task = _fp_review_tasks.get(review_id)
    if task is not None:
        task.cancel()
        print(f"Cancelling FP review task {review_id} for scan {scan_id}")
        return
    print(f"Warning: FP review {review_id} not found for stop")


async def handle_vulnerability_validation(
    scan_id: str,
    vuln_index: int,
    project_path: str,
    code_scan_path: str,
    product: str,
    validation_environment: str,
    vulnerability: dict,
    report_markdown: str,
) -> None:
    """Handle a 'vulnerability_validation' command — queue local validation by scan."""
    await enqueue_vulnerability_validation(
        scan_id=scan_id,
        vuln_index=vuln_index,
        project_path=project_path,
        code_scan_path=code_scan_path,
        product=product,
        validation_environment=validation_environment,
        vulnerability=vulnerability,
        report_markdown=report_markdown,
    )


async def enqueue_vulnerability_validation(
    *,
    scan_id: str,
    vuln_index: int,
    project_path: str,
    code_scan_path: str,
    product: str,
    validation_environment: str,
    vulnerability: dict,
    report_markdown: str,
    config: Any | None = None,
    reporter: Any | None = None,
    report_queued: bool = False,
) -> bool:
    """Queue local vulnerability validation independently from scan tasks."""
    effective_config = config or _config
    effective_reporter = reporter or _reporter
    if effective_config is None or effective_reporter is None:
        print(f"Warning: agent not fully initialized, ignoring validation {scan_id}#{vuln_index}")
        return False
    task_key = (scan_id, vuln_index)
    existing = _validation_tasks.get(task_key)
    if existing is not None and not existing.done():
        print(f"Warning: validation {scan_id}#{vuln_index} already running, ignoring duplicate")
        return False

    cancel_event = threading.Event()
    item = _ValidationQueueItem(
        config=effective_config,
        reporter=effective_reporter,
        scan_id=scan_id,
        vuln_index=vuln_index,
        project_path=project_path,
        code_scan_path=code_scan_path,
        product=product,
        validation_environment=validation_environment,
        vulnerability=vulnerability,
        report_markdown=report_markdown,
        cancel_event=cancel_event,
    )

    if report_queued:
        await _report_validation_queued(item)

    queue = _validation_queues.setdefault(scan_id, deque())
    queue.append(item)
    worker = _validation_workers.get(scan_id)
    if worker is None or worker.done():
        worker = asyncio.create_task(_run_validation_worker(scan_id))
        _validation_workers[scan_id] = worker
    _validation_tasks[task_key] = worker
    _validation_cancel_events[task_key] = cancel_event

    path_hint = f" ({project_path})" if project_path else ""
    print(f"Queued vulnerability validation {scan_id}#{vuln_index}{path_hint}")
    return True


async def _report_validation_queued(item: _ValidationQueueItem) -> None:
    from backend.models import VulnerabilityValidation

    now = datetime.now(timezone.utc).isoformat()
    try:
        await item.reporter.report_vulnerability_validation(
            item.scan_id,
            VulnerabilityValidation(
                scan_id=item.scan_id,
                vuln_index=item.vuln_index,
                status="queued",
                running=True,
                product=item.product,
                validation_environment=item.validation_environment,
                started_at=now,
                updated_at=now,
            ),
        )
    except Exception as exc:
        print(f"Warning: failed to report queued validation {item.scan_id}#{item.vuln_index}: {exc}")


async def _run_validation_worker(scan_id: str) -> None:
    """Run one vulnerability validation at a time for a scan."""
    try:
        while True:
            queue = _validation_queues.get(scan_id)
            if not queue:
                return
            item = queue.popleft()
            task_key = (item.scan_id, item.vuln_index)
            try:
                if item.cancel_event.is_set():
                    print(f"Skipping cancelled validation {item.scan_id}#{item.vuln_index}")
                    await _report_validation_cancelled(item)
                    continue
                await _run_single_validation(item)
            finally:
                _validation_tasks.pop(task_key, None)
                _validation_cancel_events.pop(task_key, None)
    finally:
        queue = _validation_queues.pop(scan_id, None)
        if queue is not None:
            for queued in queue:
                task_key = (queued.scan_id, queued.vuln_index)
                _validation_tasks.pop(task_key, None)
                _validation_cancel_events.pop(task_key, None)
        _validation_workers.pop(scan_id, None)


async def _report_validation_cancelled(item: _ValidationQueueItem) -> None:
    from backend.models import VulnerabilityValidation

    now = datetime.now(timezone.utc).isoformat()
    try:
        await item.reporter.report_vulnerability_validation(
            item.scan_id,
            VulnerabilityValidation(
                scan_id=item.scan_id,
                vuln_index=item.vuln_index,
                status="cancelled",
                running=False,
                product=item.product,
                validation_environment=item.validation_environment,
                validation_success=False,
                requires_human_intervention=True,
                validation_output="Validation cancelled before execution",
                final_output="Validation cancelled before execution",
                finished_at=now,
                updated_at=now,
            ),
        )
    except Exception as exc:
        print(
            f"Warning: failed to report cancelled validation "
            f"{item.scan_id}#{item.vuln_index}: {exc}"
        )


async def _run_single_validation(item: _ValidationQueueItem) -> None:
    from agent.config import apply_network_env, apply_remote_config
    from agent.vulnerability_validation import run_vulnerability_validation
    from backend.models import Vulnerability

    if item.reporter is not None and _agent_id is not None:
        try:
            remote_cfg = await item.reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(item.config, remote_cfg)
                apply_network_env(item.config)
        except Exception:
            pass
    try:
        work_root = Path.home() / ".opendeephole" / "vulnerability_validation" / "runs" / item.scan_id
        await run_vulnerability_validation(
            config=item.config,
            reporter=item.reporter,
            scan_id=item.scan_id,
            vuln_index=item.vuln_index,
            vulnerability=Vulnerability(**item.vulnerability),
            report_markdown=item.report_markdown,
            scan_dir=work_root,
            project_path=Path(item.project_path) if item.project_path else None,
            code_scan_path=Path(item.code_scan_path) if item.code_scan_path else None,
            product=item.product,
            validation_environment=item.validation_environment,
            cancel_event=item.cancel_event,
        )
    except Exception as exc:
        print(f"[validation] Unhandled error in validation {item.scan_id}#{item.vuln_index}: {exc}")
        from backend.models import VulnerabilityValidation

        now = datetime.now(timezone.utc).isoformat()
        try:
            await item.reporter.report_vulnerability_validation(
                item.scan_id,
                VulnerabilityValidation(
                    scan_id=item.scan_id,
                    vuln_index=item.vuln_index,
                    status="error",
                    running=False,
                    product=item.product,
                    validation_environment=item.validation_environment,
                    validation_success=False,
                    requires_human_intervention=True,
                    validation_output=f"Validation setup failed: {exc}",
                    final_output=f"Validation setup failed: {exc}",
                    finished_at=now,
                    updated_at=now,
                ),
            )
        except Exception as report_exc:
            print(
                f"Warning: failed to report validation setup error "
                f"{item.scan_id}#{item.vuln_index}: {report_exc}"
            )


async def handle_vulnerability_validation_stop(scan_id: str, vuln_index: int) -> None:
    """Handle a 'vulnerability_validation_stop' command."""
    task_key = (scan_id, vuln_index)
    cancel_event = _validation_cancel_events.get(task_key)
    if cancel_event is not None:
        cancel_event.set()
        print(f"Stopping vulnerability validation {scan_id}#{vuln_index}")
        return
    task = _validation_tasks.get(task_key)
    if task is not None and not task.done():
        task.cancel()
        print(f"Cancelling validation task {scan_id}#{vuln_index}")
        return
    print(f"Warning: validation {scan_id}#{vuln_index} not found for stop")


async def handle_feedback_selection_update(scan_id: str, feedback_entries: list[dict]) -> None:
    """Handle selected feedback changes while a scan or FP review is active."""
    if _task_manager is not None:
        task = _task_manager.get(scan_id)
        if task is not None:
            task.feedback_entries = feedback_entries
    from backend.opencode.task_service import set_scan_feedback_entries
    set_scan_feedback_entries(scan_id, feedback_entries)
    from agent.fp_reviewer import set_fp_review_feedback
    set_fp_review_feedback(scan_id, feedback_entries)


async def handle_opencode_models(request_id: str, refresh: bool = False) -> dict:
    """Return models visible to the Agent's OpenCode-compatible serve process."""
    try:
        from backend.opencode.serve_client import get_serve_manager
        from backend.opencode.runner import _build_cli_env, _opencode_process_env_overrides

        if _config is None:
            raise RuntimeError("Agent config is not initialized")
        tool = str(getattr(_config.opencode, "tool", "") or "opencode").strip().lower() or "opencode"
        executable = str(getattr(_config.opencode, "executable", "") or tool)
        if tool not in {"opencode", "nga"}:
            raise RuntimeError(f"{tool} does not support serve model listing")
        serve_env = _build_cli_env(
            Path.cwd(),
            tool,
            project_dir=Path.cwd(),
            executable=executable,
            cli_config=_config.opencode,
        )
        model_result = await get_serve_manager().list_models(
            tool=tool,
            executable=executable,
            config_content=serve_env.get("OPENCODE_CONFIG_CONTENT"),
            env_overrides=_opencode_process_env_overrides(serve_env),
            refresh=refresh,
        )
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": True,
            "message": model_result.message,
            "models": [
                {
                    "id": item.id,
                    "model": item.id,
                    "provider_id": item.provider_id,
                    "model_id": item.model_id,
                    "name": item.name,
                }
                for item in model_result.models
            ],
        }
    except Exception as exc:
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
            "models": [],
        }


async def handle_skill_create(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None = None,
) -> dict:
    """Create a pure project-level SKILL draft through the OpenCode task service."""
    try:
        draft = await _run_skill_creator(request_id, name, description, user_input, skill_creator_package)
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": True,
            "draft": draft,
        }
    except Exception as exc:
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
        }


async def _run_skill_creator(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None,
) -> dict:
    if _config is None:
        raise RuntimeError("Agent config is not initialized")

    from agent.scanner import _configure_backend
    from backend.opencode.config import get_global_opencode_workspace, get_workspace_lock
    from backend.opencode.runner import _invoke_opencode

    request_dir = Path.home() / ".opendeephole" / "skill_create" / request_id
    if request_dir.exists():
        shutil.rmtree(request_dir, ignore_errors=True)
    request_dir.mkdir(parents=True, exist_ok=True)
    workspace = get_global_opencode_workspace()
    with get_workspace_lock(workspace):
        _write_skill_creator_package(
            skill_creator_package or {},
            workspace / ".opencode" / "skills",
        )

    _configure_backend(_config, request_dir)
    prompt = _skill_creator_prompt(name, description, user_input)

    def on_output(line: str) -> None:
        if line:
            print(with_local_timestamp(line, prefix="[skill_create]"), flush=True)

    output_text = await _invoke_opencode(
        prompt,
        timeout=_config.opencode.timeout,
        on_line=on_output,
        directory=request_dir,
        model_capability="high",
        prefer_high_model=True,
        task_name="skill_create",
        priority=70,
        task_metadata={"task_type": "skill_create"},
        output_schema={
            "type": "object",
            "properties": {
                "skill_md": {"type": "string"},
                "scenarios_md": {"type": "string"},
                "summary": {"type": "string"},
            },
            "required": ["skill_md", "scenarios_md", "summary"],
            "additionalProperties": False,
        },
    )
    return _parse_skill_creator_output(output_text)


def _write_skill_creator_package(package: dict, skills_root: Path) -> None:
    name = str(package.get("name") or "").strip()
    if name != _SKILL_CREATOR_NAME:
        raise RuntimeError("Invalid deephole-skill-creator package name")

    expected_hash = str(package.get("sha256") or "").strip()
    encoded = str(package.get("archive_b64") or "")
    if not expected_hash or not encoded:
        raise RuntimeError("Invalid deephole-skill-creator package metadata")

    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError("deephole-skill-creator package hash mismatch")

    skill_dir = skills_root / _SKILL_CREATOR_NAME
    if skill_dir.exists():
        shutil.rmtree(skill_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)
    wrote_skill = False

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}")
                dest = (skill_dir / member).resolve()
                try:
                    dest.relative_to(skill_dir.resolve())
                except ValueError as exc:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}") from exc
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
                if member.as_posix() == "SKILL.md":
                    wrote_skill = True
    except zipfile.BadZipFile as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc

    if not wrote_skill:
        raise RuntimeError("deephole-skill-creator package missing SKILL.md")


def _skill_creator_prompt(name: str, description: str, user_input: str) -> str:
    return (
        "使用 `deephole-skill-creator` 技能，为 OpenDeepHole 创建一个纯 SKILL 项目级审计检查项草稿。"
        "不要创建 analyzer.py、脚本或资源文件。"
        "只输出一个 JSON 对象，不要输出 Markdown 代码围栏之外的解释。"
        "JSON 字段必须包含："
        "`skill_md`（完整 SKILL.md 内容，包含 YAML frontmatter 和项目级审计要求）、"
        "`scenarios_md`（面向用户的适用场景说明，可为空字符串）、"
        "`summary`（一句话说明）。"
        "SKILL 必须要求审计者在扫描时主动阅读代码，发现每个真实问题都在最终 JSON 的 results 数组中输出一个元素；"
        "未发现问题也必须输出一个 confirmed=false 的 results 元素。"
        f"\n名称：{name}"
        f"\n描述：{description}"
        f"\n用户输入：{user_input}"
    )


def _parse_skill_creator_output(output: str) -> dict:
    candidates = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", output, flags=re.DOTALL)
    candidates.extend(fenced)
    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end > start:
        candidates.append(output[start:end + 1])

    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        skill_md = str(data.get("skill_md") or "").strip()
        if skill_md:
            return {
                "skill_md": skill_md,
                "scenarios_md": str(data.get("scenarios_md") or "").strip(),
                "summary": str(data.get("summary") or "").strip(),
            }
    raise RuntimeError("Agent did not return a valid SKILL draft")
