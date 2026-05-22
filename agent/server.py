"""Agent command handlers — invoked by the WebSocket message loop in main.py."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

# Module-level globals injected by agent/main.py before connection starts
_config = None       # AgentConfig
_reporter = None     # Reporter
_task_manager = None  # TaskManager
_agent_id: Optional[str] = None  # Assigned by server on WebSocket connect


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
            checker_names=task.checkers,
            scan_id=task.scan_id,
            cancel_event=task.cancel_event,
            feedback_entries=task.feedback_entries,
            checker_packages=task.checker_packages,
            is_resume=is_resume,
        )
    finally:
        _task_manager.remove(task.scan_id)


async def handle_task(
    scan_id: str,
    project_path: str,
    code_scan_path: str | None,
    checkers: list[str],
    scan_name: str,
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
    feedback_entries: Optional[list[dict]] = None,
    checker_packages: Optional[list[dict]] = None,
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
            feedback_entries=feedback_entries,
            checker_packages=checker_packages,
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
        if feedback_entries is not None:
            task.feedback_entries = feedback_entries
        if checker_packages is not None:
            task.checker_packages = checker_packages

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
) -> None:
    """Handle an 'fp_review' command — start AI false-positive review."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return

    async def _run_review() -> None:
        from agent.fp_reviewer import run_fp_review
        try:
            await run_fp_review(
                config=_config,
                reporter=_reporter,
                scan_id=scan_id,
                review_id=review_id,
                project_path=project_path,
                vulnerabilities=vulnerabilities,
                feedback_entries=feedback_entries or [],
            )
        except Exception as exc:
            print(f"[fp_review] Unhandled error in review {review_id}: {exc}")

    asyncio.create_task(_run_review())
    print(f"Started FP review {review_id} for scan {scan_id}")


async def handle_feedback_selection_update(scan_id: str, feedback_entries: list[dict]) -> None:
    """Handle selected feedback changes while a scan or FP review is active."""
    if _task_manager is not None:
        task = _task_manager.get(scan_id)
        if task is not None:
            task.feedback_entries = feedback_entries
            try:
                from backend.models import FeedbackEntry
                from backend.opencode.config import refresh_skills
                selected_feedback = [FeedbackEntry(**entry) for entry in feedback_entries]
                workspace = Path.home() / ".opendeephole" / "scans" / scan_id / "opencode_workspace"
                await asyncio.to_thread(
                    refresh_skills,
                    workspace,
                    task.project_path,
                    selected_feedback,
                )
            except Exception as exc:
                print(f"Warning: failed to refresh scan skills for feedback update: {exc}")
    from agent.fp_reviewer import set_fp_review_feedback
    set_fp_review_feedback(scan_id, feedback_entries)


async def handle_config_test(request_id: str, remote_config: dict) -> dict:
    """Validate a candidate remote config without mutating the live Agent config."""
    import copy
    import os

    from agent.config import apply_remote_config
    from backend.opencode.llm_api_runner import probe_llm_api_config

    test_config = copy.deepcopy(_config)
    apply_remote_config(test_config, remote_config)

    old_no_proxy = os.environ.get("no_proxy")
    old_no_proxy_upper = os.environ.get("NO_PROXY")
    try:
        if test_config.no_proxy:
            os.environ["no_proxy"] = test_config.no_proxy
            os.environ["NO_PROXY"] = test_config.no_proxy
        else:
            os.environ.pop("no_proxy", None)
            os.environ.pop("NO_PROXY", None)
        ok, reason = await asyncio.to_thread(probe_llm_api_config, test_config.llm_api)
    except Exception as exc:
        ok, reason = False, str(exc)
    finally:
        if old_no_proxy is None:
            os.environ.pop("no_proxy", None)
        else:
            os.environ["no_proxy"] = old_no_proxy
        if old_no_proxy_upper is None:
            os.environ.pop("NO_PROXY", None)
        else:
            os.environ["NO_PROXY"] = old_no_proxy_upper

    return {
        "type": "config_test_result",
        "request_id": request_id,
        "ok": ok,
        "message": "API 配置可用" if ok else reason,
    }
