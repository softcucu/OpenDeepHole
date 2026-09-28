"""Shared scan lifecycle helpers.

The persisted scan row is the authority for top-level lifecycle state.  Model
pool snapshots contain both durable history and transient scheduler state.
Terminal transitions clear live work owned by the scan, while independent
review jobs retain their own lifecycle.
"""

from __future__ import annotations

from typing import Callable

from backend.models import OpenCodePoolStatus, ScanItemStatus


AGENT_DISCONNECT_ERROR = "Agent 断开连接"
AGENT_RECOVERY_IN_PROGRESS = "Agent 进程已重启，正在自动断点恢复"
AGENT_RECOVERY_FAILED_PREFIX = "Agent 自动断点恢复失败："


def is_agent_recovery_interruption(status: ScanItemStatus | str, error: str | None) -> bool:
    return (
        status == ScanItemStatus.CANCELLED
        and error in {AGENT_DISCONNECT_ERROR, AGENT_RECOVERY_IN_PROGRESS}
    ) or (
        status == ScanItemStatus.ERROR
        and str(error or "").startswith(AGENT_RECOVERY_FAILED_PREFIX)
    )


RUNNING_SCAN_STATUSES = frozenset({
    ScanItemStatus.PENDING,
    ScanItemStatus.ANALYZING,
    ScanItemStatus.AUDITING,
})

TERMINAL_SCAN_STATUSES = frozenset({
    ScanItemStatus.COMPLETE,
    ScanItemStatus.ERROR,
    ScanItemStatus.CANCELLED,
})


def is_terminal_scan_status(status: ScanItemStatus | str | None) -> bool:
    """Return whether *status* is a recognized top-level terminal state."""
    try:
        normalized = ScanItemStatus(status) if status is not None else None
    except ValueError:
        return False
    return normalized in TERMINAL_SCAN_STATUSES


def terminal_opencode_pool_status(
    status: OpenCodePoolStatus | None,
    *,
    keep_task: Callable[[dict], bool] | None = None,
) -> OpenCodePoolStatus | None:
    """Clear live work except explicit survivors; preserve accumulated history."""
    if status is None:
        return None
    cleared = status.model_copy(deep=True)
    keep = keep_task or (lambda _task: False)
    cleared.queued_tasks = [task for task in cleared.queued_tasks if keep(task)]
    cleared.planned_tasks = [task for task in cleared.planned_tasks if keep(task)]
    for model in cleared.models:
        model.active_tasks = [task for task in model.active_tasks if keep(task)]
        model.running = len(model.active_tasks)
        model.queued = sum(task.get("model_id") == model.id for task in cleared.queued_tasks)
        if not model.running and not model.queued and model.last_status in {"running", "queued"}:
            model.last_status = ""
    cleared.global_running = sum(model.running for model in cleared.models)
    cleared.global_queued = len(cleared.queued_tasks)
    return cleared
