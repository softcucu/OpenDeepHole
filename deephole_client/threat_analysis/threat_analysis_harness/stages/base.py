"""Shared helpers for agent-backed business stages."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Protocol, Sequence

from threat_analysis_harness.errors import StageExecutionError

TaskJson = Dict[str, Any]
TaskResultJson = Dict[str, Any]
SUCCEEDED = "succeeded"


class SubmitTasks(Protocol):
    def __call__(
        self,
        tasks: Sequence[TaskJson],
        *,
        timeout: float | None = None,
    ) -> list[TaskResultJson]:
        ...


class ProgressReporter(Protocol):
    def emit(self, message: str) -> None:
        ...


def require_success(result: TaskResultJson) -> TaskResultJson:
    if result.get("status") != SUCCEEDED:
        raise StageExecutionError(
            f"Task {result.get('task_id')} failed with status={result.get('status')}: "
            f"{result.get('error')}"
        )
    return result


def require_all_success(results: Iterable[TaskResultJson]) -> list[TaskResultJson]:
    return [require_success(result) for result in results]


def existing_success_result(task: TaskJson) -> TaskResultJson | None:
    output_path = str(task["output_path"])
    if not Path(output_path).exists():
        return None

    try:
        output = json.loads(Path(output_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    now = time.time()
    return {
        "task_id": str(task["task_id"]),
        "task_type": str(task["task_type"]),
        "status": SUCCEEDED,
        "output_path": output_path,
        "started_at": now,
        "finished_at": now,
        "returncode": 0,
        "output": output,
        "metadata": dict(task.get("metadata", {})),
    }


def run_or_resume_tasks(
    *,
    submit_tasks: SubmitTasks,
    tasks: list[TaskJson],
    resume: bool = False,
    timeout: float | None = None,
    progress_reporter: ProgressReporter | None = None,
) -> list[TaskResultJson]:
    results, pending, pending_indexes = resume_existing_tasks(
        tasks,
        resume=resume,
        progress_reporter=progress_reporter,
    )

    if pending:
        pending_results = submit_tasks(pending, timeout=timeout)
        fill_pending_results(results, pending_indexes, pending_results)

    return completed_results(results)


def run_or_resume_task(
    *,
    submit_tasks: SubmitTasks,
    task: TaskJson,
    resume: bool = False,
    timeout: float | None = None,
    progress_reporter: ProgressReporter | None = None,
) -> TaskResultJson:
    return run_or_resume_tasks(
        submit_tasks=submit_tasks,
        tasks=[task],
        resume=resume,
        timeout=timeout,
        progress_reporter=progress_reporter,
    )[0]


def resume_existing_tasks(
    tasks: list[TaskJson],
    *,
    resume: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> tuple[list[TaskResultJson | None], list[TaskJson], list[int]]:
    results: list[TaskResultJson | None] = [None] * len(tasks)
    pending: list[TaskJson] = []
    pending_indexes: list[int] = []

    for index, task in enumerate(tasks):
        existing = existing_success_result(task) if resume else None
        if existing is not None:
            results[index] = existing
            if progress_reporter is not None:
                progress_reporter.emit(
                    f"task resumed: task_id={task['task_id']} task_type={task['task_type']} "
                    f"output={task['output_path']}"
                )
            continue
        pending.append(task)
        pending_indexes.append(index)

    return results, pending, pending_indexes


def fill_pending_results(
    results: list[TaskResultJson | None],
    pending_indexes: list[int],
    pending_results: Iterable[TaskResultJson],
) -> None:
    for index, result in zip(pending_indexes, pending_results):
        results[index] = result


def completed_results(results: list[TaskResultJson | None]) -> list[TaskResultJson]:
    return [result for result in results if result is not None]
