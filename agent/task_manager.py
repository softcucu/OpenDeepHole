"""Manages scan tasks for the agent daemon."""
from __future__ import annotations
import asyncio
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanTask:
    scan_id: str
    project_path: Path
    code_scan_path: Path
    checkers: list[str]
    scan_name: str
    feedback_entries: list[dict] = field(default_factory=list)
    checker_packages: list[dict] = field(default_factory=list)
    retry_candidates: list[dict] | None = None
    retry_total_candidates: int | None = None
    retry_processed_offset: int = 0
    cancel_event: threading.Event = field(default_factory=threading.Event)
    asyncio_task: Optional[asyncio.Task] = None


class TaskManager:
    def __init__(self):
        self._tasks: dict[str, ScanTask] = {}

    def create(
        self,
        scan_id: str,
        project_path: str,
        code_scan_path: str | None,
        checkers: list[str],
        scan_name: str,
        feedback_entries: list[dict] | None = None,
        checker_packages: list[dict] | None = None,
        retry_candidates: list[dict] | None = None,
        retry_total_candidates: int | None = None,
        retry_processed_offset: int = 0,
    ) -> ScanTask:
        task = ScanTask(
            scan_id=scan_id,
            project_path=Path(project_path),
            code_scan_path=Path(code_scan_path or project_path),
            checkers=checkers,
            scan_name=scan_name,
            feedback_entries=feedback_entries or [],
            checker_packages=checker_packages or [],
            retry_candidates=retry_candidates,
            retry_total_candidates=retry_total_candidates,
            retry_processed_offset=retry_processed_offset,
        )
        self._tasks[scan_id] = task
        return task

    def get(self, scan_id: str) -> Optional[ScanTask]:
        return self._tasks.get(scan_id)

    def stop(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task:
            task.cancel_event.set()
            return True
        return False

    def resume(self, scan_id: str) -> Optional[ScanTask]:
        task = self._tasks.get(scan_id)
        if task:
            task.cancel_event.clear()
        return task

    def remove(self, scan_id: str) -> None:
        self._tasks.pop(scan_id, None)

    def active_snapshots(self) -> list[dict]:
        """Return serializable metadata for scans still running locally."""
        active: list[dict] = []
        for task in self._tasks.values():
            if task.cancel_event.is_set():
                continue
            if task.asyncio_task is None or task.asyncio_task.done():
                continue
            active.append({
                "scan_id": task.scan_id,
                "project_path": str(task.project_path),
                "code_scan_path": str(task.code_scan_path),
                "checkers": task.checkers,
                "scan_name": task.scan_name,
            })
        return active
