"""Async public entry point for standalone static analysis."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

from code_parser import CodeDatabase

from .models import Candidate
from .registry import Checker, discover_checkers
from .source_filter import source_path_has_ignored_dir

PROCESS_NAME = "static_analysis"
_ALLOWED_KEYS = {
    "project_path", "index_db_path", "checker_dirs", "code_scan_path",
    "checker_names", "deduplicate", "output", "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "index_db_path", "checker_dirs"}
PROJECT_LEVEL_FUNCTION = "__project__"


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    value = output({
        "process": PROCESS_NAME,
        "kind": kind,
        "message": message,
        "data": data,
    })
    if inspect.isawaitable(value):
        await value


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _path(value: Any, key: str, *, directory: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if directory and not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    if not directory and not path.is_file():
        raise FileNotFoundError(f"{key} is not a file: {path}")
    return path


def _normalize_candidate(candidate: Candidate, project: Path, scan_root: Path) -> Candidate | None:
    raw = Path(candidate.file)
    choices = [raw] if raw.is_absolute() else [project / raw, scan_root / raw]
    resolved = next((item.resolve() for item in choices if item.exists()), choices[0].resolve())
    try:
        resolved.relative_to(scan_root)
    except ValueError:
        return None
    try:
        relative = resolved.relative_to(project).as_posix()
    except ValueError:
        return None
    if source_path_has_ignored_dir(relative):
        return None
    return candidate.model_copy(update={"file": relative})


def _project_candidate(checker: Checker, project: Path, scan_root: Path) -> Candidate:
    relative = "." if project == scan_root else scan_root.relative_to(project).as_posix()
    return Candidate(
        file=relative,
        line=1,
        function=PROJECT_LEVEL_FUNCTION,
        description=f"Project-level audit for {checker.label}",
        vuln_type=checker.name,
    )


async def run_static_analysis(**kwargs: Any) -> dict[str, Any]:
    """Run checker analyzers and return a JSON-serializable batch result.

    Accepted keys are documented in this directory's README. Unknown keys are
    rejected so a standalone caller and the platform use the same contract.
    """
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_static_analysis() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "", []))
    if missing:
        raise TypeError(f"run_static_analysis() missing required key(s): {', '.join(missing)}")

    project = _path(kwargs["project_path"], "project_path", directory=True)
    scan_root = _path(kwargs.get("code_scan_path") or project, "code_scan_path", directory=True)
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError("code_scan_path must be inside project_path") from exc
    index_path = _path(kwargs["index_db_path"], "index_db_path")
    checker_dirs = [_path(item, "checker_dirs", directory=True) for item in kwargs["checker_dirs"]]
    checker_names = kwargs.get("checker_names")
    if checker_names is not None and not isinstance(checker_names, list):
        raise TypeError("checker_names must be a list or None")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    deduplicate = bool(kwargs.get("deduplicate", True))

    registry = discover_checkers(checker_dirs, checker_names)
    await _emit(output, "progress", f"Discovered {len(registry)} checker(s)", total=len(registry))
    if _cancelled(cancel_event):
        return {"status": "cancelled", "candidates": [], "stats": {"total": 0, "checkers": {}}}

    def execute() -> tuple[list[Candidate], dict[str, int], bool]:
        database = CodeDatabase(index_path)
        candidates: list[Candidate] = []
        counts: dict[str, int] = {}
        try:
            for checker in registry.values():
                if _cancelled(cancel_event):
                    return candidates, counts, True
                before = len(candidates)
                if checker.analyzer is None:
                    if checker.mode == "opencode":
                        candidates.append(_project_candidate(checker, project, scan_root))
                else:
                    for raw in checker.analyzer.find_candidates(scan_root, db=database):
                        if _cancelled(cancel_event):
                            return candidates, counts, True
                        candidate = raw if isinstance(raw, Candidate) else Candidate.model_validate(raw)
                        normalized = _normalize_candidate(candidate, project, scan_root)
                        if normalized is not None:
                            candidates.append(normalized)
                counts[checker.name] = len(candidates) - before
        finally:
            database.close()
        return candidates, counts, False

    # Checker analyzers are synchronous by contract.  Keeping execution in the
    # caller thread also makes this directory usable in restricted Python
    # hosts where worker threads are unavailable; cancellation is checked
    # between every yielded candidate.
    candidates, counts, was_cancelled = execute()
    if deduplicate:
        unique: dict[tuple[str, int, str, str], Candidate] = {}
        for candidate in candidates:
            unique.setdefault(
                (candidate.file, candidate.line, candidate.function, candidate.vuln_type),
                candidate,
            )
        candidates = list(unique.values())
    status = "cancelled" if was_cancelled else "success"
    await _emit(
        output,
        "progress",
        f"Static analysis {status}: {len(candidates)} candidate(s)",
        total=len(candidates),
        checker_counts=counts,
    )
    return {
        "status": status,
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "stats": {"total": len(candidates), "checkers": counts},
    }
