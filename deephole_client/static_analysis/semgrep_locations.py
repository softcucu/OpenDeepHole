"""Location helpers for semgrep-backed checker analyzers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        return row.get(key, default) if hasattr(row, "get") else default


def path_variants(path: str, project_path: Path | None = None) -> list[str]:
    normalized = path.replace("\\", "/").strip("/")
    variants = [normalized]
    if project_path is not None:
        project_name = project_path.name.replace("\\", "/").strip("/")
        if normalized.startswith(f"{project_name}/"):
            variants.append(normalized[len(project_name) + 1:])
        try:
            variants.append(Path(path).resolve().relative_to(project_path.resolve()).as_posix())
        except (OSError, ValueError):
            pass
    result: list[str] = []
    for item in variants:
        if item and item not in result:
            result.append(item)
    return result


def path_matches(indexed_path: str, reported_path: str, project_path: Path) -> bool:
    for indexed in path_variants(indexed_path, project_path):
        for reported in path_variants(reported_path, project_path):
            left, right = indexed.casefold(), reported.casefold()
            if left == right or left.endswith(f"/{right}") or right.endswith(f"/{left}"):
                return True
    return False


def relative_reported_path(project_path: Path, reported_path: str) -> str:
    variants = path_variants(reported_path, project_path)
    return min(variants, key=len) if variants else reported_path.replace("\\", "/")


def function_from_db_location(
    db: Any,
    project_path: Path,
    reported_path: str,
    line: int,
    *,
    clean_func_name: Callable[[object], str],
) -> str:
    get_by_location = getattr(db, "get_function_by_location", None)
    if callable(get_by_location):
        try:
            row = get_by_location(relative_reported_path(project_path, reported_path), line)
        except Exception:
            row = None
        return clean_func_name(_row_get(row, "name", "")) if row is not None else ""
    get_all_functions = getattr(db, "get_all_functions", None)
    if not callable(get_all_functions):
        return ""
    try:
        for func in get_all_functions():
            if (
                _row_get(func, "file_path", "")
                and path_matches(str(_row_get(func, "file_path")), reported_path, project_path)
                and _row_get(func, "start_line", 0) <= line <= _row_get(func, "end_line", 0)
            ):
                return clean_func_name(_row_get(func, "name", ""))
    except Exception:
        pass
    return ""
