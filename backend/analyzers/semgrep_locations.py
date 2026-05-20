"""Location helpers shared by semgrep-based static analyzers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        if hasattr(row, "get"):
            return row.get(key, default)
        return default


def path_variants(path: str, project_path: Path | None = None) -> list[str]:
    normalized = path.replace("\\", "/").strip("/")
    variants = [normalized]

    if project_path is not None:
        project_name = project_path.name.replace("\\", "/").strip("/")
        if normalized.startswith(f"{project_name}/"):
            variants.append(normalized[len(project_name) + 1:])

        try:
            rel = Path(path).resolve().relative_to(project_path.resolve())
            variants.append(rel.as_posix())
        except (OSError, ValueError):
            pass

    result: list[str] = []
    seen: set[str] = set()
    for item in variants:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def path_matches(indexed_path: str, reported_path: str, project_path: Path) -> bool:
    indexed_variants = path_variants(indexed_path, project_path)
    reported_variants = path_variants(reported_path, project_path)
    for indexed in indexed_variants:
        indexed_cmp = indexed.casefold()
        for reported in reported_variants:
            reported_cmp = reported.casefold()
            if (
                indexed_cmp == reported_cmp
                or indexed_cmp.endswith(f"/{reported_cmp}")
                or reported_cmp.endswith(f"/{indexed_cmp}")
            ):
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
    """Resolve a semgrep match to an indexed function without full-table scans."""
    get_by_location = getattr(db, "get_function_by_location", None)
    if callable(get_by_location):
        # CodeDatabase.get_function_by_location already has an exact lookup plus
        # suffix fallback. Calling it repeatedly for every path variant can make
        # one semgrep match scan line-range candidates multiple times.
        best_path = relative_reported_path(project_path, reported_path)
        try:
            row = get_by_location(best_path, line)
        except Exception:
            row = None
        if row is not None:
            name = clean_func_name(_row_get(row, "name", ""))
            if name:
                return name
        return ""

    get_all_functions = getattr(db, "get_all_functions", None)
    if not callable(get_all_functions):
        return ""
    try:
        for func in get_all_functions():
            fp = _row_get(func, "file_path", "")
            start = _row_get(func, "start_line", 0)
            end = _row_get(func, "end_line", 0)
            if (
                fp
                and path_matches(str(fp), reported_path, project_path)
                and start <= line <= end
            ):
                return clean_func_name(_row_get(func, "name", ""))
    except Exception:
        pass
    return ""
