"""Public checker analyzer base class for the static-analysis process."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase

__all__ = ["BaseAnalyzer", "Candidate", "in_scope", "scope_prefix", "scoped_functions"]


def scope_prefix(db: "CodeDatabase", project_path: Path) -> str | None:
    db_path = getattr(db, "db_path", None)
    if not db_path:
        return None
    try:
        project_root = Path(db_path).resolve().parent
        scan_root = Path(project_path).resolve()
        prefix = scan_root.relative_to(project_root).as_posix()
    except (ValueError, OSError):
        return None
    return "" if prefix in ("", ".") else prefix


def in_scope(file_path: str, prefix: str | None) -> bool:
    if not prefix:
        return True
    normalized = file_path.replace("\\", "/").strip("/")
    return normalized == prefix or normalized.startswith(f"{prefix}/")


def scoped_functions(db: "CodeDatabase", project_path: Path) -> list:
    prefix = scope_prefix(db, project_path)
    if prefix is None:
        return db.get_all_functions()
    getter = getattr(db, "get_functions_by_path_prefix", None)
    if getter is None:
        return [
            row for row in db.get_all_functions()
            if in_scope(str(row["file_path"]), prefix)
        ]
    return getter(prefix)


class BaseAnalyzer(ABC):
    vuln_type: str
    on_file_progress: Callable[[int, int], None] | None = None

    @abstractmethod
    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterable[Candidate]:
        """Return candidate locations under ``project_path``."""
