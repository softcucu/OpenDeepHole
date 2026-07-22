"""Persistent code index store.

Stores code_index.db directly inside the project directory being scanned.
This avoids redundant copies and keeps the index close to the source code.

Storage layout:
    <project_path>/code_index.db
"""

from __future__ import annotations

from pathlib import Path


class IndexStore:
    """Manages code_index.db in the project directory."""

    def lookup(self, project_path: Path) -> Path | None:
        """Return the DB path if *project_path* already has a code_index.db."""
        abs_path = project_path.resolve()
        db = abs_path / "code_index.db"
        if db.exists():
            return db
        return None

    def db_path(self, project_path: Path) -> Path:
        """Return the canonical DB path for a project (may not exist yet)."""
        return project_path.resolve() / "code_index.db"

    def remove(self, project_path: Path) -> bool:
        """Delete the code_index.db for a project. Returns True if it existed."""
        db = self.db_path(project_path)
        if db.exists():
            db.unlink()
            return True
        return False
