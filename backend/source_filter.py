"""Shared source-tree filtering helpers for indexing and static analyzers."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, MutableSequence
from pathlib import Path, PurePosixPath

OP_DEEP_HOLE_DIR = ".opendeephole"

DEFAULT_SOURCE_SKIP_DIRS = frozenset({
    OP_DEEP_HOLE_DIR,
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "third_party",
    "3rdparty",
    "thirdparty",
    "external",
    "extern",
    "deps",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "out",
    "output",
    "_build",
    ".build",
    "__pycache__",
    ".venv",
    "venv",
})

DEFAULT_SOURCE_SKIP_DIR_PREFIXES = (".opendeephole-index-",)


def source_path_has_ignored_dir(path: str | Path) -> bool:
    """Return True when a relative source path is under an ignored tool dir."""
    normalized = str(path).replace("\\", "/")
    parts = [part for part in PurePosixPath(normalized).parts if part not in ("", ".")]
    return OP_DEEP_HOLE_DIR in parts


def should_skip_source_dir_name(
    name: str,
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> bool:
    """Return True when a directory name should not be scanned as source."""
    return (
        name == OP_DEEP_HOLE_DIR
        or name in set(skip_dirs)
        or any(name.startswith(prefix) for prefix in skip_prefixes)
    )


def prune_source_dirnames(
    dirnames: MutableSequence[str],
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> None:
    """Mutate an os.walk dirnames list so ignored directories are not entered."""
    dirnames[:] = [
        name
        for name in dirnames
        if not should_skip_source_dir_name(
            name,
            skip_dirs=skip_dirs,
            skip_prefixes=skip_prefixes,
        )
    ]


def iter_source_files(
    root: Path,
    extensions: Iterable[str],
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> Iterator[Path]:
    """Yield source files under root while pruning internal/tool directories."""
    root = Path(root)
    if should_skip_source_dir_name(root.name, skip_dirs=skip_dirs, skip_prefixes=skip_prefixes):
        return

    normalized_exts = {ext.lower() for ext in extensions}
    for dirpath, dirnames, filenames in os.walk(root):
        prune_source_dirnames(
            dirnames,
            skip_dirs=skip_dirs,
            skip_prefixes=skip_prefixes,
        )
        for fname in filenames:
            path = Path(dirpath) / fname
            if path.suffix.lower() in normalized_exts:
                yield path
