"""Agent runtime self-update helpers."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import httpx


RUNTIME_DIRS = ("deephole_client", "task_agent", "code_parser", "mcp_server", "backend")
RUNTIME_TOOL_DIRS = ("ctags-p6.2.20260517.0-x64",)
RUNTIME_ROOT_FILES = (
    "requirements-agent.txt",
    "attack-tree-threat-analysis.md",
    "attack-method-reference-catalog.md",
)
SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "static",
    "system_skills",
}
SKIP_SUFFIXES = {".pyc", ".pyo"}
PENDING_COMMANDS_FILE = Path.home() / ".opendeephole" / "pending_commands.json"


def runtime_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _should_skip(path: Path) -> bool:
    return path.suffix in SKIP_SUFFIXES or any(part in SKIP_DIRS for part in path.parts)


def runtime_hash_scope() -> dict[str, Any]:
    return {
        "version": 3,
        "dirs": list(RUNTIME_DIRS),
        "tool_dirs": list(RUNTIME_TOOL_DIRS),
        "root_files": list(RUNTIME_ROOT_FILES),
        "skip_dirs": sorted(SKIP_DIRS),
        "skip_suffixes": sorted(SKIP_SUFFIXES),
    }


def _iter_runtime_files(root: Path):
    for dir_name in (*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS):
        dir_path = root / dir_name
        if not dir_path.is_dir():
            continue
        # Sort by POSIX arcname to ensure consistent ordering across platforms
        # (Windows Path sorting is case-insensitive, Linux is case-sensitive).
        entries = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and not _should_skip(file_path):
                arcname = file_path.relative_to(root).as_posix()
                entries.append((arcname, file_path))
        entries.sort(key=lambda e: e[0])
        yield from entries
    for filename in RUNTIME_ROOT_FILES:
        file_path = root / filename
        if file_path.is_file():
            yield filename, file_path


def compute_runtime_hash(root: Path | None = None) -> str:
    """Return a content hash for the locally installed runtime files."""
    root = root or runtime_root()
    digest = hashlib.sha256()
    for arcname, file_path in _iter_runtime_files(root):
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _runtime_hash_for_contents(files: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for arcname, content in files:
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def pending_scan_snapshots() -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    for command in load_pending_commands(clear=False):
        if not isinstance(command, dict):
            continue
        if command.get("type") not in {"task", "resume"}:
            continue
        scan_id = str(command.get("scan_id") or "")
        if not scan_id:
            continue
        snapshots.append({
            "scan_id": scan_id,
            "project_path": command.get("project_path") or "",
            "code_scan_path": command.get("code_scan_path") or command.get("project_path") or "",
            "checkers": command.get("checkers") or [],
            "scan_name": command.get("scan_name") or "",
        })
    return snapshots


def save_pending_command(command: dict[str, Any]) -> None:
    PENDING_COMMANDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    commands = load_pending_commands(clear=False)
    commands = [cmd for cmd in commands if cmd.get("scan_id") != command.get("scan_id")]
    commands.append(command)
    PENDING_COMMANDS_FILE.write_text(
        json.dumps(commands, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_pending_commands(*, clear: bool) -> list[dict[str, Any]]:
    if not PENDING_COMMANDS_FILE.is_file():
        return []
    try:
        raw = json.loads(PENDING_COMMANDS_FILE.read_text(encoding="utf-8"))
        commands = raw if isinstance(raw, list) else [raw]
        result = [cmd for cmd in commands if isinstance(cmd, dict)]
    except Exception:
        result = []
    if clear:
        try:
            PENDING_COMMANDS_FILE.unlink()
        except OSError:
            pass
    # Strip stale agent_runtime_update — tokens are one-time and server-side
    # in-memory, so they are always invalid after agent restart.
    for cmd in result:
        cmd.pop("agent_runtime_update", None)
    return result


async def ensure_runtime_updated(update: dict[str, Any] | None, command: dict[str, Any]) -> bool:
    """Install the server runtime update and restart this process when needed."""
    if not update:
        return False

    expected_hash = str(update.get("hash") or "")
    if not expected_hash or expected_hash == compute_runtime_hash():
        return False

    try:
        archive = await _download_update(update)
    except Exception as e:
        raise RuntimeError(f"runtime update download failed: {e}") from e

    save_pending_command(command)
    _install_update_archive(archive, expected_hash, update.get("manifest"))
    _install_requirements_if_needed()
    _restart_process()
    return True


async def _download_update(update: dict[str, Any]) -> bytes:
    download_url = str(update.get("download_url") or "")
    token = str(update.get("token") or "")
    expected_archive_hash = str(update.get("archive_sha256") or "")
    if not download_url:
        raise RuntimeError("Agent runtime update missing download_url")
    headers = {"X-Agent-Update-Token": token} if token else {}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(download_url, headers=headers)
        resp.raise_for_status()
        data = resp.content
    if expected_archive_hash:
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_archive_hash:
            raise RuntimeError(
                "Agent runtime update archive hash mismatch "
                f"(expected={expected_archive_hash}, actual={actual_hash})"
            )
    return data


def _install_update_archive(
    archive: bytes,
    expected_hash: str,
    manifest: dict[str, Any] | None = None,
) -> None:
    root = runtime_root()
    with tempfile.TemporaryDirectory(prefix="opendeephole-agent-update-") as tmp:
        tmp_root = Path(tmp)
        archive_files: dict[str, bytes] = {}
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise RuntimeError(f"Unsafe runtime update path: {info.filename}")
                arcname = member.as_posix()
                if arcname in archive_files:
                    raise RuntimeError(f"Duplicate runtime update path: {arcname}")
                content = zf.read(info)
                archive_files[arcname] = content
                dest = (tmp_root / member).resolve()
                dest.relative_to(tmp_root.resolve())
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)

        _verify_update_contents(tmp_root, archive_files, expected_hash, manifest)

        _install_update_files(tmp_root, root, sorted(archive_files))


def _verify_update_contents(
    tmp_root: Path,
    archive_files: dict[str, bytes],
    expected_hash: str,
    manifest: dict[str, Any] | None,
) -> None:
    if not manifest:
        actual_hash = compute_runtime_hash(tmp_root)
        if actual_hash != expected_hash:
            raise RuntimeError(
                "Agent runtime update content hash mismatch "
                f"(expected={expected_hash}, actual={actual_hash}, files={len(archive_files)})"
            )
        return

    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list):
        raise RuntimeError("Agent runtime update manifest missing files")

    expected_paths: list[str] = []
    for entry in manifest_files:
        if not isinstance(entry, dict):
            raise RuntimeError("Agent runtime update manifest contains invalid file entry")
        path = str(entry.get("path") or "")
        expected_paths.append(path)

    expected_set = set(expected_paths)
    actual_set = set(archive_files)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing={missing[0]}")
        if extra:
            detail.append(f"extra={extra[0]}")
        raise RuntimeError(
            "Agent runtime update manifest mismatch "
            f"({', '.join(detail)}, manifest_files={len(expected_set)}, archive_files={len(actual_set)})"
        )
    if len(expected_paths) != len(expected_set):
        raise RuntimeError("Agent runtime update manifest contains duplicate paths")

    ordered_files: list[tuple[str, bytes]] = []
    for entry in manifest_files:
        path = str(entry["path"])
        content = archive_files[path]
        expected_file_hash = str(entry.get("sha256") or "")
        actual_file_hash = hashlib.sha256(content).hexdigest()
        if expected_file_hash != actual_file_hash:
            raise RuntimeError(
                "Agent runtime update manifest hash mismatch "
                f"(path={path}, expected={expected_file_hash}, actual={actual_file_hash})"
            )
        expected_size = entry.get("size")
        if expected_size is not None:
            try:
                expected_size_int = int(expected_size)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Agent runtime update manifest size invalid "
                    f"(path={path}, value={expected_size})"
                ) from exc
        else:
            expected_size_int = None
        if expected_size_int is not None and expected_size_int != len(content):
            raise RuntimeError(
                "Agent runtime update manifest size mismatch "
                f"(path={path}, expected={expected_size_int}, actual={len(content)})"
            )
        ordered_files.append((path, content))

    manifest_hash = str(manifest.get("runtime_hash") or "")
    if manifest_hash and manifest_hash != expected_hash:
        raise RuntimeError(
            "Agent runtime update manifest runtime hash mismatch "
            f"(expected={expected_hash}, manifest={manifest_hash})"
        )

    actual_manifest_hash = _runtime_hash_for_contents(ordered_files)
    if actual_manifest_hash != expected_hash:
        raise RuntimeError(
            "Agent runtime update content hash mismatch "
            f"(expected={expected_hash}, actual={actual_manifest_hash}, scope=manifest, files={len(ordered_files)})"
        )

    remote_scope = manifest.get("hash_scope")
    if remote_scope == runtime_hash_scope():
        actual_hash = compute_runtime_hash(tmp_root)
        if actual_hash != expected_hash:
            raise RuntimeError(
                "Agent runtime update content hash mismatch "
                f"(expected={expected_hash}, actual={actual_hash}, scope=local, files={len(archive_files)})"
            )


def _install_update_files(tmp_root: Path, root: Path, archive_paths: list[str]) -> None:
    """Replace runtime-managed files without touching skipped local directories."""
    root = root.resolve()
    desired = set(archive_paths)
    target_roots = _target_roots_for_archive(archive_paths)

    _remove_stale_runtime_files(root, desired, target_roots)
    _prune_empty_runtime_dirs(root, target_roots)

    for arcname in archive_paths:
        member = Path(arcname)
        if member.is_absolute() or ".." in member.parts:
            raise RuntimeError(f"Unsafe runtime update path: {arcname}")
        if _should_skip(member):
            continue
        src = tmp_root / member
        if not src.is_file():
            continue
        dest = (root / member).resolve()
        dest.relative_to(root)
        if dest.exists() and dest.is_dir():
            if _contains_skipped_path(dest, root):
                raise RuntimeError(f"Refusing to replace runtime directory containing skipped paths: {arcname}")
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _target_roots_for_archive(archive_paths: list[str]) -> set[str]:
    managed_dirs = {*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS}
    managed_files = set(RUNTIME_ROOT_FILES)
    roots: set[str] = set()
    for arcname in archive_paths:
        first, sep, _rest = arcname.partition("/")
        if sep and first in managed_dirs:
            roots.add(first)
        elif not sep and first in managed_files:
            roots.add(first)
    return roots


def _remove_stale_runtime_files(root: Path, desired: set[str], target_roots: set[str]) -> None:
    managed_dirs = {*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS}
    for target in sorted(target_roots):
        target_path = root / target
        if target in RUNTIME_ROOT_FILES:
            if target not in desired and target_path.is_file():
                target_path.unlink()
            continue
        if target not in managed_dirs or not target_path.is_dir():
            continue
        for file_path in sorted(target_path.rglob("*"), reverse=True):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(root)
            if _should_skip(rel):
                continue
            if rel.as_posix() not in desired:
                file_path.unlink()


def _prune_empty_runtime_dirs(root: Path, target_roots: set[str]) -> None:
    managed_dirs = {*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS}
    for target in sorted(target_roots):
        if target not in managed_dirs:
            continue
        target_path = root / target
        if not target_path.is_dir():
            continue
        dirs = [path for path in target_path.rglob("*") if path.is_dir()]
        for dir_path in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
            rel = dir_path.relative_to(root)
            if _should_skip(rel):
                continue
            try:
                dir_path.rmdir()
            except OSError:
                pass


def _contains_skipped_path(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if _should_skip(rel):
        return True
    if not path.is_dir():
        return False
    for child in path.rglob("*"):
        if _should_skip(child.relative_to(root)):
            return True
    return False


def _install_requirements_if_needed() -> None:
    requirements = runtime_root() / "requirements-agent.txt"
    if not requirements.is_file():
        return
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        check=True,
    )


def _restart_process() -> None:
    args = [sys.executable, "-m", "deephole_client.main", *sys.argv[1:]]
    os.execv(sys.executable, args)
