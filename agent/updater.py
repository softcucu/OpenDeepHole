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


RUNTIME_DIRS = ("agent", "checkers", "code_parser", "mcp_server", "backend")
RUNTIME_TOOL_DIRS = ("ctags-p6.2.20260517.0-x64",)
RUNTIME_ROOT_FILES = ("requirements-agent.txt",)
SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache", "static"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
PENDING_COMMANDS_FILE = Path.home() / ".opendeephole" / "pending_commands.json"


def runtime_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _should_skip(path: Path) -> bool:
    return path.suffix in SKIP_SUFFIXES or any(part in SKIP_DIRS for part in path.parts)


def _iter_runtime_files(root: Path):
    for dir_name in (*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS):
        dir_path = root / dir_name
        if not dir_path.is_dir():
            continue
        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file() and not _should_skip(file_path):
                yield file_path.relative_to(root).as_posix(), file_path
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
    return result


async def ensure_runtime_updated(update: dict[str, Any] | None, command: dict[str, Any]) -> bool:
    """Install the server runtime update and restart this process when needed."""
    if not update:
        return False

    expected_hash = str(update.get("hash") or "")
    if not expected_hash or expected_hash == compute_runtime_hash():
        return False

    save_pending_command(command)
    archive = await _download_update(update)
    _install_update_archive(archive, expected_hash)
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
            raise RuntimeError("Agent runtime update archive hash mismatch")
    return data


def _install_update_archive(archive: bytes, expected_hash: str) -> None:
    root = runtime_root()
    with tempfile.TemporaryDirectory(prefix="opendeephole-agent-update-") as tmp:
        tmp_root = Path(tmp)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise RuntimeError(f"Unsafe runtime update path: {info.filename}")
                dest = (tmp_root / member).resolve()
                dest.relative_to(tmp_root.resolve())
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))

        actual_hash = compute_runtime_hash(tmp_root)
        if actual_hash != expected_hash:
            raise RuntimeError("Agent runtime update content hash mismatch")

        for dir_name in (*RUNTIME_DIRS, *RUNTIME_TOOL_DIRS):
            src = tmp_root / dir_name
            if not src.exists():
                continue
            dest = root / dir_name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)

        for filename in RUNTIME_ROOT_FILES:
            src = tmp_root / filename
            if src.is_file():
                shutil.copy2(src, root / filename)


def _install_requirements_if_needed() -> None:
    requirements = runtime_root() / "requirements-agent.txt"
    if not requirements.is_file():
        return
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        check=True,
    )


def _restart_process() -> None:
    args = [sys.executable, "-m", "agent.main", *sys.argv[1:]]
    os.execv(sys.executable, args)
