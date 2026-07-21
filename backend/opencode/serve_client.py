"""HTTP client and process manager for OpenCode-compatible serve mode."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import httpx

from backend.logger import get_logger
from backend.opencode.config_json import (
    is_sensitive_opencode_config_key,
    redact_opencode_config_content,
)

logger = get_logger(__name__)

_SERVE_START_TIMEOUT_SECONDS = 30.0
_SERVE_STOP_TIMEOUT_SECONDS = 5.0
_SERVE_REQUEST_TIMEOUT_SECONDS = 20.0
_SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS = 5.0
_SERVE_HEALTH_POLL_INTERVAL_SECONDS = 1.0
_SERVE_EVENT_FLUSH_INTERVAL_SECONDS = 1.0
_SERVE_EVENT_CONNECT_TIMEOUT_SECONDS = 2.0
_SERVE_EVENT_RECONNECT_DELAY_SECONDS = 1.0
_SERVE_EVENT_RECONNECT_MAX_SECONDS = 30.0
_SERVE_EVENT_FAILURE_SUMMARY_SECONDS = 30.0
_SERVE_EVENT_POLL_INTERVAL_SECONDS = 1.0
_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS = 1.0
_SERVE_EVENT_PREVIEW_LIMIT = 500
_SERVE_STARTUP_LOG_TAIL_LIMIT = 4000
_DEFAULT_SERVE_PORT = 4096
_SERVE_PORT_ENV = "OPENCODE_SERVE_PORT"
_SERVE_MARKER_ENV = "OPENCODE_SERVE_MARKER"
_SERVE_MARKER_OWNER = "opendeephole-agent-serve-v1"
_SERVE_BOOTSTRAP_CWD_PREFIX = "opendeephole-opencode-serve-bootstrap"
_SENSITIVE_EVENT_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|authorization|cookie|credential|"
    r"prompt|content|body)",
    re.IGNORECASE,
)
_SERVE_DEBUG_ENV_NAMES = (
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
)
_SERVE_PROXY_ENV_NAMES = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}
_SERVE_PROXY_CLEAR_ENV_NAMES = ("ALL_PROXY", "all_proxy")


@dataclass(frozen=True)
class OpenCodeServeKey:
    tool: str
    executable: str
    env_hash: str = ""
    config_hash: str = ""
    config_content: str = field(default="", compare=False, repr=False)
    env_overrides: tuple[tuple[str, str], ...] = field(default_factory=tuple, compare=False, repr=False)


@dataclass(frozen=True)
class OpenCodeModelInfo:
    id: str
    provider_id: str
    model_id: str
    name: str = ""


@dataclass(frozen=True)
class OpenCodeModelListResult:
    models: list[OpenCodeModelInfo]
    message: str = ""


@dataclass(frozen=True)
class OpenCodePromptResult:
    """Result of one message appended to an OpenCode session."""

    session_id: str
    message_id: str
    lines: list[str]
    text: str
    model: str = ""
    raw: Any = field(default=None, repr=False, compare=False)


@dataclass
class _EventChannelRuntime:
    key: str
    path: str
    params: dict[str, str]
    headers: dict[str, str]
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None
    healthy: bool = False
    connected_once: bool = False
    attempts: int = 0


def split_model_id(model: str) -> tuple[str, str]:
    """Split OpenCode's provider/model identifier."""
    provider, sep, model_id = str(model or "").partition("/")
    if not sep or not provider or not model_id:
        raise ValueError(f"OpenCode serve mode requires model id in provider/model form: {model!r}")
    return provider, model_id


def _serve_port() -> int:
    raw = os.environ.get(_SERVE_PORT_ENV, "").strip()
    if raw:
        try:
            port = int(raw)
        except ValueError as exc:
            raise ValueError(f"{_SERVE_PORT_ENV} must be an integer port: {raw!r}") from exc
        if 1 <= port <= 65535:
            return port
        raise ValueError(f"{_SERVE_PORT_ENV} must be between 1 and 65535: {raw!r}")
    return _DEFAULT_SERVE_PORT


def _port_is_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _wait_port_released(port: int, timeout: float = _SERVE_STOP_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _port_is_in_use(port):
            return True
        time.sleep(0.1)
    return not _port_is_in_use(port)


def _run_command_text(cmd: list[str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    except Exception as exc:
        logger.debug("Failed to run %s: %s", cmd[0] if cmd else cmd, exc)
        return ""
    return completed.stdout or ""


def _new_serve_startup_log_path(tool: str, port: int) -> Path:
    safe_tool = re.sub(r"[^A-Za-z0-9_.-]+", "_", tool or "opencode").strip("._") or "opencode"
    fd, raw_path = tempfile.mkstemp(
        prefix=f"opendeephole-{safe_tool}-serve-startup-",
        suffix=f"-{port}.log",
    )
    os.close(fd)
    return Path(raw_path)


def _safe_name(value: str, default: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or default).strip("._") or default


def _serve_bootstrap_cwd(tool: str) -> Path:
    try:
        root = str(Path.cwd().resolve())
    except Exception:
        root = os.getcwd()
    digest = hashlib.sha256(root.encode("utf-8", errors="replace")).hexdigest()[:12]
    safe_tool = _safe_name(tool, "opencode")
    return Path(tempfile.gettempdir()) / f"{_SERVE_BOOTSTRAP_CWD_PREFIX}-{safe_tool}-{digest}"


def _ensure_minimal_git_repo(cwd: Path) -> None:
    if (cwd / ".git").exists():
        return
    try:
        completed = subprocess.run(
            ["git", "init", "-q"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("git executable not found; OpenCode serve startup cwd remains non-git: %s", cwd)
        return
    except subprocess.TimeoutExpired:
        logger.warning("git init timed out for OpenCode serve startup cwd: %s", cwd)
        return
    except Exception as exc:
        logger.warning("Failed to initialize OpenCode serve startup cwd %s as git repo: %s", cwd, exc)
        return
    if completed.returncode != 0:
        detail = _one_line_preview(completed.stderr or completed.stdout or f"exit {completed.returncode}")
        logger.warning("Failed to initialize OpenCode serve startup cwd %s as git repo: %s", cwd, detail)


def _prepare_serve_startup_cwd(tool: str, startup_cwd: Path | None) -> Path:
    cwd = Path(startup_cwd) if startup_cwd is not None else _serve_bootstrap_cwd(tool)
    cwd.mkdir(parents=True, exist_ok=True)
    _ensure_minimal_git_repo(cwd)
    return cwd


def _write_serve_config_file(cwd: Path, config_content: str) -> Path:
    """Atomically publish the resolved config used by the next Serve process."""
    raw = config_content or "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Resolved OpenCode config is invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Resolved OpenCode config must be a JSON object")
    normalized = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    config_path = cwd / "opencode.json"
    fd, temporary_name = tempfile.mkstemp(prefix=".opencode.json.", suffix=".tmp", dir=cwd)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, config_path)
        os.chmod(config_path, 0o600)
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink()
    return config_path


def _read_serve_startup_log_tail(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""
    if len(text) > _SERVE_STARTUP_LOG_TAIL_LIMIT:
        text = text[-_SERVE_STARTUP_LOG_TAIL_LIMIT:]
    return text


def _with_serve_startup_log(message: str, path: Path | None) -> str:
    tail = _read_serve_startup_log_tail(path)
    if not tail:
        return message
    return f"{message}\n\nOpenCode serve startup output:\n{tail}"


def _serve_debug_env_value(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if name == "OPENCODE_CONFIG_CONTENT":
        return redact_opencode_config_content(value)
    return value


def _serve_startup_env_debug(env: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for name in _SERVE_DEBUG_ENV_NAMES:
        value = _serve_debug_env_value(name, env.get(name))
        lines.append(f"    {name}={value if value is not None else '(unset)'}")
    lines.append("    OPENCODE_SERVER_PASSWORD=(cleared)")
    lines.append("    OPENCODE_SERVER_USERNAME=(cleared)")
    return lines


def _serve_startup_shell_debug(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    env_parts = [
        f"{name}={shlex.quote(_serve_debug_env_value(name, env[name]) or '')}"
        for name in _SERVE_DEBUG_ENV_NAMES
        if name in env
    ]
    prefix = " ".join(env_parts)
    command = shlex.join(cmd)
    if prefix:
        command = f"{prefix} {command}"
    return f"cd {shlex.quote(str(cwd))} && {command}"


def _log_serve_startup_debug(
    *,
    key: OpenCodeServeKey,
    cmd: list[str],
    port: int,
    cwd: Path,
    env: dict[str, str],
    startup_log_path: Path,
    popen_kwargs: dict[str, Any],
    marker_path: Path,
    config_path: Path,
) -> None:
    try:
        config_content = config_path.read_text(encoding="utf-8")
    except OSError:
        config_content = key.config_content
    lines = [
        "OpenCode serve startup debug:",
        f"  tool={key.tool}",
        f"  executable_config={key.executable}",
        f"  executable_resolved={cmd[0]}",
        f"  port={port}",
        f"  cwd={cwd}",
        f"  marker_path={marker_path}",
        f"  startup_log_path={startup_log_path}",
        f"  config_hash={key.config_hash or '(none)'}",
        f"  config_file_path={config_path}",
        f"  config_content_bytes={len(config_content.encode('utf-8')) if config_content else 0}",
        f"  config_content_redacted={redact_opencode_config_content(config_content)}",
        f"  argv={json.dumps(cmd, ensure_ascii=False)}",
        f"  shell={_serve_startup_shell_debug(cmd, cwd, env)}",
        "  env_overrides:",
        *_serve_startup_env_debug(env),
        f"  popen_kwargs={popen_kwargs!r}",
    ]
    logger.info("%s", "\n".join(lines))


def _remove_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("Failed to remove %s: %s", path, exc)


def _address_token_has_port(token: str, port: int) -> bool:
    value = token.strip().strip(",")
    if ":" not in value:
        return False
    suffix = f":{port}"
    if value.endswith(suffix):
        return True
    bracket_suffix = f"]:{port}"
    return value.endswith(bracket_suffix)


def _parse_listener_pids(output: str, port: int) -> set[int]:
    pids: set[int] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "LISTEN" not in line.upper():
            continue
        tokens = line.split()
        if not any(_address_token_has_port(token, port) for token in tokens):
            continue
        for match in re.finditer(r"(?:^|[^\w])pid=(\d+)(?:[^\w]|$)", line, re.IGNORECASE):
            pids.add(int(match.group(1)))
        if tokens:
            match = re.match(r"^(\d+)(?:/.*)?$", tokens[-1])
            if match:
                pids.add(int(match.group(1)))
    return pids


def _windows_listener_pids_for_port(port: int) -> set[int]:
    return _parse_listener_pids(_run_command_text(["netstat", "-ano", "-p", "tcp"]), port)


def _posix_listener_pids_for_port(port: int) -> set[int]:
    pids: set[int] = set()
    if shutil.which("lsof"):
        output = _run_command_text(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"])
        for line in output.splitlines():
            value = line.strip()
            if value.isdigit():
                pids.add(int(value))
    if shutil.which("ss"):
        pids.update(_parse_listener_pids(_run_command_text(["ss", "-ltnp", "sport", "=", f":{port}"]), port))
    if shutil.which("netstat"):
        pids.update(_parse_listener_pids(_run_command_text(["netstat", "-ltnp"]), port))
    pids.update(_proc_listener_pids_for_port(port))
    return pids


def _proc_listener_pids_for_port(port: int) -> set[int]:
    inodes: set[str] = set()
    port_hex = f"{port:04X}"
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) <= 9 or parts[3] != "0A":
                continue
            _, _, local_port = parts[1].rpartition(":")
            if local_port.upper() == port_hex:
                inodes.add(parts[9])
    if not inodes:
        return set()

    pids: set[int] = set()
    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except Exception:
        return set()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except Exception:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except Exception:
                continue
            match = re.match(r"socket:\[(\d+)\]$", target)
            if match and match.group(1) in inodes:
                pids.add(int(entry.name))
                break
    return pids


def _listener_pids_for_port(port: int) -> set[int]:
    if sys.platform == "win32":
        return _windows_listener_pids_for_port(port)
    return _posix_listener_pids_for_port(port)


@dataclass(frozen=True)
class _PortReclaimResult:
    attempted: bool
    pids: tuple[int, ...] = ()
    released: bool = False
    detail: str = ""


def _reclaim_serve_port(port: int, *, reason: str) -> _PortReclaimResult:
    if not _port_is_in_use(port):
        return _PortReclaimResult(attempted=False, released=True, detail="port already free")
    pids = tuple(sorted(pid for pid in _listener_pids_for_port(port) if pid > 0 and pid != os.getpid()))
    if not pids:
        return _PortReclaimResult(
            attempted=False,
            released=False,
            detail="could not identify listener pid",
        )

    for pid in pids:
        logger.warning(
            "Reclaiming OpenCode serve port 127.0.0.1:%s by terminating listener pid %s (%s)",
            port,
            pid,
            reason,
        )
        _terminate_process_tree(pid)
    released = _wait_port_released(port)
    return _PortReclaimResult(
        attempted=True,
        pids=pids,
        released=released,
        detail="port released" if released else "port still in use after terminating listener pid(s)",
    )


def _port_busy_message(port: int, reclaim: _PortReclaimResult | None) -> str:
    detail = ""
    if reclaim is not None:
        pid_note = f" listener_pid(s)={','.join(str(pid) for pid in reclaim.pids)}." if reclaim.pids else ""
        detail = f" Reclaim detail: {reclaim.detail}.{pid_note}"
    return (
        f"OpenCode serve port 127.0.0.1:{port} is already in use and could not be reclaimed."
        f"{detail} Stop the listener process or set OPENCODE_SERVE_PORT."
    )


def _serve_marker_path() -> Path:
    configured = os.environ.get(_SERVE_MARKER_ENV, "").strip()
    if configured:
        return Path(configured)
    try:
        suffix = str(os.getuid())
    except AttributeError:
        suffix = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return Path(tempfile.gettempdir()) / f"opendeephole-opencode-serve-{suffix}.json"


def _read_marker(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.warning("Failed to read OpenCode serve marker %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def _write_marker(path: Path, *, proc: subprocess.Popen, key: OpenCodeServeKey, port: int) -> None:
    data = {
        "owner": _SERVE_MARKER_OWNER,
        "pid": int(proc.pid),
        "port": int(port),
        "tool": key.tool,
        "executable": key.executable,
        "config_hash": key.config_hash,
        "created_at": time.time(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write OpenCode serve marker %s: %s", path, exc)


def _remove_marker(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("Failed to remove OpenCode serve marker %s: %s", path, exc)


def _remove_marker_for_pid(path: Path, pid: int | None) -> None:
    marker = _read_marker(path)
    if marker is None:
        return
    if pid is None or int(marker.get("pid") or 0) == int(pid):
        _remove_marker(path)


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _windows_pid_is_running(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _windows_pid_is_running(pid: int) -> bool:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetLastError.restype = wintypes.DWORD

    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if not handle:
        return int(kernel32.GetLastError()) == 5
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return int(exit_code.value) == still_active
    finally:
        kernel32.CloseHandle(handle)


def _pid_cmdline(pid: int) -> list[str] | None:
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return [item.decode(errors="ignore") for item in raw.split(b"\0") if item]


def _marker_matches_serve_process(marker: dict[str, Any]) -> bool:
    if marker.get("owner") != _SERVE_MARKER_OWNER:
        return False
    pid = int(marker.get("pid") or 0)
    cmdline = _pid_cmdline(pid)
    if cmdline is None:
        return True
    lowered = [Path(item).name.lower() for item in cmdline] + [" ".join(cmdline).lower()]
    return any("serve" == item or item.endswith(" serve") or " serve " in item for item in lowered)


def _wait_process_exit(
    pid: int,
    timeout: float,
    wait: Callable[[float], None] | None = None,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if wait is not None:
            try:
                wait(0.1)
                return True
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                wait = None
        if not _pid_is_running(pid):
            return True
        time.sleep(0.1)
    if wait is not None:
        try:
            wait(0)
            return True
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    return not _pid_is_running(pid)


def _terminate_process_tree(
    pid: int,
    timeout: float = _SERVE_STOP_TIMEOUT_SECONDS,
    wait: Callable[[float], None] | None = None,
) -> None:
    if not _pid_is_running(pid):
        return
    if sys.platform == "win32":
        _terminate_windows_process_tree(pid, timeout, wait=wait)
        return

    pgid: int | None = None
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return
    except Exception:
        pgid = None

    use_process_group = pgid is not None and pgid != os.getpgrp()

    def _send(sig: signal.Signals | int) -> None:
        if use_process_group and pgid is not None:
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)

    try:
        _send(signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception as exc:
        logger.warning("Failed to terminate old OpenCode serve pid %s: %s", pid, exc)
        return

    if _wait_process_exit(pid, timeout, wait=wait):
        return
    try:
        _send(signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
    except Exception:
        pass


def _terminate_windows_process_tree(
    pid: int,
    timeout: float,
    *,
    wait: Callable[[float], None] | None = None,
) -> None:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception as exc:
        logger.warning("Failed to terminate old OpenCode serve process tree pid %s: %s", pid, exc)
    if _wait_process_exit(pid, timeout, wait=wait):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


def _resolve_executable(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    if Path(name).is_file():
        return str(Path(name).resolve())
    raise FileNotFoundError(f"OpenCode executable '{name}' not found in PATH")


def _session_id(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("id", "sessionID", "session_id"):
            value = data.get(key)
            if value:
                return str(value)
    raise RuntimeError(f"OpenCode serve did not return a session id: {data!r}")


def _config_hash(config_content: str | None) -> str:
    content = (config_content or "").strip()
    if not content:
        return ""
    try:
        content = json.dumps(
            json.loads(content),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except Exception:
        pass
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _normalized_env_overrides(env_overrides: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not env_overrides:
        return ()
    normalized: list[tuple[str, str]] = []
    for key, value in env_overrides.items():
        name = str(key).strip()
        if not name:
            continue
        normalized.append((name, str(value)))
    return tuple(sorted(normalized))


def _env_hash(env_overrides: tuple[tuple[str, str], ...]) -> str:
    if not env_overrides:
        return ""
    return hashlib.sha256(
        json.dumps(env_overrides, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _extract_text(value: Any) -> list[str]:
    lines: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            lines.append(text)
        return lines
    if isinstance(value, list):
        for item in value:
            lines.extend(_extract_text(item))
        return lines
    if isinstance(value, dict):
        part_type = value.get("type")
        if part_type == "text" and isinstance(value.get("text"), str):
            text = value["text"].strip()
            if text:
                lines.append(text)
        state = value.get("state")
        if isinstance(state, dict):
            for key in ("output", "error", "title"):
                if isinstance(state.get(key), str) and state[key].strip():
                    lines.append(state[key].strip())
        for key in ("parts", "content"):
            if key in value:
                lines.extend(_extract_text(value[key]))
    return lines


def _extract_response_text(value: Any) -> list[str]:
    """Extract assistant text parts without exposing tool state/output bodies."""
    lines: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            lines.append(text)
        return lines
    if isinstance(value, list):
        for item in value:
            lines.extend(_extract_response_text(item))
        return lines
    if not isinstance(value, dict):
        return lines
    part_type = value.get("type")
    if part_type == "text" and isinstance(value.get("text"), str):
        text = value["text"].strip()
        if text:
            lines.append(text)
        return lines
    if part_type:
        return lines
    for key in ("parts", "content"):
        if key in value:
            lines.extend(_extract_response_text(value[key]))
    return lines


def _response_model(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    info = value.get("info")
    if not isinstance(info, dict):
        return ""
    provider_id = info.get("providerID")
    model_id = info.get("modelID")
    if not isinstance(provider_id, str) or not isinstance(model_id, str):
        return ""
    provider_id = provider_id.strip()
    model_id = model_id.strip()
    if not provider_id or not model_id:
        return ""
    if model_id.startswith(f"{provider_id}/"):
        return model_id
    return f"{provider_id}/{model_id}"


def _response_message_id(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("info"), dict):
        return ""
    return str(value["info"].get("id") or "").strip()


def _normalize_tool_selector(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _mcp_tool_overrides(
    tool_ids: list[str],
    requested: list[str] | tuple[str, ...] | None,
    disabled: list[str] | tuple[str, ...] | None = None,
) -> dict[str, bool]:
    """Build message-level MCP overrides while leaving built-in tools untouched."""
    mcp_ids = [tool_id for tool_id in tool_ids if _tool_source(tool_id) == "mcp"]
    if requested is None:
        overrides = {tool_id: True for tool_id in tool_ids}
    else:
        overrides = {tool_id: False for tool_id in mcp_ids}
    unresolved: list[str] = []
    for raw_selector in requested or ():
        selector = str(raw_selector or "").strip()
        normalized = _normalize_tool_selector(selector)
        matches = [
            tool_id
            for tool_id in mcp_ids
            if selector == tool_id
            or (normalized and normalized == _normalize_tool_selector(tool_id))
            or (
                normalized
                and normalized in _normalize_tool_selector(tool_id)
                and _normalize_tool_selector(selector.rsplit("/", 1)[-1])
                in _normalize_tool_selector(tool_id)
            )
        ]
        if not matches:
            unresolved.append(selector)
            continue
        for tool_id in matches:
            overrides[tool_id] = True
    for raw_selector in disabled or ():
        selector = str(raw_selector or "").strip()
        normalized = _normalize_tool_selector(selector)
        for tool_id in mcp_ids:
            if selector == tool_id or (normalized and normalized in _normalize_tool_selector(tool_id)):
                overrides[tool_id] = False
    if unresolved:
        raise ValueError(
            "Unknown OpenCode MCP tool selector(s): " + ", ".join(unresolved)
        )
    return overrides


def _one_line_preview(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated {len(text) - limit} chars]"


def _summarize_event_value(value: object, *, max_string: int = 180) -> object:
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>"
                if _SENSITIVE_EVENT_KEY_RE.search(str(key))
                else _summarize_event_value(item, max_string=max_string)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_summarize_event_value(item, max_string=max_string) for item in value]
    if isinstance(value, str):
        preview = _one_line_preview(value, max_string)
        if len(value) > max_string or "\n" in value:
            return f"<chars={len(value)} preview={preview}>"
        return preview
    return value


def _json_one_line(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
    value = _summarize_event_value(value)
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        text = str(value)
    return _one_line_preview(text, limit)


def _tool_content_summary(value: object) -> str:
    if not isinstance(value, list):
        return "content=0"
    text_chars = 0
    files = 0
    for item in value:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            text_chars += len(str(item.get("text") or ""))
        elif item.get("type") == "file":
            files += 1
    return f"content_items={len(value)} text_chars={text_chars} files={files}"


def _tool_state_summary(value: object) -> str:
    if not isinstance(value, dict):
        return "output_chars=0 attachments=0"
    output = str(value.get("output") or "")
    attachments = value.get("attachments")
    attachment_count = len(attachments) if isinstance(attachments, list) else 0
    parts = [f"output_chars={len(output)}", f"attachments={attachment_count}"]
    timing = value.get("time")
    if isinstance(timing, dict):
        start = timing.get("start")
        end = timing.get("end")
        if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
            parts.append(f"duration_ms={round(end - start)}")
    return " ".join(parts)


def _error_summary(value: object) -> str:
    if isinstance(value, dict):
        message = _one_line_preview(value.get("message") or "")
        if message:
            return message
        name = _one_line_preview(value.get("name") or "")
        data = value.get("data")
        if isinstance(data, dict):
            nested_message = _one_line_preview(data.get("message") or "")
            if nested_message:
                return f"{name}: {nested_message}" if name else nested_message
        nested_error = value.get("error")
        if nested_error:
            nested_summary = _error_summary(nested_error)
            if nested_summary:
                return nested_summary
        if name:
            return name
        return _json_one_line(value)
    return _one_line_preview(value)


def _tool_source(tool_name: object) -> str:
    normalized = str(tool_name or "").lower().replace("_", "-")
    if "deephole-code" in normalized or normalized.startswith("mcp--"):
        return "mcp"
    return "builtin"


def _event_session_id(props: dict[str, Any]) -> str:
    session_id = props.get("sessionID")
    if isinstance(session_id, str) and session_id:
        return session_id
    for key in ("part", "info"):
        nested = props.get(key)
        if isinstance(nested, dict):
            nested_session_id = nested.get("sessionID")
            if isinstance(nested_session_id, str) and nested_session_id:
                return nested_session_id
    return ""


def _tool_ids_from_response(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    tool_ids: list[str] = []
    seen: set[str] = set()
    for item in value:
        tool_id = str(item or "").strip()
        if not tool_id or tool_id in seen:
            continue
        seen.add(tool_id)
        tool_ids.append(tool_id)
    return tool_ids


class _BufferedEventEmitter:
    def __init__(self, on_line, prefix: str) -> None:
        self._on_line = on_line
        self._prefix = prefix
        self._buffer = ""

    def _emit(self, text: object) -> bool:
        preview = _one_line_preview(text)
        if not preview:
            return False
        self._on_line(f"{self._prefix} {preview}")
        return True

    def emit(self, text: object) -> bool:
        return self._emit(text)

    def append(self, text: str) -> bool:
        if not text:
            return False
        self._buffer += text
        emitted = False
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            emitted = self._emit(line) or emitted
        return emitted

    def flush(self) -> bool:
        text = self._buffer
        self._buffer = ""
        return self._emit(text)


class _ServeEventState:
    def __init__(self, tool: str, session_id: str, on_line) -> None:
        self.tool = tool
        self.session_id = session_id
        self.on_line = on_line
        self.emitted_text = False
        self.emitted_response_text = False
        self.seen_next_text_event = False
        self.seen_next_reasoning_event = False
        self.text = _BufferedEventEmitter(on_line, f"[{tool} serve llm text]")
        self.reasoning = _BufferedEventEmitter(on_line, f"[{tool} serve llm reasoning]")
        self.final_text = _BufferedEventEmitter(on_line, f"[{tool} serve llm text final]")
        self.final_reasoning = _BufferedEventEmitter(
            on_line,
            f"[{tool} serve llm reasoning final]",
        )
        self.recovery_text = _BufferedEventEmitter(
            on_line,
            f"[{tool} serve llm text recovery]",
        )
        self.recovery_reasoning = _BufferedEventEmitter(
            on_line,
            f"[{tool} serve llm reasoning recovery]",
        )
        self.message_roles: dict[str, str] = {}
        self.part_types: dict[str, str] = {}
        self.part_message_ids: dict[str, str] = {}
        self.part_text: dict[str, str] = {}
        self.part_emitted_text: dict[str, str] = {}
        self.tool_calls_emitted: set[str] = set()
        self.tool_results_emitted: set[tuple[str, str]] = set()
        self.step_events_emitted: set[tuple[str, str]] = set()
        self.session_errors_emitted: set[str] = set()
        self.event_ids_seen: set[str] = set()
        self.last_session_status = ""
        self.observed_response_text = ""
        self.observed_reasoning_text = ""
        self.next_replay_remaining = {"text": "", "reasoning": ""}
        self.final_snapshots_emitted: set[tuple[str, str]] = set()
        self.recovery_snapshots_emitted: set[tuple[str, str]] = set()
        self.session_terminal = False

    def flush(self) -> None:
        text_flushed = self.text.flush()
        self.emitted_response_text = text_flushed or self.emitted_response_text
        self.emitted_text = text_flushed or self.emitted_text
        self.emitted_text = self.reasoning.flush() or self.emitted_text

    def record_message(self, info: object) -> None:
        if not isinstance(info, dict):
            return
        message_id = str(info.get("id") or "")
        role = str(info.get("role") or "")
        if message_id and role:
            self.message_roles[message_id] = role
        if role == "assistant":
            for part_id, part_message_id in list(self.part_message_ids.items()):
                if part_message_id == message_id:
                    self._emit_part_text(part_id)
            if info.get("error") is not None:
                self.emit_session_error(info.get("error"))
            message_time = info.get("time")
            if isinstance(message_time, dict) and message_time.get("completed") is not None:
                self.session_terminal = True

    def mark_event_seen(self, event: object) -> bool:
        if not isinstance(event, dict):
            return False
        event_id = str(event.get("id") or "")
        if not event_id:
            return False
        if event_id in self.event_ids_seen:
            return True
        self.event_ids_seen.add(event_id)
        return False

    def _append_text(self, kind: str, value: object) -> None:
        text = str(value or "")
        if not text:
            return
        if kind == "reasoning":
            self.observed_reasoning_text += text
            emitted = self.reasoning.append(text)
            self.emitted_text = emitted or self.emitted_text
            return
        self.observed_response_text += text
        emitted = self.text.append(text)
        self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def _emit_part_text(self, part_id: str) -> None:
        kind = self.part_types.get(part_id, "")
        if kind not in {"text", "reasoning"}:
            return
        message_id = self.part_message_ids.get(part_id, "")
        role = self.message_roles.get(message_id, "") if message_id else "assistant"
        if role == "user":
            return
        if role != "assistant" and kind != "reasoning":
            return
        value = self.part_text.get(part_id, "")
        emitted_value = self.part_emitted_text.get(part_id, "")
        if kind == "text" and self.seen_next_text_event:
            self.part_emitted_text[part_id] = value
            return
        if kind == "reasoning" and self.seen_next_reasoning_event:
            self.part_emitted_text[part_id] = value
            return
        if not value or value == emitted_value:
            return
        if value.startswith(emitted_value):
            delta = value[len(emitted_value):]
        elif emitted_value.startswith(value):
            return
        else:
            delta = value
        self.part_emitted_text[part_id] = value
        self._append_text(kind, delta)

    def update_part_text(self, part: dict[str, Any]) -> None:
        kind = str(part.get("type") or "")
        if kind not in {"text", "reasoning"}:
            return
        part_id = str(part.get("id") or "")
        message_id = str(part.get("messageID") or "")
        if part_id:
            self.part_types[part_id] = kind
            self.part_message_ids[part_id] = message_id
        value = str(part.get("text") or "")
        previous = self.part_text.get(part_id, "") if part_id else ""
        if not value or value == previous:
            return
        if previous.startswith(value):
            return
        if part_id:
            self.part_text[part_id] = value
            self._emit_part_text(part_id)
        elif not message_id or self.message_roles.get(message_id) == "assistant" or kind == "reasoning":
            self._append_text(kind, value)

    def append_part_delta(self, props: dict[str, Any]) -> None:
        part_id = str(props.get("partID") or "")
        field = str(props.get("field") or "")
        kind = self.part_types.get(part_id, "")
        if kind not in {"text", "reasoning"}:
            if field == "reasoning":
                kind = "reasoning"
            elif field in {"text", "content"}:
                kind = "text"
            else:
                return
            if part_id:
                self.part_types[part_id] = kind
        message_id = str(props.get("messageID") or self.part_message_ids.get(part_id, ""))
        if part_id and message_id:
            self.part_message_ids[part_id] = message_id
        delta = str(props.get("delta") or "")
        if not delta:
            return
        if part_id:
            self.part_text[part_id] = self.part_text.get(part_id, "") + delta
            self._emit_part_text(part_id)
        elif not message_id or self.message_roles.get(message_id) == "assistant" or field in {"content", "reasoning"}:
            self._append_text(kind, delta)

    def append_next_delta(self, kind: str, value: object) -> None:
        delta = str(value or "")
        if not delta:
            return
        seen_attr = "seen_next_reasoning_event" if kind == "reasoning" else "seen_next_text_event"
        if not getattr(self, seen_attr):
            setattr(self, seen_attr, True)
            observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
            self.next_replay_remaining[kind] = observed
        replay = self.next_replay_remaining[kind]
        if replay:
            if replay.startswith(delta):
                self.next_replay_remaining[kind] = replay[len(delta):]
                return
            if delta.startswith(replay):
                delta = delta[len(replay):]
            self.next_replay_remaining[kind] = ""
        self._append_text(kind, delta)

    def reconcile_text(self, kind: str, value: object) -> None:
        final_text = str(value or "")
        if not final_text:
            return
        observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
        if not observed:
            self._append_text(kind, final_text)
            return
        if final_text.strip() == observed.strip() or final_text in observed:
            return
        if final_text.startswith(observed):
            self._append_text(kind, final_text[len(observed):])
            return
        snapshot_key = (kind, final_text)
        if snapshot_key in self.final_snapshots_emitted:
            return
        self.final_snapshots_emitted.add(snapshot_key)
        emitter = self.final_reasoning if kind == "reasoning" else self.final_text
        emitted = emitter.append(final_text)
        emitted = emitter.flush() or emitted
        if kind == "reasoning":
            self.observed_reasoning_text = final_text
        else:
            self.observed_response_text = final_text
            self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def reconcile_snapshot(self, kind: str, value: object) -> None:
        """Merge a cumulative polled snapshot without duplicating streamed output."""
        snapshot = str(value or "")
        if not snapshot:
            return
        observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
        if not observed:
            self._append_text(kind, snapshot)
            return
        if snapshot.strip() == observed.strip() or snapshot in observed or observed.startswith(snapshot):
            return
        if snapshot.startswith(observed):
            self._append_text(kind, snapshot[len(observed):])
            return
        snapshot_key = (kind, snapshot)
        if snapshot_key in self.recovery_snapshots_emitted:
            return
        self.recovery_snapshots_emitted.add(snapshot_key)
        emitter = self.recovery_reasoning if kind == "reasoning" else self.recovery_text
        emitted = emitter.append(snapshot)
        emitted = emitter.flush() or emitted
        if kind == "reasoning":
            self.observed_reasoning_text = snapshot
        else:
            self.observed_response_text = snapshot
            self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def ingest_message_snapshot(self, message: object) -> None:
        if not isinstance(message, dict):
            return
        info = message.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            return
        self.record_message(info)
        parts = message.get("parts")
        if not isinstance(parts, list):
            return
        snapshots = {"text": [], "reasoning": []}
        for part in parts:
            if not isinstance(part, dict):
                continue
            part_type = str(part.get("type") or "")
            if part_type in snapshots:
                text = part.get("text")
                if isinstance(text, str):
                    snapshots[part_type].append(text)
                continue
            self.handle_part(part)
        for kind, values in snapshots.items():
            if values:
                self.reconcile_snapshot(kind, "".join(values))

    def emit_tool_call(
        self,
        *,
        call_id: object,
        tool_name: object,
        input_value: object,
        part_id: object = "",
    ) -> None:
        call = str(call_id or part_id or tool_name or "unknown")
        if call in self.tool_calls_emitted:
            return
        self.tool_calls_emitted.add(call)
        name = str(tool_name or "")
        self.on_line(
            f"[{self.tool} serve tool_call] session={self.session_id} source={_tool_source(name)} "
            f"name={name} id={call} input={_json_one_line(input_value or {})}"
        )

    def emit_tool_result(
        self,
        *,
        call_id: object,
        status: str,
        summary: str,
        tool_name: object = "",
        input_value: object = None,
        part_id: object = "",
    ) -> None:
        call = str(call_id or part_id or tool_name or "unknown")
        normalized_status = "success" if status in {"success", "completed"} else "failed"
        self.emit_tool_call(
            call_id=call,
            tool_name=tool_name,
            input_value=input_value,
            part_id=part_id,
        )
        key = (call, normalized_status)
        if key in self.tool_results_emitted:
            return
        self.tool_results_emitted.add(key)
        suffix = f" {summary}" if summary else ""
        self.on_line(
            f"[{self.tool} serve tool_result] session={self.session_id} "
            f"status={normalized_status} id={call}{suffix}"
        )

    def handle_tool_part(self, part: dict[str, Any]) -> None:
        state = part.get("state")
        if not isinstance(state, dict):
            return
        status = str(state.get("status") or "")
        common = {
            "call_id": part.get("callID"),
            "tool_name": part.get("tool"),
            "input_value": state.get("input") or {},
            "part_id": part.get("id"),
        }
        if status in {"pending", "running"}:
            self.emit_tool_call(**common)
        elif status == "completed":
            self.emit_tool_result(status="success", summary=_tool_state_summary(state), **common)
        elif status == "error":
            error = _error_summary(state.get("error") or "")
            self.emit_tool_result(status="failed", summary=f"error={error}", **common)

    def emit_session_status(self, status: object) -> None:
        if isinstance(status, dict):
            status_type = str(status.get("type") or "")
            if status_type == "retry":
                signature = "|".join(
                    str(status.get(key) or "")
                    for key in ("type", "attempt", "message", "next")
                )
            else:
                signature = status_type
        else:
            status_type = str(status or "")
            signature = status_type
            status = {}
        if status_type in {"idle", "error"}:
            self.session_terminal = True
        if not status_type or signature == self.last_session_status:
            return
        self.last_session_status = signature
        details: list[str] = []
        if status_type == "retry" and isinstance(status, dict):
            if status.get("attempt") is not None:
                details.append(f"attempt={status.get('attempt')}")
            if status.get("next") is not None:
                details.append(f"next={status.get('next')}")
            message = _one_line_preview(status.get("message") or "")
            if message:
                details.append(f"message={message}")
        suffix = f" {' '.join(details)}" if details else ""
        self.on_line(
            f"[{self.tool} serve session] session={self.session_id} status={status_type}{suffix}"
        )

    def emit_session_error(self, error: object) -> None:
        self.session_terminal = True
        summary = _error_summary(error) or "unknown"
        if summary in self.session_errors_emitted:
            return
        self.session_errors_emitted.add(summary)
        self.on_line(
            f"[{self.tool} serve session] session={self.session_id} status=error "
            f"error={summary}"
        )

    def emit_step(self, status: str, props: dict[str, Any], *, part_id: object = "") -> None:
        step_id = str(part_id or props.get("id") or props.get("stepID") or "step")
        key = (step_id, status)
        if key in self.step_events_emitted:
            return
        self.step_events_emitted.add(key)
        details: list[str] = []
        reason = _one_line_preview(props.get("reason") or "")
        if reason:
            details.append(f"reason={reason}")
        if props.get("cost") is not None:
            details.append(f"cost={props.get('cost')}")
        error = _error_summary(props.get("error") or "")
        if error:
            details.append(f"error={error}")
        suffix = f" {' '.join(details)}" if details else ""
        self.on_line(
            f"[{self.tool} serve step] session={self.session_id} status={status} id={step_id}{suffix}"
        )

    def handle_part(self, part: object) -> None:
        if not isinstance(part, dict):
            return
        part_type = str(part.get("type") or "")
        if part_type in {"text", "reasoning"}:
            self.update_part_text(part)
        elif part_type == "tool":
            self.handle_tool_part(part)
        elif part_type == "step-start":
            self.emit_step("started", part, part_id=part.get("id"))
        elif part_type == "step-finish":
            self.emit_step("finished", part, part_id=part.get("id"))
        elif part_type == "retry":
            self.emit_session_status({
                "type": "retry",
                "attempt": part.get("attempt"),
                "message": _error_summary(part.get("error") or ""),
            })


def _event_properties(event: object) -> tuple[str, dict[str, Any]]:
    if not isinstance(event, dict):
        return "", {}
    if event.get("type") == "sync":
        event_type = str(event.get("name") or "")
        properties = event.get("data")
    else:
        event_type = str(event.get("type") or "")
        properties = event.get("properties")
    event_type = re.sub(r"\.\d+$", "", event_type)
    if isinstance(properties, dict):
        return event_type, properties
    return event_type, {}


def _handle_serve_event(event: object, state: _ServeEventState) -> None:
    event_type, props = _event_properties(event)
    if _event_session_id(props) != state.session_id:
        return
    if state.mark_event_seen(event):
        return

    if event_type == "message.updated":
        state.record_message(props.get("info"))
    elif event_type == "message.part.updated":
        state.handle_part(props.get("part"))
    elif event_type == "message.part.delta":
        state.append_part_delta(props)
    elif event_type == "session.next.text.delta":
        state.append_next_delta("text", props.get("delta") or "")
    elif event_type == "session.next.text.ended":
        state.seen_next_text_event = True
        state.flush()
        state.reconcile_text("text", props.get("text") or "")
        state.flush()
    elif event_type == "session.next.reasoning.delta":
        state.append_next_delta("reasoning", props.get("delta") or "")
    elif event_type == "session.next.reasoning.ended":
        state.seen_next_reasoning_event = True
        state.flush()
        state.reconcile_text("reasoning", props.get("text") or "")
        state.flush()
    elif event_type == "session.next.tool.called":
        state.emit_tool_call(
            call_id=props.get("callID"),
            tool_name=props.get("tool"),
            input_value=props.get("input") or {},
        )
    elif event_type == "session.next.tool.success":
        state.emit_tool_result(
            call_id=props.get("callID"),
            status="success",
            summary=_tool_content_summary(props.get("content")),
        )
    elif event_type == "session.next.tool.failed":
        state.emit_tool_result(
            call_id=props.get("callID"),
            status="failed",
            summary=f"error={_error_summary(props.get('error') or '')}",
        )
    elif event_type == "session.status":
        state.emit_session_status(props.get("status"))
    elif event_type == "session.idle":
        state.emit_session_status("idle")
    elif event_type == "session.error":
        state.emit_session_error(props.get("error"))
    elif event_type == "session.next.step.started":
        event_id = event.get("id") if isinstance(event, dict) else ""
        state.emit_step("started", props, part_id=event_id)
    elif event_type == "session.next.step.ended":
        event_id = event.get("id") if isinstance(event, dict) else ""
        state.emit_step("finished", props, part_id=event_id)
    elif event_type == "session.next.step.failed":
        event_id = event.get("id") if isinstance(event, dict) else ""
        state.emit_step("failed", props, part_id=event_id)
    elif event_type == "session.next.retried":
        state.emit_session_status({
            "type": "retry",
            "attempt": props.get("attempt"),
            "message": _error_summary(props.get("error") or ""),
        })


async def _stream_sse_events(response: httpx.Response):
    data_lines: list[str] = []
    async for raw_line in response.aiter_lines():
        line = raw_line.strip("\r")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                try:
                    yield json.loads(payload)
                except Exception:
                    continue
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        try:
            yield json.loads("\n".join(data_lines))
        except Exception:
            return


async def _flush_event_state_periodically(state: _ServeEventState) -> None:
    while True:
        await asyncio.sleep(_SERVE_EVENT_FLUSH_INTERVAL_SECONDS)
        state.flush()


def _latest_assistant_message(value: object, session_id: str) -> dict[str, Any] | None:
    if not isinstance(value, list):
        return None
    for item in reversed(value):
        if not isinstance(item, dict):
            continue
        info = item.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            continue
        item_session_id = str(info.get("sessionID") or "")
        if item_session_id and item_session_id != session_id:
            continue
        return item
    return None


def _next_event_reconnect_delay(current: float) -> float:
    return min(current * 2, _SERVE_EVENT_RECONNECT_MAX_SECONDS)


def _provider_models(provider: dict[str, Any]) -> list[OpenCodeModelInfo]:
    provider_id = str(provider.get("id") or provider.get("providerID") or provider.get("name") or "").strip()
    models = provider.get("models") or {}
    result: list[OpenCodeModelInfo] = []
    if isinstance(models, dict):
        iterable = models.items()
    elif isinstance(models, list):
        iterable = [(item.get("id") if isinstance(item, dict) else item, item) for item in models]
    else:
        iterable = []
    for model_id_raw, raw in iterable:
        model_id = str(model_id_raw or "").strip()
        if not provider_id or not model_id:
            continue
        name = ""
        if isinstance(raw, dict):
            name = str(raw.get("name") or raw.get("label") or "")
            model_id = str(raw.get("id") or model_id).strip()
        result.append(OpenCodeModelInfo(
            id=f"{provider_id}/{model_id}",
            provider_id=provider_id,
            model_id=model_id,
            name=name,
        ))
    return result


class OpenCodeServeManager:
    """Manage a single Agent-wide opencode/nga serve process."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._idle = asyncio.Condition()
        self._proc: subprocess.Popen | None = None
        self._key: OpenCodeServeKey | None = None
        self._port: int | None = None
        self._startup_log_path: Path | None = None
        self._startup_cwd: Path | None = None
        self._marker_path = _serve_marker_path()
        self._active_sessions = 0
        self._active_model_listings = 0
        self._event_lock = asyncio.Lock()
        self._event_states: dict[str, _ServeEventState] = {}
        self._event_directories: dict[str, str] = {}
        self._global_event_channel: _EventChannelRuntime | None = None
        self._legacy_event_channels: dict[str, _EventChannelRuntime] = {}
        self._global_event_unsupported = False
        self._degraded_event_channels: set[str] = set()
        self._event_failure_started_at = 0.0
        self._event_failure_attempts = 0
        self._event_last_failure_summary_at = 0.0
        self._event_poll_failure_reported = False
        self._dirty = False
        self._serve_config_generation = 0
        self._model_cache: dict[
            tuple[OpenCodeServeKey, str],
            tuple[OpenCodeModelInfo, ...],
        ] = {}
        self._model_cache_generation = 0
        self._model_fetch_lock = asyncio.Lock()
        self._model_inflight: dict[
            tuple[tuple[OpenCodeServeKey, str], bool],
            asyncio.Task[OpenCodeModelListResult],
        ] = {}
        self._managed_mcp_specs: dict[str, dict[str, Any]] = {}
        self._managed_mcp_directories: dict[str, Path] = {}
        self._managed_mcp_status: dict[str, dict[str, dict[str, Any]]] = {}
        self._managed_mcp_applied: dict[str, dict[str, dict[str, Any]]] = {}
        self._managed_mcp_tasks: dict[tuple[str, str], asyncio.Task] = {}
        self._managed_mcp_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._managed_mcp_force_pending: set[tuple[str, str]] = set()

    @property
    def base_url(self) -> str:
        if self._port is None:
            raise RuntimeError("OpenCode serve is not running")
        return f"http://127.0.0.1:{self._port}"

    def mark_dirty(self) -> None:
        # Keep active sessions stable, but make the next idle acquisition reload
        # the serve process and never return a model list cached before the
        # configuration update.
        self._dirty = True
        self._serve_config_generation += 1
        self._invalidate_model_cache()
        # Do not let a request created before the config update become the
        # single-flight result for callers that arrive afterwards. The old task
        # is allowed to finish for its existing waiters, but its generation can
        # no longer populate the cache.
        self._model_inflight.clear()

    def config_runtime_status(self) -> dict[str, int | str]:
        """Return whether the current serve has loaded the latest managed config."""
        running = self._proc is not None and self._proc.poll() is None
        if running and self._dirty:
            state = "reload_pending"
        elif running:
            state = "active"
        else:
            state = "next_task"
        return {
            "runtime_state": state,
            "active_sessions": self._active_sessions,
        }

    def update_managed_mcp_configs(self, specs: dict[str, dict[str, Any]]) -> None:
        """Install the desired managed MCP set and hot-apply it to live directories."""
        normalized = {
            str(target): dict(spec)
            for target, spec in specs.items()
            if str(target) in {"code_graph", "product_info"} and isinstance(spec, dict)
        }
        changed = {
            target
            for target in set(self._managed_mcp_specs) | set(normalized)
            if self._managed_mcp_specs.get(target) != normalized.get(target)
        }
        self._managed_mcp_specs = normalized
        if not changed:
            return
        for directory_key in self._managed_mcp_directories:
            for target in changed:
                self._managed_mcp_status.setdefault(directory_key, {}).pop(target, None)
                self._spawn_managed_mcp_sync(directory_key, target)

    def retry_managed_mcp(self, target: str) -> None:
        target = str(target or "").strip()
        if target not in self._managed_mcp_specs:
            raise ValueError(f"Unknown managed MCP target: {target}")
        for directory_key in self._managed_mcp_directories:
            self._managed_mcp_status.setdefault(directory_key, {}).pop(target, None)
            self._spawn_managed_mcp_sync(directory_key, target, force=True)

    async def ensure_managed_mcp(self, directory: Path) -> None:
        """Ensure this OpenCode request directory sees the latest managed MCPs."""
        directory = Path(directory).resolve()
        directory_key = self._event_directory_key(directory)
        self._managed_mcp_directories[directory_key] = directory
        tasks = [
            self._spawn_managed_mcp_sync(directory_key, target)
            for target in self._managed_mcp_specs
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn_managed_mcp_sync(
        self,
        directory_key: str,
        target: str,
        *,
        force: bool = False,
    ) -> asyncio.Task:
        key = (directory_key, target)
        existing = self._managed_mcp_tasks.get(key)
        if existing is not None and not existing.done():
            if force:
                self._managed_mcp_force_pending.add(key)
            return existing
        self._managed_mcp_force_pending.discard(key)
        task = asyncio.create_task(
            self._sync_managed_mcp_target(directory_key, target, force=force)
        )
        self._managed_mcp_tasks[key] = task

        def done(completed: asyncio.Task) -> None:
            if self._managed_mcp_tasks.get(key) is completed:
                self._managed_mcp_tasks.pop(key, None)
            with contextlib.suppress(BaseException):
                completed.result()
            force_retry = key in self._managed_mcp_force_pending
            self._managed_mcp_force_pending.discard(key)
            spec = self._managed_mcp_specs.get(target)
            current = self._managed_mcp_status.get(directory_key, {}).get(target)
            if (
                spec is not None
                and directory_key in self._managed_mcp_directories
                and (
                    force_retry
                    or not isinstance(current, dict)
                    or current.get("fingerprint") != spec.get("fingerprint")
                )
            ):
                self._spawn_managed_mcp_sync(
                    directory_key,
                    target,
                    force=force_retry,
                )

        task.add_done_callback(done)
        return task

    @staticmethod
    def _mcp_status_map(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        nested = value.get("status")
        return nested if isinstance(nested, dict) else value

    @staticmethod
    def _mcp_native_status(value: Any) -> tuple[str, str]:
        if not isinstance(value, dict):
            return "failed", "OpenCode returned no MCP status"
        status = str(value.get("status") or "failed")
        error = str(value.get("error") or "")
        if status not in {
            "connected",
            "disabled",
            "failed",
            "needs_auth",
            "needs_client_registration",
        }:
            return "failed", error or f"Unknown OpenCode MCP status: {status}"
        return status, error

    @staticmethod
    def _redact_managed_mcp_error(value: object, spec: dict[str, Any]) -> str:
        text = _one_line_preview(value, 2000)
        config = spec.get("config")
        secrets: set[str] = set()
        for mapping_name in ("headers", "environment"):
            mapping = config.get(mapping_name) if isinstance(config, dict) else None
            if not isinstance(mapping, dict):
                continue
            secrets.update(str(item) for item in mapping.values() if str(item))
            for name, item in mapping.items():
                parts = str(item).split(None, 1)
                if is_sensitive_opencode_config_key(name) and len(parts) == 2:
                    secrets.add(parts[1])
        if secrets:
            for secret in sorted(
                secrets,
                key=len,
                reverse=True,
            ):
                text = text.replace(secret, "***")
        return text

    def _record_managed_mcp_status(
        self,
        directory_key: str,
        target: str,
        spec: dict[str, Any],
        state: str,
        *,
        error: str = "",
    ) -> None:
        self._managed_mcp_status.setdefault(directory_key, {})[target] = {
            "state": state,
            "fingerprint": str(spec.get("fingerprint") or ""),
            "error": self._redact_managed_mcp_error(error, spec) if error else "",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _disconnect_managed_mcp(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        applied: dict[str, Any],
    ) -> None:
        name = str(applied.get("name") or "").strip()
        if not name:
            return
        response = await client.post(
            f"/mcp/{quote(name, safe='')}/disconnect",
            params=_serve_context_params(directory),
            headers=_serve_context_headers(directory),
        )
        if response.status_code == 404:
            config = applied.get("config")
            if isinstance(config, dict):
                disabled = {**config, "enabled": False}
                response = await client.post(
                    "/mcp",
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                    json={"name": name, "config": disabled},
                )
        response.raise_for_status()

    async def _sync_managed_mcp_target(
        self,
        directory_key: str,
        target: str,
        *,
        force: bool = False,
    ) -> None:
        lock = self._managed_mcp_locks.setdefault((directory_key, target), asyncio.Lock())
        async with lock:
            spec = self._managed_mcp_specs.get(target)
            directory = self._managed_mcp_directories.get(directory_key)
            if spec is None or directory is None:
                return
            current = self._managed_mcp_status.get(directory_key, {}).get(target)
            if (
                not force
                and isinstance(current, dict)
                and current.get("fingerprint") == spec.get("fingerprint")
                and current.get("state") in {"connected", "disabled"}
            ):
                return
            if self._proc is None or self._proc.poll() is not None or self._port is None:
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    "disabled" if not spec.get("enabled") else "next_session",
                )
                return

            self._record_managed_mcp_status(directory_key, target, spec, "applying")
            applied = self._managed_mcp_applied.get(directory_key, {}).get(target)
            timeout_ms = 0
            config = spec.get("config")
            if isinstance(config, dict):
                timeout_ms = int(config.get("timeout") or 0)
            request_timeout = max(
                _SERVE_REQUEST_TIMEOUT_SECONDS,
                (timeout_ms / 1000.0) + 5.0 if timeout_ms else 0,
            )
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=request_timeout,
                    trust_env=False,
                ) as client:
                    state = "disabled"
                    error = ""
                    if spec.get("enabled"):
                        if spec.get("error") or not isinstance(config, dict):
                            if applied:
                                await self._disconnect_managed_mcp(client, directory, applied)
                            raise RuntimeError(spec.get("error") or "Invalid managed MCP config")
                        response = await client.post(
                            "/mcp",
                            params=_serve_context_params(directory),
                            headers=_serve_context_headers(directory),
                            json={"name": str(spec.get("name") or ""), "config": config},
                        )
                        response.raise_for_status()
                        statuses = self._mcp_status_map(response.json())
                        state, error = self._mcp_native_status(
                            statuses.get(str(spec.get("name") or ""))
                        )
                        if state == "disabled":
                            state = "failed"
                            error = error or "OpenCode reported the enabled MCP as disabled"

                    if applied and (
                        not spec.get("enabled")
                        or str(applied.get("name") or "") != str(spec.get("name") or "")
                    ):
                        await self._disconnect_managed_mcp(client, directory, applied)

                    # Record what OpenCode actually accepted before checking for
                    # a newer desired fingerprint. The follow-up sync then knows
                    # which just-connected stale name/config must be replaced or
                    # disconnected.
                    if state == "connected":
                        self._managed_mcp_applied.setdefault(directory_key, {})[target] = dict(spec)
                    else:
                        self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)
                    latest = self._managed_mcp_specs.get(target)
                    if latest is None or latest.get("fingerprint") != spec.get("fingerprint"):
                        self._spawn_managed_mcp_sync(directory_key, target)
                        return
                    self._record_managed_mcp_status(
                        directory_key,
                        target,
                        spec,
                        state,
                        error=error,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    "failed",
                    error=str(exc),
                )
                logger.warning(
                    "Failed to hot-load managed MCP %s for %s: %s",
                    target,
                    directory,
                    self._redact_managed_mcp_error(exc, spec),
                )

    def managed_mcp_runtime_status(self) -> dict[str, dict[str, Any]]:
        running = self._proc is not None and self._proc.poll() is None
        result: dict[str, dict[str, Any]] = {}
        total = len(self._managed_mcp_directories)
        for target in ("code_graph", "product_info"):
            spec = self._managed_mcp_specs.get(target) or {
                "enabled": False,
                "fingerprint": "",
            }
            records = [
                statuses.get(target)
                for statuses in self._managed_mcp_status.values()
                if isinstance(statuses.get(target), dict)
                and statuses[target].get("fingerprint") == spec.get("fingerprint")
            ]
            loaded = sum(record.get("state") == "connected" for record in records)
            applying = any(
                key[1] == target and not task.done()
                for key, task in self._managed_mcp_tasks.items()
            )
            if not spec.get("enabled"):
                if applying:
                    state = "applying"
                elif any(record.get("state") == "failed" for record in records):
                    # A failed disconnect means the old MCP may still be live;
                    # never report that as successfully disabled.
                    state = "failed"
                else:
                    state = "disabled"
            elif applying:
                state = "applying"
            elif spec.get("error"):
                state = "failed"
            elif not running or total == 0:
                state = "next_session"
            elif len(records) < total:
                state = "applying"
            elif any(record.get("state") == "needs_auth" for record in records):
                state = "needs_auth"
            elif any(record.get("state") == "needs_client_registration" for record in records):
                state = "needs_client_registration"
            elif any(record.get("state") == "failed" for record in records):
                state = "failed"
            elif loaded == total:
                state = "connected"
            else:
                state = "failed"
            errors = [str(record.get("error") or "") for record in records if record.get("error")]
            spec_error = self._redact_managed_mcp_error(spec.get("error"), spec) if spec.get("error") else ""
            updated = [str(record.get("updated_at") or "") for record in records if record.get("updated_at")]
            result[target] = {
                "state": state,
                "config_fingerprint": str(spec.get("fingerprint") or ""),
                "updated_at": max(updated, default=""),
                "error": errors[0] if errors else spec_error,
                "loaded_directories": loaded,
                "total_directories": total,
            }
        return result

    async def refresh_managed_mcp_runtime_status(self) -> dict[str, dict[str, Any]]:
        """Refresh cached states from OpenCode's live /mcp endpoint."""
        if self._proc is None or self._proc.poll() is not None or self._port is None:
            return self.managed_mcp_runtime_status()

        async def refresh_directory(
            client: httpx.AsyncClient,
            directory_key: str,
            directory: Path,
        ) -> None:
            try:
                response = await client.get(
                    "/mcp",
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                )
                response.raise_for_status()
                statuses = self._mcp_status_map(response.json())
            except Exception:
                return
            for target, spec in self._managed_mcp_specs.items():
                task = self._managed_mcp_tasks.get((directory_key, target))
                if task is not None and not task.done():
                    continue
                name = str(spec.get("name") or "")
                native = statuses.get(name)
                if isinstance(native, dict):
                    state, error = self._mcp_native_status(native)
                    if spec.get("enabled") and state == "disabled":
                        state = "failed"
                        error = error or "OpenCode reported the enabled MCP as disabled"
                elif not spec.get("enabled"):
                    state, error = "disabled", ""
                else:
                    state = "failed"
                    error = f"OpenCode MCP status does not contain {name or target}"
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    state,
                    error=error,
                )
                if state == "connected":
                    self._managed_mcp_applied.setdefault(directory_key, {})[target] = dict(spec)
                else:
                    self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)

        directories = list(self._managed_mcp_directories.items())
        if not directories:
            return self.managed_mcp_runtime_status()
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=2.0,
            trust_env=False,
        ) as client:
            await asyncio.gather(*(
                refresh_directory(client, directory_key, directory)
                for directory_key, directory in directories
            ))
        return self.managed_mcp_runtime_status()

    async def run_prompt(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        agent: str = "build",
        prompt: str,
        model: str,
        timeout: int,
        on_line=None,
        on_session_id=None,
        on_response_model=None,
        cancel_event=None,
        env_overrides: dict[str, str] | None = None,
        session_id: str | None = None,
        session_title: str = "OpenDeepHole task",
        mcp_tools: list[str] | tuple[str, ...] | None = None,
        disabled_mcp_tools: list[str] | tuple[str, ...] | None = None,
        system_prompt: str = "",
        permissions: list[dict[str, str]] | None = None,
        return_details: bool = False,
        show_serve_status: bool = False,
    ) -> list[str] | OpenCodePromptResult:
        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        if show_serve_status and on_line:
            on_line(
                f"[{tool} serve] preparing executable={executable} port={_serve_port()}"
            )
        try:
            serve_mode = await self._acquire_session(
                key,
                startup_cwd=config_workspace,
            )
        except Exception as exc:
            if show_serve_status and on_line:
                on_line(
                    f"[{tool} serve] startup failed: "
                    f"{_one_line_preview(exc, _SERVE_STARTUP_LOG_TAIL_LIMIT + 500)}"
                )
            raise
        active_session_id = str(session_id or "").strip()
        event_state: _ServeEventState | None = None
        event_registered = False
        event_flush_task: asyncio.Task | None = None
        snapshot_poll_task: asyncio.Task | None = None
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)
        try:
            if show_serve_status and on_line:
                pid = int(getattr(self._proc, "pid", 0) or 0)
                on_line(
                    f"[{tool} serve] ready mode={serve_mode} "
                    f"url={self.base_url} pid={pid}"
                )
            await self.ensure_managed_mcp(directory)
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
                trust_env=False,
            ) as client:
                if not active_session_id:
                    create_payload: dict[str, Any] = {
                        "title": str(session_title or "").strip() or "OpenDeepHole task",
                    }
                    if permissions is not None:
                        create_payload["permission"] = permissions
                    created = await client.post(
                        "/session",
                        params=params,
                        headers=headers,
                        json=create_payload,
                    )
                    created.raise_for_status()
                    active_session_id = _session_id(created.json())
                elif permissions is not None:
                    updated = await client.patch(
                        f"/session/{active_session_id}",
                        params=params,
                        headers=headers,
                        json={"permission": permissions},
                    )
                    updated.raise_for_status()
                if on_session_id:
                    result = on_session_id(active_session_id)
                    if hasattr(result, "__await__"):
                        await result
                if on_line:
                    config_note = f" config={config_workspace}" if config_workspace else ""
                    on_line(f"[{tool} serve] session={active_session_id} directory={directory}{config_note}")
                    event_state = _ServeEventState(tool, active_session_id, on_line)
                    event_flush_task = asyncio.create_task(
                        _flush_event_state_periodically(event_state)
                    )
                    await self._register_event_state(active_session_id, directory, event_state)
                    event_registered = True
                payload: dict[str, Any] = {
                    "agent": agent,
                    "parts": [{"type": "text", "text": prompt}],
                }
                tool_ids = await self._list_tool_ids(client, params, headers, on_line=on_line, tool=tool)
                mcp_overrides = _mcp_tool_overrides(tool_ids, mcp_tools, disabled_mcp_tools)
                if mcp_overrides:
                    payload["tools"] = mcp_overrides
                if model:
                    provider_id, model_id = split_model_id(model)
                    payload["model"] = {"providerID": provider_id, "modelID": model_id}
                if system_prompt:
                    payload["system"] = system_prompt

                request = asyncio.create_task(
                    client.post(
                        f"/session/{active_session_id}/message",
                        params=params,
                        headers=headers,
                        json=payload,
                        timeout=timeout + 30,
                    )
                )
                if event_state is not None:
                    snapshot_poll_task = asyncio.create_task(
                        self._poll_session_snapshots(
                            client=client,
                            session_id=active_session_id,
                            directory=directory,
                            params=params,
                            headers=headers,
                            state=event_state,
                        )
                    )
                try:
                    response = await self._wait_for_response(
                        client=client,
                        request=request,
                        session_id=active_session_id,
                        params=params,
                        headers=headers,
                        timeout=timeout,
                        cancel_event=cancel_event,
                    )
                except BaseException:
                    if not request.done():
                        request.cancel()
                    raise
                response.raise_for_status()
                if event_state:
                    deadline = (
                        asyncio.get_running_loop().time()
                        + _SERVE_EVENT_DRAIN_TIMEOUT_SECONDS
                    )
                    while (
                        not event_state.session_terminal
                        and asyncio.get_running_loop().time() < deadline
                    ):
                        await asyncio.sleep(0.01)
                    if snapshot_poll_task is not None:
                        snapshot_poll_task.cancel()
                        with contextlib.suppress(BaseException):
                            await snapshot_poll_task
                        snapshot_poll_task = None
                    if event_registered:
                        await self._unregister_event_state(active_session_id)
                        event_registered = False
                    event_state.flush()
                response_data = response.json()
                response_model = _response_model(response_data)
                if response_model and on_response_model:
                    result = on_response_model(response_model)
                    if hasattr(result, "__await__"):
                        await result
                lines = _extract_text(response_data)
                response_text = _extract_response_text(response_data)
                if event_state:
                    if isinstance(response_data, dict):
                        event_state.record_message(response_data.get("info"))
                        response_parts = response_data.get("parts")
                        if isinstance(response_parts, list):
                            for part in response_parts:
                                if not isinstance(part, dict) or part.get("type") not in {
                                    "text",
                                    "reasoning",
                                }:
                                    event_state.handle_part(part)
                    event_state.reconcile_text("text", "".join(response_text))
                    event_state.flush()
                elif on_line:
                    for line in response_text:
                        preview = _one_line_preview(line)
                        if preview:
                            on_line(f"[{tool} serve llm text] {preview}")
                details = OpenCodePromptResult(
                    session_id=active_session_id,
                    message_id=_response_message_id(response_data),
                    lines=lines,
                    text="\n".join(response_text),
                    model=response_model,
                    raw=response_data,
                )
                return details if return_details else lines
        finally:
            if snapshot_poll_task is not None:
                snapshot_poll_task.cancel()
                with contextlib.suppress(BaseException):
                    await snapshot_poll_task
            if event_registered:
                await self._unregister_event_state(active_session_id)
            if event_flush_task is not None:
                event_flush_task.cancel()
                with contextlib.suppress(BaseException):
                    await event_flush_task
            if event_state:
                event_state.flush()
            await self._release_active_session()

    async def _session_api_request(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path,
        method: str,
        path: str,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> Any:
        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        await self._acquire_session(key, startup_cwd=config_workspace)
        try:
            await self.ensure_managed_mcp(directory)
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
                trust_env=False,
            ) as client:
                response = await client.request(
                    method,
                    path,
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                    json=json_body,
                )
                response.raise_for_status()
                if not response.content:
                    return None
                return response.json()
        finally:
            await self._release_active_session()

    async def get_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="GET",
            path=f"/session/{session_id}",
            **runtime,
        )

    async def get_session_messages(self, session_id: str, **runtime: Any) -> list[dict[str, Any]]:
        value = await self._session_api_request(
            method="GET",
            path=f"/session/{session_id}/message",
            **runtime,
        )
        return value if isinstance(value, list) else []

    async def delete_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="DELETE",
            path=f"/session/{session_id}",
            **runtime,
        )

    async def abort_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="POST",
            path=f"/session/{session_id}/abort",
            **runtime,
        )

    @staticmethod
    def _event_directory_key(directory: Path) -> str:
        return os.path.normcase(os.path.normpath(str(directory)))

    def _ensure_event_channel_locked(self, directory: Path) -> _EventChannelRuntime:
        if not self._global_event_unsupported:
            runtime = self._global_event_channel
            if runtime is None or runtime.task is None or runtime.task.done():
                runtime = _EventChannelRuntime(
                    key="global",
                    path="/global/event",
                    params={},
                    headers={},
                )
                runtime.task = asyncio.create_task(
                    self._run_event_channel(runtime, is_global=True)
                )
                self._global_event_channel = runtime
            return runtime

        directory_key = self._event_directory_key(directory)
        runtime = self._legacy_event_channels.get(directory_key)
        if runtime is None or runtime.task is None or runtime.task.done():
            runtime = _EventChannelRuntime(
                key=f"legacy:{directory_key}",
                path="/event",
                params=_serve_context_params(directory),
                headers=_serve_context_headers(directory),
            )
            runtime.task = asyncio.create_task(
                self._run_event_channel(runtime, is_global=False)
            )
            self._legacy_event_channels[directory_key] = runtime
        return runtime

    async def _register_event_state(
        self,
        session_id: str,
        directory: Path,
        state: _ServeEventState,
    ) -> None:
        directory_key = self._event_directory_key(directory)
        async with self._event_lock:
            self._event_states[session_id] = state
            self._event_directories[session_id] = directory_key

        deadline = asyncio.get_running_loop().time() + _SERVE_EVENT_CONNECT_TIMEOUT_SECONDS
        while True:
            async with self._event_lock:
                runtime = self._ensure_event_channel_locked(directory)
            if runtime.healthy:
                return
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(runtime.ready.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return
            if runtime.healthy:
                return
            if runtime.path != "/global/event" or not self._global_event_unsupported:
                return

    async def _unregister_event_state(self, session_id: str) -> None:
        async with self._event_lock:
            self._event_states.pop(session_id, None)
            self._event_directories.pop(session_id, None)

    def _event_channel_healthy(self, directory: Path) -> bool:
        if not self._global_event_unsupported:
            return bool(self._global_event_channel and self._global_event_channel.healthy)
        runtime = self._legacy_event_channels.get(self._event_directory_key(directory))
        return bool(runtime and runtime.healthy)

    @staticmethod
    def _global_event_payload(event: object) -> object:
        if isinstance(event, dict) and isinstance(event.get("payload"), dict):
            return event["payload"]
        return event

    def _dispatch_event(self, event: object, *, directory_key: str = "") -> bool:
        payload = self._global_event_payload(event)
        if not isinstance(payload, dict):
            return False
        event_type, props = _event_properties(payload)
        if not event_type:
            return False
        if event_type in {"server.connected", "server.heartbeat"}:
            return True
        session_id = _event_session_id(props)
        if not session_id:
            return True
        state = self._event_states.get(session_id)
        if state is None:
            return True
        if directory_key and self._event_directories.get(session_id) != directory_key:
            return True
        _handle_serve_event(payload, state)
        return True

    def _emit_event_diagnostic(self, line: str) -> None:
        state = next(iter(self._event_states.values()), None)
        if state is None:
            logger.debug("OpenCode serve event: %s", line)
            return
        state.on_line(f"[{state.tool} serve event] {line}")

    def _note_event_channel_connected(
        self,
        runtime: _EventChannelRuntime,
        *,
        confirmed_recovery: bool = True,
    ) -> None:
        runtime.healthy = True
        runtime.ready.set()
        runtime.connected_once = True
        runtime.attempts = 0
        if not confirmed_recovery:
            return
        if runtime.key not in self._degraded_event_channels:
            return
        self._degraded_event_channels.discard(runtime.key)
        if self._degraded_event_channels or not self._event_failure_started_at:
            return
        now = time.monotonic()
        downtime = max(0.0, now - self._event_failure_started_at)
        self._emit_event_diagnostic(
            f"status=reconnected downtime={downtime:.1f}s "
            f"attempts={self._event_failure_attempts} "
            f"active_sessions={len(self._event_states)}"
        )
        self._event_failure_started_at = 0.0
        self._event_failure_attempts = 0
        self._event_last_failure_summary_at = 0.0
        self._event_poll_failure_reported = False

    def _note_event_channel_failure(
        self,
        runtime: _EventChannelRuntime,
        *,
        error: object,
        retry_in: float,
    ) -> None:
        runtime.healthy = False
        runtime.attempts += 1
        now = time.monotonic()
        first_failure = not self._degraded_event_channels
        self._degraded_event_channels.add(runtime.key)
        self._event_failure_attempts += 1
        if first_failure:
            self._event_failure_started_at = now
            self._event_last_failure_summary_at = now
            status = "disconnected" if runtime.connected_once else "unavailable"
            self._emit_event_diagnostic(
                f"status={status} active_sessions={len(self._event_states)} "
                f"retry_in={retry_in:.1f}s fallback=polling "
                f"error={_one_line_preview(error)}"
            )
            return
        if now - self._event_last_failure_summary_at < _SERVE_EVENT_FAILURE_SUMMARY_SECONDS:
            return
        self._event_last_failure_summary_at = now
        self._emit_event_diagnostic(
            f"status=unavailable attempts={self._event_failure_attempts} "
            f"active_sessions={len(self._event_states)} retry_in={retry_in:.1f}s "
            "fallback=polling"
        )

    async def _mark_global_event_unsupported(self, runtime: _EventChannelRuntime) -> None:
        runtime.healthy = False
        runtime.ready.set()
        async with self._event_lock:
            self._global_event_unsupported = True
            self._degraded_event_channels.discard(runtime.key)
            directories = {
                directory_key
                for directory_key in self._event_directories.values()
            }
            for directory_key in directories:
                directory = Path(directory_key)
                legacy = self._ensure_event_channel_locked(directory)
                if self._event_failure_started_at:
                    self._degraded_event_channels.add(legacy.key)

    async def _run_event_channel(
        self,
        runtime: _EventChannelRuntime,
        *,
        is_global: bool,
        initial_reconnect_delay: float = _SERVE_EVENT_RECONNECT_DELAY_SECONDS,
    ) -> None:
        reconnect_delay = initial_reconnect_delay
        directory_key = "" if is_global else runtime.key.removeprefix("legacy:")
        request_headers = dict(runtime.headers)
        request_headers.update({
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        })
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=None,
                trust_env=False,
            ) as client:
                while True:
                    try:
                        async with client.stream(
                            "GET",
                            runtime.path,
                            params=runtime.params,
                            headers=request_headers,
                        ) as response:
                            status_code = int(getattr(response, "status_code", 200) or 200)
                            if is_global and status_code in {404, 405, 501}:
                                await self._mark_global_event_unsupported(runtime)
                                return
                            response.raise_for_status()
                            content_type = str(
                                getattr(response, "headers", {}).get("content-type", "")
                            ).lower()
                            if content_type and "text/event-stream" not in content_type:
                                if is_global:
                                    await self._mark_global_event_unsupported(runtime)
                                    return
                                raise RuntimeError(
                                    f"unexpected content-type {content_type!r}"
                                )
                            received_event = False
                            async for event in _stream_sse_events(response):
                                if not self._dispatch_event(event, directory_key=directory_key):
                                    continue
                                payload = self._global_event_payload(event)
                                event_type, _ = _event_properties(payload)
                                confirmed_recovery = event_type != "server.connected"
                                if not received_event:
                                    received_event = True
                                    self._note_event_channel_connected(
                                        runtime,
                                        confirmed_recovery=confirmed_recovery,
                                    )
                                elif confirmed_recovery:
                                    self._note_event_channel_connected(runtime)
                                if confirmed_recovery:
                                    reconnect_delay = _SERVE_EVENT_RECONNECT_DELAY_SECONDS
                            reason = (
                                "event stream closed"
                                if received_event
                                else "event stream closed before server.connected"
                            )
                            self._note_event_channel_failure(
                                runtime,
                                error=reason,
                                retry_in=reconnect_delay,
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        self._note_event_channel_failure(
                            runtime,
                            error=exc,
                            retry_in=reconnect_delay,
                        )
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = _next_event_reconnect_delay(reconnect_delay)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._note_event_channel_failure(
                runtime,
                error=exc,
                retry_in=reconnect_delay,
            )
            await asyncio.sleep(reconnect_delay)
            runtime.task = asyncio.create_task(self._run_event_channel(
                runtime,
                is_global=is_global,
                initial_reconnect_delay=_next_event_reconnect_delay(reconnect_delay),
            ))
        finally:
            runtime.healthy = False
            runtime.ready.set()

    async def _poll_session_snapshots(
        self,
        *,
        client: httpx.AsyncClient,
        session_id: str,
        directory: Path,
        params: dict[str, str],
        headers: dict[str, str],
        state: _ServeEventState,
    ) -> None:
        poll_params = dict(params)
        poll_params["limit"] = "2"
        while True:
            if self._event_channel_healthy(directory):
                await asyncio.sleep(0.1)
                continue
            try:
                response = await client.get(
                    f"/session/{session_id}/message",
                    params=poll_params,
                    headers=headers,
                )
                response.raise_for_status()
                message = _latest_assistant_message(response.json(), session_id)
                if message is not None:
                    state.ingest_message_snapshot(message)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self._event_poll_failure_reported:
                    self._event_poll_failure_reported = True
                    self._emit_event_diagnostic(
                        f"status=poll_unavailable fallback=final_response "
                        f"error={_one_line_preview(exc)}"
                    )
            await asyncio.sleep(_SERVE_EVENT_POLL_INTERVAL_SECONDS)

    async def _list_tool_ids(
        self,
        client: httpx.AsyncClient,
        params: dict[str, str],
        headers: dict[str, str],
        *,
        on_line=None,
        tool: str = "opencode",
    ) -> list[str]:
        try:
            response = await client.get("/experimental/tool/ids", params=params, headers=headers)
            response.raise_for_status()
        except Exception as exc:
            if on_line:
                on_line(f"[{tool} serve] tool discovery unavailable: {_one_line_preview(exc)}")
            return []
        tool_ids = _tool_ids_from_response(response.json())
        if on_line:
            mcp_tool_ids = [tool_id for tool_id in tool_ids if _tool_source(tool_id) == "mcp"]
            mcp_note = ""
            if mcp_tool_ids:
                mcp_note = (
                    f" mcp_tools={len(mcp_tool_ids)} "
                    f"mcp_names={_one_line_preview(','.join(mcp_tool_ids))}"
                )
            on_line(f"[{tool} serve] tools={len(tool_ids)}{mcp_note}")
        return tool_ids

    async def list_models(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path | None = None,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        refresh: bool = False,
    ) -> OpenCodeModelListResult:
        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        directory_key = str(directory.resolve()) if directory is not None else ""
        cache_key = (key, directory_key)
        if not refresh:
            cached = self._model_cache.get(cache_key)
            if cached is not None:
                logger.info(
                    "OpenCode serve model list source=cache models=%s config_hash=%s",
                    len(cached),
                    key.config_hash[:12],
                )
                return OpenCodeModelListResult(models=list(cached))

        inflight_key = (cache_key, bool(refresh))
        task = self._model_inflight.get(inflight_key)
        if task is None:
            if refresh:
                self._invalidate_model_cache()
            generation = self._model_cache_generation
            task = asyncio.create_task(self._load_models(
                key=key,
                cache_key=cache_key,
                cache_generation=generation,
                directory=directory,
                config_workspace=config_workspace,
                refresh=refresh,
            ))
            self._model_inflight[inflight_key] = task

            def clear_inflight(done: asyncio.Task[OpenCodeModelListResult]) -> None:
                if self._model_inflight.get(inflight_key) is done:
                    self._model_inflight.pop(inflight_key, None)

            task.add_done_callback(clear_inflight)
        return await asyncio.shield(task)

    def _invalidate_model_cache(self) -> None:
        self._model_cache.clear()
        self._model_cache_generation += 1

    async def _load_models(
        self,
        *,
        key: OpenCodeServeKey,
        cache_key: tuple[OpenCodeServeKey, str],
        cache_generation: int,
        directory: Path | None,
        config_workspace: Path | None,
        refresh: bool,
    ) -> OpenCodeModelListResult:
        async with self._model_fetch_lock:
            if not refresh:
                cached = self._model_cache.get(cache_key)
                if cached is not None:
                    return OpenCodeModelListResult(models=list(cached))

            ensure_started_at = time.monotonic()
            refresh_deferred = await self._acquire_model_listing(
                key,
                startup_cwd=config_workspace,
            )
            ensure_elapsed = time.monotonic() - ensure_started_at
            request_started_at = time.monotonic()
            try:
                models = await self._fetch_models(directory)
            finally:
                await self._release_model_listing()
            request_elapsed = time.monotonic() - request_started_at
            message = ""
            if refresh_deferred:
                message = (
                    "当前有 OpenCode serve 会话运行，已返回当前模型列表；"
                    "配置重载将在会话结束后的下一次请求生效。"
                )
            if (
                not refresh_deferred
                and cache_generation == self._model_cache_generation
            ):
                self._model_cache[cache_key] = tuple(models)
            logger.info(
                "OpenCode serve model list source=serve models=%s ensure_ms=%s request_ms=%s "
                "refresh=%s refresh_deferred=%s config_hash=%s",
                len(models),
                round(ensure_elapsed * 1000),
                round(request_elapsed * 1000),
                refresh,
                refresh_deferred,
                key.config_hash[:12],
            )
            return OpenCodeModelListResult(models=models, message=message)

    async def _fetch_models(self, directory: Path | None) -> list[OpenCodeModelInfo]:
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)
        provider_data: Any = None
        provider_error: Exception | None = None
        provider_elapsed = 0.0
        config_elapsed = 0.0
        used_config_fallback = False

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
            trust_env=False,
        ) as client:
            started_at = time.monotonic()
            try:
                response = await client.get("/provider", params=params, headers=headers)
                response.raise_for_status()
                provider_data = response.json()
            except Exception as exc:
                provider_error = exc
            finally:
                provider_elapsed = time.monotonic() - started_at

            providers, provider_payload_valid = self._provider_entries(
                provider_data,
                "all",
                "providers",
            )
            connected = self._connected_provider_ids(provider_data)
            returned_provider_ids = {
                self._provider_id(provider)
                for provider in providers
                if self._provider_id(provider)
            }
            missing_connected = connected - returned_provider_ids
            needs_config_fallback = (
                not provider_payload_valid
                or not providers
                or bool(missing_connected)
            )
            config_providers: list[dict[str, Any]] = []
            config_payload_valid = False
            config_error: Exception | None = None
            if needs_config_fallback:
                used_config_fallback = True
                started_at = time.monotonic()
                try:
                    config_response = await client.get(
                        "/config/providers",
                        params=params,
                        headers=headers,
                        timeout=_SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS,
                    )
                    config_response.raise_for_status()
                    config_data = config_response.json()
                    config_providers, config_payload_valid = self._provider_entries(
                        config_data,
                        "providers",
                    )
                except Exception as exc:
                    config_error = exc
                finally:
                    config_elapsed = time.monotonic() - started_at

        if not provider_payload_valid and not config_payload_valid:
            details = []
            if provider_error is not None:
                details.append(f"/provider: {_one_line_preview(provider_error)}")
            elif provider_data is not None:
                details.append("/provider: invalid response")
            if config_error is not None:
                details.append(f"/config/providers: {_one_line_preview(config_error)}")
            else:
                details.append("/config/providers: invalid response")
            raise RuntimeError("OpenCode model listing failed (" + "; ".join(details) + ")")
        if config_error is not None and provider_payload_valid:
            logger.warning(
                "OpenCode config provider fallback unavailable: %s",
                _one_line_preview(config_error),
            )

        models: dict[str, OpenCodeModelInfo] = {}
        for provider in providers + config_providers:
            for item in _provider_models(provider):
                models[item.id] = item
        result = sorted(models.values(), key=lambda item: item.id)
        logger.info(
            "OpenCode serve provider lookup provider_ms=%s config_ms=%s fallback=%s models=%s",
            round(provider_elapsed * 1000),
            round(config_elapsed * 1000),
            used_config_fallback,
            len(result),
        )
        return result

    @staticmethod
    def _provider_entries(data: Any, *keys: str) -> tuple[list[dict[str, Any]], bool]:
        if not isinstance(data, dict):
            return [], False
        for key in keys:
            raw = data.get(key)
            if isinstance(raw, list):
                return [item for item in raw if isinstance(item, dict)], True
        return [], False

    @staticmethod
    def _provider_id(provider: dict[str, Any]) -> str:
        return str(
            provider.get("id")
            or provider.get("providerID")
            or provider.get("name")
            or ""
        ).strip()

    @staticmethod
    def _connected_provider_ids(data: Any) -> set[str]:
        if not isinstance(data, dict) or not isinstance(data.get("connected"), list):
            return set()
        return {
            str(item).strip()
            for item in data["connected"]
            if str(item).strip()
        }

    async def shutdown(self) -> None:
        async with self._lock:
            await self._stop_locked()
        self._dirty = False
        self._invalidate_model_cache()

    async def _acquire_session(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        async with self._lock:
            serve_mode = await self._ensure_started_locked(key, startup_cwd=startup_cwd)
            async with self._idle:
                self._active_sessions += 1
            return serve_mode

    async def _acquire_model_listing(
        self,
        key: OpenCodeServeKey,
        *,
        startup_cwd: Path | None = None,
    ) -> bool:
        """Acquire a short-lived serve operation and report a deferred reload."""
        async with self._lock:
            if self._proc is not None and self._proc.poll() is not None:
                await self._reset_managed_mcp_process_state()
                await self._stop_event_hub()
                self._proc = None
                self._key = None
                self._port = None
                self._startup_cwd = None

            refresh_deferred = False
            compatible_process = (
                self._proc is not None
                and self._same_process_key(self._key, key)
            )
            if (
                self._proc is not None
                and self._active_sessions > 0
                and (self._dirty or not compatible_process)
            ):
                # Never make a model picker wait for a scan to finish. Query the
                # current live serve now and keep the reload pending for the next
                # idle acquisition, even when proxy/tool/executable changes make
                # the requested process key incompatible.
                if not self._dirty:
                    self._dirty = True
                    self._serve_config_generation += 1
                    self._invalidate_model_cache()
                refresh_deferred = True
                logger.info(
                    "Deferring %s serve model config reload while %s session(s) are active",
                    key.tool,
                    self._active_sessions,
                )
            elif compatible_process and not self._dirty:
                # Model enumeration reflects the current serve process. Task-local
                # MCP/SKILL config hash churn must not restart an otherwise
                # compatible process just to show the picker.
                pass
            else:
                await self._ensure_started_locked(key, startup_cwd=startup_cwd)
                if self._dirty:
                    refresh_deferred = True

            async with self._idle:
                self._active_model_listings += 1
            return refresh_deferred

    async def _release_active_session(self) -> None:
        async with self._idle:
            self._active_sessions = max(0, self._active_sessions - 1)
            if self._active_sessions == 0 and self._active_model_listings == 0:
                self._idle.notify_all()

    async def _release_model_listing(self) -> None:
        async with self._idle:
            self._active_model_listings = max(0, self._active_model_listings - 1)
            if self._active_sessions == 0 and self._active_model_listings == 0:
                self._idle.notify_all()

    async def _wait_for_response(
        self,
        *,
        client: httpx.AsyncClient,
        request: asyncio.Task[httpx.Response],
        session_id: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: int,
        cancel_event,
    ) -> httpx.Response:
        started = time.monotonic()
        while True:
            if request.done():
                return await request
            if cancel_event and cancel_event.is_set():
                await self._abort_session(client, session_id, params, headers)
                raise asyncio.CancelledError()
            if time.monotonic() - started > timeout:
                await self._abort_session(client, session_id, params, headers)
                raise asyncio.TimeoutError()
            await asyncio.sleep(0.2)

    async def _ensure_started(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        async with self._lock:
            return await self._ensure_started_locked(key, startup_cwd=startup_cwd)

    async def _ensure_started_locked(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        had_process = self._proc is not None
        if self._proc is not None and self._proc.poll() is not None:
            await self._reset_managed_mcp_process_state()
            await self._stop_event_hub()
            self._proc = None
            self._key = None
            self._port = None
            self._startup_cwd = None
        if self._proc is not None and self._key == key and not self._dirty:
            return "reused"
        if self._proc is not None and self._same_process_key(self._key, key) and self._active_sessions > 0:
            logger.info(
                "Reusing active %s serve on 127.0.0.1:%s despite pending config change",
                key.tool,
                self._port,
            )
            return "reused"
        reload_generation = self._serve_config_generation
        await self._wait_until_idle_locked()
        await self._stop_locked()
        await self._start_locked(key, startup_cwd=startup_cwd)
        if self._serve_config_generation == reload_generation:
            self._dirty = False
        return "restarted" if had_process else "started"

    @staticmethod
    def _same_process_key(current: OpenCodeServeKey | None, requested: OpenCodeServeKey) -> bool:
        return (
            current is not None
            and current.tool == requested.tool
            and current.executable == requested.executable
            and current.env_hash == requested.env_hash
        )

    async def _wait_until_idle_locked(self) -> None:
        while self._active_sessions > 0 or self._active_model_listings > 0:
            async with self._idle:
                await self._idle.wait()

    async def _start_locked(self, key: OpenCodeServeKey, startup_cwd: Path | None = None) -> None:
        executable = _resolve_executable(key.executable)
        port = _serve_port()
        await self._stop_owned_serve_on_port(port)
        if _port_is_in_use(port):
            reclaim = await asyncio.to_thread(
                _reclaim_serve_port,
                port,
                reason="serve startup",
            )
            if _port_is_in_use(port):
                raise RuntimeError(_port_busy_message(port, reclaim))
        prepared_cwd = _prepare_serve_startup_cwd(key.tool, startup_cwd)
        config_path = _write_serve_config_file(prepared_cwd, key.config_content)
        env = dict(os.environ)
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        if any(name in _SERVE_PROXY_ENV_NAMES for name, _ in key.env_overrides):
            for name in _SERVE_PROXY_CLEAR_ENV_NAMES:
                env.pop(name, None)
        for name, value in key.env_overrides:
            env[name] = value
        # The resolved config is file-backed. Environment overrides are never
        # allowed to re-introduce content injection or redirect the config dir.
        env.pop("OPENCODE_CONFIG_CONTENT", None)
        env["OPENCODE_CONFIG_DIR"] = str(prepared_cwd)
        env.pop("OPENCODE_SERVER_PASSWORD", None)
        env.pop("OPENCODE_SERVER_USERNAME", None)
        cmd = [
            executable,
            "serve",
            "--hostname",
            "127.0.0.1",
            "--port",
            str(port),
        ]
        kwargs: dict[str, Any] = {}
        if sys.platform != "win32":
            kwargs["start_new_session"] = True
        startup_log_path = _new_serve_startup_log_path(key.tool, port)
        self._startup_log_path = startup_log_path
        _log_serve_startup_debug(
            key=key,
            cmd=cmd,
            port=port,
            cwd=prepared_cwd,
            env=env,
            startup_log_path=startup_log_path,
            popen_kwargs=kwargs,
            marker_path=self._marker_path,
            config_path=config_path,
        )
        try:
            with startup_log_path.open("ab") as startup_log:
                self._proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=startup_log,
                    stderr=subprocess.STDOUT,
                    env=env,
                    cwd=str(prepared_cwd),
                    **kwargs,
                )
        except Exception:
            self._startup_log_path = None
            _remove_file(startup_log_path)
            raise
        self._key = key
        self._port = port
        self._startup_cwd = prepared_cwd
        _write_marker(self._marker_path, proc=self._proc, key=key, port=port)
        try:
            await self._wait_health_locked(startup_log_path)
        except Exception:
            await self._stop_locked()
            raise
        _remove_file(startup_log_path)
        config_note = f" config_hash={key.config_hash[:12]}" if key.config_hash else ""
        logger.info("Started %s serve on 127.0.0.1:%s cwd=%s%s", key.tool, port, prepared_cwd, config_note)

    async def _stop_owned_serve_on_port(self, port: int) -> None:
        marker = _read_marker(self._marker_path)
        if marker is None:
            return
        if int(marker.get("port") or 0) != int(port):
            return
        pid = int(marker.get("pid") or 0)
        if not _pid_is_running(pid):
            _remove_marker(self._marker_path)
            if _port_is_in_use(port):
                await asyncio.to_thread(
                    _reclaim_serve_port,
                    port,
                    reason="stale Agent-owned serve marker",
                )
            return
        if not _marker_matches_serve_process(marker):
            return
        logger.info(
            "Stopping previous Agent-owned %s serve pid %s on 127.0.0.1:%s",
            marker.get("tool") or "opencode",
            pid,
            port,
        )
        await asyncio.to_thread(_terminate_process_tree, pid)
        _remove_marker(self._marker_path)
        if _port_is_in_use(port):
            await asyncio.to_thread(
                _reclaim_serve_port,
                port,
                reason="Agent-owned serve process tree left listener behind",
            )

    async def _wait_health_locked(self, startup_log_path: Path | None = None) -> None:
        deadline = time.monotonic() + _SERVE_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                cwd_note = f" startup_cwd={self._startup_cwd}" if self._startup_cwd else ""
                raise RuntimeError(_with_serve_startup_log(
                    f"OpenCode serve exited during startup with code {self._proc.returncode}{cwd_note}",
                    startup_log_path,
                ))
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=2.0,
                    trust_env=False,
                ) as client:
                    response = await client.get("/global/health")
                    if response.status_code < 500:
                        return
            except Exception:
                pass
            await asyncio.sleep(_SERVE_HEALTH_POLL_INTERVAL_SECONDS)
        cwd_note = f" startup_cwd={self._startup_cwd}" if self._startup_cwd else ""
        raise TimeoutError(_with_serve_startup_log(
            f"OpenCode serve did not become healthy{cwd_note}",
            startup_log_path,
        ))

    async def _abort_session(
        self,
        client: httpx.AsyncClient,
        session_id: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> None:
        try:
            await client.post(
                f"/session/{session_id}/abort",
                params=params,
                headers=headers,
                timeout=5.0,
            )
        except Exception as exc:
            logger.warning("Failed to abort OpenCode session %s: %s", session_id, exc)

    async def _stop_event_hub(self) -> None:
        async with self._event_lock:
            channels = [
                channel
                for channel in (
                    [self._global_event_channel]
                    + list(self._legacy_event_channels.values())
                )
                if channel is not None
            ]
            tasks = [
                channel.task
                for channel in channels
                if channel.task is not None and not channel.task.done()
            ]
            self._global_event_channel = None
            self._legacy_event_channels.clear()
            self._global_event_unsupported = False
            self._event_states.clear()
            self._event_directories.clear()
            self._degraded_event_channels.clear()
            self._event_failure_started_at = 0.0
            self._event_failure_attempts = 0
            self._event_last_failure_summary_at = 0.0
            self._event_poll_failure_reported = False
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _reset_managed_mcp_process_state(self) -> None:
        tasks = [task for task in self._managed_mcp_tasks.values() if not task.done()]
        self._managed_mcp_tasks.clear()
        # Clear directory ownership before cancellation callbacks run. Otherwise
        # a cancelled sync with no recorded status can schedule a replacement
        # task against the serve process that is currently being stopped.
        self._managed_mcp_directories.clear()
        self._managed_mcp_status.clear()
        self._managed_mcp_applied.clear()
        self._managed_mcp_locks.clear()
        self._managed_mcp_force_pending.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _stop_locked(self) -> None:
        await self._reset_managed_mcp_process_state()
        await self._stop_event_hub()
        proc = self._proc
        port = self._port
        startup_log_path = self._startup_log_path
        self._proc = None
        self._port = None
        self._key = None
        self._startup_log_path = None
        self._startup_cwd = None
        if proc is None:
            _remove_file(startup_log_path)
            return
        if proc.poll() is not None:
            try:
                _remove_marker_for_pid(self._marker_path, getattr(proc, "pid", None))
                if port is not None and _port_is_in_use(port):
                    await asyncio.to_thread(
                        _reclaim_serve_port,
                        port,
                        reason="serve parent process already exited",
                    )
            finally:
                _remove_file(startup_log_path)
            return
        pid = int(getattr(proc, "pid", 0) or 0)
        try:
            if pid > 0:
                await asyncio.to_thread(
                    _terminate_process_tree,
                    pid,
                    wait=lambda wait_timeout: proc.wait(timeout=wait_timeout),
                )
        finally:
            try:
                _remove_marker_for_pid(self._marker_path, getattr(proc, "pid", None))
                if port is not None and _port_is_in_use(port):
                    await asyncio.to_thread(
                        _reclaim_serve_port,
                        port,
                        reason="serve shutdown",
                    )
            finally:
                _remove_file(startup_log_path)


_manager = OpenCodeServeManager()


def _serve_context_params(
    directory: Path | None,
) -> dict[str, str]:
    params: dict[str, str] = {}
    if directory is not None:
        params["directory"] = str(directory)
    return params


def _serve_context_headers(directory: Path | None) -> dict[str, str]:
    if directory is None:
        return {}
    return {"x-opencode-directory": quote(str(directory), safe="/:\\")}


def get_serve_manager() -> OpenCodeServeManager:
    return _manager


def mark_serve_config_dirty() -> None:
    _manager.mark_dirty()
