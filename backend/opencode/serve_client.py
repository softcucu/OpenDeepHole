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
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import httpx

from backend.logger import get_logger

logger = get_logger(__name__)

_SERVE_START_TIMEOUT_SECONDS = 30.0
_SERVE_STOP_TIMEOUT_SECONDS = 5.0
_SERVE_REQUEST_TIMEOUT_SECONDS = 20.0
_SERVE_EVENT_PREVIEW_LIMIT = 500
_SERVE_STARTUP_LOG_TAIL_LIMIT = 4000
_DEFAULT_SERVE_PORT = 4096
_SERVE_PORT_ENV = "OPENCODE_SERVE_PORT"
_SERVE_MARKER_ENV = "OPENCODE_SERVE_MARKER"
_SERVE_MARKER_OWNER = "opendeephole-agent-serve-v1"
_SERVE_BOOTSTRAP_CWD_PREFIX = "opendeephole-opencode-serve-bootstrap"
_SENSITIVE_CONFIG_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|authorization|cookie|credential|headers?)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OpenCodeServeKey:
    tool: str
    executable: str
    config_hash: str = ""
    config_content: str = field(default="", compare=False, repr=False)


@dataclass(frozen=True)
class OpenCodeModelInfo:
    id: str
    provider_id: str
    model_id: str
    name: str = ""


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


def _redact_sensitive_config(value: Any, *, parent_key: str = "") -> Any:
    if parent_key and _SENSITIVE_CONFIG_KEY_RE.search(parent_key):
        return "***"
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _SENSITIVE_CONFIG_KEY_RE.search(key_text):
                redacted[key] = "***"
            else:
                redacted[key] = _redact_sensitive_config(item, parent_key=key_text)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_config(item, parent_key=parent_key) for item in value]
    return value


def _redacted_config_content(config_content: str) -> str:
    if not config_content:
        return ""
    try:
        data = json.loads(config_content)
    except Exception:
        return f"<redacted invalid config content bytes={len(config_content.encode('utf-8'))}>"
    return json.dumps(_redact_sensitive_config(data), ensure_ascii=False)


def _serve_debug_env_value(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if name == "OPENCODE_CONFIG_CONTENT":
        return _redacted_config_content(value)
    return value


def _serve_startup_env_debug(env: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for name in (
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "OPENCODE_CONFIG_CONTENT",
    ):
        value = _serve_debug_env_value(name, env.get(name))
        lines.append(f"    {name}={value if value is not None else '(unset)'}")
    lines.append("    OPENCODE_SERVER_PASSWORD=(cleared)")
    lines.append("    OPENCODE_SERVER_USERNAME=(cleared)")
    return lines


def _serve_startup_shell_debug(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    env_parts = [
        f"{name}={shlex.quote(_serve_debug_env_value(name, env[name]) or '')}"
        for name in (
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
            "OPENCODE_CONFIG_CONTENT",
        )
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
) -> None:
    config_content = env.get("OPENCODE_CONFIG_CONTENT", "")
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
        f"  config_content_bytes={len(config_content.encode('utf-8')) if config_content else 0}",
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
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


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


def _one_line_preview(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated {len(text) - limit} chars]"


def _json_one_line(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
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

    def append(self, text: str) -> bool:
        if not text:
            return False
        self._buffer += text
        emitted = False
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line.strip():
                self._on_line(f"{self._prefix} {line.strip()}")
                emitted = True
        return emitted

    def flush(self) -> bool:
        text = self._buffer.strip()
        self._buffer = ""
        if not text:
            return False
        self._on_line(f"{self._prefix} {text}")
        return True


class _ServeEventState:
    def __init__(self, tool: str, session_id: str, on_line) -> None:
        self.tool = tool
        self.session_id = session_id
        self.on_line = on_line
        self.emitted_text = False
        self.seen_next_event = False
        self.text = _BufferedEventEmitter(on_line, f"[{tool} serve llm]")
        self.reasoning = _BufferedEventEmitter(on_line, f"[{tool} serve reasoning]")

    def flush(self) -> None:
        self.emitted_text = self.text.flush() or self.emitted_text
        self.emitted_text = self.reasoning.flush() or self.emitted_text


def _event_properties(event: object) -> tuple[str, dict[str, Any]]:
    if not isinstance(event, dict):
        return "", {}
    event_type = str(event.get("type") or "")
    properties = event.get("properties")
    if isinstance(properties, dict):
        return event_type, properties
    return event_type, {}


def _handle_serve_event(event: object, state: _ServeEventState) -> None:
    event_type, props = _event_properties(event)
    if props.get("sessionID") != state.session_id:
        return

    if event_type.startswith("session.next."):
        state.seen_next_event = True

    if event_type == "session.next.text.delta":
        state.emitted_text = state.text.append(str(props.get("delta") or "")) or state.emitted_text
    elif event_type == "session.next.text.ended":
        state.emitted_text = state.text.flush() or state.emitted_text
    elif event_type == "session.next.reasoning.delta":
        state.emitted_text = state.reasoning.append(str(props.get("delta") or "")) or state.emitted_text
    elif event_type == "session.next.reasoning.ended":
        state.emitted_text = state.reasoning.flush() or state.emitted_text
    elif event_type == "session.next.tool.called":
        state.on_line(
            f"[{state.tool} serve tool] session={state.session_id} call name={props.get('tool') or ''} "
            f"id={props.get('callID') or ''} input={_json_one_line(props.get('input') or {})}"
        )
    elif event_type == "session.next.tool.success":
        state.on_line(
            f"[{state.tool} serve tool] session={state.session_id} success id={props.get('callID') or ''} "
            f"{_tool_content_summary(props.get('content'))}"
        )
    elif event_type == "session.next.tool.failed":
        state.on_line(
            f"[{state.tool} serve tool] session={state.session_id} failed id={props.get('callID') or ''} "
            f"error={_one_line_preview(props.get('error') or '')}"
        )
    elif event_type == "message.part.delta" and not state.seen_next_event:
        field = str(props.get("field") or "")
        if field in {"text", "content"}:
            state.emitted_text = state.text.append(str(props.get("delta") or "")) or state.emitted_text


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
        self._dirty = False

    @property
    def base_url(self) -> str:
        if self._port is None:
            raise RuntimeError("OpenCode serve is not running")
        return f"http://127.0.0.1:{self._port}"

    def mark_dirty(self) -> None:
        # Serve reads per-request workspace context; config refreshes should not
        # tear down active sessions. The process is restarted only when the
        # executable/tool boundary changes or the process exits.
        self._dirty = False

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
        cancel_event=None,
    ) -> list[str]:
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
        )
        await self._acquire_session(key, startup_cwd=config_workspace)
        session_id = ""
        event_task: asyncio.Task | None = None
        event_state: _ServeEventState | None = None
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=_SERVE_REQUEST_TIMEOUT_SECONDS) as client:
                created = await client.post(
                    "/session",
                    params=params,
                    headers=headers,
                    json={"title": "OpenDeepHole task"},
                )
                created.raise_for_status()
                session_id = _session_id(created.json())
                if on_session_id:
                    result = on_session_id(session_id)
                    if hasattr(result, "__await__"):
                        await result
                if on_line:
                    config_note = f" config={config_workspace}" if config_workspace else ""
                    on_line(f"[{tool} serve] session={session_id} directory={directory}{config_note}")
                    event_state = _ServeEventState(tool, session_id, on_line)
                    event_task = asyncio.create_task(self._stream_session_events(params, headers, event_state))
                payload: dict[str, Any] = {
                    "agent": agent,
                    "parts": [{"type": "text", "text": prompt}],
                }
                tool_ids = await self._list_tool_ids(client, params, headers, on_line=on_line, tool=tool)
                if tool_ids:
                    payload["tools"] = {tool_id: True for tool_id in tool_ids}
                if model:
                    provider_id, model_id = split_model_id(model)
                    payload["model"] = {"providerID": provider_id, "modelID": model_id}

                request = asyncio.create_task(
                    client.post(
                        f"/session/{session_id}/message",
                        params=params,
                        headers=headers,
                        json=payload,
                        timeout=timeout + 30,
                    )
                )
                try:
                    response = await self._wait_for_response(
                        client=client,
                        request=request,
                        session_id=session_id,
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
                    event_state.flush()
                lines = _extract_text(response.json())
                for line in lines:
                    if on_line and not (event_state and event_state.emitted_text):
                        on_line(line)
                return lines
        finally:
            if event_task is not None:
                event_task.cancel()
                with contextlib.suppress(BaseException):
                    await event_task
            if event_state:
                event_state.flush()
            async with self._idle:
                self._active_sessions = max(0, self._active_sessions - 1)
                if self._active_sessions == 0:
                    self._idle.notify_all()

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
            on_line(f"[{tool} serve] tools={len(tool_ids)}")
        return tool_ids

    async def list_models(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path | None = None,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        refresh: bool = False,
    ) -> list[OpenCodeModelInfo]:
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
        )
        await self._ensure_started(key, startup_cwd=config_workspace)
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)
        async with httpx.AsyncClient(base_url=self.base_url, timeout=_SERVE_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get("/provider", params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            try:
                config_response = await client.get("/config/providers", params=params, headers=headers)
                config_response.raise_for_status()
                config_data = config_response.json()
            except Exception:
                config_data = {}
        providers = []
        if isinstance(data, dict):
            raw = data.get("all") or data.get("providers") or []
            providers = raw if isinstance(raw, list) else []
        config_providers = []
        if isinstance(config_data, dict):
            raw = config_data.get("providers") or []
            config_providers = raw if isinstance(raw, list) else []
        models: dict[str, OpenCodeModelInfo] = {}
        for provider in providers + config_providers:
            if not isinstance(provider, dict):
                continue
            for item in _provider_models(provider):
                models[item.id] = item
        return sorted(models.values(), key=lambda item: item.id)

    async def shutdown(self) -> None:
        async with self._lock:
            await self._stop_locked()

    async def _acquire_session(self, key: OpenCodeServeKey, startup_cwd: Path | None = None) -> None:
        async with self._lock:
            await self._ensure_started_locked(key, startup_cwd=startup_cwd)
            async with self._idle:
                self._active_sessions += 1

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

    async def _ensure_started(self, key: OpenCodeServeKey, startup_cwd: Path | None = None) -> None:
        async with self._lock:
            await self._ensure_started_locked(key, startup_cwd=startup_cwd)

    async def _ensure_started_locked(self, key: OpenCodeServeKey, startup_cwd: Path | None = None) -> None:
        if self._proc is not None and self._proc.poll() is not None:
            self._proc = None
            self._port = None
            self._startup_cwd = None
        if self._proc is not None and self._key == key:
            self._dirty = False
            return
        if self._proc is not None and self._same_process_key(self._key, key) and self._active_sessions > 0:
            self._dirty = False
            logger.info(
                "Reusing active %s serve on 127.0.0.1:%s despite config hash change",
                key.tool,
                self._port,
            )
            return
        await self._wait_until_idle_locked()
        await self._stop_locked()
        await self._start_locked(key, startup_cwd=startup_cwd)
        self._dirty = False

    @staticmethod
    def _same_process_key(current: OpenCodeServeKey | None, requested: OpenCodeServeKey) -> bool:
        return (
            current is not None
            and current.tool == requested.tool
            and current.executable == requested.executable
        )

    async def _wait_until_idle_locked(self) -> None:
        while self._active_sessions > 0:
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
        env = dict(os.environ)
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        if key.config_content:
            env["OPENCODE_CONFIG_CONTENT"] = key.config_content
        else:
            env.pop("OPENCODE_CONFIG_CONTENT", None)
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
                async with httpx.AsyncClient(base_url=self.base_url, timeout=2.0) as client:
                    response = await client.get("/global/health")
                    if response.status_code < 500:
                        return
            except Exception:
                await asyncio.sleep(0.2)
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

    async def _stream_session_events(
        self,
        params: dict[str, str],
        headers: dict[str, str],
        state: _ServeEventState,
    ) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=None) as client:
                async with client.stream("GET", "/event", params=params, headers=headers) as response:
                    response.raise_for_status()
                    async for event in _stream_sse_events(response):
                        _handle_serve_event(event, state)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("OpenCode serve event stream unavailable: %s", exc)

    async def _stop_locked(self) -> None:
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
