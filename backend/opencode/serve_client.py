"""HTTP client and process manager for OpenCode-compatible serve mode."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from backend.logger import get_logger

logger = get_logger(__name__)

_SERVE_START_TIMEOUT_SECONDS = 30.0
_SERVE_STOP_TIMEOUT_SECONDS = 5.0
_SERVE_REQUEST_TIMEOUT_SECONDS = 20.0
_SERVE_EVENT_PREVIEW_LIMIT = 500
_DEFAULT_SERVE_PORT = 4096
_SERVE_PORT_ENV = "OPENCODE_SERVE_PORT"
_SERVE_MARKER_ENV = "OPENCODE_SERVE_MARKER"
_SERVE_MARKER_OWNER = "opendeephole-agent-serve-v1"


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


def _terminate_pid(pid: int, timeout: float = _SERVE_STOP_TIMEOUT_SECONDS) -> None:
    if not _pid_is_running(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception as exc:
        logger.warning("Failed to terminate old OpenCode serve pid %s: %s", pid, exc)
        return

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_running(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
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
        cancel_event=None,
    ) -> list[str]:
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            config_hash=_config_hash(config_content),
            config_content=config_content or "",
        )
        await self._acquire_session(key)
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
        await self._ensure_started(key)
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

    async def _acquire_session(self, key: OpenCodeServeKey) -> None:
        async with self._lock:
            await self._ensure_started_locked(key)
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

    async def _ensure_started(self, key: OpenCodeServeKey) -> None:
        async with self._lock:
            await self._ensure_started_locked(key)

    async def _ensure_started_locked(self, key: OpenCodeServeKey) -> None:
        if self._proc is not None and self._proc.poll() is not None:
            self._proc = None
            self._port = None
        if self._proc is not None and self._key == key:
            self._dirty = False
            return
        await self._wait_until_idle_locked()
        await self._stop_locked()
        await self._start_locked(key)
        self._dirty = False

    async def _wait_until_idle_locked(self) -> None:
        while self._active_sessions > 0:
            async with self._idle:
                await self._idle.wait()

    async def _start_locked(self, key: OpenCodeServeKey) -> None:
        executable = _resolve_executable(key.executable)
        port = _serve_port()
        await self._stop_owned_serve_on_port(port)
        if _port_is_in_use(port):
            raise RuntimeError(
                f"OpenCode serve port 127.0.0.1:{port} is already in use by a process "
                "not owned by this Agent; stop it or set OPENCODE_SERVE_PORT."
            )
        env = dict(os.environ)
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
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
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
            **kwargs,
        )
        self._key = key
        self._port = port
        _write_marker(self._marker_path, proc=self._proc, key=key, port=port)
        try:
            await self._wait_health_locked()
        except Exception:
            await self._stop_locked()
            raise
        config_note = f" config_hash={key.config_hash[:12]}" if key.config_hash else ""
        logger.info("Started %s serve on 127.0.0.1:%s%s", key.tool, port, config_note)

    async def _stop_owned_serve_on_port(self, port: int) -> None:
        marker = _read_marker(self._marker_path)
        if marker is None:
            return
        if int(marker.get("port") or 0) != int(port):
            return
        pid = int(marker.get("pid") or 0)
        if not _pid_is_running(pid):
            _remove_marker(self._marker_path)
            return
        if not _marker_matches_serve_process(marker):
            return
        logger.info(
            "Stopping previous Agent-owned %s serve pid %s on 127.0.0.1:%s",
            marker.get("tool") or "opencode",
            pid,
            port,
        )
        await asyncio.to_thread(_terminate_pid, pid)
        _remove_marker(self._marker_path)

    async def _wait_health_locked(self) -> None:
        deadline = time.monotonic() + _SERVE_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise RuntimeError(f"OpenCode serve exited during startup with code {self._proc.returncode}")
            try:
                async with httpx.AsyncClient(base_url=self.base_url, timeout=2.0) as client:
                    response = await client.get("/global/health")
                    if response.status_code < 500:
                        return
            except Exception:
                await asyncio.sleep(0.2)
        raise TimeoutError("OpenCode serve did not become healthy")

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
        self._proc = None
        self._port = None
        self._key = None
        if proc is None:
            return
        if proc.poll() is not None:
            _remove_marker_for_pid(self._marker_path, getattr(proc, "pid", None))
            return
        try:
            proc.terminate()
            await asyncio.to_thread(proc.wait, timeout=_SERVE_STOP_TIMEOUT_SECONDS)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            _remove_marker_for_pid(self._marker_path, getattr(proc, "pid", None))


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
