"""HTTP client and process manager for OpenCode-compatible serve mode."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from backend.logger import get_logger

logger = get_logger(__name__)

_SERVE_START_TIMEOUT_SECONDS = 30.0
_SERVE_STOP_TIMEOUT_SECONDS = 5.0
_SERVE_REQUEST_TIMEOUT_SECONDS = 20.0
_SERVE_EVENT_PREVIEW_LIMIT = 500


@dataclass(frozen=True)
class OpenCodeServeKey:
    tool: str
    executable: str


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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
            f"[{state.tool} serve tool] call name={props.get('tool') or ''} "
            f"id={props.get('callID') or ''} input={_json_one_line(props.get('input') or {})}"
        )
    elif event_type == "session.next.tool.success":
        state.on_line(
            f"[{state.tool} serve tool] success id={props.get('callID') or ''} "
            f"{_tool_content_summary(props.get('content'))}"
        )
    elif event_type == "session.next.tool.failed":
        state.on_line(
            f"[{state.tool} serve tool] failed id={props.get('callID') or ''} "
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


def _extract_tool_ids(value: Any) -> list[str]:
    """Return tool ids from the shapes exposed by OpenCode serve versions."""
    raw_items: Any
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, dict):
        for key in ("ids", "tools", "all"):
            items = value.get(key)
            if isinstance(items, list):
                raw_items = items
                break
        else:
            raw_items = [
                key for key, enabled in value.items()
                if isinstance(key, str) and enabled is not False
            ]
    else:
        raw_items = []

    ids: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        if isinstance(item, str):
            tool_id = item.strip()
        elif isinstance(item, dict):
            tool_id = str(item.get("id") or item.get("name") or "").strip()
        else:
            continue
        if tool_id and tool_id not in seen:
            ids.append(tool_id)
            seen.add(tool_id)
    return ids


async def _message_tools_payload(
    client: httpx.AsyncClient,
    *,
    params: dict[str, str],
    tool: str,
) -> dict[str, bool]:
    try:
        response = await client.get("/experimental/tool/ids", params=params)
        response.raise_for_status()
    except Exception as exc:
        logger.warning("Failed to list %s serve tools; using default tool set: %s", tool, exc)
        return {}

    tool_ids = _extract_tool_ids(response.json())
    return {tool_id: True for tool_id in tool_ids}


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
        prompt: str,
        model: str,
        timeout: int,
        on_line=None,
        cancel_event=None,
    ) -> list[str]:
        key = OpenCodeServeKey(tool=tool, executable=executable)
        await self._acquire_session(key)
        session_id = ""
        event_task: asyncio.Task | None = None
        event_state: _ServeEventState | None = None
        try:
            request_directory = config_workspace or directory
            params = _serve_context_params(request_directory)
            async with httpx.AsyncClient(base_url=self.base_url, timeout=_SERVE_REQUEST_TIMEOUT_SECONDS) as client:
                created = await client.post("/session", params=params, json={"title": "OpenDeepHole task"})
                created.raise_for_status()
                session_id = _session_id(created.json())
                if on_line:
                    source_note = f" source={directory}" if request_directory != directory else ""
                    on_line(f"[{tool} serve] session={session_id} directory={request_directory}{source_note}")
                    event_state = _ServeEventState(tool, session_id, on_line)
                    event_task = asyncio.create_task(self._stream_session_events(params, event_state))
                payload: dict[str, Any] = {
                    "parts": [{"type": "text", "text": prompt}],
                }
                tools = await _message_tools_payload(client, params=params, tool=tool)
                if tools:
                    payload["tools"] = tools
                if model:
                    provider_id, model_id = split_model_id(model)
                    payload["model"] = {"providerID": provider_id, "modelID": model_id}

                request = asyncio.create_task(
                    client.post(
                        f"/session/{session_id}/message",
                        params=params,
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
            if session_id:
                await self._delete_session(session_id, params)
            async with self._idle:
                self._active_sessions = max(0, self._active_sessions - 1)
                if self._active_sessions == 0:
                    self._idle.notify_all()

    async def list_models(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path | None = None,
        config_workspace: Path | None = None,
        refresh: bool = False,
    ) -> list[OpenCodeModelInfo]:
        key = OpenCodeServeKey(tool=tool, executable=executable)
        await self._ensure_started(key)
        request_directory = config_workspace or directory
        params = _serve_context_params(request_directory)
        async with httpx.AsyncClient(base_url=self.base_url, timeout=_SERVE_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get("/provider", params=params)
            response.raise_for_status()
            data = response.json()
            try:
                config_response = await client.get("/config/providers", params=params)
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
        timeout: int,
        cancel_event,
    ) -> httpx.Response:
        started = time.monotonic()
        while True:
            if request.done():
                return await request
            if cancel_event and cancel_event.is_set():
                await self._abort_session(client, session_id, params)
                raise asyncio.CancelledError()
            if time.monotonic() - started > timeout:
                await self._abort_session(client, session_id, params)
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
        port = _free_port()
        env = dict(os.environ)
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
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
        try:
            await self._wait_health_locked()
        except Exception:
            await self._stop_locked()
            raise
        logger.info("Started %s serve on 127.0.0.1:%s", key.tool, port)

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

    async def _abort_session(self, client: httpx.AsyncClient, session_id: str, params: dict[str, str]) -> None:
        try:
            await client.post(f"/session/{session_id}/abort", params=params, timeout=5.0)
        except Exception as exc:
            logger.warning("Failed to abort OpenCode session %s: %s", session_id, exc)

    async def _stream_session_events(self, params: dict[str, str], state: _ServeEventState) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=None) as client:
                async with client.stream("GET", "/event", params=params) as response:
                    response.raise_for_status()
                    async for event in _stream_sse_events(response):
                        _handle_serve_event(event, state)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("OpenCode serve event stream unavailable: %s", exc)

    async def _delete_session(self, session_id: str, params: dict[str, str]) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=5.0) as client:
                await client.delete("/session/" + session_id, params=params)
        except Exception:
            pass

    async def _stop_locked(self) -> None:
        proc = self._proc
        self._proc = None
        self._port = None
        self._key = None
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            await asyncio.to_thread(proc.wait, timeout=_SERVE_STOP_TIMEOUT_SECONDS)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


_manager = OpenCodeServeManager()


def _serve_context_params(
    directory: Path | None,
) -> dict[str, str] | None:
    params: dict[str, str] = {}
    if directory is not None:
        params["directory"] = str(directory)
    return params or None


def get_serve_manager() -> OpenCodeServeManager:
    return _manager


def mark_serve_config_dirty() -> None:
    _manager.mark_dirty()
