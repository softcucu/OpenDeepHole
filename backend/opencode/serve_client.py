"""HTTP client and process manager for OpenCode-compatible serve mode."""

from __future__ import annotations

import asyncio
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


@dataclass(frozen=True)
class OpenCodeServeKey:
    tool: str
    executable: str
    config_content: str = ""


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
        self._dirty = True

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
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            config_content=_read_config_content(config_workspace),
        )
        await self._acquire_session(key)
        session_id = ""
        try:
            params = {"directory": str(directory)}
            async with httpx.AsyncClient(base_url=self.base_url, timeout=_SERVE_REQUEST_TIMEOUT_SECONDS) as client:
                created = await client.post("/session", params=params, json={"title": "OpenDeepHole task"})
                created.raise_for_status()
                session_id = _session_id(created.json())
                if on_line:
                    on_line(f"[{tool} serve] session={session_id} directory={directory}")
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
                lines = _extract_text(response.json())
                for line in lines:
                    if on_line:
                        on_line(line)
                return lines
        finally:
            if session_id:
                await self._delete_session(session_id, Path(directory))
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
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            config_content=_read_config_content(config_workspace),
        )
        if refresh:
            self.mark_dirty()
        await self._ensure_started(key)
        params = {"directory": str(directory)} if directory is not None else None
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
        if self._proc is not None and self._key == key and not self._dirty:
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

    async def _delete_session(self, session_id: str, directory: Path) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=5.0) as client:
                await client.delete("/session/" + session_id, params={"directory": str(directory)})
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


def _read_config_content(config_workspace: Path | None) -> str:
    if config_workspace is None:
        return ""
    try:
        return (Path(config_workspace) / "opencode.json").read_text(encoding="utf-8")
    except OSError:
        return ""


def get_serve_manager() -> OpenCodeServeManager:
    return _manager


def mark_serve_config_dirty() -> None:
    _manager.mark_dirty()
