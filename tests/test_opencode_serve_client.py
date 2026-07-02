import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from backend.opencode.serve_client import OpenCodeServeKey, OpenCodeServeManager, _serve_port


class _FakeResponse:
    def __init__(self, data, *, error: Exception | None = None) -> None:
        self._data = data
        self._error = error

    def json(self):
        return self._data

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error

    async def aiter_lines(self):
        for line in self._data:
            await asyncio.sleep(0)
            yield line


class _FakeStreamContext:
    def __init__(self, lines: list[str]) -> None:
        self._response = _FakeResponse(lines)

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _FakeAsyncClient:
    instances: list["_FakeAsyncClient"] = []
    event_lines: list[str] = []

    def __init__(self, *args, **kwargs) -> None:
        self.posts: list[dict] = []
        self.gets: list[dict] = []
        self.deletes: list[dict] = []
        self.streams: list[dict] = []

    async def __aenter__(self):
        self.instances.append(self)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, path: str, **kwargs):
        self.gets.append({"path": path, **kwargs})
        return _FakeResponse({})

    async def post(self, path: str, **kwargs):
        self.posts.append({"path": path, **kwargs})
        if path == "/session":
            return _FakeResponse({"id": "session-1"})
        if path == "/session/session-1/message":
            await asyncio.sleep(0)
            return _FakeResponse({"parts": [{"type": "text", "text": "done"}]})
        return _FakeResponse({})

    async def delete(self, path: str, **kwargs):
        self.deletes.append({"path": path, **kwargs})
        return _FakeResponse(True)

    def stream(self, method: str, path: str, **kwargs):
        self.streams.append({"method": method, "path": path, **kwargs})
        return _FakeStreamContext(self.event_lines)


def test_run_prompt_uses_project_directory_and_default_tools(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        monkeypatch.setattr(
            "backend.opencode.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        config_workspace = tmp_path / "runtime"
        project.mkdir()
        config_workspace.mkdir()
        config_content = '{"mcp": {}}'
        (config_workspace / "opencode.json").write_text(config_content, encoding="utf-8")

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=config_workspace,
            config_content=config_content,
            prompt="hello",
            model="anthropic/claude-sonnet",
            timeout=30,
        )

        assert lines == ["done"]
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        expected_hash = hashlib.sha256(config_content.encode("utf-8")).hexdigest()
        assert manager._acquire_session.await_args.args[0] == OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash=expected_hash,
        )
        expected_params = {"directory": str(project)}
        expected_headers = {"x-opencode-directory": str(project)}
        assert session_client.posts[0]["path"] == "/session"
        assert session_client.posts[0]["params"] == expected_params
        assert session_client.posts[0]["headers"] == expected_headers
        assert message["params"] == expected_params
        assert message["headers"] == expected_headers
        assert message["json"]["agent"] == "build"
        assert "tools" not in message["json"]
        assert session_client.gets == []
        assert all(not client.deletes for client in _FakeAsyncClient.instances)
        assert message["json"]["model"] == {
            "providerID": "anthropic",
            "modelID": "claude-sonnet",
        }

    asyncio.run(run())


def test_run_prompt_omits_tools_field_without_tool_discovery(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        monkeypatch.setattr(
            "backend.opencode.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
        )

        assert lines == ["done"]
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        assert "tools" not in message["json"]
        assert session_client.gets == []

    asyncio.run(run())


def test_list_models_uses_project_directory_context(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        monkeypatch.setattr(
            "backend.opencode.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._ensure_started = AsyncMock()
        project = tmp_path / "project"
        config_workspace = tmp_path / "runtime"
        project.mkdir()
        config_workspace.mkdir()

        assert await manager.list_models(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=config_workspace,
        ) == []

        client = _FakeAsyncClient.instances[0]
        expected_params = {"directory": str(project)}
        expected_headers = {"x-opencode-directory": str(project)}
        assert client.gets[0] == {
            "path": "/provider",
            "params": expected_params,
            "headers": expected_headers,
        }
        assert client.gets[1] == {
            "path": "/config/providers",
            "params": expected_params,
            "headers": expected_headers,
        }

    asyncio.run(run())


def test_run_prompt_streams_session_events_without_tool_result_body(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.text.delta","properties":{"sessionID":"other","delta":"ignore"}}',
            "",
            'data: {"type":"session.next.text.delta","properties":{"sessionID":"session-1","delta":"middle output\\n"}}',
            "",
            'data: {"type":"session.next.tool.called","properties":{"sessionID":"session-1","callID":"call-1","tool":"read","input":{"filePath":"src/main.c"}}}',
            "",
            'data: {"type":"session.next.tool.success","properties":{"sessionID":"session-1","callID":"call-1","content":[{"type":"text","text":"secret source body"}]}}',
            "",
        ]
        monkeypatch.setattr(
            "backend.opencode.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_line=output.append,
        )

        assert lines == ["done"]
        logged = "\n".join(output)
        assert "middle output" in logged
        assert "name=read" in logged
        assert "src/main.c" in logged
        assert "text_chars=18" in logged
        assert "secret source body" not in logged
        assert "ignore" not in logged
        assert "done" not in logged

    asyncio.run(run())


def test_serve_port_defaults_to_fixed_port(monkeypatch) -> None:
    monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)

    assert _serve_port() == 4096


def test_serve_port_accepts_env_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENCODE_SERVE_PORT", "4100")

    assert _serve_port() == 4100


def test_start_locked_uses_fixed_port_and_writes_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 12345

            def poll(self):
                return None

        commands: list[list[str]] = []
        envs: list[dict[str, str]] = []
        marker_path = tmp_path / "serve-marker.json"
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: False)

        def fake_popen(cmd, **kwargs):
            commands.append(cmd)
            envs.append(kwargs["env"])
            return FakeProc()

        monkeypatch.setattr("backend.opencode.serve_client.subprocess.Popen", fake_popen)

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="abc123",
            config_content='{"mcp": {}}',
        ))

        assert commands[0] == [
            "/bin/opencode",
            "serve",
            "--hostname",
            "127.0.0.1",
            "--port",
            "4096",
        ]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 12345
        assert marker["port"] == 4096
        assert marker["tool"] == "opencode"
        assert marker["config_hash"] == "abc123"
        assert envs[0]["OPENCODE_CONFIG_CONTENT"] == '{"mcp": {}}'

    asyncio.run(run())


def test_start_locked_stops_previous_agent_owned_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 22222

            def poll(self):
                return None

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "pid": 11111,
                "port": 4096,
                "tool": "opencode",
                "executable": "opencode",
            }),
            encoding="utf-8",
        )
        terminated: list[int] = []
        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._pid_is_running", lambda pid: pid == 11111)
        monkeypatch.setattr("backend.opencode.serve_client._marker_matches_serve_process", lambda marker: True)
        monkeypatch.setattr("backend.opencode.serve_client._terminate_pid", lambda pid: terminated.append(pid))
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("backend.opencode.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("backend.opencode.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [11111]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 22222

    asyncio.run(run())


def test_start_locked_refuses_unowned_port(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(tmp_path / "missing-marker.json"))
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: True)

        manager = OpenCodeServeManager()

        with pytest.raises(RuntimeError, match="already in use"):
            await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

    asyncio.run(run())


def test_dirty_config_does_not_restart_same_serve_process() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = OpenCodeServeKey(tool="opencode", executable="opencode")
        manager._dirty = True
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()

        await manager._ensure_started_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._port == 12345
        assert manager._dirty is False

    asyncio.run(run())


def test_config_hash_change_restarts_after_active_sessions_drain() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="old",
        )
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()

        await manager._ensure_started_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="new",
            config_content='{"mcp": {}}',
        ))

        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once()

    asyncio.run(run())
