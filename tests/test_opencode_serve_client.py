import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

from backend.opencode.serve_client import OpenCodeServeKey, OpenCodeServeManager, _extract_tool_ids


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
    tool_ids_response = _FakeResponse([])
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
        if path == "/experimental/tool/ids":
            return self.tool_ids_response
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


def test_extract_tool_ids_accepts_serve_response_shapes() -> None:
    assert _extract_tool_ids(["read", {"id": "grep"}, {"name": "deephole_view"}]) == [
        "read",
        "grep",
        "deephole_view",
    ]
    assert _extract_tool_ids({"ids": ["read", "read", "grep"]}) == ["read", "grep"]
    assert _extract_tool_ids({"read": True, "write": False, "grep": True}) == ["read", "grep"]


def test_run_prompt_sends_all_discovered_tools(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids_response = _FakeResponse([
            "read",
            "grep",
            "glob",
            "deephole-code_view_function_code",
        ])
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
        (config_workspace / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=config_workspace,
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
        assert manager._acquire_session.await_args.args[0] == OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
        )
        expected_params = {"directory": str(config_workspace)}
        assert session_client.posts[0]["params"] == expected_params
        assert session_client.gets[0]["params"] == expected_params
        assert message["params"] == expected_params
        cleanup_client = _FakeAsyncClient.instances[1]
        assert cleanup_client.deletes[0]["params"] == expected_params
        assert message["json"]["tools"] == {
            "read": True,
            "grep": True,
            "glob": True,
            "deephole-code_view_function_code": True,
        }
        assert message["json"]["model"] == {
            "providerID": "anthropic",
            "modelID": "claude-sonnet",
        }

    asyncio.run(run())


def test_run_prompt_continues_when_tool_discovery_fails(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids_response = _FakeResponse({}, error=RuntimeError("not supported"))
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

    asyncio.run(run())


def test_list_models_uses_config_workspace_as_request_directory(monkeypatch, tmp_path: Path) -> None:
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
        expected_params = {"directory": str(config_workspace)}
        assert client.gets[0] == {
            "path": "/provider",
            "params": expected_params,
        }
        assert client.gets[1] == {
            "path": "/config/providers",
            "params": expected_params,
        }

    asyncio.run(run())


def test_run_prompt_streams_session_events_without_tool_result_body(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.tool_ids_response = _FakeResponse([])
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
