import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from agent.task_agent.serve_client import (
    OpenCodeModelInfo,
    OpenCodeModelListResult,
    OpenCodePromptResult,
    OpenCodeServeKey,
    OpenCodeServeManager,
    _ServeEventState,
    _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
    _SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS,
    _EventChannelRuntime,
    _config_hash,
    _flush_event_state_periodically,
    _handle_serve_event,
    _next_event_reconnect_delay,
    _serve_context_headers,
    _serve_port,
    _serve_startup_env_debug,
    _serve_startup_shell_debug,
)


@pytest.fixture(autouse=True)
def _short_event_drain_for_tests(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent.task_agent.serve_client._SERVE_EVENT_DRAIN_TIMEOUT_SECONDS",
        0.05,
    )


class _FakeResponse:
    def __init__(
        self,
        data,
        *,
        error: Exception | None = None,
        status_code: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self._data = data
        self._error = error
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.json_calls = 0
        self.content = b"" if data is None else b"json"

    def json(self):
        self.json_calls += 1
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
        self._response = _FakeResponse(lines, content_type="text/event-stream")

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _FakeAsyncClient:
    instances: list["_FakeAsyncClient"] = []
    init_options: list[dict] = []
    event_lines: list[str] = []
    tool_ids: list[str] | Exception = ["read", "grep", "mcp__deephole-code__view_function_code"]
    message_text = "done"
    message_info: object | None = None

    def __init__(self, *args, **kwargs) -> None:
        self.init_options.append(dict(kwargs))
        self.posts: list[dict] = []
        self.gets: list[dict] = []
        self.deletes: list[dict] = []
        self.patches: list[dict] = []
        self.requests: list[dict] = []
        self.streams: list[dict] = []
        self.message_response: _FakeResponse | None = None

    async def __aenter__(self):
        self.instances.append(self)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, path: str, **kwargs):
        self.gets.append({"path": path, **kwargs})
        if path == "/experimental/tool/ids":
            if isinstance(self.tool_ids, Exception):
                return _FakeResponse([], error=self.tool_ids)
            return _FakeResponse(self.tool_ids)
        return _FakeResponse({})

    async def post(self, path: str, **kwargs):
        self.posts.append({"path": path, **kwargs})
        if path == "/session":
            return _FakeResponse({"id": "session-1"})
        if path.startswith("/session/") and path.endswith("/message"):
            await asyncio.sleep(0)
            data = {"parts": [{"type": "text", "text": self.message_text}]}
            if self.message_info is not None:
                data["info"] = self.message_info
            self.message_response = _FakeResponse(data)
            return self.message_response
        return _FakeResponse({})

    async def patch(self, path: str, **kwargs):
        self.patches.append({"path": path, **kwargs})
        return _FakeResponse({"id": path.rsplit("/", 1)[-1]})

    async def request(self, method: str, path: str, **kwargs):
        self.requests.append({"method": method, "path": path, **kwargs})
        if method == "GET" and path.endswith("/message"):
            return _FakeResponse([{"info": {"role": "assistant"}, "parts": []}])
        if method == "GET":
            return _FakeResponse({"id": path.rsplit("/", 1)[-1]})
        return _FakeResponse(True)

    async def delete(self, path: str, **kwargs):
        self.deletes.append({"path": path, **kwargs})
        return _FakeResponse(True)

    def stream(self, method: str, path: str, **kwargs):
        self.streams.append({"method": method, "path": path, **kwargs})
        lines = list(self.event_lines)
        if path == "/global/event":
            lines = [
                'data: {"payload":{"type":"server.connected","properties":{}}}',
                "",
                *lines,
            ]
        return _FakeStreamContext(lines)


class _FakeModelAsyncClient:
    instances: list["_FakeModelAsyncClient"] = []
    responses: dict[str, object] = {}

    def __init__(self, *args, **kwargs) -> None:
        self.gets: list[dict] = []

    async def __aenter__(self):
        self.instances.append(self)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, path: str, **kwargs):
        self.gets.append({"path": path, **kwargs})
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return _FakeResponse(response)


class _HangingMessageAsyncClient:
    instances: list["_HangingMessageAsyncClient"] = []
    hang_messages = True

    def __init__(self, *args, **kwargs) -> None:
        self.posts: list[str] = []
        self.message_started = asyncio.Event()
        self.message_cancelled = False

    async def __aenter__(self):
        self.instances.append(self)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def get(self, path: str, **kwargs):
        if path == "/experimental/tool/ids":
            return _FakeResponse(["read"])
        return _FakeResponse({})

    async def post(self, path: str, **kwargs):
        self.posts.append(path)
        if path == "/session":
            return _FakeResponse({"id": "session-hanging"})
        if path.endswith("/abort"):
            return _FakeResponse(True)
        if path.endswith("/message"):
            self.message_started.set()
            if self.hang_messages:
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    self.message_cancelled = True
                    raise
            return _FakeResponse({
                "info": {
                    "id": "msg-recovered",
                    "providerID": "provider",
                    "modelID": "model",
                },
                "parts": [{"type": "text", "text": "recovered"}],
            })
        return _FakeResponse({})


def test_run_prompt_uses_project_directory_and_default_tools(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.init_options = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read", "grep", "mcp__deephole-code__view_function_code"]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
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
            env_overrides={"HTTPS_PROXY": "http://127.0.0.1:3131"},
        )

        assert lines == ["done"]
        sessions: list[str] = []
        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=config_workspace,
            config_content=config_content,
            prompt="hello",
            model="",
            timeout=30,
            on_session_id=sessions.append,
            env_overrides={"HTTPS_PROXY": "http://127.0.0.1:3131"},
        )
        assert sessions == ["session-1"]
        assert manager.ensure_managed_mcp.await_count == 2
        assert all(
            awaited.args == (project,)
            for awaited in manager.ensure_managed_mcp.await_args_list
        )
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        expected_hash = _config_hash(config_content)
        expected_env_overrides = (("HTTPS_PROXY", "http://127.0.0.1:3131"),)
        expected_env_hash = hashlib.sha256(
            json.dumps(expected_env_overrides, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        assert manager._acquire_session.await_args.args[0] == OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            env_hash=expected_env_hash,
            config_hash=expected_hash,
            env_overrides=expected_env_overrides,
        )
        assert manager._acquire_session.await_args.kwargs["startup_cwd"] == config_workspace
        expected_params = {"directory": str(project)}
        expected_headers = {"x-opencode-directory": str(project)}
        assert session_client.posts[0]["path"] == "/session"
        assert session_client.posts[0]["params"] == expected_params
        assert session_client.posts[0]["headers"] == expected_headers
        assert message["params"] == expected_params
        assert message["headers"] == expected_headers
        assert message["json"]["agent"] == "build"
        assert message["json"]["tools"] == {
            "read": True,
            "grep": True,
            "mcp__deephole-code__view_function_code": True,
        }
        assert session_client.gets == [{
            "path": "/experimental/tool/ids",
            "params": expected_params,
            "headers": expected_headers,
        }]
        assert all(not client.deletes for client in _FakeAsyncClient.instances)
        assert _FakeAsyncClient.init_options
        assert all(options.get("trust_env") is False for options in _FakeAsyncClient.init_options)
        assert message["json"]["model"] == {
            "providerID": "anthropic",
            "modelID": "claude-sonnet",
        }

    asyncio.run(run())


@pytest.mark.parametrize("serve_mode", ["started", "restarted", "reused"])
def test_run_prompt_emits_debug_serve_status(
    monkeypatch,
    tmp_path: Path,
    serve_mode: str,
) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 24680

        _FakeAsyncClient.instances = []
        _FakeAsyncClient.init_options = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read"]
        _FakeAsyncClient.message_info = None
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        monkeypatch.setenv("OPENCODE_SERVE_PORT", "12345")

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._proc = FakeProc()
        manager._acquire_session = AsyncMock(return_value=serve_mode)
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="provider/model",
            timeout=30,
            on_line=output.append,
            show_serve_status=True,
        )

        assert output[0] == "[opencode serve] preparing executable=opencode port=12345"
        assert output[1] == (
            f"[opencode serve] ready mode={serve_mode} "
            "url=http://127.0.0.1:12345 pid=24680"
        )
        assert any("[opencode serve] session=session-1" in line for line in output)

    asyncio.run(run())


def test_run_prompt_emits_debug_serve_startup_failure(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._acquire_session = AsyncMock(
            side_effect=RuntimeError(
                "OpenCode serve did not become healthy\n\n"
                "OpenCode serve startup output:\nprovider failed to load"
            )
        )
        output: list[str] = []

        with pytest.raises(RuntimeError, match="did not become healthy"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="hello",
                model="provider/model",
                timeout=30,
                on_line=output.append,
                show_serve_status=True,
            )

        assert output[0].startswith("[opencode serve] preparing")
        assert output[1].startswith("[opencode serve] startup failed:")
        assert "provider failed to load" in output[1]

    asyncio.run(run())


def test_run_prompt_timeout_aborts_and_reaps_request_before_reuse(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _HangingMessageAsyncClient.instances = []
        _HangingMessageAsyncClient.hang_messages = True
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _HangingMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        manager._acquire_session = AsyncMock(side_effect=acquire)

        with pytest.raises(asyncio.TimeoutError):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="hang",
                model="provider/model",
                timeout=0.01,
            )

        first_client = _HangingMessageAsyncClient.instances[0]
        assert "/session/session-hanging/abort" in first_client.posts
        assert first_client.message_cancelled is True
        assert manager._active_sessions == 0
        assert manager._event_states == {}

        _HangingMessageAsyncClient.hang_messages = False
        result = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=tmp_path,
            prompt="retry",
            model="provider/model",
            timeout=1,
            return_details=True,
        )

        assert isinstance(result, OpenCodePromptResult)
        assert result.text == "recovered"
        assert manager._active_sessions == 0

    asyncio.run(run())


def test_run_prompt_caller_cancellation_aborts_and_reaps_request(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _HangingMessageAsyncClient.instances = []
        _HangingMessageAsyncClient.hang_messages = True
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _HangingMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        manager._acquire_session = AsyncMock(side_effect=acquire)
        caller = asyncio.create_task(manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=tmp_path,
            prompt="cancel",
            model="provider/model",
            timeout=30,
        ))
        while not _HangingMessageAsyncClient.instances:
            await asyncio.sleep(0)
        client = _HangingMessageAsyncClient.instances[0]
        await client.message_started.wait()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller

        assert "/session/session-hanging/abort" in client.posts
        assert client.message_cancelled is True
        assert manager._active_sessions == 0
        assert manager._event_states == {}

    asyncio.run(run())


def test_run_prompt_continues_session_without_native_format_and_with_selected_mcp_tools(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = [
            "read",
            "grep",
            "mcp__deephole-code__view_function_code",
            "mcp__deephole-code__view_struct_code",
        ]
        _FakeAsyncClient.message_info = {
            "id": "msg_plain_text",
            "providerID": "provider",
            "modelID": "actual",
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        permissions = [{"permission": "edit", "pattern": "*", "action": "deny"}]

        details = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="continue",
            model="provider/requested",
            timeout=30,
            session_id="session-existing",
            mcp_tools=["view_function_code"],
            system_prompt="selected skill",
            permissions=permissions,
            return_details=True,
        )

        assert isinstance(details, OpenCodePromptResult)
        assert details.session_id == "session-existing"
        assert details.message_id == "msg_plain_text"
        assert details.text == "done"
        assert details.model == "provider/actual"
        client = _FakeAsyncClient.instances[0]
        assert all(item["path"] != "/session" for item in client.posts)
        assert client.patches == [{
            "path": "/session/session-existing",
            "params": {"directory": str(project)},
            "headers": {"x-opencode-directory": str(project)},
            "json": {"permission": permissions},
        }]
        message = next(item for item in client.posts if item["path"].endswith("/message"))
        assert "format" not in message["json"]
        assert message["json"]["system"] == "selected skill"
        assert message["json"]["tools"] == {
            "mcp__deephole-code__view_function_code": True,
            "mcp__deephole-code__view_struct_code": False,
        }

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


def test_session_management_methods_use_durable_session_routes(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        directory = tmp_path / "project"
        directory.mkdir()
        runtime = {
            "tool": "opencode",
            "executable": "opencode",
            "directory": directory,
        }
        assert (await manager.get_session("ses_1", **runtime))["id"] == "ses_1"
        assert len(await manager.get_session_messages("ses_1", **runtime)) == 1
        assert await manager.abort_session("ses_1", **runtime) is True
        assert await manager.delete_session("ses_1", **runtime) is True
        requests = [item for client in _FakeAsyncClient.instances for item in client.requests]
        assert [(item["method"], item["path"]) for item in requests] == [
            ("GET", "/session/ses_1"),
            ("GET", "/session/ses_1/message"),
            ("POST", "/session/ses_1/abort"),
            ("DELETE", "/session/ses_1"),
        ]
        assert all(item["params"] == {"directory": str(directory)} for item in requests)

    asyncio.run(run())


def test_run_prompt_reports_actual_response_model_for_default_request(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = []
        _FakeAsyncClient.message_info = {
            "providerID": "anthropic",
            "modelID": "claude-sonnet",
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        response_models: list[str] = []
        callback_awaited = False

        async def on_response_model(model: str) -> None:
            nonlocal callback_awaited
            response_models.append(model)
            callback_awaited = True

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_response_model=on_response_model,
        )

        assert lines == ["done"]
        assert response_models == ["anthropic/claude-sonnet"]
        assert callback_awaited is True
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        assert "model" not in message["json"]
        assert session_client.message_response is not None
        assert session_client.message_response.json_calls == 1

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


@pytest.mark.parametrize(
    "message_info",
    [None, {"providerID": "anthropic", "modelID": 42}],
)
def test_run_prompt_ignores_missing_or_invalid_response_model_info(
    monkeypatch,
    tmp_path: Path,
    message_info: object | None,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = []
        _FakeAsyncClient.message_info = message_info
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        response_models: list[str] = []

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_response_model=response_models.append,
        )

        assert lines == ["done"]
        assert response_models == []

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


def test_serve_context_headers_encode_non_ascii_directory(tmp_path: Path) -> None:
    directory = tmp_path / "源码 项目"

    headers = _serve_context_headers(directory)

    value = headers["x-opencode-directory"]
    assert value != str(directory)
    assert value.isascii()
    assert "%E6%BA%90%E7%A0%81" in value
    assert httpx.Headers(headers)["x-opencode-directory"] == value


def test_run_prompt_omits_tools_field_when_tool_discovery_fails(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = RuntimeError("tool endpoint unavailable")
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
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
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        assert "tools" not in message["json"]
        discovery_gets = [
            item for item in session_client.gets
            if item["path"] == "/experimental/tool/ids"
        ]
        assert discovery_gets == [{
            "path": "/experimental/tool/ids",
            "params": {"directory": str(project)},
            "headers": {"x-opencode-directory": str(project)},
        }]
        assert "tool discovery unavailable" in "\n".join(output)

    asyncio.run(run())


def test_run_prompt_logs_discovered_mcp_tool_names(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = [
            "read",
            "mcp__deephole-code__view_function_code",
            "mcp__deephole-code__view_struct_code",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        try:
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=project,
                prompt="hello",
                model="",
                timeout=30,
                on_line=output.append,
            )
        finally:
            _FakeAsyncClient.tool_ids = [
                "read",
                "grep",
                "mcp__deephole-code__view_function_code",
            ]

        logged = "\n".join(output)
        assert "tools=3 mcp_tools=2" in logged
        assert "mcp__deephole-code__view_function_code" in logged
        assert "mcp__deephole-code__view_struct_code" in logged

    asyncio.run(run())


def test_list_models_uses_project_directory_context(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/provider": {"all": [], "connected": []},
            "/config/providers": {"providers": []},
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeModelAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_model_listing = AsyncMock(return_value=False)
        manager._release_model_listing = AsyncMock()
        project = tmp_path / "project"
        config_workspace = tmp_path / "runtime"
        project.mkdir()
        config_workspace.mkdir()

        result = await manager.list_models(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=config_workspace,
        )
        assert result == OpenCodeModelListResult(models=[])

        client = _FakeModelAsyncClient.instances[0]
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
            "timeout": _SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS,
        }
        assert manager._acquire_model_listing.await_args.kwargs["startup_cwd"] == config_workspace

    asyncio.run(run())


def test_fetch_models_uses_complete_provider_response_without_config_fallback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/provider": {
                "all": [
                    {
                        "id": "anthropic",
                        "models": {
                            "claude-sonnet": {"name": "Claude Sonnet"},
                        },
                    },
                    {
                        "id": "openai",
                        "models": {
                            "gpt-5": {"name": "GPT-5"},
                        },
                    },
                ],
                "connected": ["anthropic", "openai"],
            },
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeModelAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345

        models = await manager._fetch_models(tmp_path)

        assert models == [
            OpenCodeModelInfo(
                id="anthropic/claude-sonnet",
                provider_id="anthropic",
                model_id="claude-sonnet",
                name="Claude Sonnet",
            ),
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
                name="GPT-5",
            ),
        ]
        assert [request["path"] for request in _FakeModelAsyncClient.instances[0].gets] == [
            "/provider",
        ]

    asyncio.run(run())


def test_fetch_models_falls_back_when_provider_request_fails(monkeypatch) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/provider": RuntimeError("provider unavailable"),
            "/config/providers": {
                "providers": [
                    {
                        "id": "openai",
                        "models": {"gpt-5": {"name": "GPT-5"}},
                    },
                ],
            },
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeModelAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345

        models = await manager._fetch_models(None)

        assert [model.id for model in models] == ["openai/gpt-5"]
        assert [request["path"] for request in _FakeModelAsyncClient.instances[0].gets] == [
            "/provider",
            "/config/providers",
        ]

    asyncio.run(run())


def test_fetch_models_falls_back_for_missing_connected_provider(monkeypatch) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/provider": {
                "all": [
                    {
                        "id": "anthropic",
                        "models": {"claude-sonnet": {"name": "Claude Sonnet"}},
                    },
                ],
                "connected": ["anthropic", "openai"],
            },
            "/config/providers": {
                "providers": [
                    {
                        "id": "openai",
                        "models": {"gpt-5": {"name": "GPT-5"}},
                    },
                ],
            },
        }
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeModelAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345

        models = await manager._fetch_models(None)

        assert [model.id for model in models] == [
            "anthropic/claude-sonnet",
            "openai/gpt-5",
        ]
        assert [request["path"] for request in _FakeModelAsyncClient.instances[0].gets] == [
            "/provider",
            "/config/providers",
        ]

    asyncio.run(run())


def test_list_models_caches_success_and_refresh_bypasses_cache() -> None:
    async def run() -> None:
        first_models = [
            OpenCodeModelInfo(
                id="anthropic/claude-sonnet",
                provider_id="anthropic",
                model_id="claude-sonnet",
            ),
        ]
        refreshed_models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]
        manager = OpenCodeServeManager()
        manager._acquire_model_listing = AsyncMock(return_value=False)
        manager._release_model_listing = AsyncMock()
        manager._fetch_models = AsyncMock(side_effect=[first_models, refreshed_models])

        first = await manager.list_models(tool="opencode", executable="opencode")
        cached = await manager.list_models(tool="opencode", executable="opencode")
        refreshed = await manager.list_models(
            tool="opencode",
            executable="opencode",
            refresh=True,
        )

        assert first == OpenCodeModelListResult(models=first_models)
        assert cached == OpenCodeModelListResult(models=first_models)
        assert refreshed == OpenCodeModelListResult(models=refreshed_models)
        assert manager._fetch_models.await_count == 2
        assert manager._acquire_model_listing.await_count == 2
        assert all(
            "force_reload" not in acquisition.kwargs
            for acquisition in manager._acquire_model_listing.await_args_list
        )

    asyncio.run(run())


def test_list_models_coalesces_same_key_concurrent_requests() -> None:
    async def run() -> None:
        fetch_started = asyncio.Event()
        allow_fetch = asyncio.Event()
        fetch_count = 0
        models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]

        async def fetch_models(directory: Path | None):
            nonlocal fetch_count
            fetch_count += 1
            fetch_started.set()
            await allow_fetch.wait()
            return models

        manager = OpenCodeServeManager()
        manager._acquire_model_listing = AsyncMock(return_value=False)
        manager._release_model_listing = AsyncMock()
        manager._fetch_models = fetch_models

        first_task = asyncio.create_task(
            manager.list_models(tool="opencode", executable="opencode")
        )
        await fetch_started.wait()
        second_task = asyncio.create_task(
            manager.list_models(tool="opencode", executable="opencode")
        )
        await asyncio.sleep(0)
        allow_fetch.set()
        first, second = await asyncio.gather(first_task, second_task)

        assert first == OpenCodeModelListResult(models=models)
        assert second == OpenCodeModelListResult(models=models)
        assert fetch_count == 1
        assert manager._acquire_model_listing.await_count == 1
        assert manager._release_model_listing.await_count == 1

    asyncio.run(run())


def test_run_prompt_streams_session_events_without_tool_result_body(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.text.delta","properties":{"sessionID":"other","delta":"ignore"}}',
            "",
            'data: {"type":"session.next.text.delta","properties":{"sessionID":"session-1","delta":"middle output\\n"}}',
            "",
            'data: {"type":"session.next.reasoning.delta","properties":{"sessionID":"session-1","delta":"reasoning\\nstep\\n"}}',
            "",
            'data: {"type":"session.next.tool.called","properties":{"sessionID":"session-1","callID":"call-1","tool":"read","input":{"filePath":"src/main.c"}}}',
            "",
            'data: {"type":"session.next.tool.success","properties":{"sessionID":"session-1","callID":"call-1","content":[{"type":"text","text":"secret source body"}]}}',
            "",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
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
        assert all("\n" not in line for line in output)
        assert "[opencode serve llm text] middle output" in logged
        assert "[opencode serve llm reasoning] reasoning" in logged
        assert "[opencode serve llm reasoning] step" in logged
        assert "middle output" in logged
        assert "tool_call" in logged
        assert "tool_result" in logged
        assert "status=success" in logged
        assert "session=session-1" in logged
        assert "name=read" in logged
        assert "src/main.c" in logged
        assert "text_chars=18" in logged
        assert "secret source body" not in logged
        assert "ignore" not in logged
        assert "[opencode serve llm text final] done" in logged

    asyncio.run(run())


def test_run_prompt_compacts_final_text_when_sse_has_no_text(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        monkeypatch.setattr(_FakeAsyncClient, "tool_ids", [])
        monkeypatch.setattr(_FakeAsyncClient, "message_text", "first line\nsecond line")
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
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

        assert lines == ["first line\nsecond line"]
        assert "[opencode serve llm text] first line" in output
        assert "[opencode serve llm text] second line" in output
        assert all("\n" not in line for line in output)

    asyncio.run(run())


def test_run_prompt_streams_sync_session_events(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"sync","name":"session.next.text.delta.1","data":{"sessionID":"session-1","delta":"sync text\\n"}}',
            "",
            'data: {"type":"sync","name":"session.next.reasoning.delta.1","data":{"sessionID":"session-1","delta":"sync reasoning\\n"}}',
            "",
            'data: {"type":"sync","name":"session.next.tool.called.1","data":{"sessionID":"session-1","callID":"call-2","tool":"read","input":{"filePath":"src/win.c"}}}',
            "",
            'data: {"type":"sync","name":"session.next.tool.success.1","data":{"sessionID":"session-1","callID":"call-2","content":[{"type":"text","text":"hidden sync tool body"}]}}',
            "",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
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
        assert "[opencode serve llm text] sync text" in logged
        assert "[opencode serve llm reasoning] sync reasoning" in logged
        assert "tool_call" in logged
        assert "tool_result" in logged
        assert "src/win.c" in logged
        assert "text_chars=21" in logged
        assert "hidden sync tool body" not in logged
        assert "[opencode serve llm text final] done" in logged

    asyncio.run(run())


def test_run_prompt_uses_ended_text_when_no_delta(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.text.ended","properties":{"sessionID":"session-1","text":"ended only\\ntext"}}',
            "",
            'data: {"type":"sync","name":"session.next.reasoning.ended.1","data":{"sessionID":"session-1","text":"ended reasoning\\ntext"}}',
            "",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_line=output.append,
        )

        assert "[opencode serve llm text] ended only" in output
        assert "[opencode serve llm text] text" in output
        assert "[opencode serve llm reasoning] ended reasoning" in output
        assert "[opencode serve llm reasoning] text" in output
        assert all("\n" not in line for line in output)

    asyncio.run(run())


def test_message_part_delta_survives_non_text_session_next_event(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.step.started","properties":{"sessionID":"session-1"}}',
            "",
            'data: {"type":"message.part.delta","properties":{"sessionID":"session-1","field":"content","delta":"fallback text\\n"}}',
            "",
            'data: {"type":"message.part.delta","properties":{"sessionID":"session-1","field":"reasoning","delta":"fallback reasoning\\n"}}',
            "",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_line=output.append,
        )

        assert "[opencode serve llm text] fallback text" in output
        assert "[opencode serve llm reasoning] fallback reasoning" in output
        assert all("\n" not in line for line in output)

    asyncio.run(run())


def test_final_text_prints_when_event_stream_only_has_reasoning(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.reasoning.delta","properties":{"sessionID":"session-1","delta":"only reasoning\\n"}}',
            "",
        ]
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
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
        assert "[opencode serve llm reasoning] only reasoning" in output
        assert "[opencode serve llm text] done" in output

    asyncio.run(run())


def test_run_prompt_reconciles_only_missing_sse_text_tail(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = [
            'data: {"type":"session.next.text.delta","properties":{"sessionID":"session-1","delta":"prefix"}}',
            "",
        ]
        monkeypatch.setattr(_FakeAsyncClient, "message_text", "prefix-tail")
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        output: list[str] = []

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="hello",
            model="",
            timeout=30,
            on_line=output.append,
        )

        chunks = [
            line.removeprefix("[opencode serve llm text] ")
            for line in output
            if line.startswith("[opencode serve llm text] ")
        ]
        assert "".join(chunks) == "prefix-tail"
        assert chunks.count("prefix") == 1

    asyncio.run(run())


def test_run_prompt_final_fallback_does_not_log_tool_output_body(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class ToolBodyClient(_FakeAsyncClient):
        event_lines = []
        tool_ids = []

        async def post(self, path: str, **kwargs):
            self.posts.append({"path": path, **kwargs})
            if path == "/session":
                return _FakeResponse({"id": "session-1"})
            if path == "/session/session-1/message":
                await asyncio.sleep(0)
                return _FakeResponse({
                    "info": {
                        "id": "message-ai",
                        "sessionID": "session-1",
                        "role": "assistant",
                    },
                    "parts": [
                        {
                            "id": "part-tool",
                            "sessionID": "session-1",
                            "messageID": "message-ai",
                            "type": "tool",
                            "callID": "call-1",
                            "tool": "mcp__deephole-code__view_function_code",
                            "content": [
                                {"type": "text", "text": "secret nested tool content"},
                            ],
                            "state": {
                                "status": "completed",
                                "input": {"function_name": "target"},
                                "output": "secret final tool body",
                                "title": "secret tool title",
                                "time": {"start": 1, "end": 2},
                            },
                        },
                        {
                            "id": "part-text",
                            "sessionID": "session-1",
                            "messageID": "message-ai",
                            "type": "text",
                            "text": "safe final answer",
                        },
                    ],
                })
            return _FakeResponse({})

    async def run() -> None:
        monkeypatch.setattr(
            "agent.task_agent.serve_client.httpx.AsyncClient",
            ToolBodyClient,
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

        logged = "\n".join(output)
        assert "safe final answer" in logged
        assert "secret final tool body" not in logged
        assert "secret tool title" not in logged
        assert "secret nested tool content" not in logged
        assert "secret final tool body" in lines
        assert "source=mcp" in logged
        assert "serve tool_call" in logged
        assert "serve tool_result" in logged
        assert "output_chars=22" in logged

    asyncio.run(run())


def test_open_source_message_parts_stream_text_reasoning_and_ignore_user_prompt() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    _handle_serve_event({
        "type": "message.updated",
        "properties": {
            "sessionID": "session-1",
            "info": {"id": "message-user", "sessionID": "session-1", "role": "user"},
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "part": {
                "id": "part-user",
                "sessionID": "session-1",
                "messageID": "message-user",
                "type": "text",
                "text": "secret prompt that must not be logged",
            },
            "time": 1,
        },
    }, state)
    _handle_serve_event({
        "type": "message.updated",
        "properties": {
            "sessionID": "session-1",
            "info": {"id": "message-ai", "sessionID": "session-1", "role": "assistant"},
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "sessionID": "session-1",
            "part": {
                "id": "part-text",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "text",
                "text": "",
            },
            "time": 2,
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.delta",
        "properties": {
            "sessionID": "session-1",
            "messageID": "message-ai",
            "partID": "part-text",
            "field": "text",
            "delta": "open source middle ",
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.delta",
        "properties": {
            "sessionID": "session-1",
            "messageID": "message-ai",
            "partID": "part-text",
            "field": "text",
            "delta": "output\n",
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "sessionID": "session-1",
            "part": {
                "id": "part-text",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "text",
                "text": "open source middle output\n",
            },
            "time": 3,
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "sessionID": "session-1",
            "part": {
                "id": "part-reasoning",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "reasoning",
                "text": "",
                "time": {"start": 1},
            },
            "time": 4,
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.delta",
        "properties": {
            "sessionID": "session-1",
            "messageID": "message-ai",
            "partID": "part-reasoning",
            "field": "text",
            "delta": "reasoning step\n",
        },
    }, state)

    logged = "\n".join(output)
    assert output.count("[opencode serve llm text] open source middle output") == 1
    assert "[opencode serve llm reasoning] reasoning step" in output
    assert "secret prompt" not in logged


def test_sync_message_part_snapshot_uses_nested_session_and_flushes_once() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    event = {
        "type": "sync",
        "name": "message.part.updated.1",
        "data": {
            "part": {
                "id": "part-text",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "text",
                "text": "snapshot without newline",
            },
            "time": 1,
        },
    }
    _handle_serve_event(event, state)
    _handle_serve_event(event, state)

    assert output == []
    state.flush()
    assert output == []
    _handle_serve_event({
        "type": "sync",
        "name": "message.updated.1",
        "data": {
            "info": {
                "id": "message-ai",
                "sessionID": "session-1",
                "role": "assistant",
            },
        },
    }, state)
    state.flush()
    assert output == ["[opencode serve llm text] snapshot without newline"]


def test_text_part_waits_for_message_role_before_printing() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    def part_event(part_id: str, message_id: str, text: str) -> dict:
        return {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": part_id,
                    "sessionID": "session-1",
                    "messageID": message_id,
                    "type": "text",
                    "text": text,
                },
            },
        }

    _handle_serve_event(part_event("part-user", "message-user", "TOP SECRET PROMPT"), state)
    state.flush()
    assert output == []
    _handle_serve_event({
        "type": "message.updated",
        "properties": {
            "info": {
                "id": "message-user",
                "sessionID": "session-1",
                "role": "user",
            },
        },
    }, state)
    state.flush()
    assert output == []

    _handle_serve_event(part_event("part-ai", "message-ai", "assistant answer"), state)
    state.flush()
    assert output == []
    _handle_serve_event({
        "type": "message.updated",
        "properties": {
            "info": {
                "id": "message-ai",
                "sessionID": "session-1",
                "role": "assistant",
            },
        },
    }, state)
    state.flush()

    assert output == ["[opencode serve llm text] assistant answer"]
    assert "TOP SECRET PROMPT" not in "\n".join(output)


def test_assistant_message_error_is_visible_and_deduplicated() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)
    error = {
        "name": "APIError",
        "data": {
            "message": "provider failed",
            "responseBody": "secret provider response body",
        },
    }

    _handle_serve_event({
        "id": "message-error-1",
        "type": "message.updated",
        "properties": {
            "sessionID": "session-1",
            "info": {
                "id": "message-ai",
                "sessionID": "session-1",
                "role": "assistant",
                "error": error,
            },
        },
    }, state)
    _handle_serve_event({
        "id": "session-error-1",
        "type": "session.error",
        "properties": {"sessionID": "session-1", "error": error},
    }, state)

    error_lines = [line for line in output if "status=error" in line]
    assert error_lines == [
        "[opencode serve session] session=session-1 status=error "
        "error=APIError: provider failed"
    ]
    assert "secret provider response body" not in "\n".join(output)
    assert state.session_terminal is True


def test_replayed_event_id_and_mixed_protocol_text_are_deduplicated() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)
    _handle_serve_event({
        "type": "message.updated",
        "properties": {
            "sessionID": "session-1",
            "info": {
                "id": "message-ai",
                "sessionID": "session-1",
                "role": "assistant",
            },
        },
    }, state)
    delta_event = {
        "id": "event-1",
        "type": "message.part.delta",
        "properties": {
            "sessionID": "session-1",
            "messageID": "message-ai",
            "partID": "part-text",
            "field": "text",
            "delta": "same text\n",
        },
    }
    _handle_serve_event(delta_event, state)
    _handle_serve_event(delta_event, state)
    _handle_serve_event({
        "type": "session.next.text.delta",
        "properties": {"sessionID": "session-1", "delta": "same text\n"},
    }, state)
    state.flush()

    assert output == ["[opencode serve llm text] same text"]


def test_incompatible_final_text_emits_complete_final_snapshot() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    state.append_next_delta("text", "prefix-")
    state.append_next_delta("text", "suffix")
    state.flush()
    state.reconcile_text("text", "prefix-MISSING-suffix")
    state.reconcile_text("text", "prefix-MISSING-suffix")

    assert "[opencode serve llm text] prefix-suffix" in output
    assert output.count(
        "[opencode serve llm text final] prefix-MISSING-suffix"
    ) == 1


def test_legacy_step_events_use_event_identity_for_multiple_steps() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    for event_id in ("step-event-1", "step-event-2"):
        event = {
            "id": event_id,
            "type": "session.next.step.started",
            "properties": {
                "sessionID": "session-1",
                "agent": "build",
                "model": {"id": "model", "providerID": "provider"},
            },
        }
        _handle_serve_event(event, state)
        _handle_serve_event(event, state)

    step_lines = [line for line in output if "serve step" in line]
    assert len(step_lines) == 2
    assert "id=step-event-1" in step_lines[0]
    assert "id=step-event-2" in step_lines[1]


def test_open_source_tool_parts_and_key_statuses_are_visible_without_tool_body() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)
    running_part = {
        "id": "part-tool",
        "sessionID": "session-1",
        "messageID": "message-ai",
        "type": "tool",
        "callID": "call-1",
        "tool": "mcp__deephole-code__view_function_code",
        "state": {
            "status": "running",
            "input": {"function_name": "target", "prompt": "secret tool prompt"},
            "time": {"start": 100},
        },
    }
    completed_part = {
        **running_part,
        "state": {
            "status": "completed",
            "input": {"function_name": "target"},
            "output": "secret source body",
            "title": "Read target",
            "metadata": {},
            "time": {"start": 100, "end": 140},
        },
    }
    pending_part = {
        **running_part,
        "state": {
            "status": "pending",
            "input": {"function_name": "target", "prompt": "secret tool prompt"},
            "raw": "pending call body",
        },
    }

    for part in (pending_part, running_part, running_part, completed_part, completed_part):
        _handle_serve_event({
            "type": "message.part.updated",
            "properties": {"sessionID": "session-1", "part": part, "time": 1},
        }, state)
    _handle_serve_event({
        "type": "session.next.tool.called",
        "properties": {
            "sessionID": "session-1",
            "callID": "call-1",
            "tool": "mcp__deephole-code__view_function_code",
            "input": {"function_name": "target"},
        },
    }, state)
    _handle_serve_event({
        "type": "session.next.tool.success",
        "properties": {
            "sessionID": "session-1",
            "callID": "call-1",
            "content": [{"type": "text", "text": "legacy duplicate body"}],
        },
    }, state)
    for status in ({"type": "busy"}, {"type": "busy"}, {"type": "retry", "attempt": 2, "message": "rate limited", "next": 10}, {"type": "idle"}):
        _handle_serve_event({
            "type": "session.status",
            "properties": {"sessionID": "session-1", "status": status},
        }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "sessionID": "session-1",
            "part": {
                "id": "step-start",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "step-start",
            },
            "time": 2,
        },
    }, state)
    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {
            "sessionID": "session-1",
            "part": {
                "id": "step-finish",
                "sessionID": "session-1",
                "messageID": "message-ai",
                "type": "step-finish",
                "reason": "stop",
                "cost": 0.1,
                "tokens": {"input": 1, "output": 2, "reasoning": 0, "cache": {"read": 0, "write": 0}},
            },
            "time": 3,
        },
    }, state)
    _handle_serve_event({
        "type": "session.error",
        "properties": {"sessionID": "session-1", "error": {"message": "provider failed"}},
    }, state)

    logged = "\n".join(output)
    assert logged.count("serve tool_call") == 1
    assert logged.count("serve tool_result") == 1
    assert "source=mcp" in logged
    assert "output_chars=18" in logged
    assert "duration_ms=40" in logged
    assert "secret source body" not in logged
    assert "pending call body" not in logged
    assert "secret tool prompt" not in logged
    assert '"prompt":"<redacted>"' in logged
    assert logged.count("status=busy") == 1
    assert "status=retry attempt=2 next=10 message=rate limited" in logged
    assert "status=idle" in logged
    assert "serve step" in logged
    assert "status=error error=provider failed" in logged


def test_no_newline_delta_is_flushed_periodically(monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            "agent.task_agent.serve_client._SERVE_EVENT_FLUSH_INTERVAL_SECONDS",
            0.01,
        )
        output: list[str] = []
        state = _ServeEventState("opencode", "session-1", output.append)
        _handle_serve_event({
            "type": "message.updated",
            "properties": {
                "sessionID": "session-1",
                "info": {
                    "id": "message-ai",
                    "sessionID": "session-1",
                    "role": "assistant",
                },
            },
        }, state)
        _handle_serve_event({
            "type": "message.part.delta",
            "properties": {
                "sessionID": "session-1",
                "messageID": "message-ai",
                "partID": "part-text",
                "field": "text",
                "delta": "visible before task completion",
            },
        }, state)
        task = asyncio.create_task(_flush_event_state_periodically(state))
        try:
            await asyncio.sleep(0.03)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert output == ["[opencode serve llm text] visible before task completion"]
        assert state.emitted_response_text is True

    asyncio.run(run())


def test_event_failure_logs_are_aggregated_and_recovery_is_single(monkeypatch) -> None:
    manager = OpenCodeServeManager()
    output: list[str] = []
    manager._event_states["session-1"] = _ServeEventState(
        "opencode",
        "session-1",
        output.append,
    )
    runtime = _EventChannelRuntime(
        key="global",
        path="/global/event",
        params={},
        headers={},
        connected_once=True,
    )
    clock = {"now": 100.0}
    monkeypatch.setattr(
        "agent.task_agent.serve_client.time.monotonic",
        lambda: clock["now"],
    )

    manager._note_event_channel_failure(
        runtime,
        error="closed",
        retry_in=1.0,
    )
    for now in (101.0, 110.0, 129.9):
        clock["now"] = now
        manager._note_event_channel_failure(
            runtime,
            error="closed again",
            retry_in=8.0,
        )
    clock["now"] = 130.0
    manager._note_event_channel_failure(
        runtime,
        error="still closed",
        retry_in=16.0,
    )
    clock["now"] = 132.0
    manager._note_event_channel_connected(runtime)

    event_lines = [line for line in output if "serve event" in line]
    assert len(event_lines) == 3
    assert "status=disconnected" in event_lines[0]
    assert "fallback=polling" in event_lines[0]
    assert "status=unavailable attempts=5" in event_lines[1]
    assert "status=reconnected downtime=32.0s attempts=5" in event_lines[2]
    assert all("status=connected" not in line for line in event_lines)


def test_event_reconnect_delay_is_exponential_and_capped() -> None:
    delay = 1.0
    values = []
    for _ in range(7):
        values.append(delay)
        delay = _next_event_reconnect_delay(delay)

    assert values == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]


def test_server_connected_then_immediate_eof_does_not_log_false_recovery(
    monkeypatch,
) -> None:
    async def run() -> None:
        class Response:
            status_code = 200
            headers = {"content-type": "text/event-stream"}

            def raise_for_status(self) -> None:
                return None

            async def aiter_lines(self):
                yield 'data: {"payload":{"type":"server.connected","properties":{}}}'
                yield ""

        class StreamContext:
            async def __aenter__(self):
                return Response()

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

        class Client:
            stream_calls = 0

            def __init__(self, *args, **kwargs) -> None:
                return None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            def stream(self, *args, **kwargs):
                type(self).stream_calls += 1
                return StreamContext()

        delays: list[float] = []

        async def fake_sleep(delay: float) -> None:
            delays.append(delay)
            if len(delays) >= 3:
                raise asyncio.CancelledError()

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.sleep", fake_sleep)
        manager = OpenCodeServeManager()
        manager._port = 12345
        output: list[str] = []
        manager._event_states["session-1"] = _ServeEventState(
            "opencode",
            "session-1",
            output.append,
        )
        runtime = _EventChannelRuntime(
            key="global",
            path="/global/event",
            params={},
            headers={},
        )

        with pytest.raises(asyncio.CancelledError):
            await manager._run_event_channel(runtime, is_global=True)

        event_lines = [line for line in output if "serve event" in line]
        assert len(event_lines) == 1
        assert "status=disconnected" in event_lines[0]
        assert "status=reconnected" not in event_lines[0]
        assert delays == [1.0, 2.0, 4.0]
        assert Client.stream_calls == 3

    asyncio.run(run())


def test_global_event_hub_is_shared_and_routes_wrapped_sessions(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        blocker = asyncio.Event()

        class Response:
            status_code = 200
            headers = {"content-type": "text/event-stream"}

            def raise_for_status(self) -> None:
                return None

            async def aiter_lines(self):
                yield 'data: {"payload":{"type":"server.connected","properties":{}}}'
                yield ""
                await blocker.wait()

        class StreamContext:
            async def __aenter__(self):
                return Response()

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

        class Client:
            stream_calls: list[tuple[str, dict]] = []
            init_options: list[dict] = []

            def __init__(self, *args, **kwargs) -> None:
                self.init_options.append(dict(kwargs))

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            def stream(self, method: str, path: str, **kwargs):
                self.stream_calls.append((path, kwargs))
                return StreamContext()

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", Client)
        manager = OpenCodeServeManager()
        manager._port = 12345
        directory = tmp_path / "project"
        directory.mkdir()
        output_a: list[str] = []
        output_b: list[str] = []
        state_a = _ServeEventState("opencode", "session-a", output_a.append)
        state_b = _ServeEventState("opencode", "session-b", output_b.append)

        try:
            await manager._register_event_state("session-a", directory, state_a)
            await manager._register_event_state("session-b", directory, state_b)
            assert len(Client.stream_calls) == 1
            assert Client.stream_calls[0][0] == "/global/event"
            assert Client.init_options[0]["trust_env"] is False
            assert Client.stream_calls[0][1]["headers"]["Accept"] == "text/event-stream"

            assert manager._dispatch_event({
                "directory": str(directory),
                "payload": {
                    "id": "event-a",
                    "type": "session.next.text.delta",
                    "properties": {"sessionID": "session-a", "delta": "alpha\n"},
                },
            })
            assert manager._dispatch_event({
                "directory": str(directory),
                "payload": {
                    "id": "event-b",
                    "type": "sync",
                    "name": "session.next.text.delta.1",
                    "seq": 1,
                    "data": {"sessionID": "session-b", "delta": "beta\n"},
                },
            })
            assert output_a == ["[opencode serve llm text] alpha"]
            assert output_b == ["[opencode serve llm text] beta"]
        finally:
            await manager._stop_event_hub()

    asyncio.run(run())


def test_global_event_unsupported_falls_back_to_one_legacy_stream_per_directory(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        blocker = asyncio.Event()

        class Response:
            headers = {"content-type": "text/event-stream"}

            def __init__(self, status_code: int) -> None:
                self.status_code = status_code

            def raise_for_status(self) -> None:
                return None

            async def aiter_lines(self):
                yield 'data: {"type":"server.connected","properties":{}}'
                yield ""
                await blocker.wait()

        class StreamContext:
            def __init__(self, response: Response) -> None:
                self.response = response

            async def __aenter__(self):
                return self.response

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

        class Client:
            paths: list[str] = []

            def __init__(self, *args, **kwargs) -> None:
                return None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            def stream(self, method: str, path: str, **kwargs):
                self.paths.append(path)
                return StreamContext(Response(404 if path == "/global/event" else 200))

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", Client)
        manager = OpenCodeServeManager()
        manager._port = 12345
        directory = tmp_path / "project"
        directory.mkdir()
        state_a = _ServeEventState("nga", "session-a", lambda _line: None)
        state_b = _ServeEventState("nga", "session-b", lambda _line: None)

        try:
            await manager._register_event_state("session-a", directory, state_a)
            await manager._register_event_state("session-b", directory, state_b)
            assert manager._global_event_unsupported is True
            assert Client.paths.count("/global/event") == 1
            assert Client.paths.count("/event") == 1
            assert manager._event_channel_healthy(directory) is True
        finally:
            await manager._stop_event_hub()

    asyncio.run(run())


def test_snapshot_polling_fills_text_reasoning_and_tool_state_then_pauses_on_recovery(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            "agent.task_agent.serve_client._SERVE_EVENT_POLL_INTERVAL_SECONDS",
            0.01,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        runtime = _EventChannelRuntime(
            key="global",
            path="/global/event",
            params={},
            headers={},
            healthy=False,
        )
        manager._global_event_channel = runtime
        output: list[str] = []
        state = _ServeEventState("opencode", "session-1", output.append)

        class Client:
            def __init__(self) -> None:
                self.get_calls = 0

            async def get(self, path: str, **kwargs):
                self.get_calls += 1
                completed = self.get_calls >= 2
                if completed:
                    runtime.healthy = True
                tool_state = (
                    {
                        "status": "completed",
                        "input": {"function_name": "target"},
                        "output": "SECRET TOOL BODY",
                        "title": "done",
                        "metadata": {},
                        "time": {"start": 1, "end": 2},
                    }
                    if completed
                    else {
                        "status": "pending",
                        "input": {"function_name": "target"},
                        "raw": "pending",
                    }
                )
                text = "hello world\n" if completed else "hello"
                reasoning = "think\n" if completed else ""
                return _FakeResponse([{
                    "info": {
                        "id": "message-ai",
                        "sessionID": "session-1",
                        "role": "assistant",
                        "time": {"created": 1},
                    },
                    "parts": [
                        {
                            "id": "text-1",
                            "sessionID": "session-1",
                            "messageID": "message-ai",
                            "type": "text",
                            "text": text,
                        },
                        {
                            "id": "reasoning-1",
                            "sessionID": "session-1",
                            "messageID": "message-ai",
                            "type": "reasoning",
                            "text": reasoning,
                        },
                        {
                            "id": "tool-1",
                            "sessionID": "session-1",
                            "messageID": "message-ai",
                            "type": "tool",
                            "callID": "call-1",
                            "tool": "mcp__deephole-code__view_function_code",
                            "state": tool_state,
                        },
                    ],
                }])

        client = Client()
        task = asyncio.create_task(manager._poll_session_snapshots(
            client=client,
            session_id="session-1",
            directory=tmp_path,
            params={"directory": str(tmp_path)},
            headers={"x-opencode-directory": str(tmp_path)},
            state=state,
        ))
        try:
            for _ in range(100):
                if client.get_calls >= 2:
                    break
                await asyncio.sleep(0.005)
            await asyncio.sleep(0.04)
            state.flush()
            assert client.get_calls == 2
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        logged = "\n".join(output)
        assert "[opencode serve llm text] hello world" in logged
        assert "[opencode serve llm reasoning] think" in logged
        assert logged.count("serve tool_call") == 1
        assert logged.count("serve tool_result") == 1
        assert "source=mcp" in logged
        assert "SECRET TOOL BODY" not in logged

    asyncio.run(run())


def test_serve_port_defaults_to_fixed_port(monkeypatch) -> None:
    monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)

    assert _serve_port() == 4096


def test_serve_port_accepts_env_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENCODE_SERVE_PORT", "4100")

    assert _serve_port() == 4100


def test_pid_is_running_uses_windows_fallback(monkeypatch) -> None:
    from agent.task_agent import serve_client

    monkeypatch.setattr("agent.task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr("agent.task_agent.serve_client._windows_pid_is_running", lambda pid: False)

    assert serve_client._pid_is_running(12345) is False


def test_terminate_process_tree_uses_taskkill_on_windows(monkeypatch) -> None:
    from agent.task_agent import serve_client

    running = {"alive": True}
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        running["alive"] = False

    monkeypatch.setattr("agent.task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr("agent.task_agent.serve_client._pid_is_running", lambda pid: running["alive"])
    monkeypatch.setattr("agent.task_agent.serve_client.subprocess.run", fake_run)

    serve_client._terminate_process_tree(12345)

    assert commands == [["taskkill", "/PID", "12345", "/T", "/F"]]


def test_parse_listener_pids_handles_windows_and_ipv6_netstat() -> None:
    from agent.task_agent import serve_client

    output = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:4097         0.0.0.0:0              LISTENING       1111
  TCP    0.0.0.0:4097           0.0.0.0:0              LISTENING       2222
  TCP    [::1]:4097             [::]:0                 LISTENING       3333
  TCP    127.0.0.1:4098         0.0.0.0:0              LISTENING       4444
  TCP    127.0.0.1:4097         127.0.0.1:50000        ESTABLISHED     5555
"""

    assert serve_client._parse_listener_pids(output, 4097) == {1111, 2222, 3333}


def test_parse_listener_pids_handles_ss_output_without_queue_numbers() -> None:
    from agent.task_agent import serve_client

    output = """
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:4097    0.0.0.0:*     users:(("node",pid=2222,fd=18))
"""

    assert serve_client._parse_listener_pids(output, 4097) == {2222}


def test_start_locked_uses_fixed_port_and_writes_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 12345

            def poll(self):
                return None

        commands: list[list[str]] = []
        envs: list[dict[str, str]] = []
        popen_kwargs: list[dict] = []
        startup_logs: list[str] = []
        git_init_cwds: list[Path] = []
        marker_path = tmp_path / "serve-marker.json"
        startup_log_path = tmp_path / "serve-startup.log"
        project = tmp_path / "project"
        startup_cwd = project / ".opendeephole" / "opencode" / "serve-test"
        project.mkdir()
        startup_cwd.mkdir(parents=True)
        (startup_cwd / "opencode.json").write_text('{"stale": true}', encoding="utf-8")
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)
        monkeypatch.setattr("agent.task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "agent.task_agent.serve_client._new_serve_startup_log_path",
            lambda tool, port: startup_log_path,
        )

        def fake_popen(cmd, **kwargs):
            commands.append(cmd)
            envs.append(kwargs["env"])
            popen_kwargs.append(kwargs)
            return FakeProc()

        def fake_run(cmd, **kwargs):
            assert cmd == ["git", "init", "-q"]
            cwd = Path(kwargs["cwd"])
            git_init_cwds.append(cwd)
            (cwd / ".git").mkdir(parents=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.Popen", fake_popen)
        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr(
            "agent.task_agent.serve_client.logger.info",
            lambda message, *args: startup_logs.append(message % args if args else str(message)),
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9999")
        monkeypatch.setenv("all_proxy", "http://127.0.0.1:9999")
        monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"stale": true}')

        await manager._start_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            env_hash="proxyhash",
            config_hash="abc123",
            config_content='{"mcp": {}}',
            env_overrides=(
                ("HTTP_PROXY", "http://127.0.0.1:3131"),
                ("HTTPS_PROXY", "http://127.0.0.1:3131"),
                ("NO_PROXY", "127.0.0.1,localhost"),
            ),
        ), startup_cwd=startup_cwd)

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
        assert "OPENCODE_CONFIG_CONTENT" not in envs[0]
        assert envs[0]["OPENCODE_CONFIG_DIR"] == str(startup_cwd)
        runtime_config_path = startup_cwd / "opencode.json"
        assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == {"mcp": {}}
        assert runtime_config_path.stat().st_mode & 0o777 == 0o600
        assert envs[0]["HTTP_PROXY"] == "http://127.0.0.1:3131"
        assert envs[0]["HTTPS_PROXY"] == "http://127.0.0.1:3131"
        assert "ALL_PROXY" not in envs[0]
        assert "all_proxy" not in envs[0]
        assert envs[0]["NO_PROXY"] == "127.0.0.1,localhost"
        assert envs[0]["PYTHONIOENCODING"] == "utf-8"
        assert envs[0]["PYTHONUTF8"] == "1"
        assert git_init_cwds == [startup_cwd]
        assert (startup_cwd / ".git").is_dir()
        assert not (project / ".git").exists()
        assert popen_kwargs[0]["cwd"] == str(startup_cwd)
        assert popen_kwargs[0]["stdout"] != subprocess.DEVNULL
        assert popen_kwargs[0]["stderr"] == subprocess.STDOUT
        log_text = "\n".join(startup_logs)
        assert "OpenCode serve startup debug:" in log_text
        assert "executable_config=opencode" in log_text
        assert "executable_resolved=/bin/opencode" in log_text
        assert f"cwd={startup_cwd}" in log_text
        assert f"marker_path={marker_path}" in log_text
        assert f"startup_log_path={startup_log_path}" in log_text
        assert 'argv=["/bin/opencode", "serve", "--hostname", "127.0.0.1", "--port", "4096"]' in log_text
        assert "shell=cd " in log_text
        assert "/bin/opencode serve --hostname 127.0.0.1 --port 4096" in log_text
        assert "HTTP_PROXY=http://127.0.0.1:3131" in log_text
        assert "HTTPS_PROXY=http://127.0.0.1:3131" in log_text
        assert "OPENCODE_CONFIG_CONTENT=(unset)" in log_text
        assert f"OPENCODE_CONFIG_DIR={startup_cwd}" in log_text
        assert f"config_file_path={runtime_config_path}" in log_text
        assert 'config_content_redacted={"mcp": {}}' in log_text
        assert "popen_kwargs={'start_new_session': True}" in log_text

    asyncio.run(run())


def test_serve_startup_debug_redacts_config_secrets(tmp_path: Path) -> None:
    env = {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "OPENCODE_CONFIG_CONTENT": json.dumps({
            "provider": {
                "corp": {
                    "options": {
                        "apiKey": "super-secret-key",
                        "baseURL": "https://project.example/v1",
                    },
                    "headers": {"Authorization": "Bearer secret-token"},
                }
            },
            "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
        }),
    }

    debug_text = "\n".join(_serve_startup_env_debug(env))
    shell_text = _serve_startup_shell_debug(["/bin/opencode", "serve"], tmp_path, env)
    combined = debug_text + "\n" + shell_text

    assert env["OPENCODE_CONFIG_CONTENT"].count("super-secret-key") == 1
    assert "super-secret-key" not in combined
    assert "secret-token" not in combined
    assert '"apiKey": "***"' in combined
    assert '"headers": "***"' in combined
    assert "https://project.example/v1" in combined
    assert "http://127.0.0.1:9123/mcp" in combined


def test_start_locked_uses_bootstrap_cwd_without_runtime_workspace(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 12346

            def poll(self):
                return None

        bootstrap_cwd = tmp_path / "bootstrap"
        popen_kwargs: list[dict] = []
        git_init_cwds: list[Path] = []
        marker_path = tmp_path / "serve-marker.json"
        startup_log_path = tmp_path / "serve-startup.log"
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("agent.task_agent.serve_client._serve_bootstrap_cwd", lambda tool: bootstrap_cwd)
        monkeypatch.setattr("agent.task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "agent.task_agent.serve_client._new_serve_startup_log_path",
            lambda tool, port: startup_log_path,
        )

        def fake_run(cmd, **kwargs):
            assert cmd == ["git", "init", "-q"]
            cwd = Path(kwargs["cwd"])
            git_init_cwds.append(cwd)
            (cwd / ".git").mkdir(parents=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        def fake_popen(cmd, **kwargs):
            popen_kwargs.append(kwargs)
            return FakeProc()

        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.Popen", fake_popen)

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert git_init_cwds == [bootstrap_cwd]
        assert popen_kwargs[0]["cwd"] == str(bootstrap_cwd)
        assert (bootstrap_cwd / ".git").is_dir()

    asyncio.run(run())


def test_wait_health_reports_startup_output_on_early_exit(tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            returncode = 1

            def poll(self):
                return 1

        startup_log = tmp_path / "startup.log"
        startup_log.write_bytes(b"before bad byte \x90 after\n")
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096
        manager._startup_cwd = tmp_path / "runtime"

        with pytest.raises(RuntimeError) as excinfo:
            await manager._wait_health_locked(startup_log)

        message = str(excinfo.value)
        assert "OpenCode serve exited during startup with code 1" in message
        assert f"startup_cwd={tmp_path / 'runtime'}" in message
        assert "OpenCode serve startup output:" in message
        assert "before bad byte" in message
        assert "after" in message

    asyncio.run(run())


def test_wait_health_polls_once_per_second_after_unhealthy_attempts(monkeypatch) -> None:
    async def run() -> None:
        class FakeProc:
            returncode = None

            def poll(self):
                return None

        class FakeHealthResponse:
            def __init__(self, status_code: int) -> None:
                self.status_code = status_code

        class FakeHealthClient:
            outcomes = [
                OSError("not ready"),
                FakeHealthResponse(500),
                FakeHealthResponse(200),
            ]
            requests: list[str] = []

            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def get(self, path: str):
                self.requests.append(path)
                outcome = self.outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", FakeHealthClient)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.sleep", fake_sleep)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096

        await manager._wait_health_locked()

        assert FakeHealthClient.requests == ["/global/health"] * 3
        assert sleeps == [
            _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
            _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
        ]

    asyncio.run(run())


def test_wait_health_timeout_reports_startup_output(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            returncode = None

            def poll(self):
                return None

        startup_log = tmp_path / "startup.log"
        startup_log.write_text("provider failed to load\n", encoding="utf-8")
        monkeypatch.setattr("agent.task_agent.serve_client._SERVE_START_TIMEOUT_SECONDS", 0.0)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096
        manager._startup_cwd = tmp_path / "runtime"

        with pytest.raises(TimeoutError) as excinfo:
            await manager._wait_health_locked(startup_log)

        message = str(excinfo.value)
        assert "OpenCode serve did not become healthy" in message
        assert f"startup_cwd={tmp_path / 'runtime'}" in message
        assert "provider failed to load" in message

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
        monkeypatch.setattr("agent.task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("agent.task_agent.serve_client._pid_is_running", lambda pid: pid == 11111)
        monkeypatch.setattr("agent.task_agent.serve_client._marker_matches_serve_process", lambda marker: True)
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [11111]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 22222

    asyncio.run(run())


def test_start_locked_reclaims_stale_child_listener_after_marker_parent_exits(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 33333

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
        port_state = {"in_use": True}
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        def fake_terminate(pid, *args, **kwargs):
            terminated.append(pid)
            port_state["in_use"] = False

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("agent.task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("agent.task_agent.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: port_state["in_use"])
        monkeypatch.setattr("agent.task_agent.serve_client._listener_pids_for_port", lambda port: {22222})
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("agent.task_agent.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [22222]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 33333

    asyncio.run(run())


def test_stop_locked_terminates_process_tree_and_removes_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 33333

            def __init__(self) -> None:
                self.wait_calls: list[float] = []

            def poll(self):
                return None

            def wait(self, timeout):
                self.wait_calls.append(timeout)

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "pid": 33333,
                "port": 4096,
                "tool": "opencode",
                "executable": "opencode",
            }),
            encoding="utf-8",
        )
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        def fake_terminate(pid, timeout=5.0, wait=None):
            terminated.append(pid)
            assert wait is not None
            wait(0.01)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.to_thread", fake_to_thread)

        proc = FakeProc()
        manager = OpenCodeServeManager()
        manager._proc = proc

        await manager._stop_locked()

        assert terminated == [33333]
        assert proc.wait_calls == [0.01]
        assert not marker_path.exists()

    asyncio.run(run())


def test_stop_locked_reclaims_listener_when_parent_already_exited(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 33333

            def poll(self):
                return 0

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "pid": 33333,
                "port": 4096,
                "tool": "opencode",
                "executable": "opencode",
            }),
            encoding="utf-8",
        )
        port_state = {"in_use": True}
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        def fake_terminate(pid, *args, **kwargs):
            terminated.append(pid)
            port_state["in_use"] = False

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: port_state["in_use"])
        monkeypatch.setattr("agent.task_agent.serve_client._listener_pids_for_port", lambda port: {44444})
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.to_thread", fake_to_thread)

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096

        await manager._stop_locked()

        assert terminated == [44444]
        assert not marker_path.exists()

    asyncio.run(run())


def test_stop_owned_serve_removes_stale_marker_without_terminating(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
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

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("agent.task_agent.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))

        manager = OpenCodeServeManager()
        await manager._stop_owned_serve_on_port(4096)

        assert terminated == []
        assert not marker_path.exists()

    asyncio.run(run())


def test_start_locked_reports_listener_pid_when_reclaim_fails(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(tmp_path / "missing-marker.json"))
        monkeypatch.setattr("agent.task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("agent.task_agent.serve_client._port_is_in_use", lambda port: True)
        monkeypatch.setattr("agent.task_agent.serve_client._listener_pids_for_port", lambda port: {22222})
        monkeypatch.setattr("agent.task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
        monkeypatch.setattr("agent.task_agent.serve_client._wait_port_released", lambda port: False)
        monkeypatch.setattr("agent.task_agent.serve_client.asyncio.to_thread", fake_to_thread)

        manager = OpenCodeServeManager()

        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [22222]
        assert "already in use" in str(excinfo.value)
        assert "listener_pid(s)=22222" in str(excinfo.value)

    asyncio.run(run())


def test_model_listing_reuses_compatible_idle_serve_despite_config_hash_change() -> None:
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
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()

        deferred = await manager._acquire_model_listing(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="new",
        ))

        assert deferred is False
        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._port == 12345
        assert manager._active_model_listings == 1

    asyncio.run(run())


def test_dirty_idle_serve_restarts_before_model_listing() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        key = OpenCodeServeKey(tool="opencode", executable="opencode")
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = key
        manager._dirty = True
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()

        deferred = await manager._acquire_model_listing(key)

        assert deferred is False
        manager._wait_until_idle_locked.assert_awaited_once()
        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once_with(key, startup_cwd=None)
        assert manager._dirty is False
        assert manager._active_model_listings == 1

    asyncio.run(run())


def test_mark_dirty_during_serve_start_preserves_pending_reload_generation() -> None:
    async def run() -> None:
        key = OpenCodeServeKey(tool="opencode", executable="opencode")
        model = OpenCodeModelInfo(
            id="openai/gpt-5",
            provider_id="openai",
            model_id="gpt-5",
        )
        start_entered = asyncio.Event()
        allow_start_to_finish = asyncio.Event()

        async def start_locked(
            requested_key: OpenCodeServeKey,
            startup_cwd: Path | None = None,
        ) -> None:
            assert requested_key == key
            start_entered.set()
            await allow_start_to_finish.wait()

        manager = OpenCodeServeManager()
        manager._model_cache[(key, "")] = (model,)
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock(side_effect=start_locked)
        cache_generation_before = manager._model_cache_generation

        ensure_task = asyncio.create_task(manager._ensure_started_locked(key))
        await start_entered.wait()
        manager.mark_dirty()
        allow_start_to_finish.set()
        await ensure_task

        assert manager._dirty is True
        assert manager._serve_config_generation == 1
        assert manager._model_cache_generation == cache_generation_before + 1
        assert manager._model_cache == {}

    asyncio.run(run())


def test_dirty_active_session_defers_model_reload_without_waiting_or_restarting() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="old",
        )
        manager._active_sessions = 1
        manager.mark_dirty()
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = AsyncMock(return_value=models)

        result = await manager.list_models(
            tool="opencode",
            executable="opencode",
            config_content='{"mcp": {}}',
        )

        assert result.models == models
        assert "当前有 OpenCode serve 会话运行" in result.message
        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._active_sessions == 1
        assert manager._dirty is True

    asyncio.run(run())


def test_refresh_with_active_session_fetches_live_without_reload_or_deferred_message() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        cached_models = [
            OpenCodeModelInfo(
                id="anthropic/claude-sonnet",
                provider_id="anthropic",
                model_id="claude-sonnet",
            ),
        ]
        live_models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = OpenCodeServeKey(tool="opencode", executable="opencode")
        manager._active_sessions = 1
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = AsyncMock(side_effect=[cached_models, live_models])

        initial = await manager.list_models(tool="opencode", executable="opencode")
        refreshed = await manager.list_models(
            tool="opencode",
            executable="opencode",
            refresh=True,
        )

        assert initial == OpenCodeModelListResult(models=cached_models)
        assert refreshed == OpenCodeModelListResult(models=live_models)
        assert manager._fetch_models.await_count == 2
        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._active_sessions == 1
        assert manager._dirty is False

    asyncio.run(run())


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"tool": "nga", "executable": "opencode"},
        {"tool": "opencode", "executable": "nga"},
        {
            "tool": "opencode",
            "executable": "opencode",
            "env_overrides": {"HTTPS_PROXY": "http://127.0.0.1:3131"},
        },
    ],
    ids=["tool", "executable", "environment"],
)
def test_incompatible_active_serve_defers_model_reload_without_waiting(
    request_kwargs: dict,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = OpenCodeServeKey(tool="opencode", executable="opencode")
        manager._active_sessions = 1
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = AsyncMock(return_value=models)

        result = await manager.list_models(**request_kwargs)

        assert result.models == models
        assert "当前有 OpenCode serve 会话运行" in result.message
        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._active_sessions == 1
        assert manager._dirty is True

    asyncio.run(run())


def test_prompt_config_change_waits_for_model_listing_then_restarts_serve() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        picker_config = '{"mcp": {"picker": {}}}'
        prompt_config = '{"mcp": {"prompt": {}}}'
        picker_key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash=hashlib.sha256(picker_config.encode("utf-8")).hexdigest(),
        )
        prompt_key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash=hashlib.sha256(prompt_config.encode("utf-8")).hexdigest(),
            config_content=prompt_config,
        )
        fetch_started = asyncio.Event()
        allow_fetch_to_finish = asyncio.Event()
        models = [
            OpenCodeModelInfo(
                id="openai/gpt-5",
                provider_id="openai",
                model_id="gpt-5",
            ),
        ]

        async def fetch_models(directory: Path | None):
            fetch_started.set()
            await allow_fetch_to_finish.wait()
            return models

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = picker_key
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = fetch_models

        listing_task = asyncio.create_task(manager.list_models(
            tool="opencode",
            executable="opencode",
            config_content=picker_config,
        ))
        await fetch_started.wait()
        assert manager._active_model_listings == 1

        session_task = asyncio.create_task(manager._acquire_session(prompt_key))
        await asyncio.sleep(0)

        assert session_task.done() is False
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()

        allow_fetch_to_finish.set()
        listing_result, _ = await asyncio.gather(listing_task, session_task)

        assert listing_result == OpenCodeModelListResult(models=models)
        assert manager._active_model_listings == 0
        assert manager._active_sessions == 1
        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once_with(prompt_key, startup_cwd=None)

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


def test_config_hash_change_reuses_active_serve_process_without_waiting(tmp_path: Path) -> None:
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
        manager._active_sessions = 1
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        live_config = tmp_path / "opencode.json"
        live_config.write_text('{"active": true}', encoding="utf-8")

        await manager._ensure_started_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="new",
            config_content='{"mcp": {}}',
        ), startup_cwd=tmp_path)

        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._port == 12345
        assert live_config.read_text(encoding="utf-8") == '{"active": true}'

    asyncio.run(run())


def test_managed_mcp_hot_loads_live_directory_with_auth_headers(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        calls: list[dict] = []

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def post(self, path: str, **kwargs):
                calls.append({"path": path, **kwargs})
                name = str((kwargs.get("json") or {}).get("name") or "")
                return _FakeResponse({name: {"status": "connected"}})

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._active_sessions = 1
        manager.update_managed_mcp_configs({
            "product_info": {
                "target": "product_info",
                "enabled": True,
                "name": "product-info",
                "fingerprint": "auth-v1",
                "error": "",
                "config": {
                    "type": "remote",
                    "url": "http://10.0.0.8:9000/mcp",
                    "enabled": True,
                    "timeout": 1000,
                    "oauth": False,
                    "headers": {"Authorization": "Bearer test-secret-123"},
                },
            },
        })
        project = tmp_path / "project"
        project.mkdir()

        await manager.ensure_managed_mcp(project)

        assert manager._active_sessions == 1
        assert calls[0]["path"] == "/mcp"
        assert calls[0]["params"]["directory"] == str(project.resolve())
        assert calls[0]["json"]["config"]["headers"] == {
            "Authorization": "Bearer test-secret-123",
        }
        assert manager.managed_mcp_runtime_status()["product_info"] == {
            "state": "connected",
            "config_fingerprint": "auth-v1",
            "updated_at": manager.managed_mcp_runtime_status()["product_info"]["updated_at"],
            "error": "",
            "loaded_directories": 1,
            "total_directories": 1,
        }

    asyncio.run(run())


def test_managed_mcp_rename_connects_new_name_and_disconnects_old(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        calls: list[str] = []

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def post(self, path: str, **kwargs):
                calls.append(path)
                if path == "/mcp":
                    name = str((kwargs.get("json") or {}).get("name") or "")
                    return _FakeResponse({name: {"status": "connected"}})
                return _FakeResponse(True)

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._active_sessions = 1
        project = tmp_path / "project"
        project.mkdir()
        first = {
            "target": "product_info",
            "enabled": True,
            "name": "product-v1",
            "fingerprint": "v1",
            "error": "",
            "config": {"type": "remote", "url": "http://old/mcp", "enabled": True, "timeout": 1000},
        }
        manager.update_managed_mcp_configs({"product_info": first})
        await manager.ensure_managed_mcp(project)
        calls.clear()

        manager.update_managed_mcp_configs({
            "product_info": {
                **first,
                "name": "product-v2",
                "fingerprint": "v2",
                "config": {"type": "remote", "url": "http://new/mcp", "enabled": True, "timeout": 1000},
            },
        })
        await asyncio.gather(*list(manager._managed_mcp_tasks.values()))

        assert calls == ["/mcp", "/mcp/product-v1/disconnect"]
        status = manager.managed_mcp_runtime_status()["product_info"]
        assert status["state"] == "connected"
        assert status["config_fingerprint"] == "v2"
        assert manager._active_sessions == 1

    asyncio.run(run())


def test_managed_mcp_config_change_during_connect_cleans_up_stale_server(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        connect_started = asyncio.Event()
        release_connect = asyncio.Event()
        calls: list[str] = []

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def post(self, path: str, **kwargs):
                calls.append(path)
                if path == "/mcp":
                    connect_started.set()
                    await release_connect.wait()
                    name = str((kwargs.get("json") or {}).get("name") or "")
                    return _FakeResponse({name: {"status": "connected"}})
                return _FakeResponse(True)

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        first = {
            "target": "product_info",
            "enabled": True,
            "name": "product-v1",
            "fingerprint": "v1",
            "error": "",
            "config": {"type": "remote", "url": "http://old/mcp", "enabled": True, "timeout": 1000},
        }
        manager.update_managed_mcp_configs({"product_info": first})
        project = tmp_path / "project"
        project.mkdir()
        initial_sync = asyncio.create_task(manager.ensure_managed_mcp(project))
        await connect_started.wait()

        manager.update_managed_mcp_configs({
            "product_info": {
                **first,
                "enabled": False,
                "fingerprint": "disabled-v2",
                "config": None,
            },
        })
        release_connect.set()
        await initial_sync
        while manager._managed_mcp_tasks:
            await asyncio.gather(*list(manager._managed_mcp_tasks.values()))
            await asyncio.sleep(0)

        assert calls == ["/mcp", "/mcp/product-v1/disconnect"]
        status = manager.managed_mcp_runtime_status()["product_info"]
        assert status["state"] == "disabled"
        assert status["config_fingerprint"] == "disabled-v2"

    asyncio.run(run())


def test_managed_mcp_reload_queues_forced_retry_while_sync_is_running(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        first_started = asyncio.Event()
        release_first = asyncio.Event()
        calls = 0

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def post(self, path: str, **kwargs):
                nonlocal calls
                if path == "/mcp":
                    calls += 1
                    if calls == 1:
                        first_started.set()
                        await release_first.wait()
                    name = str((kwargs.get("json") or {}).get("name") or "")
                    return _FakeResponse({name: {"status": "connected"}})
                return _FakeResponse(True)

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager.update_managed_mcp_configs({
            "product_info": {
                "target": "product_info",
                "enabled": True,
                "name": "product-info",
                "fingerprint": "v1",
                "error": "",
                "config": {"type": "remote", "url": "http://product/mcp", "enabled": True, "timeout": 1000},
            },
        })
        project = tmp_path / "project"
        project.mkdir()
        initial_sync = asyncio.create_task(manager.ensure_managed_mcp(project))
        await first_started.wait()

        manager.retry_managed_mcp("product_info")
        release_first.set()
        await initial_sync
        while manager._managed_mcp_tasks:
            await asyncio.gather(*list(manager._managed_mcp_tasks.values()))
            await asyncio.sleep(0)

        assert calls == 2
        assert manager.managed_mcp_runtime_status()["product_info"]["state"] == "connected"

    asyncio.run(run())


def test_managed_mcp_failure_redacts_authorization_value(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def post(self, path: str, **kwargs):
                return _FakeResponse(
                    {},
                    error=RuntimeError("authentication failed for test-secret-123"),
                )

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager.update_managed_mcp_configs({
            "product_info": {
                "target": "product_info",
                "enabled": True,
                "name": "product-info",
                "fingerprint": "secret-v1",
                "error": "",
                "config": {
                    "type": "remote",
                    "url": "http://product/mcp",
                    "enabled": True,
                    "timeout": 1000,
                    "headers": {"Authorization": "Bearer test-secret-123"},
                },
            },
        })
        project = tmp_path / "project"
        project.mkdir()

        await manager.ensure_managed_mcp(project)

        status = manager.managed_mcp_runtime_status()["product_info"]
        assert status["state"] == "failed"
        assert "test-secret-123" not in status["error"]
        assert "***" in status["error"]

    asyncio.run(run())


def test_managed_mcp_failed_disconnect_is_not_reported_as_disabled(tmp_path: Path) -> None:
    class FakeProc:
        def poll(self):
            return None

    manager = OpenCodeServeManager()
    manager._proc = FakeProc()
    manager._port = 12345
    directory = str((tmp_path / "project").resolve())
    manager._managed_mcp_directories[directory] = Path(directory)
    manager._managed_mcp_specs["product_info"] = {
        "enabled": False,
        "fingerprint": "disabled-v2",
    }
    manager._managed_mcp_status[directory] = {
        "product_info": {
            "state": "failed",
            "fingerprint": "disabled-v2",
            "updated_at": "2026-07-19T00:00:00+00:00",
            "error": "disconnect failed",
        },
    }

    status = manager.managed_mcp_runtime_status()["product_info"]

    assert status["state"] == "failed"
    assert status["error"] == "disconnect failed"


def test_managed_mcp_invalid_config_is_failed_before_first_session() -> None:
    manager = OpenCodeServeManager()
    manager._managed_mcp_specs["code_graph"] = {
        "enabled": True,
        "fingerprint": "missing-binary",
        "error": "CodeGraph executable not found: codegraph",
    }

    status = manager.managed_mcp_runtime_status()["code_graph"]

    assert status["state"] == "failed"
    assert status["error"] == "CodeGraph executable not found: codegraph"
    assert status["total_directories"] == 0


def test_managed_mcp_live_status_refresh_aggregates_directories_and_redacts_auth(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        class McpClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def get(self, _path: str, **kwargs):
                directory = str((kwargs.get("params") or {}).get("directory") or "")
                if directory.endswith("project-a"):
                    state = {"status": "connected"}
                else:
                    state = {
                        "status": "needs_auth",
                        "error": "rejected Authorization Bearer test-secret-123",
                    }
                return _FakeResponse({"product-info": state})

        monkeypatch.setattr("agent.task_agent.serve_client.httpx.AsyncClient", McpClient)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._managed_mcp_specs["product_info"] = {
            "enabled": True,
            "name": "product-info",
            "fingerprint": "auth-v1",
            "error": "",
            "config": {
                "type": "remote",
                "url": "http://product/mcp",
                "headers": {"Authorization": "Bearer test-secret-123"},
            },
        }
        for name in ("project-a", "project-b"):
            directory = (tmp_path / name).resolve()
            manager._managed_mcp_directories[str(directory)] = directory

        status = (await manager.refresh_managed_mcp_runtime_status())["product_info"]

        assert status["state"] == "needs_auth"
        assert status["loaded_directories"] == 1
        assert status["total_directories"] == 2
        assert "test-secret-123" not in status["error"]
        assert "***" in status["error"]

    asyncio.run(run())


def test_managed_mcp_reset_does_not_respawn_cancelled_sync(tmp_path: Path) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        directory = str((tmp_path / "project").resolve())
        manager._managed_mcp_directories[directory] = Path(directory)
        manager._managed_mcp_specs["product_info"] = {
            "enabled": True,
            "fingerprint": "pending-v1",
        }

        async def pending_sync(*_args, **_kwargs) -> None:
            await asyncio.Future()

        manager._sync_managed_mcp_target = pending_sync
        task = manager._spawn_managed_mcp_sync(directory, "product_info")
        await asyncio.sleep(0)

        await manager._reset_managed_mcp_process_state()
        await asyncio.sleep(0)

        assert task.cancelled()
        assert manager._managed_mcp_tasks == {}
        assert manager._managed_mcp_directories == {}

    asyncio.run(run())
