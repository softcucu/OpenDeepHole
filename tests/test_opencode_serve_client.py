import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from backend.opencode.serve_client import (
    OpenCodeServeKey,
    OpenCodeServeManager,
    _serve_context_headers,
    _serve_port,
    _serve_startup_env_debug,
    _serve_startup_shell_debug,
)


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
    tool_ids: list[str] | Exception = ["read", "grep", "mcp__deephole-code__view_function_code"]

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
            if isinstance(self.tool_ids, Exception):
                return _FakeResponse([], error=self.tool_ids)
            return _FakeResponse(self.tool_ids)
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
        _FakeAsyncClient.tool_ids = ["read", "grep", "mcp__deephole-code__view_function_code"]
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
        )
        assert sessions == ["session-1"]
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
        assert message["json"]["model"] == {
            "providerID": "anthropic",
            "modelID": "claude-sonnet",
        }

    asyncio.run(run())


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
        session_client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in session_client.posts
            if item["path"] == "/session/session-1/message"
        )
        assert "tools" not in message["json"]
        assert session_client.gets == [{
            "path": "/experimental/tool/ids",
            "params": {"directory": str(project)},
            "headers": {"x-opencode-directory": str(project)},
        }]
        assert "tool discovery unavailable" in "\n".join(output)

    asyncio.run(run())


def test_list_models_uses_project_directory_context(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read", "mcp__deephole-code__view_function_code"]
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
        assert manager._ensure_started.await_args.kwargs["startup_cwd"] == config_workspace

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
        assert "session=session-1" in logged
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


def test_pid_is_running_uses_windows_fallback(monkeypatch) -> None:
    from backend.opencode import serve_client

    monkeypatch.setattr("backend.opencode.serve_client.sys.platform", "win32")
    monkeypatch.setattr("backend.opencode.serve_client._windows_pid_is_running", lambda pid: False)

    assert serve_client._pid_is_running(12345) is False


def test_terminate_process_tree_uses_taskkill_on_windows(monkeypatch) -> None:
    from backend.opencode import serve_client

    running = {"alive": True}
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        running["alive"] = False

    monkeypatch.setattr("backend.opencode.serve_client.sys.platform", "win32")
    monkeypatch.setattr("backend.opencode.serve_client._pid_is_running", lambda pid: running["alive"])
    monkeypatch.setattr("backend.opencode.serve_client.subprocess.run", fake_run)

    serve_client._terminate_process_tree(12345)

    assert commands == [["taskkill", "/PID", "12345", "/T", "/F"]]


def test_parse_listener_pids_handles_windows_and_ipv6_netstat() -> None:
    from backend.opencode import serve_client

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
    from backend.opencode import serve_client

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
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "backend.opencode.serve_client._new_serve_startup_log_path",
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

        monkeypatch.setattr("backend.opencode.serve_client.subprocess.Popen", fake_popen)
        monkeypatch.setattr("backend.opencode.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr(
            "backend.opencode.serve_client.logger.info",
            lambda message, *args: startup_logs.append(message % args if args else str(message)),
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="abc123",
            config_content='{"mcp": {}}',
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
        assert envs[0]["OPENCODE_CONFIG_CONTENT"] == '{"mcp": {}}'
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
        assert 'OPENCODE_CONFIG_CONTENT={"mcp": {}}' in log_text
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
        monkeypatch.setattr("backend.opencode.serve_client._serve_bootstrap_cwd", lambda tool: bootstrap_cwd)
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "backend.opencode.serve_client._new_serve_startup_log_path",
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

        monkeypatch.setattr("backend.opencode.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr("backend.opencode.serve_client.subprocess.Popen", fake_popen)

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


def test_wait_health_timeout_reports_startup_output(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            returncode = None

            def poll(self):
                return None

        startup_log = tmp_path / "startup.log"
        startup_log.write_text("provider failed to load\n", encoding="utf-8")
        monkeypatch.setattr("backend.opencode.serve_client._SERVE_START_TIMEOUT_SECONDS", 0.0)
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
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._pid_is_running", lambda pid: pid == 11111)
        monkeypatch.setattr("backend.opencode.serve_client._marker_matches_serve_process", lambda marker: True)
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
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
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: port_state["in_use"])
        monkeypatch.setattr("backend.opencode.serve_client._listener_pids_for_port", lambda port: {22222})
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("backend.opencode.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("backend.opencode.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())

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
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("backend.opencode.serve_client.asyncio.to_thread", fake_to_thread)

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
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: port_state["in_use"])
        monkeypatch.setattr("backend.opencode.serve_client._listener_pids_for_port", lambda port: {44444})
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("backend.opencode.serve_client.asyncio.to_thread", fake_to_thread)

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
        monkeypatch.setattr("backend.opencode.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))

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
        monkeypatch.setattr("backend.opencode.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("backend.opencode.serve_client._port_is_in_use", lambda port: True)
        monkeypatch.setattr("backend.opencode.serve_client._listener_pids_for_port", lambda port: {22222})
        monkeypatch.setattr("backend.opencode.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
        monkeypatch.setattr("backend.opencode.serve_client._wait_port_released", lambda port: False)
        monkeypatch.setattr("backend.opencode.serve_client.asyncio.to_thread", fake_to_thread)

        manager = OpenCodeServeManager()

        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [22222]
        assert "already in use" in str(excinfo.value)
        assert "listener_pid(s)=22222" in str(excinfo.value)

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


def test_config_hash_change_reuses_active_serve_process_without_waiting() -> None:
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

        await manager._ensure_started_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_hash="new",
            config_content='{"mcp": {}}',
        ))

        manager._wait_until_idle_locked.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        assert manager._port == 12345

    asyncio.run(run())
