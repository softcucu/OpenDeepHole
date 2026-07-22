from __future__ import annotations

import asyncio
import re
from datetime import timedelta

import pytest
from code_parser import CodeDatabase
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from deephole_client.local_mcp import LocalMCPServer, shutdown_local_mcp_gateway


@pytest.fixture(autouse=True)
def _reset_shared_gateway():
    shutdown_local_mcp_gateway()
    yield
    shutdown_local_mcp_gateway()


class _FakeThread:
    def __init__(self, *, alive: bool) -> None:
        self.alive = alive

    def is_alive(self) -> bool:
        return self.alive


def _write_code_index(project_dir, body: str) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.c")
    db.insert_function(
        name="target",
        signature="int target(void)",
        return_type="int",
        file_id=file_id,
        start_line=1,
        end_line=3,
        is_static=False,
        linkage="external",
        body=body,
    )
    db.mark_index_complete()
    db.checkpoint()
    db.close()


def test_streamable_http_tool_call_is_logged_without_result_body(
    tmp_path, monkeypatch, capsys
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    source_marker = "REAL_MCP_SOURCE_BODY_MARKER"
    _write_code_index(
        project_dir,
        f"int target(void) {{ /* {source_marker} */ return 7; }}",
    )
    try:
        server = LocalMCPServer(project_dir=project_dir)
    except PermissionError:
        pytest.skip("sandbox does not allow loopback sockets")
    wait_ready = server._wait_ready
    monkeypatch.setattr(server, "_wait_ready", lambda: wait_ready(timeout=3.0))

    async def call_tool(port: int):
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
            read_stream, write_stream, _get_session_id = streams
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=3),
            ) as session:
                await session.initialize()
                return await session.call_tool(
                    "view_function_code",
                    {"project_id": "scan-a", "function_name": "target"},
                    read_timeout_seconds=timedelta(seconds=3),
                )

    try:
        try:
            port = server.start()
        except RuntimeError as exc:
            if isinstance(exc.__cause__, PermissionError):
                pytest.skip("sandbox does not allow loopback listeners")
            raise
        result = asyncio.run(asyncio.wait_for(call_tool(port), timeout=5.0))
    finally:
        server.stop()

    assert result.isError is False
    assert any(source_marker in getattr(block, "text", "") for block in result.content)
    output = capsys.readouterr().out
    assert re.search(
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] "
        r"\[MCP ▶\] view_function_code",
        output,
        re.MULTILINE,
    )
    assert re.search(
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] "
        r"\[MCP ◀\] view_function_code \| status=ok, 1 match\(es\), \d+ chars$",
        output,
        re.MULTILINE,
    )
    assert source_marker not in output


def test_streamable_http_survives_gateway_restart_across_event_loops(
    tmp_path, monkeypatch
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    source_marker = "MCP_MULTI_LOOP_SOURCE_MARKER"
    _write_code_index(
        project_dir,
        f"int target(void) {{ /* {source_marker} */ return 9; }}",
    )

    async def call_tool(port: int):
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
            read_stream, write_stream, _get_session_id = streams
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=3),
            ) as session:
                await session.initialize()
                return await session.call_tool(
                    "view_function_code",
                    {"project_id": "scan-restart", "function_name": "target"},
                    read_timeout_seconds=timedelta(seconds=3),
                )

    for _attempt in range(2):
        try:
            server = LocalMCPServer(
                project_dir=project_dir,
                project_id="scan-restart",
            )
        except PermissionError:
            pytest.skip("sandbox does not allow loopback sockets")
        wait_ready = server._wait_ready
        monkeypatch.setattr(
            server,
            "_wait_ready",
            lambda wait_ready=wait_ready: wait_ready(timeout=3.0),
        )

        try:
            try:
                port = server.start()
            except RuntimeError as exc:
                if isinstance(exc.__cause__, PermissionError):
                    pytest.skip("sandbox does not allow loopback listeners")
                raise
            result = asyncio.run(asyncio.wait_for(call_tool(port), timeout=5.0))
        finally:
            server.stop()
            shutdown_local_mcp_gateway()

        assert result.isError is False
        assert any(
            source_marker in getattr(block, "text", "") for block in result.content
        )


def test_wait_ready_fails_when_server_thread_exits(monkeypatch) -> None:
    monkeypatch.setattr("deephole_client.local_mcp._find_free_port", lambda: 43123)
    server = LocalMCPServer()
    server._thread = _FakeThread(alive=False)
    server._thread_error = ValueError("uvicorn failed")

    with pytest.raises(RuntimeError, match="exited before readiness") as excinfo:
        server._wait_ready(timeout=1.0)

    assert isinstance(excinfo.value.__cause__, ValueError)
    assert "127.0.0.1" in str(excinfo.value)
    assert str(server.port) in str(excinfo.value)


def test_wait_ready_times_out_explicitly(monkeypatch) -> None:
    monkeypatch.setattr("deephole_client.local_mcp._find_free_port", lambda: 43123)
    server = LocalMCPServer()
    server._thread = _FakeThread(alive=True)
    clock = {"now": 100.0}

    monkeypatch.setattr("deephole_client.local_mcp.time.monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        "deephole_client.local_mcp.time.sleep",
        lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
    )

    def connection_failed(*_args, **_kwargs):
        raise OSError("not listening")

    monkeypatch.setattr("deephole_client.local_mcp.socket.create_connection", connection_failed)

    with pytest.raises(TimeoutError, match="Timed out after 0.2s") as excinfo:
        server._wait_ready(timeout=0.2)

    assert "127.0.0.1" in str(excinfo.value)
    assert str(server.port) in str(excinfo.value)


def test_start_cleans_up_after_readiness_failure(monkeypatch) -> None:
    monkeypatch.setattr("deephole_client.local_mcp._find_free_port", lambda: 43123)
    server = LocalMCPServer()
    stopped = []

    class _FakeAppServer:
        should_exit = False

        def run(self) -> None:
            return None

    class _FakeMCP:
        def streamable_http_app(self):
            return object()

    monkeypatch.setattr("mcp_server.factory.create_mcp_server", lambda project_dir=None: _FakeMCP())
    monkeypatch.setattr("uvicorn.Server", lambda _config: _FakeAppServer())
    monkeypatch.setattr(
        server,
        "_wait_ready",
        lambda: (_ for _ in ()).throw(TimeoutError("not ready")),
    )
    with pytest.raises(TimeoutError, match="not ready"):
        server.start()

    assert server._server.should_exit is True
