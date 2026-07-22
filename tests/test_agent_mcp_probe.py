from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from deephole_client import mcp_probe
from backend.api import agent as agent_api
from backend.models import AgentInfo, AgentRemoteConfig, User
from task_agent.serve_client import OpenCodeServeManager
from backend.store.sqlite import SqliteScanStore


def _mcp_config(**overrides) -> dict:
    config = {
        "enabled": True,
        "name": "test-mcp",
        "transport": "local",
        "timeout_seconds": 5,
        "local": {"executable": sys.executable, "args": [], "environment": {}},
        "remote": {"url": "", "headers": {}},
    }
    config.update(overrides)
    return config


def test_local_stdio_probe_initializes_and_lists_tools(tmp_path: Path, monkeypatch) -> None:
    server = Path(__file__).parent / "fixtures" / "mcp_probe_server.py"
    monkeypatch.setattr(
        "deephole_client.opencode_integration.get_global_opencode_workspace",
        lambda: tmp_path,
    )
    config = _mcp_config(local={
        "executable": sys.executable,
        "args": [str(server)],
        "environment": {"PROBE_TOOL_NAME": "configured_probe_tool"},
    })

    result = asyncio.run(mcp_probe.probe_mcp_config("code_graph", config))

    assert result["success"] is True, result
    assert result["protocol"] == "stdio"
    assert result["tool_names"] == ["configured_probe_tool"]
    assert result["tool_count"] == 1


def test_local_probe_reports_missing_executable_without_leaking_environment() -> None:
    secret = "probe-secret-value"
    result = asyncio.run(mcp_probe.probe_mcp_config(
        "product_info",
        _mcp_config(local={
            "executable": "definitely-not-an-installed-mcp-command",
            "args": [],
            "environment": {"API_TOKEN": secret},
        }),
    ))

    assert result["success"] is False
    assert "executable not found" in result["error"]
    assert secret not in result["error"]


def test_remote_probe_falls_back_to_sse_and_caps_timeout(monkeypatch) -> None:
    streamable = AsyncMock(side_effect=RuntimeError("streamable unavailable"))
    sse = AsyncMock(return_value=["lookup_product", "lookup_version"])
    monkeypatch.setattr(mcp_probe, "_probe_streamable_http", streamable)
    monkeypatch.setattr(mcp_probe, "_probe_sse", sse)
    config = _mcp_config(
        transport="remote",
        timeout_seconds=300,
        remote={"url": "http://mcp.test/sse", "headers": {"Authorization": "Bearer safe"}},
    )

    result = asyncio.run(mcp_probe.probe_mcp_config("product_info", config))

    assert result["success"] is True
    assert result["protocol"] == "sse"
    assert result["tool_names"] == ["lookup_product", "lookup_version"]
    streamable.assert_awaited_once_with(
        "http://mcp.test/sse",
        {"Authorization": "Bearer safe"},
        30.0,
    )
    sse.assert_awaited_once_with(
        "http://mcp.test/sse",
        {"Authorization": "Bearer safe"},
        30.0,
    )


def test_remote_probe_redacts_header_secrets(monkeypatch) -> None:
    secret = "very-secret-token"
    monkeypatch.setattr(
        mcp_probe,
        "_probe_streamable_http",
        AsyncMock(side_effect=RuntimeError(f"Authorization: Bearer {secret}")),
    )
    monkeypatch.setattr(
        mcp_probe,
        "_probe_sse",
        AsyncMock(side_effect=RuntimeError(f"token={secret}")),
    )
    result = asyncio.run(mcp_probe.probe_mcp_config(
        "product_info",
        _mcp_config(
            transport="remote",
            remote={"url": "http://mcp.test/mcp", "headers": {"Authorization": f"Bearer {secret}"}},
        ),
    ))

    assert result["success"] is False
    assert secret not in result["error"]
    assert "***" in result["error"]


def test_probe_timeout_uses_global_cap(monkeypatch) -> None:
    async def slow_probe(_config):
        await asyncio.sleep(1)
        return "stdio", []

    monkeypatch.setattr(mcp_probe, "_MAX_PROBE_SECONDS", 0.01)
    monkeypatch.setattr(mcp_probe, "_probe_local", slow_probe)

    result = asyncio.run(mcp_probe.probe_mcp_config("code_graph", _mcp_config()))

    assert result["success"] is False
    assert "timed out" in result["error"]
    assert result["duration_ms"] < 500


def test_serve_runtime_status_distinguishes_loaded_pending_and_next_task() -> None:
    class FakeProcess:
        def poll(self):
            return None

    manager = OpenCodeServeManager()
    assert manager.config_runtime_status() == {
        "runtime_state": "next_task",
        "active_sessions": 0,
    }
    manager._proc = FakeProcess()
    assert manager.config_runtime_status()["runtime_state"] == "active"
    manager._active_sessions = 2
    manager.mark_dirty()
    assert manager.config_runtime_status() == {
        "runtime_state": "reload_pending",
        "active_sessions": 2,
    }


def test_agent_probe_result_persists_and_becomes_stale_after_config_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    config = AgentRemoteConfig()
    config.code_graph.enabled = True
    config.code_graph.local.executable = sys.executable
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="session-1",
        last_seen="2026-07-17T01:00:00+00:00",
        initial_config_json=config.model_dump_json(),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        machine_name="build-host",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", live_agent))

    async def send_result(_agent_id: str, command: dict) -> bool:
        agent_api._mcp_probe_waiters[command["request_id"]].set_result({
            "success": True,
            "transport": "local",
            "protocol": "stdio",
            "tool_names": ["search", "node"],
            "duration_ms": 12,
            "runtime_state": "reload_pending",
            "active_sessions": 1,
        })
        return True

    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    user = User(user_id="user-1", username="owner", role="user")

    result = asyncio.run(agent_api.probe_stable_agent_mcp(
        "stable-agent",
        "code_graph",
        user,
    ))
    status = asyncio.run(agent_api.get_stable_agent_mcp_status("stable-agent", user))

    assert result.success is True
    assert result.tool_names == ["node", "search"]
    assert status.code_graph.stale is False
    assert status.code_graph.last_probe == result
    persisted = json.loads(store.get_agent_record("stable-agent")["mcp_probe_json"])
    assert persisted["code_graph"]["runtime_state"] == "reload_pending"

    config.code_graph.timeout_seconds += 1
    store.update_agent_config_record("stable-agent", config.model_dump_json())
    stale_status = asyncio.run(agent_api.get_stable_agent_mcp_status("stable-agent", user))
    assert stale_status.code_graph.stale is True
    store.close()


def test_agent_probe_wait_timeout_cleans_up_waiter(monkeypatch) -> None:
    config = AgentRemoteConfig()
    config.code_graph.enabled = True
    record = {
        "agent_key": "stable-agent",
        "user_id": "user-1",
        "config_json": config.model_dump_json(),
    }

    class Store:
        def get_agent_record(self, _agent_key):
            return record

    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )

    async def sent(_agent_id: str, _command: dict) -> bool:
        return True

    async def timed_out(_waiter, timeout: float):
        assert timeout == 35
        raise asyncio.TimeoutError

    monkeypatch.setattr(agent_api, "get_scan_store", lambda: Store())
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", live_agent))
    monkeypatch.setattr(agent_api, "send_agent_command", sent)
    monkeypatch.setattr(agent_api.asyncio, "wait_for", timed_out)
    user = User(user_id="user-1", username="owner", role="user")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(agent_api.probe_stable_agent_mcp(
            "stable-agent",
            "code_graph",
            user,
        ))

    assert excinfo.value.status_code == 504
    assert agent_api._mcp_probe_waiters == {}


def test_agent_mcp_status_reports_live_hot_load_state(monkeypatch) -> None:
    config = AgentRemoteConfig()
    config.product_info.enabled = True
    config.product_info.transport = "remote"
    config.product_info.remote.url = "http://product.test/mcp"
    record = {
        "agent_key": "stable-agent",
        "user_id": "user-1",
        "config_json": config.model_dump_json(),
        "mcp_probe_json": "{}",
    }

    class Store:
        def get_agent_record(self, _agent_key):
            return record

    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )

    async def send_result(_agent_id: str, command: dict) -> bool:
        assert command["type"] == "mcp_status"
        agent_api._mcp_status_waiters[command["request_id"]].set_result({
            "targets": {
                "product_info": {
                    "state": "connected",
                    "config_fingerprint": agent_api._mcp_config_fingerprint(config.product_info),
                    "updated_at": "2026-07-19T00:00:00+00:00",
                    "error": "",
                    "loaded_directories": 2,
                    "total_directories": 2,
                },
            },
        })
        return True

    monkeypatch.setattr(agent_api, "get_scan_store", lambda: Store())
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", live_agent))
    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    user = User(user_id="user-1", username="owner", role="user")

    status = asyncio.run(agent_api.get_stable_agent_mcp_status("stable-agent", user))

    assert status.product_info.runtime.state == "connected"
    assert status.product_info.runtime.loaded_directories == 2
    assert status.product_info.runtime.total_directories == 2
    assert status.code_graph.runtime.state == "unknown"
    assert agent_api._mcp_status_waiters == {}


def test_agent_mcp_reload_sends_target_and_cleans_up_waiter(monkeypatch) -> None:
    config = AgentRemoteConfig()
    config.code_graph.enabled = True
    config.code_graph.local.executable = sys.executable
    record = {
        "agent_key": "stable-agent",
        "user_id": "user-1",
        "config_json": config.model_dump_json(),
    }

    class Store:
        def get_agent_record(self, _agent_key):
            return record

    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )

    async def send_result(_agent_id: str, command: dict) -> bool:
        assert command["type"] == "mcp_reload"
        assert command["target"] == "code_graph"
        agent_api._mcp_reload_waiters[command["request_id"]].set_result({"ok": True})
        return True

    monkeypatch.setattr(agent_api, "get_scan_store", lambda: Store())
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", live_agent))
    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    user = User(user_id="user-1", username="owner", role="user")

    result = asyncio.run(agent_api.reload_stable_agent_mcp("stable-agent", "code_graph", user))

    assert result == {"ok": True}
    assert agent_api._mcp_reload_waiters == {}


def test_agent_mcp_probe_column_is_added_to_legacy_agents_table(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """\
        CREATE TABLE agents (
            agent_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL,
            machine_name TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}',
            validator_catalog_json TEXT NOT NULL DEFAULT '{}',
            last_agent_id TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, ip, machine_name)
        )
        """
    )
    connection.commit()
    connection.close()

    store = SqliteScanStore(db_path)
    columns = {
        row[1]
        for row in store._conn.execute("PRAGMA table_info(agents)").fetchall()
    }
    assert "mcp_probe_json" in columns
    store.close()
