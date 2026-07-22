from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.responses import Response

from deephole_client import main as agent_main
from deephole_client import server as agent_server
from backend.api import agent as agent_api
from backend.models import AgentInfo, AgentRemoteConfig, User
import deephole_client.opencode_integration as opencode_config
from task_agent import serve_client
from backend.store.sqlite import SqliteScanStore


class _RuntimeManager:
    def __init__(self, runtime_state: str = "active", active_sessions: int = 0) -> None:
        self.runtime_state = runtime_state
        self.active_sessions = active_sessions

    def config_runtime_status(self) -> dict[str, object]:
        return {
            "runtime_state": self.runtime_state,
            "active_sessions": self.active_sessions,
        }


def _owner() -> User:
    return User(user_id="user-1", username="owner", role="user")


def _live_agent() -> AgentInfo:
    return AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        machine_name="build-host",
        ip="10.0.0.8",
        last_seen="2026-07-21T01:00:00+00:00",
        user_id="user-1",
    )


def _create_store(tmp_path: Path) -> SqliteScanStore:
    store = SqliteScanStore(tmp_path / "scan.db")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="session-1",
        last_seen="2026-07-21T01:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    return store


def _snapshot(content: str) -> dict[str, object]:
    raw = content.encode("utf-8")
    return {
        "exists": True,
        "content": content,
        "path": "/agent/home/.opendeephole/opencode_workspace/opencode.json",
        "captured_at": "2026-07-21T01:02:03+00:00",
        "modified_at": "2026-07-21T01:01:00+00:00",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "runtime_state": "active",
        "active_sessions": 1,
    }


def test_agent_reads_exact_runtime_file_without_rewriting_it(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config_path = workspace / "opencode.json"
    content = '{\n  "mcp": {"deephole-code": {"type": "remote"}},\n  "model": "corp/model"\n}\n'
    config_path.write_text(content, encoding="utf-8")
    before = config_path.stat().st_mtime_ns
    monkeypatch.setattr(opencode_config, "_GLOBAL_WORKSPACE", workspace)
    monkeypatch.setattr(
        serve_client,
        "get_serve_manager",
        lambda: _RuntimeManager("reload_pending", 2),
    )

    result = asyncio.run(agent_server.handle_opencode_runtime_config("request-1"))

    assert result["ok"] is True
    assert result["exists"] is True
    assert result["content"] == content
    assert result["path"] == str(config_path)
    assert result["runtime_state"] == "reload_pending"
    assert result["active_sessions"] == 2
    assert result["size_bytes"] == len(content.encode("utf-8"))
    assert config_path.stat().st_mtime_ns == before


def test_agent_missing_runtime_file_does_not_initialize_workspace(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "not-created"
    monkeypatch.setattr(opencode_config, "_GLOBAL_WORKSPACE", workspace)
    monkeypatch.setattr(serve_client, "get_serve_manager", lambda: _RuntimeManager("next_task"))

    result = asyncio.run(agent_server.handle_opencode_runtime_config("request-2"))

    assert result["ok"] is True
    assert result["exists"] is False
    assert "尚未生成" in str(result["message"])
    assert not workspace.exists()


def test_agent_command_dispatches_runtime_config_request(monkeypatch) -> None:
    handler = AsyncMock(return_value={"type": "opencode_runtime_config_result", "ok": True})
    monkeypatch.setattr(agent_server, "handle_opencode_runtime_config", handler)

    result = asyncio.run(agent_main._handle_command(
        {"type": "opencode_runtime_config", "request_id": "request-3"},
        None,
        None,
        None,
    ))

    assert result == {"type": "opencode_runtime_config_result", "ok": True}
    handler.assert_awaited_once_with(request_id="request-3")


def test_live_runtime_config_is_masked_persisted_and_explicitly_revealed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _create_store(tmp_path)
    content = json.dumps({
        "model": "corp/model",
        "provider": {"corp": {"options": {"apiKey": "secret-value", "region": "cn"}}},
        "mcp": {"deephole-code": {"type": "remote"}},
    }, ensure_ascii=False, indent=2) + "\n"
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", _live_agent()))

    async def send_result(_agent_id: str, command: dict) -> bool:
        assert command["type"] == "opencode_runtime_config"
        agent_api._opencode_runtime_config_waiters[command["request_id"]].set_result({
            "ok": True,
            **_snapshot(content),
        })
        return True

    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    response = Response()
    masked = asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
        "stable-agent",
        response,
        refresh=True,
        include_secrets=False,
        current_user=_owner(),
    ))

    assert response.headers["cache-control"] == "no-store"
    assert masked.source == "live"
    assert masked.exists is True
    assert masked.redacted is True
    masked_json = json.loads(masked.content)
    assert masked_json["provider"]["corp"]["options"]["apiKey"] == "***"
    assert masked_json["provider"]["corp"]["options"]["region"] == "cn"
    assert masked_json["mcp"]["deephole-code"]["type"] == "remote"
    persisted = json.loads(store.get_agent_record("stable-agent")["opencode_runtime_config_json"])
    assert "secret-value" in persisted["content"]

    revealed = asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
        "stable-agent",
        Response(),
        refresh=False,
        include_secrets=True,
        current_user=_owner(),
    ))
    assert revealed.source == "snapshot"
    assert revealed.redacted is False
    assert revealed.content == content
    assert agent_api._opencode_runtime_config_waiters == {}
    store.close()


def test_offline_runtime_config_uses_latest_snapshot(tmp_path: Path, monkeypatch) -> None:
    store = _create_store(tmp_path)
    content = '{"token":"offline-secret","model":"corp/model"}\n'
    store.update_agent_opencode_runtime_config_record(
        "stable-agent",
        json.dumps(_snapshot(content), ensure_ascii=False),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: None)

    result = asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
        "stable-agent",
        Response(),
        current_user=_owner(),
    ))

    assert result.online is False
    assert result.source == "snapshot"
    assert result.exists is True
    assert json.loads(result.content)["token"] == "***"
    assert "历史快照" in result.warning
    store.close()


def test_live_missing_file_does_not_masquerade_snapshot_as_current(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _create_store(tmp_path)
    store.update_agent_opencode_runtime_config_record(
        "stable-agent",
        json.dumps(_snapshot('{"model":"old/model"}\n')),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", _live_agent()))

    async def send_result(_agent_id: str, command: dict) -> bool:
        agent_api._opencode_runtime_config_waiters[command["request_id"]].set_result({
            "ok": True,
            "exists": False,
            "path": "/agent/home/.opendeephole/opencode_workspace/opencode.json",
            "captured_at": "2026-07-21T02:00:00+00:00",
            "runtime_state": "next_task",
            "active_sessions": 0,
            "message": "OpenCode Serve 尚未生成 opencode.json",
        })
        return True

    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    result = asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
        "stable-agent",
        Response(),
        current_user=_owner(),
    ))

    assert result.source == "live"
    assert result.exists is False
    assert result.content == ""
    assert "尚未生成" in result.warning
    store.close()


def test_runtime_config_timeout_falls_back_to_snapshot(tmp_path: Path, monkeypatch) -> None:
    store = _create_store(tmp_path)
    store.update_agent_opencode_runtime_config_record(
        "stable-agent",
        json.dumps(_snapshot('{"model":"cached/model"}\n')),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", _live_agent()))
    monkeypatch.setattr(
        agent_api,
        "_request_agent_opencode_runtime_config",
        AsyncMock(return_value=(None, "读取 Agent 当前 opencode.json 超时")),
    )

    result = asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
        "stable-agent",
        Response(),
        current_user=_owner(),
    ))

    assert result.online is True
    assert result.source == "snapshot"
    assert "超时" in result.warning
    assert "历史快照" in result.warning
    store.close()


def test_runtime_config_route_enforces_agent_owner(tmp_path: Path, monkeypatch) -> None:
    store = _create_store(tmp_path)
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    other = User(user_id="user-2", username="other", role="user")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(agent_api.get_stable_agent_opencode_runtime_config(
            "stable-agent",
            Response(),
            current_user=other,
        ))

    assert excinfo.value.status_code == 403
    store.close()


def test_runtime_config_column_is_added_to_legacy_agents_table(tmp_path: Path) -> None:
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
            mcp_probe_json TEXT NOT NULL DEFAULT '{}',
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
    assert "opencode_runtime_config_json" in columns
    store.close()
