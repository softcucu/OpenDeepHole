import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from task_agent.serve_client import (
    OpenCodeFileWrite,
    OpenCodeModelInfo,
    OpenCodeModelListResult,
    OpenCodePromptResult,
    OpenCodeProviderQuotaError,
    OpenCodeServeStartupError,
    OpenCodeTaskQualityError,
    OpenCodeServeKey,
    OpenCodeServeManager,
    _ScanMcpLease,
    _ServeEventState,
    _ServeHealthResult,
    _ServeStartupLogCursor,
    _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
    _SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS,
    _EventChannelRuntime,
    _FILE_WRITE_PLUGIN_HASH,
    _FILE_WRITE_PLUGIN_SOURCE,
    _KNOWLEDGE_PROJECT_PLUGIN_HASH,
    _KNOWLEDGE_PROJECT_PLUGIN_SOURCE,
    _config_hash,
    _executable_argv,
    _flush_event_state_periodically,
    _handle_serve_event,
    _log_serve_startup_output_updates,
    _message_token_entries,
    _next_event_reconnect_delay,
    _opencode_mcp_tool_ids,
    _opencode_mcp_tool_prefixes,
    _port_bind_error,
    _run_command_text_async,
    _session_tree_token_entries,
    _serve_context_headers,
    _serve_port,
    _serve_startup_env_debug,
    _serve_startup_shell_debug,
    _stop_command_probe_process,
    _token_usage_delta,
    _tool_matches_mcp_tool,
    _write_knowledge_binding,
    _write_command_binding,
    _write_serve_config_file,
    _validate_required_command_audit,
)


@pytest.fixture(autouse=True)
def _short_event_drain_for_tests(monkeypatch) -> None:
    monkeypatch.setattr(
        "task_agent.serve_client._SERVE_EVENT_DRAIN_TIMEOUT_SECONDS",
        0.05,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._port_bind_error",
        lambda _port: None,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._run_command_text",
        lambda cmd, timeout=3.0: "test-version" if "--version" in cmd else "",
    )

    async def fake_async_command_text(cmd, timeout=3.0):
        del timeout
        return "test-version" if "--version" in cmd else ""

    monkeypatch.setattr(
        "task_agent.serve_client._run_command_text_async",
        fake_async_command_text,
    )
    _FakeAsyncClient.message_parts = None
    _FakeAsyncClient.message_info = None
    _FakeAsyncClient.session_messages = []
    yield
    _FakeAsyncClient.message_parts = None
    _FakeAsyncClient.message_info = None
    _FakeAsyncClient.session_messages = []


class _FakeResponse:
    def __init__(
        self,
        data,
        *,
        error: Exception | None = None,
        status_code: int = 200,
        content_type: str = "application/json",
        json_error: Exception | None = None,
        content: bytes | None = None,
    ) -> None:
        self._data = data
        self._error = error
        self._json_error = json_error
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.json_calls = 0
        self.content = (
            content
            if content is not None
            else (b"" if data is None else b"json")
        )

    def json(self):
        self.json_calls += 1
        if self._json_error is not None:
            raise self._json_error
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
    message_parts: list[dict] | None = None
    session_messages: list[dict] = []

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
        if path.startswith("/session/") and path.endswith("/message"):
            return _FakeResponse(self.session_messages)
        return _FakeResponse({})

    async def post(self, path: str, **kwargs):
        self.posts.append({"path": path, **kwargs})
        if path == "/session":
            return _FakeResponse({"id": "session-1"})
        if path.startswith("/session/") and path.endswith("/message"):
            await asyncio.sleep(0)
            data = {
                "parts": (
                    self.message_parts
                    if self.message_parts is not None
                    else [{"type": "text", "text": self.message_text}]
                )
            }
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


def test_session_tree_token_usage_deduplicates_baseline_and_prefers_step_finish() -> None:
    old_message = {
        "info": {
            "id": "msg-old", "role": "assistant",
            "providerID": "provider-a", "modelID": "model-a",
            "tokens": {"input": 2, "output": 3},
        },
        "parts": [],
    }
    new_message = {
        "info": {
            "id": "msg-new", "role": "assistant",
            "providerID": "provider-a", "modelID": "model-a",
            "tokens": {"input": 999, "output": 999},
        },
        "parts": [
            {
                "id": "step-1", "type": "step-finish",
                "tokens": {
                    "input": 10, "output": 4, "reasoning": 2,
                    "cache": {"read": 5, "write": 1},
                },
            },
            {
                "id": "step-2", "type": "step-finish",
                "tokens": {"input": 3, "output": 1},
            },
        ],
    }
    child_message = {
        "info": {
            "id": "msg-child", "role": "assistant",
            "providerID": "provider-b", "modelID": "model-b",
            "tokens": {
                "input": 7, "output": 2, "reasoning": 1,
                "cache": {"read": 3, "write": 0},
            },
        },
        "parts": [],
    }

    class TreeClient:
        async def get(self, path: str, **_kwargs):
            values = {
                "/session/root/message": [old_message, new_message],
                "/session/root/children": [{"id": "child"}],
                "/session/child/message": [child_message],
                "/session/child/children": [],
            }
            return _FakeResponse(values[path])

    async def run() -> None:
        baseline = _message_token_entries("root", old_message, "")
        after, complete = await _session_tree_token_entries(
            TreeClient(), "root", {}, {}, ""
        )
        usage = _token_usage_delta(baseline, after, complete=complete)

        assert usage.complete is True
        assert usage.counters.input_tokens == 20
        assert usage.counters.output_tokens == 7
        assert usage.counters.reasoning_tokens == 3
        assert usage.counters.cache_read_tokens == 8
        assert usage.counters.cache_write_tokens == 1
        assert usage.counters.total_tokens == 39
        assert {
            item.model: item.counters.total_tokens for item in usage.by_model
        } == {
            "provider-a/model-a": 26,
            "provider-b/model-b": 13,
        }

    asyncio.run(run())


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
            "task_agent.serve_client.httpx.AsyncClient",
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
            serve_port_auto=True,
            env_overrides={
                "HTTPS_PROXY": "http://127.0.0.1:3131",
                "NO_PROXY": "127.0.0.1,localhost",
            },
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
            serve_port_auto=True,
            env_overrides={
                "HTTPS_PROXY": "http://127.0.0.1:3131",
                "NO_PROXY": "127.0.0.1,localhost",
            },
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
        expected_env_overrides = (("NO_PROXY", "127.0.0.1,localhost"),)
        expected_env_hash = hashlib.sha256(
            json.dumps(expected_env_overrides, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        assert manager._acquire_session.await_args.args[0] == OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            env_hash=expected_env_hash,
            config_hash=expected_hash,
            serve_port_auto=True,
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
        assert [item for item in session_client.gets if item["path"] == "/experimental/tool/ids"] == [{
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


@pytest.mark.parametrize("match_mode", ["exact", "bound_python_script"])
def test_run_prompt_allows_optional_command_without_completion_audit(
    monkeypatch,
    tmp_path: Path,
    match_mode: str,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.init_options = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read", "bash"]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        runtime = tmp_path / "runtime"
        project.mkdir()
        runtime.mkdir()
        command = f'python "{project / "validate.py"}"'

        with (
            patch(
                "task_agent.serve_client._write_command_binding",
                wraps=_write_command_binding,
            ) as binding_mock,
            patch(
                "task_agent.serve_client._validate_required_command_audit"
            ) as audit_mock,
        ):
            lines = await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=project,
                config_workspace=runtime,
                prompt="write artifacts",
                model="provider/model",
                timeout=30,
                allowed_bash_commands=(command,),
                bash_command_match_mode=match_mode,
            )

        assert lines == ["done"]
        assert binding_mock.call_args.kwargs["required_commands"] == (command,)
        assert binding_mock.call_args.kwargs["bash_command_match_mode"] == match_mode
        audit_mock.assert_not_called()
        assert not list(
            (runtime / ".opendeephole-plugins" / "command-bindings").glob("*")
        )
        assert not list(
            (runtime / ".opendeephole-plugins" / "command-audits").glob("*")
        )

    asyncio.run(run())


def test_run_prompt_binds_knowledge_project_and_hides_control_tools(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.tool_ids = ["read"]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._remove_file",
            lambda _path: None,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        manager._release_scan_mcp = AsyncMock()
        manager._disable_scan_mcp_lease = AsyncMock()

        async def acquire(
            _client,
            _directory,
            _scan_id,
            _config,
            *,
            role="code_graph",
            source_graph=True,
        ):
            del source_graph
            return _ScanMcpLease(
                directory_key="directory",
                state_key=role,
                identity=role,
                name="product-info" if role == "knowledge_base" else "",
                fingerprint=role,
                connected=role == "knowledge_base",
                role=role,
            )

        manager._acquire_scan_mcp = acquire
        project = tmp_path / "project"
        runtime = tmp_path / "runtime"
        project.mkdir()
        runtime.mkdir()
        knowledge = {
            "enabled": True,
            "name": "product-info",
            "transport": "remote",
            "timeout_seconds": 300,
            "remote": {"url": "http://knowledge.test/mcp", "headers": {}},
            "project_id": "db3dc782-0c5c-4c99-921b-96805e68e502",
            "project_name": "5G-gnodeb",
            "projects_tool": "xxx_projects",
            "set_project_tool": "xxx_set_project",
        }

        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=runtime,
            prompt="business prompt",
            model="provider/model",
            timeout=30,
            scan_id="scan-a",
            knowledge_base_mcp=knowledge,
        )

        assert lines == ["done"]
        client = _FakeAsyncClient.instances[0]
        messages = [
            item for item in client.posts
            if item["path"].endswith("/message")
        ]
        assert len(messages) == 1
        assert messages[0]["json"]["parts"] == [{
            "type": "text",
            "text": "business prompt",
        }]
        assert "system" not in messages[0]["json"]
        assert knowledge["project_id"] not in json.dumps(messages[0]["json"])
        assert messages[0]["json"]["tools"] == {
            "read": True,
            "product-info_*": True,
            "mcp__product-info__*": True,
            "mcp--product-info--*": True,
            "product-info_xxx_projects": False,
            "mcp__product-info__xxx_projects": False,
            "mcp--product-info--xxx_projects": False,
            "product-info_xxx_set_project": False,
            "mcp__product-info__xxx_set_project": False,
            "mcp--product-info--xxx_set_project": False,
        }
        tool_rules = list(messages[0]["json"]["tools"].items())
        assert max(
            index for index, (name, _enabled) in enumerate(tool_rules)
            if name.endswith("*")
        ) < min(
            index for index, (name, _enabled) in enumerate(tool_rules)
            if name.endswith("xxx_projects") or name.endswith("xxx_set_project")
        )
        assert [
            item for item in client.gets
            if item["path"] == "/experimental/tool/ids"
        ] == [client.gets[0]]
        binding_path = (
            runtime
            / ".opendeephole-plugins"
            / "knowledge-bindings"
            / f"{hashlib.sha256(b'session-1').hexdigest()}.json"
        )
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        assert binding["version"] == 2
        assert binding["project_id"] == knowledge["project_id"]
        assert binding["tool_id_prefixes"] == [
            "product-info_",
            "mcp__product-info__",
            "mcp--product-info--",
        ]
        assert binding["blocked_tool_ids"] == [
            "product-info_xxx_projects",
            "mcp__product-info__xxx_projects",
            "mcp--product-info--xxx_projects",
            "product-info_xxx_set_project",
            "mcp__product-info__xxx_set_project",
            "mcp--product-info--xxx_set_project",
        ]
        manager._disable_scan_mcp_lease.assert_not_awaited()

    asyncio.run(run())


def test_run_prompt_disables_knowledge_tools_when_binding_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.tool_ids = ["read"]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._write_knowledge_binding",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        manager._release_scan_mcp = AsyncMock()
        manager._disable_scan_mcp_lease = AsyncMock()

        async def acquire(
            _client,
            _directory,
            _scan_id,
            _config,
            *,
            role="code_graph",
            source_graph=True,
        ):
            del source_graph
            return _ScanMcpLease(
                directory_key="directory",
                state_key=role,
                identity=role,
                name="product-info" if role == "knowledge_base" else "",
                fingerprint=role,
                connected=role == "knowledge_base",
                role=role,
            )

        manager._acquire_scan_mcp = acquire
        project = tmp_path / "project"
        runtime = tmp_path / "runtime"
        project.mkdir()
        runtime.mkdir()
        lines = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            config_workspace=runtime,
            prompt="continue anyway",
            model="provider/model",
            timeout=30,
            scan_id="scan-a",
            knowledge_base_mcp={
                "enabled": True,
                "name": "product-info",
                "transport": "remote",
                "remote": {"url": "http://knowledge.test/mcp", "headers": {}},
                "project_id": "project-1",
                "project_name": "Project One",
                "projects_tool": "xxx_projects",
                "set_project_tool": "xxx_set_project",
            },
        )

        assert lines == ["done"]
        message = next(
            item for item in _FakeAsyncClient.instances[0].posts
            if item["path"].endswith("/message")
        )
        assert message["json"]["tools"]["read"] is True
        assert message["json"]["tools"] == {
            "read": True,
            "product-info_*": False,
            "mcp__product-info__*": False,
            "mcp--product-info--*": False,
        }
        manager._disable_scan_mcp_lease.assert_awaited_once()

    asyncio.run(run())


def test_knowledge_plugin_overwrites_project_id_without_chat_messages() -> None:
    assert "output.args.project_id = binding.project_id" in (
        _KNOWLEDGE_PROJECT_PLUGIN_SOURCE
    )
    assert '"tool.execute.before"' in _KNOWLEDGE_PROJECT_PLUGIN_SOURCE
    assert "chat.message" not in _KNOWLEDGE_PROJECT_PLUGIN_SOURCE


def test_knowledge_plugin_enforces_binding_for_parent_and_child_sessions(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    _write_serve_config_file(runtime, "{}")
    _write_knowledge_binding(
        runtime,
        session_id="parent-session",
        project_id="selected-project",
        mcp_name="llm-wiki",
        blocked_tool_ids=list(_opencode_mcp_tool_ids(
            "llm-wiki",
            "llm_wiki_projects",
        )),
    )
    plugin_path = (
        runtime
        / ".opendeephole-plugins"
        / f"opendeephole-knowledge-project-{_KNOWLEDGE_PROJECT_PLUGIN_HASH}.mjs"
    )
    script = r'''
import assert from "node:assert/strict"
import { pathToFileURL } from "node:url"

const plugin = await import(pathToFileURL(process.argv[1]).href)
const hooks = await plugin.OpenDeepHoleKnowledgeProjectHook()
const before = hooks["tool.execute.before"]

const parentArgs = { project_id: "wrong", query: "parent" }
await before(
  { sessionID: "parent-session", tool: "llm-wiki_search_docs" },
  { args: parentArgs },
)
assert.equal(parentArgs.project_id, "selected-project")

await hooks.event({
  event: {
    type: "session.created",
    properties: { info: { id: "child-session", parentID: "parent-session" } },
  },
})
const childArgs = { query: "child" }
await before(
  { sessionID: "child-session", tool: "llm-wiki_lookup_symbol" },
  { args: childArgs },
)
assert.equal(childArgs.project_id, "selected-project")

const unrelatedArgs = { project_id: "unchanged" }
await before(
  { sessionID: "parent-session", tool: "other-mcp_search_docs" },
  { args: unrelatedArgs },
)
assert.equal(unrelatedArgs.project_id, "unchanged")

await assert.rejects(
  before(
    { sessionID: "parent-session", tool: "llm-wiki_llm_wiki_projects" },
    { args: {} },
  ),
  /platform-only/,
)
'''
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(plugin_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_managed_file_write_plugin_allows_only_bound_command_for_parent_and_child(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    _write_serve_config_file(runtime, "{}")
    command = "python validate.py --input result.json"
    marker = "VALID: artifacts passed"
    python_bin = str(tmp_path / "python-bin")
    binding_path, audit_path = _write_command_binding(
        runtime,
        session_id="parent-session",
        required_commands=(command,),
        success_markers=((command, marker),),
        path_prepend=(python_bin,),
    )
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    assert binding["version"] == 2
    assert binding["success_markers"] == {command: marker}
    assert binding["path_prepend"] == [python_bin]
    plugin_path = (
        runtime
        / ".opendeephole-plugins"
        / f"opendeephole-file-write-{_FILE_WRITE_PLUGIN_HASH}.mjs"
    )
    script = r'''
import assert from "node:assert/strict"
import { pathToFileURL } from "node:url"

const command = process.argv[2]
const marker = process.argv[3]
const pythonBin = process.argv[4]
const plugin = await import(pathToFileURL(process.argv[1]).href)
const hooks = await plugin.OpenDeepHoleFileWriteHook({ directory: process.cwd() })
const before = hooks["tool.execute.before"]
const after = hooks["tool.execute.after"]
const shellEnv = hooks["shell.env"]

const envOutput = { env: { PATH: "/usr/bin" } }
await shellEnv({ sessionID: "parent-session" }, envOutput)
assert.equal(envOutput.env.PATH.split(process.platform === "win32" ? ";" : ":")[0], pythonBin)

await before(
  { sessionID: "parent-session", tool: "bash" },
  { args: { command } },
)
await assert.rejects(
  before(
    { sessionID: "parent-session", tool: "bash" },
    { args: { command: `${command} && echo chained` } },
  ),
  /not bound/,
)
await hooks.event({
  event: {
    type: "session.created",
    properties: { info: { id: "child-session", parentID: "parent-session" } },
  },
})
await before(
  { sessionID: "child-session", tool: "shell" },
  { args: { command } },
)
await after(
  {
    sessionID: "child-session",
    tool: "write",
    callID: "write-1",
    args: { filePath: "result.json" },
  },
  { metadata: { filepath: "result.json" } },
)
await after(
  {
    sessionID: "child-session",
    tool: "bash",
    callID: "bash-1",
    args: { command },
  },
  { output: `validator diagnostics\n${marker}\n`, metadata: {} },
)
'''
    completed = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            script,
            str(plugin_path),
            command,
            marker,
            python_bin,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    _validate_required_command_audit(audit_path, (command,))
    events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["kind"] for event in events] == ["file_write", "command"]
    assert events[-1]["session_id"] == "child-session"
    assert events[-1]["exit_code"] is None
    assert events[-1]["success_source"] == "output_marker"
    assert marker in events[-1]["output_tail"]


def test_required_command_audit_rejects_failure_and_post_validation_write(
    tmp_path: Path,
) -> None:
    command = "python validate.py"
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(
        json.dumps({
            "version": 1,
            "kind": "command",
            "command": command,
            "exit_code": 1,
            "success": False,
            "output_tail": "schema mismatch in value-assets.json",
            "output_bytes": 36,
            "output_truncated": True,
        })
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(OpenCodeTaskQualityError, match="exit=1") as exc_info:
        _validate_required_command_audit(audit_path, (command,))
    assert exc_info.value.failure_kind == "command_exit_failure"
    assert exc_info.value.command_failures[0].command == command
    assert exc_info.value.command_failures[0].exit_code == 1
    assert exc_info.value.command_failures[0].output_tail == (
        "schema mismatch in value-assets.json"
    )
    assert exc_info.value.command_failures[0].output_truncated is True

    audit_path.write_text(
        "\n".join((
            json.dumps({
                "version": 1,
                "kind": "command",
                "command": command,
                "exit_code": 0,
                "success": True,
            }),
            json.dumps({
                "version": 1,
                "kind": "file_write",
                "path": str(tmp_path / "result.json"),
            }),
        ))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(OpenCodeTaskQualityError, match="modified task files"):
        _validate_required_command_audit(audit_path, (command,))


def test_opencode_mcp_tool_ids_match_official_sanitization_and_legacy_formats() -> None:
    assert _opencode_mcp_tool_prefixes("llm.wiki") == (
        "llm_wiki_",
        "mcp__llm_wiki__",
        "mcp--llm_wiki--",
    )
    assert _opencode_mcp_tool_ids("llm.wiki", "lookup/docs") == (
        "llm_wiki_lookup_docs",
        "mcp__llm_wiki__lookup_docs",
        "mcp--llm_wiki--lookup_docs",
    )


@pytest.mark.parametrize(
    "tool_id",
    [
        "product-info_xxx_projects",
        "mcp__product-info__xxx_projects",
        "mcp--product-info--xxx_projects",
    ],
)
def test_knowledge_control_tool_matching_supports_opencode_id_formats(
    tool_id: str,
) -> None:
    assert _tool_matches_mcp_tool(
        tool_id,
        "product-info",
        "xxx_projects",
    )


def test_run_prompt_marks_serve_unhealthy_when_session_creation_returns_500(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class SessionCreate500Client(_FakeAsyncClient):
        async def post(self, path: str, **kwargs):
            self.posts.append({"path": path, **kwargs})
            if path == "/session":
                request = httpx.Request("POST", "http://127.0.0.1:12345/session")
                response = httpx.Response(500, request=request)
                return _FakeResponse(
                    {"error": "internal"},
                    status_code=500,
                    error=httpx.HTTPStatusError(
                        "session creation failed",
                        request=request,
                        response=response,
                    ),
                )
            return await super().post(path, **kwargs)

    async def run() -> None:
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            SessionCreate500Client,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()

        with pytest.raises(httpx.HTTPStatusError, match="session creation failed"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=project,
                prompt="hello",
                model="provider/model",
                timeout=30,
            )

        assert manager._restart_required is True
        assert manager._serve_failure_generation == 1

    asyncio.run(run())


def test_run_prompt_tracks_final_response_file_writes_without_output_callback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["write"]
        _FakeAsyncClient.message_info = None
        _FakeAsyncClient.message_parts = [
            {
                "id": "part-write",
                "type": "tool",
                "callID": "call-write",
                "tool": "write",
                "state": {
                    "status": "completed",
                    "input": {
                        "filePath": "result.json",
                        "content": '{"answer": 1}',
                    },
                    "metadata": {
                        "filepath": "result.json",
                        "exists": False,
                    },
                },
            },
            {"type": "text", "text": "done"},
        ]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        writes: list[OpenCodeFileWrite] = []

        details = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="write json",
            model="provider/model",
            timeout=30,
            on_file_write=writes.append,
            return_details=True,
        )

        assert isinstance(details, OpenCodePromptResult)
        assert details.text == "done"
        assert writes == [
            OpenCodeFileWrite(
                call_id="call-write",
                path="result.json",
                created=True,
            )
        ]
        assert manager._event_states == {}

    asyncio.run(run())


def test_run_prompt_replays_intermediate_message_file_writes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        project = tmp_path / "project"
        project.mkdir()
        tool_part = {
            "id": "part-intermediate-write",
            "type": "tool",
            "callID": "call-intermediate-write",
            "tool": "write",
            "state": {
                "status": "completed",
                "input": {
                    "filePath": "intermediate.json",
                    "content": '{"answer": 1}',
                },
                "metadata": {
                    "opendeepholeFileWrites": {
                        "version": 1,
                        "sessionID": "session-1",
                        "callID": "call-intermediate-write",
                        "files": [{
                            "path": str(project / "intermediate.json"),
                            "created": True,
                        }],
                    },
                },
            },
        }
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["write"]
        _FakeAsyncClient.message_info = {
            "id": "message-final",
            "sessionID": "session-1",
            "role": "assistant",
        }
        _FakeAsyncClient.message_parts = [
            {"id": "part-final", "type": "text", "text": "written"},
        ]
        _FakeAsyncClient.session_messages = [
            {
                "info": {
                    "id": "message-intermediate",
                    "sessionID": "session-1",
                    "role": "assistant",
                },
                "parts": [tool_part],
            },
            {
                "info": _FakeAsyncClient.message_info,
                "parts": _FakeAsyncClient.message_parts,
            },
        ]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        writes: list[OpenCodeFileWrite] = []

        details = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="write json",
            model="provider/model",
            timeout=30,
            on_file_write=writes.append,
            return_details=True,
        )

        assert isinstance(details, OpenCodePromptResult)
        assert details.text == "written"
        assert writes == [
            OpenCodeFileWrite(
                call_id="call-intermediate-write",
                path=str(project / "intermediate.json"),
                created=True,
            )
        ]
        history_gets = [
            item
            for item in _FakeAsyncClient.instances[0].gets
            if item["path"] == "/session/session-1/message"
            and item.get("params", {}).get("limit") == "1000"
        ]
        assert history_gets

    asyncio.run(run())


def test_run_prompt_disable_all_tools_overrides_builtins_and_mcp(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = [
            "read",
            "write",
            "mcp__deephole-code__view_function_code",
        ]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="format only",
            model="provider/model",
            timeout=30,
            disable_all_tools=True,
        )

        client = _FakeAsyncClient.instances[0]
        message = next(
            item for item in client.posts
            if item["path"] == "/session/session-1/message"
        )
        assert message["json"]["tools"]
        assert all(value is False for value in message["json"]["tools"].values())
        assert message["json"]["tools"]["bash"] is False
        assert message["json"]["tools"]["skill"] is False
        assert (
            message["json"]["tools"]["mcp__deephole-code__view_function_code"]
            is False
        )

    asyncio.run(run())


def test_continued_prompt_ignores_previous_message_file_writes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        old_tool_part = {
            "id": "part-old-write",
            "type": "tool",
            "callID": "call-old-write",
            "tool": "write",
            "state": {
                "status": "completed",
                "input": {"filePath": "old.json", "content": "{}"},
                "metadata": {"filepath": "old.json", "exists": False},
            },
        }
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["write"]
        _FakeAsyncClient.session_messages = [{
            "info": {
                "id": "message-old",
                "sessionID": "session-1",
                "role": "assistant",
            },
            "parts": [old_tool_part],
        }]
        _FakeAsyncClient.message_info = {
            "id": "message-current",
            "sessionID": "session-1",
            "role": "assistant",
        }
        _FakeAsyncClient.message_parts = [{
            "id": "part-current-write",
            "type": "tool",
            "callID": "call-current-write",
            "tool": "write",
            "state": {
                "status": "completed",
                "input": {"filePath": "current.json", "content": "{}"},
                "metadata": {"filepath": "current.json", "exists": False},
            },
        }]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        writes: list[OpenCodeFileWrite] = []

        await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="continue",
            model="provider/model",
            timeout=30,
            session_id="session-1",
            on_file_write=writes.append,
        )

        assert writes == [
            OpenCodeFileWrite(
                call_id="call-current-write",
                path="current.json",
                created=True,
            )
        ]
        session_client = _FakeAsyncClient.instances[0]
        assert any(
            item["path"] == "/session/session-1/message"
            and item["params"].get("limit") == "2"
            for item in session_client.gets
        )

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
            "task_agent.serve_client.httpx.AsyncClient",
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
            log_stage="validation",
        )

        assert output[0] == (
            "[validation][pending][task] "
            "SERVE PREPARING executable=opencode port=12345 port_mode=fixed"
        )
        assert output[1] == (
            f"[validation][pending][task] SERVE READY mode={serve_mode} "
            "url=http://127.0.0.1:12345 pid=24680"
        )
        assert any(
            line.startswith("[validation][session-1][session] START mode=created")
            for line in output
        )
        assert output[-1] == (
            "[validation][session-1][session] "
            "STOP status=success retained=true"
        )
        assert all("done" not in line for line in output)

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
        request_failures: list[str] = []

        with pytest.raises(RuntimeError, match="did not become healthy"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="hello",
                model="provider/model",
                timeout=30,
                on_line=output.append,
                on_model_request_failure=request_failures.append,
                show_serve_status=True,
            )

        assert request_failures == []
        assert output[0].startswith("[opencode][pending][task] SERVE PREPARING")
        assert output[1].startswith("[opencode][pending][task] SERVE STARTUP_FAILED")
        assert "provider failed to load" in output[1]

    asyncio.run(run())


def test_run_prompt_reports_message_request_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FailingMessageAsyncClient(_FakeAsyncClient):
        async def post(self, path: str, **kwargs):
            response = await super().post(path, **kwargs)
            if path.startswith("/session/") and path.endswith("/message"):
                response._error = RuntimeError("provider request failed")
            return response

    async def run() -> None:
        FailingMessageAsyncClient.instances = []
        FailingMessageAsyncClient.event_lines = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            FailingMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4095
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        request_failures: list[str] = []

        with pytest.raises(RuntimeError, match="provider request failed"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="fail",
                model="provider/model",
                timeout=1,
                on_model_request_failure=request_failures.append,
            )

        assert request_failures == ["failure"]

    asyncio.run(run())


@pytest.mark.parametrize(
    ("response_content", "content_type", "expected_reason"),
    [
        (b"", "application/json", "empty_body"),
        (b"secret provider response body", "text/html", "invalid_json"),
    ],
)
def test_run_prompt_recovers_invalid_message_response_from_session_history(
    monkeypatch,
    tmp_path: Path,
    response_content: bytes,
    content_type: str,
    expected_reason: str,
) -> None:
    recovered_message = {
        "info": {
            "id": "message-recovered",
            "sessionID": "session-1",
            "role": "assistant",
            "providerID": "provider",
            "modelID": "actual",
            "time": {"created": 1, "completed": 2},
        },
        "parts": [{"type": "text", "text": "recovered answer"}],
    }

    class InvalidMessageAsyncClient(_FakeAsyncClient):
        session_messages = [recovered_message]

        async def post(self, path: str, **kwargs):
            if path.startswith("/session/") and path.endswith("/message"):
                self.posts.append({"path": path, **kwargs})
                await asyncio.sleep(0)
                self.message_response = _FakeResponse(
                    None,
                    content_type=content_type,
                    json_error=json.JSONDecodeError("Expecting value", "", 0),
                    content=response_content,
                )
                return self.message_response
            return await super().post(path, **kwargs)

    async def run() -> None:
        InvalidMessageAsyncClient.instances = []
        InvalidMessageAsyncClient.event_lines = []
        InvalidMessageAsyncClient.tool_ids = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            InvalidMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        output: list[str] = []
        request_failures: list[str] = []
        response_models: list[str] = []

        result = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=tmp_path,
            prompt="recover",
            model="provider/requested",
            timeout=1,
            on_line=output.append,
            on_model_request_failure=request_failures.append,
            on_response_model=response_models.append,
            return_details=True,
        )

        assert isinstance(result, OpenCodePromptResult)
        assert result.session_id == "session-1"
        assert result.message_id == "message-recovered"
        assert result.text == "recovered answer"
        assert result.model == "provider/actual"
        assert result.raw == recovered_message
        assert request_failures == []
        assert response_models == ["provider/actual"]
        assert any(
            line == (
                "[opencode][session-1][session] RESPONSE_RECOVERED "
                f"reason={expected_reason} source=session_messages "
                f"status=200 bytes={len(response_content)}"
            )
            for line in output
        )
        assert output[-1] == (
            "[opencode][session-1][session] STOP status=success retained=true"
        )
        assert "secret provider response body" not in "\n".join(output)

    asyncio.run(run())


def test_run_prompt_rejects_stale_session_history_after_empty_response(
    monkeypatch,
    tmp_path: Path,
) -> None:
    previous_message = {
        "info": {
            "id": "message-previous",
            "sessionID": "session-1",
            "role": "assistant",
            "time": {"created": 1, "completed": 2},
        },
        "parts": [{"type": "text", "text": "previous secret answer"}],
    }

    class EmptyMessageAsyncClient(_FakeAsyncClient):
        session_messages = [previous_message]

        async def post(self, path: str, **kwargs):
            if path.startswith("/session/") and path.endswith("/message"):
                self.posts.append({"path": path, **kwargs})
                await asyncio.sleep(0)
                self.message_response = _FakeResponse(
                    None,
                    json_error=json.JSONDecodeError("Expecting value", "", 0),
                    content=b"",
                )
                return self.message_response
            return await super().post(path, **kwargs)

    async def run() -> None:
        EmptyMessageAsyncClient.instances = []
        EmptyMessageAsyncClient.event_lines = []
        EmptyMessageAsyncClient.tool_ids = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            EmptyMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        output: list[str] = []
        request_failures: list[str] = []

        with pytest.raises(RuntimeError) as exc_info:
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="continue",
                model="provider/model",
                timeout=1,
                session_id="session-1",
                on_line=output.append,
                on_model_request_failure=request_failures.append,
            )

        error = str(exc_info.value)
        assert "OpenCode message endpoint returned an empty response body" in error
        assert "status=200" in error
        assert "bytes=0" in error
        assert "no_new_completed_assistant" in error
        assert "Expecting value" not in error
        assert "previous secret answer" not in error
        assert request_failures == ["neutral"]
        assert not any("RESPONSE_RECOVERED" in line for line in output)
        assert output[-1].startswith(
            "[opencode][session-1][session] STOP status=failure retained=true"
        )
        assert "previous secret answer" not in "\n".join(output)

    asyncio.run(run())


def test_run_prompt_classifies_recovered_assistant_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    recovered_error = {
        "info": {
            "id": "message-error",
            "sessionID": "session-1",
            "role": "assistant",
            "providerID": "provider",
            "modelID": "actual",
            "error": {
                "name": "APIError",
                "data": {"message": "recovered provider failure"},
            },
            "time": {"created": 1},
        },
        "parts": [],
    }

    class EmptyMessageAsyncClient(_FakeAsyncClient):
        session_messages = [recovered_error]

        async def post(self, path: str, **kwargs):
            if path.startswith("/session/") and path.endswith("/message"):
                self.posts.append({"path": path, **kwargs})
                return _FakeResponse(
                    None,
                    json_error=json.JSONDecodeError("Expecting value", "", 0),
                    content=b"",
                )
            return await super().post(path, **kwargs)

    async def run() -> None:
        EmptyMessageAsyncClient.instances = []
        EmptyMessageAsyncClient.event_lines = []
        EmptyMessageAsyncClient.tool_ids = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            EmptyMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        output: list[str] = []
        request_failures: list[str] = []
        response_models: list[str] = []

        with pytest.raises(RuntimeError, match="recovered provider failure"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="fail",
                model="provider/model",
                timeout=1,
                on_line=output.append,
                on_model_request_failure=request_failures.append,
                on_response_model=response_models.append,
            )

        assert request_failures == ["failure"]
        assert response_models == ["provider/actual"]
        assert any("RESPONSE_RECOVERED reason=empty_body" in line for line in output)

    asyncio.run(run())


@pytest.mark.parametrize(
    ("error_name", "expected_failures"),
    [
        ("APIError", ["failure"]),
        ("ContextOverflowError", ["neutral"]),
        ("MessageOutputLengthError", ["neutral"]),
        ("StructuredOutputError", ["neutral"]),
        ("MessageAbortedError", ["neutral"]),
    ],
)
def test_run_prompt_rejects_assistant_error_response_and_classifies_health(
    monkeypatch,
    tmp_path: Path,
    error_name: str,
    expected_failures: list[str],
) -> None:
    class AssistantErrorAsyncClient(_FakeAsyncClient):
        message_info = {
            "role": "assistant",
            "providerID": "provider",
            "modelID": "actual",
            "error": {
                "name": error_name,
                "data": {"message": "assistant request failed"},
            },
        }

    async def run() -> None:
        AssistantErrorAsyncClient.instances = []
        AssistantErrorAsyncClient.event_lines = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            AssistantErrorAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        request_failures: list[str] = []
        response_models: list[str] = []

        with pytest.raises(RuntimeError, match="assistant request failed"):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="fail",
                model="provider/model",
                timeout=1,
                on_model_request_failure=request_failures.append,
                on_response_model=response_models.append,
            )

        assert request_failures == expected_failures
        assert response_models == ["provider/actual"]

    asyncio.run(run())


def test_run_prompt_classifies_nested_provider_quota_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    provider_value = {
        "text": "[DONE]",
        "error": {
            "error_msg": json.dumps({
                "type": "RPM",
                "message": "There is no request model quota",
                "identity": "appId",
                "quota": 0,
                "used": 0,
            }),
            "error_code": "InferHub.002002010.429",
        },
        "error_code": "InferHub.002002010.429",
        "error_msg": json.dumps({
            "type": "RPM",
            "message": "There is no request model quota",
            "identity": "appId",
            "quota": 0,
            "used": 0,
        }),
        "retry_after": "-1",
        "need_model_switch": "true",
    }

    class ProviderQuotaAsyncClient(_FakeAsyncClient):
        message_info = {
            "id": "message-quota",
            "sessionID": "session-1",
            "role": "assistant",
            "providerID": "provider",
            "modelID": "actual",
            "error": {
                "name": "UnknownError",
                "data": {
                    "message": (
                        "Type validation failed: Value: "
                        f"{json.dumps(provider_value)}. Error message: invalid_union"
                    ),
                },
            },
        }

    async def run() -> None:
        ProviderQuotaAsyncClient.instances = []
        ProviderQuotaAsyncClient.event_lines = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            ProviderQuotaAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        request_failures: list[str] = []
        output: list[str] = []

        with pytest.raises(OpenCodeProviderQuotaError) as excinfo:
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="fail",
                model="provider/model",
                timeout=1,
                on_model_request_failure=request_failures.append,
                on_line=output.append,
                task_id="task-quota",
                task_attempt=2,
            )

        assert excinfo.value.error_code == "InferHub.002002010.429"
        assert excinfo.value.quota_type == "RPM"
        assert excinfo.value.retry_after_seconds is None
        assert "模型 Provider 请求配额暂不可用 (RPM)" in str(excinfo.value)
        assert "invalid_union" not in str(excinfo.value)
        assert request_failures == ["quota"]
        assert any(
            "START mode=created" in line
            and "task=task-quota attempt=2" in line
            for line in output
        )
        assert output[-1].startswith(
            "[opencode][session-1][session] STOP status=failure retained=true "
            "task=task-quota attempt=2 message=message-quota"
        )

    asyncio.run(run())


def test_run_prompt_prioritizes_active_cancel_over_aborted_assistant_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class AbortedMessageAsyncClient(_FakeAsyncClient):
        message_info = {
            "role": "assistant",
            "error": {
                "name": "MessageAbortedError",
                "data": {"message": "aborted"},
            },
        }

    async def run() -> None:
        AbortedMessageAsyncClient.instances = []
        AbortedMessageAsyncClient.event_lines = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            AbortedMessageAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 4097
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        cancel_event = asyncio.Event()
        cancel_event.set()
        request_failures: list[str] = []

        with pytest.raises(asyncio.CancelledError):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="cancel",
                model="provider/model",
                timeout=1,
                cancel_event=cancel_event,
                on_model_request_failure=request_failures.append,
            )

        assert request_failures == []

    asyncio.run(run())


def test_run_prompt_timeout_aborts_and_reaps_request_before_reuse(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _HangingMessageAsyncClient.instances = []
        _HangingMessageAsyncClient.hang_messages = True
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _HangingMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()
        # This case targets the message deadline, after event preparation.
        manager._register_event_state = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        manager._acquire_session = AsyncMock(side_effect=acquire)
        output: list[str] = []
        request_failures: list[str] = []

        with pytest.raises(asyncio.TimeoutError):
            await manager.run_prompt(
                tool="opencode",
                executable="opencode",
                directory=tmp_path,
                prompt="hang",
                model="provider/model",
                timeout=0.01,
                on_line=output.append,
                on_model_request_failure=request_failures.append,
                log_stage="validation",
            )

        first_client = _HangingMessageAsyncClient.instances[0]
        assert request_failures == ["timeout"]
        assert "/session/session-hanging/abort" in first_client.posts
        assert first_client.message_cancelled is True
        assert manager._active_sessions == 0
        assert manager._event_states == {}
        assert any(
            line.startswith("[validation][session-hanging][session] START mode=created")
            for line in output
        )
        assert output[-1].startswith(
            "[validation][session-hanging][session] STOP status=timeout retained=true"
        )

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
            "task_agent.serve_client.httpx.AsyncClient",
            _HangingMessageAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        manager._acquire_session = AsyncMock(side_effect=acquire)
        output: list[str] = []
        caller = asyncio.create_task(manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=tmp_path,
            prompt="cancel",
            model="provider/model",
            timeout=30,
            on_line=output.append,
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
        assert output[-1] == (
            "[opencode][session-hanging][session] "
            "STOP status=cancelled retained=true"
        )

    asyncio.run(run())


def test_wait_for_response_prioritizes_cancel_over_completed_response() -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        cancel_event = asyncio.Event()

        async def completed_response():
            return _FakeResponse({})

        request = asyncio.create_task(completed_response())
        await asyncio.sleep(0)
        cancel_event.set()

        with pytest.raises(asyncio.CancelledError):
            await manager._wait_for_response(
                request=request,
                timeout=1,
                cancel_event=cancel_event,
            )

    asyncio.run(run())


@pytest.mark.parametrize("phase", [
    "serve_preparation", "managed_mcp", "session_create", "session_abort",
    "request_reap", "token_collection", "http_close", "all_cleanup",
])
def test_prompt_deadline_and_cleanup_bound_all_blocking_phases(monkeypatch, tmp_path, phase):
    async def run():
        gate = asyncio.Event()
        entered = asyncio.Event()
        failures = []
        output = []
        usages = []
        posted = []
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._register_event_state = AsyncMock()

        async def block(*_args):
            entered.set()
            await gate.wait()

        async def acquire(*args, **kwargs):
            if phase == "serve_preparation":
                await block()
            manager._active_sessions += 1
            return "reused"

        class Client(_HangingMessageAsyncClient):
            async def post(self, path, **kwargs):
                posted.append(path)
                if phase == "session_create" and path == "/session":
                    await block()
                if phase in {"session_abort", "all_cleanup"} and path.endswith("/abort"):
                    await block()
                if phase in {"request_reap", "all_cleanup"} and path.endswith("/message"):
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        entered.set()
                        while not gate.is_set():
                            try:
                                await gate.wait()
                            except asyncio.CancelledError:
                                continue
                        return _FakeResponse({"parts": [{"type": "text", "text": "late"}]})
                return await super().post(path, **kwargs)

            async def get(self, path, **kwargs):
                if phase in {"token_collection", "all_cleanup"} and path.endswith("/children"):
                    await block()
                return await super().get(path, **kwargs)

            async def __aexit__(self, *args):
                if phase in {"http_close", "all_cleanup"}:
                    await block()

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client.CLEANUP_TIMEOUT_SECONDS", 0.2)
        monkeypatch.setattr("task_agent.serve_client._SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.03)
        monkeypatch.setattr("task_agent.serve_client._SERVE_REQUEST_REAP_TIMEOUT_SECONDS", 0.03)
        Client.hang_messages = True
        manager._acquire_session = acquire
        manager.ensure_managed_mcp = block if phase == "managed_mcp" else AsyncMock()
        try:
            with pytest.raises(asyncio.TimeoutError, match="OpenCode call timed out"):
                await asyncio.wait_for(manager.run_prompt(
                    tool="opencode", executable="opencode", directory=tmp_path,
                    prompt="hang", model="provider/model", timeout=0.05,
                    on_line=output.append, on_model_request_failure=failures.append,
                    on_token_usage=usages.append,
                ), timeout=1)
            assert entered.is_set()
            assert manager._active_sessions == 0
            assert manager._event_states == {}
            assert any("TIMEOUT phase=" in line for line in output)
            if phase in {"serve_preparation", "managed_mcp", "session_create"}:
                assert failures == []  # Preparation faults do not penalize a model.
                assert not any(path.endswith("/message") for path in posted)
            else:
                assert failures == ["timeout"]
            if phase in {"session_create", "session_abort", "request_reap", "http_close", "all_cleanup"}:
                assert manager._restart_required is True
            before = (list(output), list(usages), list(failures))
            gate.set()
            await asyncio.sleep(0.02)
            assert (output, usages, failures) == before
        finally:
            gate.set()
            await asyncio.sleep(0.02)

    asyncio.run(run())


def test_token_tree_timeout_preserves_partial_counts_and_success(monkeypatch, tmp_path):
    async def run():
        class Client(_FakeAsyncClient):
            async def get(self, path, **kwargs):
                if path == "/session/session-1/message":
                    return _FakeResponse([{
                        "info": {"id": "msg-1", "role": "assistant", "tokens": {"input": 7, "output": 3}},
                    }])
                if path == "/session/session-1/children":
                    return _FakeResponse([{"id": "child"}])
                if path == "/session/child/message":
                    await asyncio.Future()
                return await super().get(path, **kwargs)

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client._SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.02)
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        failures = []
        result = await manager.run_prompt(
            tool="opencode", executable="opencode", directory=tmp_path,
            prompt="success", model="provider/model", timeout=1,
            return_details=True, on_model_request_failure=failures.append,
        )
        assert result.text == "done"
        assert failures == []
        assert result.token_usage.complete is False
        assert result.token_usage.counters.total_tokens == 10

    asyncio.run(run())


@pytest.mark.parametrize("callback_mode", ["blocked", "ignores_cancel", "raises"])
def test_token_callback_failure_preserves_success_and_has_own_budget(monkeypatch, tmp_path, callback_mode):
    async def run():
        release = asyncio.Event()
        entered = asyncio.Event()
        calls = []

        async def callback(usage):
            calls.append(usage)
            entered.set()
            if callback_mode == "raises":
                raise OSError("statistics unavailable")
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    if callback_mode != "ignores_cancel":
                        raise

        class Client(_FakeAsyncClient):
            message_info = {"id": "current", "role": "assistant", "tokens": {"input": 7, "output": 3}}

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client._SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.03)
        monkeypatch.setattr("task_agent.serve_client._SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0.001)
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        failures, output = [], []
        try:
            result = await asyncio.wait_for(manager.run_prompt(
                tool="opencode", executable="opencode", directory=tmp_path,
                prompt="success", model="provider/model", timeout=1,
                return_details=True, on_token_usage=callback,
                on_model_request_failure=failures.append, on_line=output.append,
            ), 0.6)
            assert entered.is_set()
            assert result.text == "done"
            assert result.token_usage.counters.total_tokens == 10
            assert result.token_usage.complete is False
            assert failures == []
            assert len(calls) == 1  # finally must not redeliver a partial callback
            assert any("STOP status=success" in line for line in output)
            assert not any("TIMEOUT" in line for line in output)
        finally:
            release.set()
            await asyncio.sleep(0.01)

    asyncio.run(run())


def test_incomplete_continuation_baseline_does_not_recount_old_tokens(monkeypatch, tmp_path):
    async def run():
        old = {"info": {"id": "old", "role": "assistant", "tokens": {"input": 100, "output": 100}}}

        class Client(_FakeAsyncClient):
            message_info = {"id": "current", "role": "assistant", "tokens": {"input": 3, "output": 2}}

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client._session_tree_token_entries", AsyncMock(side_effect=[
            ({}, False), (_message_token_entries("session-1", old, "provider/model"), True),
        ]))
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        result = await manager.run_prompt(
            tool="opencode", executable="opencode", directory=tmp_path,
            prompt="continue", model="provider/model", timeout=1,
            session_id="session-1", return_details=True,
        )
        assert result.token_usage.complete is False
        assert result.token_usage.counters.total_tokens == 5

    asyncio.run(run())


def test_token_cleanup_does_not_replace_original_request_error(monkeypatch, tmp_path):
    async def run():
        class Client(_FakeAsyncClient):
            async def post(self, path, **kwargs):
                if path.endswith("/message"):
                    return _FakeResponse({}, error=RuntimeError("original request failure"))
                return await super().post(path, **kwargs)

            async def get(self, path, **kwargs):
                if path.endswith("/children"):
                    await asyncio.Future()
                return await super().get(path, **kwargs)

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client._SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.1)
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        failures = []
        with pytest.raises(RuntimeError, match="original request failure"):
            await asyncio.wait_for(manager.run_prompt(
                tool="opencode", executable="opencode", directory=tmp_path,
                prompt="fail", model="provider/model", timeout=0.03,
                on_model_request_failure=failures.append,
            ), timeout=1)
        assert failures == ["failure"]

    asyncio.run(run())


def test_cancelled_prompt_does_not_cancel_shared_mcp_sync(monkeypatch, tmp_path):
    async def run():
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager._managed_mcp_specs = {"product_info": {}}
        manager._acquire_session = AsyncMock(return_value="reused")
        ready = asyncio.Event()
        shared = asyncio.create_task(ready.wait())
        manager._spawn_managed_mcp_sync = lambda *args: shared
        cancel = asyncio.Event()
        first = asyncio.create_task(manager.run_prompt(
            tool="opencode", executable="opencode", directory=tmp_path,
            prompt="cancel", model="provider/model", timeout=1,
            cancel_event=cancel,
        ))
        await asyncio.sleep(0.02)
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(first, timeout=0.5)
        assert not shared.done()
        ready.set()
        await shared
        assert not shared.cancelled()

    asyncio.run(run())


def test_timed_out_session_leaves_other_active_session_running(monkeypatch, tmp_path):
    async def run():
        neighbor_started = asyncio.Event()
        neighbor_finish = asyncio.Event()
        aborted = []
        sessions = []

        class Client(_FakeAsyncClient):
            async def post(self, path, **kwargs):
                if path == "/session":
                    session = f"session-{len(sessions) + 1}"
                    sessions.append(session)
                    return _FakeResponse({"id": session})
                if path.endswith("/message"):
                    prompt = kwargs["json"]["parts"][0]["text"]
                    if prompt == "neighbor":
                        neighbor_started.set()
                        await neighbor_finish.wait()
                        return _FakeResponse({"parts": [{"type": "text", "text": "done"}]})
                    await asyncio.Future()
                if path.endswith("/abort"):
                    aborted.append(path)
                    return _FakeResponse(True)
                return await super().post(path, **kwargs)

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()
        manager._stop_locked = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        manager._acquire_session = acquire
        common = dict(tool="opencode", executable="opencode", directory=tmp_path, model="provider/model")
        neighbor = asyncio.create_task(manager.run_prompt(**common, prompt="neighbor", timeout=2))
        await asyncio.wait_for(neighbor_started.wait(), timeout=1)
        try:
            with pytest.raises(asyncio.TimeoutError):
                await manager.run_prompt(**common, prompt="victim", timeout=0.03)
            assert not neighbor.done()
            assert manager._active_sessions == 1
            assert aborted == ["/session/session-2/abort"]
            manager._stop_locked.assert_not_awaited()
        finally:
            neighbor_finish.set()
            assert await neighbor == ["done"]
        assert manager._active_sessions == 0

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
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()
        permissions = [{"permission": "edit", "pattern": "*", "action": "deny"}]
        output: list[str] = []

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
            on_line=output.append,
            log_stage="audit",
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
        assert any(
            line.startswith("[audit][session-existing][session] START mode=continued")
            for line in output
        )
        assert output[-1] == (
            "[audit][session-existing][session] STOP status=success retained=true"
        )
        assert all("done" not in line for line in output)

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


def test_run_prompt_continues_without_permissions_does_not_patch_session(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read"]
        _FakeAsyncClient.message_info = {
            "id": "msg_global_permissions",
            "providerID": "provider",
            "modelID": "actual",
        }
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()

        details = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="continue with global permissions",
            model="provider/requested",
            timeout=30,
            session_id="session-existing",
            return_details=True,
        )

        assert isinstance(details, OpenCodePromptResult)
        client = _FakeAsyncClient.instances[0]
        assert client.patches == []
        assert all(item["path"] != "/session" for item in client.posts)

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


def test_run_prompt_creates_session_with_explicit_empty_permissions(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read"]
        _FakeAsyncClient.message_info = {
            "id": "msg_empty_permissions",
            "providerID": "provider",
            "modelID": "actual",
        }
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        project = tmp_path / "project"
        project.mkdir()

        details = await manager.run_prompt(
            tool="opencode",
            executable="opencode",
            directory=project,
            prompt="create with global permissions only",
            model="provider/requested",
            timeout=30,
            permissions=[],
            return_details=True,
        )

        assert isinstance(details, OpenCodePromptResult)
        client = _FakeAsyncClient.instances[0]
        create = next(item for item in client.posts if item["path"] == "/session")
        assert create["json"]["permission"] == []
        assert client.patches == []

    try:
        asyncio.run(run())
    finally:
        _FakeAsyncClient.message_info = None


def test_session_management_methods_use_durable_session_routes(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
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
            "task_agent.serve_client.httpx.AsyncClient",
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
            "task_agent.serve_client.httpx.AsyncClient",
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
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert any(
            line.startswith(
                "[opencode][session-1][session] TOOL_DISCOVERY unavailable"
            )
            for line in output
        )

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
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "[opencode][session-1][session] TOOLS count=3 mcp_tools=2" in logged
        assert "mcp__deephole-code__view_function_code" in logged
        assert "mcp__deephole-code__view_struct_code" in logged

    asyncio.run(run())


def test_run_prompt_logs_selected_source_mcp_input_in_full(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        _FakeAsyncClient.tool_ids = ["read", "static-mcp_static_read"]
        source_input = {
            "query": "find  target\nnext\tvalue",
            "path": "src/with spaces.c",
            "depth": 3,
            "prompt": "private " + ("x" * 600),
        }
        _FakeAsyncClient.message_parts = [{
            "id": "part-source-tool",
            "type": "tool",
            "callID": "call-source-tool",
            "tool": "static-mcp_static_read",
            "state": {
                "status": "completed",
                "input": source_input,
                "output": "secret source body",
            },
        }]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeAsyncClient,
        )

        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._acquire_session = AsyncMock()
        manager.ensure_managed_mcp = AsyncMock()
        manager._acquire_scan_mcp = AsyncMock(return_value=_ScanMcpLease(
            directory_key="project",
            state_key="project\0code_graph",
            identity="scan-1:static-mcp",
            name="static-mcp",
            fingerprint="fingerprint",
            connected=True,
        ))
        manager._release_scan_mcp = AsyncMock()
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
                scan_id="scan-1",
                code_graph_mcp={"enabled": True},
            )
        finally:
            _FakeAsyncClient.tool_ids = [
                "read",
                "grep",
                "mcp__deephole-code__view_function_code",
            ]

        expected_input = json.dumps(
            source_input,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        expected = (
            "[opencode][session-1][tool] "
            f"name=static-mcp_static_read input={expected_input}"
        )
        assert output.count(expected) == 1
        logged = "\n".join(output)
        assert "secret source body" not in logged
        assert "[truncated" not in logged
        assert "\\n" in expected
        assert "\\t" in expected
        assert "find  target" in expected
        manager._release_scan_mcp.assert_awaited_once()

    asyncio.run(run())


def test_selected_source_mcp_call_is_deduplicated_across_event_shapes() -> None:
    output: list[str] = []
    state = _ServeEventState(
        "opencode",
        "session-1",
        output.append,
        source_mcp_name="static-mcp",
    )
    input_value = {"query": "target", "depth": 2}
    part = {
        "id": "part-source-tool",
        "sessionID": "session-1",
        "type": "tool",
        "callID": "call-source-tool",
        "tool": "static-mcp_static_read",
        "state": {
            "status": "running",
            "input": input_value,
        },
    }

    _handle_serve_event({
        "type": "message.part.updated",
        "properties": {"sessionID": "session-1", "part": part},
    }, state)
    _handle_serve_event({
        "type": "sync",
        "name": "session.next.tool.called.1",
        "data": {
            "sessionID": "session-1",
            "callID": "call-source-tool",
            "tool": "static-mcp_static_read",
            "input": input_value,
        },
    }, state)
    state.ingest_message_snapshot({
        "info": {
            "id": "message-ai",
            "sessionID": "session-1",
            "role": "assistant",
        },
        "parts": [{**part, "messageID": "message-ai"}],
    })

    expected_input = json.dumps(
        input_value,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert output == [
        "[opencode][session-1][tool] "
        f"name=static-mcp_static_read input={expected_input}",
    ]


def test_list_models_uses_project_directory_context(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/provider": {"all": [], "connected": []},
            "/config/providers": {"providers": []},
        }
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
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
                            "claude-sonnet": {
                                "name": "Claude Sonnet",
                                "limit": {
                                    "context": 200000,
                                    "input": 180000,
                                    "output": 8192,
                                },
                            },
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
            "task_agent.serve_client.httpx.AsyncClient",
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
                limit_context=200000,
                limit_input=180000,
                limit_output=8192,
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
            "task_agent.serve_client.httpx.AsyncClient",
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
            "task_agent.serve_client.httpx.AsyncClient",
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


def test_list_models_labels_serve_preparation_failure() -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._acquire_model_listing = AsyncMock(
            side_effect=RuntimeError("startup output"),
        )

        with pytest.raises(RuntimeError) as excinfo:
            await manager.list_models(tool="opencode", executable="opencode")

        message = str(excinfo.value)
        assert "OpenCode Serve 准备失败（启动或复用阶段）" in message
        assert "startup output" in message

    asyncio.run(run())


def test_list_models_labels_provider_query_failure_and_releases_listing() -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._acquire_model_listing = AsyncMock(return_value=False)
        manager._release_model_listing = AsyncMock()
        manager._fetch_models = AsyncMock(
            side_effect=RuntimeError("/provider: 404 Not Found"),
        )

        with pytest.raises(RuntimeError) as excinfo:
            await manager.list_models(tool="opencode", executable="opencode")

        message = str(excinfo.value)
        assert "OpenCode Serve 模型接口查询失败" in message
        assert "/provider: 404 Not Found" in message
        manager._release_model_listing.assert_awaited_once()

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
            'data: {"type":"session.next.tool.called","properties":{"sessionID":"session-1","callID":"call-1","tool":"read","input":{"filePath":"src/main.c","offset":10,"limit":20}}}',
            "",
            'data: {"type":"session.next.tool.success","properties":{"sessionID":"session-1","callID":"call-1","content":[{"type":"text","text":"secret source body"}]}}',
            "",
        ]
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "middle output" not in logged
        assert "reasoning" not in logged
        assert (
            output.count(
                "[opencode][session-1][tool] name=read path=src/main.c"
                " offset=10 limit=20"
            )
            == 1
        )
        assert "[opencode][session-1][step]" not in logged
        assert "text_chars=18" not in logged
        assert "secret source body" not in logged
        assert "ignore" not in logged
        assert "done" not in logged
        assert output[-1] == (
            "[opencode][session-1][session] STOP status=success retained=true"
        )

    asyncio.run(run())


def test_run_prompt_compacts_final_text_when_sse_has_no_text(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.event_lines = []
        monkeypatch.setattr(_FakeAsyncClient, "tool_ids", [])
        monkeypatch.setattr(_FakeAsyncClient, "message_text", "first line\nsecond line")
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "first line" not in "\n".join(output)
        assert "second line" not in "\n".join(output)
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
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "sync text" not in logged
        assert "sync reasoning" not in logged
        assert (
            output.count(
                "[opencode][session-1][tool] name=read path=src/win.c"
            )
            == 1
        )
        assert "text_chars=21" not in logged
        assert "hidden sync tool body" not in logged
        assert "done" not in logged

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
            "task_agent.serve_client.httpx.AsyncClient",
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

        logged = "\n".join(output)
        assert "ended only" not in logged
        assert "ended reasoning" not in logged
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
            "task_agent.serve_client.httpx.AsyncClient",
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

        logged = "\n".join(output)
        assert "fallback text" not in logged
        assert "fallback reasoning" not in logged
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
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "only reasoning" not in logged
        assert "done" not in logged

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
            "task_agent.serve_client.httpx.AsyncClient",
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

        logged = "\n".join(output)
        assert "prefix" not in logged
        assert "tail" not in logged

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
            "task_agent.serve_client.httpx.AsyncClient",
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
        assert "safe final answer" not in logged
        assert "secret final tool body" not in logged
        assert "secret tool title" not in logged
        assert "secret nested tool content" not in logged
        assert "secret final tool body" in lines
        assert output.count(
            "[opencode][session-1][tool] "
            "name=mcp__deephole-code__view_function_code"
        ) == 1
        assert "output_chars=22" not in logged

    asyncio.run(run())


def test_open_source_message_parts_collect_text_reasoning_without_printing() -> None:
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

    assert output == []
    assert state.observed_response_text == "open source middle output\n"
    assert state.observed_reasoning_text == "reasoning step\n"
    assert "secret prompt" not in state.observed_response_text


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
    assert output == []
    assert state.observed_response_text == "snapshot without newline"


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

    assert output == []
    assert state.observed_response_text == "assistant answer"
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

    error_lines = [line for line in output if " ERROR " in line]
    assert error_lines == [
        "[opencode][session-1][session] ERROR error=APIError: provider failed"
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

    assert output == []
    assert state.observed_response_text == "same text\n"


def test_incompatible_final_text_emits_complete_final_snapshot() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    state.append_next_delta("text", "prefix-")
    state.append_next_delta("text", "suffix")
    state.flush()
    state.reconcile_text("text", "prefix-MISSING-suffix")
    state.reconcile_text("text", "prefix-MISSING-suffix")

    assert output == []
    assert state.observed_response_text == "prefix-MISSING-suffix"
    assert state.final_snapshots_emitted == {("text", "prefix-MISSING-suffix")}


def test_generic_step_events_are_not_printed() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    for event_type in (
        "session.next.step.started",
        "session.next.step.ended",
        "session.next.step.failed",
    ):
        event = {
            "id": f"{event_type}-1",
            "type": event_type,
            "properties": {
                "sessionID": "session-1",
                "agent": "build",
                "model": {"id": "model", "providerID": "provider"},
                "error": {"message": "internal step failed"},
            },
        }
        _handle_serve_event(event, state)
        _handle_serve_event(event, state)

    for part_type in ("step-start", "step-finish"):
        state.handle_part({
            "id": f"part-{part_type}",
            "sessionID": "session-1",
            "type": part_type,
            "reason": "stop",
        })

    assert output == []


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
    assert output.count(
        "[opencode][session-1][tool] "
        "name=mcp__deephole-code__view_function_code"
    ) == 1
    assert "output_chars=18" not in logged
    assert "duration_ms=40" not in logged
    assert "secret source body" not in logged
    assert "pending call body" not in logged
    assert "secret tool prompt" not in logged
    assert '"prompt":"<redacted>"' not in logged
    assert "busy" not in logged
    assert "RETRY attempt=2 next=10 message=rate limited" in logged
    assert "idle" not in logged
    assert "][step]" not in logged
    assert "][session] ERROR error=provider failed" in logged


def test_skill_call_is_single_line_and_failure_adds_error_without_prompt() -> None:
    output: list[str] = []
    state = _ServeEventState(
        "opencode",
        "session-1",
        output.append,
        log_stage="validation",
    )

    state.emit_tool_call(
        call_id="skill-1",
        tool_name="skill",
        input_value={"name": "exploit-validation", "prompt": "secret instructions"},
    )
    state.emit_tool_result(
        call_id="skill-1",
        tool_name="skill",
        input_value={"name": "exploit-validation", "prompt": "secret instructions"},
        status="failed",
        summary="error=skill unavailable",
    )
    state.emit_tool_result(
        call_id="skill-1",
        tool_name="skill",
        input_value={"name": "exploit-validation", "prompt": "secret instructions"},
        status="failed",
        summary="error=skill unavailable",
    )

    assert output == [
        "[validation][session-1][skill] name=exploit-validation",
        "[validation][session-1][skill] "
        "ERROR name=exploit-validation error=skill unavailable",
    ]
    assert "secret instructions" not in "\n".join(output)


def test_tool_failure_adds_one_error_without_start_or_stop_lines() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)
    called = {
        "type": "session.next.tool.called",
        "properties": {
            "sessionID": "session-1",
            "callID": "tool-1",
            "tool": "read",
            "input": {"filePath": "secret.c"},
        },
    }
    failed = {
        "type": "session.next.tool.failed",
        "properties": {
            "sessionID": "session-1",
            "callID": "tool-1",
            "error": {"message": "permission denied"},
        },
    }

    _handle_serve_event(called, state)
    _handle_serve_event(called, state)
    _handle_serve_event(failed, state)
    _handle_serve_event(failed, state)

    assert output == [
        "[opencode][session-1][tool] name=read path=secret.c",
        "[opencode][session-1][tool] "
        "ERROR name=read error=permission denied",
    ]


def test_write_tool_logs_path_without_content() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    state.emit_tool_call(
        call_id="write-1",
        tool_name="write",
        input_value={
            "filePath": "reports/result.json",
            "content": "private write body",
        },
    )

    assert output == [
        "[opencode][session-1][tool] "
        "name=write path=reports/result.json content_chars=18",
    ]
    assert "private write body" not in "\n".join(output)


def test_completed_builtin_file_tools_report_written_paths_once() -> None:
    writes: list[OpenCodeFileWrite] = []
    state = _ServeEventState(
        "opencode",
        "session-1",
        None,
        on_file_write=writes.append,
        ignored_file_message_ids=("message-old",),
    )
    state.ingest_message_snapshot({
        "info": {
            "id": "message-old",
            "sessionID": "session-1",
            "role": "assistant",
        },
        "parts": [{
            "id": "part-old",
            "type": "tool",
            "callID": "call-old",
            "tool": "write",
            "state": {
                "status": "completed",
                "input": {"filePath": "old.json", "content": "{}"},
                "metadata": {"filepath": "old.json", "exists": False},
            },
        }],
    })
    parts = [
        {
            "id": "part-write",
            "type": "tool",
            "callID": "call-write",
            "tool": "write",
            "state": {
                "status": "completed",
                "input": {"filePath": "write.json", "content": "{}"},
                "metadata": {"filepath": "write.json", "exists": False},
            },
        },
        {
            "id": "part-edit-existing",
            "type": "tool",
            "callID": "call-edit-existing",
            "tool": "edit",
            "state": {
                "status": "completed",
                "input": {
                    "filePath": "existing.json",
                    "oldString": "before",
                    "newString": "after",
                },
                "metadata": {"filediff": {"file": "existing.json"}},
            },
        },
        {
            "id": "part-edit-new",
            "type": "tool",
            "callID": "call-edit-new",
            "tool": "edit",
            "state": {
                "status": "completed",
                "input": {
                    "filePath": "edit-created.json",
                    "oldString": "",
                    "newString": "{}",
                },
                "metadata": {"filediff": {"file": "edit-created.json"}},
            },
        },
        {
            "id": "part-patch",
            "type": "tool",
            "callID": "call-patch",
            "tool": "apply_patch",
            "state": {
                "status": "completed",
                "input": {"patchText": "private patch body"},
                "metadata": {
                    "files": [
                        {"filePath": "added.json", "type": "add"},
                        {"filePath": "updated.json", "type": "update"},
                        {"filePath": "deleted.json", "type": "delete"},
                        {
                            "filePath": "old-name.json",
                            "movePath": "new-name.json",
                            "type": "move",
                        },
                    ]
                },
            },
        },
        {
            "id": "part-custom",
            "type": "tool",
            "callID": "call-custom",
            "tool": "mcp__custom__write",
            "state": {
                "status": "completed",
                "input": {"filePath": "unknown.json"},
                "metadata": {"filepath": "unknown.json", "exists": False},
            },
        },
    ]

    for part in parts:
        state.handle_part(part)
        state.handle_part(part)

    assert writes == [
        OpenCodeFileWrite("call-write", "write.json", created=True),
        OpenCodeFileWrite("call-edit-existing", "existing.json", created=False),
        OpenCodeFileWrite("call-edit-new", "edit-created.json", created=True),
        OpenCodeFileWrite("call-patch", "added.json", created=True),
        OpenCodeFileWrite("call-patch", "updated.json", created=False),
        OpenCodeFileWrite("call-patch", "new-name.json", created=False),
    ]


@pytest.mark.parametrize(
    ("tool_name", "input_value", "expected"),
    [
        (
            "read",
            {"file_path": "src/with spaces.c", "offset": 0, "limit": 50},
            'name=read path="src/with spaces.c" offset=0 limit=50',
        ),
        (
            "edit",
            {
                "filePath": "src/main.c",
                "oldString": "private old text",
                "newString": "private replacement",
                "replaceAll": False,
            },
            "name=edit path=src/main.c old_chars=16 new_chars=19 "
            "replace_all=false",
        ),
        (
            "grep",
            {"pattern": "unsafe call", "path": "src", "include": "*.c"},
            'name=grep pattern="unsafe call" path=src include=*.c',
        ),
        (
            "glob",
            {"pattern": "**/*.py", "path": "task agent"},
            'name=glob pattern=**/*.py path="task agent"',
        ),
        (
            "list",
            {"path": "src"},
            "name=list path=src",
        ),
        (
            "mcp__example__lookup",
            {"path": "secret.c", "query": "private query"},
            "name=mcp__example__lookup",
        ),
    ],
)
def test_common_tool_calls_log_selected_details_without_bodies(
    tool_name: str,
    input_value: dict[str, object],
    expected: str,
) -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    state.emit_tool_call(
        call_id=f"{tool_name}-1",
        tool_name=tool_name,
        input_value=input_value,
    )

    assert output == [f"[opencode][session-1][tool] {expected}"]
    logged = "\n".join(output)
    assert "private old text" not in logged
    assert "private replacement" not in logged
    assert "private query" not in logged


def test_bash_tool_logs_complete_unredacted_command_as_one_line() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)
    command = (
        "API_TOKEN=top-secret python3 - <<'PY'\n"
        f"print({'x' * 600!r})\n"
        "PY"
    )

    state.emit_tool_call(
        call_id="bash-1",
        tool_name="bash",
        input_value={
            "command": command,
            "workdir": "/tmp/task work",
            "timeout": 900000,
            "description": "run validation command",
        },
    )

    assert output == [
        "[opencode][session-1][tool] name=bash "
        f"command={json.dumps(command, ensure_ascii=False)} "
        'workdir="/tmp/task work" timeout=900000 '
        'description="run validation command"',
    ]
    assert "\\n" in output[0]
    assert "top-secret" in output[0]
    assert "x" * 600 in output[0]
    assert "[truncated" not in output[0]
    assert "\n" not in output[0]


def test_shell_tool_supports_legacy_command_and_workdir_field_aliases() -> None:
    output: list[str] = []
    state = _ServeEventState("opencode", "session-1", output.append)

    state.emit_tool_call(
        call_id="shell-1",
        tool_name="shell",
        input_value={
            "cmd": "pwd",
            "cwd": "/tmp/project",
        },
    )

    assert output == [
        '[opencode][session-1][tool] name=shell command="pwd" '
        "workdir=/tmp/project",
    ]


def test_no_newline_delta_is_flushed_periodically(monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            "task_agent.serve_client._SERVE_EVENT_FLUSH_INTERVAL_SECONDS",
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

        assert output == []
        assert state.observed_response_text == "visible before task completion"
        assert state.emitted_response_text is False

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
        "task_agent.serve_client.time.monotonic",
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

    event_lines = [line for line in output if "][session] EVENT " in line]
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
        monkeypatch.setattr("task_agent.serve_client.asyncio.sleep", fake_sleep)
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

        event_lines = [line for line in output if "][session] EVENT " in line]
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
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
            assert output_a == []
            assert output_b == []
            assert state_a.observed_response_text == "alpha\n"
            assert state_b.observed_response_text == "beta\n"
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", Client)
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
            "task_agent.serve_client._SERVE_EVENT_POLL_INTERVAL_SECONDS",
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
        assert "hello world" not in logged
        assert "think" not in logged
        assert state.observed_response_text == "hello world\n"
        assert state.observed_reasoning_text == "think\n"
        assert output.count(
            "[opencode][session-1][tool] "
            "name=mcp__deephole-code__view_function_code"
        ) == 1
        assert "SECRET TOOL BODY" not in logged

    asyncio.run(run())


def test_serve_port_defaults_to_fixed_port(monkeypatch) -> None:
    monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)

    assert _serve_port() == 4096


def test_serve_port_accepts_env_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENCODE_SERVE_PORT", "4100")

    assert _serve_port() == 4100


def test_windows_port_bind_probe_requests_exclusive_address_use(monkeypatch) -> None:
    from task_agent import serve_client

    class FakeSocket:
        def __init__(self) -> None:
            self.options: list[tuple[int, int, int]] = []
            self.bound: tuple[str, int] | None = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def setsockopt(self, level: int, option: int, value: int) -> None:
            self.options.append((level, option, value))

        def bind(self, address: tuple[str, int]) -> None:
            self.bound = address

    fake_socket = FakeSocket()
    monkeypatch.setattr(serve_client.sys, "platform", "win32")
    monkeypatch.setattr(
        serve_client.socket,
        "SO_EXCLUSIVEADDRUSE",
        0x100,
        raising=False,
    )
    monkeypatch.setattr(
        serve_client.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    assert serve_client.sys.platform == "win32"
    assert hasattr(serve_client.socket, "SO_EXCLUSIVEADDRUSE")
    assert _port_bind_error(23678) is None
    assert fake_socket.options == [(socket.SOL_SOCKET, 0x100, 1)]
    assert fake_socket.bound == ("127.0.0.1", 23678)


def test_pid_is_running_uses_windows_fallback(monkeypatch) -> None:
    from task_agent import serve_client

    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr("task_agent.serve_client._windows_pid_is_running", lambda pid: False)

    assert serve_client._pid_is_running(12345) is False


def test_terminate_process_tree_uses_taskkill_on_windows(monkeypatch) -> None:
    from task_agent import serve_client

    running = {"alive": True}
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        running["alive"] = False

    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr("task_agent.serve_client._pid_is_running", lambda pid: running["alive"])
    monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)

    serve_client._terminate_process_tree(12345)

    assert commands == [["taskkill", "/PID", "12345", "/T", "/F"]]


def test_reclaim_windows_listener_uses_port_liveness_when_pid_probe_is_false(
    monkeypatch,
) -> None:
    from task_agent import serve_client

    listening = {26364}
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        listening.clear()
        return subprocess.CompletedProcess(cmd, 0, stdout=b"")

    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr(
        "task_agent.serve_client._pid_is_running",
        lambda pid: False,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._port_is_in_use",
        lambda port: bool(listening),
    )
    monkeypatch.setattr(
        "task_agent.serve_client._listener_pids_for_port",
        lambda port: set(listening),
    )
    monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)

    result = serve_client._reclaim_serve_port(
        6579,
        reason="test stale Agent-owned serve marker",
        allowed_pids={26364},
    )

    assert commands == [["taskkill", "/PID", "26364", "/T", "/F"]]
    assert result.attempted is True
    assert result.pids == (26364,)
    assert result.released is True


def test_reclaim_windows_listener_uses_netstat_when_tcp_probe_fails_but_bind_is_blocked(
    monkeypatch,
) -> None:
    from task_agent import serve_client

    listening = {15668}
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        listening.clear()
        return subprocess.CompletedProcess(cmd, 0, stdout=b"")

    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr(
        "task_agent.serve_client._port_is_in_use",
        lambda port: False,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._port_bind_error",
        lambda port: OSError(10048, "address already in use"),
    )
    monkeypatch.setattr(
        "task_agent.serve_client._listener_pids_for_port",
        lambda port: set(listening),
    )
    monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)

    result = serve_client._reclaim_serve_port(
        26843,
        reason="test unconnectable stale Agent-owned serve marker",
        allowed_pids={15668},
    )

    assert commands == [["taskkill", "/PID", "15668", "/T", "/F"]]
    assert result.attempted is True
    assert result.pids == (15668,)
    assert result.released is True


def test_reclaim_windows_ignores_ghost_listener_when_exclusive_bind_succeeds(
    monkeypatch,
    caplog,
) -> None:
    from task_agent import serve_client

    terminated: list[int] = []
    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr(
        "task_agent.serve_client._port_is_in_use",
        lambda port: False,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._port_bind_error",
        lambda port: None,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._listener_pids_for_port",
        lambda port: {3980},
    )
    monkeypatch.setattr(
        "task_agent.serve_client._terminate_process_tree",
        lambda pid, **kwargs: terminated.append(pid),
    )
    caplog.set_level("WARNING")

    result = serve_client._reclaim_serve_port(
        23678,
        reason="test ghost Agent-owned serve marker",
        allowed_pids={3980},
    )

    assert terminated == []
    assert result.attempted is False
    assert result.pids == (3980,)
    assert result.released is True
    assert "stale listener-table pid(s) ignored" in result.detail
    assert "exclusive bind succeeded" in caplog.text


def test_reclaim_unconnectable_listener_does_not_terminate_unowned_pid(
    monkeypatch,
) -> None:
    from task_agent import serve_client

    terminated: list[int] = []
    monkeypatch.setattr(
        "task_agent.serve_client._port_is_in_use",
        lambda port: False,
    )
    monkeypatch.setattr(
        "task_agent.serve_client._listener_pids_for_port",
        lambda port: {99999},
    )
    monkeypatch.setattr(
        "task_agent.serve_client._terminate_process_tree",
        lambda pid, **kwargs: terminated.append(pid),
    )

    result = serve_client._reclaim_serve_port(
        26843,
        reason="test foreign unconnectable listener",
        allowed_pids={15668},
    )

    assert terminated == []
    assert result.attempted is False
    assert result.released is False
    assert result.detail == "listener ownership was not proven"


def test_terminate_windows_listener_falls_back_when_taskkill_fails(
    monkeypatch,
    caplog,
) -> None:
    from task_agent import serve_client

    listening = {26364}
    direct_kills: list[tuple[int, int]] = []

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            5,
            stdout=b"Access is denied",
        )

    def fake_kill(pid: int, signum: int) -> None:
        direct_kills.append((pid, signum))
        listening.discard(pid)

    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)
    monkeypatch.setattr("task_agent.serve_client.os.kill", fake_kill)
    caplog.set_level("WARNING")

    stopped = serve_client._terminate_process_tree(
        26364,
        timeout=0.0,
        is_running=lambda: 26364 in listening,
    )

    assert stopped is True
    assert direct_kills == [(26364, signal.SIGTERM)]
    assert "taskkill failed" in caplog.text
    assert "exit_code=5" in caplog.text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group behavior")
def test_terminate_process_tree_escalates_after_launcher_exits(monkeypatch) -> None:
    from task_agent import serve_client

    group_running = {"value": True}
    sent_signals: list[int] = []

    def fake_killpg(pgid: int, signum: int) -> None:
        assert pgid == 23456
        sent_signals.append(signum)
        if signum == signal.SIGKILL:
            group_running["value"] = False

    monkeypatch.setattr(
        serve_client,
        "_process_group_is_running",
        lambda pgid: group_running["value"],
    )
    monkeypatch.setattr(serve_client.os, "killpg", fake_killpg)

    stopped = serve_client._terminate_process_tree(
        12345,
        timeout=0.0,
        wait=lambda timeout: None,
        process_group_id=23456,
    )

    assert stopped is True
    assert sent_signals == [signal.SIGTERM, signal.SIGKILL]


def test_owned_serve_exit_cleanup_is_idempotent(monkeypatch, tmp_path: Path) -> None:
    from task_agent import serve_client

    class FakeProc:
        pid = 12345

        def __init__(self) -> None:
            self.wait_calls: list[float] = []

        def poll(self):
            return None

        def wait(self, timeout):
            self.wait_calls.append(timeout)

    marker_path = tmp_path / "serve-marker.json"
    marker_path.write_text(json.dumps({"pid": 12345}), encoding="utf-8")
    terminated: list[int] = []

    def fake_terminate(pid, timeout=5.0, wait=None):
        terminated.append(pid)
        assert wait is not None
        wait(0.01)

    monkeypatch.setattr(serve_client, "_install_serve_exit_hooks", lambda: None)
    monkeypatch.setattr(serve_client, "_terminate_process_tree", fake_terminate)
    proc = FakeProc()
    serve_client._register_owned_serve_process(proc, marker_path)

    serve_client._cleanup_owned_serve_processes("test exit")
    serve_client._cleanup_owned_serve_processes("duplicate exit")

    assert terminated == [12345]
    assert proc.wait_calls == [0.01]
    assert not marker_path.exists()
    assert (os.getpid(), 12345) not in serve_client._OWNED_SERVE_PROCESSES


def test_owned_serve_exit_cleanup_preserves_marker_for_new_pid(monkeypatch, tmp_path: Path) -> None:
    from task_agent import serve_client

    class FakeProc:
        pid = 12345

        def poll(self):
            return None

        def wait(self, timeout):
            return None

    marker_path = tmp_path / "serve-marker.json"
    marker_path.write_text(json.dumps({"pid": 54321}), encoding="utf-8")
    terminated: list[int] = []

    monkeypatch.setattr(serve_client, "_install_serve_exit_hooks", lambda: None)
    monkeypatch.setattr(
        serve_client,
        "_terminate_process_tree",
        lambda pid, **kwargs: terminated.append(pid),
    )
    serve_client._register_owned_serve_process(FakeProc(), marker_path)

    serve_client._cleanup_owned_serve_processes("test exit")

    assert terminated == [12345]
    assert json.loads(marker_path.read_text(encoding="utf-8"))["pid"] == 54321


def test_owned_serve_signal_hook_delegates_and_restores_host_handlers(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from task_agent import serve_client

    class FakeProc:
        pid = 12345

        def poll(self):
            return 0

    delegated: list[tuple[int, object]] = []

    def host_sigint(signum, frame):
        delegated.append((signum, frame))

    def host_sigterm(signum, frame):
        delegated.append((signum, frame))

    handlers = {
        int(signal.SIGINT): host_sigint,
        int(signal.SIGTERM): host_sigterm,
    }
    atexit_callbacks: list[tuple[object, tuple[object, ...]]] = []
    monkeypatch.setattr(serve_client, "_OWNED_SERVE_PROCESSES", {})
    monkeypatch.setattr(serve_client, "_SERVE_ATEXIT_REGISTERED", False)
    monkeypatch.setattr(serve_client, "_SERVE_SIGNAL_HANDLERS", {})
    monkeypatch.setattr(serve_client, "_SERVE_SIGNAL_HOOK_OWNER_PID", None)
    monkeypatch.setattr(
        serve_client.atexit,
        "register",
        lambda callback, *args: atexit_callbacks.append((callback, args)),
    )
    monkeypatch.setattr(
        serve_client.signal,
        "getsignal",
        lambda signum: handlers[int(signum)],
    )
    monkeypatch.setattr(
        serve_client.signal,
        "signal",
        lambda signum, handler: handlers.__setitem__(int(signum), handler),
    )

    serve_client._register_owned_serve_process(FakeProc(), tmp_path / "marker.json")
    assert handlers[int(signal.SIGINT)] is serve_client._handle_owned_serve_signal
    assert handlers[int(signal.SIGTERM)] is serve_client._handle_owned_serve_signal

    frame = object()
    serve_client._handle_owned_serve_signal(signal.SIGTERM, frame)

    assert delegated == [(signal.SIGTERM, frame)]
    assert handlers[int(signal.SIGINT)] is host_sigint
    assert handlers[int(signal.SIGTERM)] is host_sigterm
    assert atexit_callbacks == [
        (serve_client._cleanup_owned_serve_processes, ("interpreter exit",))
    ]


def test_parse_listener_pids_handles_windows_and_ipv6_netstat() -> None:
    from task_agent import serve_client

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
    from task_agent import serve_client

    output = """
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:4097    0.0.0.0:*     users:(("node",pid=2222,fd=18))
"""

    assert serve_client._parse_listener_pids(output, 4097) == {2222}


def test_owned_listener_pids_only_accept_launcher_process_tree(monkeypatch) -> None:
    from task_agent import serve_client

    monkeypatch.setattr(
        "task_agent.serve_client._listener_pids_for_port",
        lambda port: {1111, 2222},
    )
    monkeypatch.setattr(
        "task_agent.serve_client._pid_descends_from",
        lambda pid, launcher_pid: pid == 2222,
    )

    listeners, owned, verified = serve_client._owned_listener_pids_for_launcher(
        4096,
        3333,
    )

    assert listeners == {1111, 2222}
    assert owned == {2222}
    assert verified is True


def test_managed_file_write_plugin_preserves_user_plugins(tmp_path: Path) -> None:
    workspace = tmp_path / "runtime"
    workspace.mkdir()

    config_path = _write_serve_config_file(
        workspace,
        json.dumps({"plugin": ["user-plugin", "file:///custom/plugin.mjs"]}),
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["compaction"] == {
        "auto": True,
        "prune": True,
        "reserved": 20_000,
    }
    assert config["plugin"][:2] == ["user-plugin", "file:///custom/plugin.mjs"]
    assert len(config["plugin"]) == 4
    managed_path = (
        workspace
        / ".opendeephole-plugins"
        / f"opendeephole-file-write-{_FILE_WRITE_PLUGIN_HASH}.mjs"
    ).resolve()
    assert config["plugin"][2] == managed_path.as_uri()
    assert managed_path.read_text(encoding="utf-8") == _FILE_WRITE_PLUGIN_SOURCE
    knowledge_plugin_path = (
        workspace
        / ".opendeephole-plugins"
        / f"opendeephole-knowledge-project-{_KNOWLEDGE_PROJECT_PLUGIN_HASH}.mjs"
    ).resolve()
    assert config["plugin"][3] == knowledge_plugin_path.as_uri()
    assert knowledge_plugin_path.read_text(encoding="utf-8") == (
        _KNOWLEDGE_PROJECT_PLUGIN_SOURCE
    )


@pytest.mark.parametrize("configured", [None, False, []])
def test_managed_compaction_replaces_missing_or_non_object_config(
    tmp_path: Path,
    configured,
) -> None:
    workspace = tmp_path / "runtime"
    workspace.mkdir()
    source = {} if configured is None else {"compaction": configured}

    config_path = _write_serve_config_file(workspace, json.dumps(source))

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["compaction"] == {
        "auto": True,
        "prune": True,
        "reserved": 20_000,
    }


def test_managed_compaction_overrides_conflicts_and_preserves_other_fields(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "runtime"
    workspace.mkdir()

    config_path = _write_serve_config_file(
        workspace,
        json.dumps({
            "compaction": {
                "auto": False,
                "prune": False,
                "reserved": 1,
                "tail_turns": 4,
                "preserve_recent_tokens": 8_000,
            },
        }),
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["compaction"] == {
        "auto": True,
        "prune": True,
        "reserved": 20_000,
        "tail_turns": 4,
        "preserve_recent_tokens": 8_000,
    }


def test_managed_model_limits_fill_models_without_context(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "runtime"
    workspace.mkdir()

    config_path = _write_serve_config_file(
        workspace,
        json.dumps({
            "model": "custom/empty",
            "provider": {
                "custom": {
                    "name": "Custom Provider",
                    "models": {
                        "empty": {"name": "Empty Model"},
                        "output-only": {
                            "limit": {"output": 8_192},
                            "options": {"reasoningEffort": "high"},
                        },
                        "invalid-limit": {"limit": False},
                        "with-input": {
                            "limit": {"input": 100_000, "output": 16_384},
                        },
                        "input-only": {
                            "limit": {"input": 100_000},
                        },
                        "with-context": {
                            "limit": {"context": 200_000},
                        },
                    },
                },
                "without-models": {"name": "No Models"},
            },
        }),
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    custom = config["provider"]["custom"]
    assert custom["name"] == "Custom Provider"
    assert custom["models"]["empty"] == {
        "name": "Empty Model",
        "limit": {"context": 131_072, "output": 32_768},
    }
    assert custom["models"]["output-only"] == {
        "limit": {"context": 131_072, "output": 8_192},
        "options": {"reasoningEffort": "high"},
    }
    assert custom["models"]["invalid-limit"] == {
        "limit": {"context": 131_072, "output": 32_768},
    }
    assert custom["models"]["with-input"] == {
        "limit": {
            "context": 131_072,
            "input": 100_000,
            "output": 16_384,
        },
    }
    assert custom["models"]["input-only"] == {
        "limit": {
            "context": 131_072,
            "input": 100_000,
            "output": 32_768,
        },
    }
    assert custom["models"]["with-context"] == {
        "limit": {"context": 200_000},
    }
    assert config["provider"]["without-models"] == {"name": "No Models"}
    assert config["model"] == "custom/empty"
    assert config["compaction"] == {
        "auto": True,
        "prune": True,
        "reserved": 20_000,
    }


def test_managed_model_limits_do_not_create_provider_or_model_entries(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "runtime"
    workspace.mkdir()

    config_path = _write_serve_config_file(
        workspace,
        json.dumps({
            "model": "builtin/catalog-model",
            "provider": {"builtin": {"options": {"timeout": 30_000}}},
        }),
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["provider"] == {
        "builtin": {"options": {"timeout": 30_000}},
    }


def test_config_hash_uses_managed_compaction_values() -> None:
    base_hash = _config_hash("{}")
    conflicting_hash = _config_hash(json.dumps({
        "compaction": {
            "auto": False,
            "prune": False,
            "reserved": 1,
        },
    }))
    extended_hash = _config_hash(json.dumps({
        "compaction": {
            "auto": False,
            "prune": False,
            "reserved": 1,
            "tail_turns": 4,
        },
    }))

    assert conflicting_hash == base_hash
    assert extended_hash != base_hash


def test_config_hash_uses_managed_model_limit_values() -> None:
    implicit_hash = _config_hash(json.dumps({
        "provider": {
            "custom": {
                "models": {"model": {"name": "Model"}},
            },
        },
    }))
    explicit_hash = _config_hash(json.dumps({
        "provider": {
            "custom": {
                "models": {
                    "model": {
                        "name": "Model",
                        "limit": {"context": 131_072, "output": 32_768},
                    },
                },
            },
        },
    }))
    custom_hash = _config_hash(json.dumps({
        "provider": {
            "custom": {
                "models": {
                    "model": {
                        "name": "Model",
                        "limit": {"context": 200_000, "output": 32_768},
                    },
                },
            },
        },
    }))

    assert implicit_hash == explicit_hash
    assert custom_hash != implicit_hash


def test_start_locked_uses_fixed_port_and_writes_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 12345

            def poll(self):
                return None

        commands: list[list[str]] = []
        envs: list[dict[str, str]] = []
        popen_kwargs: list[dict] = []
        registered: list[tuple[object, Path]] = []
        startup_logs: list[str] = []
        git_init_cwds: list[Path] = []
        marker_path = tmp_path / "serve-marker.json"
        startup_log_path = tmp_path / "serve-startup.log"
        project = tmp_path / "project with 空格"
        startup_cwd = project / ".opendeephole" / "opencode" / "serve-test"
        project.mkdir()
        startup_cwd.mkdir(parents=True)
        (startup_cwd / "opencode.json").write_text('{"stale": true}', encoding="utf-8")
        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.delenv("OPENCODE_SERVE_PORT", raising=False)
        monkeypatch.setattr("task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "task_agent.serve_client._new_serve_startup_log_path",
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

        monkeypatch.setattr("task_agent.serve_client.subprocess.Popen", fake_popen)
        monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr(
            "task_agent.serve_client._register_owned_serve_process",
            lambda proc, path: registered.append((proc, path)),
        )
        monkeypatch.setattr(
            "task_agent.serve_client.logger.info",
            lambda message, *args: startup_logs.append(message % args if args else str(message)),
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()
        monkeypatch.setenv("HTTP_PROXY", "http://system.example:8080")
        monkeypatch.setenv("HTTPS_PROXY", "http://system.example:8080")
        monkeypatch.setenv("http_proxy", "http://system.example:8080")
        monkeypatch.setenv("https_proxy", "http://system.example:8080")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9999")
        monkeypatch.setenv("all_proxy", "http://127.0.0.1:9999")
        monkeypatch.setenv("NO_PROXY", "system-upper,shared.local")
        monkeypatch.setenv("no_proxy", "system-lower")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "ambient-config"))
        monkeypatch.setenv("OPENCODE_CONFIG", str(tmp_path / "ambient.json"))
        monkeypatch.setenv("OPENCODE_CONFIG_PATH", str(tmp_path / "legacy.json"))
        monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"stale": true}')

        await manager._start_locked(OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            env_hash="proxyhash",
            config_hash="abc123",
            config_content='{"mcp": {}}',
            env_overrides=(
                ("HTTP_PROXY", "http://configured.example:8080"),
                ("HTTPS_PROXY", "http://configured.example:8080"),
                ("http_proxy", "http://configured.example:8080"),
                ("https_proxy", "http://configured.example:8080"),
                ("ALL_PROXY", "socks5://configured.example:1080"),
                ("all_proxy", "socks5://configured.example:1080"),
                ("NO_PROXY", "shared.local,10.0.0.0/8"),
                ("no_proxy", "10.0.0.0/8"),
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
        assert registered == [(manager._proc, marker_path)]
        assert "OPENCODE_CONFIG" not in envs[0]
        assert "OPENCODE_CONFIG_PATH" not in envs[0]
        assert "OPENCODE_CONFIG_CONTENT" not in envs[0]
        assert envs[0]["OPENCODE_CONFIG_DIR"] == str(startup_cwd)
        assert envs[0]["XDG_CONFIG_HOME"] == str(
            startup_cwd / ".opendeephole-xdg-config"
        )
        assert Path(envs[0]["XDG_CONFIG_HOME"]).is_dir()
        assert envs[0]["OPENCODE_SERVE_PORT"] == "4096"
        runtime_config_path = startup_cwd / "opencode.json"
        runtime_config = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        assert runtime_config["compaction"] == {
            "auto": True,
            "prune": True,
            "reserved": 20_000,
        }
        assert runtime_config["mcp"] == {}
        assert len(runtime_config["plugin"]) == 2
        plugin_path = (
            startup_cwd
            / ".opendeephole-plugins"
            / f"opendeephole-file-write-{_FILE_WRITE_PLUGIN_HASH}.mjs"
        )
        knowledge_plugin_path = (
            startup_cwd
            / ".opendeephole-plugins"
            / f"opendeephole-knowledge-project-{_KNOWLEDGE_PROJECT_PLUGIN_HASH}.mjs"
        )
        assert runtime_config["plugin"] == [
            plugin_path.resolve().as_uri(),
            knowledge_plugin_path.resolve().as_uri(),
        ]
        assert plugin_path.read_text(encoding="utf-8") == _FILE_WRITE_PLUGIN_SOURCE
        assert plugin_path.stat().st_mode & 0o777 == 0o600
        assert knowledge_plugin_path.read_text(encoding="utf-8") == (
            _KNOWLEDGE_PROJECT_PLUGIN_SOURCE
        )
        assert knowledge_plugin_path.stat().st_mode & 0o777 == 0o600
        assert runtime_config_path.stat().st_mode & 0o777 == 0o600
        for proxy_name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ):
            assert proxy_name not in envs[0]
        assert envs[0]["NO_PROXY"] == "system-upper,shared.local,10.0.0.0/8"
        assert envs[0]["no_proxy"] == "system-lower,10.0.0.0/8"
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
        assert "executable_version=test-version" in log_text
        assert "port_mode=fixed" in log_text
        assert "startup_attempt=1" in log_text
        assert f"cwd={startup_cwd}" in log_text
        assert f"marker_path={marker_path}" in log_text
        assert f"startup_log_path={startup_log_path}" in log_text
        assert 'argv=["/bin/opencode", "serve", "--hostname", "127.0.0.1", "--port", "4096"]' in log_text
        assert "shell=cd " in log_text
        assert "/bin/opencode serve --hostname 127.0.0.1 --port 4096" in log_text
        assert "HTTP_PROXY=(unset)" in log_text
        assert "HTTPS_PROXY=(unset)" in log_text
        assert "http_proxy=(unset)" in log_text
        assert "https_proxy=(unset)" in log_text
        assert "ALL_PROXY=(unset)" in log_text
        assert "all_proxy=(unset)" in log_text
        assert "system.example" not in log_text
        assert "configured.example" not in log_text
        assert "NO_PROXY=system-upper,shared.local,10.0.0.0/8" in log_text
        assert "no_proxy=system-lower,10.0.0.0/8" in log_text
        assert "OPENCODE_CONFIG_CONTENT=(unset)" in log_text
        assert f"XDG_CONFIG_HOME={startup_cwd / '.opendeephole-xdg-config'}" in log_text
        assert f"OPENCODE_CONFIG_DIR={startup_cwd}" in log_text
        assert f"config_file_path={runtime_config_path}" in log_text
        assert "config_content_redacted=" in log_text
        assert '"mcp": {}' in log_text
        assert '"plugin": [' in log_text
        assert "popen_kwargs={'start_new_session': True}" in log_text

    asyncio.run(run())


def test_write_marker_records_windows_process_creation_times(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from task_agent import serve_client

    class FakeProc:
        pid = 12345

    marker_path = tmp_path / "serve-marker.json"
    monkeypatch.setattr(serve_client.sys, "platform", "win32")
    monkeypatch.setattr(
        serve_client,
        "_windows_process_creation_time",
        lambda pid: pid * 10,
    )

    serve_client._write_marker(
        marker_path,
        proc=FakeProc(),
        key=OpenCodeServeKey(tool="opencode", executable="opencode"),
        port=64251,
        launcher_pid=23456,
        listener_pids={34567},
    )

    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["process_creation_times"] == {
        str(os.getpid()): os.getpid() * 10,
        "12345": 123450,
        "23456": 234560,
        "34567": 345670,
    }


def test_windows_marker_pid_states_use_creation_tokens(monkeypatch) -> None:
    from task_agent import serve_client

    marker = {
        "process_creation_times": {
            "11111": 100,
            "22222": 200,
            "33333": 300,
        },
    }
    monkeypatch.setattr(
        serve_client,
        "_windows_process_parent_snapshot",
        lambda: {11111: 1, 22222: 1},
    )
    monkeypatch.setattr(
        serve_client,
        "_windows_process_creation_time",
        lambda pid: {11111: 100, 22222: 201}.get(pid),
    )

    assert serve_client._windows_marker_pid_states(
        marker,
        {11111, 22222, 33333},
        listener_pids={11111, 22222, 33333},
    ) == {
        11111: "owned",
        22222: "foreign",
        33333: "absent",
    }


def test_start_locked_resolves_only_configured_nga_when_both_are_available(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        available = {
            "opencode": "/bin/opencode",
            "nga": "/opt/nga/bin/nga",
        }
        resolved: list[str] = []

        def resolve(name: str) -> str:
            resolved.append(name)
            return available[name]

        monkeypatch.setattr("task_agent.serve_client._resolve_executable", resolve)
        monkeypatch.setattr("task_agent.serve_client._run_command_text", lambda cmd: "nga 1.0")
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("task_agent.serve_client._port_bind_error", lambda port: None)
        manager = OpenCodeServeManager()
        manager._stop_owned_serve_on_port = AsyncMock()
        manager._start_once_locked = AsyncMock()
        key = OpenCodeServeKey(tool="opencode", executable="nga")

        await manager._start_locked(key, startup_cwd=tmp_path)

        assert resolved == ["nga"]
        assert manager._start_once_locked.await_args.kwargs["executable"] == "/opt/nga/bin/nga"
        assert manager._start_once_locked.await_args.args[0] == key

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
        monkeypatch.setattr("task_agent.serve_client._serve_bootstrap_cwd", lambda tool: bootstrap_cwd)
        monkeypatch.setattr("task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "task_agent.serve_client._new_serve_startup_log_path",
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

        monkeypatch.setattr("task_agent.serve_client.subprocess.run", fake_run)
        monkeypatch.setattr("task_agent.serve_client.subprocess.Popen", fake_popen)
        monkeypatch.setattr(
            "task_agent.serve_client._register_owned_serve_process",
            lambda proc, path: None,
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert git_init_cwds == [bootstrap_cwd]
        assert popen_kwargs[0]["cwd"] == str(bootstrap_cwd)
        assert (bootstrap_cwd / ".git").is_dir()

    asyncio.run(run())


@pytest.mark.parametrize("executable", [
    r"C:\Program Files\nodejs\opencode.CMD",
    r"C:\Program Files\中文目录\opencode.bAt",
    r"C:\Users\tester\AppData\Roaming\npm\nga.cmd",
])
@pytest.mark.parametrize("arguments", [
    ("--version",),
    ("serve", "--hostname", "127.0.0.1", "--port", "51612"),
])
def test_windows_batch_executable_uses_command_processor(
    monkeypatch,
    executable: str,
    arguments: tuple[str, ...],
) -> None:
    monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
    monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")

    argv = _executable_argv(executable, *arguments)

    assert argv == [
        r"C:\Windows\System32\cmd.exe",
        "/d",
        "/c",
        "call",
        executable,
        *arguments,
    ]
    # This is the final conversion Popen performs before CreateProcess.
    rendered = subprocess.list2cmdline(argv)
    assert r'\"' not in rendered
    if " " in executable:
        assert f'"{executable}"' in rendered


@pytest.mark.parametrize(("platform", "executable"), [
    ("win32", r"C:\Program Files\OpenCode\opencode.exe"),
    ("linux", "/opt/program files/opencode"),
    ("linux", "/opt/program files/opencode.cmd"),
])
def test_native_executable_preserves_separate_arguments(
    monkeypatch,
    platform: str,
    executable: str,
) -> None:
    monkeypatch.setattr("task_agent.serve_client.sys.platform", platform)

    assert _executable_argv(executable, "serve", "--port", "51612") == [
        executable, "serve", "--port", "51612",
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows cmd.exe")
def test_windows_batch_path_with_spaces_runs_version_and_serve(tmp_path: Path) -> None:
    executable = tmp_path / "Program Files" / "中文目录" / "opencode.CMD"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(
        b'@echo off\r\n'
        b'if "%~1"=="--version" (\r\n'
        b'  echo 1.2.3\r\n'
        b'  exit /b 0\r\n'
        b')\r\n'
        b'echo %*\r\n'
        b'exit /b 0\r\n'
    )

    version = asyncio.run(_run_command_text_async(
        _executable_argv(str(executable), "--version"),
    ))
    assert version.strip() == "1.2.3"

    completed = subprocess.run(
        _executable_argv(
            str(executable), "serve", "--hostname", "127.0.0.1", "--port", "51612",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "serve --hostname 127.0.0.1 --port 51612"


def test_async_command_probe_timeout_stops_its_windows_process_tree(
    monkeypatch,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 24680
            returncode = None

            async def wait(self):
                await asyncio.Event().wait()

        captured: dict = {}
        proc = FakeProc()

        async def fake_create_subprocess_exec(*cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return proc

        async def fake_stop(candidate):
            assert candidate is proc
            proc.returncode = -9
            return True

        monkeypatch.setattr(serve_client.sys, "platform", "win32")
        monkeypatch.setattr(
            serve_client.subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0x200,
            raising=False,
        )
        monkeypatch.setattr(
            serve_client.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )
        monkeypatch.setattr(
            serve_client,
            "_stop_command_probe_process",
            fake_stop,
        )

        result = await _run_command_text_async(
            [r"C:\Windows\System32\cmd.exe", "/c", "nga.CMD --version"],
            timeout=0.01,
        )

        assert result == ""
        assert captured["cmd"][-1] == "nga.CMD --version"
        assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
        assert captured["kwargs"]["stdout"] != subprocess.PIPE
        assert captured["kwargs"]["stderr"] == subprocess.STDOUT
        assert captured["kwargs"]["creationflags"] == 0x200

    asyncio.run(run())


def test_async_command_probe_reads_stdout_and_stderr_without_pipes() -> None:
    result = asyncio.run(_run_command_text_async([
        sys.executable,
        "-c",
        (
            "import sys; "
            "print('probe-stdout'); "
            "print('probe-stderr', file=sys.stderr)"
        ),
    ]))

    assert "probe-stdout" in result
    assert "probe-stderr" in result


def test_async_command_probe_nonzero_exit_keeps_error_out_of_version(caplog) -> None:
    from task_agent import serve_client

    caplog.set_level("DEBUG", logger=serve_client.logger.name)
    result = asyncio.run(_run_command_text_async([
        sys.executable,
        "-c",
        "import sys; print('probe-failed', file=sys.stderr); sys.exit(1)",
    ]))

    assert result == ""
    assert "exit_code=1 output=probe-failed" in caplog.text


def test_stop_command_probe_process_uses_windows_taskkill_tree(
    monkeypatch,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeTarget:
            pid = 24680
            returncode = None

            async def wait(self):
                self.returncode = -9
                return self.returncode

            def kill(self):
                self.returncode = -9

        class FakeKiller:
            returncode = None

            async def wait(self):
                self.returncode = 0
                return self.returncode

            def kill(self):
                self.returncode = -9

        calls: list[tuple] = []

        async def fake_create_subprocess_exec(*cmd, **kwargs):
            calls.append((cmd, kwargs))
            return FakeKiller()

        monkeypatch.setattr(serve_client.sys, "platform", "win32")
        monkeypatch.setattr(
            serve_client.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        target = FakeTarget()
        assert await _stop_command_probe_process(target) is True
        assert calls[0][0] == (
            "taskkill",
            "/PID",
            "24680",
            "/T",
            "/F",
        )
        assert calls[0][1]["stdout"] == subprocess.DEVNULL

    asyncio.run(run())


def test_start_locked_publishes_config_before_optional_version_probe(
    caplog,
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        caplog.set_level("INFO", logger=serve_client.logger.name)
        workspace = tmp_path / "runtime"
        (workspace / ".git").mkdir(parents=True)
        version_calls: list[tuple[list[str], float]] = []

        async def unavailable_version(cmd, timeout):
            assert (workspace / "opencode.json").is_file()
            version_calls.append((cmd, timeout))
            return ""

        monkeypatch.setattr(
            serve_client,
            "_resolve_executable",
            lambda _name: "/opt/nga/bin/nga",
        )
        monkeypatch.setattr(
            serve_client,
            "_run_command_text_async",
            unavailable_version,
        )
        monkeypatch.setattr(serve_client, "_port_is_in_use", lambda _port: False)
        manager = OpenCodeServeManager()
        manager._stop_owned_serve_on_port = AsyncMock(
            return_value=serve_client._PreviousServeCleanupResult()
        )
        manager._start_once_locked = AsyncMock()

        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="nga",
                config_content='{"provider": {"corp": {}}}',
            ),
            startup_cwd=workspace,
        )

        assert version_calls == [
            (["/opt/nga/bin/nga", "--version"], 3.0),
        ]
        manager._start_once_locked.assert_awaited_once()
        assert manager._start_once_locked.await_args.kwargs["executable_version"] == ""
        published = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
        assert published["provider"] == {"corp": {}}
        log_messages = [record.getMessage() for record in caplog.records]
        assert any(
            "step=previous_serve_cleanup status=start" in message
            for message in log_messages
        )
        assert any(
            "step=previous_serve_cleanup status=complete" in message
            for message in log_messages
        )

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


def test_wait_health_records_owned_listener_pid(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 11111
            returncode = None

            def poll(self):
                return None

        class FakeHealthClient:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def get(self, path: str):
                return _FakeResponse({"healthy": True})

        marker_path = tmp_path / "serve-marker.json"
        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", FakeHealthClient)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr(
            "task_agent.serve_client._owned_listener_pids_for_launcher",
            lambda port, launcher_pid: ({22222}, {22222}, True),
        )

        key = OpenCodeServeKey(tool="opencode", executable="opencode")
        proc = FakeProc()
        manager = OpenCodeServeManager()
        manager._proc = proc
        manager._key = key
        manager._port = 4096
        serve_client._write_marker(
            marker_path,
            proc=proc,
            key=key,
            port=4096,
        )

        await manager._wait_health_locked()

        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert manager._listener_pids == {22222}
        assert marker["pid"] == 11111
        assert marker["launcher_pid"] == 11111
        assert marker["listener_pids"] == [22222]

    asyncio.run(run())


def test_wait_health_rejects_foreign_listener_response(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 11111

            def __init__(self) -> None:
                self.returncode = None

            def poll(self):
                return self.returncode

        class FakeHealthClient:
            requests: list[str] = []

            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                return None

            async def get(self, path: str):
                self.requests.append(path)
                return _FakeResponse({"healthy": True})

        proc = FakeProc()

        async def fake_sleep(delay: float) -> None:
            proc.returncode = 1

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-serve-marker.json"),
        )
        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", FakeHealthClient)
        monkeypatch.setattr("task_agent.serve_client.asyncio.sleep", fake_sleep)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr(
            "task_agent.serve_client._owned_listener_pids_for_launcher",
            lambda port, launcher_pid: ({22222}, set(), True),
        )
        manager = OpenCodeServeManager()
        manager._proc = proc
        manager._port = 4096

        with pytest.raises(RuntimeError, match="exited during startup with code 1"):
            await manager._wait_health_locked()

        assert FakeHealthClient.requests == ["/global/health"]

    asyncio.run(run())


def test_ensure_started_adopts_healthy_listener_after_launcher_exit(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 11111
            returncode = 0

            def poll(self):
                return 0

        marker_path = tmp_path / "serve-marker.json"
        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {22222},
        )
        registered: list[int] = []
        unregistered: list[int] = []
        monkeypatch.setattr(
            "task_agent.serve_client._register_owned_serve_process",
            lambda proc, path: registered.append(proc.pid),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._unregister_owned_serve_process",
            lambda pid: unregistered.append(pid),
        )

        key = OpenCodeServeKey(tool="opencode", executable="opencode")
        proc = FakeProc()
        manager = OpenCodeServeManager()
        manager._proc = proc
        manager._key = key
        manager._port = 4096
        manager._listener_pids = {22222}
        manager._serve_health_ready = AsyncMock(return_value=True)
        manager._reset_managed_mcp_process_state = AsyncMock()
        manager._stop_event_hub = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        serve_client._write_marker(
            marker_path,
            proc=proc,
            key=key,
            port=4096,
            listener_pids={22222},
        )

        mode = await manager._ensure_started_locked(key)

        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert mode == "reused"
        assert manager._proc is not proc
        assert manager._proc.pid == 22222
        assert manager._proc.poll() is None
        assert manager._listener_pids == {22222}
        assert marker["pid"] == 22222
        assert marker["launcher_pid"] == 11111
        assert marker["listener_pids"] == [22222]
        assert registered == [22222]
        assert unregistered == [11111]
        manager._reset_managed_mcp_process_state.assert_not_awaited()
        manager._stop_event_hub.assert_not_awaited()
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()

    monkeypatch.setattr(
        "task_agent.serve_client._pid_is_running",
        lambda pid: pid == 22222,
    )
    asyncio.run(run())


def test_wait_health_polls_once_per_second_after_unhealthy_attempts(monkeypatch) -> None:
    async def run() -> None:
        class FakeProc:
            returncode = None

            def poll(self):
                return None

        class FakeHealthResponse:
            def __init__(self, status_code: int, data: object) -> None:
                self.status_code = status_code
                self.data = data

            def json(self):
                return self.data

        class FakeHealthClient:
            outcomes = [
                OSError("not ready"),
                FakeHealthResponse(500, {"healthy": False}),
                FakeHealthResponse(204, {"healthy": True}),
                FakeHealthResponse(200, {"healthy": False}),
                FakeHealthResponse(200, {"healthy": True}),
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

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", FakeHealthClient)
        monkeypatch.setattr("task_agent.serve_client.asyncio.sleep", fake_sleep)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096

        await manager._wait_health_locked()

        assert FakeHealthClient.requests == ["/global/health"] * 5
        assert sleeps == [
            _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
            _SERVE_HEALTH_POLL_INTERVAL_SECONDS,
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
        monkeypatch.setattr("task_agent.serve_client._SERVE_START_TIMEOUT_SECONDS", 0.0)
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096
        manager._startup_cwd = tmp_path / "runtime"

        with pytest.raises(OpenCodeServeStartupError) as excinfo:
            await manager._wait_health_locked(startup_log)

        message = str(excinfo.value)
        assert "OpenCode serve did not become healthy" in message
        assert f"startup_cwd={tmp_path / 'runtime'}" in message
        assert "provider failed to load" in message
        assert excinfo.value.retry_kind == "health"
        assert not isinstance(excinfo.value, TimeoutError)

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
                "listener_pids": [22222],
            }),
            encoding="utf-8",
        )
        terminated: list[int] = []
        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("task_agent.serve_client._pid_is_running", lambda pid: pid == 11111)
        monkeypatch.setattr("task_agent.serve_client._marker_matches_serve_process", lambda marker: True)
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("task_agent.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())
        monkeypatch.setattr(
            "task_agent.serve_client._register_owned_serve_process",
            lambda proc, path: None,
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [11111]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 22222

    asyncio.run(run())


def test_start_locked_reclaims_unconnectable_stale_child_listener_after_marker_parent_exits(
    monkeypatch,
    tmp_path: Path,
) -> None:
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
                "listener_pids": [22222],
            }),
            encoding="utf-8",
        )
        listener_state = {"present": True}
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        def fake_terminate(pid, *args, **kwargs):
            terminated.append(pid)
            listener_state["present"] = False
            return True

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("task_agent.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {22222} if listener_state["present"] else set(),
        )
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("task_agent.serve_client.subprocess.Popen", lambda *args, **kwargs: FakeProc())
        monkeypatch.setattr(
            "task_agent.serve_client._register_owned_serve_process",
            lambda proc, path: None,
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock()

        await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == [22222]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        assert marker["pid"] == 33333

    asyncio.run(run())


def test_stop_locked_terminates_process_tree_and_removes_marker(monkeypatch, tmp_path: Path) -> None:
    async def run() -> None:
        from task_agent import serve_client

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
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)
        monkeypatch.setattr("task_agent.serve_client._install_serve_exit_hooks", lambda: None)

        proc = FakeProc()
        manager = OpenCodeServeManager()
        manager._proc = proc
        serve_client._register_owned_serve_process(proc, marker_path)

        await manager._stop_locked()

        assert terminated == [33333]
        assert proc.wait_calls == [0.01]
        assert not marker_path.exists()
        assert (os.getpid(), 33333) not in serve_client._OWNED_SERVE_PROCESSES

    asyncio.run(run())


def test_stop_locked_retains_state_and_retries_when_owned_tree_survives(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 33333

            def poll(self):
                return None

            def wait(self, timeout):
                raise subprocess.TimeoutExpired("opencode", timeout)

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": os.getpid(),
                "pid": 33333,
                "port": 4096,
                "tool": "opencode",
                "executable": "opencode",
            }),
            encoding="utf-8",
        )

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        termination_results = [False, True]

        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            lambda *args, **kwargs: termination_results.pop(0),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._pid_is_running",
            lambda pid: pid == 33333,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._install_serve_exit_hooks",
            lambda: None,
        )

        proc = FakeProc()
        manager = OpenCodeServeManager()
        manager._proc = proc
        manager._port = 4096
        manager._key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
        )
        manager._startup_cwd = tmp_path / "runtime"
        serve_client._register_owned_serve_process(proc, marker_path)
        try:
            with pytest.raises(RuntimeError, match="did not stop completely"):
                await manager._stop_locked()

            assert marker_path.exists()
            assert (os.getpid(), 33333) in serve_client._OWNED_SERVE_PROCESSES
            assert manager._proc is proc
            assert manager._port == 4096
            assert manager._key is not None
            assert manager._startup_cwd == tmp_path / "runtime"
            assert manager._restart_required is True

            await manager._stop_locked()

            assert manager._proc is None
            assert manager._port is None
            assert manager._key is None
            assert manager._startup_cwd is None
            assert not marker_path.exists()
            assert (os.getpid(), 33333) not in serve_client._OWNED_SERVE_PROCESSES
        finally:
            serve_client._unregister_owned_serve_process(33333)

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
            if pid == 33333:
                return True
            terminated.append(pid)
            port_state["in_use"] = False
            return True

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: port_state["in_use"])
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {44444} if port_state["in_use"] else set(),
        )
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", fake_terminate)
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 4096
        manager._listener_pids = {44444}

        await manager._stop_locked()

        assert terminated == [44444]
        assert not marker_path.exists()

    asyncio.run(run())


def test_stop_locked_windows_retires_absent_root_and_reused_listener(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 23256

            def poll(self):
                return None

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": os.getpid(),
                "pid": 23256,
                "launcher_pid": 23256,
                "port": 21442,
                "tool": "opencode",
                "executable": "nga.cmd",
                "listener_pids": [26848],
                "process_creation_times": {
                    "23256": 100,
                    "26848": 200,
                },
            }),
            encoding="utf-8",
        )

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1, 26848: 23256},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_creation_time",
            lambda pid: 300 if pid == 26848 else None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {26848} if port == 21442 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 21442
        manager._listener_pids = {26848}
        manager._key = OpenCodeServeKey(tool="opencode", executable="nga.cmd")

        await manager._stop_locked(reason="fresh-session retry")

        assert manager._proc is None
        assert manager._port is None
        assert manager._listener_pids == set()
        assert not marker_path.exists()

    asyncio.run(run())


def test_stop_locked_windows_retains_unknown_owned_pid_without_killing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class FakeProc:
            pid = 23256

            def poll(self):
                return None

        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": os.getpid(),
                "pid": 23256,
                "port": 21442,
                "tool": "opencode",
                "executable": "nga.cmd",
                "process_creation_times": {"23256": 100},
            }),
            encoding="utf-8",
        )

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1, 23256: os.getpid()},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_creation_time",
            lambda _pid: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda _port: set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 21442
        manager._key = OpenCodeServeKey(tool="opencode", executable="nga.cmd")

        with pytest.raises(RuntimeError, match="did not stop completely"):
            await manager._stop_locked(reason="fresh-session retry")

        assert manager._proc is not None
        assert marker_path.exists()

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
        monkeypatch.setattr("task_agent.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))

        manager = OpenCodeServeManager()
        await manager._stop_owned_serve_on_port(4096)

        assert terminated == []
        assert not marker_path.exists()

    asyncio.run(run())


def test_stop_owned_serve_retries_unconnectable_stale_listener(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 11111,
                "port": 26843,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [15668],
            }),
            encoding="utf-8",
        )
        listening = {15668}
        terminated: list[int] = []
        termination_results = [False, True]

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        def fake_terminate(pid, *args, **kwargs):
            terminated.append(pid)
            stopped = termination_results.pop(0)
            if stopped:
                listening.discard(pid)
            return stopped

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr("task_agent.serve_client._pid_is_running", lambda pid: False)
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: False)
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: (
                OSError(10048, "address already in use")
                if listening
                else None
            ),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: set(listening),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._wait_listener_pids_released",
            lambda port, pids: set(pids) & listening,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            fake_terminate,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        with pytest.raises(RuntimeError) as excinfo:
            await manager._stop_owned_serve_on_port(26843)

        assert "pid(s)=15668" in str(excinfo.value)
        assert "reclaim=owned listener pid(s) still listening" in str(excinfo.value)
        assert marker_path.exists()

        await manager._stop_owned_serve_on_port(26843)

        assert terminated == [15668, 15668]
        assert not marker_path.exists()

    asyncio.run(run())


def test_start_locked_clears_bindable_ghost_marker_without_terminating(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 11111,
                "port": 23678,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [3980],
            }),
            encoding="utf-8",
        )
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._run_command_text",
            lambda cmd: "opencode test",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._pid_is_running",
            lambda pid: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {3980} if port == 23678 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            lambda pid, **kwargs: terminated.append(pid),
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "23678"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert terminated == []
        assert not marker_path.exists()
        manager._start_once_locked.assert_awaited_once()
        assert manager._start_once_locked.await_args.kwargs["port"] == 23678
        assert manager._auto_port == 23678

    asyncio.run(run())


def test_start_locked_auto_port_skips_absent_process_while_old_port_drains(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 11111,
                "launcher_pid": 11111,
                "port": 64251,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [19680],
            }),
            encoding="utf-8",
        )
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        allocated: list[set[int]] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {19680} if port == 64251 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: (
                OSError(10048, "address already in use")
                if port == 64251
                else None
            ),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        def allocate(excluded: set[int]) -> int:
            allocated.append(set(excluded))
            return 64252

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "64251"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert allocated == [{64251}]
        assert not marker_path.exists()
        manager._start_once_locked.assert_awaited_once()
        assert manager._start_once_locked.await_args.kwargs["port"] == 64252
        assert manager._start_once_locked.await_args.kwargs["attempt"] == 2
        assert manager._auto_port == 64252

    asyncio.run(run())


def test_start_locked_fixed_port_reports_draining_absent_process_port(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 11111,
                "port": 64251,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [19680],
            }),
            encoding="utf-8",
        )
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {19680} if port == 64251 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: OSError(10048, "address already in use"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(
                OpenCodeServeKey(
                    tool="opencode",
                    executable="opencode",
                    config_content="{}",
                    env_overrides=(("OPENCODE_SERVE_PORT", "64251"),),
                ),
                startup_cwd=startup_cwd,
            )

        assert not marker_path.exists()
        manager._start_once_locked.assert_not_awaited()
        message = str(excinfo.value)
        assert "port_mode=fixed" in message
        assert "address already in use" in message
        assert "attempted_ports=64251" in message

    asyncio.run(run())


@pytest.mark.parametrize(
    ("identity_fields", "current_creation_time"),
    [
        ({"process_creation_times": {"19680": 100}}, 200),
        (
            {"created_at": 1_000_000_000},
            (1_000_000_100 + 11_644_473_600) * 10_000_000,
        ),
    ],
)
def test_start_locked_does_not_terminate_reused_marker_pid(
    monkeypatch,
    tmp_path: Path,
    identity_fields: dict,
    current_creation_time: int,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 19680,
                "launcher_pid": 19680,
                "port": 64251,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [19680],
                **identity_fields,
            }),
            encoding="utf-8",
        )
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1, 19680: 1},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_creation_time",
            lambda pid: current_creation_time if pid == 19680 else None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {19680} if port == 64251 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda port: port == 64251,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: (
                OSError(10048, "address already in use")
                if port == 64251
                else None
            ),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            lambda pid, **kwargs: terminated.append(pid),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            lambda excluded: 64252,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "64251"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert terminated == []
        assert not marker_path.exists()
        assert manager._start_once_locked.await_args.kwargs["port"] == 64252

    asyncio.run(run())


def test_stop_owned_serve_retains_marker_when_pid_identity_is_unknown(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        marker_path = tmp_path / "serve-marker.json"
        marker_path.write_text(
            json.dumps({
                "owner": "opendeephole-agent-serve-v1",
                "agent_pid": 77777,
                "pid": 19680,
                "port": 64251,
                "tool": "opencode",
                "executable": "opencode",
                "listener_pids": [19680],
                "process_creation_times": {"19680": 100},
            }),
            encoding="utf-8",
        )

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr("task_agent.serve_client.sys.platform", "win32")
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_parent_snapshot",
            lambda: {os.getpid(): 1, 19680: 1},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._windows_process_creation_time",
            lambda _pid: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda _port: {19680},
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda _port: OSError(10048, "address already in use"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.asyncio.to_thread",
            fake_to_thread,
        )

        manager = OpenCodeServeManager()
        with pytest.raises(RuntimeError) as excinfo:
            await manager._stop_owned_serve_on_port(64251)

        assert "pid_states=19680:unknown" in str(excinfo.value)
        assert marker_path.exists()

    asyncio.run(run())


def test_start_locked_reports_foreign_listener_without_terminating_it(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        terminated: list[int] = []

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(tmp_path / "missing-marker.json"))
        monkeypatch.setattr("task_agent.serve_client._resolve_executable", lambda name: "/bin/opencode")
        monkeypatch.setattr("task_agent.serve_client._port_is_in_use", lambda port: True)
        monkeypatch.setattr("task_agent.serve_client._listener_pids_for_port", lambda port: {22222})
        monkeypatch.setattr("task_agent.serve_client._terminate_process_tree", lambda pid: terminated.append(pid))
        monkeypatch.setattr("task_agent.serve_client.asyncio.to_thread", fake_to_thread)

        manager = OpenCodeServeManager()

        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(OpenCodeServeKey(tool="opencode", executable="opencode"))

        assert terminated == []
        assert "already in use" in str(excinfo.value)
        assert "listener_pid(s)=22222" in str(excinfo.value)

    asyncio.run(run())


def test_start_locked_auto_port_skips_foreign_listener(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "auto port workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        terminated: list[int] = []

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda port: port == 4096,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {22222} if port == 4096 else set(),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            lambda excluded: 43123,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._terminate_process_tree",
            lambda pid: terminated.append(pid),
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert terminated == []
        assert manager._auto_port == 43123
        assert manager._start_once_locked.await_count == 1
        assert manager._start_once_locked.await_args.kwargs["port"] == 43123
        assert manager._start_once_locked.await_args.kwargs["attempt"] == 2

    asyncio.run(run())


def test_start_locked_allocates_automatic_port_at_launch_boundary(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        events: list[str] = []
        startup_cwd = tmp_path / "workspace"
        startup_cwd.mkdir()

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._run_command_text",
            lambda _cmd: "opencode test",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._write_serve_config_file",
            lambda _cwd, _content: (
                events.append("config") or startup_cwd / "opencode.json"
            ),
        )

        def allocate(excluded: set[int]) -> int:
            assert excluded == set()
            events.append("allocate")
            return 43123

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda _port: None,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
            ),
            startup_cwd=startup_cwd,
        )

        assert events == ["config", "allocate"]
        assert manager._start_once_locked.await_args.kwargs["port"] == 43123
        assert manager._auto_port == 43123

    asyncio.run(run())


def test_start_locked_auto_port_tries_distinct_candidates_until_free(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        occupied = {4096, 43123}
        allocated: list[set[int]] = []
        candidates = iter((43123, 43124))

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda port: port in occupied,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._listener_pids_for_port",
            lambda port: {20000 + port} if port in occupied else set(),
        )

        def allocate(excluded: set[int]) -> int:
            allocated.append(set(excluded))
            return next(candidates)

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert allocated == [{4096}, {4096, 43123}]
        manager._start_once_locked.assert_awaited_once()
        assert manager._start_once_locked.await_args.kwargs["port"] == 43124
        assert manager._start_once_locked.await_args.kwargs["attempt"] == 3
        assert manager._auto_port == 43124

    asyncio.run(run())


def test_start_locked_auto_port_retries_health_timeout_on_new_port(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        allocated: list[set[int]] = []

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda _port: None,
        )

        def allocate(excluded: set[int]) -> int:
            allocated.append(set(excluded))
            return 43124

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock(side_effect=[
            OpenCodeServeStartupError(
                "OpenCode serve did not become healthy; "
                "last_health=ConnectTimeout",
                retry_kind="health",
            ),
            None,
        ])
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert allocated == [{4096}]
        assert [
            call.kwargs["port"]
            for call in manager._start_once_locked.await_args_list
        ] == [4096, 43124]
        assert manager._auto_port == 43124

    asyncio.run(run())


def test_start_locked_auto_port_retries_generic_early_exit_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        allocated: list[set[int]] = []

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )

        def allocate(excluded: set[int]) -> int:
            allocated.append(set(excluded))
            return 43124

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock(side_effect=[
            RuntimeError(
                "OpenCode serve exited during startup with code 1\n\n"
                "OpenCode serve startup output:\nError: Unexpected error"
            ),
            None,
        ])
        await manager._start_locked(
            OpenCodeServeKey(
                tool="opencode",
                executable="opencode",
                serve_port_auto=True,
                config_content="{}",
                env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
            ),
            startup_cwd=startup_cwd,
        )

        assert allocated == [{4096}]
        assert [
            call.kwargs["port"]
            for call in manager._start_once_locked.await_args_list
        ] == [4096, 43124]
        assert manager._auto_port == 43124

    asyncio.run(run())


def test_start_locked_auto_port_stops_after_one_generic_retry(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        allocated: list[set[int]] = []

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )

        def allocate(excluded: set[int]) -> int:
            allocated.append(set(excluded))
            return 43125

        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        error = RuntimeError("Error: Unexpected error")
        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock(side_effect=error)
        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(
                OpenCodeServeKey(
                    tool="opencode",
                    executable="opencode",
                    serve_port_auto=True,
                    config_content="{}",
                    env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
                ),
                startup_cwd=startup_cwd,
            )

        assert allocated == [{4096}]
        assert manager._start_once_locked.await_count == 2
        assert "attempted_ports=4096,43125" in str(excinfo.value)

    asyncio.run(run())


def test_start_locked_auto_port_does_not_retry_when_cleanup_is_incomplete(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 34567

            def poll(self):
                return None

        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)
        marker_path = tmp_path / "serve-marker.json"
        startup_log_path = tmp_path / "serve-startup.log"
        popen_ports: list[int] = []

        def fake_popen(cmd, **kwargs):
            popen_ports.append(int(cmd[-1]))
            return FakeProc()

        monkeypatch.setenv("OPENCODE_SERVE_MARKER", str(marker_path))
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._run_command_text",
            lambda cmd: "opencode test",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda port: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._new_serve_startup_log_path",
            lambda tool, port: startup_log_path,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            pytest.fail,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._install_serve_exit_hooks",
            lambda: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.subprocess.Popen",
            fake_popen,
        )

        manager = OpenCodeServeManager()
        manager._wait_health_locked = AsyncMock(
            side_effect=RuntimeError("Error: Unexpected error")
        )
        manager._stop_locked = AsyncMock(
            side_effect=RuntimeError(
                "OpenCode Serve process tree did not stop completely; "
                "pid=34567 port=4096 ownership marker was retained"
            )
        )
        try:
            with pytest.raises(RuntimeError) as excinfo:
                await manager._start_locked(
                    OpenCodeServeKey(
                        tool="opencode",
                        executable="opencode",
                        serve_port_auto=True,
                        config_content="{}",
                        env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
                    ),
                    startup_cwd=startup_cwd,
                )

            assert popen_ports == [4096]
            message = str(excinfo.value)
            assert "Error: Unexpected error" in message
            assert "cleanup after startup failure also failed" in message
            assert "did not stop completely" in message
            assert marker_path.exists()
            manager._stop_locked.assert_awaited_once()
            assert manager._stop_locked.await_args.kwargs["reason"] == (
                "startup health failure cleanup"
            )
        finally:
            serve_client._unregister_owned_serve_process(34567)

    asyncio.run(run())


def test_start_once_refuses_second_serve_registered_by_current_process(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        from task_agent import serve_client

        class FakeProc:
            pid = 34568

            def poll(self):
                return None

        marker_path = tmp_path / "existing-marker.json"
        monkeypatch.setattr(
            "task_agent.serve_client._install_serve_exit_hooks",
            lambda: None,
        )
        monkeypatch.setattr(
            "task_agent.serve_client.subprocess.Popen",
            pytest.fail,
        )
        serve_client._register_owned_serve_process(FakeProc(), marker_path)
        try:
            manager = OpenCodeServeManager()
            with pytest.raises(RuntimeError, match="Refusing to start a second"):
                await manager._start_once_locked(
                    OpenCodeServeKey(tool="opencode", executable="opencode"),
                    executable="/bin/opencode",
                    executable_version="test",
                    port=43123,
                    prepared_cwd=tmp_path,
                    config_path=tmp_path / "opencode.json",
                    attempt=1,
                )
        finally:
            serve_client._unregister_owned_serve_process(34568)

    asyncio.run(run())


def test_start_locked_auto_port_does_not_retry_non_port_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        allocate = pytest.fail
        monkeypatch.setattr(
            "task_agent.serve_client._allocate_loopback_port",
            allocate,
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock(
            side_effect=RuntimeError("ConfigError: failed to parse opencode.json")
        )
        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(
                OpenCodeServeKey(
                    tool="opencode",
                    executable="opencode",
                    serve_port_auto=True,
                    config_content="{}",
                    env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
                ),
                startup_cwd=startup_cwd,
            )

        assert manager._start_once_locked.await_count == 1
        assert "port_mode=auto" in str(excinfo.value)
        assert "attempted_ports=4096" in str(excinfo.value)

    asyncio.run(run())


def test_start_locked_fixed_port_reports_bind_denial_without_retry(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        startup_cwd = tmp_path / "workspace"
        (startup_cwd / ".git").mkdir(parents=True)

        monkeypatch.setenv(
            "OPENCODE_SERVE_MARKER",
            str(tmp_path / "missing-marker.json"),
        )
        monkeypatch.setattr(
            "task_agent.serve_client._resolve_executable",
            lambda _name: "/bin/opencode",
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_is_in_use",
            lambda _port: False,
        )
        monkeypatch.setattr(
            "task_agent.serve_client._port_bind_error",
            lambda _port: PermissionError(10013, "access permissions"),
        )

        manager = OpenCodeServeManager()
        manager._start_once_locked = AsyncMock()
        with pytest.raises(RuntimeError) as excinfo:
            await manager._start_locked(
                OpenCodeServeKey(
                    tool="opencode",
                    executable="opencode",
                    config_content="{}",
                    env_overrides=(("OPENCODE_SERVE_PORT", "4096"),),
                ),
                startup_cwd=startup_cwd,
            )

        message = str(excinfo.value)
        manager._start_once_locked.assert_not_awaited()
        assert "excluded/reserved" in message
        assert "access permissions" in message
        assert "port_mode=fixed" in message
        assert "attempted_ports=4096" in message

    asyncio.run(run())


def test_wait_health_redacts_startup_output_and_explains_password_warning(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def run() -> None:
        class ExitedProc:
            pid = 12345
            returncode = 1

            def poll(self):
                return self.returncode

        startup_log_path = tmp_path / "serve-startup.log"
        startup_log_path.write_text(
            "Warning: OPENCODE_SERVER_PASSWORD is not set; server is unsecured.\n"
            "Error: Unexpected error apiKey=super-secret-key\n",
            encoding="utf-8",
        )
        manager = OpenCodeServeManager()
        manager._proc = ExitedProc()
        manager._key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            config_content=json.dumps({
                "provider": {"corp": {"options": {"apiKey": "super-secret-key"}}}
            }),
        )
        manager._try_adopt_owned_listener_locked = AsyncMock(return_value=False)

        with pytest.raises(RuntimeError) as excinfo:
            await manager._wait_health_locked(startup_log_path)

        message = str(excinfo.value)
        assert "super-secret-key" not in message
        assert "apiKey=***" in message
        assert "warning is expected" in message
        assert "did not cause this exit" in message

    asyncio.run(run())


def test_startup_output_updates_are_streamed_once_and_redacted(
    caplog,
    tmp_path: Path,
) -> None:
    startup_log_path = tmp_path / "serve-startup.log"
    startup_log_path.write_text(
        "loading provider\napiKey=super-secret-key\npartial",
        encoding="utf-8",
    )
    cursor = _ServeStartupLogCursor()
    config_content = json.dumps({
        "provider": {"corp": {"options": {"apiKey": "super-secret-key"}}}
    })
    caplog.set_level(
        "INFO",
        logger="opendeephole.task_agent.serve_client",
    )

    _log_serve_startup_output_updates(
        startup_log_path,
        cursor,
        config_content=config_content,
    )
    _log_serve_startup_output_updates(
        startup_log_path,
        cursor,
        config_content=config_content,
        final=True,
    )

    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "OpenCode serve startup output: loading provider",
        "OpenCode serve startup output: apiKey=***",
        "OpenCode serve startup output: partial",
    ]
    assert "super-secret-key" not in "\n".join(messages)


def test_model_listing_health_probe_uses_documented_global_endpoint(
    monkeypatch,
) -> None:
    async def run() -> None:
        _FakeModelAsyncClient.instances = []
        _FakeModelAsyncClient.responses = {
            "/global/health": {"healthy": True, "version": "nga-test"},
        }
        monkeypatch.setattr(
            "task_agent.serve_client.httpx.AsyncClient",
            _FakeModelAsyncClient,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345

        result = await manager._probe_model_listing_health()

        assert result == _ServeHealthResult(
            healthy=True,
            status_code=200,
            version="nga-test",
        )
        assert _FakeModelAsyncClient.instances[0].gets == [
            {"path": "/global/health"},
        ]

    asyncio.run(run())


def test_model_listing_checks_health_before_querying_provider() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        order: list[str] = []

        async def probe_health() -> _ServeHealthResult:
            order.append("health")
            return _ServeHealthResult(healthy=True, status_code=200)

        async def fetch_models(_directory: Path | None) -> list[OpenCodeModelInfo]:
            order.append("provider")
            return []

        key = OpenCodeServeKey(tool="opencode", executable="nga")
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = key
        manager._probe_model_listing_health = probe_health
        manager._fetch_models = fetch_models

        result = await manager.list_models(
            tool="opencode",
            executable="nga",
            refresh=True,
        )

        assert result == OpenCodeModelListResult(models=[])
        assert order == ["health", "provider"]

    asyncio.run(run())


def test_unhealthy_idle_serve_restarts_once_before_provider_lookup() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        key = OpenCodeServeKey(tool="opencode", executable="nga")
        models = [OpenCodeModelInfo(
            id="provider/model",
            provider_id="provider",
            model_id="model",
        )]
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = key
        manager._probe_model_listing_health = AsyncMock(side_effect=[
            _ServeHealthResult(healthy=False, detail="connection refused"),
            _ServeHealthResult(healthy=True, status_code=200),
        ])
        manager._wait_until_idle_locked = AsyncMock()
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = AsyncMock(return_value=models)

        result = await manager.list_models(
            tool="opencode",
            executable="nga",
            refresh=True,
        )

        assert result == OpenCodeModelListResult(models=models)
        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once()
        restarted_key = manager._start_locked.await_args.args[0]
        assert restarted_key.tool == "opencode"
        assert restarted_key.executable == "nga"
        assert manager._start_locked.await_args.kwargs == {"startup_cwd": None}
        manager._fetch_models.assert_awaited_once_with(None)

    asyncio.run(run())


def test_unhealthy_active_serve_never_queries_provider_or_restarts() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        key = OpenCodeServeKey(tool="opencode", executable="nga")
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = key
        manager._active_sessions = 1
        manager._probe_model_listing_health = AsyncMock(return_value=
            _ServeHealthResult(healthy=False, detail="connection refused")
        )
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._fetch_models = AsyncMock()

        with pytest.raises(RuntimeError) as excinfo:
            await manager.list_models(
                tool="opencode",
                executable="nga",
                refresh=True,
            )

        message = str(excinfo.value)
        assert "健康检查失败" in message
        assert "不会请求 Provider" in message
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()
        manager._fetch_models.assert_not_awaited()

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
        manager._ensure_model_listing_health_locked = AsyncMock()

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
        manager._ensure_model_listing_health_locked = AsyncMock()

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
        manager._ensure_model_listing_health_locked = AsyncMock()

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
        manager._ensure_model_listing_health_locked = AsyncMock()

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
            "env_overrides": {"NO_PROXY": "127.0.0.1,localhost"},
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
        manager._ensure_model_listing_health_locked = AsyncMock()

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
        manager._ensure_model_listing_health_locked = AsyncMock()

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


def test_unhealthy_serve_waits_for_concurrent_sessions_then_restarts_once() -> None:
    async def run() -> None:
        class FakeProc:
            def poll(self):
                return None

        key = OpenCodeServeKey(tool="opencode", executable="opencode")
        manager = OpenCodeServeManager()
        manager._proc = FakeProc()
        manager._port = 12345
        manager._key = key
        manager._active_sessions = 1
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._mark_serve_unhealthy("POST /session", 500)

        first = asyncio.create_task(manager._acquire_session(key))
        second = asyncio.create_task(manager._acquire_session(key))
        await asyncio.sleep(0)

        assert first.done() is False
        assert second.done() is False
        manager._stop_locked.assert_not_awaited()
        manager._start_locked.assert_not_awaited()

        await manager._release_active_session()
        modes = await asyncio.gather(first, second)

        assert modes == ["restarted", "reused"]
        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once_with(key, startup_cwd=None)
        assert manager._restart_required is False
        assert manager._active_sessions == 2

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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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
    manager._managed_mcp_specs["product_info"] = {
        "enabled": True,
        "fingerprint": "missing-binary",
        "error": "Product MCP executable not found: product-info",
    }

    status = manager.managed_mcp_runtime_status()["product_info"]

    assert status["state"] == "failed"
    assert status["error"] == "Product MCP executable not found: product-info"
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

        monkeypatch.setattr("task_agent.serve_client.httpx.AsyncClient", McpClient)
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


def test_shared_cleanup_releases_startup_lock_when_mcp_ignores_cancellation(monkeypatch):
    async def run():
        manager = OpenCodeServeManager()
        manager._start_locked = AsyncMock()
        gate = asyncio.Event()
        async def stuck(*args, **kwargs):
            while not gate.is_set():
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    continue
        manager._sync_managed_mcp_target = AsyncMock(side_effect=stuck)
        task = manager._spawn_managed_mcp_sync("directory", "product_info")
        await asyncio.sleep(0)
        monkeypatch.setattr("task_agent.serve_client.CLEANUP_TIMEOUT_SECONDS", 0.03)
        key = OpenCodeServeKey(tool="opencode", executable="opencode", env_hash="", config_hash="")
        try:
            await asyncio.wait_for(manager._acquire_session(key), 0.3)
            assert not manager._lock.locked()
            assert manager._start_locked.await_count == 1
            assert not task.done()
            await manager._release_active_session()
            await asyncio.wait_for(manager._acquire_session(key), 0.3)
            assert manager._start_locked.await_count == 2
            await manager._release_active_session()
            manager._managed_mcp_directories["directory"] = Path("/new-process")
            manager._managed_mcp_specs["product_info"] = {"fingerprint": "new"}
            manager._managed_mcp_force_pending.add(("directory", "product_info"))
            gate.set()
            await task
            await asyncio.sleep(0)
            assert manager._sync_managed_mcp_target.await_count == 1
            assert ("directory", "product_info") in manager._managed_mcp_force_pending
        finally:
            gate.set()
            await task
    asyncio.run(run())
