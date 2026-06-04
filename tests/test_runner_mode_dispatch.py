import asyncio
import json
import time
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import Candidate
from backend.opencode import llm_api_runner
from backend.opencode.llm_api_runner import LLMApiUnavailableError
from backend.opencode.runner import (
    _build_cli_command,
    _build_cli_env,
    _prepare_cli_workspace,
    _select_cli_cwd,
    _terminate_process_tree,
    _wait_for_stream_exit_after_termination,
    run_audit,
    run_audit_batch,
)


def _candidate(line: int = 12) -> Candidate:
    return Candidate(
        file="sample.c",
        line=line,
        function="leaky",
        description="candidate issue",
        vuln_type="memleak",
    )


def _api_registry(tmp_path: Path):
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("api prompt", encoding="utf-8")
    return {"memleak": SimpleNamespace(mode="api", prompt_path=prompt_path)}


def test_cli_command_builders_use_selected_tool(tmp_path: Path) -> None:
    claude = _build_cli_command("claude", "claude", tmp_path, "hello", "sonnet")
    hac = _build_cli_command("hac", "hac", tmp_path, "hello", "gemini-model")
    nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen")
    project_dir = tmp_path / "project"
    isolated_nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen", project_dir=project_dir)

    assert claude[:3] == ["claude", "-p", "--mcp-config"]
    assert "--model" in claude
    assert hac == ["hac", "--model", "gemini-model", "-p", "hello"]
    assert nga[:3] == ["nga", "run", "--dir"]
    assert isolated_nga[:4] == ["nga", "run", "--dir", str(project_dir)]
    assert "--model" in nga


def test_prepare_cli_workspace_creates_claude_and_gemini_skill_configs(tmp_path: Path) -> None:
    (tmp_path / "opencode.json").write_text(
        '{"mcp":{"deephole-code":{"url":"http://127.0.0.1:9123/mcp"}}}',
        encoding="utf-8",
    )
    skill_dir = tmp_path / ".opencode" / "skills" / "prove-bug"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("fp skill", encoding="utf-8")

    _prepare_cli_workspace(tmp_path, "claude")
    _prepare_cli_workspace(tmp_path, "hac")

    assert (tmp_path / ".claude" / "opendeephole-mcp.json").is_file()
    assert (tmp_path / ".claude" / "skills" / "prove-bug" / "SKILL.md").is_file()
    assert (tmp_path / ".gemini" / "settings.json").is_file()
    assert (tmp_path / ".gemini" / "skills" / "prove-bug" / "SKILL.md").is_file()


def test_opencode_uses_injected_config_and_project_dir_with_isolated_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    project.mkdir()
    config_payload = {
        "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
        "skills": {"paths": [str(workspace / ".opencode" / "skills")]},
    }
    (workspace / "opencode.json").write_text(json.dumps(config_payload), encoding="utf-8")
    env = _build_cli_env(workspace, "opencode", base_env={})

    assert _build_cli_command("opencode", "opencode", workspace, "hello", "", project)[:4] == [
        "opencode",
        "run",
        "--dir",
        str(project),
    ]
    assert _select_cli_cwd(workspace, "opencode", project) == project / ".opendeephole" / "opencode"
    assert (project / ".opendeephole" / "opencode").is_dir()
    assert json.loads(env["OPENCODE_CONFIG_CONTENT"]) == config_payload
    assert env["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"


def test_opencode_runtime_cwd_receives_config_and_fp_skills(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    project.mkdir()
    skills_root = workspace / ".opencode" / "skills"
    for name in ("prove-bug", "prove-fp", "final-judge"):
        skill_dir = skills_root / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(name, encoding="utf-8")
    (workspace / "opencode.json").write_text(
        json.dumps({
            "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
            "skills": {"paths": [str(skills_root.resolve())]},
        }),
        encoding="utf-8",
    )

    runtime_cwd = _select_cli_cwd(workspace, "opencode", project)
    config_workspace = _prepare_cli_workspace(
        workspace, "opencode", runtime_cwd=runtime_cwd,
    )
    env = _build_cli_env(config_workspace, "opencode", base_env={})
    runtime_config = json.loads((runtime_cwd / "opencode.json").read_text(encoding="utf-8"))
    env_config = json.loads(env["OPENCODE_CONFIG_CONTENT"])

    assert config_workspace == runtime_cwd
    # Skills should be copied to runtime CWD (opencode walks up from CWD)
    assert (runtime_cwd / ".opencode" / "skills" / "prove-bug" / "SKILL.md").is_file()
    assert (runtime_cwd / ".opencode" / "skills" / "prove-fp" / "SKILL.md").is_file()
    assert (runtime_cwd / ".opencode" / "skills" / "final-judge" / "SKILL.md").is_file()
    assert runtime_config["skills"]["paths"] == [str((runtime_cwd / ".opencode" / "skills").resolve())]
    assert env_config["skills"]["paths"] == runtime_config["skills"]["paths"]


def test_project_runtime_cwd_falls_back_to_workspace_when_unavailable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project_file = tmp_path / "project"
    workspace.mkdir()
    project_file.write_text("not a directory", encoding="utf-8")

    assert _select_cli_cwd(workspace, "opencode", project_file) == workspace
    assert _select_cli_cwd(workspace, "nga", project_file) == workspace
    assert _select_cli_cwd(workspace, "claude", project_file) == workspace


class _FakeStdout:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    def __init__(self) -> None:
        self.pid = 12345
        self.returncode = None
        self.stdout = _FakeStdout()
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_terminate_process_tree_uses_taskkill_on_windows() -> None:
    proc = _FakeProc()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        proc.returncode = -9
        return SimpleNamespace(returncode=0)

    with (
        patch("backend.opencode.runner.sys.platform", "win32"),
        patch("backend.opencode.runner.subprocess.run", side_effect=fake_run),
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    assert calls[0][0] == ["taskkill", "/F", "/T", "/PID", "12345"]
    assert proc.stdout.closed is True
    assert proc.killed is False


def test_terminate_process_tree_falls_back_when_taskkill_fails() -> None:
    proc = _FakeProc()

    with (
        patch("backend.opencode.runner.sys.platform", "win32"),
        patch(
            "backend.opencode.runner.subprocess.run",
            return_value=SimpleNamespace(returncode=1),
        ),
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    assert proc.killed is True
    assert proc.stdout.closed is True


def test_terminate_process_tree_uses_process_group_on_posix() -> None:
    proc = _FakeProc()

    with (
        patch("backend.opencode.runner.sys.platform", "linux"),
        patch("backend.opencode.runner.os.getpgid", return_value=999) as getpgid,
        patch("backend.opencode.runner.os.killpg") as killpg,
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    getpgid.assert_called_once_with(12345)
    killpg.assert_called_once()
    assert proc.stdout.closed is True


def test_stream_exit_wait_after_termination_is_bounded() -> None:
    async def run_check() -> None:
        future = asyncio.get_running_loop().create_future()
        started = time.monotonic()

        await _wait_for_stream_exit_after_termination(
            future,
            tool="opencode",
            timed_out=True,
            cancelled=False,
            timeout=1,
            started=started,
            grace_seconds=0.01,
        )

        assert future.cancelled() is False
        future.cancel()

    asyncio.run(run_check())


def test_api_checker_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_not_awaited()
    opencode_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()
    opencode_audit.assert_awaited_once()


def test_api_checker_batch_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_batch_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_not_awaited()
    assert opencode_audit.await_count == 2


def test_api_checker_batch_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_batch_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_awaited_once()
    assert opencode_audit.await_count == 2


def test_llm_api_health_check_uses_minimal_request_and_caches(monkeypatch) -> None:
    client_kwargs = []
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            return object()

    class FakeOpenAI:
        def __init__(self, **kwargs):
            client_kwargs.append(kwargs)
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="secret",
            model="fake-model",
            timeout=30,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        asyncio.run(llm_api_runner.ensure_llm_api_available())
        asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(client_kwargs) == 1
    assert client_kwargs[0]["base_url"] == "https://example.test/v1"
    assert client_kwargs[0]["api_key"] == "secret"
    assert client_kwargs[0]["timeout"] == 10.0
    assert len(requests) == 1
    assert requests[0]["model"] == "fake-model"
    assert requests[0]["max_tokens"] == 1


def test_llm_api_health_check_failure_is_cached(monkeypatch) -> None:
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            raise RuntimeError("unauthorized")

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="bad",
            model="fake-model",
            timeout=3,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(requests) == 1
