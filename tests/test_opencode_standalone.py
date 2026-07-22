from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import yaml

import task_agent as opencode
from task_agent.host import (
    OpenCodeHostBindings,
    OpenCodeSessionRuntime,
    reset_opencode_configuration,
)
from task_agent.model_pool import ModelLease, ModelOption
from task_agent.serve_client import OpenCodePromptResult, _serve_port
from task_agent.standalone import (
    CONFIG_ENV,
    ensure_opencode_configuration,
    load_standalone_config,
)


def _config_text(
    project_dir: Path,
    *,
    port: int = 4096,
    extra: str = "",
) -> str:
    return (
        "schema_version: 1\n"
        "context:\n"
        f"  project_dir: {project_dir}\n"
        "  work_dir: work\n"
        "  workspace_dir: workspace\n"
        "serve:\n"
        "  tool: opencode\n"
        "  executable: opencode\n"
        f"  port: {port}\n"
        "  timeout: 30\n"
        "  max_retries: 0\n"
        "  environment:\n"
        "    HTTPS_PROXY: http://proxy.example:8080\n"
        "  opencode_config:\n"
        "    provider: {}\n"
        "model_pool:\n"
        "  global_concurrency: 2\n"
        "  models:\n"
        "    - id: provider/model\n"
        "      model: provider/model\n"
        "      capability: high\n"
        "      max_concurrency: 1\n"
        "      enabled: true\n"
        + extra
    )


def _write_config(root: Path, name: str = "task-agent.yaml", **kwargs) -> Path:
    project = root / "project"
    project.mkdir(exist_ok=True)
    path = root / name
    path.write_text(_config_text(project, **kwargs), encoding="utf-8")
    return path


def _host_bindings(root: Path) -> OpenCodeHostBindings:
    config = SimpleNamespace(
        opencode=SimpleNamespace(timeout=30, max_retries=0, models=[]),
        fp_review_cli=None,
        opencode_concurrency=1,
    )
    return OpenCodeHostBindings(
        get_config=lambda: config,
        get_workspace=lambda: root,
        build_session_runtime=lambda _cli, _model, directory: OpenCodeSessionRuntime(
            directory=directory,
            tool="opencode",
            executable="opencode",
            config_workspace=root,
            config_content="{}",
        ),
    )


def test_standalone_config_loads_context_runtime_and_relative_paths(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, port=4317)
    config = load_standalone_config(config_path)

    assert config.source_path == config_path.resolve()
    assert config.project_dir == (tmp_path / "project").resolve()
    assert config.work_dir == (tmp_path / "work").resolve()
    assert config.workspace_dir == (tmp_path / "workspace").resolve()
    assert config.work_dir.is_dir()
    assert config.workspace_dir.is_dir()
    assert config.port == 4317
    assert config.environment["OPENCODE_SERVE_PORT"] == "4317"
    assert config.environment["HTTPS_PROXY"] == "http://proxy.example:8080"
    assert config.opencode_concurrency == 2
    assert config.opencode.models[0].model == "provider/model"
    assert config.opencode_config == {"provider": {}}


def test_example_config_contains_disabled_remote_and_local_mcp_examples() -> None:
    example_path = (
        Path(opencode.__file__).resolve().parent / "task-agent.example.yaml"
    )
    raw = yaml.safe_load(example_path.read_text(encoding="utf-8"))
    mcp = raw["serve"]["opencode_config"]["mcp"]

    assert mcp["remote-example"] == {
        "type": "remote",
        "url": "http://127.0.0.1:9123/mcp",
        "enabled": False,
        "timeout": 30_000,
        "oauth": False,
        "headers": {"Authorization": "Bearer replace-me"},
    }
    assert mcp["local-example"] == {
        "type": "local",
        "command": ["python3", "-m", "your_mcp_server"],
        "environment": {"PROJECT_DIR": "/absolute/path/to/source"},
        "enabled": False,
        "timeout": 30_000,
    }


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("schema_version: 2\n", "schema_version"),
        (
            "schema_version: 1\ncontext: {}\nserve: {}\nmodel_pool: {}\nunknown: true\n",
            "Unknown top-level fields",
        ),
    ],
)
def test_standalone_config_rejects_invalid_schema(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_standalone_config(path)


def test_standalone_config_requires_an_enabled_model(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = tmp_path / "invalid.yaml"
    path.write_text(
        _config_text(project).replace("enabled: true", "enabled: false"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="at least one enabled model"):
        load_standalone_config(path)


def test_standalone_config_discovery_uses_environment_then_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_root = tmp_path / "env"
    env_root.mkdir()
    env_config = _write_config(env_root)
    cwd_root = tmp_path / "cwd"
    cwd_root.mkdir()
    _write_config(cwd_root)
    monkeypatch.chdir(cwd_root)
    monkeypatch.setenv(CONFIG_ENV, str(env_config))
    reset_opencode_configuration()
    try:
        configured = ensure_opencode_configuration(None)
        assert configured is not None
        assert configured.source_path == env_config.resolve()
    finally:
        reset_opencode_configuration()

    monkeypatch.delenv(CONFIG_ENV)
    try:
        configured = ensure_opencode_configuration(None)
        assert configured is not None
        assert configured.source_path == (cwd_root / "task-agent.yaml").resolve()
    finally:
        reset_opencode_configuration()


def test_concurrent_first_calls_load_standalone_configuration_once(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    reset_opencode_configuration()
    from task_agent import standalone

    original_load = standalone.load_standalone_config
    with patch(
        "task_agent.standalone.load_standalone_config",
        wraps=original_load,
    ) as load:
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                configured = list(executor.map(
                    lambda _index: ensure_opencode_configuration(config_path),
                    range(4),
                ))
            assert all(item is configured[0] for item in configured)
            load.assert_called_once_with(config_path.resolve())
        finally:
            reset_opencode_configuration()


def test_host_configuration_wins_without_reading_standalone_file(tmp_path: Path) -> None:
    reset_opencode_configuration()
    opencode.configure_opencode(_host_bindings(tmp_path))
    try:
        with patch(
            "task_agent.standalone.load_standalone_config",
            side_effect=AssertionError("must not read standalone config"),
        ):
            assert ensure_opencode_configuration(None) is None
        with pytest.raises(ValueError, match="config_path"):
            ensure_opencode_configuration(tmp_path / "unused.yaml")
    finally:
        reset_opencode_configuration()


def test_standalone_configuration_is_fixed_until_shutdown(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    first_root.mkdir()
    first = _write_config(first_root)
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _write_config(second_root)
    reset_opencode_configuration()

    async def run() -> None:
        configured = ensure_opencode_configuration(first)
        assert ensure_opencode_configuration(first) is configured
        with pytest.raises(RuntimeError, match="already bound"):
            ensure_opencode_configuration(second)
        await opencode.shutdown_opencode()
        switched = ensure_opencode_configuration(second)
        assert switched is not None
        assert switched.source_path == second.resolve()
        await opencode.shutdown_opencode()

    asyncio.run(run())


def test_public_task_bootstraps_standalone_context_and_reuses_session(
    tmp_path: Path,
) -> None:
    from task_agent import serve_client, task_service

    config_path = _write_config(tmp_path, port=4318)
    lease = ModelLease(
        option=ModelOption(
            id="provider/model",
            model="provider/model",
            use_default_model=False,
            capability="high",
            weight=1,
            max_concurrency=1,
        ),
        running=1,
        global_running=1,
        task_id="task-1",
    )
    run_prompt = AsyncMock(side_effect=[
        OpenCodePromptResult(
            session_id="ses-standalone",
            message_id="msg-1",
            lines=["first"],
            text="first",
            model="provider/model",
        ),
        OpenCodePromptResult(
            session_id="ses-standalone",
            message_id="msg-2",
            lines=["second"],
            text="second",
            model="provider/model",
        ),
    ])

    async def run() -> None:
        reset_opencode_configuration()
        task_service.reset_opencode_task_service()
        serve_client._manager = None
        try:
            with (
                patch(
                    "task_agent.task_service.acquire_model_lease",
                    new=AsyncMock(return_value=lease),
                ),
                patch(
                    "task_agent.task_service.release_model_lease",
                    new=AsyncMock(),
                ),
                patch(
                    "task_agent.task_service.update_model_lease_context",
                    new=AsyncMock(),
                ),
                patch.object(
                    serve_client.OpenCodeServeManager,
                    "run_prompt",
                    new=run_prompt,
                ),
            ):
                first = await opencode.run_opencode_task(
                    task_name="standalone first",
                    task_type="audit",
                    prompt="first",
                    required_capability="high",
                    config_path=config_path,
                )
                second = await opencode.run_opencode_task(
                    task_name="standalone second",
                    task_type="audit",
                    prompt="second",
                    required_capability="high",
                    session_id=first.session_id,
                    config_path=config_path,
                )

            assert second.text == "second"
            first_call = run_prompt.await_args_list[0].kwargs
            second_call = run_prompt.await_args_list[1].kwargs
            assert first_call["directory"] == (tmp_path / "project").resolve()
            assert first_call["config_workspace"] == (tmp_path / "workspace").resolve()
            assert first_call["env_overrides"]["OPENCODE_SERVE_PORT"] == "4318"
            assert second_call["session_id"] == "ses-standalone"
            service = task_service._get_opencode_task_service()
            assert service._session_work_directories["ses-standalone"] == (
                tmp_path / "work"
            ).resolve()
        finally:
            await opencode.shutdown_opencode()
            reset_opencode_configuration()

    asyncio.run(run())


@pytest.mark.parametrize(
    ("task_type", "stage"),
    [
        ("vulnerability_validation", "validation"),
        ("audit", "audit"),
    ],
)
def test_standalone_public_task_prints_realtime_progress(
    tmp_path: Path,
    task_type: str,
    stage: str,
) -> None:
    from task_agent import serve_client, task_service

    config_path = _write_config(tmp_path)
    lease = ModelLease(
        option=ModelOption(
            id="provider/model",
            model="provider/model",
            use_default_model=False,
            capability="high",
            weight=1,
            max_concurrency=1,
        ),
        running=1,
        global_running=1,
        task_id="task-console",
    )
    acquire = AsyncMock(return_value=lease)

    async def run_prompt(_manager, **kwargs):
        assert kwargs["show_serve_status"] is True
        assert callable(kwargs["on_line"])
        assert kwargs["log_stage"] == stage
        callback = kwargs["on_session_id"]("ses-console")
        if hasattr(callback, "__await__"):
            await callback
        return OpenCodePromptResult(
            session_id="ses-console",
            message_id="msg-console",
            lines=["done"],
            text="done",
            model="provider/model",
        )

    async def run() -> None:
        reset_opencode_configuration()
        task_service.reset_opencode_task_service()
        serve_client._manager = None
        try:
            with (
                patch(
                    "task_agent.task_service.acquire_model_lease",
                    new=acquire,
                ),
                patch(
                    "task_agent.task_service.release_model_lease",
                    new=AsyncMock(),
                ),
                patch(
                    "task_agent.task_service.update_model_lease_context",
                    new=AsyncMock(),
                ),
                patch.object(
                    serve_client.OpenCodeServeManager,
                    "run_prompt",
                    new=run_prompt,
                ),
                patch("builtins.print") as console,
            ):
                result = await opencode.run_opencode_task(
                    task_name="console task",
                    task_type=task_type,
                    prompt="test console output",
                    required_capability="high",
                    config_path=config_path,
                )

            assert result.status == "success"
            assert acquire.await_args.kwargs["wait_when_unavailable"] is True
            lines = [str(call.args[0]) for call in console.call_args_list]
            assert any(line.startswith(f"[{stage}][pending][task] QUEUED") for line in lines)
            assert any(line.startswith(f"[{stage}][pending][task] START") for line in lines)
            assert any(
                line.startswith(f"[{stage}][ses-console][task] FINISHED")
                and "status=success" in line
                for line in lines
            )
            assert all("reasoning" not in line.lower() for line in lines)
            assert all(call.kwargs == {"flush": True} for call in console.call_args_list)
        finally:
            await opencode.shutdown_opencode()
            reset_opencode_configuration()

    asyncio.run(run())


def test_host_configuration_does_not_install_default_console_output(tmp_path: Path) -> None:
    reset_opencode_configuration()
    opencode.configure_opencode(_host_bindings(tmp_path))

    async def run() -> None:
        expected = opencode.OpenCodeResult(
            session_id="ses-host",
            status="success",
            text="done",
            structured=None,
            model="provider/model",
        )
        try:
            with (
                patch(
                    "task_agent.task_service._run_component_task",
                    new=AsyncMock(return_value=expected),
                ),
                patch("builtins.print") as console,
            ):
                result = await opencode.run_opencode_task(
                    task_name="host task",
                    task_type="audit",
                    prompt="test host output",
                    required_capability="high",
                )
            assert result == expected
            console.assert_not_called()
        finally:
            reset_opencode_configuration()

    asyncio.run(run())


def test_runtime_port_override_precedes_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENCODE_SERVE_PORT", "4099")
    assert _serve_port({"OPENCODE_SERVE_PORT": "4319"}) == 4319
    assert _serve_port() == 4099
