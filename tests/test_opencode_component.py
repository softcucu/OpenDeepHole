from __future__ import annotations

import ast
import asyncio
import importlib
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import agent.task_agent as task_agent
from agent.task_agent.host import (
    OpenCodeHostBindings,
    OpenCodeInvocationMetadata,
    OpenCodeSessionRuntime,
    reset_opencode_configuration,
)
from agent.task_agent.model_pool import ModelLease, ModelOption
from agent.task_agent.serve_client import OpenCodePromptResult
from agent.task_agent.task_service import bind_opencode_execution_context


def _bindings(tmp_path: Path) -> OpenCodeHostBindings:
    config = SimpleNamespace(
        opencode=SimpleNamespace(timeout=30, max_retries=0, models=[]),
        fp_review_cli=None,
        opencode_concurrency=1,
    )
    return OpenCodeHostBindings(
        get_config=lambda: config,
        get_workspace=lambda: tmp_path,
        build_session_runtime=lambda _cli, _model, directory: OpenCodeSessionRuntime(
            directory=directory,
            tool="opencode",
            executable="opencode",
            config_workspace=tmp_path,
            config_content="{}",
        ),
    )


def test_component_has_no_opendeephole_package_imports() -> None:
    component_dir = Path(task_agent.__file__).resolve().parent
    forbidden = {"agent", "backend", "code_parser", "mcp_server"}
    violations: list[str] = []
    for source_path in component_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = {node.module.split(".", 1)[0]}
            else:
                continue
            blocked = roots & forbidden
            if blocked:
                violations.append(f"{source_path.name}:{node.lineno}:{sorted(blocked)}")
    assert violations == []


def test_invocation_metadata_can_follow_runtime_session_updates() -> None:
    metadata = OpenCodeInvocationMetadata(attempt=1)
    metadata.model = "provider/model"
    metadata.serve_session_id = "ses-1"
    assert metadata.model_dump()["serve_session_id"] == "ses-1"


def test_component_directory_can_be_imported_as_an_extracted_package(tmp_path: Path) -> None:
    source = Path(task_agent.__file__).resolve().parent
    target = tmp_path / "extracted_task_agent"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    sys.path.insert(0, str(tmp_path))
    try:
        extracted = importlib.import_module("extracted_task_agent")
        assert callable(extracted.run_opencode_task)
        assert not hasattr(extracted, "OpenCodeTaskType")
    finally:
        sys.path.remove(str(tmp_path))
        for name in list(sys.modules):
            if name == "extracted_task_agent" or name.startswith("extracted_task_agent."):
                sys.modules.pop(name, None)


def test_configuration_is_lazy_and_shutdown_discards_both_singletons(tmp_path: Path) -> None:
    from agent.task_agent import serve_client, task_service

    async def run() -> None:
        serve_client._manager = None
        task_service.reset_opencode_task_service()
        task_agent.configure_opencode(_bindings(tmp_path))
        try:
            assert serve_client._manager is None
            assert task_service._service is None

            manager = serve_client.get_serve_manager()
            service = task_service._get_opencode_task_service()
            assert manager is serve_client.get_serve_manager()
            assert service is task_service._get_opencode_task_service()
            assert manager._proc is None

            shutdown = AsyncMock()
            with patch.object(manager, "shutdown", new=shutdown):
                await task_agent.shutdown_opencode()
            shutdown.assert_awaited_once()
            assert serve_client._manager is None
            assert task_service._service is None
        finally:
            reset_opencode_configuration()

    asyncio.run(run())


def test_first_public_task_creates_both_lazy_singletons(tmp_path: Path) -> None:
    from agent.task_agent import serve_client, task_service

    async def run() -> None:
        serve_client._manager = None
        task_service.reset_opencode_task_service()
        task_agent.configure_opencode(_bindings(tmp_path))
        lease = ModelLease(
            option=ModelOption(
                id="model-1",
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
        try:
            with (
                patch(
                    "agent.task_agent.task_service.acquire_model_lease",
                    new=AsyncMock(return_value=lease),
                ),
                patch(
                    "agent.task_agent.task_service.release_model_lease",
                    new=AsyncMock(),
                ),
                patch(
                    "agent.task_agent.task_service.update_model_lease_context",
                    new=AsyncMock(),
                ),
                patch.object(
                    serve_client.OpenCodeServeManager,
                    "run_prompt",
                    new=AsyncMock(return_value=OpenCodePromptResult(
                        session_id="ses-1",
                        message_id="msg-1",
                        lines=["done"],
                        text="done",
                        model="provider/model",
                    )),
                ),
                bind_opencode_execution_context(
                    project_dir=tmp_path,
                    work_dir=tmp_path / "work",
                ),
            ):
                result = await task_agent.run_opencode_task(
                    task_name="lazy lifecycle",
                    task_type="audit",
                    prompt="run",
                    required_capability="high",
                )

            assert result.status == "success"
            assert result.session_id == "ses-1"
            assert task_service._service is not None
            assert serve_client._manager is not None
        finally:
            await task_agent.shutdown_opencode()
            reset_opencode_configuration()

    asyncio.run(run())
