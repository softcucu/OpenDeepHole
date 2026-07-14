from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.models import OutputSource
from backend.opencode.model_pool import ModelLease, ModelOption
from backend.opencode.serve_client import OpenCodePromptResult
from backend.opencode.task_service import (
    OpenCodeTaskService,
    OpenCodeTaskSpec,
    _SessionRuntime,
    _load_skill_system_prompt,
)


def _lease(task_id: str = "task-id") -> ModelLease:
    return ModelLease(
        option=ModelOption(
            id="model-low",
            model="provider/model-low",
            use_default_model=False,
            capability="low",
            weight=1,
            max_concurrency=1,
        ),
        running=1,
        global_running=1,
        started_at=1.0,
        started_at_iso="2026-01-01T00:00:00+00:00",
        task_id=task_id,
    )


def _runtime(directory: Path) -> _SessionRuntime:
    return _SessionRuntime(
        directory=directory,
        tool="opencode",
        executable="opencode",
        config_workspace=directory,
        config_content="{}",
        env_overrides={},
    )


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        opencode=SimpleNamespace(timeout=30, models=[]),
        opencode_concurrency=1,
    )


def test_task_service_parses_plain_json_text_and_records_session(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        captured: dict = {}

        async def run_prompt(**kwargs):
            captured.update(kwargs)
            callback_result = kwargs["on_session_id"]("ses_structured")
            if hasattr(callback_result, "__await__"):
                await callback_result
            kwargs["on_response_model"]("provider/actual-model")
            return OpenCodePromptResult(
                session_id="ses_structured",
                message_id="msg_1",
                lines=['result: ```json\n{"answer": 7}\n```'],
                text='result: ```json\n{"answer": 7}\n```',
                model="provider/actual-model",
            )

        manager.run_prompt = run_prompt
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path),
            "provider/model-low",
            OutputSource(tool="opencode", model_id="model-low", capability="low"),
        ))

        async def acquire(*_args, **kwargs):
            return _lease(kwargs["task_id"])

        schema = {
            "type": "object",
            "properties": {"answer": {"type": "integer"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire) as acquire_mock,
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
            patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
            patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="schema task",
                prompt="return an answer",
                directory=tmp_path,
                required_capability="low",
                mcp_tools=["view_function_code"],
                timeout_seconds=12,
                priority=87,
                global_concurrency=3,
                output_schema=schema,
                permissions=[{"permission": "edit", "pattern": "*", "action": "deny"}],
            ))

        assert result.status == "success"
        assert result.task_id
        assert result.session_id == "ses_structured"
        assert result.message_id == "msg_1"
        assert result.text.startswith("result:")
        assert result.structured == {"answer": 7}
        assert result.model == "provider/actual-model"
        assert "output_schema" not in captured
        assert "output_retry_count" not in captured
        assert captured["mcp_tools"] == ["view_function_code"]
        assert captured["timeout"] == 12
        assert captured["permissions"][0]["action"] == "deny"
        assert captured["return_details"] is True
        assert "plain JSON text" in captured["system_prompt"]
        assert '"answer"' in captured["system_prompt"]
        assert acquire_mock.await_args.kwargs["priority"] == 87
        assert acquire_mock.await_args.kwargs["global_concurrency"] == 3
        assert acquire_mock.await_args.kwargs["strict_capability"] is True
        assert acquire_mock.await_args.kwargs["prefer_lowest_capability"] is True
        assert acquire_mock.await_args.kwargs["wait_when_unavailable"] is True

        try:
            service.submit_task(OpenCodeTaskSpec(
                task_name="bad continuation",
                prompt="continue",
                directory=tmp_path / "other",
                session_id="ses_structured",
            ))
        except ValueError as exc:
            assert "continuation directory cannot change" in str(exc)
        else:
            raise AssertionError("directory-changing continuation was accepted")

    asyncio.run(run())


def test_task_service_does_not_fail_when_plain_text_has_no_json(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()

        async def run_prompt(**kwargs):
            callback_result = kwargs["on_session_id"]("ses_text")
            if hasattr(callback_result, "__await__"):
                await callback_result
            return OpenCodePromptResult(
                session_id="ses_text",
                message_id="msg_text",
                lines=["analysis completed without a JSON object"],
                text="analysis completed without a JSON object",
                model="provider/model-low",
            )

        manager.run_prompt = run_prompt
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path),
            "provider/model-low",
            OutputSource(tool="opencode", model_id="model-low", capability="low"),
        ))

        async def acquire(*_args, **kwargs):
            return _lease(kwargs["task_id"])

        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
            patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
            patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="plain text fallback",
                prompt="return JSON",
                directory=tmp_path,
                output_schema={
                    "type": "object",
                    "properties": {"answer": {"type": "integer"}},
                    "required": ["answer"],
                },
            ))

        assert result.status == "success"
        assert result.text == "analysis completed without a JSON object"
        assert result.structured is None
        result.raise_for_status()

    asyncio.run(run())


def test_new_session_and_immediate_continuation_are_serialized(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        first_can_finish = asyncio.Event()
        first_started = asyncio.Event()
        active = 0
        max_active = 0
        calls: list[tuple[str, str | None]] = []

        async def run_prompt(**kwargs):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            try:
                callback_result = kwargs["on_session_id"]("ses_shared")
                if hasattr(callback_result, "__await__"):
                    await callback_result
                if kwargs["prompt"] == "first":
                    first_started.set()
                    await first_can_finish.wait()
                return OpenCodePromptResult(
                    session_id="ses_shared",
                    message_id=f"msg_{len(calls)}",
                    lines=[kwargs["prompt"]],
                    text=kwargs["prompt"],
                    model="provider/model-low",
                )
            finally:
                active -= 1

        manager.run_prompt = run_prompt
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path),
            "provider/model-low",
            OutputSource(tool="opencode", model_id="model-low", capability="low"),
        ))

        async def acquire(*_args, **kwargs):
            return _lease(kwargs["task_id"])

        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
            patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
            patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
        ):
            first = service.submit_task(OpenCodeTaskSpec(
                task_name="first",
                prompt="first",
                directory=tmp_path,
            ))
            session_id = await asyncio.wait_for(first.wait_session_id(), timeout=1)
            assert session_id == "ses_shared"
            await first_started.wait()
            second = service.submit_task(OpenCodeTaskSpec(
                task_name="second",
                prompt="second",
                directory=tmp_path,
                session_id=session_id,
            ))
            await asyncio.sleep(0.03)
            assert calls == [("first", None)]
            first_can_finish.set()
            assert (await first.result()).status == "success"
            assert (await second.result()).status == "success"

        assert calls == [("first", None), ("second", "ses_shared")]
        assert max_active == 1

    asyncio.run(run())


def test_session_query_result_and_delete_use_saved_runtime(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        runtime = _runtime(tmp_path)
        service._session_directories["ses_existing"] = tmp_path
        service._session_runtimes["ses_existing"] = runtime
        manager = SimpleNamespace(
            get_session=AsyncMock(return_value={"id": "ses_existing"}),
            get_session_messages=AsyncMock(return_value=[{
                "info": {
                    "id": "msg_result",
                    "role": "assistant",
                    "providerID": "provider",
                    "modelID": "model",
                },
                "parts": [{"type": "text", "text": "```json\n{\"ok\": true}\n```"}],
            }]),
            delete_session=AsyncMock(return_value=True),
        )
        with patch("backend.opencode.task_service.get_serve_manager", return_value=manager):
            assert (await service.get_session("ses_existing"))["id"] == "ses_existing"
            result = await service.get_session_result("ses_existing")
            assert result is not None
            assert result.structured == {"ok": True}
            assert result.text.startswith("```json")
            assert result.model == "provider/model"
            assert await service.delete_session("ses_existing") is True
        assert "ses_existing" not in service._session_runtimes
        manager.delete_session.assert_awaited_once()

    asyncio.run(run())


def test_selected_skill_can_be_loaded_from_task_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    skill_dir = project / ".opencode" / "skills" / "validation-poc"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Validation POC\n\nFollow this workflow.", encoding="utf-8")

    system_prompt = _load_skill_system_prompt(
        workspace,
        ["validation-poc"],
        directory=project,
    )

    assert "Task SKILL: validation-poc" in system_prompt
    assert "Follow this workflow" in system_prompt


def test_queued_task_update_keeps_id_and_requeues_new_revision(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        acquire_calls: list[dict] = []
        first_queued = asyncio.Event()

        async def acquire(*_args, **kwargs):
            acquire_calls.append(kwargs)
            if kwargs["revision"] == 1:
                first_queued.set()
                while not kwargs["cancel_event"].is_set():
                    await asyncio.sleep(0.005)
                return None
            return _lease(kwargs["task_id"])

        async def run_prompt(**kwargs):
            assert kwargs["prompt"] == "updated prompt"
            assert kwargs["session_title"] == "after"
            callback_result = kwargs["on_session_id"]("ses_requeued")
            if hasattr(callback_result, "__await__"):
                await callback_result
            return OpenCodePromptResult(
                session_id="ses_requeued",
                message_id="msg_requeued",
                lines=["updated"],
                text="updated",
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path),
            "provider/model-low",
            OutputSource(tool="opencode", model_id="model-low", capability="low"),
        ))
        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
            patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
            patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
        ):
            handle = service.submit_task(OpenCodeTaskSpec(
                task_name="before",
                prompt="old prompt",
                directory=tmp_path,
                priority=10,
            ))
            await first_queued.wait()
            updated = await service.update_queued_task(
                handle.task_id,
                task_name="after",
                prompt="updated prompt",
                priority=90,
            )
            result = await updated.result()

        assert updated.task_id == handle.task_id == result.task_id
        assert updated.revision == result.revision == 2
        assert result.text == "updated"
        assert [call["revision"] for call in acquire_calls] == [1, 2]
        assert acquire_calls[1]["priority"] == 90

    asyncio.run(run())


def test_run_task_cancellation_cancels_queued_service_task(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        queued = asyncio.Event()
        captured_task_id = ""

        async def acquire(*_args, **kwargs):
            nonlocal captured_task_id
            captured_task_id = kwargs["task_id"]
            queued.set()
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.005)
            return None

        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
        ):
            caller = asyncio.create_task(service.run_task(OpenCodeTaskSpec(
                task_name="cancel me",
                prompt="wait",
                directory=tmp_path,
            )))
            await queued.wait()
            caller.cancel()
            try:
                await caller
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("cancelled caller returned normally")

        assert captured_task_id
        assert service.get_task(captured_task_id).status == "cancelled"

    asyncio.run(run())
