from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import OutputSource
from backend.opencode.model_pool import ModelLease, ModelOption
from backend.opencode.serve_client import OpenCodePromptResult
from backend.opencode.task_service import (
    OpenCodeTaskError,
    OpenCodeTaskService,
    OpenCodeTaskSpec,
    _SessionRuntime,
    bind_opencode_execution_context,
)


SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "integer"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def _lease(task_id: str = "task-id", *, scope_id: str = "") -> ModelLease:
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
        stats_scope_id=scope_id,
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


def _config(*, max_retries: int = 2) -> SimpleNamespace:
    return SimpleNamespace(
        opencode=SimpleNamespace(timeout=30, max_retries=max_retries, models=[]),
        fp_review_cli=None,
        opencode_concurrency=1,
    )


def _source() -> OutputSource:
    return OutputSource(
        backend="opencode",
        tool="opencode",
        model_id="model-low",
        model="provider/model-low",
        capability="low",
    )


def _service_patches(manager, *, max_retries: int = 2, runtime_config=None):
    async def acquire(*_args, **kwargs):
        return _lease(kwargs["task_id"], scope_id=kwargs["stats_scope_id"])

    return (
        patch(
            "backend.opencode.task_service.get_config",
            return_value=runtime_config or _config(max_retries=max_retries),
        ),
        patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
        patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
        patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
        patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
        patch(
            "backend.opencode.config.get_global_opencode_workspace",
            side_effect=lambda **_kwargs: Path("/tmp/opendeephole-global").resolve(),
        ),
    )


def test_task_spec_public_contract_is_small_and_agent_owned_fields_are_absent() -> None:
    names = [item.name for item in dataclasses.fields(OpenCodeTaskSpec)]
    assert names == [
        "task_name",
        "prompt",
        "directory",
        "required_capability",
        "timeout_seconds",
        "priority",
        "output_schema",
        "output_retry_count",
        "session_id",
        "writable_paths",
        "attempt",
        "on_output",
        "on_invocation_metadata",
        "cancel_event",
    ]
    for removed in (
        "workspace",
        "scope_id",
        "task_context",
        "mcp_tools",
        "skills",
        "permissions",
        "cli_config",
        "global_concurrency",
    ):
        assert removed not in names


def test_task_service_parses_json_and_computes_scope_and_permissions(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        captured: dict = {}

        async def run_prompt(**kwargs):
            captured.update(kwargs)
            callback = kwargs["on_session_id"]("ses_structured")
            if hasattr(callback, "__await__"):
                await callback
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
            _source(),
        ))
        patches = _service_patches(manager)
        with patches[0], patches[1] as acquire_mock, patches[2], patches[3], patches[4], patches[5]:
            scan_dir = tmp_path / ".opendeephole" / "scans" / "scan-7"
            with bind_opencode_execution_context(
                scan_id="scan-7",
                scan_work_dir=scan_dir,
                task_metadata={"task_type": "audit", "checker": "oob"},
            ):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="schema task",
                    prompt="return an answer",
                    directory=tmp_path,
                    timeout_seconds=12,
                    priority=87,
                    output_schema=SCHEMA,
                ))

        assert result.status == "success"
        assert result.structured == {"answer": 7}
        assert result.model == "provider/actual-model"
        assert result.output_source.attempt == 1
        assert captured["mcp_tools"] is None
        assert captured["timeout"] == 12
        assert captured["return_details"] is True
        assert "plain JSON text" in captured["system_prompt"]
        assert '"answer"' in captured["system_prompt"]
        permission_tuples = {
            (rule["permission"], rule["pattern"], rule["action"])
            for rule in captured["permissions"]
        }
        assert ("bash", "*", "allow") in permission_tuples
        assert ("skill", "*", "allow") in permission_tuples
        assert ("edit", "*", "deny") in permission_tuples
        assert ("edit", str(scan_dir.resolve()), "allow") in permission_tuples
        acquire_kwargs = acquire_mock.await_args.kwargs
        assert acquire_kwargs["stats_scope_id"] == "scan-7"
        assert acquire_kwargs["task_context"]["task_type"] == "audit"
        assert acquire_kwargs["task_context"]["session_attempt"] == 1
        assert callable(acquire_kwargs["global_concurrency"])

    asyncio.run(run())


def test_phase_policy_overrides_task_and_model_capability_timeout_and_retries(tmp_path: Path) -> None:
    async def run() -> None:
        calls: list[dict] = []

        async def run_prompt(**kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise RuntimeError("transient")
            callback = kwargs["on_session_id"]("ses-policy")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-policy",
                message_id="msg-policy",
                lines=["ok"],
                text="ok",
                model="provider/model-low",
            )

        runtime_config = _config(max_retries=9)
        runtime_config.vulnerability_mining = SimpleNamespace(
            required_capability="high",
            timeout_seconds=77,
            max_retries=1,
        )
        manager = SimpleNamespace(run_prompt=run_prompt)
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager, runtime_config=runtime_config)
        with patches[0], patches[1] as acquire_mock, patches[2], patches[3], patches[4], patches[5]:
            with bind_opencode_execution_context(
                task_metadata={"task_type": "threat_audit"},
            ):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="policy",
                    prompt="test",
                    directory=tmp_path,
                    required_capability="low",
                    timeout_seconds=12,
                    attempt=7,
                    output_retry_count=0,
                ))

        assert result.status == "success"
        assert len(calls) == 2
        assert [call["timeout"] for call in calls] == [77, 77]
        assert acquire_mock.await_count == 2
        assert all(
            call.kwargs["required_capability"] == "high"
            for call in acquire_mock.await_args_list
        )

    asyncio.run(run())


def test_invalid_json_is_corrected_in_the_same_session(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []
        responses = ["not json", '{"answer":"wrong type"}', '{"answer":9}']

        async def run_prompt(**kwargs):
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            callback = kwargs["on_session_id"]("ses_same")
            if hasattr(callback, "__await__"):
                await callback
            text = responses[len(calls) - 1]
            return OpenCodePromptResult(
                session_id="ses_same",
                message_id=f"msg_{len(calls)}",
                lines=[text],
                text=text,
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3], patches[4], patches[5]:
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="correct json",
                prompt="initial prompt",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=2,
                attempt=0,
            ))

        assert result.status == "success"
        assert result.structured == {"answer": 9}
        assert result.session_id == "ses_same"
        assert acquire_mock.await_count == 1
        assert release_mock.await_count == 1
        assert [session for _prompt, session in calls] == [None, "ses_same", "ses_same"]
        assert calls[0][0] == "initial prompt"
        assert all("previous response was not valid JSON" in prompt for prompt, _ in calls[1:])

    asyncio.run(run())


def test_json_correction_exhaustion_requeues_with_new_session_and_same_task_id(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []
        created_sessions = ["ses_first", "ses_first", "ses_final"]
        texts = ["bad", "still bad", '{"answer":11}']
        sources: list[OutputSource] = []

        async def run_prompt(**kwargs):
            index = len(calls)
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            callback = kwargs["on_session_id"](created_sessions[index])
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id=created_sessions[index],
                message_id=f"msg_{index + 1}",
                lines=[texts[index]],
                text=texts[index],
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)

        async def runtime_for_task(_record, _lease, *, session_attempt):
            source = _source()
            source.attempt = session_attempt
            return _runtime(tmp_path), "provider/model-low", source

        service._runtime_for_task = AsyncMock(side_effect=runtime_for_task)
        patches = _service_patches(manager)
        with patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3], patches[4], patches[5]:
            handle = service.submit_task(OpenCodeTaskSpec(
                task_name="fresh session retry",
                prompt="initial",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=1,
                attempt=1,
                on_invocation_metadata=sources.append,
            ))
            result = await handle.result()
            first_session_id = await handle.wait_session_id()

        assert result.status == "success"
        assert result.task_id == handle.task_id
        assert first_session_id == "ses_first"
        assert result.session_id == "ses_final"
        assert result.structured == {"answer": 11}
        assert [source.attempt for source in sources] == [1, 2]
        assert acquire_mock.await_count == 2
        assert [call[1] for call in calls] == [None, "ses_first", None]
        first_release = release_mock.await_args_list[0].kwargs
        final_release = release_mock.await_args_list[1].kwargs
        assert first_release["record_completion"] is False
        assert first_release["outcome"] is None
        assert final_release["record_completion"] is True
        assert final_release["outcome"] == "success"

    asyncio.run(run())


def test_execution_error_requeues_with_a_fresh_session(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[str | None] = []

        async def run_prompt(**kwargs):
            calls.append(kwargs["session_id"])
            session_id = "ses_failed" if len(calls) == 1 else "ses_success"
            callback = kwargs["on_session_id"](session_id)
            if hasattr(callback, "__await__"):
                await callback
            if len(calls) == 1:
                raise RuntimeError("transport failed")
            return OpenCodePromptResult(
                session_id=session_id,
                message_id="msg_success",
                lines=["done"],
                text="done",
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1] as acquire_mock,
            patches[2] as release_mock,
            patches[3],
            patches[4],
            patches[5],
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="retry execution",
                prompt="run",
                directory=tmp_path,
                attempt=1,
            ))

        assert result.status == "success"
        assert result.session_id == "ses_success"
        assert result.text == "done"
        assert calls == [None, None]
        assert acquire_mock.await_count == 2
        assert {
            call.kwargs["task_id"] for call in acquire_mock.await_args_list
        } == {result.task_id}
        assert release_mock.await_args_list[0].kwargs["record_completion"] is False
        assert release_mock.await_args_list[1].kwargs["outcome"] == "success"

    asyncio.run(run())


def test_failed_fresh_retry_keeps_last_created_session_in_pool_context(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls = 0

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                callback = kwargs["on_session_id"]("ses_first")
                if hasattr(callback, "__await__"):
                    await callback
                raise RuntimeError("first session failed")
            raise RuntimeError("final retry failed before session creation")

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1],
            patches[2] as release_mock,
            patches[3] as update_context_mock,
            patches[4],
            patches[5],
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="failed retry session history",
                prompt="run",
                directory=tmp_path,
                attempt=1,
            ))

        assert result.status == "failure"
        assert result.session_id == "ses_first"
        assert release_mock.await_args_list[-1].kwargs["outcome"] == "failure"
        assert release_mock.await_args_list[-1].kwargs["record_completion"] is True
        final_context_update = update_context_mock.await_args_list[-1].args[1]
        assert final_context_update["serve_session_id"] == "ses_first"
        assert final_context_update["session_attempt"] == 2

    asyncio.run(run())


def test_exhausted_json_retries_fail_and_keep_last_text(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        count = 0

        async def run_prompt(**kwargs):
            nonlocal count
            count += 1
            session_id = f"ses_{count}"
            callback = kwargs["on_session_id"](session_id)
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id=session_id,
                message_id=f"msg_{count}",
                lines=[f"invalid-{count}"],
                text=f"invalid-{count}",
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="bad forever",
                prompt="json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=0,
                attempt=1,
            ))

        assert result.status == "failure"
        assert result.session_id == "ses_2"
        assert result.text == "invalid-2"
        assert result.structured is None
        assert "same-session JSON corrections" in result.error
        with pytest.raises(OpenCodeTaskError):
            result.raise_for_status()

    asyncio.run(run())


def test_timeout_is_terminal_and_does_not_use_fresh_session_retry(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace(run_prompt=AsyncMock(side_effect=asyncio.TimeoutError("slow")))
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3], patches[4], patches[5]:
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="timeout",
                prompt="slow",
                directory=tmp_path,
                attempt=5,
            ))

        assert result.status == "timeout"
        assert acquire_mock.await_count == 1
        assert release_mock.await_count == 1
        assert release_mock.await_args.kwargs["outcome"] == "timeout"

    asyncio.run(run())


def test_new_session_and_immediate_continuation_are_serialized(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
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
                callback = kwargs["on_session_id"]("ses_shared")
                if hasattr(callback, "__await__"):
                    await callback
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

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            first = service.submit_task(OpenCodeTaskSpec(
                task_name="first", prompt="first", directory=tmp_path, attempt=0,
            ))
            session_id = await asyncio.wait_for(first.wait_session_id(), timeout=1)
            await first_started.wait()
            second = service.submit_task(OpenCodeTaskSpec(
                task_name="second",
                prompt="second",
                directory=tmp_path,
                session_id=session_id,
                attempt=0,
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
            assert result.model == "provider/model"
            assert await service.delete_session("ses_existing") is True
        assert "ses_existing" not in service._session_runtimes

    asyncio.run(run())


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
            callback = kwargs["on_session_id"]("ses_requeued")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses_requeued",
                message_id="msg_requeued",
                lines=["updated"],
                text="updated",
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        with (
            patch("backend.opencode.task_service.get_config", return_value=_config()),
            patch("backend.opencode.task_service.acquire_model_lease", side_effect=acquire),
            patch("backend.opencode.task_service.release_model_lease", new=AsyncMock()),
            patch("backend.opencode.task_service.update_model_lease_context", new=AsyncMock()),
            patch("backend.opencode.task_service.get_serve_manager", return_value=manager),
            patch("backend.opencode.config.get_global_opencode_workspace", return_value=tmp_path),
        ):
            handle = service.submit_task(OpenCodeTaskSpec(
                task_name="before", prompt="old prompt", directory=tmp_path, priority=10,
            ))
            await first_queued.wait()
            updated = await service.update_queued_task(
                handle.task_id,
                task_name="after",
                prompt="updated prompt",
                priority=90,
                attempt=0,
            )
            result = await updated.result()

        assert updated.task_id == handle.task_id == result.task_id
        assert updated.revision == result.revision == 2
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
                task_name="cancel me", prompt="wait", directory=tmp_path,
            )))
            await queued.wait()
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller

        assert captured_task_id
        assert service.get_task(captured_task_id).status == "cancelled"

    asyncio.run(run())
