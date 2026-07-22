from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import get_args, get_type_hints
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import OutputSource
from task_agent import OpenCodeResult, run_opencode_task
from task_agent.model_pool import (
    NO_AVAILABLE_MODEL_MESSAGE,
    ModelLease,
    ModelOption,
)
from task_agent.serve_client import OpenCodePromptResult
from task_agent.task_service import (
    OpenCodeTaskError,
    OpenCodeTaskResult,
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


@pytest.fixture(autouse=True)
def _configured_host_boundary():
    """Task-service unit tests provide their own config/runtime patches."""
    with patch(
        "task_agent.standalone.ensure_opencode_configuration",
        return_value=None,
    ):
        yield


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


def _task_context(tmp_path: Path, **kwargs):
    return bind_opencode_execution_context(
        project_dir=tmp_path,
        work_dir=tmp_path / "work",
        **kwargs,
    )


def _service_patches(manager, *, max_retries: int = 2, runtime_config=None):
    async def acquire(*_args, **kwargs):
        return _lease(kwargs["task_id"], scope_id=kwargs["stats_scope_id"])

    return (
        patch(
            "task_agent.task_service.get_config",
            return_value=runtime_config or _config(max_retries=max_retries),
        ),
        patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
        patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
        patch("task_agent.task_service.update_model_lease_context", new=AsyncMock()),
        patch("task_agent.task_service.get_serve_manager", return_value=manager),
        patch(
            "task_agent.task_service.get_host_bindings",
            return_value=SimpleNamespace(
                get_workspace=lambda: Path("/tmp/opendeephole-global").resolve(),
                disabled_source_mcp_tools=lambda _directory: (),
            ),
        ),
    )


def test_public_contract_contains_only_component_owned_fields() -> None:
    names = list(inspect.signature(run_opencode_task).parameters)
    assert names == [
        "task_name",
        "task_type",
        "prompt",
        "required_capability",
        "output_schema",
        "invalid_json_retry_count",
        "session_id",
        "config_path",
    ]
    assert [item.name for item in dataclasses.fields(OpenCodeResult)] == [
        "session_id",
        "status",
        "text",
        "structured",
        "model",
    ]
    assert get_type_hints(run_opencode_task)["task_type"] is str
    assert "cancelled" not in get_args(get_type_hints(OpenCodeResult)["status"])


def test_public_interface_uses_bound_directories_and_returns_only_public_result(tmp_path: Path) -> None:
    async def run() -> None:
        internal = OpenCodeTaskResult(
            task_id="task-1",
            session_id="ses-1",
            message_id="msg-1",
            status="success",
            text='{"answer": 7}',
            structured={"answer": 7},
            model="provider/model",
        )
        service = SimpleNamespace(run_task=AsyncMock(return_value=internal))
        with (
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path, task_metadata={"checker": "npd"}),
        ):
            result = await run_opencode_task(
                task_name="public task",
                task_type="audit",
                prompt="return json",
                required_capability="high",
                output_schema=SCHEMA,
                invalid_json_retry_count=4,
                session_id="ses-existing",
            )

        assert result == OpenCodeResult(
            session_id="ses-1",
            status="success",
            text='{"answer": 7}',
            structured={"answer": 7},
            model="provider/model",
        )
        spec = service.run_task.await_args.args[0]
        assert spec.directory == tmp_path.resolve()
        assert spec.required_capability == "high"
        assert spec.output_retry_count == 4
        assert spec.session_id == "ses-existing"

        service.run_task.reset_mock()
        with (
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path),
        ):
            plain = await run_opencode_task(
                task_name="plain text",
                task_type="audit",
                prompt="return text",
                required_capability="low",
            )
        assert plain.structured is None

    asyncio.run(run())


def test_public_interface_requires_context_and_propagates_cancellation(tmp_path: Path) -> None:
    async def run() -> None:
        with pytest.raises(RuntimeError, match="project_dir is not bound"):
            await run_opencode_task(
                task_name="missing context",
                task_type="audit",
                prompt="test",
                required_capability="low",
            )

        cancelled = OpenCodeTaskResult(
            task_id="task-cancelled",
            session_id="ses-cancelled",
            message_id="",
            status="cancelled",
            error="stopped",
        )
        service = SimpleNamespace(run_task=AsyncMock(return_value=cancelled))
        with (
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path),
            pytest.raises(asyncio.CancelledError),
        ):
            await run_opencode_task(
                task_name="cancelled",
                task_type="audit",
                prompt="test",
                required_capability="low",
            )

    asyncio.run(run())


def test_external_cancellation_stops_same_session_json_correction_and_retries(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        correction_started = asyncio.Event()
        external_cancel = threading.Event()
        calls = 0

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            callback = kwargs["on_session_id"]("ses-correction")
            if hasattr(callback, "__await__"):
                await callback
            if calls == 1:
                return OpenCodePromptResult(
                    session_id="ses-correction",
                    message_id="msg-invalid",
                    lines=["not json"],
                    text="not json",
                    model="provider/model-low",
                )
            correction_started.set()
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.005)
            raise asyncio.CancelledError

        manager.run_prompt = run_prompt
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            _task_context(tmp_path, cancel_event=external_cancel),
        ):
            caller = asyncio.create_task(run_opencode_task(
                task_name="cancel corrections",
                task_type="audit",
                prompt="return json",
                required_capability="low",
                output_schema=SCHEMA,
                invalid_json_retry_count=2,
            ))
            await correction_started.wait()
            external_cancel.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(caller, timeout=1)

        assert calls == 2
        assert next(iter(service._records.values())).status == "cancelled"

    asyncio.run(run())


def test_public_interface_rejects_legacy_capabilities_and_unknown_task_types() -> None:
    async def run() -> None:
        with pytest.raises(ValueError, match="low.*high"):
            await run_opencode_task(
                task_name="legacy capability",
                task_type="audit",
                prompt="test",
                required_capability="medium",  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError, match="task_type"):
            await run_opencode_task(
                task_name="unknown type",
                task_type="unknown",
                prompt="test",
                required_capability="low",
            )

    asyncio.run(run())


def test_task_service_parses_json_and_computes_scope_and_permissions(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        captured: dict = {}
        output: list[str] = []

        async def run_prompt(**kwargs):
            captured.update(kwargs)
            kwargs["on_line"]("[opencode serve llm text] streamed answer")
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
        with (
            patches[0],
            patches[1] as acquire_mock,
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patch(
                "task_agent.task_service._disabled_source_mcp_tools",
                return_value=("deephole-code",),
            ),
        ):
            scan_dir = tmp_path / ".opendeephole" / "scans" / "scan-7"
            with bind_opencode_execution_context(
                scan_id="scan-7",
                project_dir=tmp_path,
                work_dir=scan_dir,
                task_metadata={
                    "task_type": "audit",
                    "checker": "oob",
                    "validation_debug": True,
                },
                feedback_entries=({
                    "vuln_type": "oob",
                    "reason": "边界检查缺失",
                    "function_source": "void parse(void) {}",
                },),
                on_output=output.append,
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
        assert captured["show_serve_status"] is True
        schema_text = json.dumps(SCHEMA, ensure_ascii=False, indent=2)
        assert captured["prompt"].startswith("return an answer\n\n")
        assert "请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回" in captured["prompt"]
        assert captured["prompt"].endswith(schema_text)
        assert captured["prompt"].count(schema_text) == 1
        assert "JSON Schema" not in captured["system_prompt"]
        assert "## CodeGraph 项目范围" in captured["system_prompt"]
        assert f"projectPath={tmp_path.resolve()}" in captured["system_prompt"]
        assert "## 已选择的扫描反馈" in captured["system_prompt"]
        assert "仍需核验当前代码" in captured["system_prompt"]
        assert "用户理由：边界检查缺失" in captured["system_prompt"]
        assert "CodeGraph project scope" not in captured["system_prompt"]
        assert "Selected scan feedback" not in captured["system_prompt"]
        permission_tuples = {
            (rule["permission"], rule["pattern"], rule["action"])
            for rule in captured["permissions"]
        }
        assert ("bash", "*", "deny") in permission_tuples
        assert ("skill", "*", "allow") in permission_tuples
        assert ("edit", "*", "deny") in permission_tuples
        assert ("edit", str(scan_dir.resolve()), "allow") in permission_tuples
        assert ("edit", str(tmp_path.resolve()), "allow") not in permission_tuples
        assert ("external_directory", str(tmp_path.resolve()), "allow") in permission_tuples
        assert ("external_directory", str(scan_dir.resolve()), "allow") in permission_tuples
        acquire_kwargs = acquire_mock.await_args.kwargs
        assert acquire_kwargs["stats_scope_id"] == "scan-7"
        assert acquire_kwargs["task_context"]["task_type"] == "audit"
        assert acquire_kwargs["task_context"]["prompt"] == captured["prompt"]
        assert acquire_kwargs["task_context"]["prompt_length"] == len(captured["prompt"])
        assert acquire_kwargs["task_context"]["session_attempt"] == 1
        assert callable(acquire_kwargs["global_concurrency"])
        assert acquire_kwargs["wait_when_unavailable"] is False
        assert any("[opencode task] queued" in line for line in output)
        assert any("[opencode task] running" in line for line in output)
        assert any("streamed answer" in line for line in output)
        assert any(
            "[opencode task] finished" in line and "status=success" in line
            for line in output
        )

    asyncio.run(run())


def test_validation_debug_empty_model_pool_fails_without_starting_serve(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace(run_prompt=AsyncMock())
        output: list[str] = []

        with (
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.get_serve_manager", return_value=manager),
            bind_opencode_execution_context(
                scan_id="debug-scan",
                project_dir=tmp_path,
                work_dir=tmp_path / "work",
                task_metadata={"validation_debug": True},
                on_output=output.append,
            ),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="debug without model",
                prompt="test",
                directory=tmp_path,
            ))

        assert result.status == "failure"
        assert result.error == NO_AVAILABLE_MODEL_MESSAGE
        manager.run_prompt.assert_not_awaited()
        assert any("[opencode task] queued" in line for line in output)
        assert any(
            "[opencode task] finished" in line
            and "status=failure" in line
            and NO_AVAILABLE_MODEL_MESSAGE in line
            for line in output
        )

    asyncio.run(run())


def test_phase_policy_controls_timeout_and_retries_but_not_explicit_capability(tmp_path: Path) -> None:
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
                project_dir=tmp_path,
                work_dir=tmp_path / "work",
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
            call.kwargs["required_capability"] == "low"
            for call in acquire_mock.await_args_list
        )
        assert all(
            call.kwargs["wait_when_unavailable"] is True
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
            with _task_context(tmp_path):
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
        schema_text = json.dumps(SCHEMA, ensure_ascii=False, indent=2)
        assert calls[0][0].startswith("initial prompt\n\n")
        assert "请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回" in calls[0][0]
        assert calls[0][0].endswith(schema_text)
        assert all(
            "你上一次的回复不是符合目标 JSON Schema 的合法 JSON" in prompt
            for prompt, _ in calls[1:]
        )
        assert all(prompt.endswith(schema_text) for prompt, _ in calls[1:])
        assert all(prompt.count(schema_text) == 1 for prompt, _ in calls)
        assert all("Your previous response" not in prompt for prompt, _ in calls)

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
            with _task_context(tmp_path, on_invocation_metadata=sources.append):
                handle = service.submit_task(OpenCodeTaskSpec(
                    task_name="fresh session retry",
                    prompt="initial",
                    directory=tmp_path,
                    output_schema=SCHEMA,
                    output_retry_count=1,
                    attempt=1,
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
        calls: list[tuple[str, str | None]] = []

        async def run_prompt(**kwargs):
            calls.append((kwargs["prompt"], kwargs["session_id"]))
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
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="retry execution",
                    prompt="run",
                    directory=tmp_path,
                    attempt=1,
                ))

        assert result.status == "success"
        assert result.session_id == "ses_success"
        assert result.text == "done"
        assert calls == [("run", None), ("run", None)]
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
            with _task_context(tmp_path):
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
            with _task_context(tmp_path):
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
            with _task_context(tmp_path):
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
            with _task_context(tmp_path):
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
        with patch("task_agent.task_service.get_serve_manager", return_value=manager):
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
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
            patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
            patch("task_agent.task_service.update_model_lease_context", new=AsyncMock()),
            patch("task_agent.task_service.get_serve_manager", return_value=manager),
            patch("task_agent.task_service.get_global_opencode_workspace", return_value=tmp_path),
            patch("task_agent.task_service._disabled_source_mcp_tools", return_value=()),
        ):
            with _task_context(tmp_path):
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
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
            patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
        ):
            with _task_context(tmp_path):
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
