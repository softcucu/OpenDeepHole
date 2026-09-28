from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import threading
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import get_args, get_type_hints
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import OutputSource
from task_agent import OpenCodeResult, run_opencode_task, run_sync_component
from task_agent.api import (
    _normalize_allowed_bash_commands,
    _normalize_file_write_allowlist,
    _normalize_readable_paths,
    _normalize_required_bash_commands,
    _normalize_required_bash_success_markers,
    _normalize_writable_paths,
)
from task_agent.model_pool import (
    NO_AVAILABLE_MODEL_MESSAGE,
    ModelLease,
    ModelOption,
)
from task_agent.serve_client import (
    OpenCodeCommandFailure,
    OpenCodeFileWrite,
    OpenCodePromptResult,
    OpenCodeProviderQuotaError,
    OpenCodeServeStartupError,
    OpenCodeTaskQualityError,
)
from task_agent.task_service import (
    OpenCodeExecutionContext,
    OpenCodeTaskError,
    OpenCodeTaskResult,
    OpenCodeTaskService,
    OpenCodeTaskSpec,
    _SessionRuntime,
    _permission_path_patterns,
    _runtime_with_permissions,
    _runtime_with_skill_paths,
    _task_model_policy,
    _writable_path_permissions,
    bind_opencode_execution_context,
)


SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "integer"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def test_permission_path_patterns_include_native_windows_descendants() -> None:
    work_dir = PureWindowsPath(
        r"C:\Users\26388\.opendeephole\scans\scan-1\threat_analysis"
    )

    patterns = _permission_path_patterns(work_dir)

    assert str(work_dir) in patterns
    assert f"{work_dir}\\**" in patterns
    assert (
        "C:/Users/26388/.opendeephole/scans/scan-1/threat_analysis/**"
        in patterns
    )
    assert f"{work_dir}/**" not in patterns


def test_permission_path_patterns_include_home_aliases() -> None:
    scans_root = Path.home() / ".opendeephole" / "scans"

    patterns = _permission_path_patterns(scans_root)

    assert "~/.opendeephole/scans" in patterns
    assert "~/.opendeephole/scans/**" in patterns
    assert r"~\.opendeephole\scans" in patterns
    assert r"~\.opendeephole\scans\**" in patterns


def test_writable_path_permissions_allow_read_external_access_and_edits(
    tmp_path: Path,
) -> None:
    writable_root = tmp_path / "generated"

    permissions = _writable_path_permissions((writable_root,))

    assert permissions is not None
    expected_patterns = _permission_path_patterns(writable_root)
    for permission in ("read", "external_directory"):
        assert [
            rule["pattern"]
            for rule in permissions
            if rule["permission"] == permission
        ] == expected_patterns
    edit_rules = [
        rule for rule in permissions if rule["permission"] == "edit"
    ]
    assert edit_rules[0] == {
        "permission": "edit",
        "pattern": "*",
        "action": "deny",
    }
    assert [rule["pattern"] for rule in edit_rules[1:]] == expected_patterns
    assert all(rule["action"] == "allow" for rule in permissions if rule is not edit_rules[0])
    assert all(rule["permission"] != "bash" for rule in permissions)
    assert _writable_path_permissions(None) is None
    assert _writable_path_permissions(()) == [{
        "permission": "edit",
        "pattern": "*",
        "action": "deny",
    }]


def test_task_permissions_add_read_only_roots_and_exact_shell_command(
    tmp_path: Path,
) -> None:
    writable_root = tmp_path / "generated"
    readable_root = tmp_path / "references"
    optional_command = "python optional.py"
    command = "python validate.py --input generated/result.json"

    permissions = _writable_path_permissions(
        (writable_root,),
        readable_paths=(readable_root,),
        allowed_bash_commands=(optional_command,),
        required_bash_commands=(command,),
    )

    assert permissions is not None
    for pattern in _permission_path_patterns(readable_root):
        assert {
            "permission": "read",
            "pattern": pattern,
            "action": "allow",
        } in permissions
        assert {
            "permission": "external_directory",
            "pattern": pattern,
            "action": "allow",
        } in permissions
        assert not any(
            rule["permission"] == "edit" and rule["pattern"] == pattern
            for rule in permissions
        )
    bash_rules = [
        rule for rule in permissions if rule["permission"] == "bash"
    ]
    assert bash_rules == [
        {"permission": "bash", "pattern": "*", "action": "deny"},
        {"permission": "bash", "pattern": optional_command, "action": "allow"},
        {"permission": "bash", "pattern": command, "action": "allow"},
    ]


def test_dynamic_writable_paths_stay_out_of_serve_config(
    tmp_path: Path,
) -> None:
    dynamic_root = tmp_path / "external-output"
    context = OpenCodeExecutionContext(
        project_dir=tmp_path / "project",
        work_dir=tmp_path / "work",
    )
    bindings = SimpleNamespace(writable_roots=lambda: ())

    with patch(
        "task_agent.task_service.get_host_bindings",
        return_value=bindings,
    ):
        runtime = _runtime_with_permissions(_runtime(tmp_path), context)

    permission = json.loads(runtime.config_content)["permission"]
    for pattern in _permission_path_patterns(dynamic_root):
        assert pattern not in permission["edit"]
    assert _writable_path_permissions((dynamic_root,)) is not None


def test_host_writable_root_is_written_to_windows_runtime_config(
    tmp_path: Path,
) -> None:
    scans_root = PureWindowsPath(r"C:\Users\demo\.opendeephole\scans")
    context = OpenCodeExecutionContext(
        project_dir=tmp_path,
        work_dir=tmp_path / "work",
    )
    bindings = SimpleNamespace(
        get_workspace=lambda: tmp_path / "workspace",
        writable_roots=lambda: (scans_root,),
    )

    with patch(
        "task_agent.task_service.get_host_bindings",
        return_value=bindings,
    ):
        runtime = _runtime_with_permissions(
            _runtime(tmp_path),
            context,
        )

    permission = json.loads(runtime.config_content)["permission"]
    for pattern in _permission_path_patterns(scans_root):
        assert permission["read"][pattern] == "allow"
        assert permission["external_directory"][pattern] == "allow"
        assert permission["edit"][pattern] == "allow"


def test_host_readable_root_is_read_only_in_windows_runtime_config(
    tmp_path: Path,
) -> None:
    reference_root = PureWindowsPath(
        r"C:\Users\demo\OpenDeepHole\deephole_client\threat_analysis\methods"
        r"\codex_goal_threat_analysis"
    )
    context = OpenCodeExecutionContext(
        project_dir=tmp_path,
        work_dir=tmp_path / "work",
    )
    bindings = SimpleNamespace(
        readable_roots=lambda: (reference_root,),
        writable_roots=lambda: (),
    )

    with patch(
        "task_agent.task_service.get_host_bindings",
        return_value=bindings,
    ):
        runtime = _runtime_with_permissions(
            _runtime(tmp_path),
            context,
        )

    permission = json.loads(runtime.config_content)["permission"]
    for pattern in _permission_path_patterns(reference_root):
        assert permission["read"][pattern] == "allow"
        assert permission["external_directory"][pattern] == "allow"
        assert pattern not in permission["edit"]


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
        health_identity=(
            "provider/model-low",
            False,
            "opencode",
            "opencode",
        ),
        health_generation="generation",
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


async def _notify_model_request_failure(kwargs: dict, kind: str) -> None:
    callback = kwargs.get("on_model_request_failure")
    if callback is None:
        return
    result = callback(kind)
    if hasattr(result, "__await__"):
        await result


def _task_context(tmp_path: Path, **kwargs):
    return bind_opencode_execution_context(
        project_dir=tmp_path,
        work_dir=tmp_path / "work",
        **kwargs,
    )


def test_component_skill_paths_are_merged_into_runtime_config(
    tmp_path: Path,
) -> None:
    runtime = dataclasses.replace(
        _runtime(tmp_path),
        config_content='{"skills":{"paths":["/existing"]}}',
    )

    merged = _runtime_with_skill_paths(
        runtime,
        (tmp_path / "skills-a", tmp_path / "skills-a", tmp_path / "skills-b"),
    )

    config = json.loads(merged.config_content)
    assert config["skills"]["paths"] == [
        "/existing",
        str(tmp_path / "skills-a"),
        str(tmp_path / "skills-b"),
    ]
    assert runtime.config_content == '{"skills":{"paths":["/existing"]}}'


def test_runtime_permissions_are_written_to_global_config(
    tmp_path: Path,
) -> None:
    scans_root = tmp_path / ".opendeephole" / "scans"
    work_dir = scans_root / "scan-7"
    skill_root = tmp_path / "configured-skills"
    workspace = tmp_path / "workspace"
    context = OpenCodeExecutionContext(
        project_dir=tmp_path / "project",
        work_dir=work_dir,
    )
    runtime = dataclasses.replace(
        _runtime(tmp_path),
        config_workspace=workspace,
        config_content=json.dumps({
            "skills": {"paths": [str(skill_root)]},
            "permission": {
                "task": {"*": "allow"},
                "bash": {"*": "allow"},
                "edit": {"*": "allow"},
            },
        }),
    )
    bindings = SimpleNamespace(
        writable_roots=lambda: (scans_root,),
    )

    with patch(
        "task_agent.task_service.get_host_bindings",
        return_value=bindings,
    ):
        merged = _runtime_with_permissions(runtime, context)

    permission = json.loads(merged.config_content)["permission"]
    assert permission["task"] == {"*": "allow"}
    assert permission["bash"] == {"*": "deny"}
    assert permission["skill"] == {"*": "allow"}
    assert permission["read"]["*"] == "allow"
    assert permission["external_directory"]["*"] == "allow"
    assert permission["edit"]["*"] == "deny"
    assert str(work_dir.resolve()) not in permission["edit"]
    for root in (workspace / ".opencode", skill_root):
        for pattern in _permission_path_patterns(root):
            assert permission["read"][pattern] == "allow"
            assert permission["external_directory"][pattern] == "allow"
            assert pattern not in permission["edit"]
    for pattern in _permission_path_patterns(scans_root):
        assert permission["read"][pattern] == "allow"
        assert permission["external_directory"][pattern] == "allow"
        assert permission["edit"][pattern] == "allow"


def _service_patches(
    manager,
    *,
    max_retries: int = 2,
    runtime_config=None,
    writable_roots=(),
):
    async def acquire(*_args, **kwargs):
        return _lease(kwargs["task_id"], scope_id=kwargs["stats_scope_id"])

    update_context = AsyncMock()

    async def release(lease, *, context_updates=None, **_kwargs):
        # The real pool merges final metadata in the same operation as release.
        if context_updates:
            await update_context(lease, context_updates)

    return (
        patch(
            "task_agent.task_service.get_config",
            return_value=runtime_config or _config(max_retries=max_retries),
        ),
        patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
        patch("task_agent.task_service.release_model_lease", new=AsyncMock(side_effect=release)),
        patch("task_agent.task_service.update_model_lease_context", new=update_context),
        patch("task_agent.task_service.get_serve_manager", return_value=manager),
        patch(
            "task_agent.task_service.get_host_bindings",
            return_value=SimpleNamespace(
                get_workspace=lambda: Path("/tmp/opendeephole-global").resolve(),
                disabled_source_mcp_tools=lambda _directory: (),
                writable_roots=lambda: tuple(writable_roots),
            ),
        ),
    )


async def _run_service_task(
    tmp_path: Path,
    run_prompt,
    spec: OpenCodeTaskSpec,
    *,
    work_dir: Path | None = None,
) -> OpenCodeTaskResult:
    manager = SimpleNamespace(run_prompt=run_prompt)
    service = OpenCodeTaskService()
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
        bind_opencode_execution_context(
            project_dir=tmp_path,
            work_dir=work_dir or tmp_path / "work",
        ),
    ):
        return await service.run_task(spec)


def test_public_contract_contains_only_component_owned_fields() -> None:
    names = list(inspect.signature(run_opencode_task).parameters)
    assert names == [
        "task_name",
        "task_type",
        "prompt",
        "required_capability",
        "output_schema",
        "invalid_json_retry_count",
        "invalid_json_retry_prompt",
        "file_write_allowlist",
        "writable_paths",
        "readable_paths",
        "allowed_bash_commands",
        "required_bash_commands",
        "bash_command_match_mode",
        "required_bash_retry_count",
        "required_bash_success_markers",
        "post_session_validator",
        "post_session_validation_retry_count",
        "lease_state_callback",
        "session_id",
        "config_path",
        "output",
        "cancel_event",
    ]
    assert [item.name for item in dataclasses.fields(OpenCodeResult)] == [
        "session_id",
        "status",
        "text",
        "structured",
        "model",
        "output_source",
        "token_usage",
    ]
    assert get_type_hints(run_opencode_task)["task_type"] is str
    assert "cancelled" not in get_args(get_type_hints(OpenCodeResult)["status"])


@pytest.mark.parametrize("match_mode", ["exact", "bound_python_script"])
def test_public_interface_uses_bound_directories_and_returns_only_public_result(
    tmp_path: Path, match_mode: str,
) -> None:
    async def run() -> None:
        optional_command = f'python "{tmp_path / "optional.py"}"'
        required_command = f'python "{tmp_path / "validate.py"}"'
        internal = OpenCodeTaskResult(
            task_id="task-1",
            session_id="ses-1",
            message_id="msg-1",
            status="success",
            text='{"answer": 7}',
            structured={"answer": 7},
            model="provider/model",
            token_usage={
                "input_tokens": 5, "output_tokens": 2, "reasoning_tokens": 1,
                "cache_read_tokens": 3, "cache_write_tokens": 0,
                "total_tokens": 11, "complete": True,
                "by_model": [],
            },
        )
        service = SimpleNamespace(run_task=AsyncMock(return_value=internal))
        post_session_validator = lambda: None
        external_dir = tmp_path.parent / f"{tmp_path.name}-external"
        with (
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path, task_metadata={"checker": "npd"}),
        ):
            result = await run_opencode_task(
                task_name="public task",
                task_type="vulnerability_mining",
                prompt="return json",
                required_capability="high",
                output_schema=SCHEMA,
                invalid_json_retry_count=4,
                invalid_json_retry_prompt="  custom retry prompt  ",
                file_write_allowlist=[
                    "keep.json",
                    tmp_path / "work" / "reports",
                ],
                writable_paths=[
                    "generated",
                    external_dir,
                    "generated",
                ],
                readable_paths=["references", external_dir / "schemas"],
                allowed_bash_commands=optional_command,
                required_bash_commands=required_command,
                bash_command_match_mode=match_mode,
                required_bash_retry_count=1,
                required_bash_success_markers={
                    required_command: "VALID: artifacts passed",
                },
                post_session_validator=post_session_validator,
                post_session_validation_retry_count=1,
                session_id="ses-existing",
            )

        expected_output_source = internal.output_source.model_dump()
        expected_output_source["serve_session_id"] = "ses-1"
        assert result == OpenCodeResult(
            session_id="ses-1",
            status="success",
            text='{"answer": 7}',
            structured={"answer": 7},
            model="provider/model",
            output_source=expected_output_source,
            token_usage=internal.token_usage,
        )
        spec = service.run_task.await_args.args[0]
        assert spec.directory == tmp_path.resolve()
        assert spec.required_capability == "high"
        assert spec.output_retry_count == 4
        assert spec.output_retry_prompt == "  custom retry prompt  "
        assert spec.file_write_allowlist == (
            (tmp_path / "keep.json").resolve(),
            (tmp_path / "work" / "reports").resolve(),
            (tmp_path / "generated").resolve(),
            external_dir.resolve(),
        )
        assert spec.writable_paths == spec.file_write_allowlist
        assert spec.readable_paths == (
            (tmp_path / "references").resolve(),
            (external_dir / "schemas").resolve(),
        )
        assert spec.allowed_bash_commands == (optional_command,)
        assert spec.required_bash_commands == (required_command,)
        assert spec.bash_command_match_mode == match_mode
        assert spec.required_bash_retry_count == 1
        assert spec.required_bash_success_markers == ((
            required_command,
            "VALID: artifacts passed",
        ),)
        assert spec.post_session_validator is post_session_validator
        assert spec.post_session_validation_retry_count == 1
        assert spec.session_id == "ses-existing"

        service.run_task.reset_mock()
        with (
            patch("task_agent.task_service._get_opencode_task_service", return_value=service),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path),
        ):
            plain = await run_opencode_task(
                task_name="plain text",
                task_type="vulnerability_mining",
                prompt="return text",
                required_capability="low",
            )
        assert plain.structured is None
        assert service.run_task.await_args.args[0].bash_command_match_mode == "exact"

    asyncio.run(run())


@pytest.mark.parametrize(
    ("task_type", "expected_priority"),
    [
        ("vulnerability_validation", 90),
        ("threat_analysis", 50),
        ("fp_review", 60),
        ("vulnerability_mining", 50),
        ("skill_create", 70),
        ("git_history", 50),
        ("variant_hunt", 50),
        ("memory_api_discovery", 50),
    ],
)
def test_public_interface_assigns_task_type_priority(
    tmp_path: Path,
    task_type: str,
    expected_priority: int,
) -> None:
    async def run() -> None:
        internal = OpenCodeTaskResult(
            task_id="task-priority",
            session_id="ses-priority",
            message_id="msg-priority",
            status="success",
            text="ok",
            model="provider/model",
        )
        service = SimpleNamespace(run_task=AsyncMock(return_value=internal))
        with (
            patch(
                "task_agent.task_service._get_opencode_task_service",
                return_value=service,
            ),
            patch("task_agent.task_service.get_config", return_value=_config()),
            _task_context(tmp_path),
        ):
            result = await run_opencode_task(
                task_name=f"{task_type} priority",
                task_type=task_type,
                prompt="run",
                required_capability="high",
            )

        assert result.status == "success"
        spec = service.run_task.await_args.args[0]
        assert spec.priority == expected_priority

    asyncio.run(run())


def test_validation_model_task_uses_scan_policy_snapshot(tmp_path: Path) -> None:
    snapshot = {
        "required_capability": "low",
        "timeout_seconds": 17,
        "max_retries": 3,
    }
    assert _task_model_policy(OpenCodeExecutionContext(
        task_metadata={
            "task_type": "vulnerability_validation",
            "validation_model_policy": snapshot,
        },
    )) is snapshot

    async def run() -> None:
        internal = OpenCodeTaskResult(
            task_id="task-validation-policy",
            session_id="ses-validation-policy",
            message_id="msg-validation-policy",
            status="success",
            text="ok",
            model="provider/model",
        )
        service = SimpleNamespace(run_task=AsyncMock(return_value=internal))
        current_config = _config()
        current_config.vulnerability_validation = SimpleNamespace(
            model_policy=SimpleNamespace(
                required_capability="high",
                timeout_seconds=999,
                max_retries=9,
            ),
        )
        with (
            patch(
                "task_agent.task_service._get_opencode_task_service",
                return_value=service,
            ),
            patch(
                "task_agent.task_service.get_config",
                return_value=current_config,
            ),
            _task_context(
                tmp_path,
                task_metadata={
                    "validation_model_policy": snapshot,
                },
            ),
        ):
            await run_opencode_task(
                task_name="snapshotted validation policy",
                task_type="vulnerability_validation",
                prompt="validate",
                required_capability="high",
            )

        spec = service.run_task.await_args.args[0]
        assert spec.timeout_seconds == 17

    asyncio.run(run())


def test_public_interface_can_override_bound_output_and_cancellation(tmp_path: Path) -> None:
    async def run() -> None:
        from task_agent.task_service import get_opencode_execution_context

        parent_cancel = threading.Event()
        child_cancel = threading.Event()
        parent_output: list[str] = []
        captured: dict = {}

        async def component_task(**_kwargs):
            context = get_opencode_execution_context()
            captured["output"] = context.on_output
            captured["cancel_event"] = context.cancel_event
            return OpenCodeResult(
                session_id="ses-override",
                status="success",
                text="ok",
                structured=None,
                model="provider/model",
            )

        with (
            patch("task_agent.task_service._run_component_task", new=component_task),
            _task_context(
                tmp_path,
                on_output=parent_output.append,
                cancel_event=parent_cancel,
            ),
        ):
            result = await run_opencode_task(
                task_name="override context",
                task_type="vulnerability_mining",
                prompt="inspect context",
                required_capability="low",
                output=None,
                cancel_event=child_cancel,
            )

        assert result.session_id == "ses-override"
        assert captured["output"] is None
        assert captured["cancel_event"] is child_cancel

    asyncio.run(run())


def test_public_interface_requires_context_and_propagates_cancellation(tmp_path: Path) -> None:
    async def run() -> None:
        with pytest.raises(RuntimeError, match="project_dir is not bound"):
            await run_opencode_task(
                task_name="missing context",
                task_type="vulnerability_mining",
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
                task_type="vulnerability_mining",
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
                task_type="vulnerability_mining",
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
                task_type="vulnerability_mining",
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
        for legacy_type in (
            "audit",
            "project_audit",
            "threat_audit",
            "sensitive_clear",
            "report_audit",
        ):
            with pytest.raises(ValueError, match="task_type"):
                await run_opencode_task(
                    task_name="legacy task type",
                    task_type=legacy_type,
                    prompt="test",
                    required_capability="low",
                )

    asyncio.run(run())


def test_public_interface_rejects_invalid_json_retry_prompts() -> None:
    async def run() -> None:
        with pytest.raises(TypeError, match="invalid_json_retry_prompt.*string"):
            await run_opencode_task(
                task_name="invalid retry prompt type",
                task_type="vulnerability_mining",
                prompt="test",
                required_capability="low",
                invalid_json_retry_prompt=123,  # type: ignore[arg-type]
            )
        for value in ("", " \n\t "):
            with pytest.raises(ValueError, match="invalid_json_retry_prompt.*empty"):
                await run_opencode_task(
                    task_name="empty retry prompt",
                    task_type="vulnerability_mining",
                    prompt="test",
                    required_capability="low",
                    invalid_json_retry_prompt=value,
                )

    asyncio.run(run())


def test_public_interface_validates_file_write_allowlist(tmp_path: Path) -> None:
    async def run() -> None:
        assert _normalize_file_write_allowlist("keep.json") == ("keep.json",)
        assert _normalize_file_write_allowlist(Path("reports")) == ("reports",)
        with pytest.raises(TypeError, match="entries.*strings or PathLike"):
            await run_opencode_task(
                task_name="invalid allowlist entry",
                task_type="vulnerability_mining",
                prompt="test",
                required_capability="low",
                output_schema=SCHEMA,
                file_write_allowlist=[123],  # type: ignore[list-item]
            )
        for value in ("", "generated/*", "generated/file?.json"):
            with pytest.raises(ValueError, match="file_write_allowlist"):
                await run_opencode_task(
                    task_name="unsafe allowlist",
                    task_type="vulnerability_mining",
                    prompt="test",
                    required_capability="low",
                    file_write_allowlist=value,
                )
        with _task_context(tmp_path), pytest.raises(ValueError, match="filesystem root"):
            await run_opencode_task(
                task_name="root allowlist",
                task_type="vulnerability_mining",
                prompt="test",
                required_capability="low",
                file_write_allowlist=Path(tmp_path.anchor),
            )

    asyncio.run(run())


def test_public_interface_validates_writable_paths(tmp_path: Path) -> None:
    async def run() -> None:
        assert _normalize_writable_paths("generated") == ("generated",)
        assert _normalize_writable_paths(Path("reports")) == ("reports",)
        with pytest.raises(TypeError, match="entries.*strings or PathLike"):
            await run_opencode_task(
                task_name="invalid writable path",
                task_type="vulnerability_mining",
                prompt="test",
                required_capability="low",
                writable_paths=[123],  # type: ignore[list-item]
            )
        for value in ("", "generated/*", "generated/file?.json"):
            with pytest.raises(ValueError, match="writable_paths"):
                await run_opencode_task(
                    task_name="unsafe writable path",
                    task_type="vulnerability_mining",
                    prompt="test",
                    required_capability="low",
                    writable_paths=[value],
                )
        with (
            _task_context(tmp_path),
            pytest.raises(ValueError, match="filesystem root"),
        ):
            await run_opencode_task(
                task_name="root writable path",
                task_type="vulnerability_mining",
                prompt="test",
                required_capability="low",
                writable_paths=[Path(tmp_path.anchor)],
            )

    asyncio.run(run())


def test_public_interface_validates_readable_paths_and_required_commands(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        assert _normalize_readable_paths("references") == ("references",)
        assert _normalize_allowed_bash_commands("python optional.py") == (
            "python optional.py",
        )
        assert _normalize_required_bash_commands("python validate.py") == (
            "python validate.py",
        )
        assert _normalize_required_bash_success_markers(
            {"python validate.py": "VALID: artifacts passed"},
            required_commands=("python validate.py",),
        ) == (("python validate.py", "VALID: artifacts passed"),)
        with pytest.raises(TypeError, match="required_bash_commands entries"):
            _normalize_required_bash_commands([123])  # type: ignore[list-item]
        for value in ("", "python validate*.py", "python validate.py\necho bad"):
            with pytest.raises(ValueError, match="required_bash_commands"):
                _normalize_required_bash_commands(value)
        with pytest.raises(ValueError, match="allowed_bash_commands"):
            _normalize_allowed_bash_commands("python optional*.py")
        with pytest.raises(ValueError, match="must match"):
            _normalize_required_bash_success_markers(
                {"python other.py": "VALID"},
                required_commands=("python validate.py",),
            )
        with _task_context(tmp_path), pytest.raises(
            ValueError,
            match="requires required_bash_commands",
        ):
            await run_opencode_task(
                task_name="invalid required command retry",
                task_type="threat_analysis",
                prompt="test",
                required_capability="high",
                required_bash_retry_count=1,
            )
        with _task_context(tmp_path), pytest.raises(
            ValueError,
            match="requires post_session_validator",
        ):
            await run_opencode_task(
                task_name="invalid post-session retry",
                task_type="threat_analysis",
                prompt="test",
                required_capability="high",
                post_session_validation_retry_count=1,
            )
        with _task_context(tmp_path), pytest.raises(
            ValueError,
            match="readable_paths.*filesystem root",
        ):
            await run_opencode_task(
                task_name="root readable path",
                task_type="threat_analysis",
                prompt="test",
                required_capability="high",
                readable_paths=Path(tmp_path.anchor),
            )

    asyncio.run(run())


def test_task_service_parses_json_and_uses_global_permissions(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        manager = SimpleNamespace()
        captured: dict = {}
        output: list[str] = []
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        scans_root = tmp_path / ".opendeephole" / "scans"
        scan_dir = scans_root / "scan-7"
        skill_root = tmp_path / "component-skills"
        configured_skill_root = tmp_path / "configured-skills"
        reference_path = (
            skill_root
            / "attack-tree-by-asset"
            / "references"
            / "attack_mode.json"
        )
        reference_path.parent.mkdir(parents=True)
        reference_path.write_text("[]", encoding="utf-8")
        configured_skill_root.mkdir()
        scan_graph = {
            "enabled": True,
            "name": "scan-graph",
            "transport": "remote",
            "timeout_seconds": 30,
            "remote": {"url": "http://graph.test/mcp", "headers": {}},
            "local": {"executable": "", "args": [], "environment": {}},
        }

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
        runtime = dataclasses.replace(
            _runtime(tmp_path),
            config_content=json.dumps({
                "skills": {"paths": [str(configured_skill_root)]},
            }),
        )
        service._runtime_for_task = AsyncMock(return_value=(
            runtime,
            "provider/model-low",
            _source(),
        ))
        patches = _service_patches(
            manager,
            writable_roots=(scans_root,),
        )
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
            with bind_opencode_execution_context(
                scan_id="scan-7",
                project_dir=project_dir,
                work_dir=scan_dir,
                skill_paths=(skill_root,),
                task_metadata={
                    "task_type": "vulnerability_mining",
                    "checker": "oob",
                    "validation_debug": True,
                },
                feedback_entries=({
                    "vuln_type": "oob",
                    "reason": "边界检查缺失",
                    "function_source": "void parse(void) {}",
                },),
                code_graph_mcp=scan_graph,
                on_output=output.append,
            ):
                original_prompt = " \nreturn an answer exactly as written\n "
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="schema task",
                    prompt=original_prompt,
                    directory=project_dir,
                    timeout_seconds=12,
                    priority=87,
                    output_schema=SCHEMA,
                ))

        assert result.status == "success"
        assert result.structured == {"answer": 7}
        assert result.model == "provider/actual-model"
        assert result.output_source.attempt == 1
        assert captured["mcp_tools"] is None
        assert captured["scan_id"] == "scan-7"
        assert captured["code_graph_mcp"] == scan_graph
        assert captured["timeout"] == 12
        assert captured["return_details"] is True
        assert captured["show_serve_status"] is True
        assert captured["log_stage"] == "vulnerability_mining"
        assert captured["prompt"] == original_prompt
        assert "JSON Schema" not in captured["prompt"]
        assert "JSON Schema" not in captured["system_prompt"]
        assert "## 扫描代码图谱" in captured["system_prompt"]
        assert "当前任务已绑定本次扫描专属的代码图谱 MCP" in captured["system_prompt"]
        assert str(project_dir.resolve()) in captured["system_prompt"]
        assert "本次扫描标识为 `scan-7`" in captured["system_prompt"]
        assert "projectPath=" not in captured["system_prompt"]
        assert "## 已选择的扫描反馈" in captured["system_prompt"]
        assert "仍需核验当前代码" in captured["system_prompt"]
        assert "用户理由：边界检查缺失" in captured["system_prompt"]
        assert "CodeGraph project scope" not in captured["system_prompt"]
        assert "Selected scan feedback" not in captured["system_prompt"]
        assert captured["permissions"] == _writable_path_permissions((scan_dir.resolve(),))
        acquire_kwargs = acquire_mock.await_args.kwargs
        assert acquire_kwargs["stats_scope_id"] == "scan-7"
        assert acquire_kwargs["task_context"]["task_type"] == "vulnerability_mining"
        assert acquire_kwargs["task_context"]["prompt"] == captured["prompt"]
        assert acquire_kwargs["task_context"]["prompt_length"] == len(captured["prompt"])
        assert acquire_kwargs["task_context"]["session_attempt"] == 1
        assert "global_concurrency" not in acquire_kwargs
        assert acquire_kwargs["wait_when_unavailable"] is False
        assert any(line.startswith("[vulnerability_mining][pending][task] QUEUED") for line in output)
        assert any(line.startswith("[vulnerability_mining][pending][task] START") for line in output)
        assert any(
            line.startswith("[vulnerability_mining][ses_structured][task] FINISHED")
            and "status=success" in line
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
        assert any(line.startswith("[opencode][pending][task] QUEUED") for line in output)
        assert any(
            line.startswith("[opencode][pending][task] FINISHED")
            and "status=failure" in line
            and NO_AVAILABLE_MODEL_MESSAGE in line
            for line in output
        )

    asyncio.run(run())


def test_failure_progress_normalizes_multiline_error(tmp_path: Path) -> None:
    async def run() -> None:
        error = "first line\n second\tline"

        async def run_prompt(**_kwargs):
            raise RuntimeError(error)

        manager = SimpleNamespace(run_prompt=run_prompt)
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        output: list[str] = []
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            _task_context(
                tmp_path,
                task_metadata={"standalone_console": True},
                on_output=output.append,
            ),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="multiline failure",
                prompt="test",
                directory=tmp_path,
                attempt=0,
            ))

        assert result.status == "failure"
        assert result.error == error
        finished = next(
            line
            for line in output
            if line.startswith("[opencode][pending][task] FINISHED")
        )
        assert "error=first line second line" in finished
        assert "\n" not in finished
        assert "\t" not in finished

    asyncio.run(run())


def test_phase_policy_controls_capability_timeout_and_retries(tmp_path: Path) -> None:
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
        writable_root = tmp_path / "generated"
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager, runtime_config=runtime_config)
        with patches[0], patches[1] as acquire_mock, patches[2], patches[3], patches[4], patches[5]:
            with bind_opencode_execution_context(
                project_dir=tmp_path,
                work_dir=tmp_path / "work",
                task_metadata={"task_type": "vulnerability_mining"},
            ):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="policy",
                    prompt="test",
                    directory=tmp_path,
                    required_capability="low",
                    timeout_seconds=12,
                    attempt=7,
                    output_retry_count=0,
                    writable_paths=(writable_root,),
                ))

        assert result.status == "success"
        assert len(calls) == 2
        assert [call["timeout"] for call in calls] == [77, 77]
        assert [call["permissions"] for call in calls] == [
            _writable_path_permissions((
                (tmp_path / "work").resolve(),
                writable_root.resolve(),
            )),
            _writable_path_permissions((
                (tmp_path / "work").resolve(),
                writable_root.resolve(),
            )),
        ]
        assert acquire_mock.await_count == 2
        assert all(
            call.kwargs["required_capability"] == "high"
            for call in acquire_mock.await_args_list
        )
        assert all(
            call.kwargs["wait_when_unavailable"] is True
            for call in acquire_mock.await_args_list
        )

    asyncio.run(run())


def test_json_file_fallback_keeps_last_text_and_removes_new_file(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        output_file = work_dir / "result.json"
        calls = 0

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            output_file.write_text('{"answer": 41}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-result",
                path=str(output_file),
                created=True,
            ))
            callback = kwargs["on_session_id"]("ses-file-json")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-file-json",
                message_id="msg-file-json",
                lines=["JSON 已写入 result.json"],
                text="JSON 已写入 result.json",
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="file json fallback",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=2,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.text == "JSON 已写入 result.json"
        assert result.structured == {"answer": 41}
        assert calls == 1
        assert not output_file.exists()

    asyncio.run(run())


def test_text_json_stays_primary_over_written_json(tmp_path: Path) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        output_file = work_dir / "secondary.json"

        async def run_prompt(**kwargs):
            output_file.write_text('{"answer": 99}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-secondary",
                path=str(output_file),
                created=True,
            ))
            callback = kwargs["on_session_id"]("ses-text-primary")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-text-primary",
                message_id="msg-text-primary",
                lines=['{"answer": 7}'],
                text='{"answer": 7}',
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="text json primary",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.text == '{"answer": 7}'
        assert result.structured == {"answer": 7}
        assert output_file.read_text(encoding="utf-8") == '{"answer": 99}'

    asyncio.run(run())


def test_relative_written_result_path_resolves_from_project_and_is_cleaned(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        project_dir = tmp_path / "project"
        work_dir = tmp_path / "work"
        project_dir.mkdir()
        work_dir.mkdir()
        output_file = project_dir / "result.json"

        async def run_prompt(**kwargs):
            output_file.write_text('{"answer": 23}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-project-relative",
                path="result.json",
                created=True,
            ))
            callback = kwargs["on_session_id"]("ses-project-relative")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-project-relative",
                message_id="msg-project-relative",
                lines=["written"],
                text="written",
                model="provider/model-low",
            )

        result = await _run_service_task(
            project_dir,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="project relative file",
                prompt="return json",
                directory=project_dir,
                output_schema=SCHEMA,
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.structured == {"answer": 23}
        assert not output_file.exists()

    asyncio.run(run())


def test_written_json_in_explicit_allowlist_path_is_parsed_and_removed(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        project_dir = tmp_path / "project"
        work_dir = tmp_path / "work"
        writable_dir = tmp_path / "external-output"
        project_dir.mkdir()
        work_dir.mkdir()
        writable_dir.mkdir()
        output_file = writable_dir / "result.json"

        async def run_prompt(**kwargs):
            output_file.write_text('{"answer": 29}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-external",
                path=str(output_file),
                created=True,
            ))
            callback = kwargs["on_session_id"]("ses-external-file")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-external-file",
                message_id="msg-external-file",
                lines=["written"],
                text="written",
                model="provider/model-low",
            )

        result = await _run_service_task(
            project_dir,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="external writable file",
                prompt="return json",
                directory=project_dir,
                output_schema=SCHEMA,
                output_retry_count=0,
                file_write_allowlist=(writable_dir,),
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.structured == {"answer": 29}
        assert not output_file.exists()

    asyncio.run(run())


def test_latest_valid_written_json_wins_and_only_selected_file_is_forced_removed(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        retained_dir = work_dir / "reports"
        retained_dir.mkdir(parents=True)
        temporary = work_dir / "temporary.json"
        retained_file = work_dir / "keep.json"
        retained_in_dir = retained_dir / "latest.json"

        async def run_prompt(**kwargs):
            writes = (
                (temporary, 1, "write-temporary"),
                (retained_file, 2, "write-retained-file"),
                (retained_in_dir, 3, "write-retained-dir"),
            )
            for path, answer, call_id in writes:
                path.write_text(json.dumps({"answer": answer}), encoding="utf-8")
                kwargs["on_file_write"](OpenCodeFileWrite(
                    call_id=call_id,
                    path=str(path),
                    created=True,
                ))
            callback = kwargs["on_session_id"]("ses-latest-file")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-latest-file",
                message_id="msg-latest-file",
                lines=["files written"],
                text="files written",
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="latest file",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=0,
                file_write_allowlist=(retained_file, retained_dir),
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.structured == {"answer": 3}
        assert temporary.read_text(encoding="utf-8") == '{"answer": 1}'
        assert retained_file.read_text(encoding="utf-8") == '{"answer": 2}'
        assert not retained_in_dir.exists()

    asyncio.run(run())


def test_preexisting_written_file_is_never_deleted(tmp_path: Path) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        output_file = work_dir / "existing.json"
        output_file.write_text('{"answer": 1}', encoding="utf-8")

        async def run_prompt(**kwargs):
            output_file.write_text('{"answer": 8}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="edit-existing",
                path=str(output_file),
                created=False,
            ))
            callback = kwargs["on_session_id"]("ses-existing-file")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-existing-file",
                message_id="msg-existing-file",
                lines=["updated"],
                text="updated",
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="existing file",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.structured == {"answer": 8}
        assert output_file.read_text(encoding="utf-8") == '{"answer": 8}'

    asyncio.run(run())


def test_file_tracking_is_enabled_without_schema_and_work_dir_is_retained(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        output_file = work_dir / "requested.txt"

        async def run_prompt(**kwargs):
            assert kwargs["on_file_write"] is not None
            output_file.write_text("keep me", encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-no-schema",
                path=str(output_file),
                created=True,
            ))
            callback = kwargs["on_session_id"]("ses-no-schema")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-no-schema",
                message_id="msg-no-schema",
                lines=["done"],
                text="done",
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="no schema",
                prompt="write a file",
                directory=tmp_path,
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.structured is None
        assert output_file.read_text(encoding="utf-8") == "keep me"

    asyncio.run(run())


def test_allowlisted_external_directory_retains_descendants_and_cleans_sibling(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        project_dir = tmp_path / "project"
        work_dir = tmp_path / "work"
        allowed_dir = tmp_path / "external-output"
        sibling_dir = tmp_path / "external-output-other"
        project_dir.mkdir()
        work_dir.mkdir()
        allowed_file = allowed_dir / "nested" / "report.md"
        sibling_file = sibling_dir / "report.md"
        allowed_file.parent.mkdir(parents=True)
        sibling_file.parent.mkdir(parents=True)
        captured_permissions: list[dict[str, str]] | None = None

        async def run_prompt(**kwargs):
            nonlocal captured_permissions
            captured_permissions = kwargs["permissions"]
            for call_id, path in (
                ("write-allowed", allowed_file),
                ("write-sibling", sibling_file),
            ):
                path.write_text(call_id, encoding="utf-8")
                kwargs["on_file_write"](OpenCodeFileWrite(
                    call_id=call_id,
                    path=str(path),
                    created=True,
                ))
            callback = kwargs["on_session_id"]("ses-allowlisted-dir")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-allowlisted-dir",
                message_id="msg-allowlisted-dir",
                lines=["done"],
                text="done",
                model="provider/model-low",
            )

        result = await _run_service_task(
            project_dir,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="allowlisted directory",
                prompt="write reports",
                directory=project_dir,
                file_write_allowlist=(allowed_dir,),
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert allowed_file.read_text(encoding="utf-8") == "write-allowed"
        assert not sibling_file.exists()
        assert captured_permissions == _writable_path_permissions((
            work_dir.resolve(),
            allowed_dir.resolve(),
        ))

    asyncio.run(run())


def test_invalid_written_json_is_formatter_source_and_retained_in_work_dir(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        invalid_file = work_dir / "invalid.json"
        calls = 0
        permissions: list[list[dict[str, str]] | None] = []
        prompts: list[str] = []
        sessions: list[str | None] = []

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            permissions.append(kwargs["permissions"])
            prompts.append(kwargs["prompt"])
            sessions.append(kwargs["session_id"])
            created_session = (
                "ses-file-retry" if calls == 1 else "ses-file-formatter"
            )
            callback = kwargs["on_session_id"](created_session)
            if hasattr(callback, "__await__"):
                await callback
            if calls == 1:
                invalid_file.write_text('{"answer":"wrong"}', encoding="utf-8")
                kwargs["on_file_write"](OpenCodeFileWrite(
                    call_id="write-invalid",
                    path=str(invalid_file),
                    created=True,
                ))
                text = "written"
            else:
                assert invalid_file.read_text(encoding="utf-8") == '{"answer":"wrong"}'
                assert kwargs["disable_all_tools"] is True
                assert kwargs["on_file_write"] is None
                text = '{"answer": 12}'
            return OpenCodePromptResult(
                session_id=created_session,
                message_id=f"msg-file-retry-{calls}",
                lines=[text],
                text=text,
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="file retry",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=1,
                attempt=0,
                writable_paths=(work_dir,),
            ),
            work_dir=work_dir,
        )

        assert result.status == "success"
        assert result.session_id == "ses-file-retry"
        assert result.text == "written"
        assert result.structured == {"answer": 12}
        assert calls == 2
        assert sessions == [None, None]
        assert json.dumps('{"answer":"wrong"}', ensure_ascii=False) in prompts[1]
        assert json.dumps("written", ensure_ascii=False) not in prompts[1]
        assert permissions == [
            _writable_path_permissions((work_dir.resolve(),)),
            [],
        ]
        assert invalid_file.read_text(encoding="utf-8") == '{"answer":"wrong"}'

    asyncio.run(run())


def test_new_written_file_is_cleaned_when_prompt_fails(tmp_path: Path) -> None:
    async def run() -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        output_file = tmp_path / "failed.json"

        async def run_prompt(**kwargs):
            output_file.write_text('{"answer": 5}', encoding="utf-8")
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id="write-before-failure",
                path=str(output_file),
                created=True,
            ))
            raise RuntimeError("prompt failed")

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="failed prompt cleanup",
                prompt="return json",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=0,
                attempt=0,
            ),
            work_dir=work_dir,
        )

        assert result.status == "failure"
        assert "prompt failed" in result.error
        assert not output_file.exists()

    asyncio.run(run())


def test_invalid_json_is_corrected_in_the_same_session(tmp_path: Path) -> None:
    from task_agent.token_usage import TokenCounters, token_usage_from_models

    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[dict] = []
        output: list[str] = []
        responses = [
            "not json",
            "__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__",
            '{"answer":"wrong type"}',
            '{"answer":9}',
        ]
        created_sessions = ["ses_same", "ses_formatter", "ses_same", "ses_same"]

        async def run_prompt(**kwargs):
            index = len(calls)
            calls.append(kwargs)
            callback = kwargs["on_session_id"](created_sessions[index])
            if hasattr(callback, "__await__"):
                await callback
            await kwargs["on_token_usage"](token_usage_from_models({
                "provider/formatter" if index == 1 else "provider/model-low": TokenCounters(10, 2),
            }))
            text = responses[index]
            return OpenCodePromptResult(
                session_id=created_sessions[index],
                message_id=f"msg_{len(calls)}",
                lines=[text],
                text=text,
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with (patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3] as update_mock, patches[4], patches[5],
              patch("task_agent.task_service.record_model_token_usage", new=AsyncMock()) as record_usage):
            with _task_context(
                tmp_path,
                task_metadata={"standalone_console": True, "task_type": "fp_review"},
                on_output=output.append,
            ):
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
        assert result.token_usage["total_tokens"] == 48
        assert result.token_usage["by_category"] == [{
            "category": "fp_review", "label": "去误报", "complete": True,
            "input_tokens": 40, "output_tokens": 8, "reasoning_tokens": 0,
            "cache_read_tokens": 0, "cache_write_tokens": 0, "total_tokens": 48,
        }]
        assert [call.args[1].by_category[0].category for call in record_usage.await_args_list] == ["fp_review"] * 4
        assert sum(call.args[1].counters.total_tokens for call in record_usage.await_args_list) == 48
        assert acquire_mock.await_count == 3
        assert release_mock.await_count == 3
        assert [call["session_id"] for call in calls] == [
            None,
            None,
            "ses_same",
            "ses_same",
        ]
        schema_text = json.dumps(SCHEMA, ensure_ascii=False, indent=2)
        assert calls[0]["prompt"] == "initial prompt"
        formatter_prompt = calls[1]["prompt"]
        assert "你是一个只做格式转换的 JSON 修复器" in formatter_prompt
        assert json.dumps("not json", ensure_ascii=False) in formatter_prompt
        assert "__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__" in formatter_prompt
        assert calls[1]["disable_all_tools"] is True
        assert calls[1]["scan_id"] == ""
        assert all(
            "你上一次的回复不是符合目标 JSON Schema 的合法 JSON" in prompt
            for prompt in (calls[2]["prompt"], calls[3]["prompt"])
        )
        assert all(
            prompt.endswith(schema_text)
            for prompt in (calls[2]["prompt"], calls[3]["prompt"])
        )
        assert calls[0]["prompt"].count(schema_text) == 0
        assert formatter_prompt.count(schema_text) == 1
        assert all(
            prompt.count(schema_text) == 1
            for prompt in (calls[2]["prompt"], calls[3]["prompt"])
        )
        formatter_acquire = acquire_mock.await_args_list[1].kwargs
        assert formatter_acquire["required_capability"] == "low"
        assert formatter_acquire["strict_capability"] is True
        assert formatter_acquire["prefer_lowest_capability"] is True
        assert formatter_acquire["wait_when_unavailable"] is False
        formatter_context = formatter_acquire["task_context"]
        correction_context = acquire_mock.await_args_list[2].kwargs["task_context"]
        assert formatter_context["task_phase"] == "json_format"
        assert correction_context["task_phase"] == "json_correction"
        assert formatter_context["prompt"] == "initial prompt"
        assert correction_context["prompt"] == "initial prompt"
        assert formatter_context["prompt_length"] == len("initial prompt")
        assert correction_context["prompt_length"] == len("initial prompt")
        assert all(
            "Your previous response" not in call["prompt"]
            for call in calls
        )
        assert (
            "[fp_review][ses_same][session] "
            "JSON_FORMAT_RETRY reason=invalid_json next_session=new "
            "required_capability=low"
            in output
        )
        assert any(
            line.startswith("[fp_review][ses_same][session] JSON_FORMAT_FAILED")
            and "reason=source_unrelated" in line
            and "fallback=original_session" in line
            for line in output
        )
        assert (
            "[fp_review][ses_same][session] "
            "JSON_RETRY 1/2 reason=invalid_json next_session=same"
            in output
        )
        assert (
            "[fp_review][ses_same][session] "
            "JSON_RETRY 2/2 reason=invalid_json next_session=same"
            in output
        )
        assert any(
            line.startswith("[fp_review][ses_same][task] FINISHED")
            and "status=success" in line
            for line in output
        )
        traced = max(
            (
                call.args[1]["session_events"]
                for call in update_mock.await_args_list
                if len(call.args) > 1 and "session_events" in call.args[1]
            ),
            key=len,
        )
        assert [event["phase"] for event in traced] == [
            "business",
            "json_format",
            "json_retry",
            "json_retry",
        ]
        assert [event["session_id"] for event in traced] == [
            "ses_same",
            "ses_formatter",
            "ses_same",
            "ses_same",
        ]
        assert [event["outcome"] for event in traced] == [
            "invalid_output",
            "invalid_output",
            "invalid_output",
            "success",
        ]
        assert traced[0]["failure_kind"] == "no_json"
        assert traced[1]["failure_kind"] == "source_unrelated"
        assert traced[2]["failure_kind"] == "schema_mismatch"

    asyncio.run(run())


@pytest.mark.parametrize("corrected_verdict", ["true_positive", "false_positive", "uncertain"])
def test_enum_mismatch_requires_a_valid_verdict_after_correction(
    tmp_path: Path, corrected_verdict: str,
) -> None:
    async def run() -> None:
        schema = {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive"],
                },
            },
            "required": ["verdict"],
        }
        texts = [
            '{"verdict":"uncertain"}',
            "__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__",
            json.dumps({"verdict": corrected_verdict}),
        ]
        sessions = ["ses_verdict", "ses_formatter", "ses_verdict"]
        calls: list[dict] = []

        async def run_prompt(**kwargs):
            index = len(calls)
            calls.append(kwargs)
            callback = kwargs["on_session_id"](sessions[index])
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id=sessions[index],
                message_id=f"msg_{index}",
                lines=[texts[index]],
                text=texts[index],
                model="provider/model-low",
            )

        result = await _run_service_task(
            tmp_path,
            run_prompt,
            OpenCodeTaskSpec(
                task_name="binary verdict",
                prompt="return a final verdict",
                directory=tmp_path,
                output_schema=schema,
                output_retry_count=1,
                attempt=0,
            ),
        )

        assert [call["session_id"] for call in calls] == [None, None, "ses_verdict"]
        assert calls[2]["prompt"].endswith(json.dumps(schema, ensure_ascii=False, indent=2))
        if corrected_verdict == "uncertain":
            assert result.status == "failure"
            assert result.structured is None
            assert result.text == texts[-1]
        else:
            assert result.status == "success"
            assert result.structured == {"verdict": corrected_verdict}

    asyncio.run(run())


def test_custom_json_correction_prompt_is_repeated_verbatim(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[dict] = []
        responses = [
            "not json",
            "__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__",
            '{"answer":"wrong type"}',
            '{"answer":9}',
        ]

        async def run_prompt(**kwargs):
            index = len(calls)
            calls.append(kwargs)
            created_session = "ses_formatter" if index == 1 else "ses_custom"
            callback = kwargs["on_session_id"](created_session)
            if hasattr(callback, "__await__"):
                await callback
            text = responses[index]
            return OpenCodePromptResult(
                session_id=created_session,
                message_id=f"msg_{len(calls)}",
                lines=[text],
                text=text,
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        custom_prompt = " \n只按我写的方式重新输出\n "
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            _task_context(tmp_path),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="custom correction",
                prompt="original prompt",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=2,
                output_retry_prompt=custom_prompt,
                attempt=0,
            ))

        assert result.status == "success"
        assert [call["prompt"] for call in calls[2:]] == [
            custom_prompt,
            custom_prompt,
        ]
        assert calls[0]["prompt"] == "original prompt"
        assert "你是一个只做格式转换的 JSON 修复器" in calls[1]["prompt"]
        assert [call["session_id"] for call in calls] == [
            None,
            None,
            "ses_custom",
            "ses_custom",
        ]

    asyncio.run(run())


def test_formatter_request_failure_falls_back_to_original_session(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[dict] = []
        output: list[str] = []

        async def run_prompt(**kwargs):
            index = len(calls)
            calls.append(kwargs)
            if index == 0:
                callback = kwargs["on_session_id"]("ses-business")
                if hasattr(callback, "__await__"):
                    await callback
                return OpenCodePromptResult(
                    session_id="ses-business",
                    message_id="msg-business",
                    lines=["not json"],
                    text="not json",
                    model="provider/model-low",
                )
            if index == 1:
                callback = kwargs["on_session_id"]("ses-formatter-failed")
                if hasattr(callback, "__await__"):
                    await callback
                await _notify_model_request_failure(kwargs, "failure")
                raise RuntimeError("formatter transport failed")
            callback = kwargs["on_session_id"]("ses-business")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses-business",
                message_id="msg-correction",
                lines=['{"answer": 31}'],
                text='{"answer": 31}',
                model="provider/model-low",
            )

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1],
            patches[2] as release_mock,
            patches[3],
            patches[4],
            patches[5],
            _task_context(
                tmp_path,
                task_metadata={"standalone_console": True},
                on_output=output.append,
            ),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="formatter request failure",
                prompt="initial",
                directory=tmp_path,
                output_schema=SCHEMA,
                output_retry_count=1,
                attempt=0,
            ))

        assert result.status == "success"
        assert result.session_id == "ses-business"
        assert result.text == '{"answer": 31}'
        assert result.structured == {"answer": 31}
        assert [call["session_id"] for call in calls] == [
            None,
            None,
            "ses-business",
        ]
        formatter_release = release_mock.await_args_list[1].kwargs
        assert formatter_release["outcome"] == "failure"
        assert formatter_release["health_outcome"] == "failure"
        assert formatter_release["record_completion"] is False
        assert any(
            line.startswith("[opencode][ses-business][session] JSON_FORMAT_FAILED")
            and "reason=RuntimeError" in line
            and "fallback=original_session" in line
            for line in output
        )

    asyncio.run(run())


def test_json_correction_exhaustion_requeues_with_new_session_and_same_task_id(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []
        output: list[str] = []
        created_sessions = [
            "ses_first",
            "ses_formatter",
            "ses_first",
            "ses_final",
        ]
        texts = [
            "bad",
            "__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__",
            "still bad",
            '{"answer":11}',
        ]
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
        with patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3] as update_mock, patches[4], patches[5]:
            with _task_context(
                tmp_path,
                task_metadata={"standalone_console": True},
                on_output=output.append,
                on_invocation_metadata=sources.append,
            ):
                handle = service.submit_task(OpenCodeTaskSpec(
                    task_name="fresh session retry",
                    prompt="initial",
                    directory=tmp_path,
                    output_schema=SCHEMA,
                    output_retry_count=1,
                    output_retry_prompt="custom retry",
                    attempt=1,
                ))
                result = await handle.result()
                first_session_id = await handle.wait_session_id()

        assert result.status == "success"
        assert result.task_id == handle.task_id
        assert first_session_id == "ses_first"
        assert result.session_id == "ses_final"
        assert result.structured == {"answer": 11}
        assert [source.attempt for source in sources] == [1, 1, 2]
        assert acquire_mock.await_count == 4
        assert [call[1] for call in calls] == [
            None,
            None,
            "ses_first",
            None,
        ]
        assert calls[0][0] == "initial"
        assert "你是一个只做格式转换的 JSON 修复器" in calls[1][0]
        assert calls[2][0] == "custom retry"
        assert calls[3][0] == "initial"
        first_release = release_mock.await_args_list[0].kwargs
        formatter_release = release_mock.await_args_list[1].kwargs
        correction_release = release_mock.await_args_list[2].kwargs
        final_release = release_mock.await_args_list[3].kwargs
        assert first_release["record_completion"] is False
        assert first_release["outcome"] == "failure"
        assert first_release["health_outcome"] is None
        assert formatter_release["record_completion"] is False
        assert formatter_release["outcome"] == "failure"
        assert formatter_release["health_outcome"] is None
        assert correction_release["record_completion"] is False
        assert correction_release["outcome"] == "failure"
        assert correction_release["health_outcome"] is None
        assert final_release["record_completion"] is True
        assert final_release["outcome"] == "success"
        assert final_release["health_outcome"] == "success"
        identity = {("provider/model-low", False, "opencode", "opencode")}
        assert acquire_mock.await_args_list[0].kwargs["avoid_model_identities"] == set()
        assert acquire_mock.await_args_list[1].kwargs["required_capability"] == "low"
        assert acquire_mock.await_args_list[3].kwargs["avoid_model_identities"] == identity
        base_context = acquire_mock.await_args_list[0].kwargs["task_context"]
        formatter_context = acquire_mock.await_args_list[1].kwargs["task_context"]
        correction_context = acquire_mock.await_args_list[2].kwargs["task_context"]
        assert {
            key: value
            for key, value in formatter_context.items()
            if key != "session_events"
        } == {**base_context, "task_phase": "json_format"}
        assert {
            key: value
            for key, value in correction_context.items()
            if key not in {"session_events", "serve_session_id"}
        } == {**base_context, "task_phase": "json_correction"}
        assert correction_context["serve_session_id"] == "ses_first"
        assert [
            event["phase"] for event in formatter_context["session_events"]
        ] == ["business"]
        assert [
            event["phase"] for event in correction_context["session_events"]
        ] == ["business", "json_format"]
        assert (
            "[opencode][ses_first][session] "
            "JSON_RETRY 1/1 reason=invalid_json next_session=same"
            in output
        )
        assert any(
            line.startswith("[opencode][ses_first][session] RETRY 1/1")
            and "next_session=new" in line
            for line in output
        )
        assert any(
            line.startswith("[opencode][ses_final][task] FINISHED")
            and "status=success" in line
            for line in output
        )
        traced = max(
            (
                call.args[1]["session_events"]
                for call in update_mock.await_args_list
                if len(call.args) > 1 and "session_events" in call.args[1]
            ),
            key=len,
        )
        assert [event["phase"] for event in traced] == [
            "business",
            "json_format",
            "json_retry",
            "business",
        ]
        assert [event["session_id"] for event in traced] == [
            "ses_first",
            "ses_formatter",
            "ses_first",
            "ses_final",
        ]
        assert [event["outcome"] for event in traced] == [
            "invalid_output",
            "invalid_output",
            "invalid_output",
            "success",
        ]

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
                await _notify_model_request_failure(kwargs, "failure")
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
        first_release = release_mock.await_args_list[0].kwargs
        assert first_release["record_completion"] is False
        assert first_release["outcome"] == "failure"
        assert first_release["health_outcome"] == "failure"
        identity = {("provider/model-low", False, "opencode", "opencode")}
        assert acquire_mock.await_args_list[0].kwargs["avoid_model_identities"] == set()
        assert acquire_mock.await_args_list[1].kwargs["avoid_model_identities"] == identity
        assert release_mock.await_args_list[1].kwargs["outcome"] == "success"
        assert release_mock.await_args_list[1].kwargs["health_outcome"] == "success"

    asyncio.run(run())


def test_required_command_failure_requeues_without_model_health_penalty(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[str | None] = []

        async def run_prompt(**kwargs):
            calls.append(kwargs["session_id"])
            session_id = "ses_quality_failed" if len(calls) == 1 else "ses_success"
            callback = kwargs["on_session_id"](session_id)
            if hasattr(callback, "__await__"):
                await callback
            if len(calls) == 1:
                raise OpenCodeTaskQualityError(
                    "required validation command was not executed"
                )
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
                    task_name="retry task quality",
                    prompt="run",
                    directory=tmp_path,
                    required_bash_commands=("python validate.py",),
                    attempt=1,
                ))

        assert result.status == "success"
        assert calls == [None, None]
        assert acquire_mock.await_count == 2
        first_release = release_mock.await_args_list[0].kwargs
        assert first_release["record_completion"] is False
        assert first_release["outcome"] == "failure"
        assert first_release["health_outcome"] is None
        identity = {("provider/model-low", False, "opencode", "opencode")}
        assert acquire_mock.await_args_list[1].kwargs["avoid_model_identities"] == identity

    asyncio.run(run())


def test_required_command_failure_is_corrected_in_the_same_session_first(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []

        async def run_prompt(**kwargs):
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            if len(calls) == 1:
                callback = kwargs["on_session_id"]("ses_quality_failed")
                if hasattr(callback, "__await__"):
                    await callback
                error = OpenCodeTaskQualityError(
                    "validator rejected value-assets.json",
                    failure_kind="command_exit_failure",
                    command_failures=(OpenCodeCommandFailure(
                        failure_kind="command_exit_failure",
                        command="python validate.py",
                        exit_code=1,
                        output_tail="value-assets.json: missing required field name",
                        output_bytes=52,
                    ),),
                )
                error.prompt_result = OpenCodePromptResult(
                    session_id="ses_quality_failed",
                    message_id="msg_failed",
                    lines=["validation failed"],
                    text="validation failed",
                    model="provider/model-low",
                )
                raise error
            return OpenCodePromptResult(
                session_id="ses_quality_failed",
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
            patches[3] as update_context_mock,
            patches[4],
            patches[5],
        ):
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="same-session validation correction",
                    prompt="run",
                    directory=tmp_path,
                    required_bash_commands=("python validate.py",),
                    required_bash_retry_count=1,
                    attempt=1,
                ))

        assert result.status == "success"
        assert result.session_id == "ses_quality_failed"
        assert [session_id for _, session_id in calls] == [
            None,
            "ses_quality_failed",
        ]
        assert "missing required field name" in calls[1][0]
        assert "python validate.py" in calls[1][0]
        assert acquire_mock.await_count == 1
        assert release_mock.await_args.kwargs["outcome"] == "success"
        final_updates = update_context_mock.await_args_list[-1].args[1]
        assert [
            (event["phase"], event["outcome"])
            for event in final_updates["session_events"]
        ] == [
            ("business", "failure"),
            ("validation_retry", "success"),
        ]

    asyncio.run(run())


def test_exhausted_same_session_validation_retry_starts_a_fresh_session(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []

        async def run_prompt(**kwargs):
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            if len(calls) <= 2:
                if len(calls) == 1:
                    callback = kwargs["on_session_id"]("ses_first")
                    if hasattr(callback, "__await__"):
                        await callback
                error = OpenCodeTaskQualityError(
                    "validator still failed",
                    failure_kind="command_exit_failure",
                    command_failures=(OpenCodeCommandFailure(
                        failure_kind="command_exit_failure",
                        command="python validate.py",
                        exit_code=1,
                        output_tail=f"failure {len(calls)}",
                        output_bytes=9,
                    ),),
                )
                error.prompt_result = OpenCodePromptResult(
                    session_id="ses_first",
                    message_id=f"msg_failed_{len(calls)}",
                    lines=[f"failure {len(calls)}"],
                    text=f"failure {len(calls)}",
                    model="provider/model-low",
                )
                raise error
            callback = kwargs["on_session_id"]("ses_fresh")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses_fresh",
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
            patches[2],
            patches[3] as update_context_mock,
            patches[4],
            patches[5],
        ):
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="fresh session after validation correction",
                    prompt="run",
                    directory=tmp_path,
                    required_bash_commands=("python validate.py",),
                    required_bash_retry_count=1,
                    attempt=1,
                ))

        assert result.status == "success"
        assert result.session_id == "ses_fresh"
        assert [session_id for _, session_id in calls] == [
            None,
            "ses_first",
            None,
        ]
        assert calls[2][0] == "run"
        assert acquire_mock.await_count == 2
        final_updates = update_context_mock.await_args_list[-1].args[1]
        assert [
            (event["phase"], event["outcome"], event["session_id"])
            for event in final_updates["session_events"]
        ] == [
            ("business", "failure", "ses_first"),
            ("validation_retry", "failure", "ses_first"),
            ("business", "success", "ses_fresh"),
        ]

    asyncio.run(run())


@pytest.mark.parametrize("match_mode", ["exact", "bound_python_script"])
def test_post_session_validator_returns_feedback_to_the_same_session(
    tmp_path: Path, match_mode: str,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        command = f'python "{tmp_path / "validate.py"}"'
        calls: list[tuple[str, str | None, tuple[str, ...]]] = []
        rogue_path = tmp_path / "post-validation-rogue.json"
        validation_calls = 0

        def validate() -> str | None:
            nonlocal validation_calls
            validation_calls += 1
            if validation_calls == 1:
                return "attack-trees.json: missing required property 'nodes'"
            return None

        async def run_prompt(**kwargs):
            assert kwargs["bash_command_match_mode"] == match_mode
            assert [rule for rule in kwargs["permissions"] if rule["permission"] == "bash"] == [
                {"permission": "bash", "pattern": "*", "action": "deny"},
                {"permission": "bash", "pattern": command, "action": "allow"},
            ]
            calls.append((
                kwargs["prompt"],
                kwargs["session_id"],
                kwargs["allowed_bash_commands"],
            ))
            if len(calls) == 1:
                callback = kwargs["on_session_id"]("ses_post_validation")
                if hasattr(callback, "__await__"):
                    await callback
                rogue_path.write_text("{}", encoding="utf-8")
                kwargs["on_file_write"](OpenCodeFileWrite(
                    call_id="post-validation-write",
                    path=str(rogue_path),
                    created=True,
                ))
            return OpenCodePromptResult(
                session_id="ses_post_validation",
                message_id=f"msg_{len(calls)}",
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
            patches[3] as update_context_mock,
            patches[4],
            patches[5],
        ):
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="post-session validation correction",
                    prompt="run",
                    directory=tmp_path,
                    allowed_bash_commands=(command,),
                    bash_command_match_mode=match_mode,
                    post_session_validator=validate,
                    post_session_validation_retry_count=1,
                ))

        assert result.status == "success"
        assert result.session_id == "ses_post_validation"
        assert [session_id for _, session_id, _ in calls] == [
            None,
            "ses_post_validation",
        ]
        assert all(commands == (command,) for _, _, commands in calls)
        assert validation_calls == 2
        assert not rogue_path.exists()
        assert "missing required property 'nodes'" in calls[1][0]
        assert "不要求你在 Session 内执行校验命令" in calls[1][0]
        assert acquire_mock.await_count == 1
        assert release_mock.await_args.kwargs["outcome"] == "success"
        final_updates = update_context_mock.await_args_list[-1].args[1]
        assert [
            (event["phase"], event["outcome"], event.get("failure_kind", ""))
            for event in final_updates["session_events"]
        ] == [
            ("business", "failure", "post_session_validation_failed"),
            ("validation_retry", "success", ""),
        ]

    asyncio.run(run())


def test_exhausted_post_session_validation_uses_existing_fresh_retry(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls: list[tuple[str, str | None]] = []
        validation_calls = 0

        def validate() -> str | None:
            nonlocal validation_calls
            validation_calls += 1
            return {
                1: "first failure",
                2: "second failure",
            }.get(validation_calls)

        async def run_prompt(**kwargs):
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            active_session = "ses_first" if len(calls) <= 2 else "ses_fresh"
            if kwargs["session_id"] is None:
                callback = kwargs["on_session_id"](active_session)
                if hasattr(callback, "__await__"):
                    await callback
            return OpenCodePromptResult(
                session_id=active_session,
                message_id=f"msg_{len(calls)}",
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
            patches[3] as update_context_mock,
            patches[4],
            patches[5],
        ):
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="fresh session after post validation",
                    prompt="run",
                    directory=tmp_path,
                    post_session_validator=validate,
                    post_session_validation_retry_count=1,
                    attempt=1,
                ))

        assert result.status == "success"
        assert result.session_id == "ses_fresh"
        assert [session_id for _, session_id in calls] == [None, "ses_first", None]
        assert validation_calls == 3
        assert calls[2][0] == "run"
        assert acquire_mock.await_count == 2
        assert release_mock.await_args_list[0].kwargs["health_outcome"] is None
        final_updates = update_context_mock.await_args_list[-1].args[1]
        assert [
            (event["phase"], event["outcome"], event["session_id"])
            for event in final_updates["session_events"]
        ] == [
            ("business", "failure", "ses_first"),
            ("validation_retry", "failure", "ses_first"),
            ("business", "success", "ses_fresh"),
        ]

    asyncio.run(run())


def test_provider_quota_error_requeues_with_circuit_metadata(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        calls = 0

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                await _notify_model_request_failure(kwargs, "quota")
                raise OpenCodeProviderQuotaError(
                    error_code="InferHub.002002010.429",
                    quota_type="RPM",
                    identity="appId",
                    retry_after_seconds=45,
                )
            callback = kwargs["on_session_id"]("ses_success")
            if hasattr(callback, "__await__"):
                await callback
            return OpenCodePromptResult(
                session_id="ses_success",
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
                    task_name="retry quota",
                    prompt="run",
                    directory=tmp_path,
                    attempt=1,
                ))

        assert result.status == "success"
        assert calls == 2
        first_release = release_mock.await_args_list[0].kwargs
        assert first_release["health_outcome"] == "quota"
        assert first_release["quota_retry_after_seconds"] == 45
        assert first_release["record_completion"] is False
        identity = {("provider/model-low", False, "opencode", "opencode")}
        assert acquire_mock.await_args_list[1].kwargs["avoid_model_identities"] == identity
        budgets = [
            call.kwargs["quota_wait_budget"]
            for call in acquire_mock.await_args_list
        ]
        assert budgets[0] is budgets[1]
        assert budgets[0].remaining_seconds == 300

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
                await _notify_model_request_failure(kwargs, "neutral")
                raise RuntimeError("first session failed")
            raise RuntimeError("final retry failed before session creation")

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1] as acquire_mock,
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
        assert [
            call.kwargs["avoid_model_identities"]
            for call in acquire_mock.await_args_list
        ] == [
            set(),
            {("provider/model-low", False, "opencode", "opencode")},
        ]
        assert [
            call.kwargs["health_outcome"]
            for call in release_mock.await_args_list
        ] == [None, None]
        assert release_mock.await_args_list[-1].kwargs["outcome"] == "failure"
        assert release_mock.await_args_list[-1].kwargs["record_completion"] is True
        final_context_update = update_context_mock.await_args_list[-1].args[1]
        assert final_context_update["serve_session_id"] == "ses_first"
        assert final_context_update["session_attempt"] == 2
        assert final_context_update["failure_kind"] == "execution_error"
        assert final_context_update["failure_reason"] == (
            "final retry failed before session creation"
        )
        assert [
            event["session_id"]
            for event in final_context_update["session_events"]
        ] == ["ses_first", ""]
        assert [
            event["outcome"]
            for event in final_context_update["session_events"]
        ] == ["failure", "failure"]

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
        with patches[0], patches[1], patches[2], patches[3] as update_mock, patches[4], patches[5]:
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
        final_updates = update_mock.await_args_list[-1].args[1]
        assert final_updates["failure_kind"] == "no_json"
        assert [
            (event["session_id"], event["failure_kind"])
            for event in final_updates["session_events"]
        ] == [("ses_1", "no_json"), ("ses_2", "no_json")]
        with pytest.raises(OpenCodeTaskError):
            result.raise_for_status()

    asyncio.run(run())


def test_timeout_uses_fresh_session_retry_budget_for_unclassified_tasks(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        session_ids: list[str | None] = []

        async def run_prompt(**kwargs):
            session_ids.append(kwargs["session_id"])
            callback = kwargs["on_session_id"](f"ses_timeout_{len(session_ids)}")
            if hasattr(callback, "__await__"):
                await callback
            await _notify_model_request_failure(kwargs, "timeout")
            raise asyncio.TimeoutError("slow")

        manager = SimpleNamespace(run_prompt=AsyncMock(side_effect=run_prompt))
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        patches = _service_patches(manager)
        with patches[0], patches[1] as acquire_mock, patches[2] as release_mock, patches[3] as update_mock, patches[4], patches[5]:
            with _task_context(tmp_path):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="timeout",
                    prompt="slow",
                    directory=tmp_path,
                    attempt=2,
                ))

        assert result.status == "timeout"
        assert result.session_id == "ses_timeout_3"
        assert session_ids == [None, None, None]
        assert acquire_mock.await_count == 3
        assert release_mock.await_count == 3
        assert [
            call.kwargs["record_completion"]
            for call in release_mock.await_args_list
        ] == [False, False, True]
        assert [
            call.kwargs["outcome"]
            for call in release_mock.await_args_list
        ] == ["timeout", "timeout", "timeout"]
        assert [
            call.kwargs["health_outcome"]
            for call in release_mock.await_args_list
        ] == ["timeout", "timeout", "timeout"]
        assert [
            call.kwargs["avoid_model_identities"]
            for call in acquire_mock.await_args_list
        ] == [
            set(),
            {("provider/model-low", False, "opencode", "opencode")},
            {("provider/model-low", False, "opencode", "opencode")},
        ]
        assert release_mock.await_args.kwargs["outcome"] == "timeout"
        final_updates = update_mock.await_args_list[-1].args[1]
        assert final_updates["failure_kind"] == "timeout"
        assert final_updates["failure_reason"] == "slow"
        assert [
            event["session_id"] for event in final_updates["session_events"]
        ] == ["ses_timeout_1", "ses_timeout_2", "ses_timeout_3"]
        assert {
            event["failure_kind"] for event in final_updates["session_events"]
        } == {"timeout"}

    asyncio.run(run())


def test_timeout_result_is_set_even_when_lease_finalization_raises(tmp_path):
    async def run():
        manager = SimpleNamespace(run_prompt=AsyncMock(side_effect=asyncio.TimeoutError("deadline expired")))
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "p/m", _source()))
        patches = _service_patches(manager, max_retries=0)
        with patches[0], patches[1], patches[2] as release, patches[3], patches[4], patches[5]:
            release.side_effect = OSError("completion write failed")
            with _task_context(tmp_path):
                handle = service.submit_task(OpenCodeTaskSpec(task_name="timeout finalization", prompt="test", directory=tmp_path))
                result = await asyncio.wait_for(handle.result(), 0.5)
                assert result.status == "timeout"
                assert "deadline expired" in result.error
                assert await asyncio.wait_for(handle.wait_session_id(), 0.5) == ""
                assert handle._record.worker.done()
    asyncio.run(run())


def test_service_deadline_bounds_uncooperative_prompt_and_ignores_late_session(tmp_path, monkeypatch):
    async def run():
        gate = asyncio.Event()
        async def prompt(**kwargs):
            while not gate.is_set():
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    continue
            await kwargs["on_session_id"]("late-session")
            return OpenCodePromptResult(session_id="late-session", message_id="late", text="late", lines=[], model="p/m")
        manager = SimpleNamespace(run_prompt=prompt)
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "p/m", _source()))
        config = _config(max_retries=0)
        config.threat_analysis = SimpleNamespace(model_policy=SimpleNamespace(timeout_seconds=0.03, max_retries=0))
        patches = _service_patches(manager, runtime_config=config)
        monkeypatch.setattr("task_agent.task_service.CLEANUP_TIMEOUT_SECONDS", 0.03)
        try:
            with patches[0], patches[1], patches[2] as release, patches[3], patches[4], patches[5]:
                with _task_context(tmp_path, task_metadata={"task_type": "threat_analysis"}):
                    handle = service.submit_task(OpenCodeTaskSpec(task_name="outer deadline", prompt="test", directory=tmp_path))
                    result = await asyncio.wait_for(handle.result(), 0.5)
                assert result.status == "timeout"
                assert release.await_count == 1
                gate.set()
                await asyncio.sleep(0.03)
                assert handle._record.last_session_id == ""
                assert "late-session" not in service._active_session_tasks
        finally:
            gate.set()
            await asyncio.sleep(0.01)
    asyncio.run(run())


@pytest.mark.parametrize("recover", [True, False])
def test_real_message_timeout_releases_lease_and_publishes_retry_history(tmp_path, monkeypatch, recover):
    import httpx
    import task_agent.serve_client as serve

    async def run():
        sessions = []
        output = []
        manager = serve.OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()
        manager._register_event_state = AsyncMock()

        async def acquire(*args, **kwargs):
            manager._active_sessions += 1
            return "reused"

        async def respond(request):
            path = request.url.path
            if request.method == "POST" and path == "/session":
                session = f"ses_{len(sessions) + 1}"
                sessions.append(session)
                return httpx.Response(200, json={"id": session})
            if path.endswith("/message"):
                if "ses_1" in path or not recover:
                    await asyncio.Future()
                if request.method == "POST":
                    return httpx.Response(200, json={
                        "info": {"id": "msg-2", "sessionID": "ses_2", "role": "assistant"},
                        "parts": [{"type": "text", "text": "recovered"}],
                    })
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[] if path.endswith("/children") else {})

        real_client = httpx.AsyncClient
        transport = httpx.MockTransport(respond)
        monkeypatch.setattr(serve.httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
        monkeypatch.setattr(serve, "_SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.02)
        monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0.001)
        manager._acquire_session = acquire
        config = _config()
        config.threat_analysis = SimpleNamespace(model_policy=SimpleNamespace(
            required_capability="high", timeout_seconds=0.1, max_retries=1,
        ))
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path), "provider/model-low", _source(),
        ))
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[1], patches[2] as release, patches[3] as update, patches[4], patches[5]:
            with _task_context(tmp_path, task_metadata={
                "task_type": "threat_analysis", "standalone_console": True,
            }, on_output=output.append):
                result = await asyncio.wait_for(service.run_task(OpenCodeTaskSpec(
                    task_name="threat deadline", prompt="analyze", directory=tmp_path,
                )), timeout=2)
        assert sessions == ["ses_1", "ses_2"]
        assert result.session_id == "ses_2"
        assert result.status == ("success" if recover else "timeout")
        assert manager._active_sessions == 0
        assert release.await_count == 2
        assert [call.kwargs["record_completion"] for call in release.await_args_list] == [False, True]
        assert release.await_args_list[0].kwargs["health_outcome"] == "timeout"
        events = update.await_args_list[-1].args[1]["session_events"]
        assert [event["session_id"] for event in events] == sessions
        assert [event["outcome"] for event in events] == ["timeout", result.status]
        assert any("RETRY 1/1" in line for line in output)
        assert all(record.status == result.status for record in service._records.values())

    asyncio.run(run())


def test_host_validation_uses_remaining_call_budget_without_model_penalty(tmp_path):
    async def run():
        service = OpenCodeTaskService()
        calls = []
        cancelled = asyncio.Event()

        async def run_prompt(**kwargs):
            session = f"ses_{len(calls) + 1}"
            calls.append(kwargs)
            await kwargs["on_session_id"](session)
            return OpenCodePromptResult(session_id=session, message_id="msg", lines=["ok"], text="ok")

        async def validate():
            if len(calls) == 1:
                try:
                    await asyncio.Future()
                finally:
                    cancelled.set()

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        config = _config()
        config.threat_analysis = SimpleNamespace(model_policy=SimpleNamespace(
            required_capability="high", timeout_seconds=0.05, max_retries=1,
        ))
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[1], patches[2] as release, patches[3], patches[4], patches[5]:
            with _task_context(tmp_path, task_metadata={"task_type": "threat_analysis"}):
                result = await asyncio.wait_for(service.run_task(OpenCodeTaskSpec(
                    task_name="validation deadline", prompt="analyze", directory=tmp_path,
                    post_session_validator=validate,
                )), timeout=1)
        assert result.status == "success"
        assert cancelled.is_set()
        assert len(calls) == 2
        assert release.await_args_list[0].kwargs["outcome"] == "timeout"
        assert release.await_args_list[0].kwargs["health_outcome"] is None

    asyncio.run(run())


def test_same_session_validation_correction_gets_a_new_call_budget(tmp_path):
    async def run():
        service = OpenCodeTaskService()
        session_arguments = []

        async def run_prompt(**kwargs):
            session_arguments.append(kwargs["session_id"])
            await kwargs["on_session_id"]("ses_same")
            await asyncio.sleep(0.03)
            return OpenCodePromptResult(session_id="ses_same", message_id="msg", lines=["ok"], text="ok")

        async def validate():
            await asyncio.sleep(0.03)
            return "repair artifact" if len(session_arguments) == 1 else None

        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        config = _config()
        config.threat_analysis = SimpleNamespace(model_policy=SimpleNamespace(
            required_capability="high", timeout_seconds=0.09, max_retries=0,
        ))
        patches = _service_patches(SimpleNamespace(run_prompt=run_prompt), runtime_config=config)
        with patches[0], patches[1] as acquire, patches[2] as release, patches[3], patches[4], patches[5]:
            with _task_context(tmp_path, task_metadata={"task_type": "threat_analysis"}):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="correction deadline", prompt="analyze", directory=tmp_path,
                    post_session_validator=validate, post_session_validation_retry_count=1,
                ))
        assert result.status == "success"
        assert session_arguments == [None, "ses_same"]
        assert acquire.await_count == release.await_count == 1

    asyncio.run(run())


def test_serve_startup_timeout_is_not_a_model_timeout_or_fresh_session_retry(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        startup_error = OpenCodeServeStartupError(
            "OpenCode serve did not become healthy; "
            "last_health=ConnectTimeout",
            retry_kind="health",
        )
        manager = SimpleNamespace(
            run_prompt=AsyncMock(side_effect=startup_error),
        )
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager)
        with (
            patches[0],
            patches[1] as acquire_mock,
            patches[2] as release_mock,
            patches[3] as update_mock,
            patches[4],
            patches[5],
            _task_context(tmp_path),
        ):
            result = await service.run_task(OpenCodeTaskSpec(
                task_name="serve startup",
                prompt="never sent",
                directory=tmp_path,
                attempt=2,
            ))

        assert result.status == "failure"
        assert manager.run_prompt.await_count == 1
        assert acquire_mock.await_count == 1
        assert release_mock.await_count == 1
        assert release_mock.await_args.kwargs["outcome"] == "failure"
        assert release_mock.await_args.kwargs["health_outcome"] is None
        assert release_mock.await_args.kwargs["record_completion"] is True
        final_updates = update_mock.await_args_list[-1].args[1]
        assert final_updates["failure_kind"] == "serve_startup"
        assert "ConnectTimeout" in final_updates["failure_reason"]
        assert len(final_updates["session_events"]) == 1
        assert final_updates["session_events"][0]["failure_kind"] == "serve_startup"
        assert final_updates["session_events"][0]["session_id"] == ""

    asyncio.run(run())


def test_threat_analysis_policy_defaults_apply_without_caller_timeout(tmp_path: Path) -> None:
    async def run() -> None:
        runtime_config = _config(max_retries=9)
        runtime_config.threat_analysis = SimpleNamespace(
            model_policy=SimpleNamespace(
                required_capability="high",
                timeout_seconds=7200,
                max_retries=2,
            )
        )
        timeouts: list[int] = []

        async def run_prompt(**kwargs):
            timeouts.append(kwargs["timeout"])
            raise asyncio.TimeoutError("threat timeout")

        manager = SimpleNamespace(run_prompt=run_prompt)
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(
            return_value=(_runtime(tmp_path), "provider/model-low", _source())
        )
        patches = _service_patches(manager, runtime_config=runtime_config)
        with patches[0], patches[1] as acquire_mock, patches[2], patches[3], patches[4], patches[5]:
            with _task_context(
                tmp_path,
                task_metadata={"task_type": "threat_analysis"},
            ):
                result = await service.run_task(OpenCodeTaskSpec(
                    task_name="threat",
                    prompt="analyze",
                    directory=tmp_path,
                    required_capability="low",
                ))

        assert result.status == "timeout"
        assert timeouts == [7200, 7200, 7200]
        assert acquire_mock.await_count == 3
        assert all(
            call.kwargs["required_capability"] == "high"
            for call in acquire_mock.await_args_list
        )

    asyncio.run(run())


def test_new_session_and_immediate_continuation_are_serialized(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        first_can_finish = asyncio.Event()
        first_started = asyncio.Event()
        active = 0
        max_active = 0
        calls: list[tuple[str, str | None]] = []
        permissions: list[list[dict[str, str]] | None] = []

        async def run_prompt(**kwargs):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            calls.append((kwargs["prompt"], kwargs["session_id"]))
            permissions.append(kwargs["permissions"])
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
                    task_name="first",
                    prompt="first",
                    directory=tmp_path,
                    file_write_allowlist=(tmp_path / "extra",),
                    attempt=0,
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
        assert permissions == [
            _writable_path_permissions((
                (tmp_path / "work").resolve(),
                (tmp_path / "extra").resolve(),
            )),
            _writable_path_permissions(((tmp_path / "work").resolve(),)),
        ]

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


def test_cancel_execution_only_stops_matching_business_owner(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        queued: dict[str, asyncio.Event] = {
            "scan-a": asyncio.Event(),
            "scan-b": asyncio.Event(),
        }

        async def acquire(*_args, **kwargs):
            record = service._records[kwargs["task_id"]]
            execution_id = record.execution_context.execution_id
            queued[execution_id].set()
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.005)
            return None

        with (
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
            patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
        ):
            with _task_context(
                tmp_path,
                execution_kind="scan",
                execution_id="scan-a",
            ):
                first = service.submit_task(OpenCodeTaskSpec(
                    task_name="scan a",
                    prompt="wait",
                    directory=tmp_path,
                ))
            with _task_context(
                tmp_path,
                execution_kind="scan",
                execution_id="scan-b",
            ):
                second = service.submit_task(OpenCodeTaskSpec(
                    task_name="scan b",
                    prompt="wait",
                    directory=tmp_path,
                ))

            await asyncio.gather(queued["scan-a"].wait(), queued["scan-b"].wait())
            result = await service.cancel_execution("scan", "scan-a", timeout_seconds=1)

            assert result["matched_tasks"] == 1
            assert result["cancelled_tasks"] == 1
            assert result["active_tasks"] == 0
            assert first.status == "cancelled"
            assert second.status == "queued"

            await service.cancel_execution("scan", "scan-b", timeout_seconds=1)

    asyncio.run(run())


def test_old_scan_stop_does_not_cancel_newer_revision(tmp_path: Path) -> None:
    async def run() -> None:
        service = OpenCodeTaskService()
        queued = {8: asyncio.Event(), 9: asyncio.Event()}

        async def acquire(*_args, **kwargs):
            record = service._records[kwargs["task_id"]]
            queued[record.execution_context.task_metadata["execution_revision"]].set()
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.005)
            return None

        with (
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
            patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
        ):
            tasks = {}
            for revision in queued:
                with _task_context(
                    tmp_path, execution_kind="scan", execution_id="same-scan",
                    task_metadata={"execution_revision": revision},
                ):
                    tasks[revision] = service.submit_task(OpenCodeTaskSpec(
                        task_name=f"revision {revision}", prompt="wait", directory=tmp_path,
                    ))
            await asyncio.gather(*(event.wait() for event in queued.values()))
            try:
                result = await service.cancel_execution(
                    "scan", "same-scan", execution_revision=8, timeout_seconds=1,
                )
                assert result["matched_tasks"] == 1 and result["active_tasks"] == 0
                assert tasks[8].status == "cancelled"
                assert tasks[9].status == "queued"
            finally:
                await service.cancel_execution("scan", "same-scan", timeout_seconds=1)

    asyncio.run(run())


def test_run_sync_component_cancellation_unwinds_owner_loop_task() -> None:
    async def run() -> None:
        owner_started = asyncio.Event()
        owner_cancelled = asyncio.Event()

        async def fake_local(**_kwargs):
            owner_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                owner_cancelled.set()
                raise

        def component() -> OpenCodeResult:
            return asyncio.run(run_opencode_task(
                task_name="bridge cancellation",
                task_type="threat_analysis",
                prompt="wait",
                required_capability="high",
            ))

        with patch("task_agent.api._run_opencode_task_local", new=fake_local):
            caller = asyncio.create_task(run_sync_component(component))
            await asyncio.wait_for(owner_started.wait(), timeout=1)
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller
            await asyncio.wait_for(owner_cancelled.wait(), timeout=1)

    asyncio.run(run())
