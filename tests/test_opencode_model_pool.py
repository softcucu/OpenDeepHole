import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest

import backend.opencode.model_pool as model_pool_module
from backend.opencode.model_pool import (
    NoAvailableModelError,
    acquire_model_lease,
    clear_planned_task,
    clear_planned_tasks,
    model_options,
    model_pool_snapshot,
    register_planned_task,
    release_model_lease,
    refresh_configured_model_pool,
    total_model_capacity,
    update_model_lease_context,
    wait_for_model_pool_update,
)


@pytest.fixture(autouse=True)
def _reset_model_pool():
    """Each test runs in its own event loop via asyncio.run(), but the pool's
    Condition binds to the first loop that waits on it — recreate it per test."""
    model_pool_module._condition = asyncio.Condition()
    model_pool_module._running_by_model.clear()
    model_pool_module._global_running = 0
    model_pool_module._last_used.clear()
    model_pool_module._stats_by_scope.clear()
    model_pool_module._global_stats_by_model.clear()
    model_pool_module._options_by_id.clear()
    model_pool_module._scope_updated_at.clear()
    model_pool_module._global_updated_at = ""
    model_pool_module._active_tasks.clear()
    model_pool_module._completed_tasks_by_scope.clear()
    model_pool_module._peak_total_tasks_by_scope.clear()
    model_pool_module._pending_requests.clear()
    model_pool_module._planned_tasks.clear()
    model_pool_module._planned_task_ids_by_key.clear()
    model_pool_module._pending_sequence = 0
    model_pool_module._planned_sequence = 0
    yield


def test_model_options_empty_pool_does_not_fall_back_to_legacy_model() -> None:
    cfg = SimpleNamespace(tool="opencode", executable="opencode", model="default-model", models=[])

    options = model_options(cfg, global_concurrency=3)

    assert options == []


@pytest.mark.parametrize(
    "models",
    [
        [{"id": "disabled", "model": "disabled-model", "enabled": False}],
        [{"id": "empty", "model": "", "enabled": True}],
        [{"id": "missing", "enabled": True}],
    ],
)
def test_model_options_excludes_disabled_and_invalid_empty_models(models: list[dict]) -> None:
    cfg = SimpleNamespace(
        model="legacy-claude-model",
        models=models,
    )

    assert model_options(cfg, global_concurrency=3) == []


def test_model_options_keeps_explicit_default_model() -> None:
    cfg = SimpleNamespace(
        model="legacy-claude-model",
        models=[
            {
                "model": "ignored-explicit-name",
                "use_default_model": True,
                "enabled": True,
                "max_concurrency": 2,
            }
        ],
    )

    options = model_options(cfg, global_concurrency=3)

    assert len(options) == 1
    assert options[0].id == "default"
    assert options[0].model == ""
    assert options[0].use_default_model is True
    assert options[0].max_concurrency == 2


def test_model_options_normalizes_enabled_models() -> None:
    cfg = SimpleNamespace(
        models=[
            {
                "id": "fast",
                "model": "fast-model",
                "use_default_model": True,
                "capability": "low",
                "weight": 2,
                "max_concurrency": 2,
                "time_windows": [{"start": "09:00", "end": "18:00"}],
            },
            {"id": "off", "model": "off-model", "enabled": False},
        ],
    )

    options = model_options(cfg, global_concurrency=4)

    assert [option.id for option in options] == ["fast"]
    assert options[0].model == ""
    assert options[0].use_default_model is True
    assert options[0].capability == "low"
    assert options[0].weight == 2
    assert options[0].max_concurrency == 2
    assert len(options[0].time_windows) == 1
    assert options[0].time_windows[0].weekdays == (1, 2, 3, 4, 5, 6, 7)
    assert options[0].time_windows[0].start == 540
    assert options[0].time_windows[0].end == 1080


def _scheduled_option(time_windows: list[dict]) -> model_pool_module.ModelOption:
    cfg = SimpleNamespace(models=[{
        "id": "scheduled",
        "model": "scheduled-model",
        "time_windows": time_windows,
    }])
    return model_options(cfg, global_concurrency=1)[0]


def test_time_window_honors_selected_weekday_and_boundaries() -> None:
    option = _scheduled_option([{
        "weekdays": [1],
        "start": "09:00",
        "end": "18:00",
    }])

    assert model_pool_module._option_available_now(option, datetime(2024, 1, 1, 9, 0))
    assert model_pool_module._option_available_now(option, datetime(2024, 1, 1, 17, 59))
    assert not model_pool_module._option_available_now(option, datetime(2024, 1, 1, 18, 0))
    assert not model_pool_module._option_available_now(option, datetime(2024, 1, 2, 10, 0))


def test_overnight_time_window_uses_current_weekday() -> None:
    option = _scheduled_option([{
        "weekdays": [1, 2, 3, 4, 5, 6],
        "start": "22:00",
        "end": "06:00",
    }])

    # Monday early morning and late evening are both inside Monday's window.
    assert model_pool_module._option_available_now(option, datetime(2024, 1, 1, 1, 0))
    assert model_pool_module._option_available_now(option, datetime(2024, 1, 1, 23, 0))
    # Sunday is not selected, even though Saturday's configured range crosses midnight.
    assert not model_pool_module._option_available_now(option, datetime(2024, 1, 7, 1, 0))


def test_multiple_time_windows_are_combined_as_union() -> None:
    option = _scheduled_option([
        {"weekdays": [1], "start": "09:00", "end": "12:00"},
        {"weekdays": [7], "start": "14:00", "end": "18:00"},
    ])

    assert model_pool_module._option_available_now(option, datetime(2024, 1, 1, 10, 0))
    assert model_pool_module._option_available_now(option, datetime(2024, 1, 7, 16, 0))
    assert not model_pool_module._option_available_now(option, datetime(2024, 1, 1, 13, 0))


def test_model_pool_snapshot_includes_time_window_weekdays() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "scheduled",
            "model": "scheduled-model",
            "time_windows": [{"weekdays": [1, 3, 5], "start": "09:00", "end": "18:00"}],
        }])

        await refresh_configured_model_pool(cfg, global_concurrency=1)
        assert model_pool_snapshot()["models"][0]["time_windows"] == [{
            "weekdays": [1, 3, 5],
            "start": "09:00",
            "end": "18:00",
        }]

    asyncio.run(run())


def test_wait_for_model_pool_update_follows_scope_marker() -> None:
    async def run() -> None:
        unchanged = await wait_for_model_pool_update(
            "scan-1",
            last_updated_at="",
            timeout=0.001,
        )
        assert unchanged == ""

        waiter = asyncio.create_task(
            wait_for_model_pool_update(
                "scan-1",
                last_updated_at="",
                timeout=1.0,
            )
        )
        await asyncio.sleep(0)
        await register_planned_task("scan-1", {"task_type": "audit"})
        updated_at = await waiter

        assert updated_at
        assert updated_at == model_pool_snapshot("scan-1")["updated_at"]

    asyncio.run(run())


def test_acquire_model_lease_filters_by_capability_and_releases() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 3, "max_concurrency": 2},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
            ],
        )

        lease = await acquire_model_lease(cfg, global_concurrency=2, required_capability="high")
        try:
            assert lease is not None
            assert lease.option.id == "deep"
            assert lease.running == 1
            assert lease.global_running == 1
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_immediate_lease_does_not_count_as_queued() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        lease = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            stats_scope_id="scope-immediate",
        )
        try:
            snapshot = model_pool_snapshot("scope-immediate")
            assert snapshot["global_running"] == 1
            assert snapshot["global_queued"] == 0
            assert snapshot["models"][0]["running"] == 1
            assert snapshot["models"][0]["queued"] == 0
        finally:
            await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_acquire_without_models_fails_fast_and_clears_planned_task() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(model="legacy-claude-model", models=[])
        scope = "scope-no-model"
        planned_id = await register_planned_task(
            scope,
            {"task_type": "audit", "file": "src/no-model.c"},
            task_key="audit:no-model",
        )

        with pytest.raises(NoAvailableModelError) as exc_info:
            await asyncio.wait_for(
                acquire_model_lease(
                    cfg,
                    global_concurrency=1,
                    stats_scope_id=scope,
                    task_context={
                        "planned_task_id": planned_id,
                        "task_type": "audit",
                        "file": "src/no-model.c",
                        "prompt": "audit without a configured model",
                    },
                ),
                timeout=0.1,
            )

        assert str(exc_info.value) == (
            "模型池没有已启用的模型；请先添加并启用模型。"
            "如需使用 CLI 默认模型，请显式添加“默认模型”。"
        )
        snapshot = model_pool_snapshot(scope)
        assert snapshot["global_queued"] == 0
        assert snapshot["queued_tasks"] == []
        assert snapshot["planned_tasks"] == []
        assert snapshot["completed_task_count"] == 1
        completed = snapshot["completed_tasks"][0]
        assert completed["outcome"] == "failure"
        assert completed["model_id"] == ""
        assert completed["model"] == ""
        assert completed["failure_reason"] == str(exc_info.value)
        assert completed["task_type"] == "audit"
        assert completed["file"] == "src/no-model.c"
        assert completed["prompt"] == "audit without a configured model"
        assert completed["prompt_length"] == len(completed["prompt"])

    asyncio.run(run())


def test_queued_lease_fails_when_model_pool_is_cleared() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        scope = "scope-dynamically-cleared"
        first = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            stats_scope_id=scope,
        )
        planned_id = await register_planned_task(
            scope,
            {"task_type": "threat_audit"},
            task_key="threat:queued",
        )
        queued_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                global_concurrency=1,
                stats_scope_id=scope,
                task_context={
                    "planned_task_id": planned_id,
                    "task_type": "threat_audit",
                    "file": "src/dynamic.c",
                },
            )
        )
        try:
            await asyncio.sleep(0.05)
            queued_snapshot = model_pool_snapshot(scope)
            assert queued_snapshot["global_queued"] == 1
            assert queued_snapshot["planned_tasks"] == []

            cfg.models.clear()
            await refresh_configured_model_pool(cfg, global_concurrency=1)

            with pytest.raises(NoAvailableModelError):
                await asyncio.wait_for(queued_task, timeout=0.2)
            failed_snapshot = model_pool_snapshot(scope)
            assert failed_snapshot["global_queued"] == 0
            assert failed_snapshot["queued_tasks"] == []
            assert failed_snapshot["planned_tasks"] == []
            assert failed_snapshot["completed_task_count"] == 1
            assert failed_snapshot["completed_tasks"][0]["outcome"] == "failure"
            assert failed_snapshot["completed_tasks"][0]["task_type"] == "threat_audit"
            historical = {item["id"]: item for item in failed_snapshot["models"]}
            assert historical["deep"]["enabled"] is False
            assert historical["deep"]["available"] is False
        finally:
            if not queued_task.done():
                queued_task.cancel()
            await release_model_lease(first, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_planned_task_snapshot_dedupes_and_is_consumed_by_lease() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        scope = "scope-planned"

        planned_id = await register_planned_task(
            scope,
            {"task_type": "audit", "checker": "overflow", "file": "src/a.c", "line": 42},
            task_key="audit:42",
        )
        duplicate_id = await register_planned_task(
            scope,
            {"task_type": "audit", "checker": "ignored"},
            task_key="audit:42",
        )
        assert duplicate_id == planned_id

        planned_snapshot = model_pool_snapshot(scope)
        assert planned_snapshot["planned_tasks"] == [
            {
                "planned_task_id": planned_id,
                "scope_id": scope,
                "planned_at": planned_snapshot["planned_tasks"][0]["planned_at"],
                "task_type": "audit",
                "checker": "overflow",
                "file": "src/a.c",
                "line": 42,
            }
        ]

        lease = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            stats_scope_id=scope,
            task_context={"planned_task_id": planned_id, "task_type": "audit", "file": "src/a.c", "line": 42},
        )
        try:
            active_snapshot = model_pool_snapshot(scope)
            assert active_snapshot["planned_tasks"] == []
            active_tasks = active_snapshot["models"][0]["active_tasks"]
            assert active_tasks[0]["task_type"] == "audit"
            assert active_tasks[0]["file"] == "src/a.c"
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_can_clear_planned_tasks_before_lease_request() -> None:
    async def run():
        first = await register_planned_task("scan-a", {"task_type": "fp_review"}, task_key="fp:1")
        await register_planned_task("scan-a", {"task_type": "audit"}, task_key="audit:1")
        await register_planned_task("scan-b", {"task_type": "threat_analysis"}, task_key="threat")

        await clear_planned_task(first)
        assert [task["task_type"] for task in model_pool_snapshot("scan-a")["planned_tasks"]] == ["audit"]

        await register_planned_task("scan-a", {"task_type": "fp_review"}, task_key="fp:2")
        await clear_planned_tasks("scan-a", {"audit"})
        assert [task["task_type"] for task in model_pool_snapshot("scan-a")["planned_tasks"]] == ["fp_review"]

        await clear_planned_tasks("scan-a")
        assert model_pool_snapshot("scan-a")["planned_tasks"] == []
        assert [task["task_type"] for task in model_pool_snapshot("scan-b")["planned_tasks"]] == ["threat_analysis"]

    asyncio.run(run())


def test_acquire_model_lease_prefers_weighted_fast_model_for_any_capability() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 3, "max_concurrency": 3},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 3},
            ],
        )

        first = await acquire_model_lease(cfg, global_concurrency=3, required_capability="any")
        second = await acquire_model_lease(cfg, global_concurrency=3, required_capability="any")
        try:
            assert first is not None
            assert second is not None
            assert first.option.id == "fast"
            assert second.option.id == "deep"
        finally:
            await release_model_lease(second)
            await release_model_lease(first)

    asyncio.run(run())


def test_model_pool_snapshot_tracks_scope_queue_and_outcomes() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 2, "max_concurrency": 1},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
            ],
        )
        scope = "test-scope-model-pool-stats"

        # Both leases require "high", so only "deep" (max_concurrency=1) is
        # eligible and the second one must queue behind the first.
        first = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            stats_scope_id=scope,
        )
        second = None
        second_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                global_concurrency=1,
                required_capability="high",
                stats_scope_id=scope,
                task_context={
                    "task_type": "audit",
                    "prompt": "queued audit prompt",
                    "prompt_length": len("queued audit prompt"),
                },
            )
        )
        try:
            await asyncio.sleep(0.05)
            queued_snapshot = model_pool_snapshot(scope)
            assert queued_snapshot["global_running"] == 1
            assert queued_snapshot["global_queued"] == 1
            assert len(queued_snapshot["queued_tasks"]) == 1
            assert queued_snapshot["queued_tasks"][0]["prompt"] == "queued audit prompt"
            assert queued_snapshot["queued_tasks"][0]["prompt_length"] == len("queued audit prompt")
            assert all(item["queued"] == 0 for item in queued_snapshot["models"])

            assert first is not None
            await release_model_lease(first, outcome="success", duration_seconds=2.0)
            first = None
            second = await asyncio.wait_for(second_task, timeout=1)
            assert second is not None
            await release_model_lease(second, outcome="timeout", duration_seconds=4.0)
            second = None

            third = await acquire_model_lease(
                cfg,
                global_concurrency=1,
                required_capability="any",
                stats_scope_id=scope,
            )
            assert third is not None
            assert third.option.id == "fast"
            await release_model_lease(third, outcome="success", duration_seconds=2.0)

            snapshot = model_pool_snapshot(scope)
            by_id = {item["id"]: item for item in snapshot["models"]}
            assert snapshot["global_queued"] == 0
            assert snapshot["queued_tasks"] == []
            assert by_id["fast"]["total"] == 1
            assert by_id["fast"]["success"] == 1
            assert by_id["fast"]["avg_duration_seconds"] == 2.0
            assert by_id["deep"]["total"] == 2
            assert by_id["deep"]["success"] == 1
            assert by_id["deep"]["timeout"] == 1
            assert by_id["deep"]["avg_duration_seconds"] == 3.0
        finally:
            if not second_task.done():
                second_task.cancel()
            await release_model_lease(first)
            await release_model_lease(second)

    asyncio.run(run())


def test_model_pool_snapshot_persists_completed_task_prompt_for_all_outcomes() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        scope = "scan-completed-history"
        outcomes = ("success", "failure", "timeout", "cancelled")
        for index, outcome in enumerate(outcomes):
            prompt = f"full {outcome} prompt"
            session_id = f"ses_{outcome}"
            lease = await acquire_model_lease(
                cfg,
                global_concurrency=1,
                required_capability="high",
                stats_scope_id=scope,
                task_context={
                    "task_type": "threat_audit",
                    "file": f"src/{index}.c",
                    "prompt": prompt,
                },
            )
            await update_model_lease_context(
                lease,
                {"serve_session_id": session_id},
            )
            await release_model_lease(lease, outcome=outcome, duration_seconds=1.5)

        snapshot = model_pool_snapshot(scope)
        assert snapshot["total_tasks"] == len(outcomes)
        assert snapshot["completed_task_count"] == len(outcomes)
        assert len(snapshot["completed_tasks"]) == len(outcomes)
        for completed, outcome in zip(snapshot["completed_tasks"], outcomes, strict=True):
            prompt = f"full {outcome} prompt"
            assert completed["task_type"] == "threat_audit"
            assert completed["outcome"] == outcome
            assert completed["duration_seconds"] == 1.5
            assert completed["prompt"] == prompt
            assert completed["prompt_length"] == len(prompt)
            assert completed["serve_session_id"] == f"ses_{outcome}"

    asyncio.run(run())


def test_fresh_session_retry_records_only_one_terminal_completion() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(
            models=[{
                "id": "retry-model",
                "model": "provider/retry-model",
                "capability": "low",
                "max_concurrency": 1,
            }],
        )
        scope = "scan-retry-history"
        task_id = "logical-task"
        first = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            stats_scope_id=scope,
            task_id=task_id,
            task_context={"task_type": "audit", "session_attempt": 1},
        )
        await release_model_lease(
            first,
            duration_seconds=1.0,
            record_completion=False,
        )
        between = model_pool_snapshot(scope)
        assert between["completed_task_count"] == 0

        second = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            stats_scope_id=scope,
            task_id=task_id,
            task_context={"task_type": "audit", "session_attempt": 2},
        )
        await release_model_lease(
            second,
            outcome="success",
            duration_seconds=2.0,
        )
        final = model_pool_snapshot(scope)
        assert final["total_tasks"] == 1
        assert final["models"][0]["total"] == 2
        assert final["completed_task_count"] == 1
        assert final["completed_tasks"][0]["task_id"] == task_id
        assert final["completed_tasks"][0]["session_attempt"] == 2
        assert final["completed_tasks"][0]["outcome"] == "success"

    asyncio.run(run())


def test_waiting_lease_does_not_refresh_snapshot_timestamp() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        scope = "scope-stable-wait"
        cancel_event = asyncio.Event()

        first = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            stats_scope_id=scope,
        )
        second_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                global_concurrency=1,
                required_capability="high",
                stats_scope_id=scope,
                cancel_event=cancel_event,
            )
        )
        try:
            await asyncio.sleep(0.05)
            first_snapshot = model_pool_snapshot(scope)
            first_global_snapshot = model_pool_snapshot()
            assert first_snapshot["global_queued"] == 1
            assert first_snapshot["queued_tasks"][0]["scope_id"] == scope

            await asyncio.sleep(0.35)
            later_snapshot = model_pool_snapshot(scope)
            later_global_snapshot = model_pool_snapshot()

            assert later_snapshot["global_queued"] == 1
            assert later_snapshot["updated_at"] == first_snapshot["updated_at"]
            assert later_global_snapshot["updated_at"] == first_global_snapshot["updated_at"]
        finally:
            cancel_event.set()
            async with model_pool_module._condition:
                model_pool_module._condition.notify_all()
            if not second_task.done():
                result = await asyncio.wait_for(second_task, timeout=1)
                assert result is None
            assert model_pool_snapshot(scope)["global_queued"] == 0
            assert model_pool_snapshot(scope)["queued_tasks"] == []
            await release_model_lease(first)

    asyncio.run(run())


def test_global_concurrency_is_hard_gate_across_models() -> None:
    """The top-level concurrency is a hard cap over all model-pool leases."""

    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
                {"id": "fast", "model": "fast-model", "capability": "medium", "weight": 1, "max_concurrency": 1},
            ],
        )

        # Simulates an FP review holding the high model in one scan scope...
        fp_lease = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            prefer_high=True,
            stats_scope_id="scope-fp",
        )
        try:
            assert fp_lease is not None
            assert fp_lease.option.id == "deep"
            # ...while a normal scan in another scope must queue behind the
            # global limit even though the medium model itself is idle.
            scan_task = asyncio.create_task(
                acquire_model_lease(
                    cfg,
                    global_concurrency=1,
                    required_capability="any",
                    stats_scope_id="scope-scan",
                )
            )
            await asyncio.sleep(0.05)
            assert not scan_task.done()
            await release_model_lease(fp_lease, outcome="success", duration_seconds=0.1)
            fp_lease = None
            scan_lease = await asyncio.wait_for(scan_task, timeout=1)
            assert scan_lease is not None
            await release_model_lease(scan_lease, outcome="success", duration_seconds=0.1)
        finally:
            await release_model_lease(fp_lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_queued_task_falls_back_to_other_free_model() -> None:
    """A queued task must not be pinned to a model before it starts running."""

    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "a", "model": "model-a", "capability": "high", "weight": 1, "max_concurrency": 1},
                {"id": "b", "model": "model-b", "capability": "high", "weight": 1, "max_concurrency": 1},
            ],
        )
        scope = "test-scope-queue-fallback"

        lease_a = await acquire_model_lease(
            cfg, global_concurrency=2, required_capability="any", stats_scope_id=scope
        )
        lease_b = await acquire_model_lease(
            cfg, global_concurrency=2, required_capability="any", stats_scope_id=scope
        )
        assert lease_a is not None and lease_b is not None
        held = {lease_a.option.id: lease_a, lease_b.option.id: lease_b}
        assert set(held) == {"a", "b"}

        third_task = asyncio.create_task(
            acquire_model_lease(
                cfg, global_concurrency=2, required_capability="any", stats_scope_id=scope
            )
        )
        try:
            await asyncio.sleep(0.05)
            snapshot = model_pool_snapshot(scope)
            assert snapshot["global_queued"] == 1
            assert len(snapshot["queued_tasks"]) == 1
            assert all(item["queued"] == 0 for item in snapshot["models"])

            released_id = next(iter(held))
            await release_model_lease(held.pop(released_id), outcome="success", duration_seconds=0.1)
            third = await asyncio.wait_for(third_task, timeout=1)
            assert third is not None
            assert third.option.id == released_id
            await release_model_lease(third, outcome="success", duration_seconds=0.1)
        finally:
            if not third_task.done():
                third_task.cancel()
            for lease in held.values():
                await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_global_queue_skips_blocked_capability_head() -> None:
    """A high-only waiter must not keep lower-capability models idle."""

    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 1, "max_concurrency": 1},
            ],
        )
        scope = "test-scope-capability-skip"

        deep = await acquire_model_lease(
            cfg, global_concurrency=2, required_capability="high", stats_scope_id=scope
        )
        high_waiter = asyncio.create_task(
            acquire_model_lease(
                cfg,
                global_concurrency=2,
                required_capability="high",
                stats_scope_id=scope,
                task_context={"task_type": "threat_analysis"},
            )
        )
        try:
            await asyncio.sleep(0.05)
            queued = model_pool_snapshot(scope)
            assert queued["global_queued"] == 1
            assert queued["queued_tasks"][0]["task_type"] == "threat_analysis"

            any_task = asyncio.create_task(
                acquire_model_lease(
                    cfg,
                    global_concurrency=2,
                    required_capability="any",
                    stats_scope_id=scope,
                    task_context={"task_type": "audit", "checker": "npd"},
                )
            )
            any_lease = await asyncio.wait_for(any_task, timeout=1)
            assert any_lease is not None
            assert any_lease.option.id == "fast"
            still_queued = model_pool_snapshot(scope)
            assert still_queued["global_queued"] == 1
            assert still_queued["queued_tasks"][0]["task_type"] == "threat_analysis"

            await release_model_lease(any_lease, outcome="success", duration_seconds=0.1)
            await release_model_lease(deep, outcome="success", duration_seconds=0.1)
            deep = None
            high_lease = await asyncio.wait_for(high_waiter, timeout=1)
            assert high_lease is not None
            assert high_lease.option.id == "deep"
            await release_model_lease(high_lease, outcome="success", duration_seconds=0.1)
        finally:
            if not high_waiter.done():
                high_waiter.cancel()
            await release_model_lease(deep, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_planned_order_blocks_later_same_capability_request() -> None:
    """Planned audit order is the FIFO boundary even if workers request out of order."""

    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "a", "model": "model-a", "capability": "low", "weight": 1, "max_concurrency": 1},
                {"id": "b", "model": "model-b", "capability": "low", "weight": 1, "max_concurrency": 1},
            ],
        )
        scope = "test-scope-planned-audit-order"
        group = f"{scope}:audit"
        first_id = await register_planned_task(
            scope,
            {
                "task_type": "audit",
                "audit_index": 0,
                "queue_group": group,
                "required_capability": "any",
            },
            task_key="audit:0",
        )
        second_id = await register_planned_task(
            scope,
            {
                "task_type": "audit",
                "audit_index": 1,
                "queue_group": group,
                "required_capability": "any",
            },
            task_key="audit:1",
        )
        second_cancel = asyncio.Event()
        second = None
        first = None
        second_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                global_concurrency=2,
                required_capability="any",
                stats_scope_id=scope,
                cancel_event=second_cancel,
                task_context={
                    "planned_task_id": second_id,
                    "task_type": "audit",
                    "audit_index": 1,
                },
            )
        )
        try:
            await asyncio.sleep(0.05)
            assert not second_task.done()
            snapshot = model_pool_snapshot(scope)
            assert [task["audit_index"] for task in snapshot["queued_tasks"]] == [1]
            assert [task["audit_index"] for task in snapshot["planned_tasks"]] == [0]

            first = await acquire_model_lease(
                cfg,
                global_concurrency=2,
                required_capability="any",
                stats_scope_id=scope,
                task_context={
                    "planned_task_id": first_id,
                    "task_type": "audit",
                    "audit_index": 0,
                },
            )
            assert first is not None
            second = await asyncio.wait_for(second_task, timeout=1)
            assert second is not None
            active_indexes = sorted(
                task["audit_index"]
                for model in model_pool_snapshot(scope)["models"]
                for task in model["active_tasks"]
            )
            assert active_indexes == [0, 1]
        finally:
            if not second_task.done():
                second_cancel.set()
                async with model_pool_module._condition:
                    model_pool_module._condition.notify_all()
                second = await asyncio.wait_for(second_task, timeout=1)
            await release_model_lease(second, outcome="success", duration_seconds=0.1)
            await release_model_lease(first, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_planned_order_allows_later_task_when_earlier_cannot_use_free_model() -> None:
    """A high-only planned head must not block an any-capability task from a free low model."""

    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 1, "max_concurrency": 1},
            ],
        )
        scope = "test-scope-planned-capability-skip"
        group = f"{scope}:audit"
        deep = await acquire_model_lease(
            cfg,
            global_concurrency=2,
            required_capability="high",
            stats_scope_id=scope,
        )
        high_id = await register_planned_task(
            scope,
            {
                "task_type": "audit",
                "audit_index": 0,
                "queue_group": group,
                "required_capability": "high",
            },
            task_key="audit:0",
        )
        low_id = await register_planned_task(
            scope,
            {
                "task_type": "audit",
                "audit_index": 1,
                "queue_group": group,
                "required_capability": "any",
            },
            task_key="audit:1",
        )
        low = None
        try:
            assert deep is not None
            low = await asyncio.wait_for(
                acquire_model_lease(
                    cfg,
                    global_concurrency=2,
                    required_capability="any",
                    stats_scope_id=scope,
                    task_context={
                        "planned_task_id": low_id,
                        "task_type": "audit",
                        "audit_index": 1,
                    },
                ),
                timeout=1,
            )
            assert low is not None
            assert low.option.id == "fast"
            assert [task["audit_index"] for task in model_pool_snapshot(scope)["planned_tasks"]] == [0]
        finally:
            await clear_planned_task(high_id)
            await release_model_lease(low, outcome="success", duration_seconds=0.1)
            await release_model_lease(deep, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_total_model_capacity_honors_active_time_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = SimpleNamespace(
        models=[
            {"id": "day", "model": "day-model", "capability": "low", "max_concurrency": 3},
            {"id": "night", "model": "night-model", "capability": "high", "max_concurrency": 3},
        ],
    )
    monkeypatch.setattr(
        model_pool_module,
        "_option_available_now",
        lambda option, now=None: option.id == "day",
    )

    assert total_model_capacity(cfg, global_concurrency=2, required_capability="any") == 2
    # No active model satisfies the high requirement; capacity still returns a
    # single worker so the task can queue until a matching time window opens.
    assert total_model_capacity(cfg, global_concurrency=2, required_capability="high") == 1


def test_acquire_queues_when_matching_model_is_outside_time_window(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "day", "model": "day-model", "capability": "low", "max_concurrency": 1},
                {"id": "night", "model": "night-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        active = {"day"}

        def available(option, now=None):
            return option.id in active

        monkeypatch.setattr(model_pool_module, "_option_available_now", available)
        task = asyncio.create_task(acquire_model_lease(cfg, global_concurrency=1, required_capability="high"))
        await asyncio.sleep(0.05)
        assert not task.done()
        active.add("night")
        async with model_pool_module._condition:
            model_pool_module._condition.notify_all()
        lease = await asyncio.wait_for(task, timeout=1)
        assert lease is not None
        assert lease.option.id == "night"
        await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_refresh_configured_model_pool_updates_snapshot_and_wakes_waiters() -> None:
    async def run():
        initial = SimpleNamespace(
            models=[
                {"id": "day", "model": "day-model", "capability": "low", "max_concurrency": 1},
            ],
        )
        updated = SimpleNamespace(
            models=[
                {"id": "day", "model": "day-model-v2", "capability": "medium", "max_concurrency": 2},
                {"id": "night", "model": "night-model", "capability": "high", "max_concurrency": 1},
            ],
        )

        await refresh_configured_model_pool(initial, global_concurrency=1)
        before = {item["id"]: item for item in model_pool_snapshot()["models"]}
        assert before["day"]["model"] == "day-model"

        await refresh_configured_model_pool(updated, global_concurrency=3)
        after = {item["id"]: item for item in model_pool_snapshot()["models"]}
        assert after["day"]["model"] == "day-model-v2"
        assert after["day"]["capability"] == "medium"
        assert after["day"]["max_concurrency"] == 2
        assert after["night"]["model"] == "night-model"

    asyncio.run(run())


def test_model_pool_snapshot_includes_active_task_context() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        lease = await acquire_model_lease(
            cfg,
            global_concurrency=1,
            required_capability="high",
            stats_scope_id="scan-active",
            task_context={
                "task_type": "audit",
                "checker": "npd",
                "file": "src/a.c",
                "line": 42,
                "prompt": "active audit prompt",
                "prompt_length": len("active audit prompt"),
            },
        )
        try:
            snapshot = model_pool_snapshot("scan-active")
            model = snapshot["models"][0]
            assert model["running"] == 1
            assert model["active_tasks"][0]["task_type"] == "audit"
            assert model["active_tasks"][0]["checker"] == "npd"
            assert model["active_tasks"][0]["file"] == "src/a.c"
            assert model["active_tasks"][0]["line"] == 42
            assert model["active_tasks"][0]["prompt"] == "active audit prompt"
            assert model["active_tasks"][0]["prompt_length"] == len("active audit prompt")
            await update_model_lease_context(lease, {"serve_session_id": "ses_test"})
            snapshot = model_pool_snapshot("scan-active")
            model = snapshot["models"][0]
            assert model["active_tasks"][0]["serve_session_id"] == "ses_test"
        finally:
            await release_model_lease(lease, outcome="success", duration_seconds=1.0)
        snapshot = model_pool_snapshot("scan-active")
        assert snapshot["completed_tasks"][0]["serve_session_id"] == "ses_test"

    asyncio.run(run())


def test_priority_queue_runs_higher_priority_before_earlier_lower_priority() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "only", "model": "only-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        occupied = await acquire_model_lease(cfg, global_concurrency=1)
        low_task = asyncio.create_task(acquire_model_lease(
            cfg,
            global_concurrency=1,
            task_id="task-low",
            priority=10,
            strict_capability=True,
            wait_when_unavailable=True,
        ))
        await asyncio.sleep(0.02)
        high_task = asyncio.create_task(acquire_model_lease(
            cfg,
            global_concurrency=1,
            task_id="task-high",
            priority=90,
            strict_capability=True,
            wait_when_unavailable=True,
        ))
        await asyncio.sleep(0.02)
        queued = model_pool_snapshot()["queued_tasks"]
        assert [item["task_id"] for item in queued] == ["task-high", "task-low"]
        assert [item["priority"] for item in queued] == [90, 10]

        await release_model_lease(occupied, outcome="success", duration_seconds=0.1)
        high = await asyncio.wait_for(high_task, timeout=1)
        assert high is not None and high.task_id == "task-high"
        assert not low_task.done()
        await release_model_lease(high, outcome="success", duration_seconds=0.1)
        low = await asyncio.wait_for(low_task, timeout=1)
        assert low is not None and low.task_id == "task-low"
        await release_model_lease(low, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_strict_capability_uses_lowest_sufficient_model_without_downgrade() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "low", "model": "low-model", "capability": "low", "max_concurrency": 1},
                {"id": "medium", "model": "medium-model", "capability": "medium", "max_concurrency": 1},
                {"id": "high", "model": "high-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        leases = []
        for required, expected in (("low", "low"), ("medium", "medium"), ("high", "high")):
            lease = await acquire_model_lease(
                cfg,
                global_concurrency=3,
                required_capability=required,
                strict_capability=True,
                prefer_lowest_capability=True,
                wait_when_unavailable=True,
            )
            assert lease is not None
            assert lease.option.id == expected
            leases.append(lease)
        for lease in leases:
            await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_waiting_strict_task_is_redispatched_after_model_config_change() -> None:
    async def run():
        current = {
            "config": SimpleNamespace(
                models=[
                    {"id": "low", "model": "low-model", "capability": "low", "max_concurrency": 1},
                ],
            )
        }
        task = asyncio.create_task(acquire_model_lease(
            lambda: current["config"],
            global_concurrency=1,
            required_capability="high",
            task_id="strict-high",
            strict_capability=True,
            prefer_lowest_capability=True,
            wait_when_unavailable=True,
        ))
        await asyncio.sleep(0.03)
        assert not task.done()
        queued = model_pool_snapshot()["queued_tasks"]
        assert queued[0]["task_id"] == "strict-high"
        assert "high" in queued[0]["blocked_reason"]

        current["config"] = SimpleNamespace(
            models=[
                {"id": "high", "model": "high-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        await refresh_configured_model_pool(current["config"], global_concurrency=1)
        lease = await asyncio.wait_for(task, timeout=1)
        assert lease is not None and lease.option.id == "high"
        await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())
