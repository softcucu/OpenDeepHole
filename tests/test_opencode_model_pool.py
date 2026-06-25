import asyncio
from types import SimpleNamespace

import pytest

import backend.opencode.model_pool as model_pool_module
from backend.opencode.model_pool import (
    acquire_model_lease,
    model_options,
    model_pool_snapshot,
    release_model_lease,
    refresh_configured_model_pool,
    total_model_capacity,
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
    yield


def test_model_options_falls_back_to_default_model() -> None:
    cfg = SimpleNamespace(tool="opencode", executable="opencode", model="default-model", models=[])

    options = model_options(cfg, global_concurrency=3)

    assert len(options) == 1
    assert options[0].id == "default"
    assert options[0].model == "default-model"
    assert options[0].max_concurrency == 3


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
    assert options[0].time_windows == ((540, 1080),)


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
            )
        )
        try:
            await asyncio.sleep(0.05)
            queued_snapshot = model_pool_snapshot(scope)
            assert queued_snapshot["global_running"] == 1
            assert queued_snapshot["global_queued"] == 1

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
                await asyncio.wait_for(second_task, timeout=1)
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
    """A task queued behind one model must run as soon as any other eligible
    model frees up, instead of waiting for its original queue target."""

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
            queued_ids = [item["id"] for item in snapshot["models"] if item["queued"]]
            assert len(queued_ids) == 1
            queued_id = queued_ids[0]
            other_id = "b" if queued_id == "a" else "a"

            # Free the model the third task is NOT queued on.
            await release_model_lease(held.pop(other_id), outcome="success", duration_seconds=0.1)
            third = await asyncio.wait_for(third_task, timeout=1)
            assert third is not None
            assert third.option.id == other_id
            await release_model_lease(third, outcome="success", duration_seconds=0.1)
        finally:
            if not third_task.done():
                third_task.cancel()
            for lease in held.values():
                await release_model_lease(lease, outcome="success", duration_seconds=0.1)

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
        finally:
            await release_model_lease(lease, outcome="success", duration_seconds=1.0)

    asyncio.run(run())
