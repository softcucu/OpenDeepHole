import asyncio
import random
import threading
from datetime import datetime
from types import SimpleNamespace

import pytest

import task_agent.model_pool as model_pool_module
from task_agent.model_pool import (
    ModelQuotaCircuitOpenError,
    ModelQuotaWaitBudget,
    NoAvailableModelError,
    acquire_model_lease,
    clear_planned_task,
    clear_planned_tasks,
    configured_model_capacity,
    model_options,
    model_pool_snapshot,
    register_planned_task,
    record_model_token_usage,
    release_model_lease,
    refresh_configured_model_pool,
    total_model_capacity,
    update_model_lease_context,
    wait_for_model_pool_update,
)
from task_agent.token_usage import TokenCounters, attribute_token_usage, token_usage_from_models


@pytest.fixture(autouse=True)
def _reset_model_pool():
    """Each test runs in its own event loop via asyncio.run(), but the pool's
    Condition binds to the first loop that waits on it — recreate it per test."""
    model_pool_module._condition = asyncio.Condition()
    model_pool_module._change_waiters.clear()
    model_pool_module._running_by_model.clear()
    model_pool_module._global_running = 0
    model_pool_module._last_used.clear()
    model_pool_module._stats_by_scope.clear()
    model_pool_module._global_stats_by_model.clear()
    model_pool_module._options_by_id.clear()
    model_pool_module._model_health_by_id.clear()
    model_pool_module._scope_updated_at.clear()
    model_pool_module._global_updated_at = ""
    model_pool_module._active_tasks.clear()
    model_pool_module._completed_tasks_by_scope.clear()
    model_pool_module._completed_task_count_by_scope.clear()
    model_pool_module._completed_task_sink = None
    model_pool_module._token_usage_by_scope.clear()
    model_pool_module._global_token_usage = None
    model_pool_module._peak_total_tasks_by_scope.clear()
    model_pool_module._pending_requests.clear()
    model_pool_module._planned_tasks.clear()
    model_pool_module._planned_task_ids_by_key.clear()
    model_pool_module._pending_sequence = 0
    model_pool_module._planned_sequence = 0
    yield


def test_token_usage_accumulates_by_actual_model_for_scope_and_agent() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "configured",
            "model": "provider/configured",
            "capability": "high",
            "max_concurrency": 1,
        }])
        lease = await acquire_model_lease(
            cfg,
            stats_scope_id="scan-1",
        )
        assert lease is not None
        await record_model_token_usage(
            lease,
            token_usage_from_models({
                "provider/actual": TokenCounters(
                    input_tokens=8,
                    output_tokens=3,
                    reasoning_tokens=2,
                    cache_read_tokens=4,
                    cache_write_tokens=1,
                ),
            }),
        )

        scoped = model_pool_snapshot("scan-1")["token_usage"]
        global_usage = model_pool_snapshot()["token_usage"]
        assert scoped == global_usage
        assert scoped["total_tokens"] == 18
        assert scoped["by_model"][0]["model"] == "provider/actual"
        await release_model_lease(lease, outcome="success")

    asyncio.run(run())


def test_token_categories_remain_scoped_after_concurrent_failed_and_cancelled_tasks() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "shared", "model": "provider/shared", "capability": "high", "max_concurrency": 2,
        }])
        leases = await asyncio.gather(
            acquire_model_lease(cfg, stats_scope_id="scan-a"),
            acquire_model_lease(cfg, stats_scope_id="scan-b"),
        )
        await asyncio.gather(*(
            record_model_token_usage(lease, attribute_token_usage(
                token_usage_from_models({"provider/shared": TokenCounters(input_tokens=inputs, output_tokens=2)}),
                category,
            ))
            for lease, category, inputs in zip(leases, ("threat_analysis", "fp_review"), (10, 20))
        ))
        await asyncio.gather(
            release_model_lease(leases[0], outcome="failure"),
            release_model_lease(leases[1], outcome="cancelled"),
        )

        for scope, category, total in (("scan-a", "threat_analysis", 12), ("scan-b", "fp_review", 22)):
            scoped = model_pool_snapshot(scope)["token_usage"]
            assert scoped["total_tokens"] == total
            assert [(item["category"], item["total_tokens"]) for item in scoped["by_category"]] == [(category, total)]
        combined = model_pool_snapshot()["token_usage"]
        assert combined["total_tokens"] == 34
        assert sum(item["total_tokens"] for item in combined["by_model"]) == 34
        assert {item["category"]: item["total_tokens"] for item in combined["by_category"]} == {
            "threat_analysis": 12, "fp_review": 22,
        }

    asyncio.run(run())


def test_model_options_empty_pool_does_not_fall_back_to_legacy_model() -> None:
    cfg = SimpleNamespace(tool="opencode", executable="opencode", model="default-model", models=[])

    options = model_options(cfg)

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

    assert model_options(cfg) == []


def test_configured_capacity_excludes_disabled_and_invalid_rows_and_defaults_to_one() -> None:
    assert configured_model_capacity(SimpleNamespace(models=[])) == 0
    cfg = SimpleNamespace(models=[
        {"id": "default-limit", "model": "provider/default-limit"},
        {"id": "invalid-limit", "model": "provider/invalid-limit", "max_concurrency": 0},
        {"id": "disabled", "model": "provider/disabled", "max_concurrency": 100, "enabled": False},
        {"id": "missing-model", "model": "", "max_concurrency": 100},
    ])
    assert configured_model_capacity(cfg) == 2


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

    options = model_options(cfg)

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

    options = model_options(cfg)

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
    return model_options(cfg)[0]


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

        await refresh_configured_model_pool(cfg)
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
        await register_planned_task("scan-1", {"task_type": "vulnerability_mining"})
        updated_at = await waiter

        assert updated_at
        assert updated_at == model_pool_snapshot("scan-1")["updated_at"]

    asyncio.run(run())


def test_repeated_cancellation_of_pool_watchers_keeps_capacity_usable() -> None:
    """Exercise native Python 3.10 wait_for cancellation, not mocked leases."""
    async def run():
        rng = random.Random(7)

        async def watcher(index):
            for _ in range(300):
                timeout = 0.001 + rng.random() * 0.001
                task = asyncio.create_task(wait_for_model_pool_update(str(index), timeout=timeout))
                loop = asyncio.get_running_loop()
                cancellations = [loop.call_later(timeout + rng.random() * 0.0005, task.cancel) for _ in range(2)]
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                finally:
                    for callback in cancellations:
                        callback.cancel()

        workers = [asyncio.create_task(watcher(index)) for index in range(16)]
        try:
            done, pending = await asyncio.wait(workers, timeout=5)
            assert not pending, "pool watchers were stranded by cancellation"
            for task in done:
                task.result()
            cfg = SimpleNamespace(models=[{"id": "model", "model": "p/m", "max_concurrency": 1}])
            lease = await asyncio.wait_for(acquire_model_lease(cfg), 0.5)
            await asyncio.wait_for(release_model_lease(lease, outcome="success"), 0.5)
            assert model_pool_snapshot()["global_running"] == 0
            assert not model_pool_module._change_waiters
        finally:
            for task in workers:
                task.cancel()
            # Also keep this regression bounded against the old orphan-lock bug.
            for _ in range(100):
                if model_pool_module._condition.locked():
                    model_pool_module._condition.release()
                await asyncio.sleep(0)
            await asyncio.gather(*workers, return_exceptions=True)

    asyncio.run(run())


def test_cancelled_lease_waiter_is_removed_and_next_task_can_run() -> None:
    async def run():
        cfg = SimpleNamespace(models=[{"id": "one", "model": "p/m", "max_concurrency": 1}])
        first = await acquire_model_lease(cfg)
        queued = asyncio.Event()
        waiting = asyncio.create_task(acquire_model_lease(cfg, on_queued=queued.set))
        await queued.wait()
        waiting.cancel()
        await asyncio.gather(waiting, return_exceptions=True)
        assert model_pool_snapshot()["global_queued"] == 0
        await release_model_lease(first, outcome="timeout")
        next_lease = await asyncio.wait_for(acquire_model_lease(cfg), 0.5)
        await release_model_lease(next_lease, outcome="success")
        assert model_pool_snapshot()["global_running"] == 0
        assert not model_pool_module._change_waiters
    asyncio.run(run())


def test_release_commits_final_metadata_and_fences_late_token_usage() -> None:
    async def run():
        cfg = SimpleNamespace(models=[{"id": "one", "model": "p/m", "max_concurrency": 1}])
        first = await acquire_model_lease(cfg, task_id="logical", stats_scope_id="scan")
        usage = token_usage_from_models({"p/m": TokenCounters(input_tokens=7)})
        await record_model_token_usage(first, usage)
        await release_model_lease(first, outcome="timeout", context_updates={"failure_reason": "message timeout", "serve_session_id": "ses-old"})
        second = await acquire_model_lease(cfg, task_id="logical", stats_scope_id="scan")
        await record_model_token_usage(first, usage)
        await release_model_lease(first, outcome="failure", context_updates={"serve_session_id": "late"})
        snapshot = model_pool_snapshot("scan")
        assert snapshot["global_running"] == 1
        assert snapshot["token_usage"]["total_tokens"] == 7
        assert snapshot["completed_tasks"][0]["serve_session_id"] == "ses-old"
        assert snapshot["completed_tasks"][0]["failure_reason"] == "message timeout"
        await release_model_lease(second, outcome="success")
    asyncio.run(run())


@pytest.mark.parametrize("first_message_timeout", [False, True])
def test_real_service_partial_tokens_release_capacity_for_following_tasks(tmp_path, monkeypatch, first_message_timeout):
    import httpx
    from unittest.mock import AsyncMock
    import task_agent.serve_client as serve
    import task_agent.task_service as service_module
    from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec, _SessionRuntime, bind_opencode_execution_context
    from backend.models import OutputSource

    async def run():
        sessions, output = [], []
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
                session = f"ses-{len(sessions)}"
                sessions.append(session)
                return httpx.Response(200, json={"id": session})
            if request.method == "POST" and path.endswith("/message"):
                if first_message_timeout and "/ses-0/" in path:
                    await asyncio.Future()
                return httpx.Response(200, json={
                    "info": {"id": "message", "role": "assistant", "tokens": {"input": 7, "output": 3}},
                    "parts": [{"type": "text", "text": "done"}],
                })
            if path.endswith("/children"):
                await asyncio.Future()
            return httpx.Response(200, json=[] if path.endswith("/message") else {})

        client = httpx.AsyncClient
        monkeypatch.setattr(serve.httpx, "AsyncClient", lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
        monkeypatch.setattr(serve, "_SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS", 0.03)
        monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0.001)
        manager._acquire_session = acquire
        cfg = SimpleNamespace(opencode=SimpleNamespace(timeout=1, max_retries=0, models=[{
            "id": "one", "model": "p/m", "capability": "high", "max_concurrency": 1,
        }]))
        monkeypatch.setattr(service_module, "get_config", lambda: cfg)
        monkeypatch.setattr(service_module, "get_serve_manager", lambda: manager)
        monkeypatch.setattr(service_module, "get_host_bindings", lambda: SimpleNamespace(writable_roots=lambda: ()))
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(
            _SessionRuntime(directory=tmp_path, tool="opencode", executable="opencode", config_workspace=tmp_path, config_content="{}", env_overrides={}),
            "p/m", OutputSource(backend="opencode", model="p/m"),
        ))
        with bind_opencode_execution_context(
            project_dir=tmp_path, work_dir=tmp_path / "work", scan_id="scan",
            task_metadata={"task_type": "vulnerability_mining"}, on_output=output.append,
        ):
            handles = [service.submit_task(OpenCodeTaskSpec(task_name=f"task-{i}", prompt="test", directory=tmp_path, attempt=1)) for i in range(3)]
            results = await asyncio.wait_for(asyncio.gather(*(handle.result() for handle in handles)), 3)
            await asyncio.gather(*(handle._record.worker for handle in handles))
        assert [result.status for result in results] == ["success"] * 3
        assert all(result.token_usage["complete"] is False for result in results)
        snapshot = model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["completed_task_count"] == 3
        assert snapshot["token_usage"]["total_tokens"] == 30
        assert manager._active_sessions == 0
        assert len(sessions) == (4 if first_message_timeout else 3)
        if first_message_timeout:
            assert any("TIMEOUT phase=message" in line for line in output)
        assert all("TIMEOUT phase=token_collection" not in line for line in output)

    asyncio.run(run())


def test_acquire_model_lease_filters_by_capability_and_releases() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 3, "max_concurrency": 2},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
            ],
        )

        lease = await acquire_model_lease(cfg, required_capability="high")
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
        queued_events: list[str] = []
        cfg = SimpleNamespace(
            models=[
                {"id": "deep", "model": "deep-model", "capability": "high", "max_concurrency": 1},
            ],
        )
        lease = await acquire_model_lease(
            cfg,
            required_capability="high",
            stats_scope_id="scope-immediate",
            on_queued=lambda: queued_events.append("queued"),
        )
        try:
            assert queued_events == []
            snapshot = model_pool_snapshot("scope-immediate")
            assert snapshot["global_running"] == 1
            assert snapshot["global_queued"] == 0
            assert snapshot["models"][0]["running"] == 1
            assert snapshot["models"][0]["queued"] == 0
        finally:
            await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_waiting_lease_reports_queued_before_it_can_run() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "deep",
            "model": "deep-model",
            "capability": "high",
            "max_concurrency": 1,
        }])
        first = await acquire_model_lease(
            cfg,
            required_capability="high",
            stats_scope_id="scope-queued",
        )
        queued = asyncio.Event()
        second_task = asyncio.create_task(acquire_model_lease(
            cfg,
            required_capability="high",
            stats_scope_id="scope-queued",
            on_queued=queued.set,
        ))
        try:
            await asyncio.wait_for(queued.wait(), timeout=1.0)
            assert not second_task.done()
            snapshot = model_pool_snapshot("scope-queued")
            assert snapshot["global_running"] == 1
            assert snapshot["global_queued"] == 1
            await release_model_lease(first, outcome="success")
            second = await asyncio.wait_for(second_task, timeout=1.0)
            assert second is not None
            await release_model_lease(second, outcome="success")
        finally:
            if first is not None and model_pool_snapshot("scope-queued")["global_running"]:
                await release_model_lease(first, outcome="cancelled")
            if not second_task.done():
                second_task.cancel()

    asyncio.run(run())


def test_acquire_without_models_fails_fast_and_clears_planned_task() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(model="legacy-claude-model", models=[])
        scope = "scope-no-model"
        planned_id = await register_planned_task(
            scope,
            {"task_type": "vulnerability_mining", "file": "src/no-model.c"},
            task_key="audit:no-model",
        )

        with pytest.raises(NoAvailableModelError) as exc_info:
            await asyncio.wait_for(
                acquire_model_lease(
                    cfg,
                    stats_scope_id=scope,
                    task_context={
                        "planned_task_id": planned_id,
                        "task_type": "vulnerability_mining",
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
        assert completed["failure_kind"] == "no_available_model"
        assert completed["session_events"] == [{
            "sequence": 1,
            "phase": "business",
            "session_id": "",
            "session_attempt": 1,
            "outcome": "failure",
            "failure_kind": "no_available_model",
            "failure_reason": str(exc_info.value),
            "started_at": completed["started_at"],
            "finished_at": completed["finished_at"],
            "duration_seconds": completed["duration_seconds"],
        }]
        assert completed["task_type"] == "vulnerability_mining"
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
            stats_scope_id=scope,
        )
        planned_id = await register_planned_task(
            scope,
            {"task_type": "vulnerability_mining"},
            task_key="threat:queued",
        )
        queued_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                stats_scope_id=scope,
                task_context={
                    "planned_task_id": planned_id,
                    "task_type": "vulnerability_mining",
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
            await refresh_configured_model_pool(cfg)

            with pytest.raises(NoAvailableModelError):
                await asyncio.wait_for(queued_task, timeout=0.2)
            failed_snapshot = model_pool_snapshot(scope)
            assert failed_snapshot["global_queued"] == 0
            assert failed_snapshot["queued_tasks"] == []
            assert failed_snapshot["planned_tasks"] == []
            assert failed_snapshot["completed_task_count"] == 1
            assert failed_snapshot["completed_tasks"][0]["outcome"] == "failure"
            assert failed_snapshot["completed_tasks"][0]["task_type"] == "vulnerability_mining"
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
            {"task_type": "vulnerability_mining", "checker": "overflow", "file": "src/a.c", "line": 42},
            task_key="audit:42",
        )
        duplicate_id = await register_planned_task(
            scope,
            {"task_type": "vulnerability_mining", "checker": "ignored"},
            task_key="audit:42",
        )
        assert duplicate_id == planned_id

        planned_snapshot = model_pool_snapshot(scope)
        assert planned_snapshot["planned_tasks"] == [
            {
                "planned_task_id": planned_id,
                "scope_id": scope,
                "planned_at": planned_snapshot["planned_tasks"][0]["planned_at"],
                "task_type": "vulnerability_mining",
                "checker": "overflow",
                "file": "src/a.c",
                "line": 42,
            }
        ]

        lease = await acquire_model_lease(
            cfg,
            required_capability="high",
            stats_scope_id=scope,
            task_context={"planned_task_id": planned_id, "task_type": "vulnerability_mining", "file": "src/a.c", "line": 42},
        )
        try:
            active_snapshot = model_pool_snapshot(scope)
            assert active_snapshot["planned_tasks"] == []
            active_tasks = active_snapshot["models"][0]["active_tasks"]
            assert active_tasks[0]["task_type"] == "vulnerability_mining"
            assert active_tasks[0]["file"] == "src/a.c"
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_can_clear_planned_tasks_before_lease_request() -> None:
    async def run():
        first = await register_planned_task("scan-a", {"task_type": "fp_review"}, task_key="fp:1")
        await register_planned_task("scan-a", {"task_type": "vulnerability_mining"}, task_key="audit:1")
        await register_planned_task("scan-b", {"task_type": "threat_analysis"}, task_key="threat")

        await clear_planned_task(first)
        assert [task["task_type"] for task in model_pool_snapshot("scan-a")["planned_tasks"]] == ["vulnerability_mining"]

        await register_planned_task("scan-a", {"task_type": "fp_review"}, task_key="fp:2")
        await clear_planned_tasks("scan-a", {"vulnerability_mining"})
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

        first = await acquire_model_lease(cfg, required_capability="any")
        second = await acquire_model_lease(cfg, required_capability="any")
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
            required_capability="high",
            stats_scope_id=scope,
        )
        second = None
        second_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
                required_capability="high",
                stats_scope_id=scope,
                task_context={
                    "task_type": "vulnerability_mining",
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
                required_capability="high",
                stats_scope_id=scope,
                task_context={
                    "task_type": "vulnerability_mining",
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
            assert completed["task_type"] == "vulnerability_mining"
            assert completed["outcome"] == outcome
            assert completed["duration_seconds"] == 1.5
            assert completed["prompt"] == prompt
            assert completed["prompt_length"] == len(prompt)
            assert completed["serve_session_id"] == f"ses_{outcome}"

    asyncio.run(run())


def test_model_pool_snapshot_persists_terminal_session_trace() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "deep",
            "model": "provider/deep",
            "capability": "high",
            "max_concurrency": 1,
        }])
        scope = "scan-session-trace"
        lease = await acquire_model_lease(
            cfg,
            stats_scope_id=scope,
            task_id="logical-task",
            task_context={"task_type": "vulnerability_mining"},
        )
        session_events = [
            {
                "sequence": 1,
                "phase": "business",
                "session_id": "ses_timeout",
                "session_attempt": 1,
                "outcome": "timeout",
                "failure_kind": "timeout",
            },
            {
                "sequence": 2,
                "phase": "business",
                "session_id": "ses_failed",
                "session_attempt": 2,
                "outcome": "failure",
                "failure_kind": "schema_mismatch",
            },
        ]
        await update_model_lease_context(lease, {
            "serve_session_id": "ses_failed",
            "failure_kind": "schema_mismatch",
            "failure_reason": "JSON retries exhausted",
            "session_events": session_events,
        })
        await release_model_lease(lease, outcome="failure", duration_seconds=2.0)

        completed = model_pool_snapshot(scope)["completed_tasks"]
        assert len(completed) == 1
        assert completed[0]["serve_session_id"] == "ses_failed"
        assert completed[0]["failure_kind"] == "schema_mismatch"
        assert completed[0]["failure_reason"] == "JSON retries exhausted"
        assert completed[0]["session_events"] == session_events

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
            stats_scope_id=scope,
            task_id=task_id,
            task_context={"task_type": "vulnerability_mining", "session_attempt": 1},
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
            stats_scope_id=scope,
            task_id=task_id,
            task_context={"task_type": "vulnerability_mining", "session_attempt": 2},
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


def test_non_terminal_scheduling_failure_does_not_append_completed_task() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(model="legacy-claude-model", models=[])
        scope = "scope-recovery-no-model"

        with pytest.raises(NoAvailableModelError):
            await acquire_model_lease(
                cfg,
                stats_scope_id=scope,
                task_id="logical-task",
                task_context={
                    "task_type": "vulnerability_mining",
                    "task_phase": "json_format",
                    "session_attempt": 1,
                    "session_events": [{
                        "sequence": 1,
                        "phase": "business",
                        "session_id": "ses-business",
                        "session_attempt": 1,
                        "outcome": "invalid_output",
                    }],
                },
                record_completion_on_failure=False,
            )

        snapshot = model_pool_snapshot(scope)
        assert snapshot["completed_task_count"] == 0
        assert snapshot["completed_tasks"] == []

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
            required_capability="high",
            stats_scope_id=scope,
        )
        second_task = asyncio.create_task(
            acquire_model_lease(
                cfg,
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


@pytest.mark.parametrize("limits", [(4, 5), (32, 33)])
@pytest.mark.parametrize("legacy_global_limit", [1, 8, 1000])
def test_model_limits_are_shared_across_scans_without_global_gate(
    limits: tuple[int, int], legacy_global_limit: int,
) -> None:
    """All model slots are usable across scans; each model remains bounded."""
    from deephole_client.config import AgentConfig, apply_remote_config

    async def run():
        config = AgentConfig()
        apply_remote_config(config, {"model_pool": {
            "global_concurrency": legacy_global_limit,
            "models": [
                {"id": name, "model": f"provider/{name}", "max_concurrency": limit}
                for name, limit in zip(("first", "second"), limits)
            ],
        }})
        capacity = sum(limits)
        assert config.opencode_concurrency == capacity
        assert total_model_capacity(config.opencode) == capacity
        leases = []
        waiter = None
        try:
            for index in range(capacity):
                leases.append(await asyncio.wait_for(acquire_model_lease(
                    config.opencode,
                    required_capability="high",
                    stats_scope_id=f"scan-{index % 2}",
                ), timeout=1))
            snapshot = model_pool_snapshot()
            assert snapshot["global_running"] == capacity
            assert {row["id"]: row["running"] for row in snapshot["models"]} == {
                "first": limits[0], "second": limits[1],
            }
            queued = asyncio.Event()
            waiter = asyncio.create_task(acquire_model_lease(
                config.opencode, stats_scope_id="third-scan", on_queued=queued.set,
            ))
            await asyncio.wait_for(queued.wait(), timeout=1)
            assert not waiter.done()
            assert model_pool_snapshot()["global_queued"] == 1
            released = leases.pop()
            await release_model_lease(released)
            replacement = await asyncio.wait_for(waiter, timeout=1)
            leases.append(replacement)
            assert replacement.option.id == released.option.id
            assert model_pool_snapshot()["global_running"] == capacity
            assert model_pool_snapshot()["global_queued"] == 0
        finally:
            if waiter is not None and not waiter.done():
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)
            for lease in leases:
                await release_model_lease(lease)
        assert model_pool_snapshot()["global_running"] == 0

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
            cfg, required_capability="any", stats_scope_id=scope
        )
        lease_b = await acquire_model_lease(
            cfg, required_capability="any", stats_scope_id=scope
        )
        assert lease_a is not None and lease_b is not None
        held = {lease_a.option.id: lease_a, lease_b.option.id: lease_b}
        assert set(held) == {"a", "b"}

        third_task = asyncio.create_task(
            acquire_model_lease(
                cfg, required_capability="any", stats_scope_id=scope
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
            cfg, required_capability="high", stats_scope_id=scope
        )
        high_waiter = asyncio.create_task(
            acquire_model_lease(
                cfg,
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
                    required_capability="any",
                    stats_scope_id=scope,
                    task_context={"task_type": "vulnerability_mining", "checker": "npd"},
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
                "task_type": "vulnerability_mining",
                "audit_index": 0,
                "queue_group": group,
                "required_capability": "any",
            },
            task_key="audit:0",
        )
        second_id = await register_planned_task(
            scope,
            {
                "task_type": "vulnerability_mining",
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
                required_capability="any",
                stats_scope_id=scope,
                cancel_event=second_cancel,
                task_context={
                    "planned_task_id": second_id,
                    "task_type": "vulnerability_mining",
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
                required_capability="any",
                stats_scope_id=scope,
                task_context={
                    "planned_task_id": first_id,
                    "task_type": "vulnerability_mining",
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
            required_capability="high",
            stats_scope_id=scope,
        )
        high_id = await register_planned_task(
            scope,
            {
                "task_type": "vulnerability_mining",
                "audit_index": 0,
                "queue_group": group,
                "required_capability": "high",
            },
            task_key="audit:0",
        )
        low_id = await register_planned_task(
            scope,
            {
                "task_type": "vulnerability_mining",
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
                    required_capability="any",
                    stats_scope_id=scope,
                    task_context={
                        "planned_task_id": low_id,
                        "task_type": "vulnerability_mining",
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

    assert total_model_capacity(cfg, required_capability="any") == 3
    assert configured_model_capacity(cfg) == 6
    # No active model satisfies the high requirement; capacity still returns a
    # single worker so the task can queue until a matching time window opens.
    assert total_model_capacity(cfg, required_capability="high") == 1


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
        task = asyncio.create_task(acquire_model_lease(cfg, required_capability="high"))
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

        await refresh_configured_model_pool(initial)
        before = {item["id"]: item for item in model_pool_snapshot()["models"]}
        assert before["day"]["model"] == "day-model"
        scoped_before_first_lease = {
            item["id"]: item
            for item in model_pool_snapshot("new-scan")["models"]
        }
        assert scoped_before_first_lease["day"]["running"] == 0
        assert scoped_before_first_lease["day"]["queued"] == 0

        await refresh_configured_model_pool(updated)
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
            required_capability="high",
            stats_scope_id="scan-active",
            task_context={
                "task_type": "vulnerability_mining",
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
            assert model["active_tasks"][0]["task_type"] == "vulnerability_mining"
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
        occupied = await acquire_model_lease(cfg)
        low_task = asyncio.create_task(acquire_model_lease(
            cfg,
            task_id="task-low",
            priority=10,
            strict_capability=True,
            wait_when_unavailable=True,
        ))
        await asyncio.sleep(0.02)
        high_task = asyncio.create_task(acquire_model_lease(
            cfg,
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
        await refresh_configured_model_pool(current["config"])
        lease = await asyncio.wait_for(task, timeout=1)
        assert lease is not None and lease.option.id == "high"
        await release_model_lease(lease, outcome="success", duration_seconds=0.1)

    asyncio.run(run())


def test_health_outcome_is_independent_from_task_outcome_and_clamped() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "weight": 8,
            "max_concurrency": 1,
        }])

        json_failure = await acquire_model_lease(cfg)
        await release_model_lease(
            json_failure,
            outcome="failure",
            health_outcome=None,
            record_completion=False,
        )
        unchanged = model_pool_snapshot()["models"][0]
        assert unchanged["failure"] == 1
        assert unchanged["health_penalty_level"] == 0
        assert unchanged["effective_weight"] == 8

        for _ in range(5):
            lease = await acquire_model_lease(cfg)
            await release_model_lease(
                lease,
                outcome="failure",
                health_outcome="failure",
                record_completion=False,
            )

        penalized = model_pool_snapshot()["models"][0]
        assert penalized["failure"] == 6
        assert penalized["health_penalty_level"] == 4
        assert penalized["effective_weight"] == pytest.approx(0.8)
        assert penalized["last_health_failure_at"]
        assert penalized["last_health_failure_kind"] == "failure"

        success = await acquire_model_lease(cfg)
        await release_model_lease(
            success,
            outcome="success",
            health_outcome="success",
            record_completion=False,
        )
        recovered = model_pool_snapshot()["models"][0]
        assert recovered["health_penalty_level"] == 3
        assert recovered["effective_weight"] == 1
        assert recovered["last_health_failure_kind"] == "failure"

    asyncio.run(run())


def test_quota_circuit_switches_to_alternative_model_immediately() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[
            {
                "id": "primary",
                "model": "provider/primary",
                "weight": 10,
                "max_concurrency": 1,
            },
            {
                "id": "secondary",
                "model": "provider/secondary",
                "weight": 1,
                "max_concurrency": 1,
            },
        ])
        failed = await acquire_model_lease(cfg)
        assert failed is not None and failed.option.id == "primary"
        failed_identity = failed.health_identity
        await release_model_lease(
            failed,
            outcome="failure",
            health_outcome="quota",
            record_completion=False,
        )

        retry = await acquire_model_lease(
            cfg,
            avoid_model_identities={failed_identity},
            quota_wait_deadline=model_pool_module.time.monotonic() + 1,
        )
        try:
            assert retry is not None
            assert retry.option.id == "secondary"
            assert retry.quota_half_open_probe is False
        finally:
            await release_model_lease(retry, outcome="success")

    asyncio.run(run())


def test_quota_circuit_allows_only_one_half_open_probe_per_identity() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[
            {
                "id": "duplicate-a",
                "model": "provider/same",
                "max_concurrency": 1,
            },
            {
                "id": "duplicate-b",
                "model": "provider/same",
                "max_concurrency": 1,
            },
        ])
        failed = await acquire_model_lease(cfg)
        assert failed is not None
        await release_model_lease(
            failed,
            outcome="failure",
            health_outcome="quota",
            record_completion=False,
        )
        state = model_pool_module._model_health_by_id[failed.option.id]
        state.quota_open_until = model_pool_module.time.monotonic() - 0.01

        probe = await acquire_model_lease(
            cfg,
            quota_wait_deadline=model_pool_module.time.monotonic() + 1,
        )
        assert probe is not None and probe.quota_half_open_probe is True
        follower = asyncio.create_task(acquire_model_lease(
            cfg,
            wait_when_unavailable=True,
            quota_wait_deadline=model_pool_module.time.monotonic() + 1,
        ))
        await asyncio.sleep(0.03)
        assert not follower.done()

        await release_model_lease(
            probe,
            outcome="success",
            health_outcome="success",
            record_completion=False,
        )
        next_lease = await asyncio.wait_for(follower, timeout=1)
        assert next_lease is not None
        assert next_lease.quota_half_open_probe is False
        await release_model_lease(next_lease, outcome="success")

    asyncio.run(run())


def test_quota_circuit_wait_is_bounded_and_cancelable() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "max_concurrency": 1,
        }])
        failed = await acquire_model_lease(cfg)
        assert failed is not None
        await release_model_lease(
            failed,
            outcome="failure",
            health_outcome="quota",
            quota_retry_after_seconds=300,
            record_completion=False,
        )

        budget = ModelQuotaWaitBudget(total_seconds=0.03)
        with pytest.raises(ModelQuotaCircuitOpenError):
            await acquire_model_lease(
                cfg,
                wait_when_unavailable=True,
                quota_wait_budget=budget,
            )
        assert budget.remaining_seconds == 0

        cancel_event = asyncio.Event()
        waiting = asyncio.create_task(acquire_model_lease(
            cfg,
            wait_when_unavailable=True,
            cancel_event=cancel_event,
            quota_wait_budget=ModelQuotaWaitBudget(total_seconds=1),
        ))
        await asyncio.sleep(0.03)
        cancel_event.set()
        assert await asyncio.wait_for(waiting, timeout=1) is None

    asyncio.run(run())


def test_health_penalty_recovers_one_level_per_ten_failure_free_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 100.0}
    monkeypatch.setattr(model_pool_module.time, "monotonic", lambda: clock["now"])

    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "weight": 4,
            "max_concurrency": 1,
        }])
        for _ in range(3):
            lease = await acquire_model_lease(cfg)
            await release_model_lease(
                lease,
                outcome="timeout",
                health_outcome="timeout",
                duration_seconds=1,
                record_completion=False,
            )

        initial = model_pool_snapshot()["models"][0]
        assert initial["health_penalty_level"] == 3
        assert initial["effective_weight"] == pytest.approx(0.5)
        assert initial["last_health_failure_kind"] == "timeout"

        clock["now"] += 599
        assert model_pool_snapshot()["models"][0]["health_penalty_level"] == 3
        clock["now"] += 1
        after_one_window = model_pool_snapshot()["models"][0]
        assert after_one_window["health_penalty_level"] == 2
        assert after_one_window["effective_weight"] == 1

        clock["now"] += 1200
        fully_recovered = model_pool_snapshot()["models"][0]
        assert fully_recovered["health_penalty_level"] == 0
        assert fully_recovered["effective_weight"] == 4

    asyncio.run(run())


def test_effective_weight_changes_weighted_model_selection() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "weight": 16,
            "max_concurrency": 1,
        }])
        for _ in range(4):
            lease = await acquire_model_lease(cfg)
            await release_model_lease(
                lease,
                outcome="failure",
                health_outcome="failure",
                record_completion=False,
            )

        cfg.models.append({
            "id": "secondary",
            "model": "provider/secondary",
            "weight": 2,
            "max_concurrency": 1,
        })
        await refresh_configured_model_pool(cfg)
        lease = await acquire_model_lease(cfg)
        try:
            assert lease.option.id == "secondary"
            by_id = {item["id"]: item for item in model_pool_snapshot()["models"]}
            assert by_id["primary"]["weight"] == 16
            assert by_id["primary"]["effective_weight"] == pytest.approx(1.6)
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_effective_weight_can_override_lowest_capability_preference() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "low",
            "model": "provider/low",
            "capability": "low",
            "weight": 16,
            "max_concurrency": 1,
        }])
        for _ in range(4):
            lease = await acquire_model_lease(cfg)
            await release_model_lease(
                lease,
                outcome="failure",
                health_outcome="failure",
                record_completion=False,
            )

        cfg.models.append({
            "id": "high",
            "model": "provider/high",
            "capability": "high",
            "weight": 2,
            "max_concurrency": 1,
        })
        await refresh_configured_model_pool(cfg)
        lease = await acquire_model_lease(
            cfg,
            required_capability="low",
            strict_capability=True,
            prefer_lowest_capability=True,
        )
        try:
            assert lease.option.id == "high"
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_retry_avoidance_uses_execution_identity_instead_of_config_id() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[
            {
                "id": "duplicate-a",
                "model": "provider/same",
                "weight": 2,
                "max_concurrency": 1,
            },
            {
                "id": "duplicate-b",
                "model": "provider/same",
                "weight": 2,
                "max_concurrency": 1,
            },
            {
                "id": "alternative",
                "model": "provider/other",
                "weight": 1,
                "max_concurrency": 1,
            },
        ])
        failed = await acquire_model_lease(cfg)
        assert failed.option.id == "duplicate-a"
        failed_identity = failed.health_identity
        await release_model_lease(
            failed,
            outcome="failure",
            health_outcome="failure",
            record_completion=False,
        )
        duplicate_health = {
            item["id"]: item["health_penalty_level"]
            for item in model_pool_snapshot()["models"]
        }
        assert duplicate_health["duplicate-a"] == 1
        assert duplicate_health["duplicate-b"] == 1

        retry = await acquire_model_lease(
            cfg,
            avoid_model_identities={failed_identity},
        )
        try:
            assert retry.option.id == "alternative"
        finally:
            await release_model_lease(retry)

        cfg.models = [{
            "id": "duplicate-a",
            "model": "provider/reconfigured",
            "weight": 2,
            "max_concurrency": 1,
        }]
        await refresh_configured_model_pool(cfg)
        reconfigured = await acquire_model_lease(
            cfg,
            avoid_model_identities={failed_identity},
        )
        try:
            assert reconfigured.option.id == "duplicate-a"
            assert reconfigured.option.model == "provider/reconfigured"
        finally:
            await release_model_lease(reconfigured)

    asyncio.run(run())


def test_retry_waits_for_busy_untried_model_instead_of_reusing_avoided_model() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[
            {
                "id": "primary",
                "model": "provider/primary",
                "capability": "high",
                "weight": 10,
                "max_concurrency": 1,
            },
            {
                "id": "secondary",
                "model": "provider/secondary",
                "capability": "high",
                "weight": 1,
                "max_concurrency": 1,
            },
        ])
        failed = await acquire_model_lease(cfg)
        occupied_alternative = await acquire_model_lease(cfg)
        assert failed.option.id == "primary"
        assert occupied_alternative.option.id == "secondary"
        await release_model_lease(
            failed,
            outcome="failure",
            health_outcome="failure",
            record_completion=False,
        )

        retry_task = asyncio.create_task(acquire_model_lease(
            cfg,
            avoid_model_ids={"primary"},
        ))
        await asyncio.sleep(0.03)
        assert not retry_task.done()
        assert model_pool_snapshot()["global_queued"] == 1

        await release_model_lease(occupied_alternative)
        retry = await asyncio.wait_for(retry_task, timeout=1)
        try:
            assert retry is not None
            assert retry.option.id == "secondary"
        finally:
            await release_model_lease(retry)

    asyncio.run(run())


def test_retry_falls_back_when_all_eligible_models_were_avoided() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[
            {
                "id": "primary",
                "model": "provider/primary",
                "capability": "high",
                "weight": 4,
                "max_concurrency": 1,
            },
            {
                "id": "secondary",
                "model": "provider/secondary",
                "capability": "low",
                "weight": 1,
                "max_concurrency": 1,
            },
        ])
        capability_fallback = await acquire_model_lease(
            cfg,
            required_capability="high",
            avoid_model_ids={"primary"},
        )
        try:
            assert capability_fallback.option.id == "primary"
        finally:
            await release_model_lease(capability_fallback)

        all_tried_fallback = await acquire_model_lease(
            cfg,
            required_capability="any",
            avoid_model_ids={"primary", "secondary"},
        )
        try:
            assert all_tried_fallback.option.id == "primary"
        finally:
            await release_model_lease(all_tried_fallback)

    asyncio.run(run())


def test_health_survives_non_identity_config_changes_and_resets_on_identity_change() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(
            tool="nga",
            executable="/opt/opencode",
            models=[{
                "id": "primary",
                "model": "provider/primary",
                "tool": "nga",
                "executable": "/ignored/model-specific-nga",
                "weight": 4,
                "max_concurrency": 1,
            }],
        )
        lease = await acquire_model_lease(cfg)
        assert lease.option.tool == "opencode"
        assert lease.option.executable == "/opt/opencode"
        await release_model_lease(
            lease,
            outcome="failure",
            health_outcome="failure",
            record_completion=False,
        )

        cfg.models[0].update({
            "weight": 10,
            "max_concurrency": 3,
            "time_windows": [{"start": "00:00", "end": "23:59"}],
        })
        await refresh_configured_model_pool(cfg)
        preserved = model_pool_snapshot()["models"][0]
        assert preserved["health_penalty_level"] == 1
        assert preserved["weight"] == 10
        assert preserved["effective_weight"] == 5

        cfg.executable = "/opt/opencode-v2"
        await refresh_configured_model_pool(cfg)
        reset = model_pool_snapshot()["models"][0]
        assert reset["health_penalty_level"] == 0
        assert reset["effective_weight"] == 10
        assert reset["last_health_failure_at"] == ""
        assert reset["last_health_failure_kind"] == ""

    asyncio.run(run())


def test_recreated_model_ignores_late_health_result_from_old_lease() -> None:
    async def run() -> None:
        model = {
            "id": "primary",
            "model": "provider/primary",
            "weight": 4,
            "max_concurrency": 2,
        }
        cfg = SimpleNamespace(models=[dict(model)])
        old_lease = await acquire_model_lease(cfg)
        penalty_lease = await acquire_model_lease(cfg)
        await release_model_lease(
            penalty_lease,
            outcome="failure",
            health_outcome="failure",
            record_completion=False,
        )
        assert model_pool_snapshot()["models"][0]["health_penalty_level"] == 1

        cfg.models.clear()
        await refresh_configured_model_pool(cfg)
        cfg.models.append(dict(model))
        await refresh_configured_model_pool(cfg)
        recreated = model_pool_snapshot()["models"][0]
        assert recreated["health_penalty_level"] == 0

        await release_model_lease(
            old_lease,
            outcome="timeout",
            health_outcome="timeout",
            record_completion=False,
        )
        after_late_release = model_pool_snapshot()["models"][0]
        assert after_late_release["health_penalty_level"] == 0
        assert after_late_release["last_health_failure_kind"] == ""

    asyncio.run(run())


def test_intermediate_attempt_records_stats_without_terminal_completion() -> None:
    async def run() -> None:
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "max_concurrency": 1,
        }])
        lease = await acquire_model_lease(
            cfg,
            stats_scope_id="retry-scope",
            task_id="logical-task",
        )
        await release_model_lease(
            lease,
            outcome="timeout",
            health_outcome="timeout",
            duration_seconds=3,
            record_completion=False,
        )

        snapshot = model_pool_snapshot("retry-scope")
        assert snapshot["models"][0]["total"] == 1
        assert snapshot["models"][0]["timeout"] == 1
        assert snapshot["models"][0]["health_penalty_level"] == 1
        assert snapshot["completed_task_count"] == 0
        assert snapshot["completed_tasks"] == []

    asyncio.run(run())


def test_completed_task_sink_receives_history_once_and_snapshot_stays_bounded() -> None:
    async def run() -> None:
        captured: list[dict] = []
        model_pool_module.set_completed_task_sink(captured.append)
        cfg = SimpleNamespace(models=[{
            "id": "primary",
            "model": "provider/primary",
            "max_concurrency": 1,
        }])
        lease = await acquire_model_lease(
            cfg,
            stats_scope_id="scan-incremental",
            task_id="logical-task",
            task_context={"task_type": "candidate_audit"},
        )
        await update_model_lease_context(lease, {
            "serve_session_id": "ses-1",
            "session_events": [{
                "sequence": 1,
                "phase": "business",
                "session_id": "ses-1",
                "outcome": "success",
            }],
        })
        await release_model_lease(lease, outcome="success", duration_seconds=1.0)
        assert await model_pool_module.drain_completed_task_reports(timeout=1)
        snapshot = model_pool_snapshot("scan-incremental")
        assert snapshot["completed_task_count"] == 1
        assert snapshot["completed_tasks"] == []
        assert len(captured) == 1
        assert captured[0]["task_id"] == "logical-task"
        assert captured[0]["serve_session_id"] == "ses-1"
        assert captured[0]["session_events"][0]["session_id"] == "ses-1"

    asyncio.run(run())


def test_binding_completed_task_sink_migrates_legacy_in_memory_history() -> None:
    legacy = {
        "scope_id": "scan-upgrade",
        "task_id": "legacy-task",
        "revision": 1,
        "outcome": "failure",
        "serve_session_id": "ses-before-upgrade",
    }
    model_pool_module._completed_tasks_by_scope["scan-upgrade"] = [legacy]
    model_pool_module._completed_task_count_by_scope["scan-upgrade"] = 1
    captured: list[dict] = []

    model_pool_module.set_completed_task_sink(captured.append)

    assert captured == [legacy]
    assert model_pool_module._completed_tasks_by_scope == {}
    snapshot = model_pool_snapshot("scan-upgrade")
    assert snapshot["completed_task_count"] == 1
    assert snapshot["completed_tasks"] == []


def test_failed_completion_sink_does_not_block_next_lease_or_duplicate_release(monkeypatch):
    async def run():
        captured = []
        attempts = 0
        next_lease_started = threading.Event()
        def sink(task):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                assert next_lease_started.wait(2), "completion sink held model capacity"
                raise OSError("disk temporarily unavailable")
            captured.append(task)
        monkeypatch.setattr(model_pool_module, "COMPLETED_REPORT_RETRY_SECONDS", 0.01)
        model_pool_module.set_completed_task_sink(sink)
        cfg = SimpleNamespace(models=[{"id": "m", "model": "p/m", "max_concurrency": 1}])
        first = await acquire_model_lease(cfg, stats_scope_id="scan", task_id="first")
        second_task = asyncio.create_task(acquire_model_lease(cfg, stats_scope_id="scan", task_id="second"))
        await asyncio.sleep(0)
        await release_model_lease(first, outcome="timeout")
        second = await asyncio.wait_for(second_task, 0.5)
        next_lease_started.set()
        await release_model_lease(first, outcome="timeout")
        assert model_pool_snapshot("scan")["global_running"] == 1
        assert await model_pool_module.drain_completed_task_reports(timeout=1)
        assert len(captured) == 1 and captured[0]["outcome"] == "timeout"
        await release_model_lease(second, outcome="success")
        assert await model_pool_module.drain_completed_task_reports(timeout=1)
        assert model_pool_snapshot("scan")["completed_task_count"] == 2
    asyncio.run(run())
