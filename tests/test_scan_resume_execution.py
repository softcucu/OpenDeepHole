"""Stop/resume execution handoff regressions, using isolated durable storage."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from backend.api import agent as agent_api, scan as scan_api
from backend.models import (
    AgentInfo, AgentScanExecutionFailure, Candidate, MiningEngineSelection,
    OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus, User, Vulnerability,
)
from backend.store.sqlite import SqliteScanStore
from deephole_client import main as agent_main, server
from deephole_client.reporter import Reporter, scan_execution_context
from deephole_client.task_manager import TaskManager


async def direct_store(store, operation, *args, **kwargs):
    return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)


@pytest.fixture
def resume_env(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "scans.db")
    engines = [MiningEngineSelection(engine_id="static_candidate", engine_label="static")]
    scan = ScanStatus(
        scan_id="resume-scan", status=ScanItemStatus.CANCELLED,
        created_at="2026-09-01T00:00:00+00:00", mining_engines=engines,
        total_candidates=2, processed_candidates=1, progress=0.5,
        static_analysis_done=True, error_message="用户手动停止", vulnerabilities=[],
    )
    meta = ScanMeta(
        project_path="/repo", scan_name="resume", agent_id="agent",
        agent_name="agent", user_id="user", mining_engines=engines,
        scan_items=[], created_at=scan.created_at,
    )
    store.save_scan(scan, meta)
    store.replace_scan_candidates("resume-scan", [
        Candidate(file=file, line=1, function="f", vuln_type="npd", description="candidate")
        for file in ("done.c", "todo.c")
    ])
    store.add_processed_key("resume-scan", ("done.c", 1, "f", "npd"))
    store.update_scan_candidate_audit(
        "resume-scan", 0, state="success", vulnerability_idx=None, dedup_decision={},
        result=Vulnerability(
            file="done.c", line=1, function="f", vuln_type="npd", severity="low",
            description="guarded", ai_analysis="guarded", confirmed=False, ai_verdict="false_positive",
        ),
    )
    for _ in range(8):
        store.begin_scan_execution("resume-scan", agent_id="agent", agent_session_id="session")
    store.update_opencode_pool_status("resume-scan", OpenCodePoolStatus(
        execution_revision=8, agent_session_id="session",
        completed_tasks=[{"task_id": "old", "started_at": scan.created_at, "outcome": "cancelled"}],
    ))
    agent = AgentInfo(
        agent_id="agent", name="agent", agent_session_id="session",
        user_id="user", ip="127.0.0.1", last_seen=datetime.now(timezone.utc).isoformat(),
        protocol_version=2,
    )
    for module in (agent_api, scan_api):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
        monkeypatch.setattr(module, "run_store_call", direct_store)
    monkeypatch.setattr(agent_api, "_registered_agents", {"agent": agent})
    monkeypatch.setattr(agent_api, "_running_scans", {})
    monkeypatch.setattr(scan_api, "_running_scans", agent_api._running_scans)
    monkeypatch.setattr(agent_api, "_scan_owners", {})
    monkeypatch.setattr(scan_api, "_scan_owners", agent_api._scan_owners)
    monkeypatch.setattr(agent_api, "ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr(agent_api, "get_scan_agent_config_async", AsyncMock(return_value=object()))
    monkeypatch.setattr(agent_api, "agent_config_has_explicit_model", lambda _: True)
    monkeypatch.setattr(agent_api, "agent_explicit_model_ids", lambda _: ["provider/model"])
    monkeypatch.setattr(scan_api, "_checker_packages_for", lambda _: [])
    monkeypatch.setattr(agent_api, "create_agent_task_runtime_update_payload_async", AsyncMock(return_value=None))
    stop = AsyncMock(return_value={"still_active": False, "error": "", "execution_revision": 8})
    send = AsyncMock(return_value=True)
    real_stop, real_send = agent_api.request_agent_scan_stop, agent_api.send_agent_command
    monkeypatch.setattr(agent_api, "request_agent_scan_stop", stop)
    monkeypatch.setattr(agent_api, "send_agent_command", send)
    monkeypatch.setattr("backend.sse.publish", Mock())
    async def resume():
        return await scan_api.resume_scan(
            "resume-scan", SimpleNamespace(base_url="http://server/"),
            User(user_id="user", username="user", role="admin"),
        )
    yield SimpleNamespace(store=store, agent=agent, stop=stop, send=send, resume=resume,
                          real_stop=real_stop, real_send=real_send)
    store.close()


@pytest.mark.parametrize("ack", [None, {"still_active": True}, {"still_active": False, "error": "cleanup failed"}])
def test_resume_cleanup_failure_preserves_terminal_scan_and_revision(resume_env, ack):
    env = resume_env
    before = env.store.load_scan("resume-scan")[0].model_dump()
    env.stop.return_value = ack
    with pytest.raises(HTTPException) as error:
        asyncio.run(env.resume())
    assert error.value.status_code == 409
    assert "再次续扫" in error.value.detail
    assert env.store.get_scan_meta("resume-scan").execution_revision == 8
    assert env.store.load_scan("resume-scan")[0].model_dump() == before
    env.send.assert_not_awaited()


def test_resume_claim_preserves_history_and_rejects_old_manifest(resume_env):
    env = resume_env
    asyncio.run(env.resume())
    env.stop.assert_awaited_once_with("agent", "resume-scan", execution_revision=8)
    command = env.send.await_args.args[1]
    assert command["execution_revision"] == 9
    token = command["resume_manifest_url"].rsplit("/", 1)[-1]
    response = asyncio.run(agent_api.agent_get_resume_manifest_v2(token))
    assert json.loads(response.body)["execution_revision"] == 9
    stored, meta = env.store.load_scan("resume-scan")
    assert meta.execution_revision == 9
    assert stored.status == ScanItemStatus.PENDING
    assert stored.opencode_pool.execution_revision == 9
    assert stored.opencode_pool.completed_tasks[0]["task_id"] == "old"
    assert stored.created_at == "2026-09-01T00:00:00+00:00"
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.CANCELLED)
    assert env.store.claim_scan_for_resume(
        "resume-scan", processed_candidates=1, progress=0.5,
        expected_revision=9, agent_id="agent", agent_session_id="session",
    ) == 10
    with pytest.raises(HTTPException) as error:
        asyncio.run(agent_api.agent_get_resume_manifest_v2(token))
    assert error.value.status_code == 409


def test_competing_resume_requests_dispatch_only_one_execution(resume_env):
    env = resume_env
    async def run():
        both_arrived = asyncio.Event()
        arrivals = 0
        async def stopped(*args, **kwargs):
            nonlocal arrivals
            arrivals += 1
            if arrivals == 2:
                both_arrived.set()
            await both_arrived.wait()
            return {"still_active": False, "error": ""}
        env.stop.side_effect = stopped
        return await asyncio.gather(env.resume(), env.resume(), return_exceptions=True)
    results = asyncio.run(run())
    assert sum(isinstance(item, HTTPException) for item in results) == 1
    env.send.assert_awaited_once()
    assert env.store.get_scan_meta("resume-scan").execution_revision == 9


def test_manifest_persistence_failure_leaves_retryable_error(resume_env, monkeypatch):
    env = resume_env
    with monkeypatch.context() as patch:
        patch.setattr(env.store, "create_resume_manifest", Mock(side_effect=RuntimeError("write failed")))
        with pytest.raises(HTTPException) as error:
            asyncio.run(env.resume())
        assert error.value.status_code == 502
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == ScanItemStatus.ERROR
    assert scan.processed_candidates == 1
    assert meta.execution_revision == 9
    env.send.assert_not_awaited()
    asyncio.run(env.resume())
    assert env.store.get_scan_meta("resume-scan").execution_revision == 10


def test_start_failure_is_durable_retryable_and_cannot_fail_newer_execution(resume_env):
    env = resume_env
    asyncio.run(env.resume())
    for revision, changed in ((8, False), (9, True), (9, False)):
        result = asyncio.run(agent_api.agent_scan_execution_failed(
            "resume-scan", AgentScanExecutionFailure(
                agent_session_id="session", execution_revision=revision,
                error_message="旧扫描清理超时",
            ),
        ))
        assert result["changed"] is changed
    scan, _ = env.store.load_scan("resume-scan")
    assert scan.status == ScanItemStatus.ERROR
    assert scan.total_candidates == 2
    assert scan.processed_candidates == 1
    assert scan.opencode_pool.completed_tasks[0]["task_id"] == "old"
    asyncio.run(env.resume())
    result = asyncio.run(agent_api.agent_scan_execution_failed(
        "resume-scan", AgentScanExecutionFailure(
            agent_session_id="session", execution_revision=9, error_message="late failure",
        ),
    ))
    assert result["changed"] is False
    assert env.store.get_scan_meta("resume-scan").execution_revision == 10
    assert env.store.load_scan("resume-scan")[0].status == ScanItemStatus.PENDING


def test_reconnect_old_or_cancelled_inventory_does_not_suppress_recovery(resume_env, monkeypatch):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.PENDING)
    resume = AsyncMock()
    monkeypatch.setattr(scan_api, "_continue_scan", resume)
    asyncio.run(agent_api._recover_missing_agent_work(
        "agent", env.agent,
        {"active_scans": [{"scan_id": "resume-scan", "execution_revision": 7, "cancel_requested": True}]},
        server_url="http://server",
    ))
    resume.assert_awaited_once()
    assert resume.await_args.kwargs["claimed_execution_revision"] == 9


def test_restart_restores_main_scan_without_being_blocked_by_independent_review(resume_env, monkeypatch):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.AUDITING)
    env.store.create_fp_review_job("review", "resume-scan", 1, "2026-09-28T00:00:00Z")
    env.store.begin_fp_review_execution("review", agent_session_id="old-session")
    env.store.update_fp_review_job("review", status="running")
    review = AsyncMock(return_value={"status": "running"})
    monkeypatch.setattr(scan_api, "_start_fp_review", review)
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == ScanItemStatus.PENDING
    assert meta.execution_revision == 9
    assert not scan.error_message
    assert env.send.await_count == 1
    assert env.send.await_args.args[1]["type"] == "resume"
    review.assert_awaited_once_with("resume-scan", "http://server", raise_on_error=True,
                                    require_unresolved=True, claimed_execution_revision=2)
    assert env.store.get_fp_review_job("review").status == "running"


def test_recovery_failure_is_reported_and_next_hello_retries(resume_env):
    from backend.scan_runtime import AGENT_RECOVERY_FAILED_PREFIX
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.AUDITING)
    env.stop.return_value = {"still_active": True, "error": ""}
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == "error"
    assert scan.error_message.startswith(AGENT_RECOVERY_FAILED_PREFIX)
    assert "旧扫描尚未确认退出" in scan.error_message
    assert meta.execution_revision == 9
    env.send.assert_not_awaited()
    from backend.sse import publish
    assert any(call.args[1] == "scan_status" and call.args[2]["status"] == "error" for call in publish.call_args_list)
    env.stop.return_value = {"still_active": False, "error": ""}
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == "pending" and meta.execution_revision == 10
    assert not scan.error_message
    env.send.assert_awaited_once()


def test_recovery_skips_user_cancelled_scan(resume_env):
    env = resume_env
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    env.stop.assert_not_awaited()
    env.send.assert_not_awaited()
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == "cancelled" and meta.execution_revision == 8


@pytest.mark.parametrize("cancel_phase", ["before_load", "during_prepare"])
def test_user_stop_after_recovery_claim_prevents_dispatch(resume_env, monkeypatch, cancel_phase):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.AUDITING)

    def cancel():
        env.store.update_scan_progress("resume-scan", status=ScanItemStatus.CANCELLED,
                                       error_message="用户手动停止")

    if cancel_phase == "before_load":
        continue_scan = scan_api._continue_scan

        async def stop_before_load(*args, **kwargs):
            cancel()
            return await continue_scan(*args, **kwargs)

        monkeypatch.setattr(scan_api, "_continue_scan", stop_before_load)
    else:
        async def stop_during_prepare(*args, **kwargs):
            cancel()
            return {"still_active": False, "error": ""}

        env.stop.side_effect = stop_during_prepare
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    scan, meta = env.store.load_scan("resume-scan")
    assert scan.status == "cancelled" and scan.error_message == "用户手动停止"
    assert meta.execution_revision == 9
    env.send.assert_not_awaited()
    assert not env.store.list_agent_inflight_executions("", "agent")["scans"]


def test_main_recovery_does_not_reopen_user_cancelled_review(resume_env, monkeypatch):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.AUDITING)
    env.store.add_vulnerability("resume-scan", Vulnerability(
        file="todo.c", line=1, function="f", vuln_type="npd", severity="high",
        description="confirmed", ai_analysis="confirmed", confirmed=True, ai_verdict="confirmed",
    ))
    env.store.create_fp_review_job("review", "resume-scan", 1, "2026-09-28T00:00:00Z")
    env.store.begin_fp_review_execution("review", agent_session_id="old-session")
    env.store.update_fp_review_job("review", status="cancelled", error_message="用户手动停止")
    monkeypatch.setattr(scan_api, "_resolve_scan_agent_id", AsyncMock(return_value="agent"))
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    assert env.store.load_scan("resume-scan")[0].status == "pending"
    review = env.store.get_fp_review_job("review")
    assert review.status == "cancelled" and review.execution_revision == 1
    env.send.assert_awaited_once()
    assert env.send.await_args.args[1]["type"] == "resume"


@pytest.mark.parametrize("revision,cancel_requested,recovered", [(0, False, True), (1, True, True), (1, False, False)])
def test_review_inventory_recovery_checks_execution_and_cancellation(
    resume_env, monkeypatch, revision, cancel_requested, recovered,
):
    env = resume_env
    env.store.create_fp_review_job("review", "resume-scan", 1, "2026-09-28T00:00:00Z")
    env.store.begin_fp_review_execution("review", agent_session_id="old-session")
    env.store.update_fp_review_job("review", status="running")
    start_review = AsyncMock(return_value={"status": "running"})
    monkeypatch.setattr(scan_api, "_start_fp_review", start_review)
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {
        "active_fp_reviews": [{"scan_id": "resume-scan", "review_id": "review",
                               "execution_revision": revision, "cancel_requested": cancel_requested}],
    }, server_url="http://server"))
    assert start_review.await_count == int(recovered)
    review = env.store.get_fp_review_job("review")
    assert review.execution_revision == (2 if recovered else 1)
    assert review.execution_agent_session_id == env.agent.agent_session_id


def test_failed_review_recovery_clears_running_state(resume_env, monkeypatch):
    from backend.scan_runtime import AGENT_RECOVERY_FAILED_PREFIX
    env = resume_env
    env.store.create_fp_review_job("review", "resume-scan", 1, "2026-09-28T00:00:00Z")
    env.store.begin_fp_review_execution("review", agent_session_id="old-session")
    env.store.update_fp_review_job("review", status="running")
    monkeypatch.setattr(scan_api, "_start_fp_review", AsyncMock(side_effect=HTTPException(400, "模型配置不可用")))
    asyncio.run(agent_api._recover_missing_agent_work("agent", env.agent, {}, server_url="http://server"))
    review = env.store.get_fp_review_job("review")
    assert review.status == "error"
    assert review.error_message == AGENT_RECOVERY_FAILED_PREFIX + "模型配置不可用"
    assert not scan_api._fp_review_resume_state([], {}, env.store.list_fp_review_states_by_scans(["resume-scan"])["resume-scan"])[0]


def test_reconnect_adopts_only_matching_execution_before_publishing(resume_env):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.PENDING)
    env.agent.agent_session_id = "restarted-session"
    accepted = asyncio.run(agent_api._adopt_reported_agent_work(
        "agent", env.agent,
        {"active_scans": [{"scan_id": "resume-scan", "execution_revision": 8}]},
    ))
    assert accepted == [{"scan_id": "resume-scan", "execution_revision": 8}]
    assert env.store.execution_matches(
        "scan", "resume-scan", None, agent_session_id="restarted-session", execution_revision=8,
    )
    assert not env.store.adopt_active_execution(
        "scan", "resume-scan", None, previous_session_id="restarted-session",
        agent_session_id="obsolete-session", execution_revision=7,
    )


def test_old_pending_terminal_report_does_not_suppress_current_recovery(resume_env, monkeypatch):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.PENDING)
    resume = AsyncMock()
    monkeypatch.setattr(scan_api, "_continue_scan", resume)
    asyncio.run(agent_api._recover_missing_agent_work(
        "agent", env.agent, {"pending_terminal_reports": {
            "scans": ["resume-scan"],
            "scan_executions": [{"scan_id": "resume-scan", "execution_revision": 7}],
        }}, server_url="http://server",
    ))
    resume.assert_awaited_once()


def test_websocket_adopts_before_welcome_and_receives_stop_ack_during_recovery(resume_env, monkeypatch):
    env = resume_env
    env.store.update_scan_progress("resume-scan", status=ScanItemStatus.PENDING)
    env.store.upsert_agent_record(
        agent_key="stable", user_id="", ip="127.0.0.1", machine_name="resume-machine",
        display_name="agent", agent_id="agent", last_seen="2026-09-14T00:00:00+00:00",
    )
    with env.store._lock:
        env.store._conn.execute("UPDATE scans SET agent_key = 'stable' WHERE scan_id = 'resume-scan'")
        env.store._conn.commit()
    monkeypatch.setattr(agent_api, "request_agent_scan_stop", env.real_stop)
    monkeypatch.setattr(agent_api, "send_agent_command", env.real_send)
    monkeypatch.setattr(agent_api, "_agent_ws", {})
    monkeypatch.setattr(agent_api, "_agent_ws_locks", {})
    monkeypatch.setattr(agent_api, "_schedule_agent_disconnect_cancel", Mock())
    monkeypatch.setattr(agent_api, "_schedule_agent_touch_persistence", Mock())
    monkeypatch.setattr(agent_api, "_touch_agent", Mock())

    async def run():
        received = asyncio.Queue()
        sent = []
        received.put_nowait({
            "type": "hello", "name": "agent", "machine_name": "resume-machine",
            "agent_session_id": "reconnected-session", "protocol_versions": [2],
            "active_scans": [{"scan_id": "resume-scan", "execution_revision": 8}],
        })

        class WebSocket:
            client = SimpleNamespace(host="127.0.0.1")
            base_url = "ws://server/"
            accept = AsyncMock()
            close = AsyncMock()

            async def receive_json(self):
                payload = await received.get()
                if payload is None:
                    raise agent_api.WebSocketDisconnect()
                return payload

            async def send_json(self, payload):
                sent.append(payload)
                if payload["type"] == "welcome":
                    assert payload["scan_executions"] == [{"scan_id": "resume-scan", "execution_revision": 8}]
                    assert env.store.execution_matches(
                        "scan", "resume-scan", None, agent_session_id="reconnected-session", execution_revision=8,
                    )
                elif payload["type"] == "stop":
                    received.put_nowait({"type": "heartbeat"})
                    received.put_nowait({**payload, "type": "scan_stop_result", "still_active": False})

        async def recover(agent_id, *_args, **_kwargs):
            assert sent[0]["type"] == "welcome"
            result = await agent_api.request_agent_scan_stop(agent_id, "resume-scan", execution_revision=8)
            assert result["still_active"] is False
            received.put_nowait(None)

        recovery = AsyncMock(side_effect=recover)
        monkeypatch.setattr(agent_api, "_recover_missing_agent_work", recovery)
        await asyncio.wait_for(agent_api.agent_websocket(WebSocket()), timeout=2)
        recovery.assert_awaited_once()
        assert [payload["type"] for payload in sent] == ["welcome", "stop", "heartbeat_ack"]

    asyncio.run(run())


def test_agent_cleanup_timeout_does_not_switch_reporter_identity(monkeypatch):
    async def run():
        manager = TaskManager()
        monkeypatch.setattr(server, "_task_manager", manager)
        previous = manager.create("scan", "/repo", None, [], "old", execution_revision=8)
        release = asyncio.Event()
        previous.asyncio_task = asyncio.create_task(release.wait())
        reporter = SimpleNamespace(set_scan_execution=Mock(), report_scan_start_failure=AsyncMock())
        monkeypatch.setattr(server, "handle_stop", AsyncMock(return_value={"still_active": True, "error": ""}))
        try:
            with pytest.raises(RuntimeError, match="清理超时"):
                await agent_main._handle_command({
                    "type": "resume", "scan_id": "scan", "project_path": "/repo", "execution_revision": 9,
                }, None, manager, reporter)
            reporter.set_scan_execution.assert_not_called()
            reporter.report_scan_start_failure.assert_awaited_once()
            assert manager.get("scan") is previous
            assert not previous.cancel_event.suppress_terminal_report
        finally:
            release.set()
            await previous.asyncio_task
    asyncio.run(run())


def test_agent_resume_cleans_up_before_update_and_binds_once(monkeypatch):
    async def run():
        manager = TaskManager()
        monkeypatch.setattr(server, "_task_manager", manager)
        previous = manager.create("scan", "/repo", None, [], "old", execution_revision=8)
        order = []
        async def old_run():
            while not previous.cancel_event.is_set():
                await asyncio.sleep(0)
            assert previous.cancel_event.suppress_terminal_report
            order.append("old-exited")
        previous.asyncio_task = asyncio.create_task(old_run())
        monkeypatch.setattr("task_agent.cancel_opencode_execution", AsyncMock(return_value={"active_tasks": 0}))
        async def update(*args):
            assert previous.asyncio_task.done()
            order.append("update")
            return False
        monkeypatch.setattr("deephole_client.updater.ensure_runtime_updated", update)
        reporter = SimpleNamespace(
            set_scan_execution=lambda *args: order.append("bind"),
            report_scan_start_failure=AsyncMock(),
        )
        started = asyncio.Event()
        async def new_run(task, is_resume):
            assert task.execution_revision == 9 and is_resume
            assert not task.cancel_event.is_set()
            order.append("new-started")
            started.set()
        monkeypatch.setattr(server, "_run", new_run)
        command = {"type": "resume", "scan_id": "scan", "project_path": "/repo", "execution_revision": 9,
                   "agent_runtime_update": {"hash": "new"}}
        await agent_main._handle_command(command, None, manager, reporter)
        await started.wait()
        await manager.get("scan").asyncio_task
        # A duplicate and an older command cannot restart, update or rebind.
        await agent_main._handle_command(command, None, manager, reporter)
        await agent_main._handle_command({**command, "execution_revision": 8}, None, manager, reporter)
        assert order == ["old-exited", "update", "bind", "new-started"]
        response = await server.handle_stop("scan", execution_revision=8)
        assert response["still_active"]
        assert not manager.get("scan").cancel_event.is_set()
    asyncio.run(run())


def test_agent_rejects_manifest_revision_mismatch_without_binding(monkeypatch):
    monkeypatch.setattr(server, "_task_manager", TaskManager())
    reporter = SimpleNamespace(
        fetch_resume_manifest=AsyncMock(return_value={"scan_id": "scan", "project_path": "/repo", "execution_revision": 8}),
        set_scan_execution=Mock(), report_scan_start_failure=AsyncMock(),
    )
    with pytest.raises(RuntimeError, match="manifest"):
        asyncio.run(agent_main._handle_command({
            "type": "resume", "scan_id": "scan", "execution_revision": 9,
            "resume_manifest_url": "http://server/manifest",
        }, None, None, reporter))
    reporter.set_scan_execution.assert_not_called()
    reporter.report_scan_start_failure.assert_awaited_once()


def test_reporter_keeps_old_reports_bound_and_recovers_only_confirmed_identity():
    async def run():
        reporter = Reporter("http://server")
        requests = []
        accepted = False
        async def post(url, **kwargs):
            requests.append(kwargs["json"])
            return httpx.Response(
                200 if accepted else 409, request=httpx.Request("POST", url),
                json={"ok": True} if accepted else {"detail": "stale scan execution"},
            )
        await reporter._client.aclose()
        reporter._client = SimpleNamespace(post=post)
        reporter.set_scan_execution("scan", 8)
        assert not await reporter.push_opencode_pool_status("scan", {})
        accepted = True
        assert not await reporter.push_opencode_pool_status("scan", {})
        reporter.confirm_scan_executions([{"scan_id": "other", "execution_revision": 8}])
        assert not await reporter.push_opencode_pool_status("scan", {})
        reporter.confirm_scan_executions([{"scan_id": "scan", "execution_revision": 8}])
        assert await reporter.push_opencode_pool_status("scan", {})
        with scan_execution_context("scan", 8):
            reporter.set_scan_execution("scan", 9)
            assert await reporter.push_opencode_pool_status("scan", {})
            assert requests[-1]["execution_revision"] == 8
        assert reporter.set_scan_execution("scan", 7) == 9
        assert await reporter.push_opencode_pool_status("scan", {})
        assert requests[-1]["execution_revision"] == 9
    asyncio.run(run())


def test_resume_http_reports_advance_task_time_progress_and_finish(resume_env, monkeypatch):
    from backend import report_routes

    env = resume_env
    published = Mock()
    monkeypatch.setattr("backend.sse.publish", published)
    monkeypatch.setattr(report_routes, "get_scan_store", lambda: env.store)
    monkeypatch.setattr(report_routes, "run_store_call", direct_store)
    monkeypatch.setattr(scan_api, "_start_fp_review", AsyncMock())
    manager = TaskManager()
    monkeypatch.setattr(server, "_task_manager", manager)
    app = FastAPI()
    app.include_router(agent_api.router)

    async def run():
        await env.resume()
        command = env.send.await_args.args[1]
        reporter = Reporter("http://server")
        reporter.agent_session_id = "session"
        reporter.set_protocol_version(2)
        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
        new_started_at = datetime.now(timezone.utc).isoformat()

        async def execute(task, is_resume):
            assert is_resume and task.execution_revision == 9
            assert await reporter.push_opencode_pool_status(task.scan_id, {
                "global_running": 1,
                "models": [{"id": "model", "model": "provider/model", "max_concurrency": 1,
                            "running": 1, "active_tasks": [{"task_id": "new-task", "started_at": new_started_at}]}],
            })
            running, meta = env.store.load_scan(task.scan_id)
            assert meta.execution_revision == 9
            assert running.opencode_pool.models[0].active_tasks[0]["started_at"] == new_started_at
            assert running.opencode_pool.completed_tasks[0]["task_id"] == "old"
            # A delayed request from the previous execution stays rejected.
            stale = await reporter._client.post(
                f"http://server/api/agent/scan/{task.scan_id}/opencode-pool",
                json={"agent_session_id": "session", "execution_revision": 8},
            )
            assert stale.status_code == 409
            result = Vulnerability(
                file="todo.c", line=1, function="f", vuln_type="npd", severity="low",
                description="guarded", confirmed=False, ai_verdict="false_positive",
            )
            progress = await reporter.report_candidate_audit(
                task.scan_id, 1, state="success", result=result, completed_candidates=2, total_candidates=2,
            )
            assert progress["processed"] == 2
            assert env.store.load_scan(task.scan_id)[0].processed_candidates == 2
            await reporter.finish_scan(task.scan_id, [], "complete", 2, 2)

        monkeypatch.setattr(server, "_run_scan", execute)
        try:
            await agent_main._handle_command(command, None, manager, reporter)
            await manager.get("resume-scan").asyncio_task
            scan, meta = env.store.load_scan("resume-scan")
            assert scan.status == ScanItemStatus.COMPLETE
            assert scan.progress == 1.0 and scan.processed_candidates == 2
            assert meta.execution_revision == 9
            assert scan.created_at == "2026-09-01T00:00:00+00:00"
            assert env.store.get_processed_candidate_indexes("resume-scan") == {0, 1}
            finish_events = [call.args[2] for call in published.call_args_list if call.args[1] == "scan_finish"]
            assert finish_events[-1]["execution_revision"] == 9
        finally:
            await reporter.close()

    asyncio.run(run())
