"""Independent review work remains visible after the parent scan terminates."""

import asyncio
import os
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend.api.agent import agent_push_opencode_pool
from backend.models import OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def store(tmp_path, request):
    if request.param == "postgres":
        from backend.store.postgres import PostgresScanStore

        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        value = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        value = SqliteScanStore(tmp_path / "scans.db")
    value.save_scan(
        ScanStatus(scan_id="scan", project_id="project", scan_items=[], created_at="2026-09-23T00:00:00Z", status=ScanItemStatus.AUDITING,
                   progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-09-23T00:00:00Z", project_path="/repo", scan_name="scan", user_id="user"),
    )
    value._conn.execute("UPDATE scans SET execution_revision = 7, execution_agent_session_id = 'old-agent' WHERE scan_id = 'scan'")
    value._conn.commit()
    value.create_fp_review_job("review", "scan", 3, "2026-09-23T00:00:00Z")
    value.acquire_fp_review_execution("review", agent_session_id="review-agent")
    value.update_fp_review_job("review", status="running")
    try:
        yield value
    finally:
        value._conn.execute("DELETE FROM fp_review_jobs WHERE review_id = 'review'")
        value._conn.execute("DELETE FROM scans WHERE scan_id = 'scan'")
        value._conn.commit()
        value.close()


def pool():
    owner = {"execution_kind": "fp_review", "execution_id": "review", "execution_revision": 1, "agent_session_id": "review-agent", "task_type": "fp_review"}
    return OpenCodePoolStatus(
        scope_id="scan", agent_session_id="review-agent", execution_revision=7,
        execution_owner={"kind": "fp_review", "id": "review", "revision": 1},
        global_running=2, global_queued=1, total_tasks=5, completed_task_count=1,
        models=[{"id": "model", "model": "p/m", "running": 2, "active_tasks": [
            {**owner, "task_id": "review-running"},
            {"task_id": "old-scan-task", "execution_kind": "scan", "execution_id": "scan", "execution_revision": 7, "agent_session_id": "old-agent"},
        ]}],
        queued_tasks=[{**owner, "request_id": "review-queued"}],
        planned_tasks=[{**owner, "planned_task_id": "review-planned"}],
        completed_tasks=[{"task_id": "history", "outcome": "success"}],
        updated_at="2026-09-23T01:00:00Z",
    )


def assert_review_visible(status):
    assert status.global_running == 1
    assert status.global_queued == 1
    assert [task["task_id"] for task in status.models[0].active_tasks] == ["review-running"]
    assert len(status.queued_tasks) == len(status.planned_tasks) == 1
    assert status.completed_task_count == 1


def test_recovery_claims_and_failures_preserve_review_and_reject_old_owner(store):
    from backend.scan_runtime import AGENT_RECOVERY_IN_PROGRESS, AGENT_RECOVERY_FAILED_PREFIX
    store.update_scan_agent("scan", "agent", "agent", "stable")
    store.persist_opencode_pool("scan", pool())
    revision = store.claim_scan_for_agent_recovery(
        "scan", previous_session_id="old-agent", agent_id="agent", agent_session_id="new-agent",
        expected_revision=7, error_message=AGENT_RECOVERY_IN_PROGRESS,
    )
    assert revision == 8
    assert_review_visible(store.get_opencode_pool_status("scan"))
    assert store.fail_scan_recovery("scan", agent_session_id="new-agent", execution_revision=8,
                                    error_message=AGENT_RECOVERY_FAILED_PREFIX + "temporary failure")
    assert_review_visible(store.get_opencode_pool_status("scan"))
    assert [row["scan_id"] for row in store.list_agent_inflight_executions("stable", "agent")["scans"]] == ["scan"]
    assert store.claim_scan_for_agent_recovery(
        "scan", previous_session_id="new-agent", agent_id="agent", agent_session_id="next-agent",
        expected_revision=8, error_message=AGENT_RECOVERY_IN_PROGRESS,
    ) == 9
    assert not store.fail_scan_recovery("scan", agent_session_id="new-agent", execution_revision=8,
                                       error_message="late failure")
    store.update_scan_progress("scan", status=ScanItemStatus.CANCELLED, error_message="用户手动停止")
    assert not store.fail_scan_recovery("scan", agent_session_id="next-agent", execution_revision=9,
                                       error_message=AGENT_RECOVERY_FAILED_PREFIX + "late failure")
    assert not store.list_agent_inflight_executions("stable", "agent")["scans"]


def test_legacy_interrupted_recovery_is_selected_again(store):
    from backend.scan_runtime import AGENT_RECOVERY_IN_PROGRESS
    store.update_scan_agent("scan", "agent", "agent", "stable")
    store.update_scan_progress("scan", status=ScanItemStatus.CANCELLED, error_message=AGENT_RECOVERY_IN_PROGRESS)
    rows = store.list_agent_inflight_executions("stable", "agent")["scans"]
    assert [row["scan_id"] for row in rows] == ["scan"]
    assert store.claim_scan_for_agent_recovery(
        "scan", previous_session_id="old-agent", agent_id="agent", agent_session_id="new-agent",
        expected_revision=6, error_message=AGENT_RECOVERY_IN_PROGRESS,
    ) is None
    assert store.claim_scan_for_agent_recovery(
        "scan", previous_session_id="old-agent", agent_id="agent", agent_session_id="new-agent",
        expected_revision=7, error_message=AGENT_RECOVERY_IN_PROGRESS,
    ) == 8


def test_reserved_recovery_cannot_resume_wrong_session_or_user_stopped_scan(store):
    from backend.scan_runtime import AGENT_RECOVERY_IN_PROGRESS
    revision = store.claim_scan_for_agent_recovery(
        "scan", previous_session_id="old-agent", agent_id="agent", agent_session_id="new-agent",
        expected_revision=7, error_message=AGENT_RECOVERY_IN_PROGRESS,
    )
    for session in ("stale-agent", "new-agent"):
        if session == "new-agent":
            store.update_scan_progress("scan", status=ScanItemStatus.CANCELLED, error_message="用户手动停止")
        assert store.claim_scan_for_resume(
            "scan", expected_revision=revision, claimed_revision=revision,
            agent_id="agent", agent_session_id=session, processed_candidates=0, progress=0,
        ) is None
    scan, meta = store.load_scan("scan")
    assert scan.status == "cancelled" and scan.error_message == "用户手动停止"
    assert meta.execution_revision == revision


def test_failed_review_recovery_stays_retryable_and_does_not_override_user_stop(store):
    from backend.scan_runtime import AGENT_RECOVERY_FAILED_PREFIX
    store.update_scan_agent("scan", "agent", "agent", "stable")
    assert store.fail_fp_review_recovery("review", agent_session_id="review-agent", execution_revision=1,
                                         error_message=AGENT_RECOVERY_FAILED_PREFIX + "offline")
    assert [row["review_id"] for row in store.list_agent_inflight_executions("stable", "agent")["fp_reviews"]] == ["review"]
    assert store.claim_fp_review_for_agent_recovery("review", previous_session_id="review-agent", agent_session_id="new-agent") == 2
    assert not store.fail_fp_review_recovery("review", agent_session_id="review-agent", execution_revision=1, error_message="late")
    store.update_fp_review_job("review", status="cancelled", error_message="用户手动停止")
    assert not store.fail_fp_review_recovery("review", agent_session_id="new-agent", execution_revision=2, error_message="late")


@pytest.mark.parametrize("terminal", [ScanItemStatus.COMPLETE, ScanItemStatus.ERROR, ScanItemStatus.CANCELLED])
def test_terminal_scan_preserves_only_current_review_on_write_and_read(store, terminal):
    store.persist_opencode_pool("scan", pool())
    store.update_scan_progress("scan", status=terminal)
    assert_review_visible(store.get_opencode_pool_status("scan"))
    loaded, _ = store.load_scan("scan")
    assert loaded.status == terminal
    assert_review_visible(loaded.opencode_pool)
    assert_review_visible(store.load_scan_overview("scan")[0].opencode_pool)
    assert_review_visible(store.load_scan_runtime("scan")[0].opencode_pool)
    store.persist_opencode_pool("scan", pool())
    assert_review_visible(store.get_opencode_pool_status("scan"))
    store.update_fp_review_job("review", status="complete")
    status = store.get_opencode_pool_status("scan")
    assert status.global_running == status.global_queued == 0
    assert status.planned_tasks == []


async def direct_store_call(store, operation, *args, **kwargs):
    return getattr(store, operation)(*args, **kwargs)


def test_review_owner_after_agent_restart_is_accepted_and_sse_keeps_scan_revision(store):
    store.update_scan_progress("scan", status=ScanItemStatus.COMPLETE)
    value = pool()
    value.execution_revision = 0  # A review-only Agent never received the old scan dispatch.
    with patch("backend.api.agent.get_scan_store", return_value=store), patch("backend.api.agent.run_store_call", direct_store_call), patch("backend.sse.publish") as publish:
        assert asyncio.run(agent_push_opencode_pool("scan", value)) == {"ok": True}
    event = publish.call_args.args[2]
    assert event["execution_revision"] == event["opencode_pool"]["execution_revision"] == 7
    assert event["opencode_pool"]["global_running"] == 1
    assert_review_visible(store.get_opencode_pool_status("scan"))


def test_old_review_revision_cannot_restore_live_work(store):
    store.update_scan_progress("scan", status=ScanItemStatus.COMPLETE)
    store.persist_opencode_pool("scan", pool())
    store.acquire_fp_review_execution("review", agent_session_id="review-agent", force_new=True)
    assert store.get_opencode_pool_status("scan").global_running == 0
    with patch("backend.api.agent.get_scan_store", return_value=store), patch("backend.api.agent.run_store_call", direct_store_call):
        with pytest.raises(HTTPException) as caught:
            asyncio.run(agent_push_opencode_pool("scan", pool()))
    assert caught.value.status_code == 409


def test_parent_resume_does_not_clear_an_independent_active_review(store):
    store.persist_opencode_pool("scan", pool())
    store.update_scan_progress("scan", status=ScanItemStatus.COMPLETE)
    revision = store.claim_scan_for_resume("scan", processed_candidates=0, progress=0, agent_id="agent", agent_session_id="new-scan-agent", expected_revision=7)
    assert revision == 8
    assert_review_visible(store.get_opencode_pool_status("scan"))
    assert store.fail_scan_execution("scan", agent_session_id="new-scan-agent", execution_revision=8, error_message="resume failed")
    assert_review_visible(store.get_opencode_pool_status("scan"))
