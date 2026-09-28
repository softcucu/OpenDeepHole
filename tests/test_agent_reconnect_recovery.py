import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentCandidateAuditResult,
    AgentFpReviewStageOutput,
    AgentInfo,
    AgentMcpConfig,
    AgentMcpRemoteConfig,
    AgentProcessedKeyBatch,
    AgentScanCandidateBatch,
    AgentScanCandidates,
    AgentScanEventBatch,
    AgentScanFinish,
    AgentScanFinishV2,
    AgentVulnerabilityReconcile,
    Candidate,
    FpReviewResult,
    FpReviewStatus,
    MiningEngineRunStatus,
    MiningEngineSelection,
    OpenCodePoolStatus,
    ScanCandidate,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAuditTask,
    ThreatAnalysisRunStatus,
    User,
    Vulnerability,
    VulnerabilityValidation,
)
from backend.store.sqlite import SqliteScanStore


def _scan(
    scan_id: str,
    status: ScanItemStatus,
    *,
    total: int = 0,
    processed: int = 0,
    error: str | None = None,
) -> ScanStatus:
    return ScanStatus(
        scan_id=scan_id,
        project_id="project",
        scan_items=["memleak"],
        created_at="2026-01-01T00:00:00+00:00",
        status=status,
        progress=(processed / total) if total else 0.0,
        total_candidates=total,
        processed_candidates=processed,
        vulnerabilities=[],
        error_message=error,
    )


def _meta(
    *,
    agent_id: str = "agent-old",
    agent_name: str = "agent-1",
    user_id: str = "user-1",
) -> ScanMeta:
    return ScanMeta(
        scan_items=["memleak"],
        created_at="2026-01-01T00:00:00+00:00",
        agent_id=agent_id,
        agent_name=agent_name,
        project_path="/repo/project",
        scan_name="project",
        user_id=user_id,
    )


async def _run_websocket_and_cancel_disconnect(websocket) -> None:
    await agent_api.agent_websocket(websocket)
    tasks = list(agent_api._agent_disconnect_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


class AgentReconnectRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_disconnect_tasks.clear()
        agent_api._scan_index_statuses.clear()
        agent_api._scan_stop_waiters.clear()

    def tearDown(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_disconnect_tasks.clear()
        agent_api._scan_index_statuses.clear()
        agent_api._scan_stop_waiters.clear()

    def test_execution_recovery_claims_are_monotonic_and_single_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            meta = _meta().model_copy(update={"agent_key": "stable-agent"})
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING), meta)

            scan_revision = store.begin_scan_execution(
                "scan-1",
                agent_id="agent-old",
                agent_session_id="session-old",
            )
            self.assertEqual(scan_revision, 1)
            store.mark_agent_scans_cancelled(
                "agent-old",
                agent_api.AGENT_DISCONNECT_ERROR,
            )
            inflight = store.list_agent_inflight_executions(
                "stable-agent",
                "agent-new",
            )
            self.assertEqual([row["scan_id"] for row in inflight["scans"]], ["scan-1"])

            resumed_revision = store.claim_scan_for_agent_recovery(
                "scan-1",
                previous_session_id="session-old",
                agent_id="agent-new",
                agent_session_id="session-new",
                error_message="Agent 进程已重启，正在自动断点恢复",
            )
            self.assertEqual(resumed_revision, 2)
            self.assertIsNone(store.claim_scan_for_agent_recovery(
                "scan-1",
                previous_session_id="session-old",
                agent_id="agent-newer",
                agent_session_id="session-newer",
                error_message="duplicate recovery",
            ))
            self.assertFalse(store.execution_matches(
                "scan",
                "scan-1",
                None,
                agent_session_id="session-old",
                execution_revision=1,
            ))
            self.assertTrue(store.execution_matches(
                "scan",
                "scan-1",
                None,
                agent_session_id="session-new",
                execution_revision=2,
            ))

            store.create_fp_review_job(
                "review-1",
                "scan-1",
                1,
                "2026-01-01T00:00:00+00:00",
            )
            self.assertEqual(store.begin_fp_review_execution(
                "review-1",
                agent_session_id="session-old",
            ), 1)
            store.mark_fp_reviews_for_agent_error(
                "agent-new",
                agent_api.AGENT_DISCONNECT_ERROR,
            )
            inflight = store.list_agent_inflight_executions(
                "stable-agent",
                "agent-new",
            )
            self.assertEqual(
                [row["review_id"] for row in inflight["fp_reviews"]],
                ["review-1"],
            )
            self.assertEqual(store.claim_fp_review_for_agent_recovery(
                "review-1",
                previous_session_id="session-old",
                agent_session_id="session-new",
            ), 2)
            self.assertIsNone(store.claim_fp_review_for_agent_recovery(
                "review-1",
                previous_session_id="session-old",
                agent_session_id="session-newer",
            ))

            store.upsert_vulnerability_validation(
                "scan-1",
                VulnerabilityValidation(
                    scan_id="scan-1",
                    vuln_index=0,
                    status="running",
                    running=True,
                ),
            )
            self.assertEqual(store.begin_validation_execution(
                "scan-1",
                0,
                agent_session_id="session-old",
            ), 1)
            self.assertEqual(store.claim_validation_for_agent_recovery(
                "scan-1",
                0,
                previous_session_id="session-old",
                agent_session_id="session-new",
            ), 2)
            self.assertIsNone(store.claim_validation_for_agent_recovery(
                "scan-1",
                0,
                previous_session_id="session-old",
                agent_session_id="session-newer",
            ))
            store.close()

    def test_active_execution_adoption_preserves_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.AUDITING),
                _meta().model_copy(update={"agent_key": "stable-agent"}),
            )
            self.assertEqual(store.begin_scan_execution(
                "scan-1",
                agent_id="agent-old",
                agent_session_id="session-old",
            ), 1)
            self.assertTrue(store.adopt_active_execution(
                "scan",
                "scan-1",
                None,
                previous_session_id="session-old",
                agent_session_id="session-new",
            ))
            persisted = store.get_scan_meta("scan-1")
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.execution_revision, 1)
            self.assertEqual(persisted.execution_agent_session_id, "session-new")
            store.close()

    def test_missing_fp_review_inventory_dispatches_unresolved_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.COMPLETE, total=1, processed=1),
                _meta().model_copy(update={"agent_key": "stable-agent"}),
            )
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="issue.c",
                    line=10,
                    function="parse",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed finding",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
            )
            store.create_fp_review_job(
                "review-1",
                "scan-1",
                1,
                "2026-01-01T00:00:00+00:00",
            )
            store.update_fp_review_job("review-1", status="running")
            self.assertEqual(store.begin_fp_review_execution(
                "review-1",
                agent_session_id="session-old",
            ), 1)
            agent = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                agent_session_id="session-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            start_review = AsyncMock()

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.api.scan._start_fp_review", new=start_review),
            ):
                asyncio.run(agent_api._recover_missing_agent_work(
                    "agent-new",
                    agent,
                    {},
                    server_url="http://server",
                ))

            start_review.assert_awaited_once_with(
                "scan-1",
                "http://server",
                raise_on_error=True,
                require_unresolved=True,
                claimed_execution_revision=2,
            )
            job = store.get_fp_review_job("review-1")
            self.assertEqual(job.execution_agent_session_id, "session-new")
            self.assertEqual(job.execution_revision, 2)
            store.close()

    def test_recovered_fp_review_with_persisted_result_only_closes_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.COMPLETE, total=1, processed=1),
                _meta().model_copy(update={"agent_key": "stable-agent"}),
            )
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="issue.c",
                    line=10,
                    function="parse",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed finding",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
            )
            store.create_fp_review_job(
                "review-1",
                "scan-1",
                1,
                "2026-01-01T00:00:00+00:00",
            )
            store.add_fp_review_result(
                "review-1",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="final result already persisted",
                    created_at="2026-01-01T00:00:30+00:00",
                ),
            )
            store.update_fp_review_job("review-1", status="running")
            store.begin_fp_review_execution(
                "review-1",
                agent_session_id="session-old",
            )
            revision = store.claim_fp_review_for_agent_recovery(
                "review-1",
                previous_session_id="session-old",
                agent_session_id="session-new",
            )
            agent = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                agent_session_id="session-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-new"),
                ),
                patch(
                    "backend.api.agent.resolve_agent_id_connection_async",
                    new=AsyncMock(return_value=("agent-new", agent)),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                result = asyncio.run(scan_api._start_fp_review(
                    "scan-1",
                    "http://server",
                    raise_on_error=False,
                    require_unresolved=True,
                    claimed_execution_revision=revision,
                ))

            self.assertEqual(result["status"], "complete")
            send.assert_not_awaited()
            job = store.get_fp_review_job("review-1")
            self.assertEqual(job.status, FpReviewStatus.COMPLETE)
            self.assertEqual(job.processed, 1)
            self.assertIsNone(job.current_vuln_index)
            store.close()

    def test_missing_scan_inventory_dispatches_checkpoint_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.AUDITING),
                _meta().model_copy(update={"agent_key": "stable-agent"}),
            )
            store.begin_scan_execution(
                "scan-1",
                agent_id="agent-old",
                agent_session_id="session-old",
            )
            agent = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                agent_session_id="session-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            resume = AsyncMock()

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.api.scan._continue_scan", new=resume),
            ):
                asyncio.run(agent_api._recover_missing_agent_work(
                    "agent-new",
                    agent,
                    {},
                    server_url="http://server",
                ))

            resume.assert_awaited_once()
            self.assertEqual(
                resume.await_args.kwargs["claimed_execution_revision"],
                2,
            )
            persisted = store.get_scan_meta("scan-1")
            self.assertEqual(persisted.execution_agent_session_id, "session-new")
            self.assertEqual(persisted.execution_revision, 2)
            store.close()

    def test_pending_terminal_scan_report_defers_recovery_without_new_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.AUDITING),
                _meta().model_copy(update={"agent_key": "stable-agent"}),
            )
            store.begin_scan_execution(
                "scan-1",
                agent_id="agent-old",
                agent_session_id="session-old",
            )
            agent = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                agent_session_id="session-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            resume = AsyncMock()

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.api.scan._continue_scan", new=resume),
            ):
                asyncio.run(agent_api._recover_missing_agent_work(
                    "agent-new",
                    agent,
                    {"pending_terminal_reports": {"scans": ["scan-1"]}},
                    server_url="http://server",
                ))

            resume.assert_not_awaited()
            persisted = store.get_scan_meta("scan-1")
            self.assertEqual(persisted.execution_agent_session_id, "session-old")
            self.assertEqual(persisted.execution_revision, 1)
            store.close()

    def test_agent_vulnerability_dedup_context_is_paginated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.AUDITING),
                _meta(),
            )
            for line in (10, 20):
                store.add_vulnerability(
                    "scan-1",
                    Vulnerability(
                        file="src/a.c",
                        line=line,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description="null dereference",
                        vulnerability_report=f"# report {line}",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                )

            with (
                patch(
                    "backend.api.agent.get_scan_store",
                    return_value=store,
                ),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                first = asyncio.run(agent_api.agent_list_vulnerabilities(
                    "scan-1",
                    limit=1,
                    after=-1,
                ))
                second = asyncio.run(agent_api.agent_list_vulnerabilities(
                    "scan-1",
                    limit=1,
                    after=first.next_cursor if first.next_cursor is not None else -1,
                ))

            store.close()

        self.assertTrue(first.has_more)
        self.assertEqual(first.next_cursor, 0)
        self.assertEqual(first.items[0].vulnerability.line, 10)
        self.assertFalse(second.has_more)
        self.assertEqual(second.items[0].vulnerability.line, 20)

    def test_agent_websocket_heartbeat_gets_ack(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [
                    {"type": "hello", "name": "agent-1", "active_scans": []},
                    {"type": "heartbeat"},
                ]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_websocket(ws))

        self.assertEqual(ws.sent[0]["type"], "welcome")
        self.assertIn({"type": "heartbeat_ack"}, ws.sent)

    def test_agent_websocket_stores_reported_runtime_hash(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.captured_runtime_hash = ""
                self.messages = [
                    {
                        "type": "hello",
                        "name": "agent-1",
                        "runtime_hash": "old-runtime",
                        "active_scans": [],
                    },
                ]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                agents = list(agent_api._registered_agents.values())
                if agents:
                    self.captured_runtime_hash = agents[0].runtime_hash
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_websocket(ws))

        self.assertEqual(ws.captured_runtime_hash, "old-runtime")

    def test_new_client_discards_reported_models_until_user_configures_it(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [{
                    "type": "hello",
                    "name": "new-client",
                    "machine_name": "new-machine",
                    "active_scans": [],
                    "config": {
                        "model_pool": {
                            "models": [{
                                "id": "reported",
                                "model": "provider/reported",
                                "enabled": True,
                            }],
                        },
                    },
                }]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
            ):
                asyncio.run(_run_websocket_and_cancel_disconnect(ws))
            record = store.list_agent_records()[0]
            stored_config = json.loads(record["config_json"])
            store.close()

        self.assertEqual(ws.sent[0]["config"]["model_pool"]["models"], [])
        self.assertEqual(stored_config["model_pool"]["models"], [])

    def test_existing_client_preserves_persisted_models_on_reconnect(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [{
                    "type": "hello",
                    "name": "existing-client",
                    "machine_name": "existing-machine",
                    "active_scans": [],
                    "config": {"model_pool": {"models": []}},
                }]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_record(
                agent_key="stable-client",
                user_id="",
                ip="127.0.0.1",
                machine_name="existing-machine",
                display_name="existing-client",
                agent_id="old-session",
                last_seen="2026-01-01T00:00:00+00:00",
                initial_config_json=json.dumps({
                    "model_pool": {
                        "models": [{
                            "id": "persisted",
                            "model": "provider/persisted",
                            "enabled": True,
                        }],
                    },
                }),
            )
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
            ):
                asyncio.run(_run_websocket_and_cancel_disconnect(ws))
            record = store.get_agent_record("stable-client")
            store.close()

        models = ws.sent[0]["config"]["model_pool"]["models"]
        self.assertEqual(models[0]["model"], "provider/persisted")
        persisted_models = json.loads(record["config_json"])["model_pool"]["models"]
        self.assertEqual(persisted_models[0]["model"], "provider/persisted")

    def test_websocket_agent_online_requires_fresh_last_seen(self) -> None:
        fresh = datetime.now(timezone.utc).isoformat()
        stale = (
            datetime.now(timezone.utc)
            - timedelta(seconds=agent_api._WEBSOCKET_AGENT_STALE_SECONDS + 1)
        ).isoformat()
        agent_api._agent_ws["fresh"] = object()
        agent_api._agent_ws["stale"] = object()

        self.assertTrue(agent_api._is_agent_online(AgentInfo(
            agent_id="fresh",
            name="agent-1",
            ip="127.0.0.1",
            last_seen=fresh,
        )))
        self.assertFalse(agent_api._is_agent_online(AgentInfo(
            agent_id="stale",
            name="agent-1",
            ip="127.0.0.1",
            last_seen=stale,
        )))

    def test_startup_recovery_leaves_agent_owned_running_scans_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("agent-scan", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.save_scan(
                _scan("server-scan", ScanItemStatus.AUDITING, total=5, processed=2),
                _meta(agent_id="", agent_name="", user_id=""),
            )

            recovered = store.mark_running_as_error()

            self.assertEqual(recovered, 1)
            self.assertEqual(store.load_scan("agent-scan")[0].status, ScanItemStatus.AUDITING)
            server_scan = store.load_scan("server-scan")[0]
            self.assertEqual(server_scan.status, ScanItemStatus.ERROR)
            self.assertEqual(server_scan.error_message, "Process terminated unexpectedly")

    def test_agent_disconnect_cancels_persisted_agent_scan_and_fp_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                agent_api._mark_agent_scans_cancelled("agent-old")

            scan = store.load_scan("scan-1")[0]
            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertEqual(scan.error_message, "Agent 断开连接")
            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.ERROR)
            self.assertEqual(review.error_message, "Agent 断开连接")

    def test_disconnect_cleanup_drops_terminal_stale_local_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            persisted = _scan(
                "scan-1",
                ScanItemStatus.CANCELLED,
                total=5,
                processed=2,
                error="Agent 断开连接",
            )
            store.save_scan(persisted, _meta())
            stale_live = persisted.model_copy(deep=True)
            stale_live.status = ScanItemStatus.AUDITING
            agent_api._running_scans["scan-1"] = stale_live
            agent_api._scan_owners["scan-1"] = "user-1"

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                agent_api._mark_agent_scans_cancelled("agent-old")

            self.assertNotIn("scan-1", agent_api._running_scans)
            self.assertNotIn("scan-1", agent_api._scan_owners)
            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            self.assertEqual(stored.error_message, "Agent 断开连接")

    def test_offline_agent_status_query_cancels_stale_running_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")
            user = User(user_id="user-1", username="alice", role="user")
            started_at = (
                datetime.now(timezone.utc)
                - timedelta(seconds=agent_api._AGENT_DISCONNECT_GRACE_SECONDS + 1)
            )

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent._SERVER_STARTED_AT", started_at),
            ):
                scan = asyncio.run(scan_api.get_scan_status("scan-1", current_user=user))

            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertFalse(scan.agent_online)
            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.ERROR)

    def test_active_scan_hello_reattaches_disconnect_cancelled_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=8,
                    processed=3,
                    error="Agent 断开连接",
                ),
                _meta(),
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_agent_scans(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "project_path": "/repo/project"}],
                )

            scan, meta = store.load_scan("scan-1")
            self.assertEqual(meta.agent_id, "agent-new")
            self.assertEqual(scan.status, ScanItemStatus.AUDITING)
            self.assertEqual(scan.error_message, "")
            self.assertIn("scan-1", agent_api._running_scans)

    def test_active_scan_hello_does_not_revive_user_stopped_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=8,
                    processed=3,
                    error="用户手动停止",
                ),
                _meta(),
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            pending_stops: list[dict] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                agent_api._reattach_active_agent_scans(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1"}],
                    pending_stops,
                )

            scan, meta = store.load_scan("scan-1")
            self.assertEqual(meta.agent_id, "agent-old")
            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertNotIn("scan-1", agent_api._running_scans)
            self.assertEqual(
                pending_stops,
                [{"type": "stop", "scan_id": "scan-1"}],
            )

    def test_scan_stop_request_waits_for_matching_agent_ack(self) -> None:
        sent: list[dict] = []

        async def send(agent_id: str, command: dict) -> bool:
            self.assertEqual(agent_id, "agent-live")
            sent.append(command)
            await agent_api._complete_agent_response(
                {
                    "type": "scan_stop_result",
                    "request_id": command["request_id"],
                    "scan_id": command["scan_id"],
                    "still_active": False,
                    "error": "",
                },
                agent_api._scan_stop_waiters,
            )
            return True

        with (
            patch("backend.api.agent.send_agent_command", new=send),
            patch(
                "backend.api.agent.get_scan_store",
                side_effect=AssertionError(
                    "same-worker acknowledgement must not consult the store"
                ),
            ),
        ):
            response = asyncio.run(
                agent_api.request_agent_scan_stop("agent-live", "scan-1")
            )

        self.assertIsNotNone(response)
        self.assertFalse(response["still_active"])
        self.assertEqual(sent[0]["type"], "stop")
        self.assertEqual(sent[0]["scan_id"], "scan-1")
        self.assertEqual(agent_api._scan_stop_waiters, {})

    def test_upgraded_agent_promotes_existing_callback_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-upgrade", ScanItemStatus.AUDITING)
            meta = _meta()
            meta.agent_key = "stable-agent"
            store.save_scan(scan, meta)
            vuln_index = store.add_provisional_vulnerability(
                scan.scan_id,
                "legacy-batch",
                Vulnerability(
                    file="src/parser.c",
                    line=42,
                    function="parse",
                    vuln_type="overflow",
                    severity="high",
                    description="reported before Agent upgrade",
                    vulnerability_report="# Existing report",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
            )
            agent_api._running_scans[scan.scan_id] = scan
            info = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.sse.publish") as publish,
            ):
                scan_ids, promoted = asyncio.run(
                    agent_api._promote_final_callback_agent_reports(
                        "agent-new",
                        info,
                        [scan.scan_id],
                    )
                )

            self.assertEqual(scan_ids, [scan.scan_id])
            self.assertEqual(promoted, {scan.scan_id: [vuln_index]})
            stored = store.get_vulnerabilities(scan.scan_id)[vuln_index]
            self.assertFalse(stored.provisional)
            row = store._conn.execute(
                "SELECT report_batch_id FROM vulnerabilities "
                "WHERE scan_id = ? AND idx = ?",
                (scan.scan_id, vuln_index),
            ).fetchone()
            self.assertEqual(row["report_batch_id"], "")
            self.assertFalse(
                agent_api._running_scans[scan.scan_id]
                .vulnerabilities[vuln_index]
                .provisional
            )
            publish.assert_called_once_with(
                scan.scan_id,
                "scan_vulnerabilities_changed",
                {"count": 1},
            )

    def test_upgrade_recovery_resumes_unresolved_fp_review_but_not_user_stop(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-upgrade", ScanItemStatus.AUDITING)
            scan.auto_fp_review = True
            meta = _meta(agent_id="agent-new")
            meta.agent_key = "stable-agent"
            meta.auto_fp_review = True
            store.save_scan(scan, meta)
            store.add_vulnerability(
                scan.scan_id,
                Vulnerability(
                    file="src/parser.c",
                    line=42,
                    function="parse",
                    vuln_type="overflow",
                    severity="high",
                    description="confirmed issue",
                    vulnerability_report="# Existing report",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
            )
            info = AgentInfo(
                agent_id="agent-new",
                agent_key="stable-agent",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            start_fp_review = AsyncMock(return_value={"ok": True})

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch(
                    "backend.api.scan._start_fp_review",
                    start_fp_review,
                ),
            ):
                asyncio.run(agent_api._resume_final_callback_downstream(
                    info,
                    [scan.scan_id],
                    {scan.scan_id: [0]},
                    server_url="http://server",
                ))
                start_fp_review.assert_awaited_once_with(
                    scan.scan_id,
                    "http://server",
                    raise_on_error=False,
                    require_unresolved=True,
                    allow_cancelled=False,
                )

                store.update_scan_progress(
                    scan.scan_id,
                    status=ScanItemStatus.CANCELLED,
                    error_message="用户手动停止",
                )
                start_fp_review.reset_mock()
                asyncio.run(agent_api._resume_final_callback_downstream(
                    info,
                    [scan.scan_id],
                    {scan.scan_id: [0]},
                    server_url="http://server",
                ))
                start_fp_review.assert_not_awaited()

    def test_callback_capability_recovers_only_after_welcome(self) -> None:
        recovered = asyncio.Event()

        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()
            base_url = "ws://server/"

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [{
                    "type": "hello",
                    "name": "agent-1",
                    "machine_name": "agent-machine",
                    "capabilities": {
                        "final_vulnerability_callbacks": True,
                    },
                    "active_scans": [],
                }]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                await recovered.wait()
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        websocket = FakeWebSocket()
        promote = AsyncMock(return_value=([], {}))

        async def resume(*_args, **kwargs) -> None:
            self.assertEqual(websocket.sent[0]["type"], "welcome")
            self.assertEqual(kwargs["server_url"], "http://server")
            recovered.set()

        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch(
                    "backend.api.agent._promote_final_callback_agent_reports",
                    promote,
                ),
                patch(
                    "backend.api.agent._resume_final_callback_downstream",
                    new=AsyncMock(side_effect=resume),
                ) as resume_mock,
                patch("backend.api.agent._schedule_agent_disconnect_cancel"),
            ):
                asyncio.run(asyncio.wait_for(
                    agent_api.agent_websocket(websocket),
                    timeout=1,
                ))

        promote.assert_awaited_once()
        resume_mock.assert_awaited_once()

    def test_static_analysis_event_updates_total_from_candidate_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            event = ScanEvent.create("static_analysis", "已加载 7 个缓存候选点", candidate_index=7)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.total_candidates, 7)
            self.assertEqual(stored.status, ScanItemStatus.ANALYZING)

    def test_task_output_event_is_discarded_before_scan_state_and_sse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data)
                    ),
                ),
            ):
                for message in (
                    "[threat_analysis][session-1][tool] name=read path=src/a.c",
                    "[threat_analysis][session-1][step] TOOL START",
                    "[2026-08-03 12:00:00] "
                    "[candidate_audit][session-2][task] START",
                ):
                    result = asyncio.run(agent_api.agent_scan_event(
                        "scan-1",
                        ScanEvent.create("auditing", message),
                    ))
                    self.assertEqual(result, {"ok": True, "discarded": True})

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(store.get_events("scan-1"), [])
            self.assertEqual(published, [])

    def test_missing_single_event_returns_structured_scan_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.object(agent_api.logger, "warning") as warning,
                patch("backend.sse.publish") as publish,
            ):
                with self.assertRaises(agent_api.HTTPException) as raised:
                    asyncio.run(agent_api.agent_scan_event(
                        "missing-scan",
                        ScanEvent.create("auditing", "late event"),
                    ))

            self.assertEqual(raised.exception.status_code, 404)
            self.assertEqual(
                raised.exception.detail,
                {
                    "code": "scan_not_found",
                    "scan_id": "missing-scan",
                    "endpoint": "event",
                },
            )
            warning.assert_called_once()
            publish.assert_not_called()
            self.assertEqual(store.get_events("missing-scan"), [])

    def test_missing_event_batch_returns_structured_scan_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.object(agent_api.logger, "warning") as warning,
                patch("backend.sse.publish") as publish,
            ):
                with self.assertRaises(agent_api.HTTPException) as raised:
                    asyncio.run(agent_api.agent_scan_events_v2(
                        "missing-scan",
                        AgentScanEventBatch(events=[
                            ScanEvent.create("auditing", "late event"),
                        ]),
                    ))

            self.assertEqual(raised.exception.status_code, 404)
            self.assertEqual(
                raised.exception.detail,
                {
                    "code": "scan_not_found",
                    "scan_id": "missing-scan",
                    "endpoint": "events",
                },
            )
            warning.assert_called_once()
            publish.assert_not_called()
            self.assertEqual(store.get_events("missing-scan"), [])

    def test_event_batch_for_terminal_scan_is_persisted_without_reviving_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan("scan-1", ScanItemStatus.COMPLETE),
                _meta(),
            )
            events = [
                ScanEvent.create("auditing", "late event one"),
                ScanEvent.create("auditing", "late event two"),
            ]
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.sse.publish") as publish,
            ):
                result = asyncio.run(agent_api.agent_scan_events_v2(
                    "scan-1",
                    AgentScanEventBatch(events=events),
                ))

            self.assertEqual(result, {"ok": True, "count": 2})
            self.assertEqual(
                [event.message for event in store.get_events("scan-1")],
                ["late event one", "late event two"],
            )
            self.assertEqual(
                store.load_scan("scan-1")[0].status,
                ScanItemStatus.COMPLETE,
            )
            self.assertNotIn("scan-1", agent_api._running_scans)
            publish.assert_not_called()

    def test_auditing_event_marks_static_analysis_done_if_done_push_was_missed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=3)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            scan.static_analysis_done = False
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            event = ScanEvent.create("auditing", "[1/3] NPD a.c:1 — f", candidate_index=0)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertTrue(status_events[-1]["static_analysis_done"])

    def test_auditing_event_does_not_advance_processed_count_from_candidate_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=20, processed=4)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            event = ScanEvent.create("auditing", "[10/20] NPD z.c:1 — z", candidate_index=9)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertEqual(stored.processed_candidates, 4)
            self.assertEqual(stored.progress, 0.2)

    def test_static_progress_done_moves_scan_to_auditing_and_publishes_static_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._StaticProgressBody(scanned=0, total=0, done=True)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 128)
            self.assertEqual(stored.static_total_files, 128)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertEqual(status_events[-1]["status"], ScanItemStatus.AUDITING)
            self.assertTrue(status_events[-1]["static_analysis_done"])
            self.assertEqual(status_events[-1]["static_scanned_files"], 128)
            self.assertEqual(status_events[-1]["static_total_files"], 128)

    def test_index_status_done_persists_stats_and_file_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            stats = {
                "files": 7,
                "functions": 31,
                "structs": 4,
                "global_variables": 5,
                "function_calls": 42,
                "global_variable_references": 9,
            }
            published: list[tuple[str, str, dict]] = []
            body = agent_api._IndexStatusBody(status="done", stats=stats)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_index_status("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.static_scanned_files, 7)
            self.assertEqual(stored.static_total_files, 7)
            self.assertEqual(agent_api._scan_index_statuses["scan-1"]["stats"]["function_calls"], 42)
            index_events = [data for _scan_id, event_type, data in published if event_type == "index_status"]
            self.assertTrue(index_events)
            self.assertEqual(index_events[-1]["parsed_files"], 0)
            self.assertEqual(index_events[-1]["stats"], stats)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertEqual(status_events[-1]["static_scanned_files"], 7)
            self.assertEqual(status_events[-1]["static_total_files"], 7)

    def test_index_status_done_zero_counts_does_not_clear_existing_file_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            scan.static_total_files = 128
            scan.static_scanned_files = 127
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._IndexStatusBody(status="done", parsed_files=0, total_files=0)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_index_status("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.static_scanned_files, 127)
            self.assertEqual(stored.static_total_files, 128)
            self.assertFalse([data for _scan_id, event_type, data in published if event_type == "scan_status"])

    def test_index_status_skipped_does_not_change_static_file_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            scan.static_total_files = 128
            scan.static_scanned_files = 64
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._IndexStatusBody(status="skipped")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_index_status("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.static_scanned_files, 64)
            self.assertEqual(stored.static_total_files, 128)
            self.assertEqual(
                agent_api._scan_index_statuses["scan-1"]["status"],
                "skipped",
            )
            self.assertFalse([
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_status"
            ])

    def test_static_progress_updates_pending_scan_to_analyzing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            body = agent_api._StaticProgressBody(scanned=3, total=128, done=False)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.ANALYZING)
            self.assertFalse(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 3)
            self.assertEqual(stored.static_total_files, 128)

    def test_late_static_progress_does_not_clear_completed_static_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=3)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            scan.static_analysis_done = True
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._StaticProgressBody(scanned=127, total=128, done=False)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 127)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertTrue(status_events[-1]["static_analysis_done"])

    def test_late_static_progress_done_does_not_reopen_completed_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=2, processed=2)
            scan.static_analysis_done = False
            store.save_scan(scan, _meta())

            body = agent_api._StaticProgressBody(scanned=0, total=0, done=True)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.COMPLETE)
            self.assertTrue(stored.static_analysis_done)

    def test_processed_report_updates_progress_from_processed_key_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=4), _meta())

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_report_processed(
                    "scan-1",
                    {"file": "a.c", "line": 1, "function": "a", "vuln_type": "npd"},
                ))
                asyncio.run(agent_api.agent_report_processed(
                    "scan-1",
                    {"file": "b.c", "line": 2, "function": "b", "vuln_type": "npd"},
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.processed_candidates, 2)
            self.assertEqual(stored.progress, 0.5)

    def test_candidate_progress_is_absolute_bounded_and_terminally_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=3)
            scan.static_analysis_done = True
            scan.mining_engines = [MiningEngineSelection(
                engine_id="static_candidate",
                engine_label="静态规则扫描 + 候选点审计",
            )]
            scan.mining_engine_runs = [MiningEngineRunStatus(
                engine_id="static_candidate",
                engine_label="静态规则扫描 + 候选点审计",
                status="running",
            )]
            scan.candidates = [
                ScanCandidate(
                    idx=index,
                    file="same.c",
                    line=1,
                    function="same",
                    description=f"candidate {index}",
                    vuln_type="npd",
                )
                for index in range(3)
            ]
            meta = _meta()
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch("backend.sse.publish"),
            ):
                for index in (0, 1):
                    asyncio.run(agent_api.agent_report_candidate_audit(
                        "scan-1",
                        AgentCandidateAuditResult(
                            candidate_idx=index,
                            state="success",
                            result=Vulnerability(
                                file="same.c",
                                line=1,
                                function="same",
                                vuln_type="npd",
                                severity="low",
                                description=f"candidate {index} result",
                                confirmed=False,
                                ai_verdict="not_confirmed",
                            ),
                            completed_candidates=3,
                            total_candidates=3,
                        ),
                    ))
                running = store.load_scan("scan-1")[0]
                self.assertEqual(running.total_candidates, 3)
                self.assertEqual(running.processed_candidates, 2)

                asyncio.run(agent_api.agent_report_processed(
                    "scan-1",
                    {
                        "file": "same.c",
                        "line": 1,
                        "function": "same",
                        "vuln_type": "npd",
                        "processed_candidates": 1,
                        "total_candidates": 1,
                    },
                ))
                self.assertEqual(
                    store.load_scan("scan-1")[0].processed_candidates,
                    2,
                )

                asyncio.run(agent_api.agent_report_candidate_audit(
                    "scan-1",
                    AgentCandidateAuditResult(
                        candidate_idx=2,
                        state="success",
                        result=Vulnerability(
                            file="same.c",
                            line=1,
                            function="same",
                            vuln_type="npd",
                            severity="low",
                            description="candidate 2 result",
                            confirmed=False,
                            ai_verdict="not_confirmed",
                        ),
                        completed_candidates=3,
                        total_candidates=3,
                    ),
                ))
                self.assertEqual(
                    store.load_scan("scan-1")[0].processed_candidates,
                    3,
                )

                asyncio.run(agent_api.agent_report_mining_engine_run(
                    "scan-1",
                    MiningEngineRunStatus(
                        engine_id="static_candidate",
                        engine_label="静态规则扫描 + 候选点审计",
                        status="success",
                    ),
                ))

            completed = store.load_scan("scan-1")[0]
            self.assertEqual(completed.total_candidates, 3)
            self.assertEqual(completed.processed_candidates, 3)
            self.assertEqual(completed.progress, 1.0)

    def test_missing_stage_run_returns_structured_scan_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.object(agent_api.logger, "warning") as warning,
            ):
                with self.assertRaises(agent_api.HTTPException) as raised:
                    asyncio.run(agent_api.agent_report_threat_analysis_run(
                        "missing-scan",
                        ThreatAnalysisRunStatus(status="running"),
                    ))

            self.assertEqual(raised.exception.status_code, 404)
            self.assertEqual(
                raised.exception.detail,
                {
                    "code": "scan_not_found",
                    "scan_id": "missing-scan",
                    "endpoint": "threat-analysis-run",
                },
            )
            warning.assert_called_once()
            warning_args = warning.call_args.args
            self.assertIn("storage_target=%s", warning_args[0])
            self.assertEqual(warning_args[1], "missing-scan")

    def test_mining_engine_progress_persists_and_publishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-pattern-progress", ScanItemStatus.AUDITING)
            scan.mining_engines = [MiningEngineSelection(
                engine_id="threat_pattern_audit",
                engine_label="DeepHole基于攻击模式的漏洞挖掘引擎",
            )]
            scan.mining_engine_runs = [MiningEngineRunStatus(
                engine_id="threat_pattern_audit",
                engine_label="DeepHole基于攻击模式的漏洞挖掘引擎",
                status="pending",
            )]
            meta = _meta()
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                response = asyncio.run(agent_api.agent_report_mining_engine_run(
                    "scan-pattern-progress",
                    MiningEngineRunStatus(
                        engine_id="threat_pattern_audit",
                        engine_label="untrusted label",
                        status="running",
                        total_candidates=8,
                        processed_candidates=3,
                    ),
                ))

            stored = store.load_scan("scan-pattern-progress")[0]
            run = stored.mining_engine_runs[0]
            self.assertEqual(run.processed_candidates, 3)
            self.assertEqual(run.total_candidates, 8)
            self.assertEqual(response["run"]["processed_candidates"], 3)
            self.assertEqual(response["run"]["total_candidates"], 8)
            self.assertEqual(published[0][1], "mining_engine_run")
            self.assertEqual(
                published[0][2]["runs"][0]["processed_candidates"],
                3,
            )

    def test_v2_finish_merges_terminal_stage_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING)
            scan.threat_analysis_enabled = True
            scan.threat_analysis_run = ThreatAnalysisRunStatus(
                status="running",
                started_at="2026-01-01T00:00:00+00:00",
            )
            scan.mining_engine_runs = [MiningEngineRunStatus(
                engine_id="engine_b",
                engine_label="Engine B",
                status="success",
            )]
            meta = _meta()
            meta.threat_analysis_enabled = True
            meta.mining_engines = [
                MiningEngineSelection(
                    engine_id="engine_a",
                    engine_label="Engine A",
                ),
                MiningEngineSelection(
                    engine_id="engine_b",
                    engine_label="Engine B",
                ),
            ]
            store.save_scan(scan, meta)
            agent_api._running_scans["scan-1"] = store.load_scan("scan-1")[0]
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan_v2(
                    "scan-1",
                    AgentScanFinishV2(
                        status="error",
                        total_candidates=0,
                        processed_candidates=0,
                        error_message="scan failed",
                        threat_analysis_run=ThreatAnalysisRunStatus(
                            status="error",
                            error_message="threat analysis failed",
                            finished_at="2026-01-01T00:01:00+00:00",
                        ),
                        mining_engine_runs=[MiningEngineRunStatus(
                            engine_id="engine_a",
                            engine_label="untrusted label",
                            status="cancelled",
                            finished_at="2026-01-01T00:01:00+00:00",
                            total_candidates=5,
                            processed_candidates=3,
                        )],
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.threat_analysis_run.status, "error")
            self.assertEqual(
                {
                    run.engine_id: (
                        run.engine_label,
                        run.status,
                        run.processed_candidates,
                        run.total_candidates,
                    )
                    for run in stored.mining_engine_runs
                },
                {
                    "engine_a": ("Engine A", "cancelled", 3, 5),
                    "engine_b": ("Engine B", "success", None, None),
                },
            )
            event_types = [event_type for _scan_id, event_type, _data in published]
            self.assertIn("threat_analysis_run", event_types)
            self.assertIn("mining_engine_run", event_types)
            self.assertIn("scan_finish", event_types)
            engine_event = next(
                data
                for _scan_id, event_type, data in published
                if event_type == "mining_engine_run"
            )
            self.assertEqual(engine_event["run"]["processed_candidates"], 3)
            self.assertEqual(engine_event["run"]["total_candidates"], 5)

    def test_finish_missing_scan_returns_structured_404(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.object(agent_api.logger, "warning"),
            ):
                with self.assertRaises(agent_api.HTTPException) as raised:
                    asyncio.run(agent_api.agent_finish_scan(
                        "missing-scan",
                        AgentScanFinish(
                            vulnerabilities=[],
                            status="error",
                            total_candidates=0,
                            processed_candidates=0,
                        ),
                        SimpleNamespace(base_url="http://testserver/"),
                    ))

            self.assertEqual(raised.exception.status_code, 404)
            self.assertEqual(
                raised.exception.detail["code"],
                "scan_not_found",
            )
            self.assertEqual(raised.exception.detail["endpoint"], "finish")

    def test_late_agent_finish_cannot_revive_manually_stopped_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            stopped = _scan(
                "scan-1",
                ScanItemStatus.CANCELLED,
                total=1,
                processed=0,
                error="用户手动停止",
            )
            store.save_scan(stopped, _meta())

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="complete",
                        total_candidates=1,
                        processed_candidates=1,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            self.assertEqual(stored.error_message, "用户手动停止")

    def test_finalized_candidate_list_cannot_be_replaced_by_retry_subset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.CANCELLED, total=3, processed=1)
            scan.static_analysis_done = True
            scan.candidates = [
                ScanCandidate(
                    idx=index,
                    file=f"candidate-{index}.c",
                    line=index + 1,
                    function=f"candidate_{index}",
                    description="candidate",
                    vuln_type="npd",
                )
                for index in range(3)
            ]
            store.save_scan(scan, _meta())
            retry_subset = AgentScanCandidates(candidates=[Candidate(
                file="candidate-2.c",
                line=3,
                function="candidate_2",
                description="retry candidate",
                vuln_type="npd",
            )])

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                result = asyncio.run(agent_api.agent_report_scan_candidates(
                    "scan-1",
                    retry_subset,
                ))
                v2_result = asyncio.run(
                    agent_api.agent_report_scan_candidates_v2(
                        "scan-1",
                        AgentScanCandidateBatch(
                            offset=0,
                            candidates=retry_subset.candidates,
                            reset=True,
                            final=True,
                            total=1,
                        ),
                    )
                )

            stored = store.load_scan("scan-1")[0]
            self.assertTrue(result["preserved"])
            self.assertTrue(v2_result["preserved"])
            self.assertEqual(result["count"], 3)
            self.assertEqual(stored.total_candidates, 3)
            self.assertEqual(len(stored.candidates), 3)

    def test_overview_repairs_candidate_counter_mismatch_from_persisted_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=1, processed=9)
            scan.static_analysis_done = True
            scan.mining_engine_runs = [MiningEngineRunStatus(
                engine_id="static_candidate",
                engine_label="静态规则扫描 + 候选点审计",
                status="success",
            )]
            scan.candidates = [
                ScanCandidate(
                    idx=index,
                    file=f"candidate-{index}.c",
                    line=index + 1,
                    function=f"candidate_{index}",
                    description="candidate",
                    vuln_type="npd",
                    audit_state="success",
                    audit_result=Vulnerability(
                        file=f"candidate-{index}.c",
                        line=index + 1,
                        function=f"candidate_{index}",
                        vuln_type="npd",
                        severity="low",
                        description="audited",
                        confirmed=False,
                        ai_verdict="not_confirmed",
                        audit_index=index,
                    ),
                )
                for index in range(3)
            ]
            store.save_scan(scan, _meta())

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                overview = asyncio.run(scan_api.get_scan_overview_v2(
                    "scan-1",
                    current_user=User(
                        user_id="user-1",
                        username="alice",
                        role="user",
                    ),
                ))

            self.assertEqual(overview.total_candidates, 3)
            self.assertEqual(overview.processed_candidates, 3)
            self.assertEqual(overview.detail_counts.candidates, 3)

    def test_candidate_report_persists_final_static_candidate_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=0, processed=0)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan
            published: list[tuple[str, str, dict]] = []

            body = AgentScanCandidates(candidates=[
                Candidate(
                    file="src/a.c",
                    line=10,
                    function="foo",
                    description="desc",
                    vuln_type="npd",
                    metadata={"subject": "ptr"},
                ),
                Candidate(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    description="threat audit placeholder",
                    vuln_type="threat_audit",
                    metadata={"source": "threat_analysis"},
                ),
            ])

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                response = asyncio.run(agent_api.agent_report_scan_candidates("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(response["count"], 1)
            self.assertEqual(stored.total_candidates, 1)
            self.assertEqual(stored.candidates[0].metadata["subject"], "ptr")
            self.assertEqual(agent_api._running_scans["scan-1"].candidates[0].file, "src/a.c")
            self.assertTrue(any(event_type == "scan_candidates" for _sid, event_type, _data in published))

    def test_retry_counts_keep_static_candidates_and_threat_tasks_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=1, processed=1)
            store.save_scan(scan, _meta())
            static_failure = Vulnerability(
                file="static.c",
                line=7,
                function="retry_static",
                vuln_type="npd",
                severity="unknown",
                description="static timeout",
                ai_analysis="timeout",
                confirmed=False,
                ai_verdict="timeout",
                audit_index=0,
            )
            static_vulnerability_idx = store.add_vulnerability(
                "scan-1",
                static_failure,
            )
            store.replace_scan_candidates("scan-1", [ScanCandidate(
                idx=0,
                file=static_failure.file,
                line=static_failure.line,
                function=static_failure.function,
                description=static_failure.description,
                vuln_type=static_failure.vuln_type,
                audit_state="failed",
                audit_result=static_failure,
                vulnerability_idx=static_vulnerability_idx,
            )])
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    vuln_type="threat_audit",
                    severity="unknown",
                    description="threat timeout",
                    ai_analysis="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                    analysis_source="threat_audit",
                    source_task_id="threat-timeout",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(task_id="threat-timeout", status="timeout"),
            )
            user = User(user_id="user-1", username="alice", role="user")

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                status = asyncio.run(scan_api.get_scan_status("scan-1", current_user=user))

            self.assertEqual(status.retryable_candidates_count, 1)
            self.assertEqual(status.continuable_task_count, 2)

    def test_late_opencode_pool_snapshot_is_cleared_for_completed_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=4, processed=4)
            store.save_scan(scan, _meta())
            body = OpenCodePoolStatus(
                scope_id="scan-1",
                global_running=1,
                global_queued=2,
                total_tasks=3,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "task-done",
                        "task_type": "threat_analysis",
                        "outcome": "success",
                        "serve_session_id": "ses_task_done",
                        "prompt": "completed threat prompt",
                        "finished_at": "2026-01-01T00:02:00+00:00",
                    }
                ],
                models=[
                    {
                        "id": "deep",
                        "model": "deep-model",
                        "capability": "high",
                        "max_concurrency": 1,
                        "running": 1,
                        "queued": 2,
                        "total": 3,
                        "success": 2,
                        "last_status": "running",
                        "active_tasks": [{"task_type": "vulnerability_mining"}],
                    }
                ],
            )

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_push_opencode_pool("scan-1", body))

            pool = store.load_scan("scan-1")[0].opencode_pool
            self.assertIsNotNone(pool)
            self.assertEqual(pool.global_running, 0)
            self.assertEqual(pool.global_queued, 0)
            self.assertEqual(pool.models[0].running, 0)
            self.assertEqual(pool.models[0].queued, 0)
            self.assertEqual(pool.models[0].active_tasks, [])
            self.assertEqual(pool.total_tasks, 3)
            self.assertEqual(pool.completed_task_count, 1)
            self.assertEqual(pool.completed_tasks[0]["task_id"], "task-done")
            self.assertEqual(pool.completed_tasks[0]["serve_session_id"], "ses_task_done")
            self.assertEqual(pool.completed_tasks[0]["prompt"], "completed threat prompt")
            summary = store.list_scans()[0]
            self.assertEqual(summary.total_task_count, 3)
            self.assertEqual(summary.completed_task_count, 1)

    def test_opencode_pool_snapshot_merges_history_across_continue_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1)
            scan.opencode_pool = OpenCodePoolStatus(
                scope_id="scan-1",
                total_tasks=1,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "old",
                        "outcome": "success",
                        "serve_session_id": "ses_old",
                        "prompt": "old prompt",
                    }
                ],
            )
            store.save_scan(scan, _meta())
            current = OpenCodePoolStatus(
                scope_id="scan-1",
                global_queued=1,
                total_tasks=2,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "new",
                        "outcome": "timeout",
                        "serve_session_id": "ses_new",
                        "prompt": "new prompt",
                    }
                ],
                queued_tasks=[{"request_id": "queued", "task_type": "fp_review"}],
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_opencode_pool("scan-1", current))

            pool = store.load_scan("scan-1")[0].opencode_pool
            self.assertIsNotNone(pool)
            self.assertEqual([task["task_id"] for task in pool.completed_tasks], ["old", "new"])
            self.assertEqual(
                [task["prompt"] for task in pool.completed_tasks],
                ["old prompt", "new prompt"],
            )
            self.assertEqual(
                [task["serve_session_id"] for task in pool.completed_tasks],
                ["ses_old", "ses_new"],
            )
            self.assertEqual(pool.completed_task_count, 2)
            self.assertEqual(pool.total_tasks, 3)

    def test_opencode_pool_merge_keeps_richer_session_trace_for_same_revision(self) -> None:
        previous = OpenCodePoolStatus(
            scope_id="scan-1",
            total_tasks=1,
            completed_task_count=1,
            completed_tasks=[{
                "task_id": "logical-task",
                "revision": 1,
                "outcome": "timeout",
                "serve_session_id": "ses_2",
                "failure_kind": "timeout",
                "failure_reason": "slow",
                "session_events": [
                    {"sequence": 1, "phase": "business", "session_id": "ses_1"},
                    {"sequence": 2, "phase": "business", "session_id": "ses_2"},
                ],
            }],
        )
        stale = OpenCodePoolStatus(
            scope_id="scan-1",
            total_tasks=1,
            completed_task_count=1,
            completed_tasks=[{
                "task_id": "logical-task",
                "revision": 1,
                "outcome": "timeout",
                "session_events": [
                    {"sequence": 1, "phase": "business", "session_id": "ses_1"},
                ],
            }],
        )

        merged = agent_api._merge_completed_opencode_tasks(previous, stale)

        task = merged.completed_tasks[0]
        self.assertEqual(
            [event["session_id"] for event in task["session_events"]],
            ["ses_1", "ses_2"],
        )
        self.assertEqual(task["serve_session_id"], "ses_2")
        self.assertEqual(task["failure_kind"], "timeout")
        self.assertEqual(task["failure_reason"], "slow")

    @patch("backend.api.agent.request_agent_scan_stop", new=AsyncMock(return_value={"still_active": False}))
    def test_resume_preserves_total_candidate_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            graph = AgentMcpConfig(
                enabled=True,
                name="resume-graph",
                transport="remote",
                remote=AgentMcpRemoteConfig(url="http://graph.test/mcp"),
            )
            meta = _meta()
            meta.code_graph_mcp = graph
            scan = _scan(
                "scan-1",
                ScanItemStatus.CANCELLED,
                total=10,
                processed=4,
                error="Agent 断开连接",
            )
            scan.mining_engines = [
                MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                ),
            ]
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            stale_live = scan.model_copy(deep=True)
            stale_live.status = ScanItemStatus.AUDITING
            agent_api._running_scans["scan-1"] = stale_live
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
                protocol_version=2,
            )
            user = User(user_id="user-1", username="alice", role="user")

            send = AsyncMock(return_value=True)
            runtime_update = AsyncMock(return_value={"hash": "runtime-current"})
            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=send),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=runtime_update,
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
                patch(
                    "backend.api.agent.agent_explicit_model_ids",
                    return_value=["provider/model"],
                ),
            ):
                request = SimpleNamespace(base_url="http://testserver/")
                asyncio.run(scan_api.resume_scan("scan-1", request=request, current_user=user))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.total_candidates, 10)
            self.assertEqual(stored.processed_candidates, 4)
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(agent_api._running_scans["scan-1"].status, ScanItemStatus.PENDING)
            runtime_update.assert_awaited_once_with(
                "http://testserver",
                meta.agent_key,
            )
            command = send.await_args.args[1]
            self.assertEqual(command["agent_runtime_update"], {"hash": "runtime-current"})
            manifest_token = command["resume_manifest_url"].rsplit("/", 1)[-1]
            manifest_row = store.get_resume_manifest(manifest_token)
            self.assertIsNotNone(manifest_row)
            manifest = json.loads(manifest_row["payload_json"])
            self.assertEqual(manifest["agent_runtime_update"], {"hash": "runtime-current"})
            self.assertEqual(manifest["code_graph_mcp"], graph.model_dump(mode="json"))

    @patch("backend.api.agent.request_agent_scan_stop", new=AsyncMock(return_value={"still_active": False}))
    def test_retry_incomplete_scan_dispatches_retryable_failed_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=4, processed=4)
            scan.mining_engines = [
                MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                ),
            ]
            meta = _meta()
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            vulns = [
                Vulnerability(
                    file="ok.c",
                    line=1,
                    function="ok",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="timeout.c",
                    line=2,
                    function="slow",
                    vuln_type="npd",
                    severity="unknown",
                    description="timed out",
                    ai_analysis="Analysis timed out",
                    confirmed=False,
                    ai_verdict="timeout",
                ),
                Vulnerability(
                    file="none.c",
                    line=3,
                    function="missing",
                    vuln_type="npd",
                    severity="unknown",
                    description="no result",
                    ai_analysis="No analysis result returned",
                    confirmed=False,
                    ai_verdict="no_result",
                ),
                Vulnerability(
                    file="failed.c",
                    line=4,
                    function="broken",
                    vuln_type="npd",
                    severity="unknown",
                    description="failed",
                    ai_analysis="OpenCode completed without submitting a result",
                    confirmed=False,
                    ai_verdict="failed",
                    failure_reason="raw opencode output",
                ),
            ]
            for vuln in vulns:
                store.add_vulnerability("scan-1", vuln)
                store.add_processed_key(
                    "scan-1",
                    (vuln.file, vuln.line, vuln.function, vuln.vuln_type),
                )
            store.replace_scan_candidates("scan-1", [
                ScanCandidate(
                    idx=index,
                    file=vuln.file,
                    line=vuln.line,
                    function=vuln.function,
                    description=vuln.description,
                    vuln_type=vuln.vuln_type,
                    audit_state=("success" if index == 0 else "failed"),
                    audit_result=vuln.model_copy(update={"audit_index": index}),
                    vulnerability_idx=index,
                )
                for index, vuln in enumerate(vulns)
            ])
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=AsyncMock(side_effect=fake_send)),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
                patch(
                    "backend.api.agent.agent_explicit_model_ids",
                    return_value=["provider/model"],
                ),
            ):
                request = SimpleNamespace(base_url="http://testserver/")
                asyncio.run(scan_api.retry_incomplete_scan("scan-1", request=request, current_user=user))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(stored.processed_candidates, 1)
            self.assertEqual(len(store.get_processed_keys("scan-1")), 1)
            self.assertEqual(sent["type"], "resume")
            self.assertEqual(sent["codex_model_ids"], ["provider/model"])
            self.assertEqual(sent["retry_total_candidates"], 4)
            self.assertEqual(sent["retry_processed_offset"], 1)
            self.assertEqual(
                sent["retry_mining_engine_ids"],
                ["static_candidate"],
            )
            self.assertEqual(
                [(c["file"], c["line"], c["function"]) for c in sent["retry_candidates"]],
                [("timeout.c", 2, "slow"), ("none.c", 3, "missing"), ("failed.c", 4, "broken")],
            )
            self.assertEqual(
                [candidate["idx"] for candidate in sent["retry_candidates"]],
                [1, 2, 3],
            )

    @patch("backend.api.agent.request_agent_scan_stop", new=AsyncMock(return_value={"still_active": False}))
    def test_resume_dispatches_unprocessed_failed_and_threat_audit_work_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.CANCELLED, total=3, processed=2)
            scan.static_analysis_done = True
            scan.threat_analysis_enabled = True
            scan.threat_analysis_run = ThreatAnalysisRunStatus(
                status="success",
                started_at="2026-01-01T00:00:00+00:00",
                finished_at="2026-01-01T00:01:00+00:00",
            )
            scan.mining_engines = [
                MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                ),
                MiningEngineSelection(
                    engine_id="threat_audit",
                    engine_label="威胁审计",
                ),
            ]
            scan.candidates = [
                ScanCandidate(
                    idx=0,
                    file="done.c",
                    line=1,
                    function="done",
                    description="done",
                    vuln_type="npd",
                    audit_state="success",
                    audit_result=Vulnerability(
                        file="done.c",
                        line=1,
                        function="done",
                        vuln_type="npd",
                        severity="high",
                        description="done",
                        confirmed=True,
                        ai_verdict="confirmed",
                        audit_index=0,
                    ),
                    vulnerability_idx=0,
                ),
                ScanCandidate(
                    idx=1,
                    file="failed.c",
                    line=2,
                    function="failed",
                    description="failed",
                    vuln_type="npd",
                    audit_state="failed",
                    audit_result=Vulnerability(
                        file="failed.c",
                        line=2,
                        function="failed",
                        vuln_type="npd",
                        severity="unknown",
                        description="failed",
                        confirmed=False,
                        ai_verdict="failed",
                        audit_index=1,
                    ),
                    vulnerability_idx=1,
                ),
                ScanCandidate(idx=2, file="pending.c", line=3, function="pending", description="pending", vuln_type="npd"),
            ]
            meta = _meta()
            meta.threat_analysis_enabled = True
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            store.replace_threat_analysis("scan-1", {
                "entrypoint_result": {
                    "result": True,
                    "value_asset_path": "final/value-assets.json",
                    "attack_tree_path": "final/attack-trees.json",
                    "high_risk_modules_path": "final/high-risk-modules.json",
                },
                "artifacts": {
                    "value_asset_path": {
                        "path": "final/value-assets.json",
                        "content": [],
                    },
                    "attack_tree_path": {
                        "path": "final/attack-trees.json",
                        "content": {"attack_trees": []},
                    },
                    "high_risk_modules_path": {
                        "path": "final/high-risk-modules.json",
                        "content": [],
                    },
                },
            })
            store.add_processed_key("scan-1", ("done.c", 1, "done", "npd"))
            store.add_processed_key("scan-1", ("failed.c", 2, "failed", "npd"))
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="failed.c",
                    line=2,
                    function="failed",
                    vuln_type="npd",
                    severity="unknown",
                    description="failed",
                    ai_analysis="failed",
                    confirmed=False,
                    ai_verdict="failed",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="threat-complete",
                    status="completed",
                    surface_node_id="surface-1",
                    method_node_id="method-complete",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="threat-timeout",
                    status="timeout",
                    surface_node_id="surface-1",
                    method_node_id="method-timeout",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="legacy-superseded",
                    status="superseded",
                    surface_node_id="surface-legacy",
                    method_node_id="method-legacy",
                ),
            )
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    vuln_type="threat_audit",
                    severity="unknown",
                    description="timed out threat audit",
                    ai_analysis="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                    analysis_source="threat_audit",
                    source_task_id="threat-timeout",
                ),
            )
            self.assertEqual(store.get_incomplete_threat_audit_counts(["scan-1"]), {"scan-1": 1})
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=AsyncMock(side_effect=fake_send)),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value={
                        "hash": "remote-runtime",
                        "archive_sha256": "archive-hash",
                    }),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
                patch(
                    "backend.api.agent.agent_explicit_model_ids",
                    return_value=["provider/model"],
                ),
            ):
                asyncio.run(
                    scan_api.resume_scan(
                        "scan-1",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=user,
                    )
                )

            self.assertEqual(
                [(item["file"], item["line"]) for item in sent["retry_candidates"]],
                [("failed.c", 2), ("pending.c", 3)],
            )
            self.assertEqual(
                [item["idx"] for item in sent["retry_candidates"]],
                [1, 2],
            )
            self.assertEqual(sent["retry_processed_offset"], 1)
            self.assertTrue(sent["resume_threat_analysis"])
            self.assertEqual(
                sent["retry_mining_engine_ids"],
                ["static_candidate", "threat_audit"],
            )
            self.assertIsNone(sent["retry_threat_audit_task_ids"])
            self.assertEqual(
                sent["agent_runtime_update"],
                {"hash": "remote-runtime", "archive_sha256": "archive-hash"},
            )
            self.assertEqual(store.get_processed_keys("scan-1"), {("done.c", 1, "done", "npd")})
            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.threat_analysis_run.status, "success")
            self.assertEqual(
                stored.threat_analysis_run.started_at,
                "2026-01-01T00:00:00+00:00",
            )
            self.assertEqual(
                stored.threat_analysis_run.finished_at,
                "2026-01-01T00:01:00+00:00",
            )

    @patch("backend.api.agent.request_agent_scan_stop", new=AsyncMock(return_value={"still_active": False}))
    def test_resume_preserves_analysis_only_empty_engine_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-analysis", ScanItemStatus.CANCELLED)
            scan.scan_mode = "threat_analysis_only"
            scan.threat_analysis_enabled = True
            scan.mining_engines = []
            meta = _meta()
            meta.scan_mode = "threat_analysis_only"
            meta.threat_analysis_enabled = True
            meta.mining_engines = []
            store.save_scan(scan, meta)
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict(
                    "backend.api.agent._registered_agents",
                    {"agent-old": agent},
                    clear=True,
                ),
                patch(
                    "backend.api.agent.send_agent_command",
                    new=AsyncMock(side_effect=fake_send),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
                patch(
                    "backend.api.agent.agent_explicit_model_ids",
                    return_value=["provider/model"],
                ),
            ):
                asyncio.run(scan_api.resume_scan(
                    "scan-analysis",
                    request=SimpleNamespace(base_url="http://testserver/"),
                    current_user=user,
                ))

            self.assertTrue(sent["threat_analysis_enabled"])
            self.assertEqual(
                sent["threat_analysis_method"],
                "deephole_threat_analysis",
            )
            self.assertTrue(sent["resume_threat_analysis"])
            self.assertEqual(sent["mining_engines"], [])
            self.assertEqual(sent["retry_mining_engine_ids"], [])

    @patch("backend.api.agent.request_agent_scan_stop", new=AsyncMock(return_value={"still_active": False}))
    def test_failed_threat_analysis_retries_pattern_engine_without_rerunning_successful_engine(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-threat-retry", ScanItemStatus.COMPLETE)
            scan.threat_analysis_enabled = True
            scan.threat_analysis_run = ThreatAnalysisRunStatus(
                status="error",
                error_message="cached semantic mismatch",
            )
            scan.mining_engines = [
                MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                ),
                MiningEngineSelection(
                    engine_id="threat_pattern_audit",
                    engine_label="DeepHole基于攻击模式的漏洞挖掘引擎",
                ),
            ]
            scan.mining_engine_runs = [
                MiningEngineRunStatus(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                    status="success",
                ),
                MiningEngineRunStatus(
                    engine_id="threat_pattern_audit",
                    engine_label="DeepHole基于攻击模式的漏洞挖掘引擎",
                    status="skipped",
                    error_message="Blocked because threat analysis failed",
                ),
            ]
            meta = _meta()
            meta.threat_analysis_enabled = True
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                status = asyncio.run(
                    scan_api.get_scan_status(
                        "scan-threat-retry",
                        current_user=user,
                    )
                )
            self.assertTrue(status.can_continue)
            self.assertEqual(status.continuable_task_count, 2)

            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict(
                    "backend.api.agent._registered_agents",
                    {"agent-old": agent},
                    clear=True,
                ),
                patch(
                    "backend.api.agent.send_agent_command",
                    new=AsyncMock(side_effect=fake_send),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
                patch(
                    "backend.api.agent.agent_explicit_model_ids",
                    return_value=["provider/model"],
                ),
            ):
                asyncio.run(
                    scan_api.resume_scan(
                        "scan-threat-retry",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=user,
                    )
                )

            self.assertTrue(sent["resume_threat_analysis"])
            self.assertEqual(
                sent["retry_mining_engine_ids"],
                ["threat_pattern_audit"],
            )
            stored = store.load_scan("scan-threat-retry")[0]
            self.assertEqual(stored.threat_analysis_run.status, "pending")
            runs = {item.engine_id: item for item in stored.mining_engine_runs}
            self.assertEqual(runs["static_candidate"].status, "success")
            self.assertEqual(runs["threat_pattern_audit"].status, "pending")

    def test_provisional_agent_report_is_visible_then_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-live-reconcile", ScanItemStatus.AUDITING, total=1)
            store.save_scan(scan, _meta())
            agent_api._running_scans[scan.scan_id] = scan
            callback = Vulnerability(
                file="callback.c",
                line=10,
                function="callback_issue",
                vuln_type="memory_corruption",
                severity="high",
                description="callback result",
                vulnerability_report="# Callback report",
                confirmed=True,
                ai_verdict="confirmed",
            )
            final = callback.model_copy(update={
                "file": "final.c",
                "line": 20,
                "function": "final_issue",
                "description": "authoritative final result",
                "vulnerability_report": "# Authoritative final report",
            })
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                live_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        scan.scan_id,
                        callback,
                        provisional=True,
                        report_batch_id="batch-1",
                    )
                )
                self.assertTrue(live_response["provisional"])
                self.assertTrue(store.get_vulnerabilities(scan.scan_id)[0].provisional)

                reconciled = asyncio.run(
                    agent_api.agent_reconcile_vulnerabilities(
                        scan.scan_id,
                        AgentVulnerabilityReconcile(
                            report_batch_ids=["batch-1"],
                            vulnerabilities=[final],
                        ),
                    )
                )

            stored = store.get_vulnerabilities(scan.scan_id)
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].file, "final.c")
            self.assertEqual(
                stored[0].vulnerability_report,
                "# Authoritative final report",
            )
            self.assertFalse(stored[0].provisional)
            self.assertIn("# Authoritative final report", reconciled["items"][0]["report_markdown"])
            self.assertEqual(
                [event_type for _scan_id, event_type, _data in published],
                ["scan_vulnerability", "scan_vulnerabilities_changed"],
            )

    def test_finish_fallback_reconciles_provisional_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-finish-reconcile", ScanItemStatus.AUDITING, total=1)
            meta = _meta()
            meta.auto_fp_review = False
            store.save_scan(scan, meta)
            agent_api._running_scans[scan.scan_id] = scan
            callback = Vulnerability(
                file="callback.c",
                line=10,
                function="callback_issue",
                vuln_type="memory_corruption",
                severity="high",
                description="callback result",
                vulnerability_report="# Callback report",
                confirmed=True,
                ai_verdict="confirmed",
            )
            final = callback.model_copy(update={
                "file": "final.c",
                "line": 20,
                "function": "final_issue",
                "description": "authoritative final result",
                "vulnerability_report": "# Authoritative final report",
            })
            store.add_provisional_vulnerability(
                scan.scan_id,
                "batch-fallback",
                callback,
            )

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    scan.scan_id,
                    AgentScanFinish(
                        vulnerabilities=[final],
                        status="error",
                        total_candidates=1,
                        processed_candidates=1,
                        error_message="reconciliation endpoint unavailable",
                        replace_report_batch_ids=["batch-fallback"],
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities(scan.scan_id)
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].file, "final.c")
            self.assertEqual(
                stored[0].vulnerability_report,
                "# Authoritative final report",
            )
            self.assertFalse(stored[0].provisional)
            self.assertEqual(
                store.load_scan(scan.scan_id)[0].status,
                ScanItemStatus.ERROR,
            )

    def test_upsert_incomplete_vulnerability_replaces_existing_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=1), _meta())
            timeout_vuln = Vulnerability(
                file="a.c",
                line=1,
                function="a",
                vuln_type="npd",
                severity="unknown",
                description="old",
                ai_analysis="OpenCode completed without submitting a result",
                confirmed=False,
                ai_verdict="failed",
                failure_reason="old opencode output",
            )
            store.add_vulnerability("scan-1", timeout_vuln)
            replacement = Vulnerability(
                file="a.c",
                line=1,
                function="a",
                vuln_type="npd",
                severity="high",
                description="new",
                ai_analysis="confirmed now",
                confirmed=True,
                ai_verdict="confirmed",
            )

            index = store.upsert_incomplete_vulnerability("scan-1", replacement)

            self.assertEqual(index, 0)
            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].description, "new")
            self.assertEqual(stored[0].ai_verdict, "confirmed")
            self.assertEqual(stored[0].failure_reason, "")
            self.assertTrue(stored[0].confirmed)

    def test_cancel_finish_preserves_monotonic_candidate_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=8, processed=5), _meta())
            agent_api._running_scans["scan-1"] = store.load_scan("scan-1")[0]

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="cancelled",
                        total_candidates=8,
                        processed_candidates=4,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            self.assertEqual(stored.total_candidates, 8)
            self.assertEqual(stored.processed_candidates, 5)

    def test_complete_finish_reconciles_a_missing_static_success_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=3, processed=2)
            scan.static_analysis_done = True
            scan.mining_engine_runs = [MiningEngineRunStatus(
                engine_id="static_candidate",
                engine_label="静态规则扫描 + 候选点审计",
                status="running",
            )]
            scan.candidates = [
                ScanCandidate(
                    idx=index,
                    file=f"candidate-{index}.c",
                    line=index + 1,
                    function=f"candidate_{index}",
                    description="candidate",
                    vuln_type="npd",
                )
                for index in range(3)
            ]
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = store.load_scan("scan-1")[0]

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="complete",
                        total_candidates=3,
                        processed_candidates=3,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.COMPLETE)
            self.assertEqual(stored.total_candidates, 3)
            self.assertEqual(stored.processed_candidates, 3)

    def test_finish_scan_reconciles_missing_threat_findings_without_duplicates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1, processed=1)
            if hasattr(scan, "auto_fp_review"):
                scan.auto_fp_review = False
            meta = _meta()
            if hasattr(meta, "auto_fp_review"):
                meta.auto_fp_review = False
            store.save_scan(scan, meta)
            static_vuln = Vulnerability(
                file="static.c",
                line=10,
                function="static_issue",
                vuln_type="npd",
                severity="high",
                description="static issue",
                confirmed=True,
                ai_verdict="confirmed",
            )
            store.add_vulnerability("scan-1", static_vuln)
            scan.vulnerabilities = [static_vuln]
            agent_api._running_scans["scan-1"] = scan
            threat_vuln = Vulnerability(
                file="threat.c",
                line=20,
                function="threat_issue",
                vuln_type="out_of_bounds",
                severity="critical",
                description="threat-derived issue",
                confirmed=True,
                ai_verdict="confirmed",
                analysis_source="threat_audit",
                source_task_id="threat-task-1",
                threat_surface_node_id="TREE-1:NODE-1",
                threat_method_node_id="PATTERN-1",
            )
            published: list[tuple[str, str, dict]] = []
            finish = AgentScanFinish(
                vulnerabilities=[static_vuln, threat_vuln],
                status="complete",
                total_candidates=1,
                processed_candidates=1,
            )

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 2)
            self.assertEqual(
                [vuln.analysis_source for vuln in stored],
                ["static_candidate", "threat_audit"],
            )
            threat_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
                and data["vulnerability"]["analysis_source"] == "threat_audit"
            ]
            self.assertEqual(len(threat_events), 1)
            self.assertEqual(threat_events[0]["index"], 1)

    def test_report_threat_finding_is_live_and_finish_does_not_duplicate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1)
            if hasattr(scan, "auto_fp_review"):
                scan.auto_fp_review = False
            meta = _meta()
            if hasattr(meta, "auto_fp_review"):
                meta.auto_fp_review = False
            store.save_scan(scan, meta)
            agent_api._running_scans["scan-1"] = scan
            finding = {
                "file": "threat.c",
                "line": 20,
                "function": "threat_issue",
                "call_chain": [{
                    "function": "receive_packet",
                    "file": "network.c",
                    "line": 8,
                }],
                "vuln_type": "out_of_bounds",
                "severity": "critical",
                "description": "threat-derived issue",
                "attack_entry": "untrusted network packet",
                "confirmed": True,
                "ai_verdict": "confirmed",
                "analysis_source": "threat_audit",
                "source_task_id": "threat-task-1",
                "threat_surface_node_id": "TREE-1:NODE-1",
                "threat_method_node_id": "PATTERN-1",
            }
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                first_response = asyncio.run(agent_api.agent_report_vulnerability(
                    "scan-1",
                    Vulnerability(**finding),
                ))
                store.update_vulnerability(
                    "scan-1",
                    0,
                    "confirmed",
                    "verified by reviewer",
                    ticket_submitted=True,
                    ticket_id="SEC-42",
                )
                scan.vulnerabilities[0].user_verdict = "confirmed"
                scan.vulnerabilities[0].user_verdict_reason = (
                    "verified by reviewer"
                )
                scan.vulnerabilities[0].ticket_submitted = True
                scan.vulnerabilities[0].ticket_id = "SEC-42"
                replay_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-1",
                        Vulnerability(**finding),
                    ),
                )

                self.assertEqual(first_response["index"], 0)
                self.assertEqual(replay_response["index"], 0)
                self.assertEqual(
                    scan.vulnerabilities[0].user_verdict,
                    "confirmed",
                )
                self.assertEqual(scan.vulnerabilities[0].ticket_id, "SEC-42")
                distinct_finding = {
                    **finding,
                    "call_chain": [{
                        "function": "receive_datagram",
                        "file": "udp.c",
                        "line": 18,
                    }],
                    "attack_entry": "untrusted UDP datagram",
                }
                distinct_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-1",
                        Vulnerability(**distinct_finding),
                    ),
                )
                self.assertEqual(distinct_response["index"], 1)
                persisted_scan = store.load_scan("scan-1")[0]
                self.assertEqual(persisted_scan.status, ScanItemStatus.AUDITING)
                persisted_findings = store.get_vulnerabilities("scan-1")
                self.assertEqual(len(persisted_findings), 2)
                self.assertEqual(
                    persisted_findings[0].analysis_source,
                    "threat_audit",
                )
                self.assertEqual(
                    persisted_findings[0].user_verdict,
                    "confirmed",
                )
                self.assertEqual(
                    persisted_findings[1].attack_entry,
                    "untrusted UDP datagram",
                )
                live_scan = agent_api._running_scans["scan-1"]
                self.assertEqual(live_scan.status, ScanItemStatus.AUDITING)
                self.assertEqual(len(live_scan.vulnerabilities), 2)
                self.assertEqual(
                    live_scan.vulnerabilities[0].source_task_id,
                    "threat-task-1",
                )
                live_events = [
                    data
                    for _scan_id, event_type, data in published
                    if event_type == "scan_vulnerability"
                ]
                self.assertEqual(
                    [event["index"] for event in live_events],
                    [0, 1],
                )

                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[
                            Vulnerability(**finding),
                            Vulnerability(**distinct_finding),
                        ],
                        status="complete",
                        total_candidates=1,
                        processed_candidates=1,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 2)
            self.assertEqual(stored[0].source_task_id, "threat-task-1")
            self.assertEqual(stored[0].user_verdict, "confirmed")
            self.assertEqual(stored[0].ticket_id, "SEC-42")
            threat_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
                and data["vulnerability"]["analysis_source"] == "threat_audit"
            ]
            self.assertEqual(
                [event["index"] for event in threat_events],
                [0, 1],
            )

    def test_report_static_finding_replay_reuses_existing_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-static-replay", ScanItemStatus.AUDITING, total=1)
            scan.auto_fp_review = False
            meta = _meta()
            meta.auto_fp_review = False
            store.save_scan(scan, meta)
            agent_api._running_scans["scan-static-replay"] = scan
            finding = Vulnerability(
                file="static.c",
                line=12,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="null dereference",
                root_cause="unchecked pointer",
                confirmed=True,
                ai_verdict="confirmed",
                audit_index=0,
            )
            replay = finding.model_copy(deep=True)
            replay.output_source.agent_id = "agent-after-enrichment"
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    new=_direct_store_call,
                ),
                patch(
                    "backend.api.scan.run_store_call",
                    new=_direct_store_call,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                first_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-static-replay",
                        finding,
                    ),
                )
                agent_api._running_scans.pop("scan-static-replay", None)
                replay_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-static-replay",
                        replay,
                    ),
                )
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-static-replay",
                    AgentScanFinish(
                        vulnerabilities=[replay, replay.model_copy(deep=True)],
                        status="complete",
                        total_candidates=1,
                        processed_candidates=1,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            self.assertEqual(first_response["index"], 0)
            self.assertEqual(replay_response["index"], 0)
            self.assertEqual(
                len(store.get_vulnerabilities("scan-static-replay")),
                1,
            )
            vulnerability_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
            ]
            self.assertEqual(len(vulnerability_events), 1)
            self.assertEqual(vulnerability_events[0]["index"], 0)

    def test_finish_scan_keeps_same_finding_from_different_engines(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan(
                "scan-1",
                ScanItemStatus.AUDITING,
                total=1,
                processed=1,
            )
            scan.auto_fp_review = False
            selections = [
                MiningEngineSelection(
                    engine_id="engine_a",
                    engine_label="Engine A",
                ),
                MiningEngineSelection(
                    engine_id="engine_b",
                    engine_label="Engine B",
                ),
            ]
            scan.mining_engines = selections
            meta = _meta()
            meta.auto_fp_review = False
            meta.mining_engines = selections
            store.save_scan(scan, meta)

            finding_a = Vulnerability(
                file="same.c",
                line=12,
                function="same",
                vuln_type="npd",
                severity="high",
                description="same finding",
                confirmed=True,
                ai_verdict="confirmed",
                engine_id="engine_a",
                engine_label="untrusted",
            )
            finding_b = finding_a.model_copy(update={
                "engine_id": "engine_b",
                "engine_label": "also untrusted",
            })
            store.add_vulnerability(
                "scan-1",
                finding_a.model_copy(update={
                    "engine_label": "Engine A",
                }),
            )
            store._conn.execute(
                "UPDATE vulnerabilities SET fp_review_eligible = 0 "
                "WHERE scan_id = ? AND idx = ?",
                ("scan-1", 0),
            )
            store._conn.commit()
            published: list[tuple[str, str, dict]] = []
            finish = AgentScanFinish(
                vulnerabilities=[finding_a, finding_b],
                status="complete",
                total_candidates=1,
                processed_candidates=1,
            )

            with (
                patch(
                    "backend.api.agent.get_scan_store",
                    return_value=store,
                ),
                patch(
                    "backend.api.scan.get_scan_store",
                    return_value=store,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=(
                        lambda scan_id, event_type, data:
                        published.append((scan_id, event_type, data))
                    ),
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(
                [item.engine_id for item in stored],
                ["engine_a", "engine_b"],
            )
            self.assertEqual(stored[0].engine_label, "Engine A")
            self.assertEqual(stored[1].engine_label, "Engine B")
            self.assertTrue(all(
                not hasattr(item, "fp_review_eligible")
                for item in stored
            ))
            vulnerability_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
            ]
            self.assertEqual(len(vulnerability_events), 1)
            self.assertEqual(
                vulnerability_events[0]["vulnerability"]["engine_id"],
                "engine_b",
            )
            self.assertNotIn(
                "fp_review_eligible",
                vulnerability_events[0]["vulnerability"],
            )

    def test_finish_scan_clears_transient_opencode_pool_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=4, processed=2)
            pool = OpenCodePoolStatus(
                scope_id="scan-1",
                global_running=1,
                global_queued=1,
                queued_tasks=[{"task_type": "vulnerability_mining", "checker": "npd"}],
                models=[
                    {
                        "id": "deep",
                        "model": "deep-model",
                        "capability": "high",
                        "max_concurrency": 1,
                        "running": 1,
                        "queued": 1,
                        "total": 2,
                        "success": 1,
                        "last_status": "running",
                        "active_tasks": [{"task_type": "vulnerability_mining"}],
                    }
                ],
            )
            scan.opencode_pool = pool
            store.save_scan(scan, _meta())
            store.update_opencode_pool_status("scan-1", pool)
            agent_api._running_scans["scan-1"] = scan

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    side_effect=_direct_store_call,
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="complete",
                        total_candidates=4,
                        processed_candidates=4,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.COMPLETE)
            self.assertIsNotNone(stored.opencode_pool)
            self.assertEqual(stored.opencode_pool.global_running, 0)
            self.assertEqual(stored.opencode_pool.global_queued, 0)
            self.assertEqual(stored.opencode_pool.queued_tasks, [])
            self.assertEqual(stored.opencode_pool.models[0].running, 0)
            self.assertEqual(stored.opencode_pool.models[0].queued, 0)
            self.assertEqual(stored.opencode_pool.models[0].active_tasks, [])

    def test_active_fp_review_hello_reattaches_disconnect_errored_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="error", error_message="Agent 断开连接"
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_fp_reviews(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "review_id": "review-1"}],
                )

            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.RUNNING)
            self.assertEqual(review.error_message, "")
            meta = store.load_scan("scan-1")[1]
            self.assertEqual(meta.agent_id, "agent-new")

            # The old connection's delayed disconnect-cancel must not kill the
            # review once the scan points at the new agent_id.
            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._mark_agent_scans_cancelled("agent-old")
            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.RUNNING)

    def test_active_fp_review_hello_ignores_user_cancelled_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="cancelled", error_message="用户手动停止"
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_fp_reviews(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "review_id": "review-1"}],
                )

            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.CANCELLED)
            meta = store.load_scan("scan-1")[1]
            self.assertEqual(meta.agent_id, "agent-old")

    def test_stage_output_post_auto_recovers_disconnect_errored_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="error", error_message="Agent 断开连接"
            )

            with patch("backend.api.scan.get_scan_store", return_value=store):
                asyncio.run(scan_api.agent_fp_review_stage_output(
                    "scan-1",
                    AgentFpReviewStageOutput(
                        review_id="review-1",
                        vuln_index=2,
                        stage="prove_bug",
                        markdown="# Prove Bug\n\n正方论证",
                    ),
                ))

            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.RUNNING)
            self.assertEqual(review.error_message, "")
            outputs = store.list_fp_review_stage_outputs_by_review("review-1")
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0].stage, "prove_bug")

    def test_fp_review_merge_keeps_stage_outputs_without_final_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")
            store.upsert_fp_review_stage_output(
                "review-1", 3, "prove_bug", "# Prove Bug", "2026-01-01T00:01:00+00:00"
            )
            job = store.get_fp_review_job("review-1")

            with patch("backend.api.scan.get_scan_store", return_value=store):
                merged = scan_api._merge_latest_fp_review_results(job, "scan-1")

            entries = [r for r in merged.results if r.vuln_index == 3]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].reason, "")
            self.assertEqual(entries[0].stage_outputs, {"prove_bug": "# Prove Bug"})


if __name__ == "__main__":
    unittest.main()
