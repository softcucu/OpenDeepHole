import asyncio
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from backend.api import agent as agent_api
from backend.api import integration as integration_api
from backend.api import scan as scan_api
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    FeedbackEntry,
    MarkRequest,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    UnmarkRequest,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


def _request() -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://testserver/",
        query_params={"token": "scan-token"},
    )


class ExternalIntegrationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_configs.clear()
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def tearDown(self) -> None:
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_configs.clear()
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def test_invalid_integration_token_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            integration_api._require_integration_token("wrong-token")

        self.assertEqual(ctx.exception.status_code, 401)

    def test_create_integration_scan_syncs_config_before_task_and_uses_public_checkers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            user = User(
                user_id="integration-user",
                username="integration",
                role="user",
                agent_token=integration_api.INTEGRATION_TOKEN,
            )
            agent_api._registered_agents["agent-1"] = AgentInfo(
                agent_id="agent-1",
                name="reverse-linux-agent",
                ip="127.0.0.1",
                last_seen=datetime.now(timezone.utc).isoformat(),
                user_id="other-user",
            )
            agent_api._agent_ws["agent-1"] = object()

            registry = {
                "public_check": SimpleNamespace(visibility="public"),
                "admin_check": SimpleNamespace(visibility="admin"),
            }
            send = AsyncMock(return_value=True)
            with (
                patch("backend.api.integration.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.refresh_registry", return_value=registry),
                patch("backend.api.integration.refresh_registry", return_value=registry),
                patch("backend.api.scan.build_checker_packages", return_value=[]),
                patch("backend.api.agent.send_agent_command", send),
            ):
                result = asyncio.run(
                    integration_api.create_integration_scan(
                        integration_api.IntegrationScanRequest(
                            agent_name="reverse-linux-agent",
                            project_path="/repo/project",
                            scan_name="project",
                            product="LTE",
                            validation_environment="仿真UBBPi板环境",
                            agent_config=AgentRemoteConfig(
                                opencode={"tool": "opencode", "executable": "opencode", "model": "model"},
                            ),
                        ),
                        _request(),
                        current_user=user,
                    )
                )

            self.assertEqual(result.checkers, ["public_check"])
            self.assertIn("/#/public-scan/", result.result_url)
            loaded = store.load_scan(result.scan_id)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded[1].scan_items, ["public_check"])
            self.assertEqual(loaded[1].validation_environment, "仿真UBBPi板环境")
            self.assertTrue(loaded[1].public_access_token)
            self.assertEqual([call.args[1]["type"] for call in send.call_args_list], ["config", "task"])
            self.assertEqual(send.call_args_list[1].args[1]["validation_environment"], "仿真UBBPi板环境")

    def test_public_scan_token_allows_marking_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.create_user("owner", "owner", "hash", "user", "owner-token")
            vuln = Vulnerability(
                file="a.c",
                line=1,
                function="f",
                vuln_type="public_check",
                severity="high",
                description="desc",
                ai_analysis="analysis",
                confirmed=True,
            )
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["public_check"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["public_check"],
                created_at=scan.created_at,
                user_id="owner",
                public_access_token="scan-token",
            )
            store.save_scan(scan, meta)
            store.add_vulnerability("scan-1", vuln)

            with (
                patch("backend.api.integration.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                user = integration_api._public_user_for_scan("scan-1", "scan-token")
                result = asyncio.run(
                    integration_api.mark_public_vulnerability(
                        "scan-1",
                        MarkRequest(index=0, verdict="confirmed", reason="verified"),
                        current_user=user,
                    )
                )

                with self.assertRaises(HTTPException) as ctx:
                    integration_api._public_user_for_scan("scan-1", "bad-token")

            self.assertTrue(result["feedback_id"])
            self.assertEqual(ctx.exception.status_code, 403)
            updated = store.get_vulnerabilities("scan-1")[0]
            self.assertEqual(updated.user_verdict, "confirmed")

    def test_public_scan_pending_analysis_does_not_create_feedback_and_removes_old_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.create_user("owner", "owner", "hash", "user", "owner-token")
            vuln = Vulnerability(
                file="a.c",
                line=1,
                function="f",
                vuln_type="public_check",
                severity="high",
                description="desc",
                ai_analysis="analysis",
                confirmed=True,
                user_verdict="confirmed",
                user_verdict_reason="verified",
            )
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["public_check"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["public_check"],
                created_at=scan.created_at,
                user_id="owner",
                public_access_token="scan-token",
                feedback_ids=["old-feedback"],
            )
            store.save_scan(scan, meta)
            store.add_vulnerability("scan-1", vuln)
            store.add_feedback(
                FeedbackEntry(
                    id="old-feedback",
                    project_id="project",
                    vuln_type="public_check",
                    verdict="confirmed",
                    file="a.c",
                    line=1,
                    function="f",
                    description="desc",
                    reason="verified",
                    source_scan_id="scan-1",
                    created_at="2026-01-01T00:00:00+00:00",
                    updated_at="2026-01-01T00:00:00+00:00",
                )
            )

            with (
                patch("backend.api.integration.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                user = integration_api._public_user_for_scan("scan-1", "scan-token")
                result = asyncio.run(
                    integration_api.mark_public_vulnerability(
                        "scan-1",
                        MarkRequest(index=0, verdict="pending_analysis", reason="needs review"),
                        current_user=user,
                    )
                )

            self.assertIsNone(result["feedback_id"])
            self.assertEqual(result["removed_feedback_ids"], ["old-feedback"])
            self.assertEqual(store.list_feedback_by_scan("scan-1"), [])
            updated_scan, updated_meta = store.load_scan("scan-1")
            self.assertEqual(updated_scan.vulnerabilities[0].user_verdict, "pending_analysis")
            self.assertEqual(updated_scan.vulnerabilities[0].user_verdict_reason, "needs review")
            self.assertEqual(updated_meta.feedback_ids, [])

    def test_public_scan_token_allows_unmarking_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.create_user("owner", "owner", "hash", "user", "owner-token")
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["public_check"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[],
                feedback_ids=[],
            )
            meta = ScanMeta(
                scan_items=["public_check"],
                created_at=scan.created_at,
                user_id="owner",
                public_access_token="scan-token",
            )
            store.save_scan(scan, meta)
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="a.c",
                    line=1,
                    function="f",
                    vuln_type="public_check",
                    severity="high",
                    description="desc",
                    ai_analysis="analysis",
                    confirmed=True,
                    user_verdict="confirmed",
                    user_verdict_reason="verified",
                ),
            )

            with (
                patch("backend.api.integration.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                user = integration_api._public_user_for_scan("scan-1", "scan-token")
                result = asyncio.run(
                    integration_api.unmark_public_vulnerability(
                        "scan-1",
                        UnmarkRequest(index=0),
                        current_user=user,
                    )
                )

                with self.assertRaises(HTTPException) as ctx:
                    integration_api._public_user_for_scan("scan-1", "bad-token")

            self.assertTrue(result["ok"])
            self.assertEqual(ctx.exception.status_code, 403)
            updated = store.get_vulnerabilities("scan-1")[0]
            self.assertIsNone(updated.user_verdict)


if __name__ == "__main__":
    unittest.main()
