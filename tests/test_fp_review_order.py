import asyncio
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.store.sqlite import SqliteScanStore
from backend.api.scan import _ordered_fp_review_candidates
from backend.models import AgentInfo, FpReviewResult, ScanItemStatus, ScanMeta, ScanStatus, User, Vulnerability
from backend.scan_metrics import latest_fp_review_result_map


class FpReviewOrderTests(unittest.TestCase):
    def tearDown(self) -> None:
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def test_unreviewed_findings_are_reviewed_before_existing_results(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            scan_items=["npd"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=3,
            processed_candidates=3,
            vulnerabilities=[
                Vulnerability(
                    file="reviewed.c",
                    line=1,
                    function="reviewed",
                    vuln_type="npd",
                    severity="high",
                    description="reviewed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="unreviewed.c",
                    line=2,
                    function="unreviewed",
                    vuln_type="npd",
                    severity="high",
                    description="unreviewed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="manual.c",
                    line=3,
                    function="manual",
                    vuln_type="npd",
                    severity="high",
                    description="manual feedback",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
            ],
        )
        latest = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=0,
                verdict="fp",
                severity="low",
                reason="reviewed false positive",
                created_at="2026-01-01T00:01:00+00:00",
            ),
        ])

        ordered = _ordered_fp_review_candidates(scan, latest)

        self.assertEqual([item["index"] for item in ordered], [1, 0])

    def test_legacy_no_result_placeholder_is_not_effective(self) -> None:
        latest = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=0,
                verdict="tp",
                severity="low",
                reason="Review incomplete — no result returned",
                created_at="2026-01-01T00:01:00+00:00",
            ),
            FpReviewResult(
                vuln_index=1,
                verdict="tp",
                severity="medium",
                reason="real result",
                created_at="2026-01-01T00:02:00+00:00",
            ),
        ])

        self.assertNotIn(0, latest)
        self.assertIn(1, latest)

    def test_trigger_fp_review_dispatches_runtime_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            user = User(user_id="owner", username="owner", role="user")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[
                    Vulnerability(
                        file="a.c",
                        line=10,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description="desc",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                agent_id="agent-1",
                agent_name="agent",
                project_path="/repo/project",
                scan_name="project",
                user_id="owner",
            )
            store.save_scan(scan, meta)
            scan_api._running_scans["scan-1"] = scan
            scan_api._scan_owners["scan-1"] = "owner"
            agent_api._registered_agents["agent-1"] = AgentInfo(
                agent_id="agent-1",
                name="agent",
                ip="127.0.0.1",
                last_seen=now,
                user_id="owner",
            )
            agent_api._agent_ws["agent-1"] = object()
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.send_agent_command", send),
                patch(
                    "backend.api.agent.create_agent_runtime_update_payload",
                    return_value={"hash": "runtime-hash"},
                ) as runtime_update,
            ):
                result = asyncio.run(
                    scan_api.trigger_fp_review(
                        "scan-1",
                        SimpleNamespace(base_url="http://server.example/"),
                        user,
                    )
                )

            self.assertTrue(result["ok"])
            runtime_update.assert_called_once_with("http://server.example")
            command = send.await_args.args[1]
            self.assertEqual(command["type"], "fp_review")
            self.assertEqual(command["agent_runtime_update"], {"hash": "runtime-hash"})


if __name__ == "__main__":
    unittest.main()
