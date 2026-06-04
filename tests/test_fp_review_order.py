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
from backend.api.scan import _ordered_fp_review_candidates, _retry_incomplete_candidates
from backend.models import (
    AgentInfo,
    BatchUnmarkRequest,
    FeedbackEntry,
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    UnmarkRequest,
    User,
    Vulnerability,
)
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
            total_candidates=4,
            processed_candidates=4,
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
                Vulnerability(
                    file="pending.c",
                    line=4,
                    function="pending",
                    vuln_type="npd",
                    severity="high",
                    description="pending manual analysis",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="pending_analysis",
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

        self.assertEqual([item["index"] for item in ordered], [1, 3, 0])

    def test_pending_analysis_does_not_block_incomplete_retry(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            scan_items=["npd"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=2,
            processed_candidates=2,
            vulnerabilities=[
                Vulnerability(
                    file="pending.c",
                    line=1,
                    function="pending",
                    vuln_type="npd",
                    severity="unknown",
                    description="timeout pending",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="timeout",
                    user_verdict="pending_analysis",
                ),
                Vulnerability(
                    file="manual.c",
                    line=2,
                    function="manual",
                    vuln_type="npd",
                    severity="unknown",
                    description="timeout manual",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="timeout",
                    user_verdict="false_positive",
                ),
            ],
        )

        candidates = _retry_incomplete_candidates(scan)

        self.assertEqual([candidate.function for candidate in candidates], ["pending"])

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

    def test_unmark_removes_generated_feedback_and_readds_fp_review_candidate(self) -> None:
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
                vulnerabilities=[],
                feedback_ids=["feedback-1", "keep"],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                feedback_ids=["feedback-1", "keep"],
                user_id="owner",
            )
            store.save_scan(scan, meta)
            store.add_vulnerability(
                "scan-1",
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
                    user_verdict="confirmed",
                    user_verdict_reason="verified",
                ),
            )
            store.add_feedback(
                FeedbackEntry(
                    id="feedback-1",
                    project_id="project",
                    vuln_type="npd",
                    verdict="confirmed",
                    file="a.c",
                    line=10,
                    function="parse",
                    description="desc",
                    reason="verified",
                    source_scan_id="scan-1",
                    created_at=now,
                    updated_at=now,
                )
            )
            push = AsyncMock()

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan._push_feedback_selection_update", push),
            ):
                result = asyncio.run(
                    scan_api.unmark_vulnerability("scan-1", UnmarkRequest(index=0), user)
                )

            self.assertEqual(result["removed_feedback_ids"], ["feedback-1"])
            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            updated_scan, updated_meta = loaded
            self.assertEqual(updated_scan.feedback_ids, ["keep"])
            self.assertEqual(updated_meta.feedback_ids, ["keep"])
            self.assertIsNone(updated_scan.vulnerabilities[0].user_verdict)
            self.assertEqual([item["index"] for item in _ordered_fp_review_candidates(updated_scan, {})], [0])
            push.assert_awaited_once_with("scan-1", ["keep"])

    def test_batch_unmark_clears_multiple_manual_verdicts(self) -> None:
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
                total_candidates=2,
                processed_candidates=2,
                vulnerabilities=[],
                feedback_ids=["feedback-1", "feedback-2"],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                feedback_ids=["feedback-1", "feedback-2"],
                user_id="owner",
            )
            store.save_scan(scan, meta)
            for index in range(2):
                store.add_vulnerability(
                    "scan-1",
                    Vulnerability(
                        file=f"a{index}.c",
                        line=10 + index,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description=f"desc {index}",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                        user_verdict="confirmed",
                    ),
                )
                store.add_feedback(
                    FeedbackEntry(
                        id=f"feedback-{index + 1}",
                        project_id="project",
                        vuln_type="npd",
                        verdict="confirmed",
                        file=f"a{index}.c",
                        line=10 + index,
                        function="parse",
                        description=f"desc {index}",
                        reason="verified",
                        source_scan_id="scan-1",
                        created_at=now,
                        updated_at=now,
                    )
                )

            with patch("backend.api.scan.get_scan_store", return_value=store):
                result = asyncio.run(
                    scan_api.batch_unmark_vulnerabilities(
                        "scan-1",
                        BatchUnmarkRequest(indices=[0, 1, 1]),
                        user,
                    )
                )

            self.assertEqual(result["removed_feedback_ids"], ["feedback-1", "feedback-2"])
            updated_scan, updated_meta = store.load_scan("scan-1")
            self.assertEqual(updated_scan.feedback_ids, [])
            self.assertEqual(updated_meta.feedback_ids, [])
            self.assertEqual([v.user_verdict for v in updated_scan.vulnerabilities], [None, None])


if __name__ == "__main__":
    unittest.main()
