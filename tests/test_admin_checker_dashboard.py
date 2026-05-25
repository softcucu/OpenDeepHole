import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.admin import get_checker_dashboard
from backend.models import (
    FeedbackEntry,
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    User,
    Vulnerability,
)


class FakeScanStore:
    def __init__(self, scan: ScanStatus, meta: ScanMeta) -> None:
        self.scan = scan
        self.meta = meta

    def list_scans(self) -> list[ScanSummary]:
        return [
            ScanSummary(
                scan_id=self.scan.scan_id,
                project_id=self.scan.project_id,
                status=self.scan.status,
                created_at=self.scan.created_at,
                progress=self.scan.progress,
                total_candidates=self.scan.total_candidates,
                processed_candidates=self.scan.processed_candidates,
                vulnerability_count=len(self.scan.vulnerabilities),
                scan_items=self.meta.scan_items,
                username="alice",
            )
        ]

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        if scan_id != self.scan.scan_id:
            return None
        return self.scan, self.meta

    def list_fp_review_results_by_scan(self, scan_id: str) -> list[FpReviewResult]:
        if scan_id != self.scan.scan_id:
            return []
        return [
            FpReviewResult(
                vuln_index=1,
                verdict="fp",
                reason="reviewed false positive",
                created_at="2026-01-01T00:00:00+00:00",
            ),
            FpReviewResult(
                vuln_index=3,
                verdict="tp",
                reason="reviewed true positive",
                created_at="2026-01-01T00:01:00+00:00",
            ),
        ]

    def list_feedback_by_scan(self, scan_id: str) -> list[FeedbackEntry]:
        if scan_id != self.scan.scan_id:
            return []
        return [
            FeedbackEntry(
                id="feedback-1",
                project_id=self.scan.project_id,
                vuln_type="npd",
                verdict="confirmed",
                file="a.c",
                line=1,
                function="a",
                description="confirmed by llm and human",
                reason="filed",
                ticket_submitted=True,
                ticket_id="BUG-1",
                source_scan_id=scan_id,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            ),
            FeedbackEntry(
                id="feedback-2",
                project_id=self.scan.project_id,
                vuln_type="npd",
                verdict="false_positive",
                file="b.c",
                line=2,
                function="b",
                description="review false positive",
                reason="not filed",
                ticket_submitted=False,
                source_scan_id=scan_id,
                created_at="2026-01-01T00:01:00+00:00",
                updated_at="2026-01-01T00:01:00+00:00",
            ),
        ]


class AdminCheckerDashboardTests(unittest.TestCase):
    def test_summary_includes_review_and_effective_issue_counts(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            scan_items=["npd", "oob"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=4,
            processed_candidates=4,
            vulnerabilities=[
                Vulnerability(
                    file="a.c",
                    line=1,
                    function="a",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed by llm and human",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
                Vulnerability(
                    file="b.c",
                    line=2,
                    function="b",
                    vuln_type="npd",
                    severity="medium",
                    description="review false positive",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="false_positive",
                ),
                Vulnerability(
                    file="c.c",
                    line=3,
                    function="c",
                    vuln_type="npd",
                    severity="low",
                    description="not confirmed",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="not_confirmed",
                ),
                Vulnerability(
                    file="d.c",
                    line=4,
                    function="d",
                    vuln_type="oob",
                    severity="high",
                    description="review true positive",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
            ],
        )
        meta = ScanMeta(
            scan_items=["npd", "oob"],
            created_at=scan.created_at,
            project_path="/repo/project",
            scan_name="Project One",
            agent_name="agent-1",
        )
        registry = {
            "npd": SimpleNamespace(label="NPD", description="null pointer"),
            "oob": SimpleNamespace(label="OOB", description="out of bounds"),
        }

        with (
            patch("backend.api.admin.get_scan_store", return_value=FakeScanStore(scan, meta)),
            patch("backend.api.admin.refresh_registry", return_value=registry),
        ):
            response = asyncio.run(
                get_checker_dashboard(
                    _current_user=User(
                        user_id="admin",
                        username="admin",
                        role="admin",
                    )
                )
            )

        self.assertEqual(response.summary.static_issue_count, 4)
        self.assertEqual(response.summary.llm_issue_count, 3)
        self.assertEqual(response.summary.fp_review_issue_count, 1)
        self.assertEqual(response.summary.fp_review_false_positive_count, 1)
        self.assertEqual(response.summary.total_issue_count, 2)
        self.assertEqual(response.summary.human_confirmed_count, 2)
        self.assertEqual(response.summary.ticket_submitted_count, 1)
        self.assertEqual(response.summary.accuracy_basis_count, 2)
        self.assertEqual(response.summary.accuracy, 1.0)
        npd = next(checker for checker in response.checkers if checker.checker == "npd")
        self.assertEqual(npd.ticket_submitted_count, 1)
        self.assertEqual(npd.scans[0].ticket_submitted_count, 1)


if __name__ == "__main__":
    unittest.main()
