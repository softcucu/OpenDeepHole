import asyncio
import unittest
from unittest.mock import patch

from backend.api.scan import list_scans
from backend.models import (
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    User,
    Vulnerability,
)
from backend.scan_metrics import VulnStat


class FakeScanStore:
    def __init__(self, scan: ScanStatus, meta: ScanMeta) -> None:
        self.scan = scan
        self.meta = meta

    def list_scans(self) -> list[ScanSummary]:
        return [self._summary()]

    def list_scans_by_user(self, user_id: str) -> list[ScanSummary]:
        return [self._summary()]

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        if scan_id != self.scan.scan_id:
            return None
        return self.scan, self.meta

    def get_vuln_stats_by_scans(self, scan_ids: list[str]) -> dict[str, list[VulnStat]]:
        out: dict[str, list[VulnStat]] = {sid: [] for sid in scan_ids}
        if self.scan.scan_id in out:
            out[self.scan.scan_id] = [
                VulnStat(
                    vuln_type=v.vuln_type,
                    ai_verdict=v.ai_verdict,
                    confirmed=v.confirmed,
                    user_verdict=v.user_verdict,
                )
                for v in self.scan.vulnerabilities
            ]
        return out

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
        ]

    def list_fp_review_verdicts_by_scans(self, scan_ids: list[str]) -> dict[str, list[FpReviewResult]]:
        return {sid: self.list_fp_review_results_by_scan(sid) for sid in scan_ids}

    def get_incomplete_threat_audit_counts(self, _scan_ids: list[str]) -> dict[str, int]:
        return {}

    def _summary(self) -> ScanSummary:
        return ScanSummary(
            scan_id=self.scan.scan_id,
            project_id=self.scan.project_id,
            scan_name=self.meta.scan_name,
            product=self.meta.product,
            status=self.scan.status,
            created_at=self.scan.created_at,
            progress=self.scan.progress,
            total_candidates=self.scan.total_candidates,
            processed_candidates=self.scan.processed_candidates,
            vulnerability_count=len(self.scan.vulnerabilities),
            scan_items=self.meta.scan_items,
            username="alice",
            agent_name=self.meta.agent_name,
        )


class ScanHistorySummaryTests(unittest.TestCase):
    def test_list_scans_uses_project_name_and_effective_issue_counts(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            product="LTE",
            scan_items=["npd"],
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
                    description="fp review rejected",
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
                    vuln_type="npd",
                    severity="high",
                    description="confirmed by llm and human",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
            ],
        )
        meta = ScanMeta(
            scan_items=["npd"],
            created_at=scan.created_at,
            scan_name="Project One",
            product="LTE",
            agent_name="agent-1",
        )

        with (
            patch("backend.api.scan.get_scan_store", return_value=FakeScanStore(scan, meta)),
            patch("backend.api.agent.is_agent_name_online", return_value=True),
        ):
            response = asyncio.run(
                list_scans(
                    current_user=User(
                        user_id="admin",
                        username="admin",
                        role="admin",
                    )
                )
            )

        self.assertEqual(response[0].scan_name, "Project One")
        self.assertEqual(response[0].product, "LTE")
        self.assertEqual(response[0].vulnerability_count, 2)
        self.assertEqual(response[0].human_confirmed_count, 2)


if __name__ == "__main__":
    unittest.main()
