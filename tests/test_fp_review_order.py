import unittest

from backend.api.scan import _ordered_fp_review_candidates
from backend.models import FpReviewResult, ScanItemStatus, ScanStatus, Vulnerability
from backend.scan_metrics import latest_fp_review_result_map


class FpReviewOrderTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
