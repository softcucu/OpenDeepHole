import unittest

from backend.models import Vulnerability
from backend.scan_metrics import calculate_issue_metrics


class ScanMetricsTests(unittest.TestCase):
    def test_pending_analysis_is_not_counted_as_human_verdict(self) -> None:
        metrics = calculate_issue_metrics(
            [
                Vulnerability(
                    file="pending.c",
                    line=1,
                    function="pending",
                    vuln_type="npd",
                    severity="high",
                    description="pending",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="pending_analysis",
                ),
                Vulnerability(
                    file="confirmed.c",
                    line=2,
                    function="confirmed",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
                Vulnerability(
                    file="fp.c",
                    line=3,
                    function="fp",
                    vuln_type="npd",
                    severity="high",
                    description="fp",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="false_positive",
                ),
            ],
            {},
        )

        self.assertEqual(metrics.human_confirmed_count, 1)
        self.assertEqual(metrics.human_false_positive_count, 1)
        self.assertEqual(metrics.accuracy_basis_count, 3)
        self.assertEqual(metrics.accuracy, 0.3333)


if __name__ == "__main__":
    unittest.main()
