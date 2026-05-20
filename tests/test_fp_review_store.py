import tempfile
import unittest
from pathlib import Path

from backend.models import FpReviewResult
from backend.store.sqlite import SqliteScanStore


class FpReviewStoreTests(unittest.TestCase):
    def test_lists_results_for_scan_oldest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.create_fp_review_job("old", "scan-1", 1, "2026-01-01T00:00:00+00:00")
            store.create_fp_review_job("new", "scan-1", 1, "2026-01-02T00:00:00+00:00")
            store.add_fp_review_result(
                "old",
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    severity="low",
                    reason="old false positive",
                    vulnerability_report="",
                    created_at="2026-01-01T00:01:00+00:00",
                ),
            )
            store.add_fp_review_result(
                "new",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="new true positive",
                    vulnerability_report="# report\n\ncall chain",
                    created_at="2026-01-02T00:01:00+00:00",
                ),
            )

            results = store.list_fp_review_results_by_scan("scan-1")

            self.assertEqual([r.reason for r in results], ["old false positive", "new true positive"])
            self.assertEqual(results[1].severity, "high")
            self.assertEqual(results[1].vulnerability_report, "# report\n\ncall chain")

    def test_migrates_fp_review_severity_and_report_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scan.db"
            store = SqliteScanStore(db_path)
            store._conn.execute("DROP TABLE fp_review_results")
            store._conn.execute(
                """\
                CREATE TABLE fp_review_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    review_id   TEXT NOT NULL,
                    vuln_index  INTEGER NOT NULL,
                    verdict     TEXT NOT NULL,
                    reason      TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    UNIQUE(review_id, vuln_index)
                )
                """
            )
            store._conn.commit()
            store._conn.close()

            migrated = SqliteScanStore(db_path)
            migrated.create_fp_review_job("review", "scan-1", 1, "2026-01-01T00:00:00+00:00")
            migrated.add_fp_review_result(
                "review",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="medium",
                    reason="code issue",
                    vulnerability_report="",
                    created_at="2026-01-01T00:01:00+00:00",
                ),
            )

            results = migrated.list_fp_review_results_by_scan("scan-1")
            self.assertEqual(results[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
