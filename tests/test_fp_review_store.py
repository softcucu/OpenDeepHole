import tempfile
import unittest
from pathlib import Path

from backend.models import FpReviewResult, FpReviewStatus
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

    def test_tracks_current_fp_review_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.create_fp_review_job("review", "scan-1", 2, "2026-01-01T00:00:00+00:00")

            store.update_fp_review_job("review", status="running", current_vuln_index=7)
            running = store.get_fp_review_job("review")
            self.assertIsNotNone(running)
            self.assertEqual(running.current_vuln_index, 7)

            store.update_fp_review_job("review", status="complete", clear_current_vuln_index=True)
            complete = store.get_fp_review_job("review")
            self.assertIsNotNone(complete)
            self.assertIsNone(complete.current_vuln_index)

    def test_can_mark_fp_review_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.create_fp_review_job("review", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review", status="running", current_vuln_index=7)

            store.update_fp_review_job(
                "review",
                status="cancelled",
                clear_current_vuln_index=True,
                error_message="用户手动停止",
            )

            job = store.get_fp_review_job("review")
            self.assertIsNotNone(job)
            self.assertEqual(job.status, FpReviewStatus.CANCELLED)
            self.assertIsNone(job.current_vuln_index)
            self.assertEqual(job.error_message, "用户手动停止")

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

    def test_migrates_fp_review_job_current_target_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scan.db"
            store = SqliteScanStore(db_path)
            store._conn.execute("DROP TABLE fp_review_jobs")
            store._conn.execute(
                """\
                CREATE TABLE fp_review_jobs (
                    review_id     TEXT PRIMARY KEY,
                    scan_id       TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'pending',
                    created_at    TEXT NOT NULL,
                    total         INTEGER DEFAULT 0,
                    processed     INTEGER DEFAULT 0,
                    error_message TEXT
                )
                """
            )
            store._conn.commit()
            store._conn.close()

            migrated = SqliteScanStore(db_path)
            migrated.create_fp_review_job("review", "scan-1", 1, "2026-01-01T00:00:00+00:00")
            migrated.update_fp_review_job("review", current_vuln_index=3)
            job = migrated.get_fp_review_job("review")
            self.assertIsNotNone(job)
            self.assertEqual(job.current_vuln_index, 3)


if __name__ == "__main__":
    unittest.main()
