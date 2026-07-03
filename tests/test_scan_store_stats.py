import tempfile
import unittest
from pathlib import Path

from backend.models import (
    Candidate,
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


def _make_scan(scan_id: str, user_id: str = "user-1") -> tuple[ScanStatus, ScanMeta]:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id=f"project-{scan_id}",
        scan_items=["npd"],
        created_at="2026-01-01T00:00:00+00:00",
        status=ScanItemStatus.COMPLETE,
        progress=1.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["npd"],
        created_at=scan.created_at,
        agent_id="agent-id-1",
        agent_name="agent-1",
        project_path="/tmp/project",
        scan_name=f"Scan {scan_id}",
        product="LTE",
        user_id=user_id,
    )
    return scan, meta


def _make_vuln(
    idx: int,
    *,
    ai_verdict: str = "confirmed",
    user_verdict: str | None = None,
    audit_index: int | None = None,
) -> Vulnerability:
    return Vulnerability(
        file=f"f{idx}.c",
        line=idx,
        function=f"fn{idx}",
        vuln_type="npd",
        severity="high",
        description=f"desc {idx}",
        ai_analysis=f"analysis {idx}",
        confirmed=True,
        ai_verdict=ai_verdict,
        user_verdict=user_verdict,
        audit_index=audit_index,
    )


class VulnerabilityStoreTests(unittest.TestCase):
    def test_vulnerability_audit_index_round_trips_and_upsert_updates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_make_scan("scan-1"))
            store.add_vulnerability("scan-1", _make_vuln(1, audit_index=7))
            timeout = _make_vuln(2, ai_verdict="failed", audit_index=9).model_copy(
                update={"confirmed": False, "severity": "unknown"},
            )
            store.add_vulnerability("scan-1", timeout)

            replacement = _make_vuln(2, audit_index=3)
            index = store.upsert_incomplete_vulnerability("scan-1", replacement)

            self.assertEqual(index, 1)
            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual([v.audit_index for v in stored], [7, 3])
            self.assertEqual(stored[1].ai_verdict, "confirmed")

    def test_migrates_vulnerability_audit_index_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scan.db"
            store = SqliteScanStore(db_path)
            store._conn.execute("DROP TABLE vulnerabilities")
            store._conn.execute(
                """\
                CREATE TABLE vulnerabilities (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                    idx                 INTEGER NOT NULL,
                    file                TEXT NOT NULL,
                    line                INTEGER NOT NULL,
                    function            TEXT NOT NULL,
                    vuln_type           TEXT NOT NULL,
                    severity            TEXT NOT NULL,
                    description         TEXT NOT NULL,
                    ai_analysis         TEXT NOT NULL,
                    confirmed           INTEGER NOT NULL,
                    ai_verdict          TEXT NOT NULL DEFAULT '',
                    failure_reason      TEXT NOT NULL DEFAULT '',
                    function_source     TEXT NOT NULL DEFAULT '',
                    function_start_line INTEGER,
                    user_verdict        TEXT,
                    user_verdict_reason TEXT,
                    ticket_submitted    INTEGER NOT NULL DEFAULT 0,
                    ticket_id           TEXT NOT NULL DEFAULT '',
                    variant_of          TEXT NOT NULL DEFAULT '',
                    output_source       TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(scan_id, idx)
                )
                """
            )
            store._conn.commit()
            store._conn.close()

            migrated = SqliteScanStore(db_path)
            cols = {row[1] for row in migrated._conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()}
            self.assertIn("audit_index", cols)
            migrated.save_scan(*_make_scan("scan-1"))
            migrated.add_vulnerability("scan-1", _make_vuln(1, audit_index=5))
            self.assertEqual(migrated.get_vulnerabilities("scan-1")[0].audit_index, 5)


class VulnStatsStoreTests(unittest.TestCase):
    def test_batch_stats_grouped_by_scan_and_match_full_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            for sid in ("scan-1", "scan-2"):
                store.save_scan(*_make_scan(sid))
            store.add_vulnerability("scan-1", _make_vuln(1, user_verdict="confirmed"))
            store.add_vulnerability("scan-1", _make_vuln(2, ai_verdict="timeout"))
            store.add_vulnerability("scan-2", _make_vuln(3, ai_verdict="not_confirmed"))

            stats = store.get_vuln_stats_by_scans(["scan-1", "scan-2", "scan-missing"])

            self.assertEqual(set(stats.keys()), {"scan-1", "scan-2", "scan-missing"})
            self.assertEqual(len(stats["scan-1"]), 2)
            self.assertEqual(stats["scan-missing"], [])
            full = store.get_vulnerabilities("scan-1")
            for stat, vuln in zip(stats["scan-1"], full):
                self.assertEqual(stat.vuln_type, vuln.vuln_type)
                self.assertEqual(stat.ai_verdict, vuln.ai_verdict)
                self.assertEqual(stat.confirmed, vuln.confirmed)
                self.assertEqual(stat.user_verdict, vuln.user_verdict)

    def test_batch_stats_chunking_over_500_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_make_scan("scan-1"))
            store.add_vulnerability("scan-1", _make_vuln(1))

            ids = [f"scan-{i}" for i in range(2, 602)] + ["scan-1"]
            stats = store.get_vuln_stats_by_scans(ids)

            self.assertEqual(len(stats), 601)
            self.assertEqual(len(stats["scan-1"]), 1)


class FpReviewVerdictsStoreTests(unittest.TestCase):
    def test_verdicts_grouped_and_ordered_like_full_query(self) -> None:
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
                    vulnerability_report="big report",
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
                    vulnerability_report="big report",
                    created_at="2026-01-02T00:01:00+00:00",
                ),
            )

            verdicts = store.list_fp_review_verdicts_by_scans(["scan-1", "scan-missing"])
            full = store.list_fp_review_results_by_scan("scan-1")

            self.assertEqual(verdicts["scan-missing"], [])
            self.assertEqual(
                [(r.vuln_index, r.verdict, r.reason) for r in verdicts["scan-1"]],
                [(r.vuln_index, r.verdict, r.reason) for r in full],
            )
            # 轻量查询不携带大字段
            self.assertEqual(verdicts["scan-1"][0].vulnerability_report, "")


class ScanMetaStoreTests(unittest.TestCase):
    def test_get_scan_meta_equals_load_scan_meta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_make_scan("scan-1", user_id="user-9"))

            meta = store.get_scan_meta("scan-1")

            self.assertIsNotNone(meta)
            self.assertEqual(meta, store.load_scan("scan-1")[1])
            self.assertIsNone(store.get_scan_meta("scan-missing"))


class ScanCandidateStoreTests(unittest.TestCase):
    def test_candidates_are_replaced_and_loaded_with_scan_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            scan, meta = _make_scan("scan-1")
            store.save_scan(scan, meta)

            first = Candidate(
                file="src/a.c",
                line=10,
                function="foo",
                description="desc a",
                vuln_type="npd",
                related_functions=["bar"],
                metadata={"subject": "ptr"},
            )
            second = Candidate(
                file="src/b.c",
                line=20,
                function="baz",
                description="desc b",
                vuln_type="memleak",
            )

            persisted = store.replace_scan_candidates("scan-1", [first, second])
            loaded = store.load_scan("scan-1")

            self.assertEqual([candidate.idx for candidate in persisted], [0, 1])
            self.assertIsNotNone(loaded)
            loaded_scan, _ = loaded
            self.assertEqual(len(loaded_scan.candidates), 2)
            self.assertEqual(loaded_scan.candidates[0].file, "src/a.c")
            self.assertEqual(loaded_scan.candidates[0].related_functions, ["bar"])
            self.assertEqual(loaded_scan.candidates[0].metadata["subject"], "ptr")

            replacement = Candidate(
                file="src/c.c",
                line=30,
                function="qux",
                description="desc c",
                vuln_type="oob",
            )
            store.replace_scan_candidates("scan-1", [replacement])

            self.assertEqual(len(store.list_scan_candidates("scan-1")), 1)
            self.assertEqual(store.load_scan("scan-1")[0].candidates[0].file, "src/c.c")


if __name__ == "__main__":
    unittest.main()
