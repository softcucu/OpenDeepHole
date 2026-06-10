import tempfile
import unittest
import sqlite3
from pathlib import Path

from agent.scanner import (
    STATIC_PROGRESS_MIN_INTERVAL_SECONDS,
    _StaticProgressGate,
    _audit_order_summary,
    _candidate_in_scan_scope,
    _candidate_key,
    _normalize_candidate_for_project,
    _order_candidates_for_audit,
    _resolve_scan_paths,
    build_project_level_candidate,
    is_project_level_candidate,
)
from backend.models import Candidate, OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore


def _candidate(vuln_type: str, line: int) -> Candidate:
    return Candidate(
        file=f"{vuln_type}.c",
        line=line,
        function=f"{vuln_type}_fn_{line}",
        description=f"{vuln_type} candidate {line}",
        vuln_type=vuln_type,
    )


class AgentScanPathTests(unittest.TestCase):
    def test_resolve_relative_code_scan_path_under_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "src"
            scan_dir.mkdir(parents=True)

            project_root, code_scan_root = _resolve_scan_paths(project, Path("src"))

            self.assertEqual(project_root, project.resolve())
            self.assertEqual(code_scan_root, scan_dir.resolve())

    def test_reject_code_scan_path_outside_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            outside = Path(tmp) / "other"
            project.mkdir()
            outside.mkdir()

            with self.assertRaises(ValueError):
                _resolve_scan_paths(project, outside)

    def test_normalize_scan_relative_candidate_to_project_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "module"
            source = scan_dir / "foo.c"
            source.parent.mkdir(parents=True)
            source.write_text("int demo(void) { return 1; }\n", encoding="utf-8")
            candidate = Candidate(
                file="foo.c",
                line=1,
                function="demo",
                description="candidate",
                vuln_type="npd",
            )

            normalized = _normalize_candidate_for_project(
                candidate,
                project.resolve(),
                scan_dir.resolve(),
            )

            self.assertEqual(normalized.file, "module/foo.c")
            self.assertTrue(_candidate_in_scan_scope(normalized, project.resolve(), scan_dir.resolve()))

    def test_candidate_scope_filter_excludes_other_project_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "module"
            other_source = project / "other" / "bar.c"
            scan_dir.mkdir(parents=True)
            other_source.parent.mkdir(parents=True)
            other_source.write_text("int other(void) { return 1; }\n", encoding="utf-8")
            candidate = Candidate(
                file="other/bar.c",
                line=1,
                function="other",
                description="candidate",
                vuln_type="npd",
            )

            self.assertFalse(_candidate_in_scan_scope(candidate, project.resolve(), scan_dir.resolve()))

    def test_project_level_candidate_represents_code_scan_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "module"
            scan_dir.mkdir(parents=True)
            entry = type("Entry", (), {"name": "skillonly", "label": "Skill Only"})()

            candidate = build_project_level_candidate(entry, project.resolve(), scan_dir.resolve())

            self.assertEqual(candidate.file, "module")
            self.assertEqual(candidate.line, 1)
            self.assertEqual(candidate.function, "__project__")
            self.assertEqual(candidate.vuln_type, "skillonly")
            self.assertTrue(is_project_level_candidate(candidate))


class AgentAuditOrderingTests(unittest.TestCase):
    def test_orders_candidates_by_checker_candidate_count(self) -> None:
        candidates = [
            _candidate("memleak", 1),
            _candidate("npd", 1),
            _candidate("memleak", 2),
            _candidate("intoverflow", 1),
            _candidate("memleak", 3),
            _candidate("intoverflow", 2),
        ]

        ordered = _order_candidates_for_audit(
            candidates,
            ["memleak", "npd", "intoverflow"],
        )

        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered],
            [
                ("npd", 1),
                ("intoverflow", 1),
                ("intoverflow", 2),
                ("memleak", 1),
                ("memleak", 2),
                ("memleak", 3),
            ],
        )

    def test_equal_counts_keep_selected_checker_order(self) -> None:
        candidates = [
            _candidate("intoverflow", 1),
            _candidate("memleak", 1),
            _candidate("npd", 1),
            _candidate("intoverflow", 2),
            _candidate("memleak", 2),
            _candidate("npd", 2),
        ]

        ordered = _order_candidates_for_audit(
            candidates,
            ["npd", "memleak", "intoverflow"],
        )

        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered],
            [
                ("npd", 1),
                ("npd", 2),
                ("memleak", 1),
                ("memleak", 2),
                ("intoverflow", 1),
                ("intoverflow", 2),
            ],
        )

    def test_resume_order_uses_remaining_candidate_counts(self) -> None:
        candidates = [
            _candidate("small", 1),
            _candidate("large", 1),
            _candidate("large", 2),
            _candidate("small", 2),
            _candidate("large", 3),
        ]
        processed_keys = {_candidate_key(candidates[3])}
        remaining = [c for c in candidates if _candidate_key(c) not in processed_keys]

        ordered = _order_candidates_for_audit(remaining, ["small", "large"])

        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered],
            [
                ("small", 1),
                ("large", 1),
                ("large", 2),
                ("large", 3),
            ],
        )

    def test_single_checker_order_is_unchanged(self) -> None:
        candidates = [
            _candidate("npd", 3),
            _candidate("npd", 1),
            _candidate("npd", 2),
        ]

        ordered = _order_candidates_for_audit(candidates, ["npd"])

        self.assertEqual([c.line for c in ordered], [3, 1, 2])

    def test_audit_order_summary_uses_actual_audit_order(self) -> None:
        candidates = [
            _candidate("npd", 1),
            _candidate("intoverflow", 1),
            _candidate("intoverflow", 2),
            _candidate("memleak", 1),
            _candidate("memleak", 2),
        ]

        self.assertEqual(
            _audit_order_summary(candidates),
            "npd=1, intoverflow=2, memleak=2",
        )


class ScanStoreCodeScanPathTests(unittest.TestCase):
    def test_scan_meta_persists_code_scan_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.PENDING,
                progress=0.0,
                total_candidates=0,
                processed_candidates=0,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=scan.created_at,
                project_path="/repo/project",
                code_scan_path="/repo/project/module",
                scan_name="project",
            )

            store.save_scan(scan, meta)

            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded[1].code_scan_path, "/repo/project/module")

    def test_scan_meta_persists_and_updates_product(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                product="LTE",
                scan_items=["npd"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.PENDING,
                progress=0.0,
                total_candidates=0,
                processed_candidates=0,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=scan.created_at,
                project_path="/repo/project",
                code_scan_path="/repo/project/module",
                scan_name="project",
                product="LTE",
            )

            store.save_scan(scan, meta)
            store.update_scan_product("scan-1", "5G")

            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            loaded_scan, loaded_meta = loaded
            self.assertEqual(loaded_scan.product, "5G")
            self.assertEqual(loaded_meta.product, "5G")

    def test_scan_persists_opencode_pool_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.AUDITING,
                progress=0.5,
                total_candidates=2,
                processed_candidates=1,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=scan.created_at,
                project_path="/repo/project",
                code_scan_path="/repo/project/module",
                scan_name="project",
            )
            store.save_scan(scan, meta)

            store.update_opencode_pool_status(
                "scan-1",
                OpenCodePoolStatus(
                    scope_id="scan-1",
                    global_running=1,
                    global_queued=2,
                    models=[
                        {
                            "id": "fast",
                            "model": "fast-model",
                            "capability": "low",
                            "weight": 3,
                            "max_concurrency": 1,
                            "queued": 2,
                            "running": 1,
                            "total": 4,
                            "success": 3,
                            "failure": 1,
                            "timeout": 0,
                            "cancelled": 0,
                            "avg_duration_seconds": 1.5,
                            "last_status": "running",
                        }
                    ],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )

            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            pool = loaded[0].opencode_pool
            self.assertIsNotNone(pool)
            self.assertEqual(pool.scope_id, "scan-1")
            self.assertEqual(pool.global_queued, 2)
            self.assertEqual(pool.models[0].id, "fast")
            self.assertEqual(pool.models[0].success, 3)

    def test_old_scan_database_migrates_product_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scans.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                """\
                CREATE TABLE scans (
                    scan_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_items TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    progress REAL DEFAULT 0.0,
                    total_candidates INTEGER DEFAULT 0,
                    processed_candidates INTEGER DEFAULT 0,
                    current_candidate TEXT,
                    error_message TEXT,
                    feedback_ids TEXT DEFAULT '[]',
                    workspace_path TEXT,
                    static_total_files INTEGER DEFAULT 0,
                    static_scanned_files INTEGER DEFAULT 0,
                    static_analysis_done INTEGER DEFAULT 0,
                    agent_id TEXT DEFAULT '',
                    agent_name TEXT DEFAULT '',
                    project_path TEXT DEFAULT '',
                    code_scan_path TEXT DEFAULT '',
                    scan_name TEXT DEFAULT '',
                    user_id TEXT DEFAULT ''
                )
                """
            )
            conn.commit()
            conn.close()

            store = SqliteScanStore(db_path)
            cur = store._conn.execute("PRAGMA table_info(scans)")
            cols = {row[1] for row in cur.fetchall()}

        self.assertIn("product", cols)

    def test_old_scan_database_migrates_opencode_pool_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scans.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                """\
                CREATE TABLE scans (
                    scan_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_items TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    progress REAL DEFAULT 0.0,
                    total_candidates INTEGER DEFAULT 0,
                    processed_candidates INTEGER DEFAULT 0,
                    current_candidate TEXT,
                    error_message TEXT,
                    feedback_ids TEXT DEFAULT '[]',
                    workspace_path TEXT,
                    static_total_files INTEGER DEFAULT 0,
                    static_scanned_files INTEGER DEFAULT 0,
                    static_analysis_done INTEGER DEFAULT 0,
                    agent_id TEXT DEFAULT '',
                    agent_name TEXT DEFAULT '',
                    project_path TEXT DEFAULT '',
                    code_scan_path TEXT DEFAULT '',
                    scan_name TEXT DEFAULT '',
                    user_id TEXT DEFAULT '',
                    product TEXT NOT NULL DEFAULT '',
                    public_access_token TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.commit()
            conn.close()

            store = SqliteScanStore(db_path)
            cur = store._conn.execute("PRAGMA table_info(scans)")
            cols = {row[1] for row in cur.fetchall()}

        self.assertIn("opencode_pool", cols)


class StaticProgressGateTests(unittest.TestCase):
    def test_static_progress_gate_limits_large_function_scans(self) -> None:
        now = [0.0]
        gate = _StaticProgressGate(now=lambda: now[0])
        sent: list[int] = []

        for scanned in range(1, 8754):
            if gate.should_send(scanned, 8753):
                sent.append(scanned)
            now[0] += 0.001

        self.assertLess(len(sent), 150)
        self.assertIn(1, sent)
        self.assertIn(8753, sent)

    def test_static_progress_gate_sends_after_time_interval(self) -> None:
        now = [0.0]
        gate = _StaticProgressGate(now=lambda: now[0])

        self.assertTrue(gate.should_send(1, 8753))
        self.assertFalse(gate.should_send(2, 8753))
        now[0] = STATIC_PROGRESS_MIN_INTERVAL_SECONDS + 0.01
        self.assertTrue(gate.should_send(3, 8753))

    def test_static_progress_gate_force_sends_latest_value(self) -> None:
        gate = _StaticProgressGate(now=lambda: 0.0)

        self.assertTrue(gate.should_send(1, 8753))
        self.assertFalse(gate.should_send(2, 8753))
        self.assertTrue(gate.should_send(2, 8753, force=True))


if __name__ == "__main__":
    unittest.main()
