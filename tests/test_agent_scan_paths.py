import tempfile
import unittest
from pathlib import Path

from agent.scanner import (
    _candidate_in_scan_scope,
    _normalize_candidate_for_project,
    _resolve_scan_paths,
)
from backend.models import Candidate, ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore


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


if __name__ == "__main__":
    unittest.main()
