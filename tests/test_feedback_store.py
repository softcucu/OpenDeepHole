import tempfile
import unittest
from pathlib import Path

from backend.models import FeedbackEntry, ScanItemStatus, ScanMeta, ScanStatus, Vulnerability
from backend.store.sqlite import SqliteScanStore


def make_feedback(
    entry_id: str,
    verdict: str,
    reason: str,
    *,
    ticket_submitted: bool = False,
    ticket_id: str = "",
) -> FeedbackEntry:
    return FeedbackEntry(
        id=entry_id,
        project_id="project-1",
        vuln_type="npd",
        verdict=verdict,
        file="src/a.c",
        line=42,
        function="parse",
        description="possible null dereference",
        reason=reason,
        ticket_submitted=ticket_submitted,
        ticket_id=ticket_id,
        function_source="void parse(void) {\n}",
        function_start_line=40,
        source_scan_id="scan-1",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


class FeedbackStoreTests(unittest.TestCase):
    def test_upsert_feedback_for_report_updates_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")

            first = store.upsert_feedback_for_report(
                make_feedback("first", "false_positive", "old reason")
            )
            second = make_feedback("second", "confirmed", "new reason")
            second.ticket_submitted = True
            second.ticket_id = "BUG-123"
            second.updated_at = "2026-01-02T00:00:00+00:00"
            updated = store.upsert_feedback_for_report(second)

            self.assertEqual(first.id, "first")
            self.assertEqual(updated.id, "first")
            self.assertEqual(updated.verdict, "confirmed")
            self.assertEqual(updated.reason, "new reason")
            self.assertTrue(updated.ticket_submitted)
            self.assertEqual(updated.ticket_id, "BUG-123")
            self.assertEqual(updated.function_source, "void parse(void) {\n}")
            self.assertEqual(updated.function_start_line, 40)
            self.assertEqual(updated.updated_at, "2026-01-02T00:00:00+00:00")

            entries = store.list_feedback_by_scan("scan-1")
            self.assertEqual([entry.id for entry in entries], ["first"])

    def test_upsert_feedback_for_report_removes_old_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            first = make_feedback("first", "false_positive", "old reason")
            duplicate = make_feedback("duplicate", "false_positive", "duplicate reason")
            duplicate.created_at = "2026-01-02T00:00:00+00:00"
            duplicate.updated_at = "2026-01-02T00:00:00+00:00"
            store.add_feedback(first)
            store.add_feedback(duplicate)

            updated = store.upsert_feedback_for_report(
                make_feedback("new", "false_positive", "replacement reason")
            )

            self.assertEqual(updated.id, "first")
            self.assertEqual(updated.reason, "replacement reason")
            entries = store.list_feedback_by_scan("scan-1")
            self.assertEqual([entry.id for entry in entries], ["first"])

    def test_update_feedback_updates_ticket_fields_and_clears_ticket_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.add_feedback(make_feedback("first", "confirmed", "reason"))

            ok = store.update_feedback("first", None, None, True, "BUG-456")
            self.assertTrue(ok)
            entry = store.get_feedback_by_ids(["first"])[0]
            self.assertTrue(entry.ticket_submitted)
            self.assertEqual(entry.ticket_id, "BUG-456")

            ok = store.update_feedback("first", None, None, False, None)
            self.assertTrue(ok)
            entry = store.get_feedback_by_ids(["first"])[0]
            self.assertFalse(entry.ticket_submitted)
            self.assertEqual(entry.ticket_id, "")

    def test_clear_vulnerability_user_verdict_deletes_same_source_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project-1",
                scan_items=["npd"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=scan.created_at,
                feedback_ids=["first"],
            )
            store.save_scan(scan, meta)
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="src/a.c",
                    line=42,
                    function="parse",
                    vuln_type="npd",
                    severity="high",
                    description="possible null dereference",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                    user_verdict_reason="verified",
                    ticket_submitted=True,
                    ticket_id="BUG-1",
                ),
            )
            store.add_feedback(make_feedback("first", "confirmed", "verified"))

            removed = store.clear_vulnerability_user_verdict("scan-1", 0)

            self.assertEqual(removed, ["first"])
            self.assertEqual(store.list_feedback_by_scan("scan-1"), [])
            vuln = store.get_vulnerabilities("scan-1")[0]
            self.assertIsNone(vuln.user_verdict)
            self.assertIsNone(vuln.user_verdict_reason)
            self.assertFalse(vuln.ticket_submitted)
            self.assertEqual(vuln.ticket_id, "")


if __name__ == "__main__":
    unittest.main()
