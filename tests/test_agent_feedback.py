import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import fp_reviewer
from agent.scanner import _build_function_source_cache, _attach_function_source
from backend.models import Candidate, Vulnerability


class AgentFeedbackTests(unittest.TestCase):
    def test_update_local_feedback_replaces_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feedback_file = Path(tmp) / "fp_feedback.json"
            with patch.object(fp_reviewer, "_FP_FEEDBACK_FILE", feedback_file):
                fp_reviewer.update_local_feedback(
                    {"id": "fb-1", "vuln_type": "npd", "reason": "old"}
                )
                fp_reviewer.update_local_feedback(
                    {"id": "fb-1", "vuln_type": "npd", "reason": "new"}
                )

                feedback = fp_reviewer.load_local_feedback()
                self.assertEqual(feedback["npd"], [
                    {"id": "fb-1", "vuln_type": "npd", "reason": "new"}
                ])

    def test_fp_review_severity_normalization(self) -> None:
        self.assertEqual(fp_reviewer._normalize_fp_severity("high", "tp"), "high")
        self.assertEqual(fp_reviewer._normalize_fp_severity("medium", "tp"), "medium")
        self.assertEqual(fp_reviewer._normalize_fp_severity("high", "fp"), "low")
        self.assertEqual(fp_reviewer._normalize_fp_severity("critical", "tp"), "low")

    def test_scanner_snapshots_function_source_for_vulnerability(self) -> None:
        class FakeDb:
            def get_functions_by_name(self, name: str):
                return [
                    {
                        "file_path": "src/a.c",
                        "start_line": 10,
                        "end_line": 20,
                        "body": "void parse(void) {\n}",
                    }
                ]

        candidate = Candidate(
            file="src/a.c",
            line=12,
            function="parse",
            description="possible null dereference",
            vuln_type="npd",
        )
        cache = _build_function_source_cache(Path("."), [candidate], FakeDb())
        vuln = Vulnerability(
            file=candidate.file,
            line=candidate.line,
            function=candidate.function,
            vuln_type=candidate.vuln_type,
            severity="medium",
            description=candidate.description,
            ai_analysis="analysis",
            confirmed=True,
        )

        _attach_function_source(vuln, candidate, cache)

        self.assertEqual(vuln.function_source, "void parse(void) {\n}")
        self.assertEqual(vuln.function_start_line, 10)


if __name__ == "__main__":
    unittest.main()
