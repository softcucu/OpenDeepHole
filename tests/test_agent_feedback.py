import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent import fp_reviewer
from agent.config import AgentConfig, OpenCodeConfig
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

    def test_fp_review_does_not_save_result_when_cli_returns_none(self) -> None:
        class FakeReporter:
            def __init__(self) -> None:
                self.results: list[tuple] = []
                self.progress: list[tuple[int, int | None]] = []
                self.finished: tuple[str, str | None] | None = None

            async def send_event(self, scan_id, event) -> None:
                return None

            async def push_fp_progress(self, scan_id, review_id, vuln_index, processed=None) -> None:
                self.progress.append((vuln_index, processed))

            async def push_fp_result(
                self,
                scan_id,
                review_id,
                vuln_index,
                verdict,
                severity,
                reason,
                vulnerability_report="",
            ) -> None:
                self.results.append((vuln_index, verdict, reason))

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> FakeReporter:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch.object(fp_reviewer, "_cleanup_fp_workspace"),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("backend.opencode.runner._invoke_opencode", new=AsyncMock()),
                    patch("backend.opencode.runner._read_result", return_value=None),
                ):
                    await fp_reviewer.run_fp_review(
                        config=config,
                        reporter=reporter,
                        scan_id="scan-1",
                        review_id="review-1",
                        project_path=str(Path(tmp)),
                        vulnerabilities=[
                            {
                                "index": 3,
                                "file": "a.c",
                                "line": 10,
                                "function": "parse",
                                "vuln_type": "npd",
                                "description": "desc",
                                "ai_analysis": "analysis",
                            }
                        ],
                    )
            return reporter

        import asyncio

        reporter = asyncio.run(_run())
        self.assertEqual(reporter.results, [])
        self.assertEqual(reporter.progress, [(3, 0), (3, 1)])
        self.assertEqual(reporter.finished, ("complete", None))

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
