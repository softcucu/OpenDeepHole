import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent import fp_reviewer
from agent.config import AgentConfig, OpenCodeConfig
from agent.scanner import _build_function_source_cache, _attach_function_source
from backend.models import Candidate, Vulnerability


def _valid_issue_report() -> str:
    return """# Vulnerability Report: NPD parse

## Summary
External input reaches a null dereference.

## Vulnerable Code
`a.c:10 parse` dereferences `ptr`.

## Full Call Stack
1. `entry` - external input enters
2. `parse` - value is propagated

## Root Cause
Missing null check.

## Why It is Reachable
No validation blocks the path.

## Impact
Crash.

## Evidence
Checked `entry` and `parse`.
"""


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
        self.assertEqual(fp_reviewer._normalize_fp_severity("low", "tp"), "medium")
        self.assertEqual(fp_reviewer._normalize_fp_severity("high", "fp"), "low")
        self.assertEqual(fp_reviewer._normalize_fp_severity("critical", "tp"), "medium")

    def test_fp_review_finalizes_prove_fp_false_as_fp(self) -> None:
        prove_bug = fp_reviewer._FpStageResult(
            result_id="bug",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="prove-bug tp",
                ai_analysis="prove-bug exploit chain",
                confirmed=True,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )
        prove_fp = fp_reviewer._FpStageResult(
            result_id="fp",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="prove-fp fp",
                ai_analysis="最强不可利用理由：caller checks null",
                confirmed=False,
            ),
            payload={},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(prove_bug, prove_fp)

        self.assertEqual((verdict, severity, report), ("fp", "low", ""))
        self.assertIn("[prove-bug]", reason)
        self.assertIn("[prove-fp]", reason)

    def test_fp_review_preserves_medium_issue_report(self) -> None:
        prove_bug = fp_reviewer._FpStageResult(
            result_id="bug",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="medium",
                description="prove-bug tp",
                ai_analysis="prove-bug code issue",
                confirmed=True,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )
        prove_fp = fp_reviewer._FpStageResult(
            result_id="fp",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="prove-fp tp",
                ai_analysis="未能证明误报",
                confirmed=True,
            ),
            payload={},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(prove_bug, prove_fp)

        self.assertEqual((verdict, severity), ("tp", "medium"))
        self.assertIn("## Full Call Stack", report)
        self.assertIn("Prove-fp 未能证明非问题", reason)

    def test_fp_review_preserves_high_issue_report_after_prove_fp(self) -> None:
        prove_bug = fp_reviewer._FpStageResult(
            result_id="bug",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="prove-bug tp",
                ai_analysis="prove-bug exploit chain",
                confirmed=True,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )
        prove_fp = fp_reviewer._FpStageResult(
            result_id="fp",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="prove-fp tp",
                ai_analysis="仍然成立的证据：external chain remains",
                confirmed=True,
            ),
            payload={},
        )

        verdict, severity, _, report = fp_reviewer._finalize_fp_review_result(prove_bug, prove_fp)

        self.assertEqual((verdict, severity), ("tp", "high"))
        self.assertIn("## Full Call Stack", report)

    def test_fp_review_short_circuits_when_prove_bug_reports_fp(self) -> None:
        prove_bug = fp_reviewer._FpStageResult(
            result_id="bug",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="prove-bug fp",
                ai_analysis="NOT_PROVEN",
                confirmed=False,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(prove_bug, None)

        self.assertEqual((verdict, severity, report), ("fp", "low", ""))
        self.assertIn("未进入反方论证", reason)

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

    def test_fp_review_does_not_save_result_when_prove_fp_returns_none(self) -> None:
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
                self.results.append((vuln_index, verdict, severity, reason, vulnerability_report))

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> tuple[FakeReporter, AsyncMock]:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            prove_bug_result = Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="prove-bug tp",
                ai_analysis="prove-bug exploit chain",
                confirmed=True,
            )
            invoke = AsyncMock()
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch.object(fp_reviewer, "_cleanup_fp_workspace"),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("backend.opencode.runner._invoke_opencode", new=invoke),
                    patch("backend.opencode.runner._read_result", side_effect=[prove_bug_result, None]),
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
            return reporter, invoke

        import asyncio

        reporter, invoke = asyncio.run(_run())
        self.assertEqual(invoke.await_count, 2)
        self.assertEqual(reporter.results, [])
        self.assertEqual(reporter.progress, [(3, 0), (3, 1)])
        self.assertEqual(reporter.finished, ("complete", None))

    def test_fp_review_short_circuits_runtime_when_prove_bug_reports_fp(self) -> None:
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
                self.results.append((vuln_index, verdict, severity, reason, vulnerability_report))

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> tuple[FakeReporter, AsyncMock]:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            prove_bug_result = Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="prove-bug fp",
                ai_analysis="NOT_PROVEN",
                confirmed=False,
            )
            invoke = AsyncMock()
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch.object(fp_reviewer, "_cleanup_fp_workspace"),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("backend.opencode.runner._invoke_opencode", new=invoke),
                    patch("backend.opencode.runner._read_result", return_value=prove_bug_result),
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
            return reporter, invoke

        import asyncio

        reporter, invoke = asyncio.run(_run())
        self.assertEqual(invoke.await_count, 1)
        self.assertEqual(reporter.results[0][0:3], (3, "fp", "low"))
        self.assertEqual(reporter.results[0][4], "")
        self.assertIn("[prove-bug]", reporter.results[0][3])
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
