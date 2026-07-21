import json
import tempfile
import unittest
import re
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent import fp_reviewer
from agent.config import AgentConfig, OpenCodeConfig
from agent.scanner import _build_function_source_cache, _attach_function_source
from backend.models import Candidate, Vulnerability
from agent.task_agent import OpenCodeResult


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


def _write_stage_artifact_from_prompt(prompt: str, content: str = "# Stage\n\nanalysis") -> None:
    matches = re.findall(r"`([^`]+\.md)`", prompt)
    if matches:
        Path(matches[-1]).write_text(content, encoding="utf-8")


def _opencode_result(structured=None) -> OpenCodeResult:
    return OpenCodeResult(
        session_id="ses-test",
        status="success",
        text="",
        structured=structured,
        model="provider/model",
    )


def _stage_json_result(
    *,
    confirmed: bool,
    severity: str,
    description: str,
    ai_analysis: str,
    report: str = "",
) -> str:
    return json.dumps({
        "confirmed": confirmed,
        "severity": severity,
        "description": description,
        "ai_analysis": ai_analysis,
        "vulnerability_report": report,
        "file": "a.c",
        "line": 10,
        "function": "parse",
        "stage_markdown": report or f"# Stage\n\n{ai_analysis}",
        "match_type": "",
        "match_reference": "",
    })


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
        # 二元定级：外部可触发(high) → high，其余一律 low。
        self.assertEqual(fp_reviewer._normalize_fp_severity("high", "tp"), "high")
        self.assertEqual(fp_reviewer._normalize_fp_severity("medium", "tp"), "low")
        self.assertEqual(fp_reviewer._normalize_fp_severity("low", "tp"), "low")
        self.assertEqual(fp_reviewer._normalize_fp_severity("high", "fp"), "low")
        self.assertEqual(fp_reviewer._normalize_fp_severity("critical", "tp"), "low")

    def test_fp_review_final_judge_false_as_fp(self) -> None:
        final_judge = fp_reviewer._FpStageResult(
            session_id="final",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="final fp",
                ai_analysis="最终裁决：caller checks null",
                confirmed=False,
            ),
            payload={},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(final_judge)

        self.assertEqual((verdict, severity, report), ("fp", "low", ""))
        self.assertIn("caller checks null", reason)

    def test_fp_review_final_judge_non_high_normalized_to_low(self) -> None:
        # 二元定级：confirmed 但非外部可触发（severity!=high）一律归一为 low，
        # 报告仍需保留（confirmed=true）。
        final_judge = fp_reviewer._FpStageResult(
            session_id="final",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="medium",
                description="final tp",
                ai_analysis="final code chain",
                confirmed=True,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(final_judge)

        self.assertEqual((verdict, severity), ("tp", "low"))
        self.assertIn("final code chain", reason)
        self.assertIn("## Full Call Stack", report)

    def test_fp_review_final_judge_high_preserved(self) -> None:
        final_judge = fp_reviewer._FpStageResult(
            session_id="final",
            result=Vulnerability(
                file="a.c",
                line=10,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="final tp",
                ai_analysis="final code chain",
                confirmed=True,
            ),
            payload={"vulnerability_report": _valid_issue_report()},
        )

        verdict, severity, reason, report = fp_reviewer._finalize_fp_review_result(final_judge)

        self.assertEqual((verdict, severity), ("tp", "high"))
        self.assertIn("## Full Call Stack", report)

    def test_fp_review_does_not_save_result_when_cli_returns_none(self) -> None:
        class FakeReporter:
            def __init__(self) -> None:
                self.results: list[tuple] = []
                self.progress: list[tuple[int, int | None]] = []
                self.stage_outputs: list[tuple[str, str]] = []
                self.finished: tuple[str, str | None] | None = None

            async def publish_opencode_pool_until(self, scan_id, stop_event, **kwargs) -> None:
                return None

            async def send_event(self, scan_id, event) -> None:
                return None

            async def push_fp_progress(self, scan_id, review_id, vuln_index, processed=None, active_indices=None) -> None:
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
	                stage_outputs=None,
                    **kwargs,
	            ) -> None:
	                self.results.append((vuln_index, verdict, reason))

            async def push_fp_stage_output(self, scan_id, review_id, vuln_index, stage, markdown, **kwargs) -> None:
                self.stage_outputs.append((stage, markdown))

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> FakeReporter:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            invoke = AsyncMock()

            async def invoke_side_effect(**kwargs):
                prompt = kwargs["prompt"]
                _write_stage_artifact_from_prompt(prompt)
                return _opencode_result()

            invoke.side_effect = invoke_side_effect
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("agent.fp_reviewer.run_opencode_task", new=invoke),
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
        self.assertEqual(len(reporter.stage_outputs), 1)
        self.assertEqual(reporter.stage_outputs[0][0], "prove_bug")
        self.assertIn("Schema-valid FP stage result could not be converted", reporter.stage_outputs[0][1])
        self.assertEqual(reporter.progress, [(3, 0), (3, 1)])
        self.assertEqual(reporter.finished, ("complete", None))

    def test_fp_review_does_not_save_result_when_final_judge_returns_none(self) -> None:
        class FakeReporter:
            def __init__(self) -> None:
                self.results: list[tuple] = []
                self.progress: list[tuple[int, int | None]] = []
                self.finished: tuple[str, str | None] | None = None

            async def publish_opencode_pool_until(self, scan_id, stop_event, **kwargs) -> None:
                return None

            async def send_event(self, scan_id, event) -> None:
                return None

            async def push_fp_progress(self, scan_id, review_id, vuln_index, processed=None, active_indices=None) -> None:
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
	                stage_outputs=None,
                    **kwargs,
	            ) -> None:
	                self.results.append((vuln_index, verdict, severity, reason, vulnerability_report))

            async def push_fp_stage_output(self, scan_id, review_id, vuln_index, stage, markdown, **kwargs) -> None:
                return None

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> tuple[FakeReporter, AsyncMock]:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            invoke = AsyncMock()
            outputs = [
                _stage_json_result(
                    confirmed=True,
                    severity="high",
                    description="prove-bug tp",
                    ai_analysis="prove-bug exploit chain",
                ),
                _stage_json_result(
                    confirmed=True,
                    severity="low",
                    description="prove-fp did not disprove",
                    ai_analysis="prove-fp kept issue",
                ),
                "{}",
            ]

            async def invoke_side_effect(**kwargs):
                prompt = kwargs["prompt"]
                _write_stage_artifact_from_prompt(prompt)
                return _opencode_result(json.loads(outputs.pop(0)))

            invoke.side_effect = invoke_side_effect
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("agent.fp_reviewer.run_opencode_task", new=invoke),
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
        self.assertEqual(invoke.await_count, 3)
        self.assertEqual(reporter.results, [])
        self.assertEqual(reporter.progress, [(3, 0), (3, 1)])
        self.assertEqual(reporter.finished, ("complete", None))

    def test_fp_review_early_exits_when_prove_bug_reports_fp(self) -> None:
        class FakeReporter:
            def __init__(self) -> None:
                self.results: list[tuple] = []
                self.progress: list[tuple[int, int | None]] = []
                self.finished: tuple[str, str | None] | None = None

            async def publish_opencode_pool_until(self, scan_id, stop_event, **kwargs) -> None:
                return None

            async def send_event(self, scan_id, event) -> None:
                return None

            async def push_fp_progress(self, scan_id, review_id, vuln_index, processed=None, active_indices=None) -> None:
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
	                stage_outputs=None,
                    **kwargs,
	            ) -> None:
	                self.results.append((vuln_index, verdict, severity, reason, vulnerability_report))

            async def push_fp_stage_output(self, scan_id, review_id, vuln_index, stage, markdown, **kwargs) -> None:
                return None

            async def finish_fp_review(self, scan_id, review_id, status, error_message=None) -> None:
                self.finished = (status, error_message)

        async def _run() -> tuple[FakeReporter, AsyncMock]:
            reporter = FakeReporter()
            config = AgentConfig(opencode=OpenCodeConfig(timeout=1, max_retries=0))
            invoke = AsyncMock()

            async def invoke_side_effect(**kwargs):
                prompt = kwargs["prompt"]
                _write_stage_artifact_from_prompt(prompt)
                return _opencode_result(json.loads(_stage_json_result(
                    confirmed=False,
                    severity="low",
                    description="prove-bug fp",
                    ai_analysis="NOT_PROVEN",
                )))

            invoke.side_effect = invoke_side_effect
            with tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "workspace"
                with (
                    patch("agent.fp_reviewer.Path.home", return_value=Path(tmp)),
                    patch("agent.mcp_registry.lookup", return_value=(7000, "scan-1")),
                    patch.object(fp_reviewer, "_create_fp_workspace", return_value=workspace),
                    patch("backend.config.get_config", return_value=SimpleNamespace()),
                    patch("agent.fp_reviewer.run_opencode_task", new=invoke),
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
        # 正方论证 confirmed=false 时正式早退：只跑 prove_bug 一个阶段，
        # 直接以正方理由记录误报结果。
        self.assertEqual(invoke.await_count, 1)
        self.assertEqual(reporter.results[0][0:3], (3, "fp", "low"))
        self.assertEqual(reporter.results[0][4], "")
        self.assertIn("NOT_PROVEN", reporter.results[0][3])
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
