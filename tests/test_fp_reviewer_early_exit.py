import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client import fp_reviewer
from deephole_client.fp_reviewer import _FpStageResult
from task_agent.model_pool import NoAvailableModelError


def _make_reporter() -> SimpleNamespace:
    return SimpleNamespace(
        send_event=AsyncMock(),
        push_fp_progress=AsyncMock(),
        push_fp_stage_output=AsyncMock(),
        push_fp_result=AsyncMock(),
        finish_fp_review=AsyncMock(),
        publish_opencode_pool_until=AsyncMock(),
    )


def _stage_result(confirmed: bool) -> _FpStageResult:
    return _FpStageResult(
        session_id="sid",
        result=SimpleNamespace(
            confirmed=confirmed,
            severity="low",
            description="未发现真实问题",
            ai_analysis="正方论证未能证明该候选是真实问题",
        ),
        payload={},
        markdown="# Prove Bug\n\n论证内容",
    )


class FpReviewerEarlyExitTests(unittest.TestCase):
    def test_no_model_marks_fp_review_job_error_without_stage_retry(self) -> None:
        reporter = _make_reporter()
        config = SimpleNamespace(opencode_concurrency=1)
        cli_config = SimpleNamespace(
            tool="opencode", executable="", model="", timeout=60, max_retries=3
        )
        stage_mock = AsyncMock(side_effect=NoAvailableModelError())
        vulnerabilities = [{
            "index": 0,
            "file": "a.c",
            "line": 10,
            "function": "f",
            "vuln_type": "npd",
            "description": "desc",
            "ai_analysis": "analysis",
        }]

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("deephole_client.fp_reviewer.Path.home", return_value=Path(tmp)),
                patch("deephole_client.mcp_registry.lookup", return_value=(12345, "active-scan")),
                patch.object(fp_reviewer, "_create_fp_workspace", return_value=Path(tmp) / "workspace"),
                patch.object(fp_reviewer, "_run_fp_review_stage", stage_mock),
                patch.object(fp_reviewer, "effective_fp_review_cli_config", return_value=cli_config),
                patch("task_agent.model_pool.total_model_capacity", return_value=1),
            ):
                asyncio.run(fp_reviewer.run_fp_review(
                    config=config,
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-no-model",
                    project_path="/tmp/does-not-matter",
                    vulnerabilities=vulnerabilities,
                ))

        stage_mock.assert_awaited_once()
        reporter.finish_fp_review.assert_awaited_once_with(
            "scan-1",
            "review-no-model",
            "error",
            str(NoAvailableModelError()),
        )

    def test_prove_bug_not_confirmed_skips_later_stages_and_pushes_fp_result(self) -> None:
        reporter = _make_reporter()
        config = SimpleNamespace(opencode_concurrency=1)
        cli_config = SimpleNamespace(
            tool="opencode", executable="", model="", timeout=60, max_retries=0
        )
        stage_mock = AsyncMock(return_value=_stage_result(confirmed=False))
        vulnerabilities = [{
            "index": 0,
            "file": "a.c",
            "line": 10,
            "function": "f",
            "vuln_type": "npd",
            "description": "desc",
            "ai_analysis": "analysis",
        }]

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("deephole_client.fp_reviewer.Path.home", return_value=Path(tmp)),
                patch("deephole_client.mcp_registry.lookup", return_value=(12345, "active-scan")),
                patch.object(fp_reviewer, "_create_fp_workspace", return_value=Path(tmp) / "workspace"),
                patch.object(fp_reviewer, "_run_fp_review_stage", stage_mock),
                patch.object(fp_reviewer, "effective_fp_review_cli_config", return_value=cli_config),
                patch("task_agent.model_pool.total_model_capacity", return_value=1),
            ):
                asyncio.run(fp_reviewer.run_fp_review(
                    config=config,
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-early-exit-test",
                    project_path="/tmp/does-not-matter",
                    vulnerabilities=vulnerabilities,
                ))

        # Only the prove_bug stage ran — prove_fp and final_judge were skipped.
        self.assertEqual(stage_mock.await_count, 1)
        self.assertEqual(stage_mock.await_args.kwargs["stage"], "prove_bug")

        reporter.push_fp_result.assert_awaited_once()
        args = reporter.push_fp_result.await_args.args
        self.assertEqual(args[2], 0)      # vuln_index
        self.assertEqual(args[3], "fp")   # verdict
        self.assertEqual(args[4], "low")  # severity
        self.assertTrue(args[5])          # reason is non-empty

        reporter.finish_fp_review.assert_awaited_once()
        self.assertEqual(reporter.finish_fp_review.await_args.args[2], "complete")

    def test_prove_bug_confirmed_continues_to_later_stages(self) -> None:
        reporter = _make_reporter()
        config = SimpleNamespace(opencode_concurrency=1)
        cli_config = SimpleNamespace(
            tool="opencode", executable="", model="", timeout=60, max_retries=0
        )
        stage_mock = AsyncMock(return_value=_stage_result(confirmed=True))
        vulnerabilities = [{
            "index": 0,
            "file": "a.c",
            "line": 10,
            "function": "f",
            "vuln_type": "npd",
            "description": "desc",
            "ai_analysis": "analysis",
        }]

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("deephole_client.fp_reviewer.Path.home", return_value=Path(tmp)),
                patch("deephole_client.mcp_registry.lookup", return_value=(12345, "active-scan")),
                patch.object(fp_reviewer, "_create_fp_workspace", return_value=Path(tmp) / "workspace"),
                patch.object(fp_reviewer, "_run_fp_review_stage", stage_mock),
                patch.object(fp_reviewer, "effective_fp_review_cli_config", return_value=cli_config),
                patch("task_agent.model_pool.total_model_capacity", return_value=1),
            ):
                asyncio.run(fp_reviewer.run_fp_review(
                    config=config,
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-full-stages-test",
                    project_path="/tmp/does-not-matter",
                    vulnerabilities=vulnerabilities,
                ))

        self.assertEqual(stage_mock.await_count, 3)
        stages = [call.kwargs["stage"] for call in stage_mock.await_args_list]
        self.assertEqual(stages, ["prove_bug", "prove_fp", "final_judge"])
        reporter.push_fp_result.assert_awaited_once()
        self.assertEqual(reporter.push_fp_result.await_args.args[3], "tp")


if __name__ == "__main__":
    unittest.main()
