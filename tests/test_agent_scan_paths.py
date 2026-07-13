import asyncio
import tempfile
import threading
import unittest
import sqlite3
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent.scanner import (
    GIT_HISTORY_PIPELINE_ENABLED,
    MEMORY_API_DISCOVERY_PIPELINE_ENABLED,
    STATIC_PROGRESS_MIN_INTERVAL_SECONDS,
    _StaticProgressGate,
    _audit_order_summary,
    _candidate_in_scan_scope,
    _candidate_key,
    _candidate_pattern_key,
    _dedup_candidates,
    _load_existing_threat_analysis_for_scope,
    _normalize_candidate_for_project,
    _order_candidates_for_audit,
    _prepare_audit_queue,
    _round_robin_by_pattern,
    _run_threat_analysis_phase,
    _resolve_scan_paths,
    _should_run_memory_api_phase,
    _should_run_git_history_phase,
    _wait_for_threat_analysis_task,
    _configure_backend,
    build_project_level_candidate,
    is_project_level_candidate,
    refresh_backend_runtime_config,
)
from agent.config import AgentConfig
from backend.api import agent as agent_api
from backend.models import (
    AgentInfo,
    Candidate,
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAnalysis,
    ThreatAuditTask,
    User,
)
from backend.opencode.model_pool import NoAvailableModelError
from backend.store.sqlite import SqliteScanStore
from backend.threat_analysis import apply_threat_analysis_scan_scope


def _candidate(vuln_type: str, line: int) -> Candidate:
    return Candidate(
        file=f"{vuln_type}.c",
        line=line,
        function=f"{vuln_type}_fn_{line}",
        description=f"{vuln_type} candidate {line}",
        vuln_type=vuln_type,
    )


def _subject_candidate(vuln_type: str, line: int, subject: str, *, function: str = "target") -> Candidate:
    return Candidate(
        file="src/demo.c",
        line=line,
        function=function,
        description=f"{vuln_type} {subject}",
        vuln_type=vuln_type,
        metadata={"subject": subject, "problem": "空指针解引用"},
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

    def test_candidate_scope_filter_excludes_project_opendeephole_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            internal_source = project / ".opendeephole" / "opencode" / "generated.c"
            internal_source.parent.mkdir(parents=True)
            internal_source.write_text("int generated(void) { return 1; }\n", encoding="utf-8")
            candidate = Candidate(
                file=".opendeephole/opencode/generated.c",
                line=1,
                function="generated",
                description="candidate",
                vuln_type="npd",
            )

            self.assertFalse(
                _candidate_in_scan_scope(
                    candidate,
                    project.resolve(),
                    project.resolve(),
                )
            )

    def test_candidate_scope_filter_excludes_when_scan_root_is_opendeephole(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / ".opendeephole"
            source = scan_dir / "generated.c"
            source.parent.mkdir(parents=True)
            source.write_text("int generated(void) { return 1; }\n", encoding="utf-8")
            candidate = Candidate(
                file="generated.c",
                line=1,
                function="generated",
                description="candidate",
                vuln_type="npd",
            )

            self.assertFalse(
                _candidate_in_scan_scope(
                    candidate,
                    project.resolve(),
                    scan_dir.resolve(),
                )
            )

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

    def test_reuse_existing_threat_analysis_for_matching_scan_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "module"
            scan_dir.mkdir(parents=True)
            (project / "res.json").write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "analysis_id": "ATA-MODULE",
                    "scan_scope": {
                        "project_path": project.resolve().as_posix(),
                        "code_scan_path": scan_dir.resolve().as_posix(),
                        "code_scan_relative_path": "module",
                    },
                    "assets": [],
                }),
                encoding="utf-8",
            )

            analysis, message = _load_existing_threat_analysis_for_scope(
                project.resolve(), scan_dir.resolve(),
            )

            self.assertIsNotNone(analysis)
            self.assertEqual(analysis.analysis_id, "ATA-MODULE")
            self.assertIn("复用已有威胁分析产物", message)

    def test_reject_existing_threat_analysis_for_different_scan_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            old_dir = project / "old"
            new_dir = project / "new"
            old_dir.mkdir(parents=True)
            new_dir.mkdir()
            (project / "res.json").write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "analysis_id": "ATA-OLD",
                    "scan_scope": {
                        "project_path": project.resolve().as_posix(),
                        "code_scan_path": old_dir.resolve().as_posix(),
                        "code_scan_relative_path": "old",
                    },
                    "assets": [],
                }),
                encoding="utf-8",
            )

            analysis, message = _load_existing_threat_analysis_for_scope(
                project.resolve(), new_dir.resolve(),
            )

            self.assertIsNone(analysis)
            self.assertIn("当前扫描范围为 new", message)

    def test_reject_existing_threat_analysis_without_scan_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_dir = project / "module"
            scan_dir.mkdir(parents=True)
            (project / "res.json").write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "analysis_id": "ATA-LEGACY",
                    "assets": [],
                }),
                encoding="utf-8",
            )

            analysis, message = _load_existing_threat_analysis_for_scope(
                project.resolve(), scan_dir.resolve(),
            )

            self.assertIsNone(analysis)
            self.assertIn("未标记", message)

    def test_threat_analysis_phase_pushes_result_without_terminal_scan_state(self) -> None:
        class FakeReporter:
            def __init__(self) -> None:
                self.pushed: list[tuple[str, dict]] = []

            async def push_threat_analysis(self, scan_id: str, analysis: dict) -> None:
                self.pushed.append((scan_id, analysis))

        async def run() -> tuple[list[tuple[str, str]], FakeReporter, AsyncMock]:
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                workspace = Path(tmp) / "workspace"
                project.mkdir()
                workspace.mkdir()
                reporter = FakeReporter()
                events: list[tuple[str, str]] = []

                async def emit(phase: str, message: str) -> None:
                    events.append((phase, message))

                runner = AsyncMock(return_value=ThreatAnalysis(
                    schema_version="1.0",
                    analysis_id="threat-1",
                ))
                with patch("backend.opencode.runner.run_threat_analysis_audit", runner):
                    await _run_threat_analysis_phase(
                        config=AgentConfig(),
                        project_path=project.resolve(),
                        code_scan_path=project.resolve(),
                        reporter=reporter,  # type: ignore[arg-type]
                        scan_id="scan-1",
                        product="demo",
                        workspace=workspace,
                        cancel_event=threading.Event(),
                        emit=emit,
                    )
                return events, reporter, runner

        events, reporter, runner = asyncio.run(run())

        runner.assert_awaited_once()
        self.assertEqual(reporter.pushed[0][0], "scan-1")
        self.assertEqual(reporter.pushed[0][1]["analysis_id"], "threat-1")
        self.assertTrue(any("开始基于攻击树的威胁分析" in message for _phase, message in events))
        self.assertTrue(any("威胁分析完成" in message for _phase, message in events))

    def test_threat_analysis_phase_propagates_no_model_error(self) -> None:
        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                workspace = Path(tmp) / "workspace"
                project.mkdir()
                workspace.mkdir()

                async def emit(_phase: str, _message: str) -> None:
                    return None

                with patch(
                    "backend.opencode.runner.run_threat_analysis_audit",
                    new=AsyncMock(side_effect=NoAvailableModelError()),
                ):
                    await _run_threat_analysis_phase(
                        config=AgentConfig(),
                        project_path=project.resolve(),
                        code_scan_path=project.resolve(),
                        reporter=AsyncMock(),
                        scan_id="scan-no-model",
                        product="demo",
                        workspace=workspace,
                        cancel_event=threading.Event(),
                        emit=emit,
                    )

        with self.assertRaises(NoAvailableModelError):
            asyncio.run(run())

    def test_threat_auditor_persists_failure_then_propagates_no_model_error(self) -> None:
        from agent.threat_auditor import run_threat_audit_tasks

        task = ThreatAuditTask(
            task_id="threat-audit-no-model",
            surface_node_id="surface-1",
            surface_name="管理接口",
            method_node_id="method-1",
            method_name="认证绕过",
            code_path="src/api",
        )
        reporter = AsyncMock()
        reporter.get_threat_audit_tasks.return_value = []
        cancel_event = threading.Event()

        async def run() -> None:
            with (
                patch("agent.threat_auditor.build_threat_audit_tasks", return_value=[task]),
                patch(
                    "backend.opencode.model_pool.register_planned_task",
                    new=AsyncMock(return_value="planned-1"),
                ),
                patch("backend.opencode.model_pool.total_model_capacity", return_value=1),
                patch("backend.opencode.model_pool.clear_planned_task", new=AsyncMock()),
                patch(
                    "backend.opencode.runner.run_threat_audit",
                    new=AsyncMock(side_effect=NoAvailableModelError()),
                ) as runner,
            ):
                with self.assertRaises(NoAvailableModelError):
                    await run_threat_audit_tasks(
                        config=AgentConfig(),
                        analysis=ThreatAnalysis(schema_version="1.0", analysis_id="analysis-1"),
                        reporter=reporter,
                        scan_id="scan-no-model",
                        project_path=Path("/tmp/project"),
                        workspace=Path("/tmp/workspace"),
                        cancel_event=cancel_event,
                        emit=AsyncMock(),
                    )
                runner.assert_awaited_once()

        asyncio.run(run())

        pushed_tasks = [call.args[1] for call in reporter.push_threat_audit_task.await_args_list]
        self.assertEqual(pushed_tasks[-1].status, "failed")
        self.assertEqual(pushed_tasks[-1].failure_reason, str(NoAvailableModelError()))
        self.assertTrue(cancel_event.is_set())

    def test_resume_reuses_stored_threat_analysis_for_matching_scan_scope(self) -> None:
        class FakeReporter:
            def __init__(self, analysis: ThreatAnalysis) -> None:
                self.analysis = analysis
                self.pushed: list[tuple[str, dict]] = []

            async def get_threat_analysis(self, scan_id: str) -> ThreatAnalysis | None:
                return self.analysis

            async def push_threat_analysis(self, scan_id: str, analysis: dict) -> None:
                self.pushed.append((scan_id, analysis))

        async def run() -> tuple[list[tuple[str, str]], FakeReporter, AsyncMock]:
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                scan_dir = project / "module"
                workspace = Path(tmp) / "workspace"
                scan_dir.mkdir(parents=True)
                workspace.mkdir()
                analysis = apply_threat_analysis_scan_scope(
                    ThreatAnalysis(schema_version="1.0", analysis_id="stored-threat"),
                    project.resolve(),
                    scan_dir.resolve(),
                )
                reporter = FakeReporter(analysis)
                events: list[tuple[str, str]] = []

                async def emit(phase: str, message: str) -> None:
                    events.append((phase, message))

                runner = AsyncMock(return_value=ThreatAnalysis(
                    schema_version="1.0",
                    analysis_id="new-threat",
                ))
                with patch("backend.opencode.runner.run_threat_analysis_audit", runner):
                    await _run_threat_analysis_phase(
                        config=AgentConfig(),
                        project_path=project.resolve(),
                        code_scan_path=scan_dir.resolve(),
                        reporter=reporter,  # type: ignore[arg-type]
                        scan_id="scan-1",
                        product="demo",
                        workspace=workspace,
                        cancel_event=threading.Event(),
                        emit=emit,
                        is_resume=True,
                    )
                return events, reporter, runner

        events, reporter, runner = asyncio.run(run())

        runner.assert_not_awaited()
        self.assertEqual(reporter.pushed, [])
        self.assertTrue(any("复用本次任务已完成的威胁分析结果" in message for _phase, message in events))
        self.assertFalse(any("开始基于攻击树的威胁分析" in message for _phase, message in events))

    def test_resume_reuses_analysis_and_continues_selected_threat_audits(self) -> None:
        class FakeReporter:
            def __init__(self, analysis: ThreatAnalysis) -> None:
                self.analysis = analysis

            async def get_threat_analysis(self, _scan_id: str) -> ThreatAnalysis:
                return self.analysis

        async def run() -> AsyncMock:
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                workspace = Path(tmp) / "workspace"
                project.mkdir()
                workspace.mkdir()
                analysis = apply_threat_analysis_scan_scope(
                    ThreatAnalysis(schema_version="1.0", analysis_id="stored-threat"),
                    project.resolve(),
                    project.resolve(),
                )
                auditor = AsyncMock()
                with (
                    patch("backend.opencode.runner.run_threat_analysis_audit", AsyncMock()) as runner,
                    patch("agent.threat_auditor.run_threat_audit_tasks", auditor),
                ):
                    await _run_threat_analysis_phase(
                        config=AgentConfig(),
                        project_path=project.resolve(),
                        code_scan_path=project.resolve(),
                        reporter=FakeReporter(analysis),  # type: ignore[arg-type]
                        scan_id="scan-1",
                        product="demo",
                        workspace=workspace,
                        cancel_event=threading.Event(),
                        emit=lambda _phase, _message: None,
                        is_resume=True,
                        retry_threat_audit_task_ids=["threat-audit-1"],
                    )
                runner.assert_not_awaited()
                return auditor

        auditor = asyncio.run(run())
        auditor.assert_awaited_once()
        self.assertEqual(auditor.await_args.kwargs["only_task_ids"], {"threat-audit-1"})

    def test_resume_reruns_threat_analysis_when_stored_scope_differs(self) -> None:
        class FakeReporter:
            def __init__(self, analysis: ThreatAnalysis) -> None:
                self.analysis = analysis
                self.pushed: list[tuple[str, dict]] = []

            async def get_threat_analysis(self, scan_id: str) -> ThreatAnalysis | None:
                return self.analysis

            async def push_threat_analysis(self, scan_id: str, analysis: dict) -> None:
                self.pushed.append((scan_id, analysis))

        async def run() -> tuple[list[tuple[str, str]], FakeReporter, AsyncMock]:
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                old_dir = project / "old"
                scan_dir = project / "module"
                workspace = Path(tmp) / "workspace"
                old_dir.mkdir(parents=True)
                scan_dir.mkdir()
                workspace.mkdir()
                analysis = apply_threat_analysis_scan_scope(
                    ThreatAnalysis(schema_version="1.0", analysis_id="stored-threat"),
                    project.resolve(),
                    old_dir.resolve(),
                )
                reporter = FakeReporter(analysis)
                events: list[tuple[str, str]] = []

                async def emit(phase: str, message: str) -> None:
                    events.append((phase, message))

                runner = AsyncMock(return_value=ThreatAnalysis(
                    schema_version="1.0",
                    analysis_id="new-threat",
                ))
                with patch("backend.opencode.runner.run_threat_analysis_audit", runner):
                    await _run_threat_analysis_phase(
                        config=AgentConfig(),
                        project_path=project.resolve(),
                        code_scan_path=scan_dir.resolve(),
                        reporter=reporter,  # type: ignore[arg-type]
                        scan_id="scan-1",
                        product="demo",
                        workspace=workspace,
                        cancel_event=threading.Event(),
                        emit=emit,
                        is_resume=True,
                    )
                return events, reporter, runner

        events, reporter, runner = asyncio.run(run())

        runner.assert_awaited_once()
        self.assertEqual(reporter.pushed[0][1]["analysis_id"], "new-threat")
        self.assertTrue(any("扫描范围与当前续扫路径不一致" in message for _phase, message in events))
        self.assertTrue(any("开始基于攻击树的威胁分析" in message for _phase, message in events))

    def test_wait_for_threat_analysis_task_blocks_until_background_done(self) -> None:
        async def run() -> list[object]:
            release = asyncio.Event()
            events: list[object] = []

            async def background() -> None:
                events.append("started")
                await release.wait()
                events.append("done")

            async def emit(phase: str, message: str) -> None:
                events.append((phase, message))

            task = asyncio.create_task(background())
            await asyncio.sleep(0)
            waiter = asyncio.create_task(_wait_for_threat_analysis_task(task, emit=emit))
            await asyncio.sleep(0)
            events.append(("waiter_done_before_release", waiter.done()))
            release.set()
            await waiter
            return events

        events = asyncio.run(run())

        self.assertIn(("threat_analysis", "等待威胁分析后台任务收尾..."), events)
        self.assertIn(("waiter_done_before_release", False), events)
        self.assertIn("done", events)

    def test_git_history_phase_is_hard_disabled_even_when_config_enabled(self) -> None:
        config = AgentConfig()
        config.git_history.enabled = True
        cancel_event = threading.Event()

        self.assertFalse(GIT_HISTORY_PIPELINE_ENABLED)
        self.assertFalse(
            _should_run_git_history_phase(
                config,
                ran_fresh_static=True,
                retry_mode=False,
                workspace=Path("/tmp/opencode-workspace"),
                cancel_event=cancel_event,
            )
        )

    def test_memory_api_phase_is_hard_disabled_even_when_config_enabled(self) -> None:
        config = AgentConfig()
        config.memory_api_discovery.enabled = True
        cancel_event = threading.Event()

        self.assertFalse(MEMORY_API_DISCOVERY_PIPELINE_ENABLED)
        self.assertFalse(
            _should_run_memory_api_phase(
                config,
                workspace=Path("/tmp/opencode-workspace"),
                cancel_event=cancel_event,
            )
        )


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

    def test_first_audit_function_is_always_first_for_any_checker(self) -> None:
        candidates = [
            _candidate("intoverflow", 1).model_copy(
                update={"function": "MC_EthBuildPayloadByFrag"},
            ),
            _candidate("npd", 1),
            _candidate("memleak", 1),
            _candidate("memleak", 2),
            _candidate("safe_mem_oob", 1),
        ]

        ordered = _prepare_audit_queue(
            candidates,
            ["npd", "safe_mem_oob", "memleak", "intoverflow"],
            family_of={
                "npd": "npd",
                "safe_mem_oob": "oob",
                "memleak": "memleak",
                "intoverflow": "intoverflow",
            },
        )

        self.assertEqual(ordered[0].function, "MC_EthBuildPayloadByFrag")
        self.assertEqual(ordered[0].vuln_type, "intoverflow")

    def test_non_exact_first_audit_function_is_not_prioritized(self) -> None:
        candidates = [
            _candidate("npd", 1),
            _candidate("intoverflow", 1).model_copy(
                update={"function": "MC_EthBuildPayloadByFragTypo"},
            ),
            _candidate("intoverflow", 2),
        ]

        ordered = _prepare_audit_queue(
            candidates,
            ["npd", "intoverflow"],
            family_of={"intoverflow": "intoverflow", "npd": "npd"},
        )

        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered],
            [("npd", 1), ("intoverflow", 1), ("intoverflow", 2)],
        )

    def test_multiple_first_audit_function_candidates_keep_original_order(self) -> None:
        candidates = [
            _candidate("memleak", 20).model_copy(
                update={"function": "MC_EthBuildPayloadByFrag"},
            ),
            _candidate("npd", 1),
            _candidate("intoverflow", 10).model_copy(
                update={"function": "MC_EthBuildPayloadByFrag"},
            ),
            _candidate("safe_mem_oob", 10).model_copy(
                update={"function": "MC_EthBuildPayloadByFrag"},
            ),
        ]

        ordered = _prepare_audit_queue(
            candidates,
            ["npd", "safe_mem_oob", "intoverflow", "memleak"],
            family_of={
                "safe_mem_oob": "oob",
                "intoverflow": "intoverflow",
                "memleak": "memleak",
                "npd": "npd",
            },
        )

        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered[:3]],
            [("memleak", 20), ("intoverflow", 10), ("safe_mem_oob", 10)],
        )

    def test_first_audit_function_stays_first_after_pattern_round_robin(self) -> None:
        candidates = [
            _subject_candidate("npd", 1, "ptr"),
            _subject_candidate("npd", 2, "ptr", function="MC_EthBuildPayloadByFrag"),
            _subject_candidate("memleak", 1, "buf"),
        ]

        ordered = _prepare_audit_queue(
            candidates,
            ["npd", "memleak"],
            pattern_filter_enabled=True,
            pattern_filter_scope="directory",
        )

        self.assertEqual(ordered[0].function, "MC_EthBuildPayloadByFrag")
        self.assertEqual(
            [(c.vuln_type, c.line) for c in ordered[1:]],
            [("memleak", 1), ("npd", 1)],
        )

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

    def test_dedup_candidates_merges_same_family_same_function(self) -> None:
        candidates = [
            _subject_candidate("npd", 10, "ptr"),
            _subject_candidate("chain_npd", 12, "ctx->session"),
            _subject_candidate("npd", 20, "other", function="other_fn"),
        ]

        deduped, removed = _dedup_candidates(
            candidates,
            {"npd": "npd", "chain_npd": "npd"},
            ["npd", "chain_npd"],
        )

        self.assertEqual(removed, 1)
        self.assertEqual(len(deduped), 2)
        merged = next(c for c in deduped if c.function == "target")
        self.assertEqual(merged.vuln_type, "chain_npd")
        self.assertIn("`ctx->session, ptr`", merged.description)
        self.assertEqual(merged.metadata["subject"], "ctx->session, ptr")
        self.assertEqual(
            [(item["vuln_type"], item["subject"]) for item in merged.metadata["merged_from"]],
            [("chain_npd", "ctx->session"), ("npd", "ptr")],
        )

    def test_dedup_candidates_keeps_same_family_different_files(self) -> None:
        left = _subject_candidate("npd", 10, "ptr")
        right = left.model_copy(update={"file": "src/other.c"})

        deduped, removed = _dedup_candidates([left, right], {"npd": "npd"}, ["npd"])

        self.assertEqual(removed, 0)
        self.assertEqual(len(deduped), 2)

    def test_pattern_key_without_subject_is_unique_and_non_propagating(self) -> None:
        candidate = _candidate("npd", 1)

        key, can_propagate = _candidate_pattern_key(candidate, "directory")

        self.assertFalse(can_propagate)
        self.assertEqual(key, ("unique", candidate.file, candidate.line, candidate.function, candidate.vuln_type))

    def test_round_robin_by_pattern_interleaves_same_pattern_candidates(self) -> None:
        candidates = [
            _subject_candidate("npd", 1, "ptr"),
            _subject_candidate("npd", 2, "ptr"),
            _subject_candidate("npd", 3, "ctx"),
            _subject_candidate("npd", 4, "ptr"),
        ]

        ordered = _round_robin_by_pattern(candidates, "directory")

        self.assertEqual([c.line for c in ordered], [1, 3, 2, 4])


class ScanStoreCodeScanPathTests(unittest.TestCase):
    def test_refresh_backend_runtime_config_updates_loaded_backend_config(self) -> None:
        import backend.config as backend_config

        old_config_path = os.environ.get("CONFIG_PATH")
        old_config = backend_config._config
        with tempfile.TemporaryDirectory() as tmp:
            try:
                scan_dir = Path(tmp) / "scan"
                scan_dir.mkdir()
                cfg = AgentConfig()
                cfg.opencode.model = "old-model"
                cfg.opencode_concurrency = 1
                cfg.git_history.enabled = True
                cfg.git_history.max_commits = 12
                _configure_backend(cfg, scan_dir)
                loaded = backend_config.get_config()
                self.assertEqual(loaded.opencode.model, "old-model")
                self.assertEqual(loaded.opencode_concurrency, 1)
                self.assertTrue(loaded.git_history.enabled)
                self.assertEqual(loaded.git_history.max_commits, 12)

                cfg.opencode.model = "new-model"
                cfg.opencode_concurrency = 4
                cfg.git_history.enabled = False
                refresh_backend_runtime_config(cfg)

                self.assertEqual(loaded.opencode.model, "new-model")
                self.assertEqual(loaded.opencode_concurrency, 4)
                self.assertFalse(loaded.git_history.enabled)
            finally:
                if old_config_path is None:
                    os.environ.pop("CONFIG_PATH", None)
                else:
                    os.environ["CONFIG_PATH"] = old_config_path
                backend_config._config = old_config

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
                validation_environment="仿真UBBPi板环境",
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
                validation_environment="仿真UBBPi板环境",
            )

            store.save_scan(scan, meta)
            store.update_scan_product("scan-1", "5G")

            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            loaded_scan, loaded_meta = loaded
            self.assertEqual(loaded_scan.product, "5G")
            self.assertEqual(loaded_meta.product, "5G")
            self.assertEqual(loaded_scan.validation_environment, "仿真UBBPi板环境")
            self.assertEqual(loaded_meta.validation_environment, "仿真UBBPi板环境")

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

    def test_agent_opencode_pool_status_aggregates_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")

            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    global_running=0,
                    models=[
                        {
                            "id": "fast",
                            "model": "fast-model",
                            "capability": "low",
                            "max_concurrency": 2,
                            "total": 3,
                            "success": 2,
                            "failure": 1,
                            "avg_duration_seconds": 10,
                            "last_status": "failure",
                        }
                    ],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                status=OpenCodePoolStatus(
                    agent_session_id="session-2",
                    global_running=1,
                    models=[
                        {
                            "id": "fast",
                            "model": "fast-model",
                            "capability": "low",
                            "max_concurrency": 2,
                            "running": 1,
                            "total": 2,
                            "success": 2,
                            "avg_duration_seconds": 20,
                            "active_tasks": [{"task_type": "audit", "checker": "npd"}],
                            "last_status": "running",
                        }
                    ],
                    updated_at="2026-01-01T00:00:20+00:00",
                ),
            )

            status = store.get_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_id="agent-id",
                agent_session_id="session-2",
                online=True,
            )

            self.assertEqual(status.agent_id, "agent-id")
            self.assertTrue(status.online)
            self.assertEqual(status.models[0].total, 5)
            self.assertEqual(status.models[0].success, 4)
            self.assertEqual(status.models[0].failure, 1)
            self.assertEqual(status.models[0].running, 0)
            self.assertEqual(status.models[0].avg_duration_seconds, 14)
            self.assertEqual(status.models[0].active_tasks, [])

    def test_agent_pool_current_default_model_does_not_inherit_historical_claude(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    models=[{
                        "id": "default",
                        "model": "anthropic/claude-sonnet",
                        "use_default_model": True,
                        "capability": "high",
                        "total": 3,
                        "success": 3,
                        "avg_duration_seconds": 10,
                    }],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                status=OpenCodePoolStatus(
                    agent_session_id="session-2",
                    models=[{
                        "id": "default",
                        "model": "",
                        "use_default_model": True,
                        "capability": "low",
                        "weight": 2,
                        "max_concurrency": 2,
                        "time_windows": [{"start": "09:00", "end": "18:00"}],
                        "total": 2,
                        "success": 2,
                        "avg_duration_seconds": 20,
                    }],
                    updated_at="2026-01-01T00:00:20+00:00",
                ),
            )

            status = store.get_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                online=True,
            )

            model = status.models[0]
            self.assertEqual(model.model, "")
            self.assertTrue(model.use_default_model)
            self.assertEqual(model.capability, "low")
            self.assertEqual(model.weight, 2)
            self.assertEqual(model.max_concurrency, 2)
            self.assertEqual(model.time_windows, [{"start": "09:00", "end": "18:00"}])
            self.assertEqual(model.total, 5)
            self.assertEqual(model.avg_duration_seconds, 14)

    def test_agent_pool_new_session_named_model_disables_historical_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    models=[{
                        "id": "default",
                        "model": "anthropic/claude-sonnet",
                        "use_default_model": True,
                        "total": 4,
                        "success": 4,
                    }],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                status=OpenCodePoolStatus(
                    agent_session_id="session-2",
                    models=[{
                        "id": "named",
                        "model": "openai/gpt-current",
                        "enabled": True,
                        "available": True,
                    }],
                    updated_at="2026-01-01T00:00:20+00:00",
                ),
            )

            status = store.get_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                online=True,
            )

            models = {model.id: model for model in status.models}
            self.assertEqual(models["default"].model, "anthropic/claude-sonnet")
            self.assertEqual(models["default"].total, 4)
            self.assertFalse(models["default"].enabled)
            self.assertFalse(models["default"].available)
            self.assertEqual(models["named"].model, "openai/gpt-current")
            self.assertTrue(models["named"].enabled)
            self.assertTrue(models["named"].available)

    def test_agent_pool_empty_snapshot_invalidates_same_session_models(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    models=[{
                        "id": "default",
                        "model": "anthropic/claude-sonnet",
                        "use_default_model": True,
                        "running": 1,
                        "queued": 2,
                        "active_tasks": [{"task_type": "audit"}],
                    }],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    models=[],
                    updated_at="2026-01-01T00:00:20+00:00",
                ),
            )

            status = store.get_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                online=True,
            )

            model = status.models[0]
            self.assertFalse(model.enabled)
            self.assertFalse(model.available)
            self.assertEqual(model.running, 0)
            self.assertEqual(model.queued, 0)
            self.assertEqual(model.active_tasks, [])

    def test_agent_pool_api_live_snapshot_overrides_config_and_missing_models(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                status=OpenCodePoolStatus(
                    agent_session_id="session-2",
                    models=[
                        {
                            "id": "default",
                            "model": "stale-persisted-model",
                            "total": 5,
                            "success": 5,
                        },
                        {
                            "id": "removed",
                            "model": "removed-model",
                            "enabled": True,
                            "available": True,
                        },
                    ],
                    updated_at="2026-01-01T00:00:10+00:00",
                ),
            )
            agent = AgentInfo(
                agent_id="agent-id",
                name="agent-a",
                ip="127.0.0.1",
                port=8001,
                last_seen=datetime.now(timezone.utc).isoformat(),
                user_id="user-1",
                agent_session_id="session-2",
            )
            latest = OpenCodePoolStatus(
                agent_session_id="session-2",
                global_running=1,
                global_queued=2,
                queued_tasks=[{"task_type": "audit"}],
                models=[
                    {
                        "id": "default",
                        "model": "",
                        "use_default_model": True,
                        "capability": "high",
                        "weight": 4,
                        "max_concurrency": 3,
                        "enabled": True,
                        "available": True,
                        "time_windows": [{"start": "10:00", "end": "20:00"}],
                        "running": 1,
                        "queued": 2,
                        "active_tasks": [{"task_type": "audit", "checker": "npd"}],
                    },
                    {
                        "id": "live-only",
                        "model": "openai/gpt-live",
                    },
                ],
                updated_at="2026-01-01T00:00:20+00:00",
            )
            user = User(user_id="user-1", username="alice", role="user")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch.dict(agent_api._registered_agents, {"agent-id": agent}, clear=True),
                patch.dict(agent_api._agent_opencode_pool_latest, {"agent-id": latest}, clear=True),
            ):
                status = asyncio.run(
                    agent_api.get_agent_opencode_pool("agent-id", current_user=user)
                )

            models = {model.id: model for model in status.models}
            self.assertEqual(models["default"].model, "")
            self.assertTrue(models["default"].use_default_model)
            self.assertEqual(models["default"].capability, "high")
            self.assertEqual(models["default"].weight, 4)
            self.assertEqual(models["default"].max_concurrency, 3)
            self.assertEqual(models["default"].total, 5)
            self.assertEqual(models["default"].running, 1)
            self.assertEqual(models["default"].queued, 2)
            self.assertEqual(
                models["default"].active_tasks,
                [{"task_type": "audit", "checker": "npd"}],
            )
            self.assertFalse(models["removed"].enabled)
            self.assertFalse(models["removed"].available)
            self.assertIn("live-only", models)
            self.assertEqual(status.global_running, 1)
            self.assertEqual(status.global_queued, 2)

    def test_agent_pool_api_ignores_live_snapshot_from_other_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-2",
                status=OpenCodePoolStatus(
                    agent_session_id="session-2",
                    models=[{"id": "default", "model": "current-model"}],
                ),
            )
            agent = AgentInfo(
                agent_id="agent-id",
                name="agent-a",
                ip="127.0.0.1",
                port=8001,
                last_seen=datetime.now(timezone.utc).isoformat(),
                user_id="user-1",
                agent_session_id="session-2",
            )
            stale = OpenCodePoolStatus(
                agent_session_id="session-1",
                global_running=1,
                models=[{
                    "id": "default",
                    "model": "anthropic/claude-stale",
                    "running": 1,
                }],
            )
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch.dict(agent_api._registered_agents, {"agent-id": agent}, clear=True),
                patch.dict(agent_api._agent_opencode_pool_latest, {"agent-id": stale}, clear=True),
            ):
                status = asyncio.run(
                    agent_api.get_agent_opencode_pool(
                        "agent-id",
                        current_user=User(user_id="user-1", username="alice", role="user"),
                    )
                )

            self.assertEqual(status.models[0].model, "current-model")
            self.assertEqual(status.models[0].running, 0)
            self.assertEqual(status.global_running, 0)

    def test_agent_pool_api_marks_live_models_unavailable_when_agent_is_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_opencode_pool_status(
                agent_name="agent-a",
                user_id="user-1",
                agent_session_id="session-1",
                status=OpenCodePoolStatus(
                    agent_session_id="session-1",
                    models=[{"id": "named", "model": "openai/gpt", "available": True}],
                ),
            )
            agent = AgentInfo(
                agent_id="agent-id",
                name="agent-a",
                ip="127.0.0.1",
                port=8001,
                last_seen="2026-01-01T00:00:00+00:00",
                user_id="user-1",
                agent_session_id="session-1",
            )
            latest = OpenCodePoolStatus(
                agent_session_id="session-1",
                models=[{"id": "named", "model": "openai/gpt", "available": True}],
            )
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch.dict(agent_api._registered_agents, {"agent-id": agent}, clear=True),
                patch.dict(agent_api._agent_opencode_pool_latest, {"agent-id": latest}, clear=True),
            ):
                status = asyncio.run(
                    agent_api.get_agent_opencode_pool(
                        "agent-id",
                        current_user=User(user_id="user-1", username="alice", role="user"),
                    )
                )

            self.assertFalse(status.online)
            self.assertFalse(status.models[0].available)
            self.assertEqual(status.models[0].running, 0)
            self.assertEqual(status.global_running, 0)

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
