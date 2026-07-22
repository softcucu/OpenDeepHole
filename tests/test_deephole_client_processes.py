from __future__ import annotations

import asyncio
import inspect
import tempfile
import threading
from pathlib import Path
from unittest.mock import AsyncMock, patch

from code_parser import CodeDatabase
from task_agent import OpenCodeResult

from deephole_client.candidate_audit import run_candidate_audit
from deephole_client.fp_review import run_fp_review
from deephole_client.static_analysis import run_static_analysis
from deephole_client.threat_analysis import run_threat_analysis
from deephole_client.threat_audit import run_threat_audit
from deephole_client.vulnerability_validation import run_vulnerability_validation


PROCESS_FUNCTIONS = (
    run_threat_analysis,
    run_static_analysis,
    run_candidate_audit,
    run_threat_audit,
    run_fp_review,
    run_vulnerability_validation,
)


def _task_result(structured: dict) -> OpenCodeResult:
    return OpenCodeResult(
        session_id="session-1",
        status="success",
        text="{}",
        structured=structured,
        model="test/model",
        output_source={"model": "test/model", "serve_session_id": "session-1"},
    )


def test_all_process_entries_are_async_and_reject_unknown_keys() -> None:
    for function in PROCESS_FUNCTIONS:
        assert inspect.iscoroutinefunction(function)
        try:
            asyncio.run(function(unknown_process_key=True))
        except TypeError as exc:
            assert "unexpected key" in str(exc)
        else:
            raise AssertionError(f"{function.__name__} accepted an unknown key")


def test_threat_processes_run_with_task_agent_only() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        events: list[dict] = []
        threat_result = _task_result({
            "assets": [],
            "high_risk_external_interfaces": [],
            "attack_trees": [],
            "attack_paths": [{
                "path_id": "AP-1",
                "attack_surface_name": "socket",
                "attack_method_name": "malformed packet",
                "code_paths": [{"path": "src/parser.c", "description": "parser"}],
            }],
            "code_path_mappings": [],
        })
        with patch(
            "deephole_client.threat_analysis.runner.run_opencode_task",
            new=AsyncMock(return_value=threat_result),
        ):
            analysis = await run_threat_analysis(
                project_path=project,
                work_dir=root / "threat",
                scan_id="scan-1",
                output=events.append,
            )
        assert analysis["status"] == "success"
        assert analysis["analysis"]["attack_paths"][0]["path_id"] == "AP-1"
        assert events and all(event["process"] == "threat_analysis" for event in events)

        audit_task_result = _task_result({"vulnerabilities": [{
            "file": "src/parser.c", "line": 10, "function": "parse",
            "vuln_type": "oob", "severity": "high", "description": "bad length",
            "ai_analysis": "reachable", "confirmed": True, "ai_verdict": "confirmed",
        }]})
        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=audit_task_result),
        ):
            audit = await run_threat_audit(
                project_path=project,
                work_dir=root / "audit",
                scan_id="scan-1",
                threat_analysis=analysis["analysis"],
            )
        assert audit["status"] == "success"
        assert audit["vulnerabilities"][0]["analysis_source"] == "threat_audit"

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_and_candidate_audit_processes_form_a_minimal_pipeline() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        source = project / "sample.c"
        source.write_text("int bad(void) { return 0; }\n", encoding="utf-8")
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        checker_root = root / "checkers"
        checker = checker_root / "demo"
        checker.mkdir(parents=True)
        (checker / "checker.yaml").write_text(
            "name: demo\nlabel: Demo\nenabled: true\nmode: opencode\n",
            encoding="utf-8",
        )
        (checker / "SKILL.md").write_text("Audit the candidate.", encoding="utf-8")
        (checker / "analyzer.py").write_text(
            "from deephole_client.static_analysis.base import BaseAnalyzer, Candidate\n"
            "class Analyzer(BaseAnalyzer):\n"
            "    vuln_type = 'demo'\n"
            "    def find_candidates(self, project_path, db=None):\n"
            "        return [Candidate(file='sample.c', line=1, function='bad', "
            "description='candidate', vuln_type='demo')]\n",
            encoding="utf-8",
        )
        static = await asyncio.wait_for(run_static_analysis(
            project_path=project,
            index_db_path=index_path,
            checker_dirs=[checker_root],
        ), timeout=5)
        assert static["status"] == "success"
        assert static["stats"]["total"] == 1

        model_result = _task_result({
            "vulnerabilities": [{
                "file": "sample.c", "line": 1, "function": "bad", "vuln_type": "demo",
                "severity": "low", "description": "candidate", "ai_analysis": "safe",
                "confirmed": False, "ai_verdict": "not_confirmed",
            }],
            "markdown_reports": [],
        })
        with patch(
            "deephole_client.candidate_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=model_result),
        ):
            audited = await asyncio.wait_for(run_candidate_audit(
                project_path=project,
                work_dir=root / "candidate-audit",
                scan_id="scan-1",
                candidates=static["candidates"],
                checker_dirs=[checker_root],
                index_db_path=index_path,
            ), timeout=5)
        assert audited["status"] == "success"
        assert audited["vulnerabilities"][0]["ai_verdict"] == "not_confirmed"
        assert audited["processed_keys"] == [{
            "file": "sample.c", "line": 1, "function": "bad", "vuln_type": "demo",
        }]

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_fp_review_and_validation_processes_run_in_batches() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        vulnerability = {
            "index": 7, "file": "sample.c", "line": 1, "function": "bad",
            "vuln_type": "oob", "severity": "high", "description": "candidate",
            "ai_analysis": "analysis", "confirmed": True,
        }
        with patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=AsyncMock(return_value=_task_result({
                "verdict": "false_positive", "reason": "guarded", "evidence": ["check"],
                "revised_severity": "low",
            })),
        ):
            reviewed = await run_fp_review(
                project_path=project,
                work_dir=root / "fp",
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[vulnerability],
            )
        assert reviewed["processed"] == 1
        assert reviewed["results"][0]["verdict"] == "false_positive"

        validators = root / "validators"
        validator = validators / "demo"
        validator.mkdir(parents=True)
        (validator / "validator.yaml").write_text(
            "schema_version: 1\nproduct: Demo\nvalidation_environment: lab\n",
            encoding="utf-8",
        )
        (validator / "validator.py").write_text(
            "from deephole_client.vulnerability_validation import ValidationResult\n"
            "async def validate(**kwargs):\n"
            "    await kwargs['emit_stdout']('validation', 'ran')\n"
            "    return ValidationResult(True, True, summary='verified')\n",
            encoding="utf-8",
        )
        validated = await run_vulnerability_validation(
            project_path=project,
            code_scan_path=project,
            work_dir=root / "validation",
            scan_id="scan-1",
            product="Demo",
            environment="lab",
            validation_items=[{"vuln_index": 7, "vulnerability": vulnerability}],
            validators_dir=validators,
            environment_config={},
            cancel_event=threading.Event(),
        )
        assert validated["status"] == "success"
        assert validated["validations"][0]["status"] == "verified"
        assert validated["validations"][0]["is_problem"] is True

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))
