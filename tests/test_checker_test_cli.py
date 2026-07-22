from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.models import Vulnerability
from tools import checker_test


@pytest.fixture(autouse=True)
def _mock_code_indexer(monkeypatch) -> None:
    def fake_analyze_directory(self, project_path: Path, on_progress=None, cancel_check=None):
        file_id = self.db.get_or_create_file("sample.c")
        self.db.insert_function(
            name="safe",
            signature="safe(void)",
            return_type="int",
            file_id=file_id,
            start_line=1,
            end_line=1,
            is_static=False,
            linkage="extern",
            body="int safe(void) { return 0; }",
        )
        self.db.insert_function(
            name="local_vuln",
            signature="local_vuln(void)",
            return_type="int",
            file_id=file_id,
            start_line=2,
            end_line=2,
            is_static=False,
            linkage="extern",
            body="int local_vuln(void) { return 1; }",
        )
        self.db.commit()
        if on_progress:
            on_progress(1, 1)

    monkeypatch.setattr(
        "code_parser.cpp_analyzer.CppAnalyzer.analyze_directory",
        fake_analyze_directory,
    )


def test_checker_test_cli_runs_static_analysis(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "localcheck")

    rc = checker_test.main([
        "localcheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--expect-candidates",
        "1",
    ])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Checker: localcheck" in out
    assert "Candidates: 1" in out
    assert "sample.c:2 local_vuln" in out


def test_checker_test_cli_allows_disabled_checker(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "disabledcheck", enabled=False)

    rc = checker_test.main([
        "disabledcheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["checker"]["enabled"] is False
    assert payload["candidate_count"] == 1
    assert "enabled: false" in payload["warnings"][0]


def test_checker_test_cli_json_output_writes_pretty_unicode_file(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    output_path = tmp_path / "result" / "candidates.json"
    _write_checker(
        checkers_dir,
        "unicodecheck",
        candidate_description="函数 'local_vuln' 中发现 1 个疑似内存泄漏点",
    )

    rc = checker_test.main([
        "unicodecheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--json-output",
        str(output_path),
    ])

    captured = capsys.readouterr()
    text = output_path.read_text(encoding="utf-8")
    payload = json.loads(text)
    assert rc == 0
    assert captured.out == ""
    assert payload["candidate_count"] == 1
    assert payload["candidates"][0]["description"].startswith("函数 'local_vuln'")
    assert '\n  "ok": true' in text
    assert "\\u51fd" not in text


def test_checker_test_cli_rejects_mismatched_vuln_type(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "localcheck", vuln_type="wrong")

    rc = checker_test.main([
        "localcheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
    ])

    err = capsys.readouterr().err
    assert rc == 2
    assert "expected 'localcheck'" in err


def test_checker_test_cli_candidate_count_assertion(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "localcheck")

    rc = checker_test.main([
        "localcheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--expect-candidates",
        "2",
    ])

    err = capsys.readouterr().err
    assert rc == 2
    assert "--expect-candidates 2" in err


def test_checker_test_cli_audit_uses_existing_audit_path(tmp_path: Path, monkeypatch, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "localcheck")
    calls: list[tuple[str, int]] = []

    class DummyMCPServer:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> int:
            return 9999

        def stop(self) -> None:
            return None

    async def fake_run_audit(
        workspace,
        candidate,
        project_id,
        on_output=None,
        cancel_event=None,
        timeout=None,
        project_dir=None,
    ):
        calls.append((candidate.file, candidate.line))
        return Vulnerability(
            file=candidate.file,
            line=candidate.line,
            function=candidate.function,
            vuln_type=candidate.vuln_type,
            severity="low",
            description=candidate.description,
            ai_analysis="mock audit",
            confirmed=True,
            ai_verdict="confirmed",
        )

    monkeypatch.setattr("deephole_client.local_mcp.LocalMCPServer", DummyMCPServer)
    monkeypatch.setattr("deephole_client.mcp_registry.register", lambda *args, **kwargs: None)
    monkeypatch.setattr("deephole_client.mcp_registry.unregister", lambda *args, **kwargs: None)
    monkeypatch.setattr("deephole_client.opencode_integration.get_global_opencode_workspace", lambda *args, **kwargs: project_dir)
    monkeypatch.setattr("deephole_client.opencode_workflows.run_audit", fake_run_audit)

    rc = checker_test.main([
        "localcheck",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--audit",
        "--audit-limit",
        "1",
        "--json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert calls == [("sample.c", 2)]
    assert payload["audits"][0]["ai_verdict"] == "confirmed"


def test_checker_test_cli_generates_project_candidate_for_skill_only_checker(tmp_path: Path, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "skillonly", with_analyzer=False)

    rc = checker_test.main([
        "skillonly",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["candidate_count"] == 1
    candidate = payload["candidates"][0]
    assert candidate["file"] == "."
    assert candidate["line"] == 1
    assert candidate["function"] == "__project__"


def test_checker_test_cli_project_audit_returns_multiple_results(tmp_path: Path, monkeypatch, capsys) -> None:
    checkers_dir = tmp_path / "checkers"
    project_dir = _write_project(tmp_path)
    _write_checker(checkers_dir, "skillonly", with_analyzer=False)

    class DummyMCPServer:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> int:
            return 9999

        def stop(self) -> None:
            return None

    async def fake_run_project_audit(
        workspace,
        candidate,
        project_id,
        on_output=None,
        cancel_event=None,
        timeout=None,
        project_dir=None,
    ):
        return [
            Vulnerability(
                file="sample.c",
                line=2,
                function="local_vuln",
                vuln_type=candidate.vuln_type,
                severity="high",
                description="project issue",
                ai_analysis="project analysis",
                confirmed=True,
                ai_verdict="confirmed",
            ),
            Vulnerability(
                file=candidate.file,
                line=candidate.line,
                function=candidate.function,
                vuln_type=candidate.vuln_type,
                severity="low",
                description="no more issues",
                ai_analysis="done",
                confirmed=False,
                ai_verdict="not_confirmed",
            ),
        ]

    monkeypatch.setattr("deephole_client.local_mcp.LocalMCPServer", DummyMCPServer)
    monkeypatch.setattr("deephole_client.mcp_registry.register", lambda *args, **kwargs: None)
    monkeypatch.setattr("deephole_client.mcp_registry.unregister", lambda *args, **kwargs: None)
    monkeypatch.setattr("deephole_client.opencode_integration.get_global_opencode_workspace", lambda *args, **kwargs: project_dir)
    monkeypatch.setattr("deephole_client.opencode_workflows.run_project_audit", fake_run_project_audit)

    rc = checker_test.main([
        "skillonly",
        str(project_dir),
        "--checkers-dir",
        str(checkers_dir),
        "--audit",
        "--json",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert len(payload["audits"]) == 2
    assert payload["audits"][0]["file"] == "sample.c"
    assert payload["audits"][1]["function"] == "__project__"


def _write_project(tmp_path: Path) -> Path:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "sample.c").write_text(
        "int safe(void) { return 0; }\n"
        "int local_vuln(void) { return 1; }\n",
        encoding="utf-8",
    )
    return project_dir


def _write_checker(
    checkers_dir: Path,
    name: str,
    *,
    enabled: bool = True,
    vuln_type: str | None = None,
    with_analyzer: bool = True,
    candidate_description: str = "local test candidate",
) -> None:
    checker_dir = checkers_dir / name
    checker_dir.mkdir(parents=True)
    (checker_dir / "checker.yaml").write_text(
        "\n".join(
            [
                f"name: {name}",
                f"label: {name.upper()}",
                f"description: {name} checker",
                f"enabled: {str(enabled).lower()}",
                "visibility: admin",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (checker_dir / "SKILL.md").write_text("# Local checker\n", encoding="utf-8")
    if with_analyzer:
        (checker_dir / "helper.py").write_text(
            f"VULN_TYPE = {vuln_type or name!r}\n",
            encoding="utf-8",
        )
        (checker_dir / "analyzer.py").write_text(
            "from backend.analyzers.base import BaseAnalyzer, Candidate\n"
            "from .helper import VULN_TYPE\n\n"
            "class Analyzer(BaseAnalyzer):\n"
            "    vuln_type = VULN_TYPE\n\n"
            "    def find_candidates(self, project_path, db=None):\n"
            "        return [Candidate(\n"
            "            file='sample.c',\n"
            "            line=2,\n"
            "            function='local_vuln',\n"
            f"            description={candidate_description!r},\n"
            "            vuln_type=self.vuln_type,\n"
            "        )]\n",
            encoding="utf-8",
        )
