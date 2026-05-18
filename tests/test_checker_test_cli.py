from __future__ import annotations

import json
from pathlib import Path

from backend.models import Vulnerability
from tools import checker_test


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
        def start(self) -> int:
            return 9999

        def stop(self) -> None:
            return None

    async def fake_run_audit(workspace, candidate, project_id, on_output=None, cancel_event=None, timeout=None):
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

    monkeypatch.setattr("agent.local_mcp.LocalMCPServer", DummyMCPServer)
    monkeypatch.setattr("agent.mcp_registry.register", lambda *args, **kwargs: None)
    monkeypatch.setattr("agent.mcp_registry.unregister", lambda *args, **kwargs: None)
    monkeypatch.setattr("backend.opencode.config.create_scan_workspace", lambda *args, **kwargs: project_dir)
    monkeypatch.setattr("backend.opencode.config.cleanup_workspace", lambda *args, **kwargs: None)
    monkeypatch.setattr("backend.opencode.runner.run_audit", fake_run_audit)

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
        "            description='local test candidate',\n"
        "            vuln_type=self.vuln_type,\n"
        "        )]\n",
        encoding="utf-8",
    )
