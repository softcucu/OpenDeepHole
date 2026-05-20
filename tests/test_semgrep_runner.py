import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

from backend.analyzers.semgrep_runner import run_semgrep


def test_semgrep_runner_sets_noninteractive_env(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["semgrep", "scan"]
        assert "--metrics=off" in cmd
        assert "--disable-version-check" in cmd
        assert "--no-autofix" in cmd
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["env"]["PYTHONUTF8"] == "1"
        assert kwargs["env"]["PYTHONIOENCODING"] == "utf-8"
        assert kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"
        assert kwargs["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run):
        result = run_semgrep(tmp_path, rule_file=rule_file, checker_name="unit", timeout=3)

    assert result is not None
    assert result.returncode == 0
    assert result.stdout == '{"results":[]}'


def test_semgrep_runner_returns_none_when_timeout_has_no_json(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run):
        result = run_semgrep(tmp_path, rule_file=rule_file, checker_name="unit", timeout=1)

    assert result is None
