import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

from checkers.inf_loop.analyzer import Analyzer as InfLoopAnalyzer
from checkers.resleak import analyzer as resleak_analyzer


def test_inf_loop_semgrep_output_uses_utf8_replace(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        assert kwargs["timeout"] == 900
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert cmd[:2] == ["semgrep", "scan"]
        assert "--metrics=off" in cmd
        assert "--disable-version-check" in cmd
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        assert list(InfLoopAnalyzer().find_candidates(tmp_path)) == []


def test_inf_loop_uses_semgrep_json_file_after_timeout(tmp_path: Path) -> None:
    output = _semgrep_output(
        path="missing.c",
        line=12,
        message=(
            "Function=`append`. CWE-835 potential infinite loop: "
            "loop-progress variable `begin` is advanced by `count`."
        ),
        metavars={},
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(output.stdout, encoding="utf-8")
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(InfLoopAnalyzer().find_candidates(tmp_path))

    assert candidates[0].function == "append"


def test_resleak_cppcheck_output_uses_utf8_replace(tmp_path: Path) -> None:
    (tmp_path / "sample.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    internal = tmp_path / ".opendeephole" / "opencode" / "generated.c"
    internal.parent.mkdir(parents=True)
    internal.write_text("int generated(void) { return 0; }\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        file_list_arg = next(arg for arg in cmd if arg.startswith("--file-list="))
        listed_files = Path(file_list_arg.split("=", 1)[1]).read_text(encoding="utf-8").splitlines()
        assert listed_files == [(tmp_path / "sample.c").as_posix()]
        assert str(tmp_path) not in cmd
        return CompletedProcess(cmd, 0, stdout="", stderr="<results><errors /></results>")

    with patch("checkers.resleak.analyzer.subprocess.run", side_effect=fake_run):
        assert list(resleak_analyzer._run_cppcheck(tmp_path, "cppcheck")) == []


def test_inf_loop_uses_function_name_from_semgrep_message(tmp_path: Path) -> None:
    output = _semgrep_output(
        path="missing.c",
        line=12,
        message=(
            "Function=`append`. CWE-835 potential infinite loop: "
            "loop-progress variable `begin` is advanced by `count`."
        ),
        metavars={},
    )

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(InfLoopAnalyzer().find_candidates(tmp_path))

    assert candidates[0].function == "append"


def test_inf_loop_matches_windows_semgrep_path_to_code_database(tmp_path: Path) -> None:
    project = tmp_path / "srsRAN_Project-main"
    project.mkdir()
    reported_path = r"srsRAN_Project-main\external\fmt\include\fmt\base.h"
    output = _semgrep_output(
        path=reported_path,
        line=1812,
        message="CWE-835 potential infinite loop",
        metavars={},
    )

    class FakeDb:
        def get_all_functions(self):
            return [
                {
                    "file_path": "external/fmt/include/fmt/base.h",
                    "start_line": 1800,
                    "end_line": 1820,
                    "name": "append",
                }
            ]

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(InfLoopAnalyzer().find_candidates(project, FakeDb()))

    assert candidates[0].function == "append"
    assert candidates[0].file == "external/fmt/include/fmt/base.h"


def test_inf_loop_resolves_windows_semgrep_path_for_tree_sitter(tmp_path: Path) -> None:
    project = tmp_path / "srsRAN_Project-main"
    source = project / "external" / "fmt" / "include" / "fmt" / "base.h"
    source.parent.mkdir(parents=True)
    source.write_text(
        "void append() {\n"
        "  int begin = 0;\n"
        "  while (begin < 10) {\n"
        "    begin += 1;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    output = _semgrep_output(
        path=r"srsRAN_Project-main\external\fmt\include\fmt\base.h",
        line=3,
        message="CWE-835 potential infinite loop",
        metavars={},
    )

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(InfLoopAnalyzer().find_candidates(project))

    assert candidates[0].function == "append"
    assert candidates[0].file == "external/fmt/include/fmt/base.h"


def _semgrep_output(
    *,
    path: str,
    line: int,
    message: str,
    metavars: dict,
) -> CompletedProcess:
    payload = {
        "results": [
            {
                "path": path,
                "start": {"line": line},
                "check_id": "c-cpp.loop.unchecked-zero-step-add-assign",
                "extra": {
                    "severity": "WARNING",
                    "message": message,
                    "metavars": metavars,
                },
            }
        ]
    }
    return CompletedProcess(["semgrep"], 0, stdout=json.dumps(payload), stderr="")
