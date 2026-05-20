from __future__ import annotations

import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

from checkers.safe_mem_oob.analyzer import Analyzer as SafeMemOobAnalyzer


def test_safe_mem_oob_skips_when_semgrep_missing(tmp_path: Path) -> None:
    with patch("shutil.which", return_value=None):
        assert list(SafeMemOobAnalyzer().find_candidates(tmp_path)) == []


def test_safe_mem_oob_semgrep_output_uses_utf8_replace(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        assert kwargs["timeout"] == 900
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert cmd[:2] == ["semgrep", "scan"]
        assert any(arg.startswith("--json-output=") for arg in cmd)
        assert "--metrics=off" in cmd
        assert "--disable-version-check" in cmd
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        assert list(SafeMemOobAnalyzer().find_candidates(tmp_path)) == []


def test_safe_mem_oob_prefers_json_output_file(tmp_path: Path) -> None:
    file_output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=8,
        check_id="c-cpp.safe-mem.offset-full-size",
        message=(
            "Function=`copy_bad`. Safe memory call `memcpy_s` writes to an "
            "offset destination while dstsz still uses the full object size."
        ),
        metavars={
            "$CALL": {"abstract_content": "memcpy_s"},
            "$FUNC": {"abstract_content": "copy_bad"},
            "$BUF": {"abstract_content": "buf"},
            "$OFF": {"abstract_content": "off"},
            "$COUNT": {"abstract_content": "len"},
        },
        lines="memcpy_s(buf + off, sizeof(buf), src, len);",
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(file_output.stdout, encoding="utf-8")
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    assert candidates[0].file == "sample.c"
    assert candidates[0].line == 8
    assert candidates[0].function == "copy_bad"
    assert candidates[0].vuln_type == "safe_mem_oob"
    assert "offset-full-size" in candidates[0].description
    assert "memcpy_s" in candidates[0].description
    assert "匹配代码" in candidates[0].description


def test_safe_mem_oob_uses_semgrep_json_file_after_timeout(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "message_func.c"),
        line=12,
        check_id="c-cpp.safe-mem.member-non-member-size",
        message="Function=`handle_msg`. Safe memory call `memcpy_s` writes to member target.",
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
        candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    assert candidates[0].function == "handle_msg"
    assert candidates[0].file == "message_func.c"


def test_safe_mem_oob_skips_tool_errors_and_bad_json(tmp_path: Path) -> None:
    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 2, stdout="", stderr="bad config"),
        ),
    ):
        assert list(SafeMemOobAnalyzer().find_candidates(tmp_path)) == []

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 0, stdout="not-json", stderr=""),
        ),
    ):
        assert list(SafeMemOobAnalyzer().find_candidates(tmp_path)) == []


def test_safe_mem_oob_deduplicates_same_rule_and_destination(tmp_path: Path) -> None:
    payload = {
        "results": [
            _match(
                path=str(tmp_path / "dup.c"),
                line=5,
                check_id="c-cpp.safe-mem.member-non-member-size",
                message="Function=`f`. Safe memory call `memcpy_s` writes to member target.",
                metavars={
                    "$FUNC": {"abstract_content": "f"},
                    "$CALL": {"abstract_content": "memcpy_s"},
                    "$DST": {"abstract_content": "msg.payload"},
                    "$DSTSZ": {"abstract_content": "sizeof(msg)"},
                },
            ),
            _match(
                path=str(tmp_path / "dup.c"),
                line=5,
                check_id="c-cpp.safe-mem.member-non-member-size",
                message="Function=`f`. Safe memory call `memcpy_s` writes to member target.",
                metavars={
                    "$FUNC": {"abstract_content": "f"},
                    "$CALL": {"abstract_content": "memcpy_s"},
                    "$DST": {"abstract_content": "msg.payload"},
                    "$DSTSZ": {"abstract_content": "sizeof(msg)"},
                },
            ),
        ],
    }

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 1, stdout=json.dumps(payload), stderr=""),
        ),
    ):
        candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1


def test_safe_mem_oob_describes_pointer_sizeof_dst(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "ptr.c"),
        line=9,
        check_id="c-cpp.safe-mem.pointer-sizeof-dst",
        message=(
            "Function=`copy_ptr`. Safe memory call `memcpy_s` uses "
            "sizeof(pointer) as dstsz."
        ),
        metavars={
            "$FUNC": {"abstract_content": "copy_ptr"},
            "$CALL": {"abstract_content": "memcpy_s"},
            "$PTR": {"abstract_content": "dst"},
            "$COUNT": {"abstract_content": "len"},
        },
    )

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    assert "pointer-sizeof-dst" in candidates[0].description
    assert "dst: dst" in candidates[0].description
    assert "dstsz: sizeof(dst)" in candidates[0].description
    assert "count: len" in candidates[0].description


def test_safe_mem_oob_describes_three_argument_string_call_without_count(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "string.c"),
        line=7,
        check_id="c-cpp.safe-mem.member-non-member-size",
        message="Function=`copy_name`. Safe memory call `strcpy_s` writes to member target.",
        metavars={
            "$FUNC": {"abstract_content": "copy_name"},
            "$CALL": {"abstract_content": "strcpy_s"},
            "$OBJ": {"abstract_content": "msg"},
            "$FIELD": {"abstract_content": "name"},
            "$DSTSZ": {"abstract_content": "sizeof(msg)"},
        },
    )

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    assert "安全内存函数: strcpy_s" in candidates[0].description
    assert "dst: msg.name" in candidates[0].description
    assert "dstsz: sizeof(msg)" in candidates[0].description
    assert "count:" not in candidates[0].description


def _semgrep_output(
    *,
    path: str,
    line: int,
    check_id: str,
    message: str,
    metavars: dict,
    lines: str = "",
) -> CompletedProcess:
    payload = {
        "results": [
            _match(
                path=path,
                line=line,
                check_id=check_id,
                message=message,
                metavars=metavars,
                lines=lines,
            )
        ]
    }
    return CompletedProcess(["semgrep"], 0, stdout=json.dumps(payload), stderr="")


def _match(
    *,
    path: str,
    line: int,
    check_id: str,
    message: str,
    metavars: dict,
    lines: str = "",
) -> dict:
    return {
        "path": path,
        "start": {"line": line},
        "check_id": check_id,
        "extra": {
            "severity": "WARNING",
            "message": message,
            "metavars": metavars,
            "lines": lines,
            "metadata": {"risk_class": "test-risk"},
        },
    }
