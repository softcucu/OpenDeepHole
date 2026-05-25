from __future__ import annotations

import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import yaml

from checkers.intoverflow.analyzer import Analyzer as IntOverflowAnalyzer


RULE_FILE = Path("checkers/intoverflow/intoverflow_semgrep.yml")


class FakeDb:
    def get_function_by_location(self, file_path: str, line: int):
        if file_path == "sample.c" and line == 12:
            return {"name": "parse_packet"}
        if file_path == "dup.c" and line == 21:
            return {"name": "copy_items"}
        return None


def test_intoverflow_skips_when_semgrep_missing(tmp_path: Path) -> None:
    with patch("shutil.which", return_value=None):
        assert list(IntOverflowAnalyzer().find_candidates(tmp_path)) == []


def test_intoverflow_rule_yaml_is_valid() -> None:
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 7
    rule_ids = {rule["id"] for rule in data["rules"]}
    assert "c-cpp.intoverflow.direct-arith-sink" in rule_ids
    assert "c-cpp.intoverflow.direct-arith-access-sink" in rule_ids
    assert "c-cpp.intoverflow.assigned-arith-to-sink" in rule_ids
    assert "c-cpp.intoverflow.assigned-arith-access-sink" in rule_ids
    assert "c-cpp.intoverflow.header-subtract-sink" in rule_ids
    assert "c-cpp.intoverflow.multiply-size-to-allocation" in rule_ids
    assert "c-cpp.intoverflow.narrowed-arith-to-sink" in rule_ids


def test_intoverflow_semgrep_runner_arguments(tmp_path: Path) -> None:
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
        assert list(IntOverflowAnalyzer().find_candidates(tmp_path)) == []


def test_intoverflow_result_uses_json_file_and_code_db(tmp_path: Path) -> None:
    file_output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=12,
        check_id="c-cpp.intoverflow.header-subtract-sink",
        message="Function=`parse_packet`. Length-like value is reduced by a header.",
        metavars={
            "$LEN": {"abstract_content": "packet_len"},
            "$OFF": {"abstract_content": "HEADER_SIZE"},
            "$VAR": {"abstract_content": "body_len"},
            "$CALL": {"abstract_content": "memcpy"},
        },
        metadata={"source_kind": "header-subtract-sink", "risk_class": "length minus header"},
        lines="memcpy(dst, src, body_len);",
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(file_output.stdout, encoding="utf-8")
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(IntOverflowAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.line == 12
    assert candidate.function == "parse_packet"
    assert candidate.vuln_type == "intoverflow"
    assert "header-subtract-sink" in candidate.description
    assert "可疑整数运算: packet_len - HEADER_SIZE" in candidate.description
    assert "危险使用点: memcpy(...)" in candidate.description
    assert "复核重点" in candidate.description
    assert "匹配代码" in candidate.description


def test_intoverflow_deduplicates_same_match(tmp_path: Path) -> None:
    payload = {
        "results": [
            _match(
                path=str(tmp_path / "dup.c"),
                line=21,
                check_id="c-cpp.intoverflow.multiply-size-to-allocation",
                message="Function=`copy_items`. Multiplication reaches allocation.",
                metavars={
                    "$COUNT": {"abstract_content": "count"},
                    "$SIZE": {"abstract_content": "sizeof(Item)"},
                    "$SIZEVAR": {"abstract_content": "bytes"},
                    "$CALL": {"abstract_content": "malloc"},
                },
                metadata={"source_kind": "multiply-size-to-allocation"},
                lines="char *buf = malloc(bytes);",
            ),
            _match(
                path=str(tmp_path / "dup.c"),
                line=21,
                check_id="c-cpp.intoverflow.multiply-size-to-allocation",
                message="Function=`copy_items`. Multiplication reaches allocation.",
                metavars={
                    "$COUNT": {"abstract_content": "count"},
                    "$SIZE": {"abstract_content": "sizeof(Item)"},
                    "$SIZEVAR": {"abstract_content": "bytes"},
                    "$CALL": {"abstract_content": "malloc"},
                },
                metadata={"source_kind": "multiply-size-to-allocation"},
                lines="char *buf = malloc(bytes);",
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
        candidates = list(IntOverflowAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "copy_items"
    assert "count * sizeof(Item)" in candidates[0].description


def test_intoverflow_timeout_uses_partial_json(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=12,
        check_id="c-cpp.intoverflow.direct-arith-sink",
        message="Function=`parse_packet`. Arithmetic expression reaches a sink.",
        metavars={"$A": {"abstract_content": "off"}, "$B": {"abstract_content": "len"}},
        metadata={"source_kind": "direct-arith-sink"},
        lines="dst[off + len] = 0;",
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(output.stdout, encoding="utf-8")
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(IntOverflowAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "parse_packet"


def test_intoverflow_skips_tool_errors_and_bad_json(tmp_path: Path) -> None:
    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 2, stdout="", stderr="bad config"),
        ),
    ):
        assert list(IntOverflowAnalyzer().find_candidates(tmp_path)) == []

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 0, stdout="not-json", stderr=""),
        ),
    ):
        assert list(IntOverflowAnalyzer().find_candidates(tmp_path)) == []


def _semgrep_output(
    *,
    path: str,
    line: int,
    check_id: str,
    message: str,
    metavars: dict,
    metadata: dict | None = None,
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
                metadata=metadata,
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
    metadata: dict | None = None,
    lines: str = "",
) -> dict:
    return {
        "path": path,
        "start": {"line": line},
        "check_id": check_id,
        "extra": {
            "severity": "ERROR",
            "message": message,
            "metavars": metavars,
            "lines": lines,
            "metadata": metadata or {"llm_audit": True},
        },
    }
