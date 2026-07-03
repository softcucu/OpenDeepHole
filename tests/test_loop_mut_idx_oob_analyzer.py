from __future__ import annotations

import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import yaml

from checkers.loop_mut_idx_oob.analyzer import Analyzer as LoopMutIdxOobAnalyzer


RULE_FILE = Path("checkers/loop_mut_idx_oob/loop_mut_idx_oob_semgrep.yml")


class FakeDb:
    def get_function_by_location(self, file_path: str, line: int):
        if file_path == "sample.c" and line == 8:
            return {"name": "copy_loop"}
        if file_path == "derived.c" and line == 17:
            return {"name": "derived_loop"}
        return None


def test_loop_mut_idx_oob_skips_when_semgrep_missing(tmp_path: Path) -> None:
    with patch("shutil.which", return_value=None):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


def test_loop_mut_idx_oob_rule_yaml_is_valid() -> None:
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 5
    rule_ids = {rule["id"] for rule in data["rules"]}
    assert "c.loop-mutated-index-array-access.broad" in rule_ids
    assert "c.loop-bound-unchecked-index-access.broad" in rule_ids
    assert "c.loop-mutated-index-pointer-access.broad" in rule_ids
    assert "c.loop-mutated-index-memory-call.broad" in rule_ids
    assert "c.loop-mutated-index-derived-pointer-sink.broad" in rule_ids


def test_loop_mut_idx_oob_semgrep_runner_arguments(tmp_path: Path) -> None:
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
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


def test_loop_mut_idx_oob_direct_result_uses_json_file_and_code_db(tmp_path: Path) -> None:
    file_output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=8,
        check_id="c.loop-mutated-index-array-access.broad",
        message="Possible unchecked loop index memory access.",
        metavars={
            "$IDX": {"abstract_content": "idx"},
            "$COND": {"abstract_content": "remain > 0"},
            "$STEP": {"abstract_content": "step"},
            "$BASE": {"abstract_content": "dst"},
        },
        metadata={"source_kind": "array", "recall": "high"},
        lines="dst[idx] = src[idx];",
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(file_output.stdout, encoding="utf-8")
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.line == 8
    assert candidate.function == "copy_loop"
    assert candidate.vuln_type == "loop_mut_idx_oob"
    assert "越界访问问题" in candidate.description
    assert "循环变化索引: idx" in candidate.description
    assert "循环条件: remain > 0" in candidate.description
    assert "内存访问: dst[idx]" in candidate.description
    assert "宽召回" not in candidate.description
    assert "匹配代码" not in candidate.description


def test_loop_mut_idx_oob_derived_pointer_result_and_dedup(tmp_path: Path) -> None:
    payload = {
        "results": [
            _match(
                path=str(tmp_path / "derived.c"),
                line=17,
                check_id="c.loop-mutated-index-derived-pointer-sink.broad",
                message="Possible unchecked loop-index-derived pointer reaches memory sink.",
                metavars={
                    "$IDX": {"abstract_content": "idx"},
                    "$COND": {"abstract_content": "remain"},
                    "$BASE": {"abstract_content": "base"},
                    "$P": {"abstract_content": "tmp"},
                },
                metadata={"source_kind": "derived-pointer", "recall": "high"},
                lines="*tmp = 0;",
            ),
            _match(
                path=str(tmp_path / "derived.c"),
                line=17,
                check_id="c.loop-mutated-index-derived-pointer-sink.broad",
                message="Possible unchecked loop-index-derived pointer reaches memory sink.",
                metavars={
                    "$IDX": {"abstract_content": "idx"},
                    "$COND": {"abstract_content": "remain"},
                    "$BASE": {"abstract_content": "base"},
                    "$P": {"abstract_content": "tmp"},
                },
                metadata={"source_kind": "derived-pointer", "recall": "high"},
                lines="*tmp = 0;",
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
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "derived_loop"
    assert "越界访问问题" in candidates[0].description
    assert "derived-pointer" not in candidates[0].description
    assert "循环条件: remain" in candidates[0].description


def test_loop_mut_idx_oob_timeout_uses_partial_json(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=8,
        check_id="c.loop-mutated-index-array-access.broad",
        message="Possible unchecked loop index memory access.",
        metavars={"$IDX": {"abstract_content": "idx"}, "$COND": {"abstract_content": "remain"}},
        metadata={"source_kind": "array", "recall": "high"},
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(output.stdout, encoding="utf-8")
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("backend.analyzers.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "copy_loop"


def test_loop_mut_idx_oob_skips_tool_errors_and_bad_json(tmp_path: Path) -> None:
    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 2, stdout="", stderr="bad config"),
        ),
    ):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "backend.analyzers.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 0, stdout="not-json", stderr=""),
        ),
    ):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


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
            "severity": "WARNING",
            "message": message,
            "metavars": metavars,
            "lines": lines,
            "metadata": metadata or {"llm_audit": True},
        },
    }
