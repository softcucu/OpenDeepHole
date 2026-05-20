from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.analyzers.semgrep_runner import SemgrepRunResult
from checkers.bufoverflow import analyzer as bufoverflow_analyzer
from checkers.double_free import analyzer as double_free_analyzer
from checkers.inf_loop import analyzer as inf_loop_analyzer
from checkers.mp_npd import analyzer as mp_npd_analyzer
from checkers.mp_resouce_leak import analyzer as mp_resouce_leak_analyzer


@pytest.mark.parametrize(
    ("module", "checker_cls", "check_id"),
    [
        (bufoverflow_analyzer, bufoverflow_analyzer.Analyzer, "ccpp.struct-cast-field-access-without-min-size-check"),
        (double_free_analyzer, double_free_analyzer.Analyzer, "c-cpp.double-free.A.release-before-goto-cleanup-same-resource"),
        (inf_loop_analyzer, inf_loop_analyzer.Analyzer, "c-cpp.loop.unchecked-zero-step-add-assign"),
        (mp_npd_analyzer, mp_npd_analyzer.Analyzer, "ccpp.multi-layer-pointer-use-before-null-check"),
        (
            mp_resouce_leak_analyzer,
            mp_resouce_leak_analyzer.Analyzer,
            "ccpp.multi-ptr-member-resource-acquire-no-release-in-function",
        ),
    ],
)
def test_semgrep_checkers_use_location_lookup_before_full_function_scan(
    tmp_path: Path,
    module,
    checker_cls,
    check_id: str,
) -> None:
    project = tmp_path / "demo-project"
    (project / "src").mkdir(parents=True)
    reported_path = r"demo-project\src\a.c"
    payload = {
        "results": [
            {
                "path": reported_path,
                "start": {"line": 12},
                "check_id": check_id,
                "extra": {
                    "severity": "WARNING",
                    "message": "candidate without function metadata",
                    "metavars": {},
                    "lines": "target();",
                },
            }
        ]
    }

    class FakeDb:
        def __init__(self) -> None:
            self.location_paths: list[str] = []

        def get_function_by_location(self, file_path: str, line: int):
            self.location_paths.append(file_path)
            if file_path == "src/a.c" and line == 12:
                return {
                    "file_path": "src/a.c",
                    "start_line": 10,
                    "end_line": 20,
                    "name": "fast_func",
                }
            return None

        def get_all_functions(self):
            raise AssertionError("full function table scan should not be used")

    db = FakeDb()

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch.object(module, "run_semgrep", return_value=SemgrepRunResult(0, json.dumps(payload), "")),
    ):
        candidates = list(checker_cls().find_candidates(project, db=db))

    assert candidates
    assert candidates[0].function == "fast_func"
    assert "src/a.c" in db.location_paths
