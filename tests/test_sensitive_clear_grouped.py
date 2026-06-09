import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.models import Candidate
from backend.opencode.runner import _read_sensitive_clear_audit_result
from checkers.sensitive_clear.analyzer import Analyzer


class _FakeDb:
    def __init__(self, functions):
        self._functions = functions

    def get_all_functions(self):
        return self._functions


def _func(name: str, idx: int, body: str | None = None, line_count: int = 3) -> dict:
    body = body or f"void {name}(int arg{idx}) {{\n  int local{idx} = arg{idx};\n}}\n"
    return {
        "name": name,
        "body": body,
        "file_path": "src/demo.c",
        "start_line": idx * 10,
        "end_line": idx * 10 + line_count - 1,
    }


class SensitiveClearGroupedTests(unittest.TestCase):
    def test_analyzer_groups_functions_and_keeps_all_variables(self) -> None:
        functions = [_func(f"fn{i}", i) for i in range(1, 22)]

        candidates = Analyzer().find_candidates(Path("."), db=_FakeDb(functions))

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].function, "__project__")
        self.assertEqual(candidates[0].metadata["kind"], "sensitive_clear_group")
        self.assertEqual(len(candidates[0].metadata["functions"]), 20)
        pair_names = {
            (pair["function_name"], pair["variable_name"])
            for pair in candidates[0].metadata["pairs"]
        }
        self.assertIn(("fn1", "arg1"), pair_names)
        self.assertIn(("fn1", "local1"), pair_names)
        self.assertIn(("fn20", "arg20"), pair_names)
        self.assertIn(("fn20", "local20"), pair_names)
        self.assertNotIn("void fn1", candidates[0].description)

    def test_analyzer_splits_very_long_function(self) -> None:
        functions = [
            _func("small1", 1),
            _func("small2", 2),
            _func("huge", 3, body="void huge() {\n  int secret;\n}\n", line_count=1300),
            _func("small3", 4),
        ]

        candidates = Analyzer().find_candidates(Path("."), db=_FakeDb(functions))

        self.assertGreaterEqual(len(candidates), 3)
        huge_groups = [
            candidate for candidate in candidates
            if any(func["function_name"] == "huge" for func in candidate.metadata["functions"])
        ]
        self.assertEqual(len(huge_groups), 1)
        self.assertEqual(len(huge_groups[0].metadata["functions"]), 1)

    def test_sensitive_clear_result_requires_all_pairs_and_expands_only_confirmed(self) -> None:
        candidate = Candidate(
            file="src/demo.c",
            line=10,
            function="__project__",
            description="grouped sensitive clear",
            vuln_type="sensitive_clear",
            metadata={
                "kind": "sensitive_clear_group",
                "group_id": "sensitive-clear-group-0001",
                "pairs": [
                    {
                        "pair_id": "p1",
                        "function_name": "login",
                        "variable_name": "password",
                        "file": "src/auth.c",
                        "function_start_line": 20,
                    },
                    {
                        "pair_id": "p2",
                        "function_name": "login",
                        "variable_name": "status",
                        "file": "src/auth.c",
                        "function_start_line": 20,
                    },
                ],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            result_id = "result-sensitive"
            Path(tmp, f"{result_id}.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "confirmed": True,
                                "severity": "high",
                                "description": "password is not cleared",
                                "file": "src/auth.c",
                                "line": 25,
                                "function": "login",
                                "ai_analysis": json.dumps(
                                    {
                                        "pair_id": "p1",
                                        "function_name": "login",
                                        "variable_name": "password",
                                        "is_sensitive": True,
                                        "cleared_after_last_use": False,
                                        "confirmed": True,
                                        "evidence": "password receives credential data",
                                        "reason": "no clear after use",
                                    }
                                ),
                            },
                            {
                                "confirmed": False,
                                "severity": "low",
                                "description": "status is not sensitive",
                                "ai_analysis": json.dumps(
                                    {
                                        "pair_id": "p2",
                                        "function_name": "login",
                                        "variable_name": "status",
                                        "is_sensitive": False,
                                        "cleared_after_last_use": False,
                                        "confirmed": False,
                                        "evidence": "status is an integer state",
                                        "reason": "not sensitive",
                                    }
                                ),
                            },
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            fake_config = SimpleNamespace(storage=SimpleNamespace(scans_dir=tmp))
            with patch("backend.opencode.runner.get_config", return_value=fake_config):
                result = _read_sensitive_clear_audit_result(result_id, candidate)

        self.assertIsNotNone(result)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].file, "src/auth.c")
        self.assertEqual(result.vulnerabilities[0].line, 25)
        self.assertEqual(result.vulnerabilities[0].function, "login")
        self.assertEqual(len(result.reports), 1)
        report_data = json.loads(result.reports[0]["content"])
        self.assertEqual(report_data["total_pairs"], 2)
        self.assertEqual(report_data["confirmed_count"], 1)

    def test_sensitive_clear_result_rejects_missing_pair(self) -> None:
        candidate = Candidate(
            file="src/demo.c",
            line=10,
            function="__project__",
            description="grouped sensitive clear",
            vuln_type="sensitive_clear",
            metadata={
                "kind": "sensitive_clear_group",
                "group_id": "sensitive-clear-group-0001",
                "pairs": [
                    {"pair_id": "p1", "function_name": "a", "variable_name": "x"},
                    {"pair_id": "p2", "function_name": "b", "variable_name": "y"},
                ],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            result_id = "result-sensitive"
            Path(tmp, f"{result_id}.json").write_text(
                json.dumps(
                    {
                        "confirmed": False,
                        "severity": "low",
                        "description": "only one result",
                        "ai_analysis": json.dumps(
                            {
                                "pair_id": "p1",
                                "function_name": "a",
                                "variable_name": "x",
                                "is_sensitive": False,
                                "cleared_after_last_use": False,
                                "confirmed": False,
                                "evidence": "",
                                "reason": "not sensitive",
                            }
                        ),
                    }
                ),
                encoding="utf-8",
            )
            fake_config = SimpleNamespace(storage=SimpleNamespace(scans_dir=tmp))
            with patch("backend.opencode.runner.get_config", return_value=fake_config):
                result = _read_sensitive_clear_audit_result(result_id, candidate)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
