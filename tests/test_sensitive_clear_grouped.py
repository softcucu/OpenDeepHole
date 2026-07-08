import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.models import Candidate
from backend.opencode.submit_sink import record_submission
from backend.opencode.runner import _read_sensitive_clear_audit_result, _sensitive_clear_prompt
from checkers.sensitive_clear.analyzer import Analyzer


class _FakeDb:
    def __init__(self, functions):
        self._functions = functions

    def get_all_functions(self):
        return self._functions


def _func(name: str, idx: int, body: str) -> dict:
    return {
        "name": name,
        "body": body,
        "file_path": "src/demo.c",
        "start_line": idx * 10,
        "end_line": idx * 10 + body.count("\n"),
    }


def _candidate() -> Candidate:
    return Candidate(
        file="src/auth.c",
        line=20,
        function="login",
        description="function-level sensitive clear",
        vuln_type="sensitive_clear",
        metadata={
            "kind": "sensitive_clear_function",
            "candidate_id": "sensitive-clear-src/auth.c:20:login",
            "function_name": "login",
            "file": "src/auth.c",
            "start_line": 20,
            "end_line": 42,
            "suspicious_variables": [
                {
                    "name": "password",
                    "kind": "local",
                    "line": 22,
                    "type": "char *",
                    "declaration": "char *password = input;",
                    "matches": ["password"],
                }
            ],
        },
    )


MARKDOWN_ANALYSIS = """## 变量包含什么敏感信息

- `password` 保存认证口令。

## 生命周期在哪里结束

- 函数返回前生命周期结束。

## 生命周期结束后是否显式清零

- 未发现清零调用。

## 是否有类似变量做了清零

- 未发现。

## 结论

- confirmed=true，因为口令缓冲区返回前未清零。
"""


class SensitiveClearFunctionTests(unittest.TestCase):
    def test_analyzer_emits_one_candidate_per_function_with_sensitive_heuristic_hits(self) -> None:
        functions = [
            _func(
                "login",
                1,
                "void login(char *input) {\n  char *password = input;\n  int status = 0;\n}\n",
            ),
            _func(
                "status_only",
                2,
                "void status_only(int code) {\n  int status = code;\n}\n",
            ),
            _func(
                "derive",
                3,
                "void derive(unsigned char *seed) {\n  unsigned char session_key[32];\n}\n",
            ),
        ]

        candidates = Analyzer().find_candidates(Path("."), db=_FakeDb(functions))

        self.assertEqual([candidate.function for candidate in candidates], ["login", "derive"])
        self.assertEqual(candidates[0].metadata["kind"], "sensitive_clear_function")
        self.assertEqual(candidates[0].metadata["suspicious_variables"][0]["name"], "password")
        self.assertEqual(candidates[0].metadata["subject"], "password")
        self.assertEqual(candidates[0].metadata["problem"], "敏感信息未清零")
        self.assertEqual(candidates[1].metadata["suspicious_variables"][0]["name"], "seed")
        self.assertIn("password", candidates[0].description)
        self.assertIn("seed", candidates[1].description)
        self.assertNotIn("char *password", candidates[0].description)
        self.assertNotIn("unsigned char session_key", candidates[1].description)

    def test_sensitive_clear_prompt_only_exposes_function_name_not_variable_names(self) -> None:
        prompt = _sensitive_clear_prompt(
            "sensitive-variable-clear-check",
            _candidate(),
            "project-1",
        )

        self.assertIn("`src/auth.c` 文件中的 `login` 函数敏感信息未清0问题", prompt)
        self.assertIn("project_id: `project-1`", prompt)
        self.assertNotIn("result_id", prompt)
        self.assertNotIn("初始提示词只提供函数名", prompt)
        self.assertNotIn("Markdown", prompt)
        self.assertNotIn("password", prompt)
        self.assertNotIn("char *password", prompt)
        self.assertNotIn("变量清单", prompt)

    def test_sensitive_clear_result_stores_markdown_in_vulnerability_entry_only(self) -> None:
        candidate = _candidate()
        with tempfile.TemporaryDirectory() as tmp:
            session_id = "session-sensitive"
            payload = {
                "confirmed": True,
                "severity": "high",
                "description": "login leaves password uncleared",
                "file": "src/auth.c",
                "line": 25,
                "function": "login",
                "ai_analysis": MARKDOWN_ANALYSIS,
            }

            fake_config = SimpleNamespace(storage=SimpleNamespace(scans_dir=tmp))
            with patch("backend.opencode.submit_sink.get_config", return_value=fake_config):
                record_submission(session_id, "submit_result", payload)
                result = _read_sensitive_clear_audit_result(session_id, candidate)

        self.assertIsNotNone(result)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].file, "src/auth.c")
        self.assertEqual(result.vulnerabilities[0].line, 25)
        self.assertEqual(result.vulnerabilities[0].function, "login")
        self.assertEqual(result.vulnerabilities[0].ai_analysis, MARKDOWN_ANALYSIS.strip())
        self.assertEqual(result.reports, [])

    def test_sensitive_clear_result_accepts_single_false_markdown_result(self) -> None:
        candidate = _candidate()
        with tempfile.TemporaryDirectory() as tmp:
            session_id = "session-sensitive"
            payload = {
                "confirmed": False,
                "severity": "low",
                "description": "login clears all sensitive data",
                "ai_analysis": MARKDOWN_ANALYSIS.replace("confirmed=true", "confirmed=false"),
            }

            fake_config = SimpleNamespace(storage=SimpleNamespace(scans_dir=tmp))
            with patch("backend.opencode.submit_sink.get_config", return_value=fake_config):
                record_submission(session_id, "submit_result", payload)
                result = _read_sensitive_clear_audit_result(session_id, candidate)

        self.assertIsNotNone(result)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertFalse(result.vulnerabilities[0].confirmed)
        self.assertEqual(result.vulnerabilities[0].ai_verdict, "not_confirmed")
        self.assertIn("confirmed=false", result.vulnerabilities[0].ai_analysis)
        self.assertEqual(result.reports, [])

    def test_sensitive_clear_result_rejects_multiple_submit_results(self) -> None:
        candidate = _candidate()
        with tempfile.TemporaryDirectory() as tmp:
            session_id = "session-sensitive"

            fake_config = SimpleNamespace(storage=SimpleNamespace(scans_dir=tmp))
            with patch("backend.opencode.submit_sink.get_config", return_value=fake_config):
                record_submission(session_id, "submit_result", {
                    "confirmed": False,
                    "severity": "low",
                    "description": "first",
                    "ai_analysis": MARKDOWN_ANALYSIS,
                })
                record_submission(session_id, "submit_result", {
                    "confirmed": False,
                    "severity": "low",
                    "description": "second",
                    "ai_analysis": MARKDOWN_ANALYSIS,
                })
                result = _read_sensitive_clear_audit_result(session_id, candidate)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
