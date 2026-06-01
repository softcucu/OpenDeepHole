import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from agent.config import AgentConfig
from agent.scanner import _configure_backend
from backend.models import Candidate
from backend.opencode.runner import _read_result, _read_results


class AgentResultPathTests(unittest.TestCase):
    def test_agent_backend_config_uses_scan_dir_for_results(self) -> None:
        old_config_path = os.environ.get("CONFIG_PATH")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                scan_dir = Path(tmp) / "scans" / "scan-123"
                scan_dir.mkdir(parents=True)

                _configure_backend(AgentConfig(), scan_dir)

                raw = yaml.safe_load((scan_dir / "config.yaml").read_text(encoding="utf-8"))
                self.assertEqual(raw["storage"]["scans_dir"], str(scan_dir))
                self.assertEqual(raw["storage"]["projects_dir"], str(scan_dir.parent))
        finally:
            if old_config_path is None:
                os.environ.pop("CONFIG_PATH", None)
            else:
                os.environ["CONFIG_PATH"] = old_config_path

            import backend.config as _cfg
            _cfg._config = None

            import backend.registry as _reg
            _reg._registry = None

    def test_read_result_uses_configured_scans_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scans_dir = Path(tmp) / "scan-123"
            scans_dir.mkdir()
            result_id = "result-test"
            (scans_dir / f"{result_id}.json").write_text(
                json.dumps({
                    "confirmed": True,
                    "severity": "high",
                    "description": "confirmed issue",
                    "ai_analysis": "analysis text",
                }),
                encoding="utf-8",
            )

            candidate = Candidate(
                file="test.c",
                line=42,
                function="demo",
                description="candidate issue",
                vuln_type="npd",
            )

            fake_config = SimpleNamespace(
                storage=SimpleNamespace(scans_dir=str(scans_dir))
            )
            with patch("backend.opencode.runner.get_config", return_value=fake_config):
                result = _read_result(result_id, candidate)

            self.assertIsNotNone(result)
            self.assertEqual(result.file, "test.c")
            self.assertEqual(result.line, 42)
            self.assertTrue(result.confirmed)
            self.assertEqual(result.ai_verdict, "confirmed")

    def test_read_results_accepts_project_level_multiple_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scans_dir = Path(tmp) / "scan-123"
            scans_dir.mkdir()
            result_id = "result-project"
            (scans_dir / f"{result_id}.json").write_text(
                json.dumps({
                    "results": [
                        {
                            "confirmed": True,
                            "severity": "high",
                            "description": "first issue",
                            "ai_analysis": "analysis one",
                            "file": "src/a.c",
                            "line": 10,
                            "function": "a",
                        },
                        {
                            "confirmed": False,
                            "severity": "low",
                            "description": "no issue",
                            "ai_analysis": "analysis two",
                            "file": ".",
                            "line": 1,
                            "function": "__project__",
                        },
                    ]
                }),
                encoding="utf-8",
            )
            candidate = Candidate(
                file=".",
                line=1,
                function="__project__",
                description="project audit",
                vuln_type="auth_bypass",
            )
            fake_config = SimpleNamespace(
                storage=SimpleNamespace(scans_dir=str(scans_dir))
            )

            with patch("backend.opencode.runner.get_config", return_value=fake_config):
                results = _read_results(result_id, candidate)

            self.assertEqual(len(results), 2)
            self.assertEqual(results[0].file, "src/a.c")
            self.assertEqual(results[0].line, 10)
            self.assertEqual(results[0].function, "a")
            self.assertTrue(results[0].confirmed)
            self.assertEqual(results[1].file, ".")
            self.assertFalse(results[1].confirmed)


if __name__ == "__main__":
    unittest.main()
