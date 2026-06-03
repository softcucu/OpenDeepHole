import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from agent.config import (
    AgentConfig,
    apply_network_env,
    apply_remote_config,
    effective_fp_review_cli_config,
    load_config,
    remote_config_dict,
    save_config,
)


class AgentConfigTests(unittest.TestCase):
    def test_defaults_match_agent_template_values(self) -> None:
        cfg = AgentConfig()

        self.assertEqual(cfg.no_proxy, "10.0.0.0/8")
        self.assertEqual(cfg.llm_api.timeout, 300)
        self.assertFalse(cfg.llm_api.stream)
        self.assertEqual(cfg.opencode.tool, "opencode")
        self.assertEqual(cfg.opencode.timeout, 1200)
        self.assertEqual(cfg.opencode.max_retries, 2)
        self.assertIsNone(cfg.fp_review_cli)
        self.assertTrue(cfg.memory_api_discovery.enabled)
        self.assertEqual(cfg.memory_api_discovery.batch_size, 8)

    def test_apply_remote_config_overwrites_falsey_values(self) -> None:
        cfg = AgentConfig()
        cfg.no_proxy = "localhost"
        cfg.llm_api.stream = True
        cfg.opencode.max_retries = 5

        apply_remote_config(
            cfg,
            {
                "no_proxy": "",
                "llm_api": {"stream": False, "timeout": 300},
                "opencode": {"tool": "nga", "executable": "nga", "max_retries": 0, "timeout": 1200},
                "fp_review_cli": {
                    "tool": "claude",
                    "executable": "claude",
                    "model": "sonnet",
                    "timeout": 900,
                    "max_retries": 1,
                },
                "memory_api_discovery": {
                    "enabled": False,
                    "batch_size": 5,
                    "timeout_seconds": 120,
                    "max_candidates": 50,
                },
            },
        )

        self.assertEqual(cfg.no_proxy, "")
        self.assertFalse(cfg.llm_api.stream)
        self.assertEqual(cfg.llm_api.timeout, 300)
        self.assertEqual(cfg.opencode.max_retries, 0)
        self.assertEqual(cfg.opencode.timeout, 1200)
        self.assertEqual(cfg.opencode.tool, "nga")
        self.assertIsNotNone(cfg.fp_review_cli)
        self.assertEqual(cfg.fp_review_cli.tool, "claude")
        self.assertEqual(cfg.fp_review_cli.model, "sonnet")
        self.assertFalse(cfg.memory_api_discovery.enabled)
        self.assertEqual(cfg.memory_api_discovery.batch_size, 5)
        self.assertEqual(cfg.memory_api_discovery.timeout_seconds, 120)
        self.assertEqual(cfg.memory_api_discovery.max_candidates, 50)

    def test_remote_config_dict_exports_managed_fields(self) -> None:
        cfg = AgentConfig()
        cfg.llm_api.stream = True
        cfg.opencode.tool = "nga"
        cfg.opencode.executable = "nga"

        remote = remote_config_dict(cfg)

        self.assertEqual(remote["no_proxy"], "10.0.0.0/8")
        self.assertTrue(remote["llm_api"]["stream"])
        self.assertEqual(remote["llm_api"]["timeout"], 300)
        self.assertEqual(remote["opencode"]["executable"], "nga")
        self.assertEqual(remote["opencode"]["tool"], "nga")
        self.assertEqual(remote["opencode"]["timeout"], 1200)
        self.assertEqual(remote["opencode"]["max_retries"], 2)
        self.assertIsNone(remote["fp_review_cli"])
        self.assertEqual(remote["memory_api_discovery"]["batch_size"], 8)
        self.assertEqual(remote["memory_api_discovery"]["max_candidates"], 200)

    def test_save_config_persists_remote_managed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.yaml"
            path.write_text(
                yaml.dump(
                    {
                        "server_url": "http://example.test",
                        "agent_name": "local-agent",
                        "llm_api": {"stream": True, "timeout": 120},
                        "opencode": {"executable": "nga", "timeout": 300, "max_retries": 4},
                    }
                ),
                encoding="utf-8",
            )

            cfg = load_config(path)
            apply_remote_config(
                cfg,
                {
                    "no_proxy": "10.0.0.0/8",
                    "llm_api": {"stream": False, "timeout": 300},
                    "opencode": {"tool": "opencode", "executable": "opencode", "timeout": 1200, "max_retries": 2},
                    "fp_review_cli": {"tool": "claude", "executable": "claude", "timeout": 900},
                    "memory_api_discovery": {"enabled": True, "batch_size": 10, "timeout_seconds": 240},
                },
            )
            save_config(cfg)

            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["server_url"], "http://example.test")
            self.assertEqual(raw["agent_name"], "local-agent")
            self.assertEqual(raw["no_proxy"], "10.0.0.0/8")
            self.assertEqual(raw["llm_api"]["timeout"], 300)
            self.assertFalse(raw["llm_api"]["stream"])
            self.assertEqual(raw["opencode"]["tool"], "opencode")
            self.assertEqual(raw["opencode"]["timeout"], 1200)
            self.assertEqual(raw["opencode"]["max_retries"], 2)
            self.assertEqual(raw["fp_review_cli"]["tool"], "claude")
            self.assertEqual(raw["fp_review_cli"]["timeout"], 900)
            self.assertTrue(raw["memory_api_discovery"]["enabled"])
            self.assertEqual(raw["memory_api_discovery"]["batch_size"], 10)
            self.assertEqual(raw["memory_api_discovery"]["timeout_seconds"], 240)

    def test_legacy_executable_infers_tool_and_fp_review_inherits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.yaml"
            path.write_text(
                yaml.dump({"opencode": {"executable": "nga", "model": "audit-model"}}),
                encoding="utf-8",
            )

            cfg = load_config(path)

            self.assertEqual(cfg.opencode.tool, "nga")
            self.assertEqual(effective_fp_review_cli_config(cfg).model, "audit-model")

    def test_apply_network_env_clears_blank_no_proxy(self) -> None:
        cfg = AgentConfig(no_proxy="")

        with patch.dict("os.environ", {"no_proxy": "old", "NO_PROXY": "old"}, clear=False):
            apply_network_env(cfg)
            import os

            self.assertNotIn("no_proxy", os.environ)
            self.assertNotIn("NO_PROXY", os.environ)


if __name__ == "__main__":
    unittest.main()
