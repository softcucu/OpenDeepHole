import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from agent.config import AgentConfig, apply_network_env, apply_remote_config, load_config, remote_config_dict, save_config


class AgentConfigTests(unittest.TestCase):
    def test_defaults_match_agent_template_values(self) -> None:
        cfg = AgentConfig()

        self.assertEqual(cfg.no_proxy, "10.0.0.0/8")
        self.assertEqual(cfg.llm_api.timeout, 300)
        self.assertFalse(cfg.llm_api.stream)
        self.assertEqual(cfg.opencode.timeout, 1200)
        self.assertEqual(cfg.opencode.max_retries, 2)

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
                "opencode": {"max_retries": 0, "timeout": 1200},
            },
        )

        self.assertEqual(cfg.no_proxy, "")
        self.assertFalse(cfg.llm_api.stream)
        self.assertEqual(cfg.llm_api.timeout, 300)
        self.assertEqual(cfg.opencode.max_retries, 0)
        self.assertEqual(cfg.opencode.timeout, 1200)

    def test_remote_config_dict_exports_managed_fields(self) -> None:
        cfg = AgentConfig()
        cfg.llm_api.stream = True
        cfg.opencode.executable = "nga"

        remote = remote_config_dict(cfg)

        self.assertEqual(remote["no_proxy"], "10.0.0.0/8")
        self.assertTrue(remote["llm_api"]["stream"])
        self.assertEqual(remote["llm_api"]["timeout"], 300)
        self.assertEqual(remote["opencode"]["executable"], "nga")
        self.assertEqual(remote["opencode"]["timeout"], 1200)
        self.assertEqual(remote["opencode"]["max_retries"], 2)

    def test_save_config_persists_remote_managed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.yaml"
            path.write_text(
                yaml.dump(
                    {
                        "server_url": "http://example.test",
                        "agent_name": "local-agent",
                        "llm_api": {"stream": True, "timeout": 120},
                        "opencode": {"timeout": 300, "max_retries": 4},
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
                    "opencode": {"timeout": 1200, "max_retries": 2},
                },
            )
            save_config(cfg)

            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["server_url"], "http://example.test")
            self.assertEqual(raw["agent_name"], "local-agent")
            self.assertEqual(raw["no_proxy"], "10.0.0.0/8")
            self.assertEqual(raw["llm_api"]["timeout"], 300)
            self.assertFalse(raw["llm_api"]["stream"])
            self.assertEqual(raw["opencode"]["timeout"], 1200)
            self.assertEqual(raw["opencode"]["max_retries"], 2)

    def test_apply_network_env_clears_blank_no_proxy(self) -> None:
        cfg = AgentConfig(no_proxy="")

        with patch.dict("os.environ", {"no_proxy": "old", "NO_PROXY": "old"}, clear=False):
            apply_network_env(cfg)
            import os

            self.assertNotIn("no_proxy", os.environ)
            self.assertNotIn("NO_PROXY", os.environ)


if __name__ == "__main__":
    unittest.main()
