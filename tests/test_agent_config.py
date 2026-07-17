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
from backend.config import GitHistoryConfig as BackendGitHistoryConfig
from backend.models import AgentRemoteConfig


class AgentConfigTests(unittest.TestCase):
    def test_defaults_match_agent_template_values(self) -> None:
        cfg = AgentConfig()

        self.assertEqual(cfg.no_proxy, "10.0.0.0/8")
        self.assertEqual(cfg.opencode.tool, "nga")
        self.assertEqual(cfg.opencode.executable, "nga")
        self.assertEqual(cfg.opencode.timeout, 1200)
        self.assertEqual(cfg.opencode.max_retries, 2)
        self.assertEqual(cfg.opencode.config_paths, [])
        self.assertEqual(cfg.opencode.proxy_url, "")
        self.assertEqual(cfg.opencode.no_proxy, "")
        self.assertIsNone(cfg.fp_review_cli)
        self.assertTrue(cfg.memory_api_discovery.enabled)
        self.assertEqual(cfg.memory_api_discovery.batch_size, 8)
        self.assertFalse(cfg.git_history.enabled)
        self.assertEqual(cfg.git_history.max_commits, 200)
        self.assertTrue(cfg.git_history.variant_hunt)
        self.assertTrue(cfg.threat_analysis.enabled)
        self.assertEqual(cfg.threat_analysis.implementation, "attack_tree")
        self.assertEqual(cfg.threat_analysis.attack_path_audit_mode, "after_analysis")
        self.assertTrue(cfg.static_dedup)
        self.assertTrue(cfg.pattern_filter.enabled)
        self.assertEqual(cfg.pattern_filter.scope, "directory")
        self.assertTrue(cfg.vulnerability_validation.enabled)
        self.assertEqual(cfg.vulnerability_validation.timeout_seconds, 7200)
        self.assertEqual(cfg.opencode_concurrency, 4)

    def test_backend_and_remote_git_history_defaults_are_disabled(self) -> None:
        self.assertFalse(BackendGitHistoryConfig().enabled)
        self.assertFalse(AgentRemoteConfig().git_history.enabled)
        self.assertEqual(AgentRemoteConfig().opencode.tool, "nga")
        self.assertEqual(AgentRemoteConfig().opencode.executable, "nga")
        self.assertEqual(AgentRemoteConfig().opencode.config_paths, [])
        self.assertEqual(AgentRemoteConfig().opencode.proxy_url, "")
        self.assertEqual(AgentRemoteConfig().opencode.no_proxy, "")
        self.assertEqual(AgentRemoteConfig().opencode_concurrency, 4)
        self.assertTrue(AgentRemoteConfig().threat_analysis.enabled)
        self.assertEqual(AgentRemoteConfig().threat_analysis.implementation, "attack_tree")
        self.assertEqual(AgentRemoteConfig().threat_analysis.attack_path_audit_mode, "after_analysis")

    def test_full_remote_defaults_do_not_switch_agent_to_opencode(self) -> None:
        cfg = AgentConfig()
        cfg.opencode.tool = "nga"
        cfg.opencode.executable = "nga"

        apply_remote_config(cfg, AgentRemoteConfig().model_dump())

        self.assertEqual(cfg.opencode.tool, "nga")
        self.assertEqual(cfg.opencode.executable, "nga")

    def test_apply_remote_config_overwrites_falsey_values(self) -> None:
        cfg = AgentConfig()
        cfg.no_proxy = "localhost"
        cfg.opencode.max_retries = 5
        cfg.git_history.enabled = True

        apply_remote_config(
            cfg,
            {
                "no_proxy": "",
                "opencode": {
                    "tool": "nga",
                    "executable": "nga",
                    "max_retries": 0,
                    "timeout": 1200,
                    "config_paths": ["/opt/opencode/config.json"],
                    "proxy_url": "http://127.0.0.1:3131",
                    "no_proxy": "corp.local,127.0.0.1",
                },
                "fp_review_cli": {
                    "tool": "opencode",
                    "executable": "opencode",
                    "model": "sonnet",
                    "timeout": 900,
                    "max_retries": 1,
                    "config_paths": ["/opt/opencode/fp.json"],
                    "proxy_url": "http://127.0.0.1:3132",
                    "no_proxy": "fp.local,127.0.0.1",
                },
                "memory_api_discovery": {
                    "enabled": False,
                    "batch_size": 5,
                    "timeout_seconds": 120,
                    "max_candidates": 50,
                },
                "git_history": {
                    "enabled": False,
                    "max_commits": 0,
                    "since": "6 months ago",
                    "paths": "src tests",
                    "variant_hunt": False,
                },
                "threat_analysis": {
                    "enabled": False,
                    "implementation": "custom_impl",
                    "attack_path_audit_mode": "immediate",
                },
                "static_dedup": False,
                "pattern_filter": {"enabled": False, "scope": "repo"},
                "vulnerability_validation": {
                    "enabled": False,
                    "timeout_seconds": 90,
                },
            },
        )

        self.assertEqual(cfg.no_proxy, "")
        self.assertEqual(cfg.opencode.max_retries, 0)
        self.assertEqual(cfg.opencode.timeout, 1200)
        self.assertEqual(cfg.opencode.tool, "nga")
        self.assertEqual(cfg.opencode.config_paths, ["/opt/opencode/config.json"])
        self.assertEqual(cfg.opencode.proxy_url, "http://127.0.0.1:3131")
        self.assertEqual(cfg.opencode.no_proxy, "corp.local,127.0.0.1")
        self.assertIsNotNone(cfg.fp_review_cli)
        self.assertEqual(cfg.fp_review_cli.tool, "opencode")
        self.assertEqual(cfg.fp_review_cli.model, "sonnet")
        self.assertEqual(cfg.fp_review_cli.config_paths, ["/opt/opencode/fp.json"])
        self.assertEqual(cfg.fp_review_cli.proxy_url, "http://127.0.0.1:3132")
        self.assertEqual(cfg.fp_review_cli.no_proxy, "fp.local,127.0.0.1")
        self.assertFalse(cfg.memory_api_discovery.enabled)
        self.assertEqual(cfg.memory_api_discovery.batch_size, 5)
        self.assertEqual(cfg.memory_api_discovery.timeout_seconds, 120)
        self.assertEqual(cfg.memory_api_discovery.max_candidates, 50)
        self.assertFalse(cfg.git_history.enabled)
        self.assertEqual(cfg.git_history.max_commits, 0)
        self.assertEqual(cfg.git_history.since, "6 months ago")
        self.assertEqual(cfg.git_history.paths, "src tests")
        self.assertFalse(cfg.git_history.variant_hunt)
        self.assertFalse(cfg.threat_analysis.enabled)
        self.assertEqual(cfg.threat_analysis.implementation, "custom_impl")
        self.assertEqual(cfg.threat_analysis.attack_path_audit_mode, "immediate")
        self.assertFalse(cfg.static_dedup)
        self.assertFalse(cfg.pattern_filter.enabled)
        self.assertEqual(cfg.pattern_filter.scope, "repo")
        self.assertFalse(cfg.vulnerability_validation.enabled)
        self.assertEqual(cfg.vulnerability_validation.timeout_seconds, 90)

    def test_remote_config_dict_exports_managed_fields(self) -> None:
        cfg = AgentConfig()
        cfg.opencode.tool = "nga"
        cfg.opencode.executable = "nga"

        remote = remote_config_dict(cfg)

        self.assertEqual(remote["no_proxy"], "10.0.0.0/8")
        self.assertNotIn("llm_api", remote)
        self.assertEqual(remote["opencode"]["executable"], "nga")
        self.assertEqual(remote["opencode"]["tool"], "nga")
        self.assertEqual(remote["opencode"]["timeout"], 1200)
        self.assertEqual(remote["opencode"]["max_retries"], 2)
        self.assertEqual(remote["opencode_concurrency"], 4)
        self.assertEqual(remote["opencode"]["models"], [])
        self.assertEqual(remote["opencode"]["config_paths"], [])
        self.assertEqual(remote["opencode"]["proxy_url"], "")
        self.assertEqual(remote["opencode"]["no_proxy"], "")
        self.assertIsNone(remote["fp_review_cli"])
        self.assertEqual(remote["memory_api_discovery"]["batch_size"], 8)
        self.assertEqual(remote["memory_api_discovery"]["max_candidates"], 200)
        self.assertEqual(
            remote["git_history"],
            {"enabled": False, "max_commits": 200, "since": "", "paths": "", "variant_hunt": True},
        )
        self.assertEqual(
            remote["threat_analysis"],
            {
                "enabled": True,
                "implementation": "attack_tree",
                "attack_path_audit_mode": "after_analysis",
                "product_mcp_name": "product-info",
                "product_mcp_detection_timeout_seconds": 60,
            },
        )
        self.assertTrue(remote["static_dedup"])
        self.assertEqual(remote["pattern_filter"], {"enabled": True, "scope": "directory"})
        self.assertEqual(
            remote["vulnerability_validation"],
            {"enabled": True, "timeout_seconds": 7200},
        )

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
                    "opencode": {
                        "tool": "opencode",
                        "executable": "opencode",
                        "timeout": 1200,
                        "max_retries": 2,
                        "config_paths": ["/opt/opencode/config.json"],
                        "proxy_url": "http://127.0.0.1:3131",
                        "no_proxy": "corp.local,127.0.0.1",
                    },
                    "fp_review_cli": {
                        "tool": "opencode",
                        "executable": "opencode",
                        "timeout": 900,
                        "config_paths": ["/opt/opencode/fp.json"],
                        "proxy_url": "http://127.0.0.1:3132",
                        "no_proxy": "fp.local,127.0.0.1",
                    },
                    "memory_api_discovery": {"enabled": True, "batch_size": 10, "timeout_seconds": 240},
                    "git_history": {
                        "enabled": True,
                        "max_commits": 12,
                        "since": "1 year ago",
                        "paths": "src",
                        "variant_hunt": False,
                    },
                    "threat_analysis": {
                        "enabled": False,
                        "implementation": "custom_impl",
                        "attack_path_audit_mode": "immediate",
                    },
                    "static_dedup": False,
                    "pattern_filter": {"enabled": False, "scope": "file"},
                    "vulnerability_validation": {"enabled": True, "timeout_seconds": 600},
                },
            )
            save_config(cfg)

            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["server_url"], "http://example.test")
            self.assertEqual(raw["agent_name"], "local-agent")
            self.assertEqual(raw["no_proxy"], "10.0.0.0/8")
            self.assertNotIn("llm_api", raw)
            self.assertEqual(raw["opencode"]["tool"], "opencode")
            self.assertEqual(raw["opencode"]["timeout"], 1200)
            self.assertEqual(raw["opencode"]["max_retries"], 2)
            self.assertEqual(raw["opencode"]["models"], [])
            self.assertEqual(raw["opencode"]["config_paths"], ["/opt/opencode/config.json"])
            self.assertEqual(raw["opencode"]["proxy_url"], "http://127.0.0.1:3131")
            self.assertEqual(raw["opencode"]["no_proxy"], "corp.local,127.0.0.1")
            self.assertEqual(raw["opencode_concurrency"], 4)
            self.assertEqual(raw["fp_review_cli"]["tool"], "opencode")
            self.assertEqual(raw["fp_review_cli"]["timeout"], 900)
            self.assertEqual(raw["fp_review_cli"]["config_paths"], ["/opt/opencode/fp.json"])
            self.assertEqual(raw["fp_review_cli"]["proxy_url"], "http://127.0.0.1:3132")
            self.assertEqual(raw["fp_review_cli"]["no_proxy"], "fp.local,127.0.0.1")
            self.assertTrue(raw["memory_api_discovery"]["enabled"])
            self.assertEqual(raw["memory_api_discovery"]["batch_size"], 10)
            self.assertEqual(raw["memory_api_discovery"]["timeout_seconds"], 240)
            self.assertEqual(
                raw["git_history"],
                {
                    "enabled": True,
                    "max_commits": 12,
                    "paths": "src",
                    "since": "1 year ago",
                    "variant_hunt": False,
                },
            )
            self.assertEqual(
                raw["threat_analysis"],
                {
                    "enabled": False,
                    "implementation": "custom_impl",
                    "attack_path_audit_mode": "immediate",
                    "product_mcp_name": "product-info",
                    "product_mcp_detection_timeout_seconds": 60,
                },
            )
            self.assertFalse(raw["static_dedup"])
            self.assertEqual(raw["pattern_filter"], {"enabled": False, "scope": "file"})
            self.assertNotIn("script_path", raw["vulnerability_validation"])
            self.assertNotIn("command", raw["vulnerability_validation"])
            self.assertEqual(raw["vulnerability_validation"]["timeout_seconds"], 600)

    def test_invalid_pattern_filter_scope_falls_back_to_directory(self) -> None:
        cfg = AgentConfig()

        apply_remote_config(
            cfg,
            {
                "pattern_filter": {"enabled": "false", "scope": "invalid"},
                "threat_analysis": {"attack_path_audit_mode": "invalid"},
            },
        )

        self.assertFalse(cfg.pattern_filter.enabled)
        self.assertEqual(cfg.pattern_filter.scope, "directory")
        self.assertEqual(cfg.threat_analysis.attack_path_audit_mode, "after_analysis")

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

    def test_load_config_defaults_git_history_off_and_allows_explicit_enable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.yaml"
            path.write_text("opencode: {}\n", encoding="utf-8")

            cfg = load_config(path)

            self.assertFalse(cfg.git_history.enabled)

            path.write_text(
                yaml.dump({"git_history": {"enabled": "true", "max_commits": "3", "variant_hunt": "false"}}),
                encoding="utf-8",
            )

            cfg = load_config(path)

            self.assertTrue(cfg.git_history.enabled)
            self.assertEqual(cfg.git_history.max_commits, 3)
            self.assertFalse(cfg.git_history.variant_hunt)

    def test_apply_network_env_clears_blank_no_proxy(self) -> None:
        cfg = AgentConfig(no_proxy="")

        with patch.dict("os.environ", {"no_proxy": "old", "NO_PROXY": "old"}, clear=False):
            apply_network_env(cfg)
            import os

            self.assertNotIn("no_proxy", os.environ)
            self.assertNotIn("NO_PROXY", os.environ)

    def test_remote_config_round_trips_opencode_model_pool(self) -> None:
        cfg = AgentConfig()
        apply_remote_config(
            cfg,
            {
                "opencode_concurrency": 4,
                "opencode": {
                    "tool": "opencode",
                    "executable": "opencode",
                    "models": [
                        {
                            "id": "fast",
                            "model": "fast-model",
                            "use_default_model": True,
                            "capability": "low",
                            "weight": 3,
                            "max_concurrency": 2,
                            "enabled": True,
                            "time_windows": [{"start": "09:00", "end": "18:00"}],
                        },
                        {
                            "id": "deep",
                            "model": "deep-model",
                            "capability": "high",
                            "weight": 1,
                            "max_concurrency": 1,
                            "enabled": True,
                        },
                    ],
                },
                "fp_review_cli": {
                    "tool": "opencode",
                    "executable": "opencode",
                    "models": [
                        {
                            "id": "judge",
                            "model": "judge-model",
                            "capability": "high",
                        }
                    ],
                },
            },
        )

        self.assertEqual(cfg.opencode_concurrency, 4)
        self.assertEqual(cfg.opencode.models[0].id, "fast")
        self.assertEqual(cfg.opencode.models[0].model, "")
        self.assertTrue(cfg.opencode.models[0].use_default_model)
        self.assertEqual(cfg.opencode.models[0].capability, "low")
        self.assertEqual(cfg.opencode.models[0].weight, 3)
        self.assertEqual(cfg.opencode.models[0].time_windows, [{"start": "09:00", "end": "18:00"}])
        self.assertIsNotNone(cfg.fp_review_cli)
        self.assertEqual(cfg.fp_review_cli.models[0].id, "judge")

        remote = remote_config_dict(cfg)
        self.assertEqual(remote["opencode_concurrency"], 4)
        self.assertTrue(remote["opencode"]["models"][0]["use_default_model"])
        self.assertEqual(remote["opencode"]["models"][0]["time_windows"][0]["start"], "09:00")
        self.assertEqual(remote["opencode"]["models"][1]["model"], "deep-model")
        self.assertEqual(remote["fp_review_cli"]["models"][0]["capability"], "high")

    def test_load_config_normalizes_invalid_model_pool_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.yaml"
            path.write_text(
                yaml.dump(
                    {
                        "opencode_concurrency": "bad",
                        "opencode": {
                            "models": [
                                {
                                    "model": "m1",
                                    "capability": "unknown",
                                    "weight": 0,
                                    "max_concurrency": 0,
                                    "time_windows": "bad",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            cfg = load_config(path)

            self.assertEqual(cfg.opencode_concurrency, 4)
            self.assertEqual(cfg.opencode.models[0].id, "m1")
            self.assertEqual(cfg.opencode.models[0].capability, "high")
            self.assertEqual(cfg.opencode.models[0].weight, 1)
            self.assertEqual(cfg.opencode.models[0].max_concurrency, 1)
            self.assertEqual(cfg.opencode.models[0].time_windows, [])


if __name__ == "__main__":
    unittest.main()
