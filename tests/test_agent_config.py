import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from deephole_client.config import (
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
        self.assertEqual(cfg.opencode.config_jsonc, "{}")
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

    def test_backend_and_remote_v2_defaults(self) -> None:
        self.assertFalse(BackendGitHistoryConfig().enabled)
        self.assertEqual(AgentRemoteConfig().schema_version, 2)
        self.assertEqual(AgentRemoteConfig().opencode_config, "{}")
        self.assertEqual(AgentRemoteConfig().base.no_proxy, "10.0.0.0/8")
        self.assertEqual(AgentRemoteConfig().opencode.tool, "nga")
        self.assertEqual(AgentRemoteConfig().opencode.executable, "nga")
        self.assertEqual(AgentRemoteConfig().opencode.config_jsonc, "{}")
        self.assertEqual(AgentRemoteConfig().model_pool.models, [])
        self.assertEqual(AgentRemoteConfig().opencode_concurrency, 4)
        self.assertTrue(AgentRemoteConfig().threat_analysis.enabled)
        self.assertEqual(AgentRemoteConfig().threat_analysis.attack_path_audit_mode, "after_analysis")
        self.assertEqual(AgentRemoteConfig().threat_analysis.model_policy.max_retries, 3)

    def test_full_remote_defaults_do_not_switch_agent_to_opencode(self) -> None:
        cfg = AgentConfig()
        cfg.opencode.tool = "nga"
        cfg.opencode.executable = "nga"
        cfg.opencode.config_jsonc = '{\n  // kept verbatim\n  "model": "corp/model",\n}'

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

        self.assertEqual(remote["schema_version"], 2)
        self.assertEqual(remote["opencode_config"], cfg.opencode.config_jsonc)
        self.assertNotIn("llm_api", remote)
        self.assertEqual(remote["base"], {
            "tool": "nga",
            "executable": "nga",
            "no_proxy": "10.0.0.0/8",
        })
        self.assertEqual(remote["model_pool"], {"global_concurrency": 4, "models": []})
        self.assertEqual(
            remote["threat_analysis"],
            {
                "enabled": True,
                "attack_path_audit_mode": "after_analysis",
                "model_policy": {
                    "required_capability": "high",
                    "timeout_seconds": 1200,
                    "max_retries": 3,
                },
            },
        )
        self.assertEqual(remote["vulnerability_mining"]["required_capability"], "low")
        self.assertEqual(remote["false_positive"]["required_capability"], "high")
        self.assertEqual(remote["vulnerability_validation"], {"environments": {}})
        self.assertNotIn("git_history", remote)
        self.assertNotIn("pattern_filter", remote)

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
                    "schema_version": 2,
                    "opencode_config": '{\n  // managed on the Web\n  "model": "provider/model",\n}',
                    "base": {
                        "tool": "opencode",
                        "executable": "opencode",
                        "no_proxy": "10.0.0.0/8",
                    },
                    "model_pool": {
                        "global_concurrency": 3,
                        "models": [{
                            "id": "primary",
                            "model": "provider/model",
                            "capability": "high",
                            "max_concurrency": 2,
                        }],
                    },
                    "threat_analysis": {
                        "enabled": False,
                        "attack_path_audit_mode": "immediate",
                        "model_policy": {
                            "required_capability": "medium",
                            "timeout_seconds": 900,
                            "max_retries": 4,
                        },
                    },
                    "code_graph": {
                        "enabled": True,
                        "name": "codegraph",
                        "transport": "remote",
                        "timeout_seconds": 30,
                        "remote": {
                            "url": "http://graph.test/mcp",
                            "headers": {"Authorization": "Bearer test-secret-123"},
                        },
                    },
                    "vulnerability_mining": {
                        "required_capability": "any",
                        "timeout_seconds": 600,
                        "max_retries": 1,
                    },
                    "false_positive": {
                        "required_capability": "high",
                        "timeout_seconds": 700,
                        "max_retries": 2,
                    },
                    "vulnerability_validation": {
                        "environments": {
                            "lab": {
                                "supported_vulnerability_types": ["oob"],
                                "concurrency": 2,
                                "validation_max_retries": 1,
                                "model_policy": {
                                    "required_capability": "high",
                                    "timeout_seconds": 800,
                                    "max_retries": 3,
                                },
                                "methods": {"demo:LTE:lab": {"target_ip": "10.0.0.8"}},
                            },
                        },
                    },
                },
            )
            save_config(cfg)

            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["server_url"], "http://example.test")
            self.assertEqual(raw["agent_name"], "local-agent")
            self.assertEqual(raw["schema_version"], 2)
            self.assertEqual(
                raw["opencode_config"],
                '{\n  // managed on the Web\n  "model": "provider/model",\n}',
            )
            self.assertNotIn("llm_api", raw)
            self.assertEqual(raw["base"]["tool"], "opencode")
            self.assertEqual(raw["base"]["no_proxy"], "10.0.0.0/8")
            self.assertEqual(raw["model_pool"]["global_concurrency"], 3)
            self.assertEqual(raw["model_pool"]["models"][0]["model"], "provider/model")
            self.assertNotIn("use_default_model", raw["model_pool"]["models"][0])
            self.assertEqual(raw["threat_analysis"]["model_policy"]["max_retries"], 4)
            self.assertEqual(raw["threat_analysis"]["model_policy"]["required_capability"], "high")
            self.assertEqual(raw["code_graph"]["remote"]["url"], "http://graph.test/mcp")
            self.assertEqual(
                raw["code_graph"]["remote"]["headers"]["Authorization"],
                "Bearer test-secret-123",
            )
            self.assertEqual(raw["vulnerability_mining"]["timeout_seconds"], 600)
            self.assertEqual(raw["vulnerability_mining"]["required_capability"], "low")
            self.assertEqual(raw["false_positive"]["timeout_seconds"], 700)
            self.assertEqual(raw["vulnerability_validation"]["environments"]["lab"]["concurrency"], 2)
            self.assertEqual(
                raw["vulnerability_validation"]["environments"]["lab"]["methods"]
                ["demo:LTE:lab"]["target_ip"],
                "10.0.0.8",
            )
            for legacy_key in (
                "no_proxy", "opencode", "opencode_concurrency", "fp_review_cli",
                "memory_api_discovery", "git_history", "static_dedup", "pattern_filter",
            ):
                self.assertNotIn(legacy_key, raw)

            reloaded = load_config(path)
            self.assertEqual(reloaded.opencode.config_jsonc, raw["opencode_config"])

    def test_remote_opencode_jsonc_is_validated_and_applied(self) -> None:
        from fastapi import HTTPException

        from backend.api.agent import _validate_managed_config

        config = AgentRemoteConfig(opencode_config='{"model": "corp/model", // comment\n}')
        agent_config = AgentConfig()

        apply_remote_config(agent_config, config.model_dump(mode="json"))

        self.assertEqual(agent_config.opencode.config_jsonc, config.opencode_config)
        with self.assertRaisesRegex(HTTPException, "JSONC 格式错误"):
            _validate_managed_config(AgentRemoteConfig(opencode_config='{"model": }'))

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
                            "time_windows": [{"weekdays": [1, 3, 5], "start": "09:00", "end": "18:00"}],
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
        self.assertEqual(cfg.opencode.models[0].time_windows, [{
            "weekdays": [1, 3, 5],
            "start": "09:00",
            "end": "18:00",
        }])
        self.assertIsNotNone(cfg.fp_review_cli)
        self.assertEqual(cfg.fp_review_cli.models[0].id, "judge")

        remote = remote_config_dict(cfg)
        self.assertEqual(remote["model_pool"]["global_concurrency"], 4)
        self.assertFalse(remote["model_pool"]["models"][0]["enabled"])
        self.assertNotIn("use_default_model", remote["model_pool"]["models"][0])
        self.assertEqual(remote["model_pool"]["models"][0]["time_windows"][0]["weekdays"], [1, 3, 5])
        self.assertEqual(remote["model_pool"]["models"][0]["time_windows"][0]["start"], "09:00")
        self.assertEqual(remote["model_pool"]["models"][1]["model"], "deep-model")
        self.assertEqual(remote["model_pool"]["models"][2]["capability"], "high")
        self.assertEqual(remote["model_pool"]["models"][2]["id"], "judge")

    def test_legacy_time_window_without_weekdays_defaults_to_every_day(self) -> None:
        config = AgentRemoteConfig.model_validate({
            "schema_version": 2,
            "model_pool": {
                "global_concurrency": 1,
                "models": [{
                    "id": "legacy",
                    "model": "provider/model",
                    "time_windows": [{"start": "09:00", "end": "18:00"}],
                }],
            },
        })

        window = config.model_pool.models[0].time_windows[0]
        self.assertEqual(window.weekdays, [1, 2, 3, 4, 5, 6, 7])

        agent_config = AgentConfig()
        apply_remote_config(agent_config, config.model_dump(mode="json"))
        self.assertEqual(
            agent_config.opencode.models[0].time_windows[0]["weekdays"],
            [1, 2, 3, 4, 5, 6, 7],
        )

    def test_managed_config_rejects_invalid_time_windows(self) -> None:
        from fastapi import HTTPException

        from backend.api.agent import _validate_managed_config

        invalid_windows = [
            ({"weekdays": [], "start": "09:00", "end": "18:00"}, "至少要选择一天"),
            ({"weekdays": [0], "start": "09:00", "end": "18:00"}, "星期配置"),
            ({"weekdays": [1, 1], "start": "09:00", "end": "18:00"}, "星期配置"),
            ({"weekdays": [1], "start": "25:00", "end": "18:00"}, "必须为 HH:MM-HH:MM"),
            ({"weekdays": [1], "start": "09:00", "end": "09:00"}, "起止时间不能相同"),
        ]
        for window, error_text in invalid_windows:
            with self.subTest(window=window):
                config = AgentRemoteConfig.model_validate({
                    "schema_version": 2,
                    "base": {"tool": "nga", "executable": "nga", "no_proxy": ""},
                    "model_pool": {
                        "models": [{
                            "id": "scheduled",
                            "model": "provider/model",
                            "time_windows": [window],
                        }],
                    },
                })
                with self.assertRaisesRegex(HTTPException, error_text):
                    _validate_managed_config(config)

    def test_managed_config_accepts_bearer_authorization_header(self) -> None:
        from backend.api.agent import _validate_managed_config
        from deephole_client.opencode_integration import managed_mcp_config_fingerprint

        config = AgentRemoteConfig()
        config.product_info.enabled = True
        config.product_info.transport = "remote"
        config.product_info.remote.url = "http://product.test/mcp"
        config.product_info.remote.headers = {
            "Authorization": "Bearer test-secret-123",
        }

        _validate_managed_config(config)

        agent_config = AgentConfig()
        apply_remote_config(agent_config, config.model_dump(mode="json"))
        self.assertEqual(
            managed_mcp_config_fingerprint(config.product_info),
            managed_mcp_config_fingerprint(agent_config.product_info),
        )

    def test_managed_config_rejects_invalid_or_duplicate_header_names(self) -> None:
        from fastapi import HTTPException

        from backend.api.agent import _validate_managed_config

        for headers, error_text in (
            ({"Bad Header": "value"}, "请求头名称无效"),
            ({" Authorization ": "Bearer value"}, "请求头名称无效"),
            ({"Authorization": "a", "authorization": "b"}, "请求头名称重复"),
            ({"Authorization": "Bearer value\r\ninjected: true"}, "不能包含换行"),
        ):
            with self.subTest(headers=headers):
                config = AgentRemoteConfig()
                config.product_info.remote.headers = headers
                with self.assertRaisesRegex(HTTPException, error_text):
                    _validate_managed_config(config)

    def test_legacy_remote_payload_migrates_to_v2_and_disables_default_model(self) -> None:
        config = AgentRemoteConfig.model_validate({
            "no_proxy": "localhost",
            "opencode_concurrency": 2,
            "opencode": {
                "tool": "opencode",
                "executable": "opencode",
                "config_jsonc": '{"model": "legacy/model"}',
                "models": [
                    {"id": "default", "use_default_model": True, "enabled": True},
                    {"id": "explicit", "model": "provider/model", "enabled": True},
                ],
            },
        })

        self.assertEqual(config.schema_version, 2)
        self.assertEqual(config.base.no_proxy, "localhost")
        self.assertEqual(config.opencode_config, '{"model": "legacy/model"}')
        self.assertEqual(config.model_pool.global_concurrency, 2)
        self.assertFalse(config.model_pool.models[0].enabled)
        self.assertEqual(config.model_pool.models[0].model, "")
        self.assertTrue(config.model_pool.models[1].enabled)

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
