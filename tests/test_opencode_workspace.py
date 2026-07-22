import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client import codegraph as codegraph_runtime
from deephole_client.fp_reviewer import _create_fp_workspace
from deephole_client.opencode_integration import (
    build_opencode_config,
    get_global_opencode_workspace,
    managed_opencode_config_path,
    refresh_global_opencode_config,
    writable_edit_patterns,
)
from backend.registry import CheckerEntry
from deephole_client.threat_analysis_workspace import install_attack_tree_threat_analysis_skill


def assert_opencode_read_permissions(testcase: unittest.TestCase, config: dict) -> None:
    permission = config.get("permission", {})
    for key in ("read", "list", "glob", "grep"):
        testcase.assertEqual(permission.get(key), {"*": "allow"})
    testcase.assertEqual(permission.get("external_directory"), {"*": "deny"})
    testcase.assertEqual(permission.get("edit"), {"*": "deny"})
    testcase.assertEqual(permission.get("bash"), {"*": "deny"})


class OpencodeWorkspaceTests(unittest.TestCase):
    def test_writable_edit_patterns_include_windows_slash_variants(self) -> None:
        path = PureWindowsPath("C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1")
        patterns = writable_edit_patterns(path)
        self.assertIn(r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1", patterns)
        self.assertIn(r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1/**", patterns)
        self.assertIn("C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1", patterns)
        self.assertIn("C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1/**", patterns)

    def test_build_opencode_config_allows_windows_slash_variants(self) -> None:
        path = PureWindowsPath("C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1")
        config = build_opencode_config(
            "http://127.0.0.1:9123/mcp",
            writable_paths=[str(path)],
        )
        edit = config["permission"]["edit"]
        self.assertEqual(edit["*"], "deny")
        self.assertEqual(
            edit["C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1/**"],
            "allow",
        )
        self.assertEqual(
            edit[r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1/**"],
            "allow",
        )

    def test_build_opencode_config_includes_local_and_remote_managed_mcp(self) -> None:
        fake_config = SimpleNamespace(
            code_graph=SimpleNamespace(
                enabled=True,
                name="codegraph",
                transport="local",
                timeout_seconds=45,
                local=SimpleNamespace(
                    executable="codegraph",
                    args=["serve", "--mcp"],
                    environment={"CODEGRAPH_MCP_TOOLS": "explore,node"},
                ),
            ),
            product_info=SimpleNamespace(
                enabled=True,
                name="product-info",
                transport="remote",
                timeout_seconds=12,
                remote=SimpleNamespace(
                    url="http://10.0.0.8:9000/mcp",
                    headers={"Authorization": "Bearer token"},
                ),
            ),
        )
        with (
            patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
            patch("deephole_client.opencode_integration.shutil.which", return_value="/usr/bin/codegraph"),
        ):
            config = build_opencode_config("http://127.0.0.1:9123/mcp")

        self.assertEqual(
            config["mcp"]["codegraph"]["command"],
            ["codegraph", "serve", "--mcp"],
        )
        self.assertEqual(config["mcp"]["codegraph"]["timeout"], 45_000)
        self.assertEqual(
            config["mcp"]["codegraph"]["environment"]["CODEGRAPH_MCP_TOOLS"],
            "explore,node",
        )
        self.assertEqual(config["mcp"]["product-info"]["type"], "remote")
        self.assertEqual(config["mcp"]["product-info"]["timeout"], 12_000)
        self.assertEqual(
            config["mcp"]["product-info"]["headers"]["Authorization"],
            "Bearer token",
        )
        self.assertIs(config["mcp"]["product-info"]["oauth"], False)

    def test_codegraph_readiness_survives_restart_and_applies_to_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            nested = root / "src" / "module"
            nested.mkdir(parents=True)
            database = root / ".codegraph" / "codegraph.db"
            database.parent.mkdir()
            database.write_bytes(b"sqlite")
            codegraph_runtime._ready_projects.clear()

            self.assertTrue(codegraph_runtime.is_codegraph_ready(nested))
            self.assertIn(root.resolve(), codegraph_runtime._ready_projects)
            codegraph_runtime._ready_projects.clear()

    def test_existing_codegraph_database_does_not_disable_fallback_without_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / ".codegraph" / "codegraph.db"
            database.parent.mkdir()
            database.touch()
            runtime = SimpleNamespace(
                code_graph=SimpleNamespace(
                    enabled=True,
                    name="codegraph",
                    transport="local",
                    local=SimpleNamespace(executable="missing-codegraph"),
                ),
            )

            codegraph_runtime._ready_projects.clear()
            with (
                patch("deephole_client.codegraph.shutil.which", return_value=None),
                patch("deephole_client.opencode_integration.get_config", return_value=runtime),
            ):
                from deephole_client.opencode_integration import _disabled_source_mcp_tools

                self.assertFalse(codegraph_runtime.is_codegraph_mcp_available(runtime))
                self.assertEqual(_disabled_source_mcp_tools(root), ("codegraph",))

    def test_global_workspace_is_shared_and_does_not_embed_scan_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace_path = root / ".opendeephole" / "opencode_workspace"
            checker_dir = root / "checkers" / "npd"
            checker_dir.mkdir(parents=True)
            skill_path = checker_dir / "SKILL.md"
            skill_path.write_text("base npd skill", encoding="utf-8")
            entry = CheckerEntry(
                name="npd",
                label="NPD",
                description="",
                enabled=True,
                skill_path=skill_path,
                directory=checker_dir,
                mode="opencode",
            )
            fake_config = SimpleNamespace(mcp_server=SimpleNamespace(port=8100))
            with (
                patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace_path),
                patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
                patch("deephole_client.opencode_integration.get_registry", return_value={"npd": entry}),
            ):
                first = get_global_opencode_workspace(mcp_port=9123)
                second = get_global_opencode_workspace(mcp_port=9123)

            self.assertEqual(first, workspace_path)
            self.assertEqual(second, first)
            managed_path = managed_opencode_config_path(first)
            config = json.loads(managed_path.read_text(encoding="utf-8"))
            self.assertFalse((first / "opencode.json").exists())
            self.assertEqual(managed_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                config["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            self.assertEqual(
                config["skills"]["paths"],
                [str((first / ".opencode" / "skills").resolve())],
            )
            assert_opencode_read_permissions(self, config)
            skill = (first / ".opencode" / "skills" / "npd" / "SKILL.md").read_text(encoding="utf-8")
            self.assertEqual(skill, "base npd skill")
            self.assertNotIn("历史用户经验", skill)

    def test_global_refresh_does_not_overwrite_live_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(mcp_server=SimpleNamespace(port=8100))
            with (
                patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace_path),
                patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
                patch("deephole_client.opencode_integration.get_registry", return_value={}),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)
                live_path = workspace / "opencode.json"
                live_path.write_text('{"sentinel": true}', encoding="utf-8")
                refresh_global_opencode_config()

            self.assertEqual(live_path.read_text(encoding="utf-8"), '{"sentinel": true}')
            managed = json.loads(managed_opencode_config_path(workspace).read_text(encoding="utf-8"))
            self.assertEqual(
                managed["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            self.assertEqual(managed["permission"]["task"], {"*": "allow"})
            self.assertIn("threat-asset-enumerator", managed["agent"])

    def test_api_checker_is_registered_globally_without_feedback_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace_path = root / "opencode_workspace"
            checker_dir = root / "checkers" / "memleak"
            checker_dir.mkdir(parents=True)
            prompt_path = checker_dir / "prompt.txt"
            skill_path = checker_dir / "SKILL.md"
            prompt_path.write_text("api prompt", encoding="utf-8")
            skill_path.write_text("fallback skill", encoding="utf-8")
            entry = CheckerEntry(
                name="memleak",
                label="MEMLEAK",
                description="",
                enabled=True,
                skill_path=skill_path,
                directory=checker_dir,
                mode="api",
                prompt_path=prompt_path,
            )
            fake_config = SimpleNamespace(mcp_server=SimpleNamespace(port=8100))
            with (
                patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace_path),
                patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
                patch("deephole_client.opencode_integration.get_registry", return_value={"memleak": entry}),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)

            skill_dir = workspace / ".opencode" / "skills" / "memleak"
            self.assertEqual((skill_dir / "PROMPT.md").read_text(encoding="utf-8"), "api prompt")
            self.assertEqual((skill_dir / "SKILL.md").read_text(encoding="utf-8"), "fallback skill")

    def test_global_refresh_removes_obsolete_threat_audit_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            stale = workspace_path / ".opencode" / "skills" / "threat-path-audit"
            stale.mkdir(parents=True)
            (stale / "SKILL.md").write_text("obsolete", encoding="utf-8")
            fake_config = SimpleNamespace(mcp_server=SimpleNamespace(port=8100))
            with (
                patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace_path),
                patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
                patch("deephole_client.opencode_integration.get_registry", return_value={}),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)
            self.assertFalse((workspace / ".opencode" / "skills" / "threat-path-audit").exists())

    def test_threat_analysis_install_registers_first_step_agent_skills(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(__file__).resolve().parents[1]
            workspace = Path(tmp)
            managed_path = managed_opencode_config_path(workspace)
            managed_path.write_text(
                json.dumps(build_opencode_config("http://127.0.0.1:9123/mcp"), ensure_ascii=False),
                encoding="utf-8",
            )

            install_attack_tree_threat_analysis_skill(
                workspace=workspace,
                skill_path=repo_root / "attack-tree-threat-analysis.md",
                reference_catalog_path=repo_root / "attack-method-reference-catalog.md",
            )

            config = json.loads(managed_path.read_text(encoding="utf-8"))
            self.assertFalse((workspace / "opencode.json").exists())
            self.assertEqual(config.get("permission", {}).get("task"), {"*": "allow"})
            self.assertTrue((
                workspace / ".opencode" / "skills" / "threat-base-model-shard-planner" / "SKILL.md"
            ).is_file())
            self.assertTrue((
                workspace / ".opencode" / "skills" / "threat-base-model-gap-review-agent" / "SKILL.md"
            ).is_file())
            agents = config.get("agent", {})
            self.assertIsInstance(agents, dict)
            for name in (
                "threat-asset-enumerator",
                "threat-attack-goal-enumerator",
                "threat-code-evidence-mapper",
            ):
                self.assertEqual(agents[name]["mode"], "subagent")
                self.assertTrue(agents[name]["hidden"])
                self.assertEqual(agents[name]["permission"]["task"], "deny")
                self.assertFalse(agents[name]["tools"]["task"])
                self.assertTrue((workspace / ".opencode" / "skills" / name / "SKILL.md").is_file())

            asset_skill = (
                workspace / ".opencode" / "skills" / "threat-asset-enumerator" / "SKILL.md"
            ).read_text(encoding="utf-8")
            goal_skill = (
                workspace / ".opencode" / "skills" / "threat-attack-goal-enumerator" / "SKILL.md"
            ).read_text(encoding="utf-8")
            evidence_skill = (
                workspace / ".opencode" / "skills" / "threat-code-evidence-mapper" / "SKILL.md"
            ).read_text(encoding="utf-8")
            self.assertIn("shard_scope", asset_skill)
            self.assertIn("goal_scope", goal_skill)
            self.assertIn("evidence_scope", evidence_skill)

    def test_all_builtin_skills_are_registered_in_the_same_global_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(mcp_server=SimpleNamespace(port=8100))
            with (
                patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace_path),
                patch("deephole_client.opencode_integration.get_config", return_value=fake_config),
                patch("deephole_client.opencode_integration.get_registry", return_value={}),
            ):
                workspace = _create_fp_workspace(9123)
            self.assertEqual(workspace, workspace_path)
            for skill_name in (
                "history-match",
                "prove-bug",
                "prove-fp",
                "final-judge",
                "git-history-mine",
                "variant-hunt",
                "attack-tree-threat-analysis",
                "threat-analysis-harness",
                "threat-asset-interface-agent",
                "threat-attack-goal-agent",
                "threat-attack-domain-agent",
                "threat-attack-surface-agent",
                "threat-method-confirm-agent",
            ):
                text = (
                    workspace / ".opencode" / "skills" / skill_name / "SKILL.md"
                ).read_text(encoding="utf-8")
                self.assertTrue(text.strip())
                self.assertNotIn("历史用户经验", text)


if __name__ == "__main__":
    unittest.main()
