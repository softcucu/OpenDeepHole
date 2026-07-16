import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from agent.fp_reviewer import _create_fp_workspace
from backend.opencode.config import (
    build_opencode_config,
    get_global_opencode_workspace,
    writable_edit_patterns,
)
from backend.registry import CheckerEntry
from backend.threat_analysis.workspace import install_attack_tree_threat_analysis_skill


def assert_opencode_read_permissions(testcase: unittest.TestCase, config: dict) -> None:
    permission = config.get("permission", {})
    for key in ("read", "list", "glob", "grep", "external_directory"):
        testcase.assertEqual(permission.get(key), {"*": "allow"})
    testcase.assertEqual(permission.get("edit"), {"*": "deny"})


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
        self.assertNotIn("*", edit)
        self.assertEqual(
            edit["C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1/**"],
            "allow",
        )
        self.assertEqual(
            edit[r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1/**"],
            "allow",
        )

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
                patch("backend.opencode.config._GLOBAL_WORKSPACE", workspace_path),
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={"npd": entry}),
            ):
                first = get_global_opencode_workspace(mcp_port=9123)
                second = get_global_opencode_workspace(mcp_port=9123)

            self.assertEqual(first, workspace_path)
            self.assertEqual(second, first)
            config = json.loads((first / "opencode.json").read_text(encoding="utf-8"))
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
                patch("backend.opencode.config._GLOBAL_WORKSPACE", workspace_path),
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={"memleak": entry}),
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
                patch("backend.opencode.config._GLOBAL_WORKSPACE", workspace_path),
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={}),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)
            self.assertFalse((workspace / ".opencode" / "skills" / "threat-path-audit").exists())

    def test_threat_analysis_install_registers_first_step_agent_skills(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(__file__).resolve().parents[1]
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text(
                json.dumps(build_opencode_config("http://127.0.0.1:9123/mcp"), ensure_ascii=False),
                encoding="utf-8",
            )

            install_attack_tree_threat_analysis_skill(
                workspace=workspace,
                skill_path=repo_root / "attack-tree-threat-analysis.md",
                reference_catalog_path=repo_root / "attack-method-reference-catalog.md",
            )

            config = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
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
                patch("backend.opencode.config._GLOBAL_WORKSPACE", workspace_path),
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={}),
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
