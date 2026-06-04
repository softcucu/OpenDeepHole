import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from agent.fp_reviewer import _cleanup_fp_workspace, _create_fp_workspace
from backend.models import FeedbackEntry
from backend.opencode.config import build_opencode_config, cleanup_workspace, create_scan_workspace, writable_edit_patterns
from backend.registry import CheckerEntry


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

        config = build_opencode_config("http://127.0.0.1:9123/mcp", writable_paths=[str(path)])
        edit = config["permission"]["edit"]

        self.assertEqual(edit["*"], "deny")
        self.assertEqual(edit["C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1/**"], "allow")
        self.assertEqual(edit[r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1/**"], "allow")

    def test_scan_cleanup_preserves_fp_review_skill_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            skills_dir = workspace / ".opencode" / "skills"
            for name in ("npd", "oob", "prove-bug", "custom"):
                skill_dir = skills_dir / name
                skill_dir.mkdir(parents=True)
                (skill_dir / "SKILL.md").write_text(name, encoding="utf-8")

            with patch("backend.opencode.config.get_registry", return_value={"npd": object(), "oob": object()}):
                cleanup_workspace(workspace)

            self.assertFalse((skills_dir / "npd").exists())
            self.assertFalse((skills_dir / "oob").exists())
            self.assertTrue((skills_dir / "prove-bug" / "SKILL.md").is_file())
            self.assertTrue((skills_dir / "custom" / "SKILL.md").is_file())
            self.assertTrue((workspace / "opencode.json").is_file())

    def test_scan_cleanup_removes_config_when_no_skills_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            skill_dir = workspace / ".opencode" / "skills" / "npd"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text("npd", encoding="utf-8")

            with patch("backend.opencode.config.get_registry", return_value={"npd": object()}):
                cleanup_workspace(workspace)

            self.assertFalse((workspace / ".opencode").exists())
            self.assertFalse((workspace / "opencode.json").exists())

    def test_fp_workspace_start_creates_project_root_skill_and_mcp_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)

            self.assertEqual(_create_fp_workspace(workspace, 9123), workspace)

            config = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
            self.assertEqual(
                config["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            assert_opencode_read_permissions(self, config)
            self.assertTrue((workspace / ".opencode" / "skills" / "prove-bug" / "SKILL.md").is_file())
            self.assertTrue((workspace / ".opencode" / "skills" / "prove-fp" / "SKILL.md").is_file())
            self.assertTrue((workspace / ".opencode" / "skills" / "final-judge" / "SKILL.md").is_file())

    def test_fp_workspace_injects_only_selected_feedback_for_vuln_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)

            _create_fp_workspace(
                workspace,
                9123,
                vuln_type="npd",
                feedback_entries=[
                    {
                        "vuln_type": "npd",
                        "verdict": "confirmed",
                        "reason": "npd true-positive rule",
                        "function_source": "void checked(void) {}",
                    },
                    {
                        "vuln_type": "npd",
                        "verdict": "false_positive",
                        "reason": "npd false-positive rule",
                        "function_source": "void guarded(void) {}",
                    },
                    {"vuln_type": "oob", "verdict": "false_positive", "reason": "oob rule"},
                    {"vuln_type": "npd", "verdict": "false_positive", "reason": ""},
                ],
            )

            skill = (workspace / ".opencode" / "skills" / "prove-bug" / "SKILL.md").read_text(encoding="utf-8")
            fp_skill = (
                workspace / ".opencode" / "skills" / "prove-fp" / "SKILL.md"
            ).read_text(encoding="utf-8")
            self.assertIn("历史用户经验", skill)
            self.assertIn("用户理由：npd true-positive rule", skill)
            self.assertIn("void checked(void) {}", skill)
            self.assertIn("用户理由：npd false-positive rule", skill)
            self.assertIn("void guarded(void) {}", skill)
            self.assertNotIn("[正报]", skill)
            self.assertNotIn("[误报]", skill)
            self.assertNotIn("oob rule", skill)
            self.assertIn("历史用户经验", fp_skill)
            self.assertIn("用户理由：npd false-positive rule", fp_skill)
            self.assertNotIn("oob rule", fp_skill)

    def test_fp_cleanup_only_removes_fp_review_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            fp_dir = workspace / ".opencode" / "skills" / "prove-bug"
            fp_discriminator_dir = workspace / ".opencode" / "skills" / "prove-fp"
            fp_final_dir = workspace / ".opencode" / "skills" / "final-judge"
            legacy_fp_dir = workspace / ".opencode" / "skills" / "fp-review"
            scan_dir = workspace / ".opencode" / "skills" / "npd"
            fp_dir.mkdir(parents=True)
            fp_discriminator_dir.mkdir(parents=True)
            fp_final_dir.mkdir(parents=True)
            legacy_fp_dir.mkdir(parents=True)
            scan_dir.mkdir(parents=True)
            (fp_dir / "SKILL.md").write_text("fp", encoding="utf-8")
            (fp_discriminator_dir / "SKILL.md").write_text("fp-discriminator", encoding="utf-8")
            (fp_final_dir / "SKILL.md").write_text("fp-final", encoding="utf-8")
            (legacy_fp_dir / "SKILL.md").write_text("legacy-fp", encoding="utf-8")
            (scan_dir / "SKILL.md").write_text("npd", encoding="utf-8")

            _cleanup_fp_workspace(workspace)

            self.assertFalse(fp_dir.exists())
            self.assertFalse(fp_discriminator_dir.exists())
            self.assertFalse(fp_final_dir.exists())
            self.assertFalse(legacy_fp_dir.exists())
            self.assertTrue((scan_dir / "SKILL.md").is_file())
            self.assertTrue((workspace / "opencode.json").is_file())

    def test_api_checker_workspace_includes_prompt_and_fallback_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
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
            feedback = FeedbackEntry(
                id="fb-1",
                project_id="project-1",
                vuln_type="memleak",
                verdict="false_positive",
                file="sample.c",
                line=12,
                function="leaky",
                description="candidate",
                reason="known false positive",
                function_source="void leaky(void) {}",
                function_start_line=10,
                created_at="2026-05-16T00:00:00",
                updated_at="2026-05-16T00:00:00",
            )

            scans_dir = root / "scans"
            fake_config = SimpleNamespace(
                storage=SimpleNamespace(scans_dir=str(scans_dir)),
                mcp_server=SimpleNamespace(port=8100),
            )

            with (
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={"memleak": entry}),
            ):
                workspace = create_scan_workspace(
                    "scan-1",
                    project_dir=project,
                    feedback_entries=[feedback],
                    mcp_port=9123,
                )

            skill_dir = workspace / ".opencode" / "skills" / "memleak"
            prompt = (skill_dir / "PROMPT.md").read_text(encoding="utf-8")
            skill = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            config = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))

            self.assertEqual(workspace, scans_dir / "scan-1" / "opencode_workspace")
            self.assertFalse((project / "opencode.json").exists())
            self.assertIn("api prompt", prompt)
            self.assertIn("fallback skill", skill)
            self.assertIn("历史用户经验", prompt)
            self.assertIn("历史用户经验", skill)
            self.assertIn("known false positive", prompt)
            self.assertIn("known false positive", skill)
            self.assertIn("void leaky(void) {}", prompt)
            self.assertIn("void leaky(void) {}", skill)
            self.assertNotIn("candidate", prompt)
            self.assertNotIn("candidate", skill)
            self.assertEqual(
                config["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            self.assertEqual(config["skills"]["paths"], [str((workspace / ".opencode" / "skills").resolve())])
            assert_opencode_read_permissions(self, config)

    def test_scan_workspaces_are_isolated_per_scan_for_same_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            scans_dir = root / "scans"
            fake_config = SimpleNamespace(
                storage=SimpleNamespace(scans_dir=str(scans_dir)),
                mcp_server=SimpleNamespace(port=8100),
            )

            with (
                patch("backend.opencode.config.get_config", return_value=fake_config),
                patch("backend.opencode.config.get_registry", return_value={}),
            ):
                workspace_a = create_scan_workspace("scan-a", project_dir=project, mcp_port=9001)
                workspace_b = create_scan_workspace("scan-b", project_dir=project, mcp_port=9002)

            config_a = json.loads((workspace_a / "opencode.json").read_text(encoding="utf-8"))
            config_b = json.loads((workspace_b / "opencode.json").read_text(encoding="utf-8"))

            self.assertNotEqual(workspace_a, workspace_b)
            self.assertEqual(config_a["mcp"]["deephole-code"]["url"], "http://127.0.0.1:9001/mcp")
            self.assertEqual(config_b["mcp"]["deephole-code"]["url"], "http://127.0.0.1:9002/mcp")
            self.assertFalse((project / "opencode.json").exists())


if __name__ == "__main__":
    unittest.main()
