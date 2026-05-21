import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.fp_reviewer import _cleanup_fp_workspace, _create_fp_workspace
from backend.models import FeedbackEntry
from backend.opencode.config import cleanup_workspace, create_scan_workspace
from backend.registry import CheckerEntry


def assert_opencode_read_permissions(testcase: unittest.TestCase, config: dict) -> None:
    permission = config.get("permission", {})
    for key in ("read", "list", "glob", "grep", "external_directory"):
        testcase.assertEqual(permission.get(key), {"*": "allow"})
    testcase.assertEqual(permission.get("edit"), {"*": "deny"})


class OpencodeWorkspaceTests(unittest.TestCase):
    def test_scan_cleanup_preserves_fp_review_skill_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            skills_dir = workspace / ".opencode" / "skills"
            for name in ("npd", "oob", "fp-review", "custom"):
                skill_dir = skills_dir / name
                skill_dir.mkdir(parents=True)
                (skill_dir / "SKILL.md").write_text(name, encoding="utf-8")

            with patch("backend.opencode.config.get_registry", return_value={"npd": object(), "oob": object()}):
                cleanup_workspace(workspace)

            self.assertFalse((skills_dir / "npd").exists())
            self.assertFalse((skills_dir / "oob").exists())
            self.assertTrue((skills_dir / "fp-review" / "SKILL.md").is_file())
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
            self.assertTrue((workspace / ".opencode" / "skills" / "fp-review" / "SKILL.md").is_file())

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

            skill = (workspace / ".opencode" / "skills" / "fp-review" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("历史用户经验", skill)
            self.assertIn("用户理由：npd true-positive rule", skill)
            self.assertIn("void checked(void) {}", skill)
            self.assertIn("用户理由：npd false-positive rule", skill)
            self.assertIn("void guarded(void) {}", skill)
            self.assertNotIn("[正报]", skill)
            self.assertNotIn("[误报]", skill)
            self.assertNotIn("oob rule", skill)

    def test_fp_cleanup_only_removes_fp_review_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "opencode.json").write_text("{}", encoding="utf-8")
            fp_dir = workspace / ".opencode" / "skills" / "fp-review"
            scan_dir = workspace / ".opencode" / "skills" / "npd"
            fp_dir.mkdir(parents=True)
            scan_dir.mkdir(parents=True)
            (fp_dir / "SKILL.md").write_text("fp", encoding="utf-8")
            (scan_dir / "SKILL.md").write_text("npd", encoding="utf-8")

            _cleanup_fp_workspace(workspace)

            self.assertFalse(fp_dir.exists())
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

            with patch("backend.opencode.config.get_registry", return_value={"memleak": entry}):
                create_scan_workspace(
                    "scan-1",
                    project_dir=project,
                    feedback_entries=[feedback],
                    mcp_port=9123,
                )

            skill_dir = project / ".opencode" / "skills" / "memleak"
            prompt = (skill_dir / "PROMPT.md").read_text(encoding="utf-8")
            skill = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            config = json.loads((project / "opencode.json").read_text(encoding="utf-8"))

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
            assert_opencode_read_permissions(self, config)


if __name__ == "__main__":
    unittest.main()
