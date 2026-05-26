import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.api.checkers import _discover_catalog_items, list_checker_catalog
from backend.models import User


class CheckerCatalogTests(unittest.TestCase):
    def test_catalog_prefers_scenarios_over_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checker_dir = Path(tmp) / "intoverflow"
            checker_dir.mkdir()
            (checker_dir / "checker.yaml").write_text(
                "name: intoverflow\nlabel: Integer Overflow\ndescription: description\nenabled: true\n",
                encoding="utf-8",
            )
            skill_path = checker_dir / "SKILL.md"
            skill_path.write_text("# Skill intro\n", encoding="utf-8")
            (checker_dir / "SCENARIOS.md").write_text("# Scenario intro\n", encoding="utf-8")

            with patch("backend.api.checkers.CHECKERS_DIR", Path(tmp)):
                response = asyncio.run(
                    list_checker_catalog(
                        current_user=User(user_id="u1", username="alice", role="user")
                    )
                )

        self.assertEqual(len(response), 1)
        self.assertTrue(response[0].enabled)
        self.assertEqual(response[0].introduction, "# Scenario intro")
        self.assertEqual(response[0].introduction_source, "SCENARIOS.md")

    def test_catalog_includes_disabled_checkers_and_falls_back_to_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npd_dir = root / "npd"
            npd_dir.mkdir()
            (npd_dir / "checker.yaml").write_text(
                "\n".join(
                    [
                        "name: npd",
                        "label: NPD",
                        "description: null pointer",
                        "enabled: false",
                        "category: illegal_memory_use",
                        'modified_at: "2026-05-20T12:00:00+08:00"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (npd_dir / "SKILL.md").write_text("# Skill only\n", encoding="utf-8")

            response = _discover_catalog_items(root)

        by_name = {item.name: item for item in response}
        self.assertFalse(by_name["npd"].enabled)
        self.assertEqual(by_name["npd"].category, "illegal_memory_use")
        self.assertEqual(by_name["npd"].category_label, "非法内存使用")
        self.assertEqual(by_name["npd"].modified_at, "2026-05-20T12:00:00+08:00")
        self.assertEqual(by_name["npd"].introduction, "# Skill only")
        self.assertEqual(by_name["npd"].introduction_source, "SKILL.md")

    def test_catalog_sorts_by_modified_at_descending_and_missing_values_last(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_checker(
                root,
                "old",
                category="resource_leak",
                modified_at="2026-05-18T12:00:00+08:00",
            )
            self._write_checker(
                root,
                "new",
                category="out_of_bounds",
                modified_at="2026-05-20T12:00:00+08:00",
            )
            self._write_checker(root, "missing", category="not-a-category")

            response = _discover_catalog_items(root)

        self.assertEqual([item.name for item in response], ["new", "old", "missing"])
        self.assertEqual(response[0].category_label, "读写越界")
        self.assertEqual(response[1].category_label, "资源泄露")
        self.assertEqual(response[2].category, "illegal_memory_use")
        self.assertEqual(response[2].category_label, "非法内存使用")

    def test_catalog_accepts_auth_bypass_and_other_categories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_checker(
                root,
                "auth_check",
                category="auth_bypass",
                modified_at="2026-05-20T12:00:00+08:00",
            )
            self._write_checker(
                root,
                "other_check",
                category="other",
                modified_at="2026-05-19T12:00:00+08:00",
            )

            response = _discover_catalog_items(root)

        by_name = {item.name: item for item in response}
        self.assertEqual(by_name["auth_check"].category, "auth_bypass")
        self.assertEqual(by_name["auth_check"].category_label, "认证绕过")
        self.assertEqual(by_name["other_check"].category, "other")
        self.assertEqual(by_name["other_check"].category_label, "其他")

    def test_catalog_falls_back_to_description_when_intro_files_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker_dir = root / "api_checker"
            checker_dir.mkdir()
            (checker_dir / "checker.yaml").write_text(
                "name: api_checker\nlabel: API Checker\ndescription: api description\nenabled: false\n",
                encoding="utf-8",
            )

            response = _discover_catalog_items(root)

        self.assertEqual(response[0].introduction, "api description")
        self.assertEqual(response[0].introduction_source, "checker.yaml")

    def _write_checker(
        self,
        root: Path,
        name: str,
        *,
        category: str | None = None,
        modified_at: str | None = None,
    ) -> None:
        checker_dir = root / name
        checker_dir.mkdir(parents=True)
        lines = [
            f"name: {name}",
            f"label: {name.upper()}",
            f"description: {name} checker",
            "enabled: true",
        ]
        if category is not None:
            lines.append(f"category: {category}")
        if modified_at is not None:
            lines.append(f'modified_at: "{modified_at}"')
        (checker_dir / "checker.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (checker_dir / "SKILL.md").write_text("# Skill\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
