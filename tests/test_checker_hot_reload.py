import asyncio
import base64
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.checkers import list_checkers
from backend.api.scan import _validated_checker_names
from backend.checker_sync import build_checker_packages, unpack_checker_packages
from backend.models import User
from backend.registry import discover_checkers, refresh_registry


class CheckerHotReloadTests(unittest.TestCase):
    def test_refresh_registry_discovers_new_checker_without_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_checker(root, "first")
            registry = refresh_registry(root)
            self.assertIn("first", registry)

            self._write_checker(root, "second")
            registry = refresh_registry(root)

        self.assertIn("first", registry)
        self.assertIn("second", registry)

    def test_admin_visibility_is_hidden_from_regular_users(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_checker(root, "public_check", modified_at="2026-05-18T12:00:00+08:00")
            self._write_checker(
                root,
                "admin_check",
                visibility="admin",
                category="auth_bypass",
                modified_at="2026-05-20T12:00:00+08:00",
            )
            user = User(user_id="u1", username="alice", role="user")
            admin = User(user_id="u2", username="root", role="admin")

            cfg = SimpleNamespace(storage=SimpleNamespace(user_skills_dir=str(root)))
            with (
                patch("backend.registry.CHECKERS_DIR", root),
                patch("backend.config.get_config", return_value=cfg),
            ):
                user_items = asyncio.run(list_checkers(current_user=user))
                admin_items = asyncio.run(list_checkers(current_user=admin))

        self.assertEqual([item.name for item in user_items], ["public_check"])
        self.assertEqual([item.name for item in admin_items], ["admin_check", "public_check"])
        self.assertEqual(admin_items[0].category, "auth_bypass")
        self.assertEqual(admin_items[0].category_label, "认证绕过")
        self.assertEqual(admin_items[0].modified_at, "2026-05-20T12:00:00+08:00")

    def test_regular_user_cannot_select_admin_only_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_checker(root, "admin_check", visibility="admin")
            user = User(user_id="u1", username="alice", role="user")

            with patch("backend.registry.CHECKERS_DIR", root):
                with self.assertRaises(Exception) as ctx:
                    _validated_checker_names(["admin_check"], user)

        self.assertEqual(getattr(ctx.exception, "status_code", None), 403)

    def test_checker_package_loads_with_relative_imports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "source"
            target_root = Path(tmp) / "target"
            self._write_checker(source_root, "relcheck", with_analyzer=True)
            registry = discover_checkers(source_root)
            packages = build_checker_packages(registry, ["relcheck"])

            unpacked = unpack_checker_packages(packages, target_root)
            synced_registry = refresh_registry(target_root)

        self.assertEqual(unpacked, ["relcheck"])
        self.assertIn("relcheck", synced_registry)
        self.assertIsNotNone(synced_registry["relcheck"].analyzer)
        self.assertEqual(getattr(synced_registry["relcheck"].analyzer, "marker", ""), "relative-ok")

    def test_refresh_registry_discovers_user_skill_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            builtins_root = root / "builtins"
            user_root = root / "user_skills"
            self._write_checker(builtins_root, "builtin_check")
            self._write_checker(user_root, "user_skill", category="other")

            cfg = SimpleNamespace(storage=SimpleNamespace(user_skills_dir=str(user_root)))
            with (
                patch("backend.registry.CHECKERS_DIR", builtins_root),
                patch("backend.config.get_config", return_value=cfg),
            ):
                registry = refresh_registry()

        self.assertIn("builtin_check", registry)
        self.assertIn("user_skill", registry)
        self.assertEqual(registry["user_skill"].category, "other")

    def test_unpack_rejects_path_traversal(self) -> None:
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as zf:
            zf.writestr("../evil.txt", "bad")
        raw = data.getvalue()
        package = {
            "name": "bad",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "archive_b64": base64.b64encode(raw).decode("ascii"),
        }

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                unpack_checker_packages([package], Path(tmp))

    def _write_checker(
        self,
        root: Path,
        name: str,
        *,
        visibility: str = "public",
        category: str = "illegal_memory_use",
        modified_at: str = "2026-05-19T12:00:00+08:00",
        with_analyzer: bool = False,
    ) -> None:
        checker_dir = root / name
        checker_dir.mkdir(parents=True)
        (checker_dir / "checker.yaml").write_text(
            "\n".join(
                [
                    f"name: {name}",
                    f"label: {name.upper()}",
                    f"description: {name} checker",
                    "enabled: true",
                    f"visibility: {visibility}",
                    f"category: {category}",
                    f'modified_at: "{modified_at}"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (checker_dir / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
        if with_analyzer:
            (checker_dir / "helper.py").write_text("MARKER = 'relative-ok'\n", encoding="utf-8")
            (checker_dir / "analyzer.py").write_text(
                "from backend.analyzers.base import BaseAnalyzer\n"
                "from .helper import MARKER\n\n"
                "class Analyzer(BaseAnalyzer):\n"
                "    def __init__(self):\n"
                "        self.marker = MARKER\n"
                "    def find_candidates(self, project_path, db=None):\n"
                "        return iter(())\n",
                encoding="utf-8",
            )


if __name__ == "__main__":
    unittest.main()
