import asyncio
import base64
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import agent.updater as updater
import agent.main as agent_main
import agent.server as agent_server
from agent.config import AgentConfig
from agent.updater import compute_runtime_hash
from backend.api import agent as agent_api


class AgentRuntimePackageTests(unittest.TestCase):
    def test_runtime_zip_excludes_local_config_and_launchers(self) -> None:
        data = agent_api._build_agent_runtime_zip()
        with zipfile.ZipFile(_bytes_path(data)) as zf:
            names = set(zf.namelist())

        self.assertIn("agent/main.py", names)
        self.assertIn("requirements-agent.txt", names)
        self.assertIn("ctags-p6.2.20260517.0-x64/ctags.exe", names)
        self.assertFalse(any(name.startswith("checkers/") for name in names))
        self.assertNotIn("agent.yaml", names)
        self.assertNotIn("run_agent.sh", names)
        self.assertNotIn("run_agent.bat", names)
        self.assertFalse(any(name.startswith("backend/static/") for name in names))
        self.assertFalse(any(name.startswith("backend/system_skills/") for name in names))
        self.assertFalse(any("/vulnerability_validation/" in name for name in names))
        self.assertFalse(any(name.startswith("agent/product_validators/") for name in names))

    def test_agent_download_zip_includes_launchers_config_and_bundled_ctags(self) -> None:
        data = agent_api._build_agent_zip("http://server.example", "owner-token")
        with zipfile.ZipFile(_bytes_path(data)) as zf:
            names = set(zf.namelist())
            agent_yaml = zf.read("agent.yaml").decode("utf-8")

        self.assertIn("run_agent.sh", names)
        self.assertIn("run_agent.bat", names)
        self.assertIn("requirements-agent.txt", names)
        self.assertTrue(any(name.startswith("checkers/") for name in names))
        self.assertIn("ctags-p6.2.20260517.0-x64/ctags.exe", names)
        self.assertIn("agent/product_validators/demo.py", names)
        self.assertIn('server_url: "http://server.example"', agent_yaml)
        self.assertIn('owner_token: "owner-token"', agent_yaml)

    def test_launchers_do_not_auto_install_ctags_system_packages(self) -> None:
        root = Path(__file__).resolve().parent.parent
        script_text = (root / "run_agent.sh").read_text(encoding="utf-8")
        batch_text = (root / "run_agent.bat").read_text(encoding="utf-8")

        self.assertIn("ctags-p6.2.20260517.0-x64", script_text)
        self.assertIn("ctags-p6.2.20260517.0-x64", batch_text)
        for text in (script_text, batch_text):
            self.assertNotIn("winget", text)
            self.assertNotIn("pacman -S --needed", text)
            self.assertNotIn("INSTALL_MSYS2", text)

    def test_windows_launcher_detects_python_without_py_launcher(self) -> None:
        root = Path(__file__).resolve().parent.parent
        batch_text = (root / "run_agent.bat").read_text(encoding="utf-8")

        self.assertIn('set "PYTHON_CMD="', batch_text)
        self.assertIn("where.exe /q python3", batch_text)
        self.assertIn("where.exe /q python", batch_text)
        self.assertLess(
            batch_text.index("where.exe /q python3"),
            batch_text.index("where.exe /q python >nul"),
        )
        self.assertNotIn("PYTHON_CMD=py -3", batch_text)
        self.assertIn("[ERROR] Python was not found", batch_text)
        self.assertIn("%PYTHON_CMD% -m pip install -r requirements-agent.txt", batch_text)
        self.assertIn("%PYTHON_CMD% -m agent.main %*", batch_text)

    def test_runtime_hash_matches_archive_contents(self) -> None:
        data = agent_api._build_agent_runtime_zip()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(_bytes_path(data)) as zf:
                zf.extractall(root)
            self.assertEqual(compute_runtime_hash(root), agent_api._agent_runtime_hash())

    def test_runtime_hash_ignores_checker_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent").mkdir()
            (root / "agent" / "main.py").write_text("print('agent')\n", encoding="utf-8")
            checker_dir = root / "checkers" / "demo"
            checker_dir.mkdir(parents=True)
            (checker_dir / "checker.yaml").write_text("name: demo\n", encoding="utf-8")

            before = compute_runtime_hash(root)
            (checker_dir / "checker.yaml").write_text(
                "name: demo\nlabel: changed\n",
                encoding="utf-8",
            )

            self.assertEqual(before, compute_runtime_hash(root))

    def test_runtime_hash_ignores_system_skill_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent").mkdir()
            (root / "agent" / "main.py").write_text("print('agent')\n", encoding="utf-8")
            skill_dir = root / "backend" / "system_skills" / "deephole-skill-creator"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "name: deephole-skill-creator\n",
                encoding="utf-8",
            )

            before = compute_runtime_hash(root)
            (skill_dir / "SKILL.md").write_text(
                "name: deephole-skill-creator\nchanged\n",
                encoding="utf-8",
            )

            self.assertEqual(before, compute_runtime_hash(root))

    def test_runtime_hash_ignores_local_validation_script_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent").mkdir()
            (root / "agent" / "main.py").write_text("print('agent')\n", encoding="utf-8")
            validator_dir = root / "agent" / "vulnerability_validation"
            validator_dir.mkdir()
            (validator_dir / "validator.py").write_text("print('v1')\n", encoding="utf-8")

            before = compute_runtime_hash(root)
            (validator_dir / "validator.py").write_text("print('v2')\n", encoding="utf-8")

            self.assertEqual(before, compute_runtime_hash(root))

    def test_runtime_hash_ignores_product_validator_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent" / "product_validators").mkdir(parents=True)
            (root / "agent" / "main.py").write_text("print('agent')\n", encoding="utf-8")
            validator = root / "agent" / "product_validators" / "demo.py"
            validator.write_text("print('v1')\n", encoding="utf-8")

            before = compute_runtime_hash(root)
            validator.write_text("print('v2')\n", encoding="utf-8")

            self.assertEqual(before, compute_runtime_hash(root))

    def test_runtime_download_serves_payload_snapshot(self) -> None:
        agent_api._runtime_download_tokens.clear()
        snapshot_files = [("agent/main.py", b"snapshot")]

        with patch("backend.api.agent._read_agent_runtime_files", return_value=snapshot_files):
            payload = agent_api.create_agent_runtime_update_payload("http://server.example")

        self.assertEqual(payload["manifest"]["runtime_hash"], payload["hash"])
        self.assertEqual(payload["manifest"]["hash_scope"], payload["hash_scope"])
        self.assertEqual(payload["manifest"]["files"][0]["path"], "agent/main.py")
        request = _FakeRequest(payload["token"])
        response = asyncio.run(agent_api.agent_runtime_download(request))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(_bytes_path(response.body)) as zf:
                self.assertEqual(zf.read("agent/main.py"), b"snapshot")
                zf.extractall(root)
            self.assertEqual(compute_runtime_hash(root), payload["hash"])
        self.assertEqual(agent_api._runtime_download_tokens, {})

    def test_runtime_install_accepts_manifest_verified_scope_mismatch(self) -> None:
        files = [("agent/main.py", b"print('server snapshot')\n")]
        archive = agent_api._build_agent_runtime_zip_from_files(files)
        expected_hash = agent_api._agent_runtime_hash_for_files(files)
        manifest = _runtime_manifest(files, scope={"version": 1, "dirs": ["agent", "checkers"]})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("agent.updater.runtime_root", return_value=root):
                updater._install_update_archive(archive, expected_hash, manifest)

            self.assertEqual(
                (root / "agent" / "main.py").read_text(encoding="utf-8"),
                "print('server snapshot')\n",
            )

    def test_runtime_install_preserves_skipped_validator_dirs(self) -> None:
        files = [
            ("agent/main.py", b"print('server snapshot')\n"),
            ("agent/server.py", b"# server\n"),
            ("backend/api.py", b"# api\n"),
            ("requirements-agent.txt", b"requests\n"),
        ]
        archive = agent_api._build_agent_runtime_zip_from_files(files)
        expected_hash = agent_api._agent_runtime_hash_for_files(files)
        manifest = _runtime_manifest(files)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent" / "product_validators").mkdir(parents=True)
            (root / "agent" / "product_validators" / "custom.py").write_text(
                "def register(registry):\n    pass\n",
                encoding="utf-8",
            )
            (root / "agent" / "vulnerability_validation").mkdir(parents=True)
            (root / "agent" / "vulnerability_validation" / "validator.py").write_text(
                "print('local validator')\n",
                encoding="utf-8",
            )
            (root / "agent" / "main.py").write_text("print('old')\n", encoding="utf-8")
            (root / "agent" / "stale.py").write_text("# stale\n", encoding="utf-8")
            (root / "backend").mkdir()
            (root / "backend" / "old.py").write_text("# old\n", encoding="utf-8")
            (root / "requirements-agent.txt").write_text("old\n", encoding="utf-8")

            with patch("agent.updater.runtime_root", return_value=root):
                updater._install_update_archive(archive, expected_hash, manifest)

            self.assertEqual(
                (root / "agent" / "product_validators" / "custom.py").read_text(encoding="utf-8"),
                "def register(registry):\n    pass\n",
            )
            self.assertEqual(
                (root / "agent" / "vulnerability_validation" / "validator.py").read_text(encoding="utf-8"),
                "print('local validator')\n",
            )
            self.assertFalse((root / "agent" / "stale.py").exists())
            self.assertFalse((root / "backend" / "old.py").exists())
            self.assertEqual(
                (root / "agent" / "main.py").read_text(encoding="utf-8"),
                "print('server snapshot')\n",
            )
            self.assertEqual(compute_runtime_hash(root), expected_hash)

    def test_runtime_install_rejects_manifest_missing_file(self) -> None:
        manifest_files = [
            ("agent/main.py", b"print('server snapshot')\n"),
            ("backend/api.py", b"# backend\n"),
        ]
        archive_files = [manifest_files[0]]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("agent.updater.runtime_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "manifest mismatch"):
                    updater._install_update_archive(
                        agent_api._build_agent_runtime_zip_from_files(archive_files),
                        agent_api._agent_runtime_hash_for_files(manifest_files),
                        _runtime_manifest(manifest_files),
                    )

    def test_runtime_install_rejects_manifest_extra_file(self) -> None:
        manifest_files = [("agent/main.py", b"print('server snapshot')\n")]
        archive_files = [
            *manifest_files,
            ("backend/api.py", b"# backend\n"),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("agent.updater.runtime_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "manifest mismatch"):
                    updater._install_update_archive(
                        agent_api._build_agent_runtime_zip_from_files(archive_files),
                        agent_api._agent_runtime_hash_for_files(manifest_files),
                        _runtime_manifest(manifest_files),
                    )

    def test_runtime_install_rejects_manifest_file_hash_mismatch(self) -> None:
        manifest_files = [("agent/main.py", b"print('server snapshot')\n")]
        archive_files = [("agent/main.py", b"print('tampered')\n")]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("agent.updater.runtime_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "manifest hash mismatch"):
                    updater._install_update_archive(
                        agent_api._build_agent_runtime_zip_from_files(archive_files),
                        agent_api._agent_runtime_hash_for_files(manifest_files),
                        _runtime_manifest(manifest_files),
                    )

    def test_runtime_install_without_manifest_keeps_strict_hash_check(self) -> None:
        files = [("agent/main.py", b"print('server snapshot')\n")]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("agent.updater.runtime_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "content hash mismatch"):
                    updater._install_update_archive(
                        agent_api._build_agent_runtime_zip_from_files(files),
                        "not-the-expected-hash",
                    )

    def test_config_test_does_not_mutate_live_config(self) -> None:
        live_config = AgentConfig()
        live_config.llm_api.api_key = "live-key"
        agent_server._config = live_config

        def fake_probe(llm_cfg):
            self.assertEqual(llm_cfg.api_key, "form-key")
            return True, ""

        async def fake_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        with (
            patch("agent.server.asyncio.to_thread", new=fake_to_thread),
            patch("backend.opencode.llm_api_runner.probe_llm_api_config", side_effect=fake_probe),
        ):
            result = asyncio.run(agent_server.handle_config_test(
                "req-1",
                {"llm_api": {"api_key": "form-key"}},
            ))

        self.assertTrue(result["ok"])
        self.assertEqual(live_config.llm_api.api_key, "live-key")

    def test_skill_creator_output_parser_accepts_fenced_json(self) -> None:
        parsed = agent_server._parse_skill_creator_output(
            "```json\n"
            '{"skill_md":"---\\nname: demo\\ndescription: demo\\n---\\n\\n# Demo",'
            '"scenarios_md":"# 场景","summary":"ok"}'
            "\n```"
        )

        self.assertIn("# Demo", parsed["skill_md"])
        self.assertEqual(parsed["scenarios_md"], "# 场景")
        self.assertEqual(parsed["summary"], "ok")

    def test_skill_creator_package_writer_uses_dispatched_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent_server._write_skill_creator_package(
                _skill_creator_package({"SKILL.md": "# Creator\n"}),
                root,
            )

            self.assertEqual(
                (root / "deephole-skill-creator" / "SKILL.md").read_text(encoding="utf-8"),
                "# Creator\n",
            )

    def test_skill_creator_prompt_uses_deephole_skill_creator(self) -> None:
        self.assertIn(
            "`deephole-skill-creator`",
            agent_server._skill_creator_prompt("Name", "Description", "Input"),
        )

    def test_skill_creator_package_writer_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "Unsafe deephole-skill-creator package path"):
                agent_server._write_skill_creator_package(
                    _skill_creator_package({"../SKILL.md": "bad"}),
                    Path(tmp),
                )

    def test_skill_creator_package_writer_rejects_hash_mismatch(self) -> None:
        package = _skill_creator_package({"SKILL.md": "# Creator\n"})
        package["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "package hash mismatch"):
                agent_server._write_skill_creator_package(package, Path(tmp))

    def test_product_validator_package_writer_uses_dispatched_files(self) -> None:
        package = _product_validators_package({
            "__init__.py": "",
            "demo.py": "def register(registry):\n    pass\n",
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "product_validators"
            installed = agent_server._write_product_validators_package(package, root)

            self.assertEqual(installed, ["__init__.py", "demo.py"])
            self.assertEqual(
                (root / "demo.py").read_text(encoding="utf-8"),
                "def register(registry):\n    pass\n",
            )

    def test_product_validator_package_writer_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "Unsafe product validators package path"):
                agent_server._write_product_validators_package(
                    _product_validators_package({"../bad.py": "bad"}),
                    Path(tmp) / "product_validators",
                )

    def test_product_validator_package_writer_rejects_hash_mismatch(self) -> None:
        package = _product_validators_package({"demo.py": ""})
        package["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                agent_server._write_product_validators_package(package, Path(tmp) / "product_validators")

    def test_runtime_update_only_task_runs_post_update_skill_create(self) -> None:
        update = AsyncMock(return_value=False)
        handler = AsyncMock(return_value={"ok": True})

        with (
            patch("agent.updater.ensure_runtime_updated", new=update),
            patch("agent.server.handle_skill_create", new=handler),
        ):
            result = asyncio.run(agent_main._handle_command(
                {
                    "type": "task",
                    "runtime_update_only": True,
                    "agent_runtime_update": {"hash": "new-runtime"},
                    "post_update_command": {
                        "type": "skill_create",
                        "request_id": "job-1",
                        "name": "Name",
                        "description": "Description",
                        "input": "Input",
                        "deephole_skill_creator_package": {"name": "deephole-skill-creator"},
                    },
                },
                None,
                None,
                None,
            ))

        self.assertEqual(result, {"ok": True})
        self.assertEqual(update.await_count, 2)
        handler.assert_awaited_once()

    def test_fp_review_command_checks_runtime_update_before_review(self) -> None:
        update = AsyncMock(return_value=False)
        handler = AsyncMock()

        with (
            patch("agent.updater.ensure_runtime_updated", new=update),
            patch("agent.server.handle_fp_review", new=handler),
        ):
            asyncio.run(agent_main._handle_command(
                {
                    "type": "fp_review",
                    "scan_id": "scan-1",
                    "review_id": "review-1",
                    "project_path": "/repo/project",
                    "vulnerabilities": [],
                    "feedback_entries": [],
                    "agent_runtime_update": {"hash": "new-runtime"},
                },
                None,
                None,
                None,
            ))

        update.assert_awaited_once()
        self.assertEqual(update.await_args.args[0], {"hash": "new-runtime"})
        handler.assert_awaited_once()


def _bytes_path(data: bytes):
    import io

    return io.BytesIO(data)


def _skill_creator_package(files: dict[str, str]) -> dict[str, str]:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    data = archive.getvalue()
    return {
        "name": "deephole-skill-creator",
        "sha256": hashlib.sha256(data).hexdigest(),
        "archive_b64": base64.b64encode(data).decode("ascii"),
    }


def _product_validators_package(files: dict[str, str]) -> dict[str, str]:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    data = archive.getvalue()
    return {
        "name": "product_validators",
        "sha256": hashlib.sha256(data).hexdigest(),
        "archive_b64": base64.b64encode(data).decode("ascii"),
    }


def _runtime_manifest(files: list[tuple[str, bytes]], scope: dict | None = None) -> dict:
    manifest = agent_api._agent_runtime_manifest_for_files(files)
    manifest["runtime_hash"] = agent_api._agent_runtime_hash_for_files(files)
    if scope is not None:
        manifest["hash_scope"] = scope
    return manifest


class _FakeRequest:
    def __init__(self, token: str) -> None:
        self.headers = {}
        self.query_params = {"token": token}


if __name__ == "__main__":
    unittest.main()
