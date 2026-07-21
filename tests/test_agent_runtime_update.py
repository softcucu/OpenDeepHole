import asyncio
import base64
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

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
        self.assertIn("attack-tree-threat-analysis.md", names)
        self.assertIn("attack-method-reference-catalog.md", names)
        self.assertIn("ctags-p6.2.20260517.0-x64/ctags.exe", names)
        self.assertFalse(any(name.startswith("checkers/") for name in names))
        self.assertNotIn("agent.yaml", names)
        self.assertNotIn("run_agent.sh", names)
        self.assertNotIn("run_agent.bat", names)
        self.assertFalse(any(name.startswith("backend/static/") for name in names))
        self.assertFalse(any(name.startswith("backend/system_skills/") for name in names))
        self.assertFalse(any("/vulnerability_validation/" in name for name in names))
        self.assertIn("agent/product_validators/demo/validator.yaml", names)
        self.assertIn("agent/product_validators/demo/validator.py", names)
        self.assertIn("agent/task_agent/standalone.py", names)
        self.assertIn("agent/task_agent/task-agent.example.yaml", names)
        self.assertNotIn("agent/validation_debug.py", names)

    def test_agent_download_zip_includes_launchers_config_and_bundled_ctags(self) -> None:
        data = agent_api._build_agent_zip("http://server.example", "owner-token")
        with zipfile.ZipFile(_bytes_path(data)) as zf:
            names = set(zf.namelist())
            agent_yaml = zf.read("agent.yaml").decode("utf-8")

        self.assertIn("run_agent.sh", names)
        self.assertIn("run_agent.bat", names)
        self.assertIn("requirements-agent.txt", names)
        self.assertIn("attack-tree-threat-analysis.md", names)
        self.assertIn("attack-method-reference-catalog.md", names)
        self.assertTrue(any(name.startswith("checkers/") for name in names))
        self.assertIn("ctags-p6.2.20260517.0-x64/ctags.exe", names)
        self.assertIn("agent/product_validators/demo/validator.yaml", names)
        self.assertIn("agent/product_validators/demo/validator.py", names)
        self.assertIn("agent/task_agent/standalone.py", names)
        self.assertIn("agent/task_agent/task-agent.example.yaml", names)
        self.assertNotIn("agent/validation_debug.py", names)
        self.assertIn('server_url: "http://server.example"', agent_yaml)
        self.assertIn('owner_token: "owner-token"', agent_yaml)
        parsed = yaml.safe_load(agent_yaml)
        self.assertEqual(parsed["schema_version"], 2)
        self.assertEqual(parsed["model_pool"]["models"], [])
        self.assertNotIn("llm_api", parsed)

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

    def test_mcp_sse_dependency_requires_multi_loop_safe_version(self) -> None:
        root = Path(__file__).resolve().parent.parent
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        agent_requirements = (root / "requirements-agent.txt").read_text(
            encoding="utf-8"
        )
        script_text = (root / "run_agent.sh").read_text(encoding="utf-8")
        batch_text = (root / "run_agent.bat").read_text(encoding="utf-8")

        self.assertIn("sse-starlette>=3.0.0", requirements.splitlines())
        self.assertIn("sse-starlette>=3.0.0", agent_requirements.splitlines())
        for text in (script_text, batch_text):
            self.assertIn("version('sse-starlette')", text)
            self.assertIn(">= 3", text)

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

    def test_runtime_hash_includes_product_validator_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent" / "product_validators").mkdir(parents=True)
            (root / "agent" / "main.py").write_text("print('agent')\n", encoding="utf-8")
            validator = root / "agent" / "product_validators" / "demo" / "__init__.py"
            validator.parent.mkdir()
            validator.write_text("print('v1')\n", encoding="utf-8")

            before = compute_runtime_hash(root)
            validator.write_text("print('v2')\n", encoding="utf-8")

            self.assertNotEqual(before, compute_runtime_hash(root))

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

    def test_runtime_install_replaces_product_validators_but_preserves_local_validation_dir(self) -> None:
        files = [
            ("agent/main.py", b"print('server snapshot')\n"),
            ("agent/product_validators/demo/validator.py", b"async def validate(**kwargs):\n    pass\n"),
            ("agent/product_validators/demo/validator.yaml", b"schema_version: 1\nproduct: LTE\nvalidation_environment: lab\n"),
            ("agent/server.py", b"# server\n"),
            ("agent/task_agent/api.py", b"async def run_opencode_task(**kwargs):\n    pass\n"),
            ("backend/api.py", b"# api\n"),
            ("requirements-agent.txt", b"requests\n"),
        ]
        archive = agent_api._build_agent_runtime_zip_from_files(files)
        expected_hash = agent_api._agent_runtime_hash_for_files(files)
        manifest = _runtime_manifest(files)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent" / "product_validators" / "custom").mkdir(parents=True)
            (root / "agent" / "product_validators" / "custom" / "validator.py").write_text(
                "async def validate(**kwargs):\n    pass\n",
                encoding="utf-8",
            )
            (root / "agent" / "vulnerability_validation").mkdir(parents=True)
            (root / "agent" / "vulnerability_validation" / "validator.py").write_text(
                "print('local validator')\n",
                encoding="utf-8",
            )
            (root / "agent" / "main.py").write_text("print('old')\n", encoding="utf-8")
            (root / "agent" / "stale.py").write_text("# stale\n", encoding="utf-8")
            (root / "agent" / "opencode").mkdir()
            (root / "agent" / "opencode" / "api.py").write_text(
                "# stale component package\n",
                encoding="utf-8",
            )
            (root / "backend").mkdir()
            (root / "backend" / "old.py").write_text("# old\n", encoding="utf-8")
            (root / "backend" / "opencode").mkdir()
            (root / "backend" / "opencode" / "serve_client.py").write_text(
                "# stale OpenCode client\n",
                encoding="utf-8",
            )
            (root / "requirements-agent.txt").write_text("old\n", encoding="utf-8")

            with patch("agent.updater.runtime_root", return_value=root):
                updater._install_update_archive(archive, expected_hash, manifest)

            self.assertFalse((root / "agent" / "product_validators" / "custom").exists())
            self.assertTrue((root / "agent" / "product_validators" / "demo" / "validator.yaml").is_file())
            self.assertEqual(
                (root / "agent" / "vulnerability_validation" / "validator.py").read_text(encoding="utf-8"),
                "print('local validator')\n",
            )
            self.assertFalse((root / "agent" / "stale.py").exists())
            self.assertFalse((root / "agent" / "opencode").exists())
            self.assertFalse((root / "backend" / "old.py").exists())
            self.assertFalse((root / "backend" / "opencode").exists())
            self.assertTrue((root / "agent" / "task_agent" / "api.py").is_file())
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

    def test_resume_command_checks_runtime_update_before_resume(self) -> None:
        calls: list[str] = []

        async def check_update(update: dict, command: dict) -> bool:
            calls.append("update")
            self.assertEqual(update, {"hash": "new-runtime"})
            self.assertEqual(command["retry_threat_audit_task_ids"], ["threat-timeout"])
            return False

        async def handle_resume(**kwargs) -> None:
            calls.append("resume")
            self.assertEqual(kwargs["retry_candidates"][0]["file"], "src/a.c")
            self.assertEqual(kwargs["retry_threat_audit_task_ids"], ["threat-timeout"])
            self.assertTrue(kwargs["resume_threat_analysis"])
            self.assertEqual(kwargs["scan_mode"], "threat_analysis_only")

        command = {
            "type": "resume",
            "scan_id": "scan-1",
            "project_path": "/repo/project",
            "code_scan_path": "/repo/project/src",
            "checkers": ["npd"],
            "scan_mode": "threat_analysis_only",
            "retry_candidates": [{"file": "src/a.c"}],
            "retry_total_candidates": 2,
            "retry_processed_offset": 1,
            "resume_threat_analysis": True,
            "retry_threat_audit_task_ids": ["threat-timeout"],
            "agent_runtime_update": {"hash": "new-runtime"},
        }
        with (
            patch("agent.updater.ensure_runtime_updated", new=check_update),
            patch("agent.server.handle_resume", new=handle_resume),
        ):
            asyncio.run(agent_main._handle_command(command, None, None, None))

        self.assertEqual(calls, ["update", "resume"])

    def test_runtime_update_preserves_resume_command_before_install_and_restart(self) -> None:
        calls: list[str] = []
        command = {
            "type": "resume",
            "scan_id": "scan-1",
            "retry_candidates": [{"file": "src/a.c"}],
            "retry_total_candidates": 2,
            "retry_processed_offset": 1,
            "resume_threat_analysis": True,
            "retry_threat_audit_task_ids": ["threat-timeout"],
            "agent_runtime_update": {"hash": "new-runtime"},
        }

        async def download(_update: dict) -> bytes:
            calls.append("download")
            return b"archive"

        original_save_pending_command = updater.save_pending_command

        def save_pending(saved: dict) -> None:
            calls.append("save")
            original_save_pending_command(saved)

        with tempfile.TemporaryDirectory() as tmp:
            pending_file = Path(tmp) / "pending_commands.json"
            with (
                patch.object(updater, "PENDING_COMMANDS_FILE", pending_file),
                patch("agent.updater.compute_runtime_hash", return_value="old-runtime"),
                patch("agent.updater._download_update", new=download),
                patch("agent.updater.save_pending_command", side_effect=save_pending),
                patch("agent.updater._install_update_archive", side_effect=lambda *_args: calls.append("install")),
                patch("agent.updater._install_requirements_if_needed", side_effect=lambda: calls.append("requirements")),
                patch("agent.updater._restart_process", side_effect=lambda: calls.append("restart")),
            ):
                updated = asyncio.run(
                    updater.ensure_runtime_updated(
                        {"hash": "new-runtime", "manifest": {"runtime_hash": "new-runtime"}},
                        command,
                    )
                )
                pending_commands = updater.load_pending_commands(clear=True)

        self.assertTrue(updated)
        self.assertEqual(calls, ["download", "save", "install", "requirements", "restart"])
        expected_command = dict(command)
        expected_command.pop("agent_runtime_update")
        self.assertEqual(pending_commands, [expected_command])

    def test_vulnerability_validation_command_checks_runtime_update_before_validation(self) -> None:
        update = AsyncMock(return_value=False)
        handler = AsyncMock()

        with (
            patch("agent.updater.ensure_runtime_updated", new=update),
            patch("agent.server.handle_vulnerability_validation", new=handler),
        ):
            asyncio.run(agent_main._handle_command(
                {
                    "type": "vulnerability_validation",
                    "scan_id": "scan-1",
                    "vuln_index": 0,
                    "project_path": "/repo/project",
                    "code_scan_path": "/repo/project",
                    "product": "LTE",
                    "validation_environment": "lab",
                    "vulnerability": {"file": "src/a.c", "line": 1},
                    "report_markdown": "# report\n",
                    "agent_runtime_update": {"hash": "new-runtime"},
                },
                None,
                None,
                None,
            ))

        update.assert_awaited_once()
        handler.assert_awaited_once()

    def test_vulnerability_validation_stops_when_forced_runtime_update_fails(self) -> None:
        update = AsyncMock(side_effect=RuntimeError("download unavailable"))
        handler = AsyncMock()
        reporter = AsyncMock()

        with (
            patch("agent.updater.ensure_runtime_updated", new=update),
            patch("agent.server.handle_vulnerability_validation", new=handler),
        ):
            asyncio.run(agent_main._handle_command(
                {
                    "type": "vulnerability_validation",
                    "scan_id": "scan-1",
                    "vuln_index": 0,
                    "project_path": "/repo/project",
                    "code_scan_path": "/repo/project",
                    "product": "LTE",
                    "validation_environment": "lab",
                    "vulnerability": {"file": "src/a.c", "line": 1},
                    "report_markdown": "# report\n",
                    "agent_runtime_update": {"hash": "new-runtime"},
                },
                None,
                None,
                reporter,
            ))

        update.assert_awaited_once()
        handler.assert_not_awaited()
        reported = reporter.report_vulnerability_validation.await_args.args[1]
        self.assertEqual(reported.status, "error")
        self.assertFalse(reported.running)
        self.assertIn("download unavailable", reported.final_output)


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
