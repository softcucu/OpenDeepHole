import asyncio
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import agent.updater as updater
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
        import agent.server as agent_server

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


def _bytes_path(data: bytes):
    import io

    return io.BytesIO(data)


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
