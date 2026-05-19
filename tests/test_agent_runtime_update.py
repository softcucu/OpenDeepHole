import asyncio
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
