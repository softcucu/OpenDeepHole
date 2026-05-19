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
        self.assertNotIn("agent.yaml", names)
        self.assertNotIn("run_agent.sh", names)
        self.assertNotIn("run_agent.bat", names)
        self.assertFalse(any(name.startswith("backend/static/") for name in names))

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
