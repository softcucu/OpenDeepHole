import os
import tempfile
import unittest
from pathlib import Path

import yaml

from deephole_client.config import AgentConfig
from deephole_client.scanner import _configure_backend


class AgentResultPathTests(unittest.TestCase):
    def test_agent_backend_config_uses_scan_dir_for_results(self) -> None:
        old_config_path = os.environ.get("CONFIG_PATH")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                scan_dir = Path(tmp) / "scans" / "scan-123"
                scan_dir.mkdir(parents=True)

                _configure_backend(AgentConfig(), scan_dir)

                raw = yaml.safe_load((scan_dir / "config.yaml").read_text(encoding="utf-8"))
                self.assertEqual(raw["storage"]["scans_dir"], str(scan_dir))
                self.assertEqual(raw["storage"]["projects_dir"], str(scan_dir.parent))
        finally:
            if old_config_path is None:
                os.environ.pop("CONFIG_PATH", None)
            else:
                os.environ["CONFIG_PATH"] = old_config_path

            import backend.config as _cfg
            _cfg._config = None

            import backend.registry as _reg
            _reg._registry = None


if __name__ == "__main__":
    unittest.main()
