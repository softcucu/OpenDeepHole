import tempfile
import unittest
from pathlib import Path

from backend.config import StorageConfig, load_config


class ConfigPathTests(unittest.TestCase):
    def test_default_storage_uses_repo_sibling_data_dir(self) -> None:
        config = StorageConfig()

        self.assertTrue(config.projects_dir.endswith("/OpenDeepHoleData/projects"))
        self.assertTrue(config.scans_dir.endswith("/OpenDeepHoleData/scans"))
        self.assertNotIn("/tmp/opendeephole", config.projects_dir)
        self.assertNotIn("/tmp/opendeephole", config.scans_dir)

    def test_relative_storage_paths_resolve_from_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "nested" / "config.yaml"
            cfg.parent.mkdir()
            cfg.write_text(
                "storage:\n"
                "  projects_dir: \"../OpenDeepHoleData/projects\"\n"
                "  scans_dir: \"../OpenDeepHoleData/scans\"\n",
                encoding="utf-8",
            )

            config = load_config(str(cfg))

            self.assertEqual(
                config.storage.projects_dir,
                str((root / "OpenDeepHoleData" / "projects").resolve()),
            )
            self.assertEqual(
                config.storage.scans_dir,
                str((root / "OpenDeepHoleData" / "scans").resolve()),
            )

    def test_scan_catalog_is_not_part_of_global_config(self) -> None:
        config = load_config("/path/that/does/not/exist.yaml")

        self.assertFalse(hasattr(config, "scan"))

    def test_legacy_scan_catalog_yaml_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.yaml"
            cfg.write_text(
                "scan:\n"
                "  products:\n"
                "    - LTE\n"
                "    - Custom\n"
                "  validation_environments:\n"
                "    - 仿真UBBPi板环境\n"
                "    - 实验室环境\n",
                encoding="utf-8",
            )

            config = load_config(str(cfg))

        self.assertFalse(hasattr(config, "scan"))


if __name__ == "__main__":
    unittest.main()
