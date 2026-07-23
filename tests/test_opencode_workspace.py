import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client import codegraph as codegraph_runtime
from deephole_client.opencode_integration import (
    build_opencode_config,
    get_global_opencode_workspace,
    managed_opencode_config_path,
    refresh_global_opencode_config,
    writable_edit_patterns,
)


def assert_opencode_read_permissions(
    testcase: unittest.TestCase,
    config: dict,
) -> None:
    permission = config.get("permission", {})
    for key in ("read", "list", "glob", "grep"):
        testcase.assertEqual(permission.get(key), {"*": "allow"})
    testcase.assertEqual(permission.get("external_directory"), {"*": "deny"})
    testcase.assertEqual(permission.get("edit"), {"*": "deny"})
    testcase.assertEqual(permission.get("bash"), {"*": "deny"})


class OpencodeWorkspaceTests(unittest.TestCase):
    def test_writable_edit_patterns_include_windows_slash_variants(self) -> None:
        path = PureWindowsPath(
            "C:/Users/demo/.opendeephole/fp_reviews/review/artifacts/1"
        )
        patterns = writable_edit_patterns(path)
        self.assertIn(
            r"C:\Users\demo\.opendeephole\fp_reviews\review\artifacts\1",
            patterns,
        )
        self.assertIn(
            "C:/Users/demo/.opendeephole/fp_reviews/review/artifacts/1/**",
            patterns,
        )

    def test_build_opencode_config_allows_explicit_writable_path(self) -> None:
        path = PureWindowsPath(
            "C:/Users/demo/.opendeephole/work/review"
        )
        fake_config = SimpleNamespace(
            code_graph=SimpleNamespace(enabled=False, name="codegraph"),
            product_info=SimpleNamespace(enabled=False, name="product-info"),
        )
        with patch(
            "deephole_client.opencode_integration.get_config",
            return_value=fake_config,
        ):
            config = build_opencode_config(
                "http://127.0.0.1:9123/mcp",
                writable_paths=[str(path)],
            )
        edit = config["permission"]["edit"]
        self.assertEqual(edit["*"], "deny")
        self.assertEqual(
            edit["C:/Users/demo/.opendeephole/work/review/**"],
            "allow",
        )

    def test_build_opencode_config_includes_managed_mcp_entries(self) -> None:
        fake_config = SimpleNamespace(
            code_graph=SimpleNamespace(
                enabled=True,
                name="codegraph",
                transport="local",
                timeout_seconds=45,
                local=SimpleNamespace(
                    executable="codegraph",
                    args=["serve", "--mcp"],
                    environment={"CODEGRAPH_MCP_TOOLS": "explore,node"},
                ),
            ),
            product_info=SimpleNamespace(
                enabled=True,
                name="product-info",
                transport="remote",
                timeout_seconds=12,
                remote=SimpleNamespace(
                    url="http://10.0.0.8:9000/mcp",
                    headers={"Authorization": "Bearer token"},
                ),
            ),
        )
        with (
            patch(
                "deephole_client.opencode_integration.get_config",
                return_value=fake_config,
            ),
            patch(
                "deephole_client.opencode_integration.shutil.which",
                return_value="/usr/bin/codegraph",
            ),
        ):
            config = build_opencode_config("http://127.0.0.1:9123/mcp")

        self.assertEqual(
            config["mcp"]["codegraph"]["command"],
            ["codegraph", "serve", "--mcp"],
        )
        self.assertEqual(config["mcp"]["product-info"]["type"], "remote")
        self.assertIs(config["mcp"]["product-info"]["oauth"], False)

    def test_codegraph_readiness_survives_restart_and_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            nested = root / "src" / "module"
            nested.mkdir(parents=True)
            database = root / ".codegraph" / "codegraph.db"
            database.parent.mkdir()
            database.write_bytes(b"sqlite")
            codegraph_runtime._ready_projects.clear()

            self.assertTrue(codegraph_runtime.is_codegraph_ready(nested))
            self.assertIn(root.resolve(), codegraph_runtime._ready_projects)

    def test_global_workspace_contains_only_generic_managed_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(
                mcp_server=SimpleNamespace(port=8100),
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)

            config = json.loads(
                managed_opencode_config_path(workspace).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                config["mcp"]["deephole-code"]["url"],
                "http://127.0.0.1:9123/mcp",
            )
            assert_opencode_read_permissions(self, config)
            self.assertNotIn("agent", config)
            self.assertFalse((workspace / ".opencode" / "skills").exists())

    def test_global_refresh_does_not_overwrite_live_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(
                mcp_server=SimpleNamespace(port=8100),
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace(mcp_port=9123)
                live_path = workspace / "opencode.json"
                live_path.write_text('{"sentinel": true}', encoding="utf-8")
                refresh_global_opencode_config()

            self.assertEqual(
                live_path.read_text(encoding="utf-8"),
                '{"sentinel": true}',
            )
