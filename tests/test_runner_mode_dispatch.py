from __future__ import annotations

import ast
import importlib
import inspect
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


FRAMEWORK_PROCESS_ENTRIES = {
    "code_graph_build": "run_code_graph_build",
    "static_analysis": "run_static_analysis",
    "candidate_audit": "run_candidate_audit",
    "threat_audit": "run_threat_audit",
    "fp_review": "run_fp_review",
    "vulnerability_validation": "run_vulnerability_validation",
}
PROCESS_NAMES = set(FRAMEWORK_PROCESS_ENTRIES) | {"threat_analysis"}


def _assert_async_kwargs_entry(module: object, entry_name: str) -> None:
    entry = getattr(module, entry_name)
    signature = inspect.signature(entry)

    assert inspect.iscoroutinefunction(entry)
    assert len(signature.parameters) == 1
    parameter = next(iter(signature.parameters.values()))
    assert parameter.kind is inspect.Parameter.VAR_KEYWORD


def test_framework_process_packages_export_one_async_kwargs_entry() -> None:
    for package, entry_name in FRAMEWORK_PROCESS_ENTRIES.items():
        module = importlib.import_module(f"deephole_client.{package}")
        _assert_async_kwargs_entry(module, entry_name)
        assert list(module.__all__) == [entry_name]


def test_threat_analysis_uses_an_external_async_adapter() -> None:
    module = importlib.import_module("deephole_client.threat_analysis_runner")

    _assert_async_kwargs_entry(module, "run_threat_analysis")


def test_process_sources_do_not_import_platform_or_sibling_processes() -> None:
    client_root = Path(__file__).resolve().parents[1] / "deephole_client"
    violations: list[str] = []
    for package in PROCESS_NAMES:
        package_root = client_root / package
        for source in package_root.rglob("*.py"):
            tree = ast.parse(
                source.read_text(encoding="utf-8"),
                filename=str(source),
            )
            for node in ast.walk(tree):
                imported: list[str] = []
                if isinstance(node, ast.Import):
                    imported = [item.name for item in node.names]
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.level == 0
                    and node.module
                ):
                    imported = [node.module]
                for name in imported:
                    root = name.split(".", 1)[0]
                    if root in {"backend", "mcp_server", "deephole_client"}:
                        violations.append(
                            f"{source.relative_to(client_root)}:{node.lineno}:{name}"
                        )
                    if root in PROCESS_NAMES and root != package:
                        violations.append(
                            f"{source.relative_to(client_root)}:{node.lineno}:{name}"
                        )

    assert violations == []


def test_framework_processes_can_be_imported_and_show_cli_help_after_extraction() -> None:
    repository = Path(__file__).resolve().parents[1]
    source_client = repository / "deephole_client"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for package, entry_name in FRAMEWORK_PROCESS_ENTRIES.items():
            target = root / package
            target.mkdir()
            shutil.copytree(
                repository / "task_agent",
                target / "task_agent",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copytree(
                source_client / package,
                target / package,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )

            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(target)
            imported = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        f"import {package} as component; "
                        f"assert component.__all__ == ['{entry_name}']; "
                        f"assert callable(component.{entry_name})"
                    ),
                ],
                cwd=target,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert imported.returncode == 0, imported.stderr

            help_result = subprocess.run(
                [sys.executable, "-m", package, "--help"],
                cwd=target,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert help_result.returncode == 0, (
                f"{package}: {help_result.stderr}"
            )
            assert "usage:" in help_result.stdout.lower()


def test_native_threat_analysis_can_be_imported_after_extraction() -> None:
    repository = Path(__file__).resolve().parents[1]
    source_client = repository / "deephole_client"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(
            repository / "task_agent",
            root / "task_agent",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        shutil.copytree(
            source_client / "threat_analysis",
            root / "threat_analysis_harness",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(root)
        imported = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import threat_analysis_harness as component; "
                    "assert callable(component.run_threat_analysis)"
                ),
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        assert imported.returncode == 0, imported.stderr


def test_static_and_audit_rule_resources_are_physically_separate() -> None:
    client_root = Path(__file__).resolve().parents[1] / "deephole_client"
    static_root = client_root / "static_analysis" / "rules"
    audit_root = client_root / "candidate_audit" / "rules"

    assert list(static_root.rglob("analyzer.py"))
    assert list(audit_root.rglob("SKILL.md"))
    assert not list(static_root.rglob("SKILL.md"))
    assert not list(audit_root.rglob("analyzer.py"))


@pytest.mark.parametrize(
    "relative_path",
    [
        "fp_reviewer.py",
        "opencode_workflows.py",
        "threat_auditor.py",
        "threat_analysis_cli.py",
        "threat_analysis_opencode.py",
        "threat_analysis_workspace.py",
    ],
)
def test_old_coupled_business_modules_are_removed(relative_path: str) -> None:
    client_root = Path(__file__).resolve().parents[1] / "deephole_client"
    assert not (client_root / relative_path).exists()
