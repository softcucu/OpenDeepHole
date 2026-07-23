from __future__ import annotations

import asyncio
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.models import ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore
from backend.threat_data import parse_threat_analysis_data
from deephole_client.process_artifacts import collect_json_artifacts
from deephole_client.threat_analysis import run_threat_analysis
from deephole_client.threat_audit.runner import _tasks
from task_agent import OpenCodeResult, run_opencode_task, run_sync_component
from task_agent.task_service import get_opencode_execution_context


def _artifact_bundle() -> dict:
    return {
        "entrypoint_result": {
            "result": True,
            "value_asset_path": "final/value-assets.json",
            "attack_tree_path": "final/attack-trees.json",
            "high_risk_modules_path": "final/high-risk-modules.json",
        },
        "artifacts": {
            "value_asset_path": {
                "path": "final/value-assets.json",
                "content": [{"资产名": "凭据"}],
            },
            "attack_tree_path": {
                "path": "final/attack-trees.json",
                "content": {"attack_trees": []},
            },
            "high_risk_modules_path": {
                "path": "final/high-risk-modules.json",
                "content": [],
            },
        },
    }


def _scan(scan_id: str) -> tuple[ScanStatus, ScanMeta]:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id="project",
        scan_items=["npd"],
        created_at="2026-01-01T00:00:00+00:00",
        status=ScanItemStatus.COMPLETE,
        progress=1.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["npd"],
        created_at=scan.created_at,
        project_path="/tmp/project",
        scan_name="project",
        user_id="user-1",
    )
    return scan, meta


def test_vendored_harness_contains_native_entry_and_private_skills() -> None:
    root = (
        Path(__file__).resolve().parents[1]
        / "deephole_client"
        / "threat_analysis"
        / "threat_analysis_harness"
    )

    assert (root / "threat_analysis.py").is_file()
    assert (root / "task_agent_submitter.py").is_file()
    assert (root / "skills/value-assets/value-asset-map/SKILL.md").is_file()
    assert (
        root / "skills/high-risk-modules/high-risk-module-merge/SKILL.md"
    ).is_file()
    assert (
        root / "skills/attack-trees/attack-tree-by-asset/SKILL.md"
    ).is_file()


def test_async_facade_calls_sync_native_entry_and_preserves_native_result(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    output_path = tmp_path / "output"
    project.mkdir()
    events: list[dict] = []
    captured: dict = {}
    native_result = {
        "result": True,
        "value_asset_path": str(output_path / "value-assets.json"),
        "attack_tree_path": str(output_path / "attack-trees.json"),
        "high_risk_modules_path": str(output_path / "high-risk-modules.json"),
    }

    def native_entry(**kwargs):
        context = get_opencode_execution_context()
        captured.update({
            "kwargs": kwargs,
            "project_dir": context.project_dir,
            "work_dir": context.work_dir,
            "skill_paths": context.skill_paths,
        })
        return native_result

    async def scenario() -> dict:
        with patch(
            "deephole_client.threat_analysis.runner._load_implementation",
            return_value=SimpleNamespace(run_threat_analysis=native_entry),
        ):
            return await run_threat_analysis(
                code_path=project,
                output_path=output_path,
                is_resume=True,
                product_mcp="product-info",
                attack_modes={"network": True},
                output=events.append,
            )

    result = asyncio.run(scenario())

    assert result is native_result
    assert captured["kwargs"] == {
        "code_path": project.resolve(),
        "output_path": output_path.resolve(),
        "is_resume": True,
        "product_mcp": "product-info",
        "attack_modes": {"network": True},
    }
    assert captured["project_dir"] == project.resolve()
    assert captured["work_dir"] == output_path.resolve()
    assert len(captured["skill_paths"]) == 3
    assert events[0]["process"] == "threat_analysis"
    assert events[-1]["kind"] == "artifact"


def test_sync_component_can_call_async_task_agent_on_owner_loop() -> None:
    async def scenario() -> None:
        owner_loop = asyncio.get_running_loop()
        owner_thread = threading.get_ident()
        observed: dict = {}

        async def fake_local(**kwargs):
            observed["loop"] = asyncio.get_running_loop()
            observed["task_name"] = kwargs["task_name"]
            return OpenCodeResult(
                session_id="session-1",
                status="success",
                text="ok",
                structured=None,
                model="test/model",
            )

        def sync_entry() -> OpenCodeResult:
            observed["worker_thread"] = threading.get_ident()
            return asyncio.run(run_opencode_task(
                task_name="native-sync-task",
                task_type="threat_analysis",
                prompt="inspect",
                required_capability="high",
            ))

        with patch("task_agent.api._run_opencode_task_local", new=fake_local):
            result = await run_sync_component(sync_entry)

        assert result.status == "success"
        assert observed["loop"] is owner_loop
        assert observed["worker_thread"] != owner_thread
        assert observed["task_name"] == "native-sync-task"

    asyncio.run(scenario())


def test_collect_json_artifacts_keeps_native_result_and_loads_content(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    files = {
        "value_asset_path": ("value-assets.json", [{"资产名": "凭据"}]),
        "attack_tree_path": ("attack-trees.json", {"attack_trees": []}),
        "high_risk_modules_path": ("high-risk-modules.json", []),
    }
    native_result: dict = {"result": True}
    for key, (filename, content) in files.items():
        path = output_root / filename
        path.write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
        native_result[key] = str(path)

    bundle = collect_json_artifacts(native_result, output_root=output_root)

    assert bundle["entrypoint_result"]["result"] is True
    assert bundle["entrypoint_result"]["value_asset_path"] == "value-assets.json"
    assert bundle["artifacts"]["value_asset_path"]["content"][0]["资产名"] == "凭据"


def test_collect_json_artifacts_rejects_output_root_escape(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes output root"):
        collect_json_artifacts(
            {"result": True, "attack_tree_path": str(outside)},
            output_root=output_root,
        )


def test_opaque_artifact_bundle_round_trips_without_schema_conversion() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = SqliteScanStore(Path(tmp) / "scan.db")
        store.save_scan(*_scan("scan-1"))
        bundle = _artifact_bundle()
        parsed = parse_threat_analysis_data(bundle)

        stored = store.replace_threat_analysis("scan-1", parsed)
        loaded = store.get_threat_analysis("scan-1")
        scan, _meta = store.load_scan("scan-1")  # type: ignore[misc]

        assert stored == bundle
        assert loaded == bundle
        assert scan.threat_analysis == bundle


def test_threat_audit_creates_one_task_for_each_native_attack_pattern() -> None:
    attack_tree_data = {
        "attack_trees": [{
            "tree_id": "TREE-1",
            "value_asset": {
                "asset_name": "管理权限",
                "asset_category": "服务资产",
            },
            "nodes": [],
            "attack_paths": [{
                "path_id": "PATH-1",
                "path_name": "绕过认证",
                "path_description": "从管理入口到权限资产",
                "related_high_risk_modules": [
                    {
                        "module_name": "管理接口",
                        "node_id": "NODE-1",
                        "association_description": "外部输入入口",
                    },
                    {
                        "module_name": "认证模块",
                        "node_id": "NODE-2",
                        "association_description": "验证凭据",
                    },
                ],
                "attack_patterns": [
                    {
                        "pattern_id": "PATTERN-1",
                        "pattern_name": "弱口令",
                        "association_description": "猜测凭据",
                    },
                    {
                        "pattern_id": "PATTERN-2",
                        "pattern_name": "会话伪造",
                        "association_description": "伪造会话",
                    },
                ],
            }],
        }],
    }
    high_risk_modules = [
        {
            "模块名称": "管理接口",
            "代码目录": ["src/api", "src/common"],
            "面临威胁": "未授权访问",
        },
        {
            "模块名称": "认证模块",
            "代码目录": "src/auth",
            "面临威胁": "认证绕过",
        },
    ]

    tasks = _tasks("scan-1", attack_tree_data, high_risk_modules)

    assert [task["method_name"] for task in tasks] == ["弱口令", "会话伪造"]
    assert len({task["task_id"] for task in tasks}) == 2
    assert [path["path"] for path in tasks[0]["code_paths"]] == [
        "src/api",
        "src/common",
        "src/auth",
    ]
    assert all(task["attack_path_id"] == "PATH-1" for task in tasks)
