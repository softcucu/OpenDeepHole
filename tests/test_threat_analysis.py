import tempfile
import unittest
import time
from pathlib import Path

from agent.threat_auditor import _scan_path_from_analysis, build_threat_audit_tasks
from backend.opencode.runner import _read_fresh_threat_analysis_result
from backend.models import ScanItemStatus, ScanMeta, ScanStatus, ThreatAuditTask, Vulnerability
from backend.store.sqlite import SqliteScanStore
from backend.threat_analysis import (
    append_or_merge_attack_path,
    apply_threat_analysis_scan_scope,
    build_analysis_from_attack_paths,
    parse_threat_analysis_data,
    parse_attack_path_data,
    parse_threat_analysis_file,
    threat_analysis_scope_matches,
    write_threat_analysis_file,
)


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


class ThreatAnalysisParserTests(unittest.TestCase):
    def test_parse_attack_tree_res_json_shape(self) -> None:
        analysis = parse_threat_analysis_data({
            "schema_version": "1.0",
            "analysis_id": "ATA-001",
            "sources": {"repositories": ["."], "documents": []},
            "scan_scope": {
                "project_path": "/tmp/project",
                "code_scan_path": "/tmp/project/src",
                "code_scan_relative_path": "src",
            },
            "assets": [
                {
                    "asset_id": "ASSET-001",
                    "name": "基站服务",
                    "asset_type": "service",
                    "criticality": "critical",
                    "risks": [
                        {
                            "risk_id": "RISK-001",
                            "name": "服务不可用",
                            "security_property": "availability",
                        }
                    ],
                }
            ],
            "attack_trees": [
                {
                    "tree_id": "TREE-001",
                    "asset_id": "ASSET-001",
                    "risk_id": "RISK-001",
                    "attack_goal": "造成基站服务中断",
                    "root_node_id": "NODE-001",
                    "nodes": [
                        {"node_id": "NODE-001", "parent_id": None, "node_type": "goal", "name": "造成基站服务中断", "order": 1},
                        {"node_id": "NODE-002", "parent_id": "NODE-001", "node_type": "domain", "name": "管理面", "order": 1},
                        {"node_id": "NODE-003", "parent_id": "NODE-002", "node_type": "surface", "name": "管理接口", "surface_type": "api", "order": 1},
                        {"node_id": "NODE-004", "parent_id": "NODE-003", "node_type": "method", "name": "口令爆破", "order": 1, "preconditions": ["允许远程登录"]},
                    ],
                }
            ],
            "code_path_mappings": [
                {
                    "surface_node_id": "NODE-003",
                    "code_paths": [{"path": "src/api", "description": "管理接口"}],
                }
            ],
        })

        self.assertEqual(analysis.assets[0].name, "基站服务")
        self.assertEqual(analysis.assets[0].risks[0].security_property, "availability")
        self.assertEqual(analysis.attack_trees[0].nodes[-1].preconditions, ["允许远程登录"])
        self.assertEqual(analysis.code_path_mappings[0].code_paths[0].path, "src/api")
        self.assertEqual(analysis.scan_scope.code_scan_relative_path, "src")

    def test_parse_v11_attack_paths_and_interfaces(self) -> None:
        analysis = parse_threat_analysis_data({
            "schema_version": "1.1",
            "sources": {
                "repositories": ["."],
                "documents": [],
                "mcp_available": True,
                "product_mcp_name": "product-info",
            },
            "high_risk_external_interfaces": [
                {
                    "interface_id": "IF-1",
                    "name": "管理 API",
                    "interface_type": "api",
                    "candidate_code_paths": ["src/api"],
                    "source": "mcp_and_code",
                }
            ],
            "attack_paths": [
                {
                    "path_id": "AP-1",
                    "fingerprint": "fp-1",
                    "asset_id": "ASSET-1",
                    "asset_name": "管理员权限",
                    "risk_id": "RISK-1",
                    "risk_name": "管理员权限被未授权获取",
                    "attack_goal_id": "GOAL-1",
                    "attack_goal_name": "绕过管理面身份认证",
                    "attack_surface_id": "SURFACE-1",
                    "attack_surface_name": "管理 API",
                    "attack_method_id": "METHOD-1",
                    "attack_method_name": "认证绕过",
                    "code_paths": [{"path": "src/api", "description": "管理接口"}],
                    "source": "mcp_and_code",
                }
            ],
        })

        self.assertTrue(analysis.sources.mcp_available)
        self.assertEqual(analysis.sources.product_mcp_name, "product-info")
        self.assertEqual(analysis.high_risk_external_interfaces[0].candidate_code_paths[0].path, "src/api")
        self.assertEqual(analysis.attack_paths[0].attack_method_name, "认证绕过")

    def test_attack_paths_jsonl_merges_and_rebuilds_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stream_path = Path(tmp) / "runs" / "scan-1" / "stream" / "attack_paths.jsonl"
            first = parse_attack_path_data({
                "asset": {"name": "管理员权限"},
                "risk": {"name": "管理员权限被未授权获取"},
                "attack_goal": {"name": "绕过管理面身份认证"},
                "attack_domain": {"name": "管理面"},
                "attack_surface": {"name": "管理 API", "surface_type": "api"},
                "attack_method": {"name": "认证绕过"},
                "code_paths": [{"path": "src/api", "description": "管理 API"}],
                "evidence": ["route found"],
                "source": "code",
            })
            duplicate = parse_attack_path_data({
                **first.model_dump(),
                "preconditions": ["攻击者可访问管理 API"],
                "evidence": ["auth middleware found"],
                "source": "mcp",
            })

            merged = append_or_merge_attack_path(stream_path, first)
            merged = append_or_merge_attack_path(stream_path, duplicate)

            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0].source, "mcp_and_code")
            self.assertIn("攻击者可访问管理 API", merged[0].preconditions)
            analysis = build_analysis_from_attack_paths(
                merged,
                analysis_id="ATA-JSONL",
                sources=parse_threat_analysis_data({
                    "sources": {"repositories": ["."]}
                }).sources,
                scan_scope=parse_threat_analysis_data({}).scan_scope,
            )
            self.assertEqual(analysis.schema_version, "1.1")
            self.assertEqual(len(analysis.assets), 1)
            self.assertEqual(len(analysis.attack_trees), 1)
            self.assertEqual(analysis.code_path_mappings[0].code_paths[0].path, "src/api")

    def test_build_threat_audit_tasks_from_surface_methods_ignores_paths(self) -> None:
        payload = {
            "schema_version": "1.0",
            "analysis_id": "ATA-001",
            "assets": [
                {
                    "asset_id": "ASSET-001",
                    "name": "基站服务",
                    "risks": [{"risk_id": "RISK-001", "name": "服务不可用"}],
                }
            ],
            "attack_trees": [
                {
                    "tree_id": "TREE-001",
                    "asset_id": "ASSET-001",
                    "risk_id": "RISK-001",
                    "attack_goal": "造成基站服务中断",
                    "root_node_id": "NODE-001",
                    "nodes": [
                        {"node_id": "NODE-001", "node_type": "goal", "name": "造成基站服务中断"},
                        {"node_id": "NODE-002", "parent_id": "NODE-001", "node_type": "domain", "name": "管理面"},
                        {"node_id": "NODE-003", "parent_id": "NODE-002", "node_type": "surface", "name": "管理接口"},
                        {"node_id": "NODE-004", "parent_id": "NODE-003", "node_type": "method", "name": "认证绕过", "order": 1},
                        {"node_id": "NODE-005", "parent_id": "NODE-003", "node_type": "method", "name": "接口泛洪", "order": 2},
                    ],
                }
            ],
            "code_path_mappings": [
                {
                    "surface_node_id": "NODE-003",
                    "code_paths": [
                        {"path": "src/api", "description": "管理接口实现"},
                        {"path": "src/api/v2", "description": "管理接口新实现"},
                    ],
                }
            ],
        }
        analysis = parse_threat_analysis_data(payload)

        tasks = build_threat_audit_tasks("scan-1", analysis)

        self.assertEqual(len(tasks), 2)
        self.assertEqual({task.method_name for task in tasks}, {"认证绕过", "接口泛洪"})
        self.assertTrue(all(task.code_path == "" for task in tasks))
        self.assertTrue(all(task.code_path_description == "" for task in tasks))
        self.assertTrue(all(task.task_id.startswith("threat-audit-") for task in tasks))
        self.assertIn("攻击面节点", tasks[0].description)
        self.assertNotIn("代码路径", tasks[0].description)

        pathless = parse_threat_analysis_data({
            **payload,
            "code_path_mappings": [{"surface_node_id": "NODE-003", "code_paths": []}],
        })
        pathless_tasks = build_threat_audit_tasks("scan-1", pathless)

        self.assertEqual([task.task_id for task in pathless_tasks], [task.task_id for task in tasks])

    def test_build_threat_audit_tasks_prefers_attack_paths(self) -> None:
        analysis = parse_threat_analysis_data({
            "schema_version": "1.1",
            "attack_paths": [
                {
                    "path_id": "AP-1",
                    "fingerprint": "fp-1",
                    "asset_id": "ASSET-1",
                    "asset_name": "管理员权限",
                    "risk_id": "RISK-1",
                    "risk_name": "管理员权限被未授权获取",
                    "attack_goal_id": "GOAL-1",
                    "attack_goal_name": "绕过管理面身份认证",
                    "attack_surface_id": "SURFACE-1",
                    "attack_surface_name": "管理 API",
                    "attack_method_id": "METHOD-1",
                    "attack_method_name": "认证绕过",
                    "code_paths": [{"path": "src/api"}, {"path": "src/auth"}],
                }
            ],
            "attack_trees": [
                {
                    "tree_id": "TREE-OLD",
                    "asset_id": "ASSET-OLD",
                    "risk_id": "RISK-OLD",
                    "nodes": [],
                }
            ],
        })

        tasks = build_threat_audit_tasks("scan-1", analysis)

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].attack_path_id, "AP-1")
        self.assertEqual(tasks[0].attack_path_fingerprint, "fp-1")
        self.assertEqual([item.path for item in tasks[0].code_paths], ["src/api", "src/auth"])

    def test_parse_file_accepts_fenced_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "res.json"
            path.write_text('```json\n{"schema_version":"1.0","assets":[]}\n```\n', encoding="utf-8")

            analysis = parse_threat_analysis_file(path)

            self.assertEqual(analysis.schema_version, "1.0")
            self.assertEqual(analysis.assets, [])

    def test_apply_scan_scope_marks_subdirectory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            analysis = parse_threat_analysis_data({"schema_version": "1.0", "assets": []})

            scoped = apply_threat_analysis_scan_scope(analysis, project, scan_root)

            self.assertEqual(scoped.scan_scope.project_path, project.resolve().as_posix())
            self.assertEqual(scoped.scan_scope.code_scan_path, scan_root.resolve().as_posix())
            self.assertEqual(scoped.scan_scope.code_scan_relative_path, "src")
            self.assertTrue(threat_analysis_scope_matches(scoped, project, scan_root))
            self.assertFalse(threat_analysis_scope_matches(scoped, project, project))

    def test_threat_audit_scan_path_uses_analysis_scan_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            analysis = apply_threat_analysis_scan_scope(
                parse_threat_analysis_data({"schema_version": "1.0", "assets": []}),
                project,
                scan_root,
            )

            self.assertEqual(
                _scan_path_from_analysis(analysis, project),
                scan_root.resolve().as_posix(),
            )

    def test_write_scan_scope_to_result_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            result_path = project / "res.json"
            analysis = apply_threat_analysis_scan_scope(
                parse_threat_analysis_data({"analysis_id": "ATA-SCOPE", "assets": []}),
                project,
                scan_root,
            )

            write_threat_analysis_file(result_path, analysis)
            loaded = parse_threat_analysis_file(result_path)

            self.assertEqual(loaded.analysis_id, "ATA-SCOPE")
            self.assertEqual(loaded.scan_scope.code_scan_relative_path, "src")

    def test_runner_read_result_writes_scan_scope_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            result_path = project / "res.json"
            result_path.write_text('{"analysis_id":"ATA-RUNNER","assets":[]}', encoding="utf-8")

            analysis = _read_fresh_threat_analysis_result(
                result_path,
                None,
                time.time(),
                None,
                project_dir=project,
                code_scan_path=scan_root,
            )
            loaded = parse_threat_analysis_file(result_path)

            self.assertIsNotNone(analysis)
            self.assertEqual(analysis.scan_scope.code_scan_relative_path, "src")
            self.assertEqual(loaded.scan_scope.code_scan_relative_path, "src")


class ThreatAnalysisStoreTests(unittest.TestCase):
    def test_replace_and_get_threat_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_scan("scan-1"))
            analysis = parse_threat_analysis_data({
                "schema_version": "1.0",
                "analysis_id": "ATA-STORE",
                "assets": [{"asset_id": "A1", "name": "资产"}],
            })

            stored = store.replace_threat_analysis("scan-1", analysis)
            loaded = store.get_threat_analysis("scan-1")
            scan, _meta = store.load_scan("scan-1")  # type: ignore[misc]

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.analysis_id, "ATA-STORE")
            self.assertTrue(stored.updated_at)
            self.assertEqual(scan.threat_analysis.analysis_id, "ATA-STORE")

    def test_threat_audit_tasks_and_source_fields_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(*_scan("scan-1"))
            task = ThreatAuditTask(
                task_id="threat-audit-1",
                surface_node_id="SURFACE-1",
                surface_name="管理接口",
                method_node_id="METHOD-1",
                method_name="认证绕过",
                code_path="src/api",
                code_paths=[
                    {"path": "src/api", "description": "管理接口"},
                    {"path": "src/auth", "description": "认证逻辑"},
                ],
                attack_path_id="AP-1",
                attack_path_fingerprint="fp-1",
                status="completed",
                result_vuln_indexes=[0],
            )
            vuln = Vulnerability(
                file="src/api/auth.c",
                line=12,
                function="auth",
                vuln_type="threat_audit",
                severity="high",
                description="认证绕过",
                ai_analysis="analysis",
                confirmed=True,
                ai_verdict="confirmed",
                analysis_source="threat_audit",
                source_task_id=task.task_id,
                threat_surface_node_id=task.surface_node_id,
                threat_method_node_id=task.method_node_id,
                threat_code_path=task.code_path,
            )

            stored_task = store.upsert_threat_audit_task("scan-1", task)
            store.add_vulnerability("scan-1", vuln)
            loaded_scan, _meta = store.load_scan("scan-1")  # type: ignore[misc]

            self.assertEqual(stored_task.scan_id, "scan-1")
            self.assertEqual(loaded_scan.threat_audit_tasks[0].method_name, "认证绕过")
            self.assertEqual(loaded_scan.threat_audit_tasks[0].attack_path_id, "AP-1")
            self.assertEqual(loaded_scan.threat_audit_tasks[0].attack_path_fingerprint, "fp-1")
            self.assertEqual(
                [item.path for item in loaded_scan.threat_audit_tasks[0].code_paths],
                ["src/api", "src/auth"],
            )
            self.assertEqual(loaded_scan.threat_audit_tasks[0].result_vuln_indexes, [0])
            self.assertEqual(loaded_scan.vulnerabilities[0].analysis_source, "threat_audit")
            self.assertEqual(loaded_scan.vulnerabilities[0].source_task_id, "threat-audit-1")
