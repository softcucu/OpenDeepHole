import tempfile
import unittest
from pathlib import Path

from backend.models import ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore
from backend.threat_analysis import parse_threat_analysis_data, parse_threat_analysis_file


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

    def test_parse_file_accepts_fenced_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "res.json"
            path.write_text('```json\n{"schema_version":"1.0","assets":[]}\n```\n', encoding="utf-8")

            analysis = parse_threat_analysis_file(path)

            self.assertEqual(analysis.schema_version, "1.0")
            self.assertEqual(analysis.assets, [])


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
