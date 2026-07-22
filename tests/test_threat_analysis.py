import asyncio
import json
import re
import tempfile
import unittest
import time
from pathlib import Path

from deephole_client.scanner import (
    _is_streaming_threat_analysis,
    _opencode_pool_has_pipeline_work,
    _streaming_threat_analysis_id,
)
from deephole_client.threat_auditor import _scan_path_from_analysis, build_threat_audit_tasks
from deephole_client.threat_analysis_opencode import (
    _attack_goals_from_base_output,
    _base_model_agent_shards,
    _invoke_stage,
    _merge_base_model_outputs,
    _run_base_model_agents,
    _stage_prompt,
    _validate_stage_output,
    _with_attack_path_defaults,
    _with_method_confirmation_task_defaults,
)
from backend.threat_analysis.harness import build_code_index
from deephole_client.opencode_workflows import _read_fresh_threat_analysis_result
from task_agent import OpenCodeResult
from task_agent.task_service import get_opencode_execution_context
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
    def test_opencode_pool_pipeline_work_ignores_post_scan_fp_review(self) -> None:
        self.assertFalse(
            _opencode_pool_has_pipeline_work(
                {
                    "planned_tasks": [{"task_type": "fp_review"}],
                    "queued_tasks": [],
                    "models": [
                        {
                            "active_tasks": [
                                {"task_type": "fp_review"},
                            ],
                        },
                    ],
                }
            )
        )
        self.assertTrue(
            _opencode_pool_has_pipeline_work(
                {
                    "planned_tasks": [],
                    "queued_tasks": [{"task_type": "threat_analysis"}],
                    "models": [],
                }
            )
        )
        self.assertTrue(
            _opencode_pool_has_pipeline_work(
                {
                    "planned_tasks": [],
                    "queued_tasks": [],
                    "models": [
                        {
                            "active_tasks": [
                                {"task_type": "threat_audit"},
                            ],
                        },
                    ],
                }
            )
        )

    def test_stage_prompt_requires_chinese_display_text(self) -> None:
        prompt = _stage_prompt(
            skill_name="threat-attack-surface-agent",
            input_path=Path("/tmp/input.json"),
            output_path=Path("/tmp/output.json"),
            task_label="攻击面分析 1/1",
        )

        self.assertIn("所有面向用户展示的自然语言字段必须使用中文", prompt)
        self.assertIn("英文严重性标签", prompt)
        self.assertIn("不要把 `ASSET-*`", prompt)
        self.assertIn("唯一上级上下文", prompt)

    def test_stage_validation_rejects_base_model_attack_paths(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "out-of-scope"):
            _validate_stage_output(
                "threat-asset-interface-agent",
                {
                    "assets": [],
                    "high_risk_external_interfaces": [],
                    "asset_interface_links": [],
                    "risks": [],
                    "attack_goals": [],
                    "attack_paths": [
                        {
                            "attack_method_name": "泛洪攻击",
                            "code_paths": [{"path": "src/amf/context.cpp"}],
                        }
                    ],
                },
            )

    def test_stage_validation_rejects_generated_or_missing_method_names(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "readable display label"):
            _validate_stage_output(
                "threat-attack-surface-agent",
                {
                    "methods": [
                        {
                            "method_id": "METHOD-UE-CONTEXT-STEAL",
                            "name": "METHOD-UE-CONTEXT-STEAL",
                        }
                    ],
                    "attack_paths": [],
                    "method_confirmation_tasks": [],
                },
            )

        with self.assertRaisesRegex(RuntimeError, "readable attack method name"):
            _validate_stage_output(
                "threat-method-confirm-agent",
                {
                    "attack_paths": [
                        {
                            "attack_method_id": "METHOD-UE-CONTEXT-STEAL",
                            "code_paths": [{"path": "src/amf/context.cpp"}],
                        }
                    ],
                },
            )

    def test_stage_validation_rejects_attack_path_method_mismatch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "attack method must match one item in methods"):
            _validate_stage_output(
                "threat-attack-surface-agent",
                {
                    "methods": [
                        {
                            "method_id": "METHOD-AUTH-BYPASS",
                            "name": "认证绕过",
                        }
                    ],
                    "attack_paths": [
                        {
                            "attack_method_id": "METHOD-FLOOD",
                            "attack_method_name": "接口泛洪",
                            "code_paths": [{"path": "src/api.cpp"}],
                        }
                    ],
                    "method_confirmation_tasks": [],
                },
            )

    def test_build_code_index_limits_scope_to_cpp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan_root = root / "src"
            (scan_root / "api").mkdir(parents=True)
            (scan_root / "core").mkdir(parents=True)
            (scan_root / "web").mkdir(parents=True)
            (scan_root / "api" / "auth.cpp").write_text("int auth() { return 0; }\n", encoding="utf-8")
            (scan_root / "core" / "config.hpp").write_text("#pragma once\n", encoding="utf-8")
            (scan_root / "web" / "app.ts").write_text("export const app = 1;\n", encoding="utf-8")
            (scan_root / "server.py").write_text("def main(): pass\n", encoding="utf-8")
            (scan_root / "CMakeLists.txt").write_text("add_executable(app api/auth.cpp)\n", encoding="utf-8")
            (scan_root / "package.json").write_text("{}", encoding="utf-8")

            index = build_code_index(root, scan_root)

        self.assertEqual(
            set(index["files"]),
            {"src/api/auth.cpp", "src/core/config.hpp"},
        )
        self.assertEqual(
            set(index["entry_candidates"]),
            {"src/api/auth.cpp", "src/core/config.hpp"},
        )
        self.assertEqual(index["build_files"], ["src/CMakeLists.txt"])
        self.assertNotIn("src/web/app.ts", index["files"])
        self.assertNotIn("src/server.py", index["files"])
        self.assertNotIn("src/package.json", index["build_files"])

    def test_base_model_uses_single_initial_agent_then_three_gap_review_agents(self) -> None:
        class FakeOpenCodeRunner:
            class NoAvailableModelError(RuntimeError):
                pass

            def __init__(self, stage_dir: Path) -> None:
                self.stage_dir = stage_dir
                self.stages: list[str] = []
                self.prompts: list[str] = []
                self.gap_calls = 0

            async def run_opencode_task(self, **kwargs) -> OpenCodeResult:
                stage = get_opencode_execution_context().task_metadata["stage"]
                self.stages.append(stage)
                prompt = str(kwargs["prompt"])
                self.prompts.append(prompt)
                output_match = re.search(r"将阶段结果写入输出 JSON 文件：`([^`]+)`", prompt)
                assert output_match is not None
                output_path = Path(output_match.group(1))
                input_match = re.search(r"读取输入 JSON 文件：`([^`]+)`", prompt)
                assert input_match is not None
                input_data = json.loads(Path(input_match.group(1)).read_text(encoding="utf-8"))
                if stage == "threat-asset-interface-agent":
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(
                        json.dumps({
                            "assets": [
                                {
                                    "asset_id": "ASSET-1",
                                    "name": "管理员权限",
                                    "risks": [{"risk_id": "RISK-1", "name": "权限被未授权获取"}],
                                }
                            ],
                            "high_risk_external_interfaces": [
                                {"interface_id": "IF-1", "name": "管理 API", "candidate_code_paths": []}
                            ],
                            "asset_interface_links": [{"asset_id": "ASSET-1", "interface_id": "IF-1"}],
                            "risks": [{"risk_id": "RISK-1", "asset_id": "ASSET-1", "name": "权限被未授权获取"}],
                            "attack_goals": [
                                {
                                    "attack_goal_id": "GOAL-1",
                                    "asset_id": "ASSET-1",
                                    "risk_id": "RISK-1",
                                    "name": "绕过管理面认证获取管理员权限",
                                    "related_interface_ids": ["IF-1"],
                                    "candidate_code_paths": ["src/api"],
                                }
                            ],
                        }),
                        encoding="utf-8",
                    )
                    return OpenCodeResult("ses-test", "success", "", None, "provider/model")
                assert stage == "threat-base-model-gap-review-agent"
                self.gap_calls += 1
                current_items = input_data["current_identified_items"]
                assert current_items["assets"][0]["name"] == "管理员权限"
                assert current_items["attack_goals"][0]["name"] == "绕过管理面认证获取管理员权限"
                payloads = [
                    {
                        "assets": [
                            {
                                "asset_id": "ASSET-2",
                                "name": "用户配置数据",
                                "candidate_code_paths": ["src/web/config/routes.cpp"],
                                "risks": [{"risk_id": "RISK-2", "name": "配置被未授权篡改"}],
                            }
                        ],
                        "high_risk_external_interfaces": [
                            {"interface_id": "IF-2", "name": "配置接口", "candidate_code_paths": ["src/web/config/routes.cpp"]}
                        ],
                        "asset_interface_links": [{"asset_id": "ASSET-2", "interface_id": "IF-2"}],
                        "risks": [{"risk_id": "RISK-2", "asset_id": "ASSET-2", "name": "配置被未授权篡改"}],
                        "attack_goals": [
                            {
                                "attack_goal_id": "GOAL-2",
                                "asset_id": "ASSET-2",
                                "risk_id": "RISK-2",
                                "name": "通过配置接口篡改关键配置",
                                "related_interface_ids": ["IF-2"],
                                "candidate_code_paths": ["src/web/config/routes.cpp"],
                            }
                        ],
                    },
                    {
                        "assets": [
                            {
                                "asset_id": "ASSET-3",
                                "name": "用户配置数据",
                                "candidate_code_paths": ["src/web/config/store.cpp"],
                                "risks": [{"risk_id": "RISK-3", "name": "配置被未授权篡改"}],
                            }
                        ],
                        "high_risk_external_interfaces": [
                            {"interface_id": "IF-3", "name": "配置接口", "candidate_code_paths": ["src/web/config/store.cpp"]}
                        ],
                        "asset_interface_links": [{"asset_id": "ASSET-3", "interface_id": "IF-3"}],
                        "risks": [{"risk_id": "RISK-3", "asset_id": "ASSET-3", "name": "配置被未授权篡改"}],
                        "attack_goals": [
                            {
                                "attack_goal_id": "GOAL-3",
                                "asset_id": "ASSET-3",
                                "risk_id": "RISK-3",
                                "name": "通过配置接口篡改关键配置",
                                "related_interface_ids": ["IF-3"],
                                "candidate_code_paths": ["src/web/config/store.cpp"],
                            }
                        ],
                    },
                    {
                        "assets": [],
                        "high_risk_external_interfaces": [],
                        "asset_interface_links": [],
                        "risks": [],
                        "attack_goals": [],
                    },
                ]
                payload = payloads[self.gap_calls - 1]
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(payload), encoding="utf-8")
                return OpenCodeResult("ses-test", "success", "", None, "provider/model")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = FakeOpenCodeRunner(root / "run" / "stages")
            result = asyncio.run(_run_base_model_agents(
                opencode_runner=runner,
                workspace=root,
                analysis_root=root,
                run_dir=root / "run",
                contexts_dir=root / "run" / "contexts",
                stages_dir=root / "run" / "stages",
                base_input={
                    "project_id": "scan-1",
                    "scan_scope": {"code_scan_relative_path": "src"},
                    "code_index": {
                        "files": [
                            "src/api/auth.cpp",
                            "src/api/session.cpp",
                            "src/web/config/routes.cpp",
                            "src/web/config/store.cpp",
                            "src/driver/ioctl.cpp",
                            "src/protocol/codec.cpp",
                            "src/core/cache.hpp",
                            "src/core/log.cpp",
                        ],
                        "entry_candidates": [
                            "src/api/auth.cpp",
                            "src/web/config/routes.cpp",
                            "src/driver/ioctl.cpp",
                            "src/protocol/codec.cpp",
                        ],
                        "languages": [{"language": "cpp", "files": 8}],
                    },
                    "product_mcp": {},
                },
                output_path=root / "run" / "stages" / "base_model.output.json",
                timeout=1,
                on_output=None,
                cancel_event=None,
                planned_task_id="",
                stats_scope_id="scan-1",
            ))

            self.assertEqual(runner.stages[0], "threat-asset-interface-agent")
            self.assertEqual(runner.stages.count("threat-asset-interface-agent"), 1)
            self.assertEqual(runner.stages.count("threat-base-model-gap-review-agent"), 3)
            self.assertNotIn("threat-base-model-shard-planner", runner.stages)
            self.assertIn("只调用这一个 Agent", runner.prompts[0])
            self.assertTrue(all(
                "current_identified_items.assets" in prompt
                for prompt in runner.prompts[1:]
            ))
            self.assertEqual(result["assets"][0]["name"], "管理员权限")
            self.assertEqual(result["assets"][1]["name"], "用户配置数据")
            self.assertEqual(
                set(result["attack_goals"][1]["candidate_code_paths"]),
                {"src/web/config/routes.cpp", "src/web/config/store.cpp"},
            )
            self.assertEqual(
                set(result["high_risk_external_interfaces"][1]["candidate_code_paths"]),
                {"src/web/config/routes.cpp", "src/web/config/store.cpp"},
            )

    def test_base_model_shards_follow_cpp_paths_without_six_agent_cap(self) -> None:
        files = [f"src/module{i}/entry.cpp" for i in range(1, 9)]
        shards = _base_model_agent_shards({
            "scan_scope": {"code_scan_relative_path": "src"},
            "code_index": {
                "files": files,
                "entry_candidates": files,
                "languages": [{"language": "cpp", "files": len(files)}],
            },
        })

        self.assertEqual(len(shards), 8)
        self.assertEqual(
            {shard["name"] for shard in shards},
            {f"module{i}" for i in range(1, 9)},
        )
        self.assertFalse(any(shard["name"] == "其他路径" for shard in shards))

    def test_base_model_shards_ignore_non_cpp_code_index_entries(self) -> None:
        shards = _base_model_agent_shards({
            "scan_scope": {"code_scan_relative_path": "src"},
            "code_index": {
                "files": [
                    "src/api/auth.cpp",
                    "src/core/config.hpp",
                    "src/web/app.ts",
                    "scripts/build.py",
                ],
                "entry_candidates": [
                    "src/api/auth.cpp",
                    "src/core/config.hpp",
                    "src/web/app.ts",
                    "scripts/build.py",
                ],
                "languages": [
                    {"language": "cpp", "files": 2},
                    {"language": "typescript", "files": 1},
                    {"language": "python", "files": 1},
                ],
            },
        })

        include_paths = [path for shard in shards for path in shard["include_paths"]]
        entry_candidates = [path for shard in shards for path in shard["entry_candidates"]]
        self.assertEqual(set(include_paths), {"src/api/auth.cpp", "src/core/config.hpp"})
        self.assertEqual(set(entry_candidates), {"src/api/auth.cpp", "src/core/config.hpp"})
        self.assertNotIn("src/web/app.ts", include_paths)
        self.assertNotIn("scripts/build.py", include_paths)

    def test_base_model_merge_deduplicates_semantic_assets_and_rewrites_references(self) -> None:
        merged = _merge_base_model_outputs(
            {
                "assets": [
                    {
                        "asset_id": "ASSET-A",
                        "name": "管理员权限",
                        "candidate_code_paths": ["src/auth/admin.cpp"],
                        "risks": [
                            {"risk_id": "RISK-A", "name": "权限被未授权获取"}
                        ],
                    }
                ],
                "high_risk_external_interfaces": [
                    {
                        "interface_id": "IF-A",
                        "name": "管理 API",
                        "affected_asset_ids": ["ASSET-A"],
                        "candidate_code_paths": ["src/api/admin.cpp"],
                    }
                ],
                "asset_interface_links": [
                    {
                        "asset_id": "ASSET-A",
                        "interface_id": "IF-A",
                        "risk_id": "RISK-A",
                        "attack_goal_id": "GOAL-A",
                    }
                ],
                "risks": [
                    {"risk_id": "RISK-A", "asset_id": "ASSET-A", "name": "权限被未授权获取"}
                ],
                "attack_goals": [
                    {
                        "attack_goal_id": "GOAL-A",
                        "asset_id": "ASSET-A",
                        "risk_id": "RISK-A",
                        "name": "绕过管理面身份认证获取管理员权限",
                        "related_interface_ids": ["IF-A"],
                        "candidate_code_paths": ["src/api/admin.cpp"],
                    }
                ],
            },
            {
                "assets": [
                    {
                        "asset_id": "ASSET-B",
                        "name": "管理员权限",
                        "candidate_code_paths": ["src/session/role.cpp"],
                        "risks": [
                            {"risk_id": "RISK-B", "name": "权限被未授权获取"}
                        ],
                    }
                ],
                "high_risk_external_interfaces": [
                    {
                        "interface_id": "IF-B",
                        "name": "管理 API",
                        "affected_asset_ids": ["ASSET-B"],
                        "candidate_code_paths": ["src/session/admin_route.cpp"],
                    }
                ],
                "asset_interface_links": [
                    {
                        "asset_id": "ASSET-B",
                        "interface_id": "IF-B",
                        "risk_id": "RISK-B",
                        "attack_goal_id": "GOAL-B",
                    }
                ],
                "risks": [
                    {"risk_id": "RISK-B", "asset_id": "ASSET-B", "name": "权限被未授权获取"}
                ],
                "attack_goals": [
                    {
                        "attack_goal_id": "GOAL-B",
                        "asset_id": "ASSET-B",
                        "risk_id": "RISK-B",
                        "name": "绕过管理面身份认证获取管理员权限",
                        "related_interface_ids": ["IF-B"],
                        "candidate_code_paths": ["src/session/admin_route.cpp"],
                    }
                ],
            },
        )

        self.assertEqual(len(merged["assets"]), 1)
        self.assertEqual(merged["assets"][0]["asset_id"], "ASSET-A")
        self.assertEqual(
            set(merged["assets"][0]["candidate_code_paths"]),
            {"src/auth/admin.cpp", "src/session/role.cpp"},
        )
        self.assertEqual(len(merged["assets"][0]["risks"]), 1)
        self.assertEqual(merged["assets"][0]["risks"][0]["risk_id"], "RISK-A")
        self.assertEqual(merged["assets"][0]["risks"][0]["asset_id"], "ASSET-A")

        self.assertEqual(len(merged["risks"]), 1)
        self.assertEqual(merged["risks"][0]["risk_id"], "RISK-A")
        self.assertEqual(merged["risks"][0]["asset_id"], "ASSET-A")

        self.assertEqual(len(merged["high_risk_external_interfaces"]), 1)
        interface = merged["high_risk_external_interfaces"][0]
        self.assertEqual(interface["interface_id"], "IF-A")
        self.assertEqual(interface["affected_asset_ids"], ["ASSET-A"])
        self.assertEqual(
            set(interface["candidate_code_paths"]),
            {"src/api/admin.cpp", "src/session/admin_route.cpp"},
        )

        self.assertEqual(len(merged["attack_goals"]), 1)
        goal = merged["attack_goals"][0]
        self.assertEqual(goal["attack_goal_id"], "GOAL-A")
        self.assertEqual(goal["asset_id"], "ASSET-A")
        self.assertEqual(goal["risk_id"], "RISK-A")
        self.assertEqual(goal["related_interface_ids"], ["IF-A"])
        self.assertEqual(
            set(goal["candidate_code_paths"]),
            {"src/api/admin.cpp", "src/session/admin_route.cpp"},
        )
        self.assertEqual(merged["asset_interface_links"], [
            {
                "asset_id": "ASSET-A",
                "interface_id": "IF-A",
                "risk_id": "RISK-A",
                "attack_goal_id": "GOAL-A",
            }
        ])

    def test_attack_goals_are_enriched_with_asset_and_risk_names(self) -> None:
        goals = _attack_goals_from_base_output({
            "assets": [
                {
                    "asset_id": "ASSET-UE",
                    "name": "UE 上下文数据",
                    "risks": [{"risk_id": "RISK-UE", "name": "UE 上下文被未授权窃取"}],
                }
            ],
            "risks": [
                {
                    "risk_id": "RISK-UE",
                    "asset_id": "ASSET-UE",
                    "name": "UE 上下文被未授权窃取",
                }
            ],
            "attack_goals": [
                {
                    "attack_goal_id": "GOAL-UE",
                    "asset_id": "ASSET-UE",
                    "risk_id": "RISK-UE",
                    "name": "窃取 UE 上下文",
                }
            ],
        })

        self.assertEqual(goals[0]["asset_name"], "UE 上下文数据")
        self.assertEqual(goals[0]["risk_name"], "UE 上下文被未授权窃取")
        self.assertEqual(goals[0]["name"], "窃取 UE 上下文")

    def test_attack_path_defaults_override_mismatched_stage_context(self) -> None:
        normalized = _with_attack_path_defaults(
            {
                "asset_name": "基站可用性",
                "risk_name": "服务不可用",
                "attack_goal_id": "GOAL-DOS",
                "attack_goal_name": "造成基站服务中断",
                "attack_domain_id": "DOMAIN-N2",
                "attack_domain_name": "N2 信令域",
                "attack_surface_id": "SURFACE-NGAP",
                "attack_surface_name": "NGAP 信令入口",
                "attack_method_id": "METHOD-FLOOD",
                "attack_method_name": "泛洪攻击",
                "code_paths": [{"path": "src/amf/context.cpp"}],
            },
            {
                "attack_goal": {
                    "attack_goal_id": "GOAL-UE-CONTEXT",
                    "asset_id": "ASSET-UE",
                    "asset_name": "UE 上下文数据",
                    "risk_id": "RISK-UE",
                    "risk_name": "UE 上下文被未授权窃取",
                    "name": "窃取 UE 上下文",
                },
                "attack_domain": {
                    "domain_id": "DOMAIN-CONTEXT",
                    "name": "UE 上下文管理域",
                },
                "attack_surface": {
                    "surface_id": "SURFACE-CONTEXT-API",
                    "name": "UE 上下文查询接口",
                    "surface_type": "api",
                },
                "method_confirmation_task": {
                    "method_id": "METHOD-UE-CONTEXT-STEAL",
                    "name": "UE 上下文窃取",
                },
            },
            {"attack_paths": []},
        )
        path = parse_attack_path_data(normalized)

        self.assertEqual(path.asset_name, "UE 上下文数据")
        self.assertEqual(path.risk_name, "UE 上下文被未授权窃取")
        self.assertEqual(path.attack_goal_id, "GOAL-UE-CONTEXT")
        self.assertEqual(path.attack_goal_name, "窃取 UE 上下文")
        self.assertEqual(path.attack_domain_name, "UE 上下文管理域")
        self.assertEqual(path.attack_surface_name, "UE 上下文查询接口")
        self.assertEqual(path.attack_surface_type, "api")
        self.assertEqual(path.attack_method_id, "METHOD-UE-CONTEXT-STEAL")
        self.assertEqual(path.attack_method_name, "UE 上下文窃取")

    def test_attack_path_defaults_fill_method_name_from_surface_methods(self) -> None:
        normalized = _with_attack_path_defaults(
            {
                "attack_method_id": "METHOD-UE-CONTEXT-STEAL",
                "attack_method_name": "METHOD-UE-CONTEXT-STEAL",
                "code_paths": [{"path": "src/amf/context.cpp"}],
            },
            {
                "attack_goal": {
                    "attack_goal_id": "GOAL-UE-CONTEXT",
                    "asset_id": "ASSET-UE",
                    "asset_name": "UE 上下文数据",
                    "risk_id": "RISK-UE",
                    "risk_name": "UE 上下文被未授权窃取",
                    "name": "窃取 UE 上下文",
                },
                "attack_domain": {"domain_id": "DOMAIN-CONTEXT", "name": "UE 上下文管理域"},
                "attack_surface": {"surface_id": "SURFACE-CONTEXT-API", "name": "UE 上下文查询接口"},
            },
            {
                "methods": [
                    {
                        "method_id": "METHOD-UE-CONTEXT-STEAL",
                        "name": "UE 上下文窃取",
                        "preconditions": ["攻击者可访问上下文查询接口"],
                    }
                ],
                "attack_paths": [],
            },
        )
        path = parse_attack_path_data(normalized)

        self.assertEqual(path.attack_method_name, "UE 上下文窃取")
        self.assertEqual(path.preconditions, ["攻击者可访问上下文查询接口"])

    def test_method_confirmation_tasks_inherit_method_names_from_surface_output(self) -> None:
        task = _with_method_confirmation_task_defaults(
            {
                "task_id": "CONFIRM-1",
                "method_id": "METHOD-UE-CONTEXT-STEAL",
                "attack_method_name": "泛洪攻击",
            },
            {
                "methods": [
                    {
                        "method_id": "METHOD-UE-CONTEXT-STEAL",
                        "name": "UE 上下文窃取",
                    }
                ]
            },
        )

        self.assertEqual(task["attack_method_id"], "METHOD-UE-CONTEXT-STEAL")
        self.assertEqual(task["attack_method_name"], "UE 上下文窃取")

    def test_threat_analysis_stage_retries_invalid_json_three_times(self) -> None:
        class FakeOpenCodeRunner:
            class NoAvailableModelError(RuntimeError):
                pass

            def __init__(self, output_path: Path) -> None:
                self.output_path = output_path
                self.calls = 0

            async def run_opencode_task(self, **kwargs) -> OpenCodeResult:
                self.calls += 1
                if self.calls <= 3:
                    self.output_path.write_text("{not-json", encoding="utf-8")
                else:
                    self.output_path.write_text(
                        json.dumps({"attack_goal_id": "GOAL-1", "domains": []}),
                        encoding="utf-8",
                    )
                return OpenCodeResult("ses-test", "success", "", None, "provider/model")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_path = root / "run" / "stages" / "goal.output.json"
            runner = FakeOpenCodeRunner(output_path)
            logs: list[str] = []

            asyncio.run(_invoke_stage(
                opencode_runner=runner,
                workspace=root,
                analysis_root=root,
                run_dir=root / "run",
                skill_name="threat-attack-goal-agent",
                input_path=root / "input.json",
                output_path=output_path,
                timeout=1,
                on_output=logs.append,
                cancel_event=None,
                planned_task_id="",
                stats_scope_id="scan-1",
                attempt=1,
                task_label="攻击目标分解 1/1",
            ))

            self.assertEqual(runner.calls, 4)
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8"))["domains"], [])
            self.assertTrue(any("重试 3/3" in line for line in logs))

    def test_streaming_threat_analysis_marker(self) -> None:
        streaming = parse_threat_analysis_data({
            "analysis_id": _streaming_threat_analysis_id("scan-1"),
            "assets": [],
        })
        final = parse_threat_analysis_data({
            "analysis_id": "ATA-FINAL",
            "assets": [],
        })

        self.assertTrue(_is_streaming_threat_analysis(streaming))
        self.assertFalse(_is_streaming_threat_analysis(final))

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

    def test_generated_method_ids_are_not_used_as_display_names(self) -> None:
        path = parse_attack_path_data({
            "asset": {"name": "管理员权限"},
            "risk": {"name": "管理员权限被未授权获取"},
            "attack_goal": {"name": "绕过管理面身份认证"},
            "attack_domain": {"name": "管理面"},
            "attack_surface": {"name": "管理 API", "surface_type": "api"},
            "attack_method": {"id": "METHOD-2C94B22378", "name": "METHOD-2C94B22378"},
            "code_paths": [{"path": "src/api", "description": "管理 API"}],
        })

        self.assertEqual(path.attack_method_id, "METHOD-2C94B22378")
        self.assertEqual(path.attack_method_name, "")
        analysis = build_analysis_from_attack_paths(
            [path],
            analysis_id="ATA-NO-METHOD-ID-DISPLAY",
            sources=parse_threat_analysis_data({"sources": {"repositories": ["."]}}).sources,
            scan_scope=parse_threat_analysis_data({}).scan_scope,
        )
        method_nodes = [
            node
            for tree in analysis.attack_trees
            for node in tree.nodes
            if node.node_type == "method"
        ]
        self.assertEqual(method_nodes[0].node_id, "METHOD-2C94B22378")
        self.assertEqual(method_nodes[0].name, "未命名攻击方式")

        tasks = build_threat_audit_tasks("scan-1", analysis)

        self.assertEqual(tasks[0].method_node_id, "METHOD-2C94B22378")
        self.assertEqual(tasks[0].method_name, "未命名攻击方式")
        self.assertNotIn("METHOD-2C94B22378", tasks[0].description)

    def test_generated_object_ids_are_not_used_as_display_names(self) -> None:
        path = parse_attack_path_data({
            "asset": {"asset_id": "ASSET-XX-01", "name": "ASSET-XX-01"},
            "risk": {"risk_id": "RISK-XX-01", "name": "RISK-XX-01"},
            "attack_goal": {"attack_goal_id": "GOAL-XX-01", "name": "GOAL-XX-01"},
            "attack_domain": {"domain_id": "DOMAIN-XX-01", "name": "DOMAIN-XX-01"},
            "attack_surface": {
                "surface_id": "SURFACE-XX-01",
                "name": "SURFACE-XX-01",
                "surface_type": "api",
            },
            "attack_method": {"name": "认证绕过"},
            "code_paths": [{"path": "src/api"}],
        })

        self.assertEqual(path.asset_name, "")
        self.assertEqual(path.risk_name, "")
        self.assertEqual(path.attack_goal_name, "")
        self.assertEqual(path.attack_domain_name, "")
        self.assertEqual(path.attack_surface_name, "")
        analysis = build_analysis_from_attack_paths(
            [path],
            analysis_id="ATA-NO-OBJECT-ID-DISPLAY",
            sources=parse_threat_analysis_data({"sources": {"repositories": ["."]}}).sources,
            scan_scope=parse_threat_analysis_data({}).scan_scope,
        )

        self.assertEqual(analysis.assets[0].name, "未命名资产")
        self.assertEqual(analysis.assets[0].risks[0].name, "未命名风险")
        tree = analysis.attack_trees[0]
        self.assertEqual(tree.attack_goal, "未命名攻击目标")
        node_names = {node.node_type: node.name for node in tree.nodes}
        self.assertEqual(node_names["goal"], "未命名攻击目标")
        self.assertEqual(node_names["domain"], "未命名攻击域")
        self.assertEqual(node_names["surface"], "未命名攻击面")

        tasks = build_threat_audit_tasks("scan-1", analysis)

        self.assertEqual(tasks[0].surface_name, "未命名攻击面")
        self.assertEqual(tasks[0].asset_name, "未命名资产")
        self.assertEqual(tasks[0].risk_name, "未命名风险")
        self.assertEqual(tasks[0].attack_goal, "未命名攻击目标")
        self.assertNotIn("ASSET-XX-01", tasks[0].description)
        self.assertNotIn("SURFACE-XX-01", tasks[0].description)

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
