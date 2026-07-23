"""High-risk module identification and merge stage."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.schemas import HIGH_RISK_MODULES_SCHEMA
from threat_analysis_harness.stages.base import (
    SubmitTasks,
    TaskJson,
    require_all_success,
    require_success,
)


HIGH_RISK_MAP_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    (
        "management-control",
        "管理和控制接口相关代码",
        "是否涉及设备或系统对外提供管理和控制接口相关的代码",
    ),
    (
        "untrusted-data",
        "不可信来源数据解析或处理代码",
        "是否涉及对不可信来源数据进行解析或处理的代码",
    ),
    (
        "security",
        "安全相关类代码",
        "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)",
    ),
    (
        "sensitive-data",
        "个人数据或者敏感数据代码",
        "是否涉及个人数据或者敏感数据的代码",
    ),
    (
        "web",
        "Web 相关处理",
        "是否涉及web相关处理",
    ),
)


class HighRiskModuleStage:
    map_task_type = "high_risk_module_map"
    merge_task_type = "high_risk_module_merge"
    map_skill_name = "high-risk-module-map"
    merge_skill_name = "high-risk-module-merge"

    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout

    def build_map_tasks(
        self,
        *,
        input_batches: Sequence[Sequence[str | Path]],
        runtime_prompt: str | None = None,
    ) -> list[TaskJson]:
        tasks: list[TaskJson] = []
        for index, input_files in enumerate(input_batches, start=1):
            if runtime_prompt is not None:
                task_id = f"high-risk-module-map-{index:03d}"
                tasks.append(
                    {
                        "task_id": task_id,
                        "task_type": self.map_task_type,
                        "skill_name": self.map_skill_name,
                        "runtime_prompt": runtime_prompt,
                        "input_files": [str(path) for path in input_files],
                        "output_path": str(self.layout.high_risk_raw_dir / f"{task_id}.json"),
                        "output_schema": HIGH_RISK_MODULES_SCHEMA,
                        "metadata": {
                            "stage": "high_risk_modules",
                            "phase": "map",
                            "batch": index,
                        },
                        "priority": 20,
                    }
                )
                continue

            for slug, category_label, category_field in HIGH_RISK_MAP_CATEGORIES:
                task_id = f"high-risk-module-map-{index:03d}-{slug}"
                tasks.append(
                    {
                        "task_id": task_id,
                        "task_type": self.map_task_type,
                        "skill_name": self.map_skill_name,
                        "runtime_prompt": _category_map_prompt(
                            input_files,
                            category_label=category_label,
                            category_field=category_field,
                        ),
                        "input_files": [str(path) for path in input_files],
                        "output_path": str(self.layout.high_risk_raw_dir / f"{task_id}.json"),
                        "output_schema": HIGH_RISK_MODULES_SCHEMA,
                        "metadata": {
                            "stage": "high_risk_modules",
                            "phase": "map",
                            "batch": index,
                            "high_risk_category": category_label,
                            "high_risk_field": category_field,
                        },
                        "priority": 20,
                    }
                )
        return tasks

    def build_merge_task(
        self,
        *,
        candidate_files: Sequence[str | Path],
        task_id: str = "high-risk-module-merge",
        runtime_prompt: str | None = None,
    ) -> TaskJson:
        return {
            "task_id": task_id,
            "task_type": self.merge_task_type,
            "skill_name": self.merge_skill_name,
            "runtime_prompt": runtime_prompt or _merge_prompt(candidate_files),
            "input_files": [str(path) for path in candidate_files],
            "output_path": str(self.layout.high_risk_final_dir / f"{task_id}.json"),
            "output_schema": HIGH_RISK_MODULES_SCHEMA,
            "metadata": {"stage": "high_risk_modules", "phase": "merge"},
            "priority": 30,
        }

    def run(
        self,
        *,
        input_batches: Sequence[Sequence[str | Path]],
        map_runtime_prompt: str | None = None,
        merge_runtime_prompt: str | None = None,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        self.layout.ensure()
        map_tasks = self.build_map_tasks(
            input_batches=input_batches,
            runtime_prompt=map_runtime_prompt,
        )
        map_results = require_all_success(self.submit_tasks(map_tasks, timeout=timeout))
        candidate_files = [result["output_path"] for result in map_results]
        merge_task = self.build_merge_task(
            candidate_files=candidate_files,
            runtime_prompt=merge_runtime_prompt,
        )
        merge_result = require_success(self.submit_tasks([merge_task], timeout=timeout)[0])
        return merge_result["output"]


def _category_map_prompt(
    input_files: Sequence[str | Path],
    *,
    category_label: str,
    category_field: str,
) -> str:
    return (
        "请根据 skill 要求分析输入文件和代码仓内容，识别高风险模块。"
        f"当前只识别命中“{category_label}”这一类高风险特征的模块；"
        f"输出项的“{category_field}”必须全部为“是”。"
        "其他“是否涉及”字段仍需结合代码证据真实填写，不得为了当前分类强行填写“是”；"
        "“是否外部暴露面”也必须按代码中的外部接口、外部输入或暴露路径证据真实判断。"
        "最终只输出符合 JSON schema 的数组。"
        "输入文件："
        + ", ".join(str(path) for path in input_files)
    )


def _merge_prompt(candidate_files: Sequence[str | Path]) -> str:
    return (
        "请根据 skill 要求合并多个按高风险特征拆分识别的高风险模块候选 JSON，"
        "处理命名不一致、功能重叠和同一模块命中多个高风险特征的情况，"
        "最终只输出符合 JSON schema 的最终高风险模块数组。"
        "候选文件："
        + ", ".join(str(path) for path in candidate_files)
    )
