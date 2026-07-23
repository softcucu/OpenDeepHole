"""Value asset identification stage."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.schemas import VALUE_ASSETS_SCHEMA
from threat_analysis_harness.stages.base import (
    SubmitTasks,
    TaskJson,
    require_all_success,
    require_success,
)


VALUE_ASSET_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("data", "数据资产", "数据"),
    ("software", "软件资产", "软件"),
    ("hardware", "硬件资产", "硬件"),
    ("service", "服务资产", "服务"),
)


class ValueAssetStage:
    task_type = "value_asset_map"
    skill_name = "value-asset-map"

    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout

    def build_task(
        self,
        *,
        input_files: Sequence[str | Path],
        task_id: str = "value-asset-map",
        runtime_prompt: str | None = None,
    ) -> TaskJson:
        return {
            "task_id": task_id,
            "task_type": self.task_type,
            "skill_name": self.skill_name,
            "runtime_prompt": runtime_prompt or _default_prompt(input_files),
            "input_files": [str(path) for path in input_files],
            "output_path": str(self.layout.value_assets_raw_dir / f"{task_id}.json"),
            "output_schema": VALUE_ASSETS_SCHEMA,
            "metadata": {"stage": "value_assets"},
            "priority": 20,
        }

    def build_category_tasks(
        self,
        *,
        input_files: Sequence[str | Path],
        task_id_prefix: str = "value-asset-map",
    ) -> list[TaskJson]:
        tasks: list[TaskJson] = []
        for slug, asset_category, category_label in VALUE_ASSET_CATEGORIES:
            task_id = f"{task_id_prefix}-{slug}"
            tasks.append(
                {
                    "task_id": task_id,
                    "task_type": self.task_type,
                    "skill_name": self.skill_name,
                    "runtime_prompt": _category_prompt(
                        input_files,
                        asset_category=asset_category,
                        category_label=category_label,
                    ),
                    "input_files": [str(path) for path in input_files],
                    "output_path": str(self.layout.value_assets_raw_dir / f"{task_id}.json"),
                    "output_schema": VALUE_ASSETS_SCHEMA,
                    "metadata": {
                        "stage": "value_assets",
                        "phase": "category_map",
                        "asset_category": asset_category,
                    },
                    "priority": 20,
                }
            )
        return tasks

    def merge_category_outputs(
        self,
        category_outputs: Sequence[tuple[str, Sequence[dict[str, Any]]]],
    ) -> list[dict[str, Any]]:
        merged = _merge_value_assets(category_outputs)
        self.layout.write_final_json("value_assets/final/value-assets.json", merged)
        return merged

    def run(
        self,
        *,
        input_files: Sequence[str | Path],
        task_id: str = "value-asset-map",
        runtime_prompt: str | None = None,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        self.layout.ensure()
        if runtime_prompt is not None:
            task = self.build_task(
                input_files=input_files,
                task_id=task_id,
                runtime_prompt=runtime_prompt,
            )
            result = require_success(self.submit_tasks([task], timeout=timeout)[0])
            return result["output"]

        tasks = self.build_category_tasks(input_files=input_files, task_id_prefix=task_id)
        results = require_all_success(self.submit_tasks(tasks, timeout=timeout))
        category_outputs = [
            (str(result.get("metadata", {}).get("asset_category", "")), result.get("output") or [])
            for result in results
        ]
        return self.merge_category_outputs(category_outputs)


def _category_prompt(
    input_files: Sequence[str | Path],
    *,
    asset_category: str,
    category_label: str,
) -> str:
    other_categories = [
        category
        for _, category, _ in VALUE_ASSET_CATEGORIES
        if category != asset_category
    ]
    return (
        "请根据 skill 要求分析输入文件和代码仓内容，识别价值资产。"
        f"当前只识别{category_label}类价值资产，输出项的“资产类别”必须全部为“{asset_category}”；"
        f"不得输出{_format_categories(other_categories)}。"
        "最终只输出符合 JSON schema 的数组。"
        "输入文件："
        + ", ".join(str(path) for path in input_files)
    )


def _default_prompt(input_files: Sequence[str | Path]) -> str:
    return (
        "请根据 skill 要求分析输入文件和代码仓内容，识别价值资产。"
        "最终只输出符合 JSON schema 的数组。"
        "输入文件："
        + ", ".join(str(path) for path in input_files)
    )


def _merge_value_assets(
    category_outputs: Sequence[tuple[str, Sequence[dict[str, Any]]]],
) -> list[dict[str, Any]]:
    merged_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []

    for expected_category, assets in category_outputs:
        for asset in assets:
            asset_category = str(asset.get("资产类别", "")).strip()
            if expected_category and asset_category != expected_category:
                continue
            asset_name = str(asset.get("资产名", "")).strip()
            if not asset_name or not asset_category:
                continue

            normalized = _normalized_asset_name(asset_name)
            key = (asset_category, normalized)
            if key not in merged_by_key:
                merged_by_key[key] = dict(asset)
                order.append(key)
                continue

            _merge_duplicate_asset(merged_by_key[key], asset)

    return [merged_by_key[key] for key in order]


def _merge_duplicate_asset(target: dict[str, Any], source: dict[str, Any]) -> None:
    for field in ("资产描述", "攻击损失", "判断为价值资产的原因"):
        target[field] = _merge_text(target.get(field), source.get(field))


def _merge_text(left: Any, right: Any) -> str:
    left_text = str(left or "").strip()
    right_text = str(right or "").strip()
    if not left_text:
        return right_text
    if not right_text or right_text == left_text or right_text in left_text:
        return left_text
    if left_text in right_text:
        return right_text
    return f"{left_text}；{right_text}"


def _normalized_asset_name(value: str) -> str:
    return re.sub(r"\s+", "", value).casefold()


def _format_categories(categories: Sequence[str]) -> str:
    if not categories:
        return "其他资产类别"
    return "、".join(categories)
