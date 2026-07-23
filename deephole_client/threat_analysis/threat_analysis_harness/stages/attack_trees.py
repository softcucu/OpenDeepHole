"""Attack tree analysis stage."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.errors import ArtifactConsistencyError
from threat_analysis_harness.schemas import ATTACK_TREE_SCHEMA
from threat_analysis_harness.stages.base import (
    ProgressReporter,
    SubmitTasks,
    TaskJson,
    require_all_success,
    run_or_resume_tasks,
)


class AttackTreeStage:
    task_type = "attack_tree_by_asset"
    skill_name = "attack-tree-by-asset"

    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout

    def build_tasks(
        self,
        *,
        value_assets: Sequence[dict[str, Any]],
        high_risk_modules: Sequence[dict[str, Any]],
        context_files: Sequence[str | Path] = (),
        runtime_prompt: str | None = None,
    ) -> list[TaskJson]:
        tasks: list[TaskJson] = []
        for index, asset in enumerate(value_assets, start=1):
            task_id = f"attack-tree-by-asset-{index:03d}"
            task_input = self.layout.write_task_input(
                f"{task_id}.input.json",
                {
                    "value_asset": asset,
                    "high_risk_modules": list(high_risk_modules),
                },
            )
            tasks.append(
                {
                    "task_id": task_id,
                    "task_type": self.task_type,
                    "skill_name": self.skill_name,
                    "runtime_prompt": runtime_prompt
                    or _asset_prompt(
                        asset,
                        task_input=task_input,
                        context_files=context_files,
                    ),
                    "input_files": [str(task_input)] + [str(path) for path in context_files],
                    "output_path": str(self.layout.attack_trees_raw_dir / f"{task_id}.json"),
                    "output_schema": ATTACK_TREE_SCHEMA,
                    "metadata": {
                        "stage": "attack_trees",
                        "asset_name": asset.get("资产名") or asset.get("asset_name"),
                    },
                    "priority": 40,
                }
            )
        return tasks

    def run(
        self,
        *,
        value_assets: Sequence[dict[str, Any]],
        high_risk_modules: Sequence[dict[str, Any]],
        context_files: Sequence[str | Path] = (),
        runtime_prompt: str | None = None,
        timeout: float | None = None,
        resume: bool = False,
        progress_reporter: ProgressReporter | None = None,
    ) -> dict[str, Any]:
        self.layout.ensure()
        tasks = self.build_tasks(
            value_assets=value_assets,
            high_risk_modules=high_risk_modules,
            context_files=context_files,
            runtime_prompt=runtime_prompt,
        )
        results = require_all_success(
            run_or_resume_tasks(
                submit_tasks=self.submit_tasks,
                tasks=tasks,
                resume=resume,
                timeout=timeout,
                progress_reporter=progress_reporter,
            )
        )
        normalized_outputs = [
            normalize_attack_tree_output(
                result["output"],
                value_asset=asset,
                high_risk_modules=high_risk_modules,
            )
            for asset, result in zip(value_assets, results)
        ]
        combined = combine_attack_tree_outputs(normalized_outputs)
        self.layout.write_final_json("attack_trees/final/attack_trees.json", combined)
        return combined


def normalize_attack_tree_output(
    output: dict[str, Any],
    *,
    value_asset: dict[str, Any],
    high_risk_modules: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    normalized = copy.deepcopy(output)
    attack_trees = normalized.get("attack_trees", [])
    if not attack_trees:
        asset_name = _asset_name(value_asset)
        raise ArtifactConsistencyError(
            f"Attack tree output is missing tree for asset: {asset_name}"
        )

    canonical_asset = _canonical_attack_tree_asset(value_asset)
    module_index = _high_risk_module_index(high_risk_modules)

    for tree in attack_trees:
        tree["value_asset"] = dict(canonical_asset)
        _normalize_tree_nodes(tree, canonical_asset, module_index)
        _normalize_attack_paths(tree, module_index)

    return normalized


def combine_attack_tree_outputs(outputs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    attack_trees: list[dict[str, Any]] = []
    for output in outputs:
        attack_trees.extend(output.get("attack_trees", []))
    return {
        "attack_trees": attack_trees,
    }


def _asset_prompt(
    asset: dict[str, Any],
    *,
    task_input: str | Path,
    context_files: Sequence[str | Path] = (),
) -> str:
    asset_name = asset.get("资产名") or asset.get("asset_name") or "当前价值资产"
    context_text = (
        "额外代码上下文文件：" + "、".join(str(path) for path in context_files) + "。"
        if context_files
        else "未提供额外代码上下文文件。"
    )
    return (
        f"请根据 skill 要求，仅针对价值资产“{asset_name}”进行攻击树分析。"
        f"结构化输入文件：{task_input}，其中 value_asset 是当前价值资产，"
        "high_risk_modules 是全部最终高风险模块列表；必须读取该文件中的高风险模块后再分析攻击路径。"
        f"{context_text}"
        "最终只输出符合 JSON schema 的对象。"
    )


def _normalize_tree_nodes(
    tree: dict[str, Any],
    canonical_asset: dict[str, str],
    module_index: dict[str, dict[str, Any]],
) -> None:
    root_name = f"攻击价值资产：{canonical_asset['asset_name']}"
    for node in tree.get("nodes", []):
        if node.get("node_type") == "根节点":
            node["node_name"] = root_name
            node["module_name"] = None
            node["is_high_risk_module"] = False
            node["external_exposure"] = False
            node["external_interface_description"] = None
            continue

        match = _find_high_risk_module(
            module_index,
            node.get("module_name"),
            node.get("node_name"),
        )
        if node.get("node_type") == "叶子节点":
            module = _require_high_risk_module(match, "Leaf node", node.get("node_name"))
            _apply_high_risk_module_to_node(node, module)
            if not _is_external_module(module):
                raise ArtifactConsistencyError(
                    f"Leaf node references non-external high-risk module: {_module_name(module)}"
                )
            continue

        if node.get("is_high_risk_module") is True:
            module = _require_high_risk_module(
                match,
                "High-risk internal node",
                node.get("module_name") or node.get("node_name"),
            )
            _apply_high_risk_module_to_node(node, module)
            continue

        if match is not None:
            _apply_high_risk_module_to_node(node, match)


def _normalize_attack_paths(
    tree: dict[str, Any],
    module_index: dict[str, dict[str, Any]],
) -> None:
    nodes_by_id = {
        str(node.get("node_id")): node
        for node in tree.get("nodes", [])
        if node.get("node_id") is not None
    }

    for path in tree.get("attack_paths", []):
        node_ids = {str(node_id) for node_id in path.get("node_ids", [])}
        related_modules: list[dict[str, Any]] = []
        seen_modules: set[str] = set()

        for related in path.get("related_high_risk_modules", []):
            node_id = str(related.get("node_id", ""))
            if node_id not in node_ids:
                continue
            node = nodes_by_id.get(node_id)
            match = _find_high_risk_module(
                module_index,
                related.get("module_name"),
                None if node is None else node.get("module_name"),
                None if node is None else node.get("node_name"),
            )
            module = _require_high_risk_module(
                match,
                "Related high-risk module",
                related.get("module_name"),
            )
            if node is not None:
                _apply_high_risk_module_to_node(node, module)
            canonical_name = _module_name(module)
            if canonical_name in seen_modules:
                continue
            related["module_name"] = canonical_name
            related["external_exposure"] = _is_external_module(module)
            related_modules.append(related)
            seen_modules.add(canonical_name)

        for node_id in path.get("node_ids", []):
            node = nodes_by_id.get(str(node_id))
            if node is None:
                raise ArtifactConsistencyError(
                    f"Attack path references unknown node_id: {node_id}"
                )
            if node.get("is_high_risk_module") is not True:
                continue
            module = _require_high_risk_module(
                _find_high_risk_module(
                    module_index,
                    node.get("module_name"),
                    node.get("node_name"),
                ),
                "Path high-risk node",
                node.get("module_name") or node.get("node_name"),
            )
            _apply_high_risk_module_to_node(node, module)
            canonical_name = _module_name(module)
            if canonical_name in seen_modules:
                continue
            related_modules.append(
                {
                    "module_name": canonical_name,
                    "node_id": str(node_id),
                    "external_exposure": _is_external_module(module),
                    "path_role": _path_role_for_node(node),
                    "association_description": "该节点在攻击路径中被标记为高风险模块，名称已与最终高风险模块列表对齐。",
                }
            )
            seen_modules.add(canonical_name)

        path["related_high_risk_modules"] = related_modules


def _apply_high_risk_module_to_node(node: dict[str, Any], module: dict[str, Any]) -> None:
    module_name = _module_name(module)
    node["node_name"] = module_name
    node["module_name"] = module_name
    node["is_high_risk_module"] = True
    node["external_exposure"] = _is_external_module(module)


def _canonical_attack_tree_asset(asset: dict[str, Any]) -> dict[str, str]:
    return {
        "asset_name": _asset_name(asset),
        "asset_category": str(asset.get("资产类别") or asset.get("asset_category") or "").strip(),
        "asset_description": str(
            asset.get("资产描述") or asset.get("asset_description") or ""
        ).strip(),
        "attack_loss": str(asset.get("攻击损失") or asset.get("attack_loss") or "").strip(),
    }


def _asset_name(asset: dict[str, Any]) -> str:
    return str(asset.get("资产名") or asset.get("asset_name") or "").strip()


def _high_risk_module_index(
    high_risk_modules: Sequence[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for module in high_risk_modules:
        module_name = _module_name(module)
        if module_name:
            index[_normalize_name(module_name)] = module
    return index


def _find_high_risk_module(
    module_index: dict[str, dict[str, Any]],
    *names: Any,
) -> dict[str, Any] | None:
    for name in names:
        normalized = _normalize_name(name)
        if normalized and normalized in module_index:
            return module_index[normalized]
    return None


def _require_high_risk_module(
    module: dict[str, Any] | None,
    label: str,
    name: Any,
) -> dict[str, Any]:
    if module is None:
        raise ArtifactConsistencyError(
            f"{label} cannot be matched to final high-risk modules: {name}"
        )
    return module


def _module_name(module: dict[str, Any]) -> str:
    return str(module.get("模块名称") or module.get("module_name") or "").strip()


def _is_external_module(module: dict[str, Any]) -> bool:
    value = module.get("是否外部暴露面")
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(module.get("external_exposure"))
    return str(value).strip() == "是"


def _path_role_for_node(node: dict[str, Any]) -> str:
    if node.get("node_type") == "叶子节点" or node.get("external_exposure") is True:
        return "外部攻击入口"
    return "内部影响模块"


def _normalize_name(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).casefold()
