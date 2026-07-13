"""Parsing helpers for attack-tree threat-analysis JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.models import (
    ThreatAnalysis,
    ThreatAnalysisScanScope,
    ThreatAnalysisSources,
    ThreatAsset,
    ThreatAttackPath,
    ThreatAttackTree,
    ThreatAttackTreeNode,
    ThreatCodePath,
    ThreatCodePathMapping,
    ThreatExternalInterface,
    ThreatRisk,
)


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            raise
        data = json.loads(stripped[start:end + 1])
    if not isinstance(data, dict):
        raise ValueError("threat analysis output must be a JSON object")
    return data


def _str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized if normalized else None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        normalized = _str(item)
        if normalized:
            out.append(normalized)
    return out


def _code_paths(value: Any) -> list[ThreatCodePath]:
    paths: list[ThreatCodePath] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                path = _str(item.get("path"))
                if path:
                    paths.append(
                        ThreatCodePath(
                            path=path,
                            description=_str(item.get("description")),
                        )
                    )
            else:
                path = _str(item)
                if path:
                    paths.append(ThreatCodePath(path=path))
    return paths


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_threat_analysis_scan_scope(
    project_path: Path,
    code_scan_path: Path | None = None,
) -> ThreatAnalysisScanScope:
    """Return normalized scope metadata for a threat-analysis artifact."""
    project_root = project_path.expanduser().resolve()
    scan_root = (code_scan_path or project_root).expanduser().resolve()
    try:
        relative = scan_root.relative_to(project_root).as_posix()
    except ValueError:
        relative = scan_root.as_posix()
    if not relative:
        relative = "."
    return ThreatAnalysisScanScope(
        project_path=project_root.as_posix(),
        code_scan_path=scan_root.as_posix(),
        code_scan_relative_path=relative,
    )


def apply_threat_analysis_scan_scope(
    analysis: ThreatAnalysis,
    project_path: Path,
    code_scan_path: Path | None = None,
) -> ThreatAnalysis:
    """Attach the authoritative scan scope to parsed threat-analysis output."""
    return analysis.model_copy(
        update={
            "scan_scope": build_threat_analysis_scan_scope(project_path, code_scan_path),
        }
    )


def threat_analysis_scope_matches(
    analysis: ThreatAnalysis,
    project_path: Path,
    code_scan_path: Path | None = None,
) -> bool:
    """Return True only when an artifact was generated for the requested scan scope."""
    scope = analysis.scan_scope
    if not scope.project_path or not scope.code_scan_path:
        return False
    expected = build_threat_analysis_scan_scope(project_path, code_scan_path)
    try:
        stored_project = Path(scope.project_path).expanduser().resolve()
        stored_scan = Path(scope.code_scan_path).expanduser().resolve()
    except OSError:
        return (
            scope.project_path == expected.project_path
            and scope.code_scan_path == expected.code_scan_path
        )
    return (
        stored_project == Path(expected.project_path)
        and stored_scan == Path(expected.code_scan_path)
    )


def write_threat_analysis_file(path: Path, analysis: ThreatAnalysis) -> None:
    """Persist normalized threat-analysis JSON."""
    path.write_text(
        json.dumps(analysis.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_threat_analysis_data(data: dict[str, Any]) -> ThreatAnalysis:
    """Normalize raw ``res.json`` data into the public API model."""
    sources_raw = data.get("sources") if isinstance(data.get("sources"), dict) else {}
    sources = ThreatAnalysisSources(
        repositories=_str_list(sources_raw.get("repositories")),
        documents=_str_list(sources_raw.get("documents")),
        mcp_available=bool(sources_raw.get("mcp_available", False)),
        product_mcp_name=_str(sources_raw.get("product_mcp_name")),
    )
    scan_scope_raw = data.get("scan_scope") if isinstance(data.get("scan_scope"), dict) else {}
    scan_scope = ThreatAnalysisScanScope(
        project_path=_str(scan_scope_raw.get("project_path")),
        code_scan_path=_str(scan_scope_raw.get("code_scan_path")),
        code_scan_relative_path=_str(scan_scope_raw.get("code_scan_relative_path")),
    )

    assets: list[ThreatAsset] = []
    for raw_asset in _dict_list(data.get("assets")):
        risks = [
            ThreatRisk(
                risk_id=_str(raw_risk.get("risk_id")),
                name=_str(raw_risk.get("name")),
                security_property=_str(raw_risk.get("security_property")),
                description=_str(raw_risk.get("description")),
            )
            for raw_risk in _dict_list(raw_asset.get("risks"))
        ]
        assets.append(
            ThreatAsset(
                asset_id=_str(raw_asset.get("asset_id")),
                name=_str(raw_asset.get("name")),
                description=_str(raw_asset.get("description")),
                asset_type=_str(raw_asset.get("asset_type"), "other") or "other",
                criticality=_str(raw_asset.get("criticality"), "medium") or "medium",
                risks=risks,
            )
        )

    attack_trees: list[ThreatAttackTree] = []
    for raw_tree in _dict_list(data.get("attack_trees")):
        nodes = [
            ThreatAttackTreeNode(
                node_id=_str(raw_node.get("node_id")),
                parent_id=_str_or_none(raw_node.get("parent_id")),
                node_type=_str(raw_node.get("node_type")),
                name=_str(raw_node.get("name")),
                order=_int(raw_node.get("order")),
                basis=_str_list(raw_node.get("basis")),
                surface_type=_str(raw_node.get("surface_type")),
                preconditions=_str_list(raw_node.get("preconditions")),
            )
            for raw_node in _dict_list(raw_tree.get("nodes"))
        ]
        attack_trees.append(
            ThreatAttackTree(
                tree_id=_str(raw_tree.get("tree_id")),
                asset_id=_str(raw_tree.get("asset_id")),
                risk_id=_str(raw_tree.get("risk_id")),
                attack_goal=_str(raw_tree.get("attack_goal")),
                root_node_id=_str(raw_tree.get("root_node_id")),
                nodes=nodes,
            )
        )

    mappings: list[ThreatCodePathMapping] = []
    for raw_mapping in _dict_list(data.get("code_path_mappings")):
        mappings.append(
            ThreatCodePathMapping(
                surface_node_id=_str(raw_mapping.get("surface_node_id")),
                code_paths=_code_paths(raw_mapping.get("code_paths")),
            )
        )

    interfaces: list[ThreatExternalInterface] = []
    for raw_interface in _dict_list(data.get("high_risk_external_interfaces")):
        interfaces.append(
            ThreatExternalInterface(
                interface_id=_str(raw_interface.get("interface_id")),
                name=_str(raw_interface.get("name")),
                description=_str(raw_interface.get("description")),
                interface_type=_str(raw_interface.get("interface_type"), "other") or "other",
                component=_str(raw_interface.get("component")),
                exposure=_str(raw_interface.get("exposure")),
                input_types=_str_list(raw_interface.get("input_types")),
                auth_required=_str(raw_interface.get("auth_required")),
                affected_asset_ids=_str_list(raw_interface.get("affected_asset_ids")),
                candidate_code_paths=_code_paths(raw_interface.get("candidate_code_paths")),
                source=_str(raw_interface.get("source"), "code") or "code",
            )
        )

    attack_paths: list[ThreatAttackPath] = []
    for raw_path in _dict_list(data.get("attack_paths")):
        attack_paths.append(
            ThreatAttackPath(
                path_id=_str(raw_path.get("path_id")),
                fingerprint=_str(raw_path.get("fingerprint")),
                asset_id=_str(raw_path.get("asset_id")),
                asset_name=_str(raw_path.get("asset_name")),
                risk_id=_str(raw_path.get("risk_id")),
                risk_name=_str(raw_path.get("risk_name")),
                attack_goal_id=_str(raw_path.get("attack_goal_id")),
                attack_goal_name=_str(raw_path.get("attack_goal_name")),
                attack_domain_id=_str(raw_path.get("attack_domain_id")),
                attack_domain_name=_str(raw_path.get("attack_domain_name")),
                attack_surface_id=_str(raw_path.get("attack_surface_id")),
                attack_surface_name=_str(raw_path.get("attack_surface_name")),
                attack_surface_type=_str(raw_path.get("attack_surface_type")),
                attack_method_id=_str(raw_path.get("attack_method_id")),
                attack_method_name=_str(raw_path.get("attack_method_name")),
                preconditions=_str_list(raw_path.get("preconditions")),
                code_paths=_code_paths(raw_path.get("code_paths")),
                evidence=_str_list(raw_path.get("evidence")),
                source=_str(raw_path.get("source"), "code") or "code",
                agent_sources=_str_list(raw_path.get("agent_sources")),
            )
        )

    return ThreatAnalysis(
        schema_version=_str(data.get("schema_version"), "1.0") or "1.0",
        analysis_id=_str(data.get("analysis_id")),
        sources=sources,
        scan_scope=scan_scope,
        assets=assets,
        high_risk_external_interfaces=interfaces,
        attack_trees=attack_trees,
        attack_paths=attack_paths,
        code_path_mappings=mappings,
        updated_at=_str(data.get("updated_at")),
    )


def parse_threat_analysis_file(path: Path) -> ThreatAnalysis:
    """Read and parse the attack-tree Skill ``res.json`` output."""
    return parse_threat_analysis_data(_extract_json_object(path.read_text(encoding="utf-8")))
