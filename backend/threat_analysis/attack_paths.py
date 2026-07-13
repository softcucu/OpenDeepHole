"""Streaming attack-path helpers for the threat-analysis harness."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
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


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str_list(value: Any) -> list[str]:
    out: list[str] = []
    for item in _list(value):
        if isinstance(item, dict):
            normalized = json.dumps(item, ensure_ascii=False, sort_keys=True)
        else:
            normalized = _text(item)
        if normalized and normalized not in out:
            out.append(normalized)
    return out


def _stable_id(prefix: str, *parts: object) -> str:
    raw = "\0".join(_text(part).lower() for part in parts if _text(part))
    if not raw:
        raw = prefix.lower()
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def _normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", _text(value).lower())


def _normalize_path(value: str) -> str:
    normalized = _text(value).replace("\\", "/")
    normalized = re.sub(r"/+", "/", normalized).strip("/")
    return normalized or "."


def _code_paths(value: Any) -> list[ThreatCodePath]:
    paths: list[ThreatCodePath] = []
    seen: set[str] = set()
    for item in _list(value):
        if isinstance(item, dict):
            path = _normalize_path(item.get("path", ""))
            description = _text(item.get("description"))
        else:
            path = _normalize_path(item)
            description = ""
        if not path or path in seen:
            continue
        seen.add(path)
        paths.append(ThreatCodePath(path=path, description=description))
    return paths


def attack_path_fingerprint(path: ThreatAttackPath) -> str:
    """Return the stable dedupe key for one normalized attack path."""
    code_path_key = "|".join(sorted(_normalize_path(item.path) for item in path.code_paths))
    raw = "\0".join([
        _normalize_name(path.asset_name or path.asset_id),
        _normalize_name(path.attack_goal_name or path.attack_goal_id),
        _normalize_name(path.attack_domain_name or path.attack_domain_id),
        _normalize_name(path.attack_surface_name or path.attack_surface_id),
        _normalize_name(path.attack_method_name or path.attack_method_id),
        code_path_key,
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def parse_attack_path_data(data: dict[str, Any]) -> ThreatAttackPath:
    """Normalize flat or nested Agent output into ``ThreatAttackPath``."""
    asset = data.get("asset") if isinstance(data.get("asset"), dict) else {}
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    goal = data.get("attack_goal") if isinstance(data.get("attack_goal"), dict) else {}
    domain = data.get("attack_domain") if isinstance(data.get("attack_domain"), dict) else {}
    surface = data.get("attack_surface") if isinstance(data.get("attack_surface"), dict) else {}
    method = data.get("attack_method") if isinstance(data.get("attack_method"), dict) else {}

    asset_name = _text(data.get("asset_name") or asset.get("name"))
    risk_name = _text(data.get("risk_name") or risk.get("name"))
    goal_name = _text(data.get("attack_goal_name") or goal.get("name"))
    domain_name = _text(data.get("attack_domain_name") or domain.get("name"))
    surface_name = _text(data.get("attack_surface_name") or surface.get("name"))
    method_name = _text(data.get("attack_method_name") or method.get("name"))
    code_paths = _code_paths(data.get("code_paths"))

    path = ThreatAttackPath(
        path_id=_text(data.get("path_id")),
        fingerprint=_text(data.get("fingerprint")),
        asset_id=_text(data.get("asset_id") or asset.get("asset_id") or asset.get("id")),
        asset_name=asset_name,
        risk_id=_text(data.get("risk_id") or risk.get("risk_id") or risk.get("id")),
        risk_name=risk_name,
        attack_goal_id=_text(data.get("attack_goal_id") or goal.get("attack_goal_id") or goal.get("goal_id") or goal.get("id")),
        attack_goal_name=goal_name,
        attack_domain_id=_text(data.get("attack_domain_id") or domain.get("domain_id") or domain.get("id")),
        attack_domain_name=domain_name,
        attack_surface_id=_text(data.get("attack_surface_id") or surface.get("surface_id") or surface.get("id")),
        attack_surface_name=surface_name,
        attack_surface_type=_text(data.get("attack_surface_type") or surface.get("surface_type") or surface.get("type")),
        attack_method_id=_text(data.get("attack_method_id") or method.get("method_id") or method.get("id")),
        attack_method_name=method_name,
        preconditions=_str_list(data.get("preconditions") or method.get("preconditions")),
        code_paths=code_paths,
        evidence=_str_list(data.get("evidence")),
        source=_text(data.get("source"), "code") or "code",
        agent_sources=_str_list(data.get("agent_sources")),
    )
    path = _fill_missing_ids(path)
    fingerprint = path.fingerprint or attack_path_fingerprint(path)
    path_id = path.path_id or _stable_id("AP", fingerprint)
    return path.model_copy(update={"fingerprint": fingerprint, "path_id": path_id})


def _fill_missing_ids(path: ThreatAttackPath) -> ThreatAttackPath:
    asset_id = path.asset_id or _stable_id("ASSET", path.asset_name)
    risk_id = path.risk_id or _stable_id("RISK", asset_id, path.risk_name)
    goal_id = path.attack_goal_id or _stable_id("GOAL", risk_id, path.attack_goal_name)
    domain_id = path.attack_domain_id or _stable_id("DOMAIN", goal_id, path.attack_domain_name)
    surface_id = path.attack_surface_id or _stable_id("SURFACE", domain_id, path.attack_surface_name)
    method_id = path.attack_method_id or _stable_id("METHOD", surface_id, path.attack_method_name)
    return path.model_copy(update={
        "asset_id": asset_id,
        "risk_id": risk_id,
        "attack_goal_id": goal_id,
        "attack_domain_id": domain_id,
        "attack_surface_id": surface_id,
        "attack_method_id": method_id,
    })


def _merge_unique_strings(*groups: list[str]) -> list[str]:
    out: list[str] = []
    for group in groups:
        for item in group:
            normalized = _text(item)
            if normalized and normalized not in out:
                out.append(normalized)
    return out


def _merge_code_paths(*groups: list[ThreatCodePath]) -> list[ThreatCodePath]:
    out: dict[str, ThreatCodePath] = {}
    for group in groups:
        for item in group:
            path = _normalize_path(item.path)
            if not path:
                continue
            existing = out.get(path)
            if existing is None:
                out[path] = item.model_copy(update={"path": path})
            elif not existing.description and item.description:
                out[path] = existing.model_copy(update={"description": item.description})
    return list(out.values())


def _merged_source(left: str, right: str) -> str:
    values = {_text(left), _text(right)} - {""}
    if "mcp_and_code" in values or values == {"mcp", "code"}:
        return "mcp_and_code"
    if "mcp" in values:
        return "mcp"
    return "code"


def merge_attack_path(existing: ThreatAttackPath, incoming: ThreatAttackPath) -> ThreatAttackPath:
    """Merge duplicate attack paths without losing evidence or source details."""
    updates: dict[str, object] = {
        "preconditions": _merge_unique_strings(existing.preconditions, incoming.preconditions),
        "code_paths": _merge_code_paths(existing.code_paths, incoming.code_paths),
        "evidence": _merge_unique_strings(existing.evidence, incoming.evidence),
        "agent_sources": _merge_unique_strings(existing.agent_sources, incoming.agent_sources),
        "source": _merged_source(existing.source, incoming.source),
    }
    for field in (
        "path_id", "asset_id", "asset_name", "risk_id", "risk_name",
        "attack_goal_id", "attack_goal_name", "attack_domain_id", "attack_domain_name",
        "attack_surface_id", "attack_surface_name", "attack_surface_type",
        "attack_method_id", "attack_method_name",
    ):
        if not getattr(existing, field) and getattr(incoming, field):
            updates[field] = getattr(incoming, field)
    return existing.model_copy(update=updates)


def read_attack_paths_jsonl(path: Path) -> list[ThreatAttackPath]:
    if not path.is_file():
        return []
    out: list[ThreatAttackPath] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        data = json.loads(stripped)
        if isinstance(data, dict):
            out.append(parse_attack_path_data(data))
    return out


def merge_attack_paths(paths: list[ThreatAttackPath]) -> list[ThreatAttackPath]:
    by_fingerprint: dict[str, ThreatAttackPath] = {}
    for path in paths:
        normalized = _fill_missing_ids(path)
        fingerprint = normalized.fingerprint or attack_path_fingerprint(normalized)
        normalized = normalized.model_copy(update={
            "fingerprint": fingerprint,
            "path_id": normalized.path_id or _stable_id("AP", fingerprint),
        })
        existing = by_fingerprint.get(fingerprint)
        by_fingerprint[fingerprint] = (
            normalized if existing is None else merge_attack_path(existing, normalized)
        )
    return list(by_fingerprint.values())


def write_attack_paths_jsonl(path: Path, paths: list[ThreatAttackPath]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = merge_attack_paths(paths)
    text = "\n".join(item.model_dump_json() for item in merged)
    path.write_text(text + ("\n" if text else ""), encoding="utf-8")


def append_or_merge_attack_path(path: Path, attack_path: ThreatAttackPath) -> list[ThreatAttackPath]:
    paths = read_attack_paths_jsonl(path)
    paths.append(attack_path)
    merged = merge_attack_paths(paths)
    write_attack_paths_jsonl(path, merged)
    return merged


def build_analysis_from_attack_paths(
    paths: list[ThreatAttackPath],
    *,
    analysis_id: str,
    sources: ThreatAnalysisSources,
    scan_scope: ThreatAnalysisScanScope,
) -> ThreatAnalysis:
    """Rebuild public threat-analysis objects from the JSONL fact stream."""
    normalized_paths = merge_attack_paths(paths)
    assets_by_id: dict[str, ThreatAsset] = {}
    interfaces_by_id: dict[str, ThreatExternalInterface] = {}
    code_paths_by_surface: dict[str, list[ThreatCodePath]] = {}
    tree_data: dict[tuple[str, str, str], dict[str, Any]] = {}

    for path in normalized_paths:
        asset = assets_by_id.get(path.asset_id)
        risk = ThreatRisk(
            risk_id=path.risk_id,
            name=path.risk_name,
            description=path.risk_name,
        )
        if asset is None:
            assets_by_id[path.asset_id] = ThreatAsset(
                asset_id=path.asset_id,
                name=path.asset_name,
                asset_type="other",
                criticality="medium",
                risks=[risk] if path.risk_id else [],
            )
        elif path.risk_id and all(item.risk_id != path.risk_id for item in asset.risks):
            asset.risks.append(risk)

        interface = interfaces_by_id.get(path.attack_surface_id)
        if interface is None:
            interfaces_by_id[path.attack_surface_id] = ThreatExternalInterface(
                interface_id=path.attack_surface_id,
                name=path.attack_surface_name,
                interface_type=path.attack_surface_type or "other",
                affected_asset_ids=[path.asset_id] if path.asset_id else [],
                candidate_code_paths=path.code_paths,
                source=path.source,
            )
        else:
            interface.affected_asset_ids = _merge_unique_strings(interface.affected_asset_ids, [path.asset_id])
            interface.candidate_code_paths = _merge_code_paths(interface.candidate_code_paths, path.code_paths)
            interface.source = _merged_source(interface.source, path.source)

        code_paths_by_surface[path.attack_surface_id] = _merge_code_paths(
            code_paths_by_surface.get(path.attack_surface_id, []),
            path.code_paths,
        )

        tree_key = (path.asset_id, path.risk_id, path.attack_goal_id)
        current = tree_data.setdefault(tree_key, {
            "asset_id": path.asset_id,
            "risk_id": path.risk_id,
            "goal_id": path.attack_goal_id,
            "goal_name": path.attack_goal_name,
            "domains": {},
        })
        domains = current["domains"]
        domain = domains.setdefault(path.attack_domain_id, {
            "name": path.attack_domain_name,
            "surfaces": {},
        })
        surfaces = domain["surfaces"]
        surface = surfaces.setdefault(path.attack_surface_id, {
            "name": path.attack_surface_name,
            "surface_type": path.attack_surface_type,
            "methods": {},
        })
        surface["methods"].setdefault(path.attack_method_id, {
            "name": path.attack_method_name,
            "preconditions": path.preconditions,
            "basis": path.evidence,
        })

    attack_trees: list[ThreatAttackTree] = []
    for index, item in enumerate(tree_data.values(), start=1):
        nodes: list[ThreatAttackTreeNode] = []
        goal_id = item["goal_id"]
        nodes.append(ThreatAttackTreeNode(
            node_id=goal_id,
            parent_id=None,
            node_type="goal",
            name=item["goal_name"],
            order=1,
        ))
        domain_order = 1
        for domain_id, domain in item["domains"].items():
            nodes.append(ThreatAttackTreeNode(
                node_id=domain_id,
                parent_id=goal_id,
                node_type="domain",
                name=domain["name"],
                order=domain_order,
            ))
            surface_order = 1
            for surface_id, surface in domain["surfaces"].items():
                nodes.append(ThreatAttackTreeNode(
                    node_id=surface_id,
                    parent_id=domain_id,
                    node_type="surface",
                    name=surface["name"],
                    order=surface_order,
                    surface_type=surface["surface_type"],
                ))
                method_order = 1
                for method_id, method in surface["methods"].items():
                    nodes.append(ThreatAttackTreeNode(
                        node_id=method_id,
                        parent_id=surface_id,
                        node_type="method",
                        name=method["name"],
                        order=method_order,
                        basis=method["basis"],
                        preconditions=method["preconditions"],
                    ))
                    method_order += 1
                surface_order += 1
            domain_order += 1
        attack_trees.append(ThreatAttackTree(
            tree_id=f"TREE-{index:03d}",
            asset_id=item["asset_id"],
            risk_id=item["risk_id"],
            attack_goal=item["goal_name"],
            root_node_id=goal_id,
            nodes=nodes,
        ))

    mappings = [
        ThreatCodePathMapping(surface_node_id=surface_id, code_paths=code_paths)
        for surface_id, code_paths in code_paths_by_surface.items()
    ]
    return ThreatAnalysis(
        schema_version="1.1",
        analysis_id=analysis_id,
        sources=sources,
        scan_scope=scan_scope,
        assets=list(assets_by_id.values()),
        high_risk_external_interfaces=list(interfaces_by_id.values()),
        attack_trees=attack_trees,
        attack_paths=normalized_paths,
        code_path_mappings=mappings,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
