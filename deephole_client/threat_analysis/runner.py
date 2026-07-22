"""Async threat-analysis entry point independent from the backend."""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from task_agent import run_opencode_task

PROCESS_NAME = "threat_analysis"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "code_scan_path", "scan_id", "product",
    "reuse_cache", "result_path", "required_capability", "task_agent_config",
    "output", "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir"}

THREAT_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "assets": {"type": "array", "items": {"type": "object"}},
        "high_risk_external_interfaces": {"type": "array", "items": {"type": "object"}},
        "attack_trees": {"type": "array", "items": {"type": "object"}},
        "attack_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path_id": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "asset_name": {"type": "string"},
                    "risk_id": {"type": "string"},
                    "risk_name": {"type": "string"},
                    "attack_goal_name": {"type": "string"},
                    "attack_surface_id": {"type": "string"},
                    "attack_surface_name": {"type": "string"},
                    "attack_surface_type": {"type": "string"},
                    "attack_method_id": {"type": "string"},
                    "attack_method_name": {"type": "string"},
                    "preconditions": {"type": "array", "items": {"type": "string"}},
                    "code_paths": {"type": "array", "items": {"type": "object"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["path_id", "attack_surface_name", "attack_method_name", "code_paths"],
            },
        },
        "code_path_mappings": {"type": "array", "items": {"type": "object"}},
    },
    "required": ["assets", "high_risk_external_interfaces", "attack_paths"],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _directory(value: Any, key: str, *, create: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


async def run_threat_analysis(**kwargs: Any) -> dict[str, Any]:
    """Analyze one project and return an attack-tree-oriented threat model."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_threat_analysis() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_threat_analysis() missing required key(s): {', '.join(missing)}")

    project = _directory(kwargs["project_path"], "project_path")
    work_dir = _directory(kwargs["work_dir"], "work_dir", create=True)
    scan_root = _directory(kwargs.get("code_scan_path") or project, "code_scan_path")
    try:
        scope = scan_root.relative_to(project).as_posix()
    except ValueError as exc:
        raise ValueError("code_scan_path must be inside project_path") from exc
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    result_path = Path(kwargs.get("result_path") or work_dir / "threat_analysis.json").expanduser().resolve()

    if bool(kwargs.get("reuse_cache", True)) and result_path.is_file():
        cached = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(cached, dict):
            raise ValueError(f"cached threat analysis is not an object: {result_path}")
        await _emit(output, "artifact", "Loaded cached threat analysis", path=str(result_path))
        return {"status": "success", "analysis": cached, "cache_hit": True, "output_source": {}}
    if _cancelled(cancel_event):
        return {"status": "cancelled", "analysis": None, "cache_hit": False, "output_source": {}}

    product = str(kwargs.get("product") or "").strip()
    scan_id = str(kwargs.get("scan_id") or "standalone").strip()
    prompt = f"""你是软件威胁建模专家。请对当前项目目录进行攻击树威胁分析。

项目根目录：{project}
扫描范围：{scope or '.'}
产品：{product or '未指定'}

必须先检查真实代码、入口、协议解析、权限边界和敏感资产，再输出符合给定 JSON schema 的结果。
每条 attack_path 必须给出可审计的 attack_surface、attack_method 和 code_paths；不要编造不存在的文件。
"""
    await _emit(output, "progress", "Threat analysis started", scan_id=scan_id)
    result = await run_opencode_task(
        task_name=f"threat-analysis-{scan_id}",
        task_type="threat_analysis",
        prompt=prompt,
        required_capability=capability,
        output_schema=THREAT_ANALYSIS_SCHEMA,
        config_path=kwargs.get("task_agent_config"),
        output=None,
        cancel_event=cancel_event,
    )
    if result.status != "success" or not isinstance(result.structured, dict):
        await _emit(output, "log", "Threat analysis failed", status=result.status, error=result.text)
        return {
            "status": result.status,
            "analysis": None,
            "cache_hit": False,
            "error": result.text,
            "output_source": result.output_source,
        }
    raw = dict(result.structured)
    analysis = {
        "schema_version": "1.1",
        "analysis_id": f"TA-{uuid4().hex[:16]}",
        "sources": {"code": True, "document": False, "mcp": False},
        "scan_scope": {
            "project_root": str(project),
            "code_scan_path": str(scan_root),
            "relative_path": scope or ".",
        },
        "assets": list(raw.get("assets") or []),
        "high_risk_external_interfaces": list(raw.get("high_risk_external_interfaces") or []),
        "attack_trees": list(raw.get("attack_trees") or []),
        "attack_paths": list(raw.get("attack_paths") or []),
        "code_path_mappings": list(raw.get("code_path_mappings") or []),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    await _emit(
        output, "artifact", "Threat analysis completed",
        path=str(result_path), attack_path_count=len(analysis["attack_paths"]),
    )
    return {
        "status": "success",
        "analysis": analysis,
        "cache_hit": False,
        "output_source": result.output_source,
    }
