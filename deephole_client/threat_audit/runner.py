"""Audit code paths derived from a threat-analysis result."""

from __future__ import annotations

import asyncio
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task

PROCESS_NAME = "threat_audit"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "threat_analysis", "concurrency",
    "required_capability", "include_task_ids", "exclude_task_ids",
    "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir", "scan_id", "threat_analysis"}
_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "call_chain": {"type": "array", "items": {"type": "string"}},
                    "vuln_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": "string"},
                    "ai_analysis": {"type": "string"},
                    "vulnerability_report": {"type": "string"},
                    "confirmed": {"type": "boolean"},
                    "ai_verdict": {"type": "string"},
                },
                "required": [
                    "file", "line", "function", "vuln_type", "severity",
                    "description", "ai_analysis", "confirmed", "ai_verdict",
                ],
            },
        }
    },
    "required": ["vulnerabilities"],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _tasks(scan_id: str, analysis: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path_index, attack_path in enumerate(analysis.get("attack_paths") or []):
        if not isinstance(attack_path, dict):
            continue
        code_paths = attack_path.get("code_paths") or [{}]
        for code_index, code_path in enumerate(code_paths):
            if isinstance(code_path, str):
                code_path = {"path": code_path, "description": ""}
            if not isinstance(code_path, dict):
                continue
            path_id = str(attack_path.get("path_id") or f"path-{path_index + 1}")
            result.append({
                "task_id": f"{scan_id}:threat:{path_id}:{code_index + 1}",
                "scan_id": scan_id,
                "status": "pending",
                "surface_node_id": str(attack_path.get("attack_surface_id") or ""),
                "surface_name": str(attack_path.get("attack_surface_name") or ""),
                "method_node_id": str(attack_path.get("attack_method_id") or ""),
                "method_name": str(attack_path.get("attack_method_name") or ""),
                "attack_goal": str(attack_path.get("attack_goal_name") or ""),
                "risk_id": str(attack_path.get("risk_id") or ""),
                "risk_name": str(attack_path.get("risk_name") or ""),
                "asset_id": str(attack_path.get("asset_id") or ""),
                "asset_name": str(attack_path.get("asset_name") or ""),
                "code_path": str(code_path.get("path") or ""),
                "code_path_description": str(code_path.get("description") or ""),
                "attack_path_id": path_id,
                "attack_path_fingerprint": str(attack_path.get("fingerprint") or ""),
                "preconditions": list(attack_path.get("preconditions") or []),
                "evidence": list(attack_path.get("evidence") or []),
            })
    return result


def _normalize_vulnerability(raw: dict[str, Any], task: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    confirmed = bool(raw.get("confirmed"))
    return {
        "file": str(raw.get("file") or task["code_path"] or "."),
        "line": max(1, int(raw.get("line") or 1)),
        "function": str(raw.get("function") or "__threat_path__"),
        "call_chain": list(raw.get("call_chain") or []),
        "vuln_type": str(raw.get("vuln_type") or "threat_path"),
        "severity": str(raw.get("severity") or "unknown"),
        "description": str(raw.get("description") or task["method_name"]),
        "ai_analysis": str(raw.get("ai_analysis") or ""),
        "vulnerability_report": str(raw.get("vulnerability_report") or ""),
        "confirmed": confirmed,
        "ai_verdict": str(raw.get("ai_verdict") or ("confirmed" if confirmed else "not_confirmed")),
        "failure_reason": "",
        "analysis_source": "threat_audit",
        "source_task_id": task["task_id"],
        "threat_surface_node_id": task["surface_node_id"],
        "threat_method_node_id": task["method_node_id"],
        "threat_code_path": task["code_path"],
        "output_source": source,
    }


async def run_threat_audit(**kwargs: Any) -> dict[str, Any]:
    """Run a bounded model audit for every selected threat code path."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_threat_audit() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_threat_audit() missing required key(s): {', '.join(missing)}")
    project = Path(kwargs["project_path"]).expanduser().resolve()
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    work_dir.mkdir(parents=True, exist_ok=True)
    analysis = kwargs["threat_analysis"]
    if not isinstance(analysis, dict):
        raise TypeError("threat_analysis must be a dict")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    scan_id = str(kwargs["scan_id"]).strip()
    tasks = _tasks(scan_id, analysis)
    included = {str(item) for item in kwargs.get("include_task_ids") or []}
    excluded = {str(item) for item in kwargs.get("exclude_task_ids") or []}
    if included:
        tasks = [task for task in tasks if task["task_id"] in included]
    tasks = [task for task in tasks if task["task_id"] not in excluded]
    await _emit(output, "progress", f"Prepared {len(tasks)} threat audit task(s)", total=len(tasks))

    semaphore = asyncio.Semaphore(concurrency)
    vulnerabilities: list[dict[str, Any]] = []

    async def audit(task: dict[str, Any]) -> None:
        if _cancelled(cancel_event):
            task["status"] = "cancelled"
            return
        async with semaphore:
            task["status"] = "running"
            task["started_at"] = datetime.now(timezone.utc).isoformat()
            await _emit(output, "progress", f"Auditing {task['task_id']}", task_id=task["task_id"])
            prompt = """请审计当前项目中的以下威胁路径，确认是否存在可利用的真实漏洞。
必须读取真实代码。不存在漏洞时返回空 vulnerabilities；不得为凑结果而推测。
威胁任务：
""" + json.dumps(task, ensure_ascii=False, indent=2)
            result = await run_opencode_task(
                task_name=task["task_id"],
                task_type="threat_audit",
                prompt=prompt,
                required_capability=capability,
                output_schema=_RESULT_SCHEMA,
                config_path=kwargs.get("task_agent_config"),
                output=None,
                cancel_event=cancel_event,
            )
            task["finished_at"] = datetime.now(timezone.utc).isoformat()
            task["output_source"] = result.output_source
            if result.status != "success" or not isinstance(result.structured, dict):
                task["status"] = result.status
                task["failure_reason"] = result.text
                return
            produced = [
                _normalize_vulnerability(item, task, result.output_source)
                for item in result.structured.get("vulnerabilities") or []
                if isinstance(item, dict)
            ]
            vulnerabilities.extend(produced)
            task["status"] = "completed"
            task["result_count"] = len(produced)
            await _emit(
                output, "item", f"Completed {task['task_id']}",
                task_id=task["task_id"], vulnerability_count=len(produced),
            )

    await asyncio.gather(*(audit(task) for task in tasks))
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {"status": status, "tasks": tasks, "vulnerabilities": vulnerabilities}
