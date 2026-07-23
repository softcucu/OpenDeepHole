"""Audit code paths derived from a threat-analysis result."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task

PROCESS_NAME = "threat_audit"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "attack_tree_path",
    "high_risk_modules_path", "concurrency",
    "required_capability", "include_task_ids", "exclude_task_ids",
    "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {
    "project_path",
    "work_dir",
    "scan_id",
    "attack_tree_path",
    "high_risk_modules_path",
}
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-"
    r"[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)
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


def _display_label(value: Any, fallback: str) -> str:
    normalized = str(value or "").strip()
    if normalized and not _GENERATED_THREAT_ID_PATTERN.fullmatch(normalized):
        return normalized
    return fallback


def _stable_task_id(scan_id: str, identity: str) -> str:
    digest = hashlib.sha1(
        f"{scan_id}\0{identity}".encode("utf-8"),
    ).hexdigest()[:20]
    return f"threat-audit-{digest}"


def _task_description(
    *,
    attack_goal: str,
    surface_name: str,
    method_name: str,
    asset_name: str,
    risk_name: str,
) -> str:
    return (
        f"攻击目标：{attack_goal}；攻击面节点：{surface_name}；"
        f"攻击方式：{method_name}；资产：{asset_name}；风险：{risk_name}"
    )


def _load_json(path_value: Any, key: str) -> Any:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"{key} is not a file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{key} is not valid JSON: {path}") from exc


def _module_code_paths(module: dict[str, Any]) -> list[dict[str, str]]:
    raw_paths = module.get("代码目录")
    values = raw_paths if isinstance(raw_paths, list) else [raw_paths]
    description = str(
        module.get("判断为高风险模块的原因")
        or module.get("面临威胁")
        or ""
    )
    return [
        {"path": str(value).strip(), "description": description}
        for value in values
        if str(value or "").strip()
    ]


def _tasks(
    scan_id: str,
    attack_tree_data: dict[str, Any],
    high_risk_modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    modules_by_name = {
        str(module.get("模块名称") or "").strip(): module
        for module in high_risk_modules
        if isinstance(module, dict) and str(module.get("模块名称") or "").strip()
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_trees = attack_tree_data.get("attack_trees") or []
    for tree_index, tree in enumerate(raw_trees):
        if not isinstance(tree, dict):
            continue
        tree_id = str(tree.get("tree_id") or f"tree-{tree_index + 1}")
        asset = tree.get("value_asset")
        asset = asset if isinstance(asset, dict) else {}
        asset_name = _display_label(asset.get("asset_name"), "未命名资产")
        nodes = {
            str(node.get("node_id") or ""): node
            for node in tree.get("nodes") or []
            if isinstance(node, dict) and node.get("node_id")
        }
        for path_index, attack_path in enumerate(tree.get("attack_paths") or []):
            if not isinstance(attack_path, dict):
                continue
            path_id = str(
                attack_path.get("path_id")
                or f"{tree_id}-path-{path_index + 1}"
            )
            related = [
                item
                for item in attack_path.get("related_high_risk_modules") or []
                if isinstance(item, dict)
            ]
            matched_modules = [
                modules_by_name[name]
                for name in (
                    str(item.get("module_name") or "").strip()
                    for item in related
                )
                if name in modules_by_name
            ]
            code_paths: list[dict[str, str]] = []
            seen_paths: set[str] = set()
            for module in matched_modules:
                for code_path in _module_code_paths(module):
                    if code_path["path"] in seen_paths:
                        continue
                    seen_paths.add(code_path["path"])
                    code_paths.append(code_path)
            first_code_path = code_paths[0] if code_paths else {}
            surface = related[0] if related else {}
            surface_id = str(surface.get("node_id") or "")
            surface_name = _display_label(
                surface.get("module_name")
                or (nodes.get(surface_id) or {}).get("node_name"),
                "未命名高风险模块",
            )
            risks = list(dict.fromkeys(
                str(module.get("面临威胁") or "").strip()
                for module in matched_modules
                if str(module.get("面临威胁") or "").strip()
            ))
            risk_name = "；".join(risks) or "未命名风险"
            attack_goal = _display_label(
                attack_path.get("path_name"),
                str((nodes.get(str(tree.get("root_node_id") or "")) or {}).get("node_name") or "未命名攻击目标"),
            )
            evidence = [
                value
                for value in [
                    str(attack_path.get("path_description") or "").strip(),
                    *(str(item.get("association_description") or "").strip() for item in related),
                ]
                if value
            ]
            patterns = [
                item
                for item in attack_path.get("attack_patterns") or []
                if isinstance(item, dict)
            ]
            for pattern_index, pattern in enumerate(patterns):
                pattern_id = str(
                    pattern.get("pattern_id")
                    or f"{path_id}-pattern-{pattern_index + 1}"
                )
                method_name = _display_label(
                    pattern.get("pattern_name"),
                    "未命名攻击模式",
                )
                identity = f"{tree_id}\0{path_id}\0{pattern_id}\0{method_name}"
                if identity in seen:
                    continue
                seen.add(identity)
                fingerprint = hashlib.sha1(identity.encode("utf-8")).hexdigest()
                result.append({
                    "task_id": _stable_task_id(scan_id, identity),
                    "scan_id": scan_id,
                    "status": "pending",
                    "surface_node_id": surface_id,
                    "surface_name": surface_name,
                    "method_node_id": pattern_id,
                    "method_name": method_name,
                    "attack_goal": attack_goal,
                    "risk_id": "",
                    "risk_name": risk_name,
                    "asset_id": "",
                    "asset_name": asset_name,
                    "code_path": str(first_code_path.get("path") or ""),
                    "code_path_description": str(
                        first_code_path.get("description") or "",
                    ),
                    "code_paths": code_paths,
                    "attack_path_id": path_id,
                    "attack_path_fingerprint": fingerprint,
                    "preconditions": [],
                    "evidence": evidence,
                    "attack_pattern": dict(pattern),
                    "native_attack_path": dict(attack_path),
                    "description": _task_description(
                        attack_goal=attack_goal,
                        surface_name=surface_name,
                        method_name=method_name,
                        asset_name=asset_name,
                        risk_name=risk_name,
                    ),
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
    attack_tree_data = _load_json(
        kwargs["attack_tree_path"],
        "attack_tree_path",
    )
    if not isinstance(attack_tree_data, dict):
        raise TypeError("attack_tree_path must contain a JSON object")
    high_risk_modules = _load_json(
        kwargs["high_risk_modules_path"],
        "high_risk_modules_path",
    )
    if not isinstance(high_risk_modules, list):
        raise TypeError("high_risk_modules_path must contain a JSON array")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    scan_id = str(kwargs["scan_id"]).strip()
    tasks = _tasks(scan_id, attack_tree_data, high_risk_modules)
    included = {str(item) for item in kwargs.get("include_task_ids") or []}
    excluded = {str(item) for item in kwargs.get("exclude_task_ids") or []}
    if included:
        tasks = [task for task in tasks if task["task_id"] in included]
    tasks = [task for task in tasks if task["task_id"] not in excluded]
    await _emit(output, "progress", f"Prepared {len(tasks)} threat audit task(s)", total=len(tasks))

    semaphore = asyncio.Semaphore(concurrency)
    vulnerabilities: list[dict[str, Any]] = []
    result_lock = asyncio.Lock()

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
            prompt += (
                "\n\n请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回。"
                "最终回复只能包含这一个 JSON 值，不要使用 Markdown 代码围栏，"
                "也不要附加任何解释。应用程序会自行解析回复文本。\nJSON Schema：\n"
                + json.dumps(_RESULT_SCHEMA, ensure_ascii=False, indent=2)
            )
            try:
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
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                task["finished_at"] = datetime.now(timezone.utc).isoformat()
                task["status"] = "failed"
                task["failure_reason"] = str(exc)
                await _emit(
                    output,
                    "error",
                    f"Threat audit failed for {task['task_id']}: {exc}",
                    task_id=task["task_id"],
                )
                return
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
            async with result_lock:
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
