"""Audit a batch of static-analysis candidates with Task Agent."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

import yaml
from task_agent import run_opencode_task

PROCESS_NAME = "candidate_audit"
PROJECT_LEVEL_FUNCTION = "__project__"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "candidates", "checker_dirs",
    "index_db_path", "checker_names", "concurrency", "required_capability",
    "pattern_filter_enabled", "pattern_filter_scope", "feedback_entries",
    "audit_index_offset", "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {
    "project_path", "work_dir", "scan_id", "candidates", "checker_dirs", "index_db_path",
}
_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"}, "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "call_chain": {"type": "array", "items": {"type": "string"}},
                    "vuln_type": {"type": "string"}, "severity": {"type": "string"},
                    "description": {"type": "string"}, "ai_analysis": {"type": "string"},
                    "vulnerability_report": {"type": "string"},
                    "confirmed": {"type": "boolean"}, "ai_verdict": {"type": "string"},
                },
                "required": [
                    "file", "line", "function", "vuln_type", "severity",
                    "description", "ai_analysis", "confirmed", "ai_verdict",
                ],
            },
        },
        "markdown_reports": {"type": "array", "items": {"type": "object"}},
    },
    "required": ["vulnerabilities", "markdown_reports"],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _checker_catalog(roots: list[Path]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for root in roots:
        if not root.is_dir():
            raise FileNotFoundError(f"checker directory does not exist: {root}")
        for directory in sorted(root.iterdir()):
            manifest = directory / "checker.yaml"
            if not directory.is_dir() or not manifest.is_file():
                continue
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or directory.name).strip()
            if name in result:
                continue
            skill_path = directory / "SKILL.md"
            result[name] = {
                "name": name,
                "label": str(raw.get("label") or name),
                "result_mode": str(raw.get("result_mode") or "vulnerabilities"),
                "skill": skill_path.read_text(encoding="utf-8") if skill_path.is_file() else "",
            }
    return result


def _normalize_vulnerability(
    raw: dict[str, Any], candidate: dict[str, Any], audit_index: int, source: dict[str, Any],
) -> dict[str, Any]:
    confirmed = bool(raw.get("confirmed"))
    return {
        "file": str(raw.get("file") or candidate.get("file") or "."),
        "line": max(1, int(raw.get("line") or candidate.get("line") or 1)),
        "function": str(raw.get("function") or candidate.get("function") or "<unknown>"),
        "call_chain": list(raw.get("call_chain") or []),
        "vuln_type": str(raw.get("vuln_type") or candidate.get("vuln_type") or "unknown"),
        "severity": str(raw.get("severity") or "unknown"),
        "description": str(raw.get("description") or candidate.get("description") or ""),
        "ai_analysis": str(raw.get("ai_analysis") or ""),
        "vulnerability_report": str(raw.get("vulnerability_report") or ""),
        "confirmed": confirmed,
        "ai_verdict": str(raw.get("ai_verdict") or ("confirmed" if confirmed else "not_confirmed")),
        "failure_reason": "",
        "audit_index": audit_index,
        "analysis_source": "static_candidate",
        "output_source": source,
    }


def _fallback(candidate: dict[str, Any], audit_index: int, status: str, reason: str, source: dict[str, Any]) -> dict[str, Any]:
    verdict = "timeout" if status == "timeout" else "failed"
    return {
        "file": str(candidate.get("file") or "."),
        "line": max(1, int(candidate.get("line") or 1)),
        "function": str(candidate.get("function") or "<unknown>"),
        "call_chain": [],
        "vuln_type": str(candidate.get("vuln_type") or "unknown"),
        "severity": "unknown",
        "description": str(candidate.get("description") or ""),
        "ai_analysis": reason or "No analysis result returned",
        "vulnerability_report": "",
        "confirmed": False,
        "ai_verdict": verdict,
        "failure_reason": reason,
        "audit_index": audit_index,
        "analysis_source": "static_candidate",
        "output_source": source,
    }


def _pattern_key(candidate: dict[str, Any], scope: str) -> tuple[str, ...]:
    if scope == "file":
        return (str(candidate.get("vuln_type")), str(candidate.get("file")))
    if scope == "global":
        return (str(candidate.get("vuln_type")),)
    return (str(candidate.get("vuln_type")), str(candidate.get("function")))


async def run_candidate_audit(**kwargs: Any) -> dict[str, Any]:
    """Audit a whole candidate batch and return vulnerabilities and checkpoints."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_candidate_audit() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_candidate_audit() missing required key(s): {', '.join(missing)}")
    project = Path(kwargs["project_path"]).expanduser().resolve()
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    index_path = Path(kwargs["index_db_path"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    if not index_path.is_file():
        raise FileNotFoundError(f"index_db_path is not a file: {index_path}")
    work_dir.mkdir(parents=True, exist_ok=True)
    candidates = kwargs["candidates"]
    if not isinstance(candidates, list):
        raise TypeError("candidates must be a list")
    normalized_candidates = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            if hasattr(candidate, "model_dump"):
                candidate = candidate.model_dump()
            else:
                raise TypeError(f"candidates[{index}] must be a dict")
        normalized_candidates.append(dict(candidate))
    checker_dirs = [Path(item).expanduser().resolve() for item in kwargs["checker_dirs"]]
    catalog = _checker_catalog(checker_dirs)
    selected = {str(item) for item in kwargs.get("checker_names") or []}
    if selected:
        normalized_candidates = [
            item for item in normalized_candidates if str(item.get("vuln_type")) in selected
        ]
    missing_checkers = sorted({str(item.get("vuln_type")) for item in normalized_candidates} - set(catalog))
    if missing_checkers:
        raise ValueError(f"candidate checker(s) not found: {', '.join(missing_checkers)}")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    audit_offset = max(0, int(kwargs.get("audit_index_offset") or 0))
    feedback = kwargs.get("feedback_entries") or []
    if not isinstance(feedback, list):
        raise TypeError("feedback_entries must be a list")
    filter_enabled = bool(kwargs.get("pattern_filter_enabled", False))
    filter_scope = str(kwargs.get("pattern_filter_scope") or "function")

    vulnerabilities: list[dict[str, Any]] = []
    skill_reports: dict[str, list[dict[str, Any]]] = {}
    processed_keys: list[dict[str, Any]] = []
    rejected_patterns: set[tuple[str, ...]] = set()
    result_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(concurrency)
    await _emit(output, "progress", f"Starting audit of {len(normalized_candidates)} candidate(s)", total=len(normalized_candidates))

    async def audit(local_index: int, candidate: dict[str, Any]) -> None:
        audit_index = audit_offset + local_index
        key = _pattern_key(candidate, filter_scope)
        if _cancelled(cancel_event):
            return
        async with semaphore:
            async with result_lock:
                skip = filter_enabled and key in rejected_patterns
            if skip:
                result = _fallback(candidate, audit_index, "success", "Filtered by a previously rejected same-pattern candidate", {})
                result["ai_verdict"] = "filtered_same_pattern"
                async with result_lock:
                    vulnerabilities.append(result)
                    processed_keys.append({name: candidate.get(name) for name in ("file", "line", "function", "vuln_type")})
                return
            checker = catalog[str(candidate.get("vuln_type"))]
            prompt = """请依据以下 checker 规则审计静态候选点。必须读取当前项目真实代码并验证完整数据流。
如果不成立要明确返回 not_confirmed；不要仅复述候选描述。

Checker 规则：
""" + checker["skill"] + "\n\n候选点：\n" + json.dumps(candidate, ensure_ascii=False, indent=2)
            if feedback:
                prompt += "\n\n历史人工反馈（只作判定参考）：\n" + json.dumps(feedback, ensure_ascii=False, indent=2)
            await _emit(output, "progress", f"Auditing candidate {audit_index + 1}", audit_index=audit_index)
            task_result = await run_opencode_task(
                task_name=f"candidate-audit-{kwargs['scan_id']}-{audit_index}",
                task_type="project_audit" if candidate.get("function") == PROJECT_LEVEL_FUNCTION else "audit",
                prompt=prompt,
                required_capability=capability,
                output_schema=_RESULT_SCHEMA,
                config_path=kwargs.get("task_agent_config"),
                output=None,
                cancel_event=cancel_event,
            )
            produced: list[dict[str, Any]] = []
            reports: list[dict[str, Any]] = []
            if task_result.status == "success" and isinstance(task_result.structured, dict):
                produced = [
                    _normalize_vulnerability(item, candidate, audit_index, task_result.output_source)
                    for item in task_result.structured.get("vulnerabilities") or []
                    if isinstance(item, dict)
                ]
                reports = [item for item in task_result.structured.get("markdown_reports") or [] if isinstance(item, dict)]
                if not produced and not reports and candidate.get("function") != PROJECT_LEVEL_FUNCTION:
                    produced = [_fallback(candidate, audit_index, "success", "No result returned", task_result.output_source)]
                    produced[0]["ai_verdict"] = "no_result"
            else:
                produced = [_fallback(candidate, audit_index, task_result.status, task_result.text, task_result.output_source)]
            async with result_lock:
                vulnerabilities.extend(produced)
                if reports:
                    skill_reports.setdefault(str(candidate.get("vuln_type")), []).extend(reports)
                if filter_enabled and produced and all(
                    not item["confirmed"] and item["ai_verdict"] == "not_confirmed" for item in produced
                ):
                    rejected_patterns.add(key)
                processed_keys.append({name: candidate.get(name) for name in ("file", "line", "function", "vuln_type")})
            await _emit(
                output, "item", f"Candidate {audit_index + 1} completed",
                audit_index=audit_index, vulnerability_count=len(produced), report_count=len(reports),
            )

    await asyncio.gather(*(audit(index, candidate) for index, candidate in enumerate(normalized_candidates)))
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {
        "status": status,
        "vulnerabilities": sorted(vulnerabilities, key=lambda item: int(item.get("audit_index") or 0)),
        "skill_reports": skill_reports,
        "processed_keys": processed_keys,
    }
