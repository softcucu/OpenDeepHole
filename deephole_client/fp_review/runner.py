"""Review a batch of reported vulnerabilities for false positives."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task

PROCESS_NAME = "fp_review"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "review_id", "vulnerabilities",
    "feedback_entries", "history", "processed_offset", "concurrency",
    "required_capability", "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir", "scan_id", "review_id", "vulnerabilities"}
_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "uncertain"]},
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "revised_severity": {"type": "string"},
    },
    "required": ["verdict", "reason", "evidence", "revised_severity"],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


async def run_fp_review(**kwargs: Any) -> dict[str, Any]:
    """Run independent second-opinion reviews for a vulnerability batch."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_fp_review() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_fp_review() missing required key(s): {', '.join(missing)}")
    project = Path(kwargs["project_path"]).expanduser().resolve()
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    work_dir.mkdir(parents=True, exist_ok=True)
    vulnerabilities = kwargs["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise TypeError("vulnerabilities must be a list")
    normalized: list[dict[str, Any]] = []
    for index, vulnerability in enumerate(vulnerabilities):
        if hasattr(vulnerability, "model_dump"):
            vulnerability = vulnerability.model_dump()
        if not isinstance(vulnerability, dict):
            raise TypeError(f"vulnerabilities[{index}] must be a dict")
        normalized.append(dict(vulnerability))
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    offset = max(0, int(kwargs.get("processed_offset") or 0))
    context = {
        "feedback_entries": kwargs.get("feedback_entries") or [],
        "history": kwargs.get("history") or [],
    }
    if not isinstance(context["feedback_entries"], list) or not isinstance(context["history"], list):
        raise TypeError("feedback_entries and history must be lists")

    semaphore = asyncio.Semaphore(concurrency)
    results: list[tuple[int, dict[str, Any]]] = []
    result_lock = asyncio.Lock()
    await _emit(output, "progress", f"Starting FP review of {len(normalized)} item(s)", total=len(normalized))

    async def review(local_index: int, vulnerability: dict[str, Any]) -> None:
        if _cancelled(cancel_event):
            return
        item_index = offset + local_index
        vuln_index = vulnerability.get("index", item_index)
        async with semaphore:
            prompt = """你是独立漏洞复核员。请读取当前项目真实代码，对下面的漏洞报告做去误报复核。
不要沿用原结论；分别检查入口可达性、约束条件、数据流和真实危险操作。
verdict 必须是 true_positive、false_positive 或 uncertain。

待复核漏洞：
""" + json.dumps(vulnerability, ensure_ascii=False, indent=2)
            if context["feedback_entries"] or context["history"]:
                prompt += "\n\n历史上下文：\n" + json.dumps(context, ensure_ascii=False, indent=2)
            await _emit(output, "progress", f"Reviewing vulnerability {vuln_index}", vuln_index=vuln_index)
            task_result = await run_opencode_task(
                task_name=f"fp-review-{kwargs['review_id']}-{vuln_index}",
                task_type="fp_review",
                prompt=prompt,
                required_capability=capability,
                output_schema=_RESULT_SCHEMA,
                config_path=kwargs.get("task_agent_config"),
                output=None,
                cancel_event=cancel_event,
            )
            if task_result.status == "success" and isinstance(task_result.structured, dict):
                item = {
                    "vuln_index": vuln_index,
                    "status": "success",
                    "verdict": str(task_result.structured.get("verdict") or "uncertain"),
                    "reason": str(task_result.structured.get("reason") or ""),
                    "evidence": list(task_result.structured.get("evidence") or []),
                    "revised_severity": str(task_result.structured.get("revised_severity") or ""),
                    "output_source": task_result.output_source,
                }
            else:
                item = {
                    "vuln_index": vuln_index,
                    "status": task_result.status,
                    "verdict": "uncertain",
                    "reason": task_result.text,
                    "evidence": [],
                    "revised_severity": "",
                    "output_source": task_result.output_source,
                }
            async with result_lock:
                results.append((item_index, item))
            await _emit(output, "item", f"Reviewed vulnerability {vuln_index}", **item)

    await asyncio.gather(*(review(index, item) for index, item in enumerate(normalized)))
    ordered = [item for _, item in sorted(results, key=lambda pair: pair[0])]
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {
        "status": status,
        "review_id": str(kwargs["review_id"]),
        "results": ordered,
        "processed": len(ordered),
    }
