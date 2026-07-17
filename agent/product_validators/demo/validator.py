"""Minimal asynchronous product-validator example."""

from __future__ import annotations

import json

from agent.vulnerability_validation import ValidationResult
from backend.opencode.task_service import OpenCodeTaskSpec, get_opencode_task_service


RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_problem": {"type": "boolean"},
        "summary": {"type": "string", "minLength": 1},
        "evidence": {"type": "string"},
    },
    "required": ["is_problem", "summary", "evidence"],
    "additionalProperties": False,
}


async def validate(ctx) -> ValidationResult:
    await ctx.emit_stdout(
        "验证过程",
        f"入口={ctx.validation_entry_function} 漏洞函数={ctx.vulnerable_function} "
        f"类型={ctx.vulnerability_type}",
    )
    prompt = (
        "请根据当前项目代码和以下 Markdown 漏洞报告验证问题是否真实可触发。"
        "重点从验证入口沿函数调用链检查输入是否能够到达漏洞函数。\n\n"
        f"调用链：{' -> '.join(ctx.call_chain)}\n\n"
        f"{ctx.report_markdown}"
    )
    try:
        result = await get_opencode_task_service().run_task(
            OpenCodeTaskSpec(
                task_name=f"漏洞验证 {ctx.vulnerability_type}",
                prompt=prompt,
                directory=ctx.project_path,
                required_capability="high",
                timeout_seconds=ctx.timeout_seconds,
                priority=80,
                output_schema=RESULT_SCHEMA,
                on_output=ctx.opencode_output,
                cancel_event=ctx.cancel_event,
            )
        )
        result.raise_for_status()
    except Exception as exc:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"OpenCode validation failed: {exc}",
        )

    payload = result.structured if isinstance(result.structured, dict) else {}
    artifact_path = ctx.work_dir / "opencode-result.json"
    artifact_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    await ctx.publish_artifact(
        "opencode-result.json",
        path=artifact_path,
        title="验证产物",
        kind="result",
    )
    await ctx.emit_stdout("验证过程", str(payload.get("summary") or "验证完成"))
    return ValidationResult(
        validation_success=True,
        is_problem=bool(payload.get("is_problem")),
        requires_human_intervention=False,
        summary=str(payload.get("summary") or "验证完成"),
    )
