"""Minimal asynchronous product-validator example."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agent.vulnerability_validation import ValidationResult
from agent.task_agent import run_opencode_task


RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_problem": {"type": "boolean"},
        "summary": {"type": "string", "minLength": 1},
        "evidence": {
            "type": "array",
            "minItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": ["string", "null"]},
                },
                "required": ["id", "name"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["is_problem", "summary", "evidence"],
    "additionalProperties": False,
}


async def validate(**kwargs) -> ValidationResult:
    emit_stdout = kwargs["emit_stdout"]
    validation_entry_function = kwargs["validation_entry_function"]
    vulnerable_function = kwargs["vulnerable_function"]
    vulnerability_type = kwargs["vulnerability_type"]
    call_chain = kwargs["call_chain"]
    report_markdown = kwargs["report_markdown"]
    required_capability = kwargs["required_capability"]
    work_dir = kwargs["work_dir"]
    target_ip = kwargs.get("target_ip", "")

    await emit_stdout(
        "验证过程",
        f"入口={validation_entry_function} 漏洞函数={vulnerable_function} "
        f"类型={vulnerability_type} 目标={target_ip or '自动发现'}",
    )
    prompt = (
        "请根据当前项目代码和以下 Markdown 漏洞报告验证问题是否真实可触发。"
        "重点从验证入口沿函数调用链检查输入是否能够到达漏洞函数。\n\n"
        f"调用链：{' -> '.join(call_chain)}\n\n"
        f"{report_markdown}"
    )
    prompt = (
        "随机生成一段内容"
    )
    try:
        result = await run_opencode_task(
            task_name=f"漏洞验证 {vulnerability_type}",
            task_type="vulnerability_validation",
            prompt=prompt,
            required_capability=required_capability,
            output_schema=RESULT_SCHEMA,
        )
        if result.status != "success":
            raise RuntimeError(result.text)
    except Exception as exc:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"OpenCode validation failed: {exc}",
        )

    payload = result.structured if isinstance(result.structured, dict) else {}
    artifact_path = work_dir / "opencode-result.json"
    artifact_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    await emit_stdout("验证过程", str(payload.get("summary") or "验证完成"))
    print(result.structured)
    return ValidationResult(
        validation_success=True,
        is_problem=bool(payload.get("is_problem")),
        requires_human_intervention=False,
        summary=str(payload.get("summary") or "验证完成"),
    )


async def main() -> None:
    """Run this example with the standalone Task Agent component configuration."""
    work_dir = (Path.cwd() / ".opendeephole" / "validator-demo").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    async def emit_stdout(title, content=None) -> None:
        if content is None:
            print(str(title), flush=True)
        else:
            print(f"[{title}] {content}", flush=True)

    result = await validate(
        emit_stdout=emit_stdout,
        validation_entry_function="handle_packet",
        vulnerable_function="parse_payload",
        vulnerability_type="oob",
        call_chain=("handle_packet", "parse_message", "parse_payload"),
        report_markdown="# 漏洞报告\n\n验证该越界路径。",
        required_capability="high",
        work_dir=work_dir,
        target_ip="",
    )
    print(f"[validator-demo] status={result.status}", flush=True)
    print(f"[validator-demo] conclusion={result.summary}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
