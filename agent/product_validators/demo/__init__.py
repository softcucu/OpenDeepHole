"""Example product validator using the shared OpenCode task/session service."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import ValidationResult


VALIDATION_TIMEOUT_SECONDS = 7200
VALIDATION_ENVIRONMENT = "仿真UBBPi板环境"
STAGES = (
    ("validation-skill-1", "01-validation-skill-1.md", 2),
    ("validation-skill-2", "02-validation-skill-2.md", 2),
    ("validation-skill-3", "03-validation-skill-3.md", 2),
    ("validation-skill-4", "04-validation-skill-4.md", 2),
)
ARTIFACT_SCHEMA = {
    "type": "object",
    "properties": {
        "content": {
            "type": "string",
            "description": "Complete Markdown content for this validation stage",
        },
    },
    "required": ["content"],
    "additionalProperties": False,
}


def register(registry) -> None:
    registry.register(
        "LTE",
        validate_demo,
        validation_environment=VALIDATION_ENVIRONMENT,
        timeout_seconds=VALIDATION_TIMEOUT_SECONDS,
    )


def _emit(ctx, message: str) -> None:
    print(message, flush=True)
    ctx.emit_stdout("验证过程", message)


def _cancelled_result() -> ValidationResult:
    return ValidationResult(
        validation_success=False,
        is_problem=True,
        requires_human_intervention=True,
        status="cancelled",
        summary="demo validation cancelled",
    )


def validate_demo(ctx) -> ValidationResult:
    if ctx.project_path is None:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary="demo validator requires project_dir/project_path",
        )

    project_dir = Path(ctx.project_path)
    validation_info = ctx.get_validation_info()
    vulnerability = validation_info["vulnerability"]
    validation_dir = (
        project_dir
        / ".opendeephole"
        / "vulnerability_validation"
        / str(validation_info["scan_id"])
        / f"vuln-{validation_info['vuln_index']}"
    )
    validation_dir.mkdir(parents=True, exist_ok=True)
    report_path = validation_dir / "vulnerability.md"
    report_path.write_text(ctx.get_report_markdown(), encoding="utf-8")
    ctx.publish_artifact("vulnerability.md", path=report_path, title="输入报告", kind="report")
    _emit(
        ctx,
        "validating "
        f"{vulnerability.get('vuln_type')} at "
        f"{vulnerability.get('file')}:{vulnerability.get('line')}; report={report_path}",
    )

    # All stages continue the same durable OpenCode session. The task service
    # parses the plain JSON reply locally; the validator owns the filesystem write.
    session_id: str | None = None
    for stage_index, (skill_name, artifact_name, retries) in enumerate(STAGES, start=1):
        artifact_path = validation_dir / artifact_name
        succeeded = False
        last_error = ""
        for attempt in range(1, retries + 2):
            if ctx.cancelled():
                return _cancelled_result()
            _emit(
                ctx,
                f"STEP {stage_index} running {skill_name}, attempt {attempt}/{retries + 1}",
            )
            prompt = (
                f"这是漏洞验证的第 {stage_index}/4 阶段。读取 {report_path}，"
                f"按照 {skill_name} 的方法完成验证。最终只输出符合指定 JSON Schema、包含完整 Markdown 的 JSON "
                f"阶段结论，不要直接写文件。前序阶段信息保留在当前 session 中。"
            )
            try:
                task_result = ctx.run_opencode_task(
                    task_name=f"validation:{skill_name}",
                    prompt=prompt,
                    required_capability="high",
                    directory=project_dir,
                    skills=[skill_name],
                    timeout_seconds=ctx.timeout_seconds,
                    priority=80,
                    output_schema=ARTIFACT_SCHEMA,
                    session_id=session_id,
                )
                session_id = str(task_result.get("session_id") or session_id or "") or None
                structured = task_result.get("structured")
                content = structured.get("content") if isinstance(structured, dict) else ""
                if str(content or "").strip():
                    artifact_path.write_text(str(content), encoding="utf-8")
                    succeeded = True
                    break
                last_error = "OpenCode returned empty JSON content"
            except Exception as exc:
                last_error = str(exc)
            _emit(ctx, f"STEP {stage_index} attempt failed: {last_error}")

        if not succeeded:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="failed",
                summary=(
                    f"STEP {stage_index} {skill_name} did not produce required artifact: "
                    f"{artifact_path}; error={last_error}"
                ),
            )
        ctx.publish_artifact(
            artifact_name,
            path=artifact_path,
            title="阶段产物",
            kind="artifact",
        )
        _emit(ctx, f"STEP {stage_index} completed: {artifact_path}; session={session_id}")

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=True,
        summary=(
            "Demo validator completed all OpenCode session stages; "
            "human intervention is required."
        ),
    )
