"""Example product validator that drives nga-based validation skills."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import ValidationResult


# 接入真实验证流程时，优先替换这 4 组 skill 名称、产物文件名和失败重试次数。
VALIDATION_TIMEOUT_SECONDS = 7200
STEP_1_SKILL = "validation-skill-1"
STEP_1_ARTIFACT = "01-validation-skill-1.md"
STEP_1_RETRIES = 2
STEP_2_SKILL = "validation-skill-2"
STEP_2_ARTIFACT = "02-validation-skill-2.md"
STEP_2_RETRIES = 2
STEP_3_SKILL = "validation-skill-3"
STEP_3_ARTIFACT = "03-validation-skill-3.md"
STEP_3_RETRIES = 2
STEP_4_SKILL = "validation-skill-4"
STEP_4_ARTIFACT = "04-validation-skill-4.md"
STEP_4_RETRIES = 2


def register(registry) -> None:
    registry.register("LTE", validate_demo, timeout_seconds=VALIDATION_TIMEOUT_SECONDS)


def _emit(ctx, text: object) -> None:
    print(str(text), flush=True)
    ctx.emit_stdout(text)


def _cancelled_result() -> ValidationResult:
    return ValidationResult(
        validation_success=False,
        is_problem=True,
        requires_human_intervention=True,
        status="cancelled",
        summary="demo validation cancelled",
    )


def _run_stage(
    ctx,
    *,
    project_dir: Path,
    validation_dir: Path,
    report_path: Path,
    step_number: int,
    skill: str,
    artifact_name: str,
    retries: int,
) -> ValidationResult | None:
    artifact_path = validation_dir / artifact_name
    prompt = (
        f"使用 {skill} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {artifact_path}。如果找不到SKILL，就写入保存“Step{step_number} 找不到SKILL”"
    )
    return_code = 0
    for attempt in range(1, retries + 2):
        if ctx.cancelled():
            return _cancelled_result()
        if artifact_path.exists():
            artifact_path.unlink()

        _emit(ctx, f"STEP {step_number} running {skill}, attempt {attempt}/{retries + 1}")
        command = ["nga", "run", "--dir", str(project_dir), prompt]
        try:
            return_code = ctx.run_command(command, cwd=project_dir, timeout=ctx.timeout_seconds)
        except OSError as exc:
            return_code = 1
            _emit(ctx, f"STEP {step_number} failed to start nga: {exc}")
        if (
            return_code == 0
            and artifact_path.is_file()
            and artifact_path.read_text(encoding="utf-8").strip()
        ):
            ctx.publish_artifact(artifact_name, path=artifact_path, kind="artifact")
            _emit(ctx, f"STEP {step_number} completed: {artifact_path}")
            return None
        if return_code == 124:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="timeout",
                summary=f"STEP {step_number} {skill} timed out after {ctx.timeout_seconds}s",
            )
        _emit(
            ctx,
            f"STEP {step_number} attempt {attempt}/{retries + 1} failed, return_code={return_code}",
        )
    return ValidationResult(
        validation_success=False,
        is_problem=True,
        requires_human_intervention=True,
        status="failed",
        summary=f"STEP {step_number} {skill} did not produce required artifact: {artifact_path}",
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
    report_markdown = ctx.get_report_markdown()
    validation_info = ctx.get_validation_info()
    vulnerability = validation_info["vulnerability"]
    # 所有验证输入和中间产物都放在 project_dir 下，方便 nga 在同一项目根目录内发现 skill 并读写文件。
    validation_dir = (
        project_dir
        / ".opendeephole"
        / "vulnerability_validation"
        / str(validation_info["scan_id"])
        / f"vuln-{validation_info['vuln_index']}"
    )
    validation_dir.mkdir(parents=True, exist_ok=True)
    # 这个 Markdown 报告会传给后续 4 个 nga skill。
    report_path = validation_dir / "vulnerability.md"
    report_path.write_text(report_markdown, encoding="utf-8")

    _emit(ctx, f"demo validator started for product={ctx.product}")
    _emit(
        ctx,
        "validating "
        f"{vulnerability.get('vuln_type')} at {vulnerability.get('file')}:{vulnerability.get('line')}; "
        f"report={report_path}"
    )
    ctx.publish_artifact("vulnerability.md", path=report_path, kind="report")

    stages = (
        (1, STEP_1_SKILL, STEP_1_ARTIFACT, STEP_1_RETRIES),
        (2, STEP_2_SKILL, STEP_2_ARTIFACT, STEP_2_RETRIES),
        (3, STEP_3_SKILL, STEP_3_ARTIFACT, STEP_3_RETRIES),
        (4, STEP_4_SKILL, STEP_4_ARTIFACT, STEP_4_RETRIES),
    )
    for step_number, skill, artifact_name, retries in stages:
        stage_result = _run_stage(
            ctx,
            project_dir=project_dir,
            validation_dir=validation_dir,
            report_path=report_path,
            step_number=step_number,
            skill=skill,
            artifact_name=artifact_name,
            retries=retries,
        )
        if stage_result is not None:
            return stage_result

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=True,
        summary="Demo validator completed all nga skill stages; human intervention is required.",
    )
