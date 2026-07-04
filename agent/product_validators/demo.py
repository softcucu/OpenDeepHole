"""Example product validator that drives nga-based validation skills."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import ValidationResult


STEP_1_SKILL = "validation-skill-1"
STEP_1_ARTIFACT = "01-validation-skill-1.md"
STEP_2_SKILL = "validation-skill-2"
STEP_2_ARTIFACT = "02-validation-skill-2.md"
STEP_3_SKILL = "validation-skill-3"
STEP_3_ARTIFACT = "03-validation-skill-3.md"
STEP_4_SKILL = "validation-skill-4"
STEP_4_ARTIFACT = "04-validation-skill-4.md"


def register(registry) -> None:
    registry.register("LTE", validate_demo)


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
    validation_dir = (
        project_dir
        / ".opendeephole"
        / "vulnerability_validation"
        / str(validation_info["scan_id"])
        / f"vuln-{validation_info['vuln_index']}"
    )
    validation_dir.mkdir(parents=True, exist_ok=True)
    report_path = validation_dir / "vulnerability.md"
    report_path.write_text(report_markdown, encoding="utf-8")

    ctx.emit_stdout(f"demo validator started for product={ctx.product}")
    ctx.emit_stdout(
        "validating "
        f"{vulnerability.get('vuln_type')} at {vulnerability.get('file')}:{vulnerability.get('line')}; "
        f"report={report_path}"
    )
    ctx.publish_artifact("vulnerability.md", path=report_path, kind="report")

    # STEP 1
    if ctx.cancelled():
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="cancelled",
            summary="demo validation cancelled",
        )
    step_1_artifact = validation_dir / STEP_1_ARTIFACT
    if step_1_artifact.exists():
        step_1_artifact.unlink()
    step_1_prompt = (
        f"使用 {STEP_1_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_1_artifact}。"
    )
    ctx.emit_stdout(f"STEP 1 running {STEP_1_SKILL}")
    step_1_return_code = ctx.run_command(
        ["nga", "run", "--dir", str(project_dir), step_1_prompt],
        cwd=project_dir,
    )
    if (
        step_1_return_code != 0
        or not step_1_artifact.is_file()
        or not step_1_artifact.read_text(encoding="utf-8").strip()
    ):
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 1 {STEP_1_SKILL} did not produce required artifact: {step_1_artifact}",
        )
    ctx.publish_artifact(STEP_1_ARTIFACT, path=step_1_artifact, kind="artifact")
    ctx.emit_stdout(f"STEP 1 completed: {step_1_artifact}")

    # STEP 2
    if ctx.cancelled():
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="cancelled",
            summary="demo validation cancelled",
        )
    step_2_artifact = validation_dir / STEP_2_ARTIFACT
    if step_2_artifact.exists():
        step_2_artifact.unlink()
    step_2_prompt = (
        f"使用 {STEP_2_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_2_artifact}。"
    )
    ctx.emit_stdout(f"STEP 2 running {STEP_2_SKILL}")
    step_2_return_code = ctx.run_command(
        ["nga", "run", "--dir", str(project_dir), step_2_prompt],
        cwd=project_dir,
    )
    if (
        step_2_return_code != 0
        or not step_2_artifact.is_file()
        or not step_2_artifact.read_text(encoding="utf-8").strip()
    ):
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 2 {STEP_2_SKILL} did not produce required artifact: {step_2_artifact}",
        )
    ctx.publish_artifact(STEP_2_ARTIFACT, path=step_2_artifact, kind="artifact")
    ctx.emit_stdout(f"STEP 2 completed: {step_2_artifact}")

    # STEP 3
    if ctx.cancelled():
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="cancelled",
            summary="demo validation cancelled",
        )
    step_3_artifact = validation_dir / STEP_3_ARTIFACT
    if step_3_artifact.exists():
        step_3_artifact.unlink()
    step_3_prompt = (
        f"使用 {STEP_3_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_3_artifact}。"
    )
    ctx.emit_stdout(f"STEP 3 running {STEP_3_SKILL}")
    step_3_return_code = ctx.run_command(
        ["nga", "run", "--dir", str(project_dir), step_3_prompt],
        cwd=project_dir,
    )
    if (
        step_3_return_code != 0
        or not step_3_artifact.is_file()
        or not step_3_artifact.read_text(encoding="utf-8").strip()
    ):
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 3 {STEP_3_SKILL} did not produce required artifact: {step_3_artifact}",
        )
    ctx.publish_artifact(STEP_3_ARTIFACT, path=step_3_artifact, kind="artifact")
    ctx.emit_stdout(f"STEP 3 completed: {step_3_artifact}")

    # STEP 4
    if ctx.cancelled():
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="cancelled",
            summary="demo validation cancelled",
        )
    step_4_artifact = validation_dir / STEP_4_ARTIFACT
    if step_4_artifact.exists():
        step_4_artifact.unlink()
    step_4_prompt = (
        f"使用 {STEP_4_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_4_artifact}。"
    )
    ctx.emit_stdout(f"STEP 4 running {STEP_4_SKILL}")
    step_4_return_code = ctx.run_command(
        ["nga", "run", "--dir", str(project_dir), step_4_prompt],
        cwd=project_dir,
    )
    if (
        step_4_return_code != 0
        or not step_4_artifact.is_file()
        or not step_4_artifact.read_text(encoding="utf-8").strip()
    ):
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 4 {STEP_4_SKILL} did not produce required artifact: {step_4_artifact}",
        )
    ctx.publish_artifact(STEP_4_ARTIFACT, path=step_4_artifact, kind="artifact")
    ctx.emit_stdout(f"STEP 4 completed: {step_4_artifact}")

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=True,
        summary="Demo validator completed all nga skill stages; human intervention is required.",
    )
