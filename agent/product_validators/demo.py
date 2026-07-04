"""Example product validator that drives nga-based validation skills."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import ValidationResult


MAX_STAGE_RETRIES = 2
VALIDATION_STAGES = [
    ("validation-skill-1", "01-validation-skill-1.md"),
    ("validation-skill-2", "02-validation-skill-2.md"),
    ("validation-skill-3", "03-validation-skill-3.md"),
    ("validation-skill-4", "04-validation-skill-4.md"),
]


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

    for index, (skill_name, artifact_name) in enumerate(VALIDATION_STAGES, start=1):
        artifact_path = validation_dir / artifact_name
        prompt = (
            f"使用 {skill_name} 验证 {report_path} 中的问题，"
            f"中间产物保存在 {artifact_path}。"
        )
        for attempt in range(1, MAX_STAGE_RETRIES + 2):
            if ctx.cancelled():
                return ValidationResult(
                    validation_success=False,
                    is_problem=True,
                    requires_human_intervention=True,
                    status="cancelled",
                    summary="demo validation cancelled",
                )
            if artifact_path.exists():
                artifact_path.unlink()

            ctx.emit_stdout(
                f"stage {index}/{len(VALIDATION_STAGES)} running {skill_name}, "
                f"attempt {attempt}/{MAX_STAGE_RETRIES + 1}"
            )
            return_code = ctx.run_command(
                ["nga", "run", "--dir", str(project_dir), prompt],
                cwd=project_dir,
            )
            if return_code == 0 and artifact_path.is_file() and artifact_path.read_text(encoding="utf-8").strip():
                ctx.publish_artifact(artifact_name, path=artifact_path, kind="artifact")
                ctx.emit_stdout(f"stage {index}/{len(VALIDATION_STAGES)} completed: {artifact_path}")
                break

            ctx.emit_stdout(
                f"stage {index}/{len(VALIDATION_STAGES)} failed to produce artifact "
                f"{artifact_path}, return_code={return_code}"
            )
        else:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="failed",
                summary=f"{skill_name} did not produce required artifact: {artifact_path}",
            )

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=True,
        summary="Demo validator completed all nga skill stages; human intervention is required.",
    )
