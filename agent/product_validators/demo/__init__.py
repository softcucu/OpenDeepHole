"""Example directory-based product validator that drives nga-based validation skills."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import ValidationResult


# 接入真实验证流程时，优先替换这 4 组 skill 名称、产物文件名和失败重试次数。
VALIDATION_TIMEOUT_SECONDS = 7200
VALIDATION_ENVIRONMENT = "仿真UBBPi板环境"
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
    registry.register(
        "LTE",
        validate_demo,
        validation_environment=VALIDATION_ENVIRONMENT,
        timeout_seconds=VALIDATION_TIMEOUT_SECONDS,
    )


def _emit(ctx, message: str) -> None:
    print(message, flush=True)
    ctx.emit_stdout("验证过程", message)


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

    start_message = (
        f"demo validator started for product={ctx.product}, "
        f"validation_environment={ctx.validation_environment}"
    )
    _emit(ctx, start_message)
    validation_message = (
        "validating "
        f"{vulnerability.get('vuln_type')} at {vulnerability.get('file')}:{vulnerability.get('line')}; "
        f"report={report_path}"
    )
    _emit(ctx, validation_message)
    ctx.publish_artifact("vulnerability.md", path=report_path, title="输入报告", kind="report")

    # STEP 1：修改第一阶段时，同步调整 STEP_1_SKILL、STEP_1_ARTIFACT、STEP_1_RETRIES 和这里的提示词。
    step_1_artifact = validation_dir / STEP_1_ARTIFACT
    step_1_prompt = (
        f"使用 {STEP_1_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_1_artifact}。如果找不到SKILL，就写入保存“Step1 找不到SKILL”"
    )
    step_1_success = False
    step_1_return_code = 0
    for step_1_attempt in range(1, STEP_1_RETRIES + 2):
        if ctx.cancelled():
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="cancelled",
                summary="demo validation cancelled",
            )
        if step_1_artifact.exists():
            step_1_artifact.unlink()

        step_1_message = (
            f"STEP 1 running {STEP_1_SKILL}, "
            f"attempt {step_1_attempt}/{STEP_1_RETRIES + 1}"
        )
        _emit(ctx, step_1_message)
        try:
            step_1_return_code = ctx.run_command(
                ["nga", "run", "--dir", str(project_dir), step_1_prompt],
                cwd=project_dir,
                timeout=ctx.timeout_seconds,
                output_title="命令输出",
            )
        except OSError as exc:
            step_1_return_code = 1
            step_1_message = f"STEP 1 failed to start nga: {exc}"
            _emit(ctx, step_1_message)
        if (
            step_1_return_code == 0
            and step_1_artifact.is_file()
            and step_1_artifact.read_text(encoding="utf-8").strip()
        ):
            step_1_success = True
            break
        if step_1_return_code == 124:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="timeout",
                summary=f"STEP 1 {STEP_1_SKILL} timed out after {ctx.timeout_seconds}s",
            )
        step_1_message = (
            f"STEP 1 attempt {step_1_attempt}/{STEP_1_RETRIES + 1} failed, "
            f"return_code={step_1_return_code}"
        )
        _emit(ctx, step_1_message)
    if not step_1_success:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 1 {STEP_1_SKILL} did not produce required artifact: {step_1_artifact}",
        )
    ctx.publish_artifact(STEP_1_ARTIFACT, path=step_1_artifact, title="阶段产物", kind="artifact")
    step_1_message = f"STEP 1 completed: {step_1_artifact}"
    _emit(ctx, step_1_message)

    # STEP 2：修改第二阶段时，同步调整 STEP_2_SKILL、STEP_2_ARTIFACT、STEP_2_RETRIES 和这里的提示词。
    step_2_artifact = validation_dir / STEP_2_ARTIFACT
    step_2_prompt = (
        f"使用 {STEP_2_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_2_artifact}。如果找不到SKILL，就写入保存“Step2 找不到SKILL”"
    )
    step_2_success = False
    step_2_return_code = 0
    for step_2_attempt in range(1, STEP_2_RETRIES + 2):
        if ctx.cancelled():
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="cancelled",
                summary="demo validation cancelled",
            )
        if step_2_artifact.exists():
            step_2_artifact.unlink()

        step_2_message = (
            f"STEP 2 running {STEP_2_SKILL}, "
            f"attempt {step_2_attempt}/{STEP_2_RETRIES + 1}"
        )
        _emit(ctx, step_2_message)
        try:
            step_2_return_code = ctx.run_command(
                ["nga", "run", "--dir", str(project_dir), step_2_prompt],
                cwd=project_dir,
                timeout=ctx.timeout_seconds,
                output_title="命令输出",
            )
        except OSError as exc:
            step_2_return_code = 1
            step_2_message = f"STEP 2 failed to start nga: {exc}"
            _emit(ctx, step_2_message)
        if (
            step_2_return_code == 0
            and step_2_artifact.is_file()
            and step_2_artifact.read_text(encoding="utf-8").strip()
        ):
            step_2_success = True
            break
        if step_2_return_code == 124:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="timeout",
                summary=f"STEP 2 {STEP_2_SKILL} timed out after {ctx.timeout_seconds}s",
            )
        step_2_message = (
            f"STEP 2 attempt {step_2_attempt}/{STEP_2_RETRIES + 1} failed, "
            f"return_code={step_2_return_code}"
        )
        _emit(ctx, step_2_message)
    if not step_2_success:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 2 {STEP_2_SKILL} did not produce required artifact: {step_2_artifact}",
        )
    ctx.publish_artifact(STEP_2_ARTIFACT, path=step_2_artifact, title="阶段产物", kind="artifact")
    step_2_message = f"STEP 2 completed: {step_2_artifact}"
    _emit(ctx, step_2_message)

    # STEP 3：修改第三阶段时，同步调整 STEP_3_SKILL、STEP_3_ARTIFACT、STEP_3_RETRIES 和这里的提示词。
    step_3_artifact = validation_dir / STEP_3_ARTIFACT
    step_3_prompt = (
        f"使用 {STEP_3_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_3_artifact}。如果找不到SKILL，就写入保存“Step3 找不到SKILL”"
    )
    step_3_success = False
    step_3_return_code = 0
    for step_3_attempt in range(1, STEP_3_RETRIES + 2):
        if ctx.cancelled():
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="cancelled",
                summary="demo validation cancelled",
            )
        if step_3_artifact.exists():
            step_3_artifact.unlink()

        step_3_message = (
            f"STEP 3 running {STEP_3_SKILL}, "
            f"attempt {step_3_attempt}/{STEP_3_RETRIES + 1}"
        )
        _emit(ctx, step_3_message)
        try:
            step_3_return_code = ctx.run_command(
                ["nga", "run", "--dir", str(project_dir), step_3_prompt],
                cwd=project_dir,
                timeout=ctx.timeout_seconds,
                output_title="命令输出",
            )
        except OSError as exc:
            step_3_return_code = 1
            step_3_message = f"STEP 3 failed to start nga: {exc}"
            _emit(ctx, step_3_message)
        if (
            step_3_return_code == 0
            and step_3_artifact.is_file()
            and step_3_artifact.read_text(encoding="utf-8").strip()
        ):
            step_3_success = True
            break
        if step_3_return_code == 124:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="timeout",
                summary=f"STEP 3 {STEP_3_SKILL} timed out after {ctx.timeout_seconds}s",
            )
        step_3_message = (
            f"STEP 3 attempt {step_3_attempt}/{STEP_3_RETRIES + 1} failed, "
            f"return_code={step_3_return_code}"
        )
        _emit(ctx, step_3_message)
    if not step_3_success:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 3 {STEP_3_SKILL} did not produce required artifact: {step_3_artifact}",
        )
    ctx.publish_artifact(STEP_3_ARTIFACT, path=step_3_artifact, title="阶段产物", kind="artifact")
    step_3_message = f"STEP 3 completed: {step_3_artifact}"
    _emit(ctx, step_3_message)

    # STEP 4：修改第四阶段时，同步调整 STEP_4_SKILL、STEP_4_ARTIFACT、STEP_4_RETRIES 和这里的提示词。
    step_4_artifact = validation_dir / STEP_4_ARTIFACT
    step_4_prompt = (
        f"使用 {STEP_4_SKILL} 验证 {report_path} 中的问题，"
        f"中间产物保存在 {step_4_artifact}。如果找不到SKILL，就写入保存“Step4 找不到SKILL”"
    )
    step_4_success = False
    step_4_return_code = 0
    for step_4_attempt in range(1, STEP_4_RETRIES + 2):
        if ctx.cancelled():
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="cancelled",
                summary="demo validation cancelled",
            )
        if step_4_artifact.exists():
            step_4_artifact.unlink()

        step_4_message = (
            f"STEP 4 running {STEP_4_SKILL}, "
            f"attempt {step_4_attempt}/{STEP_4_RETRIES + 1}"
        )
        _emit(ctx, step_4_message)
        try:
            step_4_return_code = ctx.run_command(
                ["nga", "run", "--dir", str(project_dir), step_4_prompt],
                cwd=project_dir,
                timeout=ctx.timeout_seconds,
                output_title="命令输出",
            )
        except OSError as exc:
            step_4_return_code = 1
            step_4_message = f"STEP 4 failed to start nga: {exc}"
            _emit(ctx, step_4_message)
        if (
            step_4_return_code == 0
            and step_4_artifact.is_file()
            and step_4_artifact.read_text(encoding="utf-8").strip()
        ):
            step_4_success = True
            break
        if step_4_return_code == 124:
            return ValidationResult(
                validation_success=False,
                is_problem=True,
                requires_human_intervention=True,
                status="timeout",
                summary=f"STEP 4 {STEP_4_SKILL} timed out after {ctx.timeout_seconds}s",
            )
        step_4_message = (
            f"STEP 4 attempt {step_4_attempt}/{STEP_4_RETRIES + 1} failed, "
            f"return_code={step_4_return_code}"
        )
        _emit(ctx, step_4_message)
    if not step_4_success:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"STEP 4 {STEP_4_SKILL} did not produce required artifact: {step_4_artifact}",
        )
    ctx.publish_artifact(STEP_4_ARTIFACT, path=step_4_artifact, title="阶段产物", kind="artifact")
    step_4_message = f"STEP 4 completed: {step_4_artifact}"
    _emit(ctx, step_4_message)

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=True,
        summary="Demo validator completed all nga skill stages; human intervention is required.",
    )
