"""Example product validators.

Copy this file or add new files in this directory. Each file can register one
or more products by exposing register(registry).
"""

from __future__ import annotations

import time

from agent.vulnerability_validation import ValidationResult


def register(registry) -> None:
    registry.register("LTE", validate_demo)


def validate_demo(ctx) -> ValidationResult:
    ctx.emit_stdout(f"demo validator started for product={ctx.product}")
    ctx.publish_artifact(
        "demo_validation.py",
        "print('replace this with product-specific validation code')\n",
        kind="code",
    )
    total_stages = 13
    seconds_per_stage = 10
    for stage in range(1, total_stages + 1):
        for _second in range(seconds_per_stage):
            if ctx.cancelled():
                return ValidationResult(False, False, "demo validation cancelled", status="cancelled")
            time.sleep(1)
        elapsed = stage * seconds_per_stage
        ctx.emit_stdout(f"demo stage {stage}/{total_stages} completed, elapsed={elapsed}s")
    return ValidationResult(
        validation_success=True,
        is_problem=True,
        summary="Demo validator completed. Replace this implementation with a real product validator.",
    )
