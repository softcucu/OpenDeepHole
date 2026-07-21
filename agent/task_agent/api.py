"""The single public OpenCode task interface used by OpenDeepHole components."""

from __future__ import annotations

from dataclasses import dataclass
from os import PathLike
from typing import Any, Callable, Literal


_SUPPORTED_TASK_TYPES = frozenset({
    "audit",
    "project_audit",
    "sensitive_clear",
    "report_audit",
    "threat_analysis",
    "threat_audit",
    "fp_review",
    "vulnerability_validation",
    "git_history",
    "variant_hunt",
    "memory_api_discovery",
    "skill_create",
})


def _standalone_output_prefix(task_type: str) -> str:
    stage = "validation" if task_type == "vulnerability_validation" else task_type
    return f"[{stage}/opencode]"


def _standalone_console_output(task_type: str) -> Callable[[str], None]:
    prefix = _standalone_output_prefix(task_type)

    def emit(line: str) -> None:
        text = str(line or "")
        if text:
            print(f"{prefix} {text}", flush=True)

    return emit


@dataclass(frozen=True)
class OpenCodeResult:
    session_id: str
    status: Literal["success", "failure", "timeout"]
    text: str
    structured: Any
    model: str


async def run_opencode_task(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    session_id: str | None = None,
    config_path: str | PathLike[str] | None = None,
) -> OpenCodeResult:
    """Run one OpenCode task using host-bound or standalone file configuration."""
    normalized_name = str(task_name or "").strip()
    normalized_prompt = str(prompt or "")
    if not normalized_name:
        raise ValueError("OpenCode task_name is required")
    if not normalized_prompt.strip():
        raise ValueError("OpenCode prompt is required")
    normalized_task_type = task_type.strip() if isinstance(task_type, str) else ""
    if normalized_task_type not in _SUPPORTED_TASK_TYPES:
        raise ValueError(f"Unsupported OpenCode task_type: {task_type!r}")
    capability = str(required_capability or "").strip().lower()
    if capability not in {"low", "high"}:
        raise ValueError("OpenCode required_capability must be 'low' or 'high'")
    if output_schema is not None and not isinstance(output_schema, dict):
        raise TypeError("OpenCode output_schema must be a dict or None")
    retry_count = int(invalid_json_retry_count)
    if retry_count < 0:
        raise ValueError("OpenCode invalid_json_retry_count cannot be negative")

    from .standalone import ensure_opencode_configuration
    from .task_service import _run_component_task, bind_opencode_execution_context

    standalone = ensure_opencode_configuration(config_path)

    async def run() -> OpenCodeResult:
        return await _run_component_task(
            task_name=normalized_name,
            task_type=normalized_task_type,
            prompt=normalized_prompt,
            required_capability=capability,
            output_schema=output_schema,
            invalid_json_retry_count=retry_count,
            session_id=str(session_id or "").strip() or None,
        )

    if standalone is None:
        return await run()
    with bind_opencode_execution_context(
        project_dir=standalone.project_dir,
        work_dir=standalone.work_dir,
        task_metadata={"standalone_console": True},
        on_output=_standalone_console_output(normalized_task_type),
    ):
        return await run()
