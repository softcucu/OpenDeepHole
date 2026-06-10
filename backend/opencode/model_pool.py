"""Model-pool scheduling for OpenCode-compatible CLI invocations."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any


CAPABILITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class ModelOption:
    id: str
    model: str
    capability: str
    weight: float
    max_concurrency: int
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None


@dataclass(frozen=True)
class ModelLease:
    option: ModelOption
    running: int
    global_running: int


_condition = asyncio.Condition()
_running_by_model: dict[str, int] = {}
_global_running = 0
_last_used: dict[str, float] = {}


def _cfg_value(config_obj: Any, key: str, default=None):
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


def normalize_capability(value: object, default: str = "high") -> str:
    normalized = str(value or default).strip().lower()
    if normalized == "any":
        return "low"
    return normalized if normalized in CAPABILITY_ORDER else default


def normalize_requirement(value: object) -> str:
    normalized = str(value or "any").strip().lower()
    if normalized in {"", "any"}:
        return "low"
    return normalized if normalized in CAPABILITY_ORDER else "low"


def capability_satisfies(model_capability: str, required: str) -> bool:
    return CAPABILITY_ORDER[model_capability] >= CAPABILITY_ORDER[required]


def _safe_int(value: object, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def _safe_float(value: object, default: float, minimum: float = 0.01) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def configured_global_concurrency(config: Any) -> int:
    return _safe_int(_cfg_value(config, "opencode_concurrency", 1), 1, 1)


def model_options(cli_config: Any, *, global_concurrency: int) -> list[ModelOption]:
    raw_models = _cfg_value(cli_config, "models", None) or []
    options: list[ModelOption] = []
    for index, raw in enumerate(raw_models):
        if raw is None:
            continue
        enabled = bool(_cfg_value(raw, "enabled", True))
        if not enabled:
            continue
        model = str(_cfg_value(raw, "model", "") or "").strip()
        model_id = str(_cfg_value(raw, "id", "") or model or f"model-{index + 1}").strip()
        if not model_id:
            continue
        options.append(
            ModelOption(
                id=model_id,
                model=model,
                capability=normalize_capability(_cfg_value(raw, "capability", "high")),
                weight=_safe_float(_cfg_value(raw, "weight", 1), 1.0),
                max_concurrency=_safe_int(
                    _cfg_value(raw, "max_concurrency", global_concurrency),
                    global_concurrency,
                ),
                tool=str(_cfg_value(raw, "tool", "") or ""),
                executable=str(_cfg_value(raw, "executable", "") or ""),
                timeout=(
                    _safe_int(_cfg_value(raw, "timeout", None), 0, 1)
                    if _cfg_value(raw, "timeout", None) not in (None, "")
                    else None
                ),
                max_retries=(
                    _safe_int(_cfg_value(raw, "max_retries", None), 0, 0)
                    if _cfg_value(raw, "max_retries", None) not in (None, "")
                    else None
                ),
            )
        )
    if options:
        return options

    return [
        ModelOption(
            id="default",
            model=str(_cfg_value(cli_config, "model", "") or ""),
            capability="high",
            weight=1.0,
            max_concurrency=global_concurrency,
            tool=str(_cfg_value(cli_config, "tool", "") or ""),
            executable=str(_cfg_value(cli_config, "executable", "") or ""),
        )
    ]


def _eligible_options(
    options: list[ModelOption],
    *,
    required_capability: str,
    prefer_high: bool,
) -> list[ModelOption]:
    eligible = [
        option for option in options
        if capability_satisfies(option.capability, required_capability)
    ]
    if prefer_high:
        high = [option for option in eligible if option.capability == "high"]
        if high:
            return high
    return eligible


def _choose_available(options: list[ModelOption]) -> ModelOption | None:
    available = [
        option for option in options
        if _running_by_model.get(option.id, 0) < option.max_concurrency
    ]
    if not available:
        return None
    return min(
        available,
        key=lambda option: (
            _running_by_model.get(option.id, 0) / option.weight,
            _running_by_model.get(option.id, 0),
            -option.weight,
            _last_used.get(option.id, 0.0),
            option.id,
        ),
    )


async def acquire_model_lease(
    cli_config: Any,
    *,
    global_concurrency: int,
    required_capability: str = "any",
    prefer_high: bool = False,
    cancel_event=None,
) -> ModelLease | None:
    required = normalize_requirement(required_capability)
    options = model_options(cli_config, global_concurrency=global_concurrency)
    eligible = _eligible_options(
        options,
        required_capability=required,
        prefer_high=prefer_high,
    )
    if not eligible:
        # Configuration is too restrictive. Fall back to all enabled models so
        # the audit can still run, but scheduling will make the mismatch visible.
        eligible = options

    global _global_running
    while True:
        if cancel_event is not None and cancel_event.is_set():
            return None
        async with _condition:
            option = None
            if _global_running < global_concurrency:
                option = _choose_available(eligible)
            if option is not None:
                _global_running += 1
                _running_by_model[option.id] = _running_by_model.get(option.id, 0) + 1
                _last_used[option.id] = time.monotonic()
                return ModelLease(
                    option=option,
                    running=_running_by_model[option.id],
                    global_running=_global_running,
                )
            try:
                await asyncio.wait_for(_condition.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass


async def release_model_lease(lease: ModelLease | None) -> None:
    if lease is None:
        return
    global _global_running
    async with _condition:
        _global_running = max(0, _global_running - 1)
        current = _running_by_model.get(lease.option.id, 0)
        if current <= 1:
            _running_by_model.pop(lease.option.id, None)
        else:
            _running_by_model[lease.option.id] = current - 1
        _condition.notify_all()


def model_pool_snapshot() -> dict[str, Any]:
    return {
        "global_running": _global_running,
        "models": dict(_running_by_model),
    }
