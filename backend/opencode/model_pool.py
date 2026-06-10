"""Model-pool scheduling for OpenCode-compatible CLI invocations."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
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
    stats_scope_id: str = ""
    started_at: float = 0.0


@dataclass
class ModelRuntimeStats:
    id: str
    model: str
    capability: str
    weight: float
    max_concurrency: int
    queued: int = 0
    running: int = 0
    total: int = 0
    success: int = 0
    failure: int = 0
    timeout: int = 0
    cancelled: int = 0
    total_duration_seconds: float = 0.0
    last_status: str = ""
    last_started_at: str = ""
    last_finished_at: str = ""


_condition = asyncio.Condition()
_running_by_model: dict[str, int] = {}
_global_running = 0
_last_used: dict[str, float] = {}
_stats_by_scope: dict[str, dict[str, ModelRuntimeStats]] = {}
_scope_updated_at: dict[str, str] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _choose_queue_target(options: list[ModelOption], stats: dict[str, ModelRuntimeStats]) -> ModelOption:
    return min(
        options,
        key=lambda option: (
            (
                (stats.get(option.id).queued if option.id in stats else 0)
                + _running_by_model.get(option.id, 0)
            ) / option.weight,
            stats.get(option.id).queued if option.id in stats else 0,
            _running_by_model.get(option.id, 0),
            -option.weight,
            option.id,
        ),
    )


def _ensure_scope_models_locked(scope_id: str, options: list[ModelOption]) -> dict[str, ModelRuntimeStats]:
    stats = _stats_by_scope.setdefault(scope_id, {})
    for option in options:
        current = stats.get(option.id)
        if current is None:
            stats[option.id] = ModelRuntimeStats(
                id=option.id,
                model=option.model,
                capability=option.capability,
                weight=option.weight,
                max_concurrency=option.max_concurrency,
            )
        else:
            current.model = option.model
            current.capability = option.capability
            current.weight = option.weight
            current.max_concurrency = option.max_concurrency
    _scope_updated_at[scope_id] = _now_iso()
    return stats


def _decrement_queued_locked(scope_id: str, model_id: str) -> None:
    stats = _stats_by_scope.get(scope_id)
    if not stats:
        return
    item = stats.get(model_id)
    if item is not None:
        item.queued = max(0, item.queued - 1)
        _scope_updated_at[scope_id] = _now_iso()


async def acquire_model_lease(
    cli_config: Any,
    *,
    global_concurrency: int,
    required_capability: str = "any",
    prefer_high: bool = False,
    cancel_event=None,
    stats_scope_id: str = "",
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
    queued_model_id = ""
    if stats_scope_id:
        async with _condition:
            stats = _ensure_scope_models_locked(stats_scope_id, options)
            queued_option = _choose_queue_target(eligible, stats)
            queued_model_id = queued_option.id
            stats[queued_model_id].queued += 1
            stats[queued_model_id].last_status = "queued"
            _scope_updated_at[stats_scope_id] = _now_iso()

    while True:
        if cancel_event is not None and cancel_event.is_set():
            if stats_scope_id and queued_model_id:
                async with _condition:
                    _decrement_queued_locked(stats_scope_id, queued_model_id)
            return None
        async with _condition:
            option = None
            if _global_running < global_concurrency:
                assignable = eligible
                if queued_model_id:
                    assigned = [candidate for candidate in eligible if candidate.id == queued_model_id]
                    if assigned:
                        assignable = assigned
                option = _choose_available(assignable)
            if option is not None:
                _global_running += 1
                _running_by_model[option.id] = _running_by_model.get(option.id, 0) + 1
                _last_used[option.id] = time.monotonic()
                started_at = time.monotonic()
                if stats_scope_id:
                    stats = _ensure_scope_models_locked(stats_scope_id, options)
                    if queued_model_id:
                        _decrement_queued_locked(stats_scope_id, queued_model_id)
                    item = stats[option.id]
                    item.running += 1
                    item.total += 1
                    item.last_status = "running"
                    item.last_started_at = _now_iso()
                    _scope_updated_at[stats_scope_id] = item.last_started_at
                return ModelLease(
                    option=option,
                    running=_running_by_model[option.id],
                    global_running=_global_running,
                    stats_scope_id=stats_scope_id,
                    started_at=started_at,
                )
            try:
                await asyncio.wait_for(_condition.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass


async def release_model_lease(
    lease: ModelLease | None,
    *,
    outcome: str | None = None,
    duration_seconds: float | None = None,
) -> None:
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
        if lease.stats_scope_id:
            stats = _ensure_scope_models_locked(lease.stats_scope_id, [lease.option])
            item = stats[lease.option.id]
            item.running = max(0, item.running - 1)
            normalized_outcome = outcome if outcome in {"success", "failure", "timeout", "cancelled"} else ""
            if normalized_outcome:
                setattr(item, normalized_outcome, getattr(item, normalized_outcome) + 1)
                item.last_status = normalized_outcome
            if duration_seconds is not None and duration_seconds >= 0:
                item.total_duration_seconds += duration_seconds
            item.last_finished_at = _now_iso()
            _scope_updated_at[lease.stats_scope_id] = item.last_finished_at
        _condition.notify_all()


def _completed_count(item: ModelRuntimeStats) -> int:
    return item.success + item.failure + item.timeout + item.cancelled


def _stats_item_snapshot(item: ModelRuntimeStats) -> dict[str, Any]:
    completed = _completed_count(item)
    return {
        "id": item.id,
        "model": item.model,
        "capability": item.capability,
        "weight": item.weight,
        "max_concurrency": item.max_concurrency,
        "queued": item.queued,
        "running": item.running,
        "total": item.total,
        "success": item.success,
        "failure": item.failure,
        "timeout": item.timeout,
        "cancelled": item.cancelled,
        "avg_duration_seconds": item.total_duration_seconds / completed if completed else 0.0,
        "last_status": item.last_status,
        "last_started_at": item.last_started_at,
        "last_finished_at": item.last_finished_at,
    }


def model_pool_snapshot(scope_id: str = "") -> dict[str, Any]:
    if scope_id:
        stats = _stats_by_scope.get(scope_id, {})
        models = [_stats_item_snapshot(item) for item in stats.values()]
        return {
            "scope_id": scope_id,
            "global_running": sum(item.running for item in stats.values()),
            "global_queued": sum(item.queued for item in stats.values()),
            "models": sorted(models, key=lambda item: item["id"]),
            "updated_at": _scope_updated_at.get(scope_id, ""),
        }
    return {
        "global_running": _global_running,
        "models": dict(_running_by_model),
    }
