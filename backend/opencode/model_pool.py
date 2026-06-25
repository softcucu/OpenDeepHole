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
    use_default_model: bool
    capability: str
    weight: float
    max_concurrency: int
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: tuple[tuple[int, int], ...] = ()


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


def _bool_value(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def configured_global_concurrency(config: Any) -> int:
    return _safe_int(_cfg_value(config, "opencode_concurrency", 1), 1, 1)


def _configured_model_pool_enabled(cli_config: Any) -> bool:
    return bool(_cfg_value(cli_config, "models", None) or [])


def _parse_minutes(value: object) -> int | None:
    parts = str(value or "").strip().split(":")
    if len(parts) != 2:
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return None
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    return hour * 60 + minute


def _parse_time_windows(value: object) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        return ()
    windows: list[tuple[int, int]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        start = _parse_minutes(item.get("start"))
        end = _parse_minutes(item.get("end"))
        if start is None or end is None or start == end:
            continue
        windows.append((start, end))
    return tuple(windows)


def _option_available_now(option: ModelOption, now: datetime | None = None) -> bool:
    if not option.time_windows:
        return True
    local_now = now or datetime.now().astimezone()
    current = local_now.hour * 60 + local_now.minute
    for start, end in option.time_windows:
        if start < end:
            if start <= current < end:
                return True
        elif current >= start or current < end:
            return True
    return False


def _active_options(options: list[ModelOption], now: datetime | None = None) -> list[ModelOption]:
    return [option for option in options if _option_available_now(option, now)]


def total_model_capacity(
    cli_config: Any,
    *,
    global_concurrency: int,
    required_capability: str = "any",
) -> int:
    """Sum of max_concurrency across enabled models satisfying the requirement.

    This is the number of CLI invocations that can actually run in parallel.
    When a model pool is configured, the top-level concurrency is a hard cap
    over all currently time-eligible models.
    """
    required = normalize_requirement(required_capability)
    options = model_options(cli_config, global_concurrency=global_concurrency)
    if _configured_model_pool_enabled(cli_config):
        options = _active_options(options)
    eligible = [
        option for option in options
        if capability_satisfies(option.capability, required)
    ]
    if not eligible:
        all_options = model_options(cli_config, global_concurrency=global_concurrency)
        configured_match = _eligible_options(all_options, required_capability=required)
        if not _configured_model_pool_enabled(cli_config) or not configured_match:
            # Mirror acquire_model_lease(): an over-restrictive requirement falls
            # back to all enabled models rather than deadlocking. A configured
            # but currently out-of-window matching model should still be waited on.
            eligible = options
    capacity = sum(option.max_concurrency for option in eligible)
    if _configured_model_pool_enabled(cli_config):
        capacity = min(global_concurrency, capacity)
    return max(1, capacity)


def model_options(cli_config: Any, *, global_concurrency: int) -> list[ModelOption]:
    raw_models = _cfg_value(cli_config, "models", None) or []
    options: list[ModelOption] = []
    for index, raw in enumerate(raw_models):
        if raw is None:
            continue
        enabled = bool(_cfg_value(raw, "enabled", True))
        if not enabled:
            continue
        use_default_model = _bool_value(_cfg_value(raw, "use_default_model", False))
        model = "" if use_default_model else str(_cfg_value(raw, "model", "") or "").strip()
        model_id = str(
            _cfg_value(raw, "id", "") or model or ("default" if use_default_model else f"model-{index + 1}")
        ).strip()
        if not model_id:
            continue
        options.append(
            ModelOption(
                id=model_id,
                model=model,
                use_default_model=use_default_model,
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
                time_windows=_parse_time_windows(_cfg_value(raw, "time_windows", [])),
            )
        )
    if options:
        return options

    return [
        ModelOption(
            id="default",
            model=str(_cfg_value(cli_config, "model", "") or ""),
            use_default_model=not bool(str(_cfg_value(cli_config, "model", "") or "").strip()),
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
) -> list[ModelOption]:
    return [
        option for option in options
        if capability_satisfies(option.capability, required_capability)
    ]


def _choose_available(
    options: list[ModelOption],
    *,
    global_concurrency: int,
    prefer_high: bool = False,
) -> ModelOption | None:
    if _global_running >= global_concurrency:
        return None
    available = [
        option for option in options
        if _running_by_model.get(option.id, 0) < option.max_concurrency
    ]
    if not available:
        return None
    if prefer_high:
        # Soft preference: pick a high-capability model when one has free
        # capacity, but never leave other eligible models idle waiting for one.
        high = [option for option in available if option.capability == "high"]
        if high:
            available = high
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
    hard_global_concurrency = max(1, global_concurrency)
    pool_enabled = _configured_model_pool_enabled(cli_config)
    all_options = model_options(cli_config, global_concurrency=hard_global_concurrency)

    global _global_running
    queued_model_id = ""
    if stats_scope_id:
        async with _condition:
            stats = _ensure_scope_models_locked(stats_scope_id, all_options)
            active_options = _active_options(all_options) if pool_enabled else all_options
            eligible = _eligible_options(active_options, required_capability=required)
            configured_match = _eligible_options(all_options, required_capability=required)
            if not eligible and active_options and (not pool_enabled or not configured_match):
                eligible = active_options
            queue_candidates = eligible or _eligible_options(all_options, required_capability=required) or all_options
            queued_option = _choose_queue_target(queue_candidates, stats)
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
            all_options = model_options(cli_config, global_concurrency=hard_global_concurrency)
            active_options = _active_options(all_options) if pool_enabled else all_options
            eligible = _eligible_options(active_options, required_capability=required)
            configured_match = _eligible_options(all_options, required_capability=required)
            if not eligible and active_options and (not pool_enabled or not configured_match):
                # Configuration is too restrictive for the requested capability.
                # Fall back to all currently time-eligible models rather than
                # using a model outside its configured window.
                eligible = active_options
            if stats_scope_id:
                _ensure_scope_models_locked(stats_scope_id, all_options)
            option = None
            if queued_model_id and eligible:
                assigned = [candidate for candidate in eligible if candidate.id == queued_model_id]
                if assigned:
                    option = _choose_available(
                        assigned,
                        global_concurrency=hard_global_concurrency,
                        prefer_high=prefer_high,
                    )
            if option is None and eligible:
                # Queued-target model is busy: take any other eligible model
                # with free capacity instead of idling behind the pinned one.
                option = _choose_available(
                    eligible,
                    global_concurrency=hard_global_concurrency,
                    prefer_high=prefer_high,
                )
            if option is not None:
                _global_running += 1
                _running_by_model[option.id] = _running_by_model.get(option.id, 0) + 1
                _last_used[option.id] = time.monotonic()
                started_at = time.monotonic()
                if stats_scope_id:
                    stats = _ensure_scope_models_locked(stats_scope_id, all_options)
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
