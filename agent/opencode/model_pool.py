"""Capability and priority scheduling for unified OpenCode tasks."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


CAPABILITY_ORDER = {"low": 0, "medium": 1, "high": 2}
NO_AVAILABLE_MODEL_MESSAGE = (
    "模型池没有已启用的模型；请先添加并启用模型。"
    "如需使用 CLI 默认模型，请显式添加“默认模型”。"
)


class NoAvailableModelError(RuntimeError):
    """Raised when no explicit, enabled model can service a lease request."""

    def __init__(self) -> None:
        super().__init__(NO_AVAILABLE_MODEL_MESSAGE)


@dataclass(frozen=True)
class ModelTimeWindow:
    weekdays: tuple[int, ...]
    start: int
    end: int


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
    time_windows: tuple[ModelTimeWindow, ...] = ()


@dataclass(frozen=True)
class ModelLease:
    option: ModelOption
    running: int
    global_running: int
    stats_scope_id: str = ""
    started_at: float = 0.0
    started_at_iso: str = ""
    task_id: str = ""


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


@dataclass
class _PendingLeaseRequest:
    request_id: str
    sequence: int
    priority: int
    revision: int
    cli_config: Any
    global_concurrency: int | Any
    required_capability: str
    prefer_high: bool
    cancel_event: Any
    stats_scope_id: str
    task_context: dict[str, Any]
    queued_at: float
    queued_at_iso: str
    strict_capability: bool = False
    prefer_lowest_capability: bool = False
    wait_when_unavailable: bool = False


@dataclass
class _PlannedTask:
    task_id: str
    task_key: str
    sequence: int
    scope_id: str
    task_context: dict[str, Any]
    planned_at_iso: str


_condition = asyncio.Condition()
_running_by_model: dict[str, int] = {}
_global_running = 0
_last_used: dict[str, float] = {}
_stats_by_scope: dict[str, dict[str, ModelRuntimeStats]] = {}
_global_stats_by_model: dict[str, ModelRuntimeStats] = {}
_options_by_id: dict[str, ModelOption] = {}
_scope_updated_at: dict[str, str] = {}
_global_updated_at: str = ""
_active_tasks: dict[str, dict[str, Any]] = {}
_completed_tasks_by_scope: dict[str, list[dict[str, Any]]] = {}
_peak_total_tasks_by_scope: dict[str, int] = {}
_pending_requests: list[_PendingLeaseRequest] = []
_planned_tasks: dict[str, _PlannedTask] = {}
_planned_task_ids_by_key: dict[tuple[str, str], str] = {}
_pending_sequence = 0
_planned_sequence = 0


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


def normalize_priority(value: object, default: int = 50) -> int:
    """Normalize public task priority to the supported 1..100 range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(100, parsed))


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


def _parse_time_windows(value: object) -> tuple[ModelTimeWindow, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    windows: list[ModelTimeWindow] = []
    for item in value:
        if not isinstance(item, dict) and not hasattr(item, "start"):
            continue
        start = _parse_minutes(_cfg_value(item, "start"))
        end = _parse_minutes(_cfg_value(item, "end"))
        if start is None or end is None or start == end:
            continue
        raw_weekdays = _cfg_value(item, "weekdays", None)
        if raw_weekdays is None:
            weekdays = tuple(range(1, 8))
        elif isinstance(raw_weekdays, (list, tuple, set)):
            parsed_weekdays: set[int] = set()
            for raw_day in raw_weekdays:
                try:
                    day = int(raw_day)
                except (TypeError, ValueError):
                    continue
                if 1 <= day <= 7:
                    parsed_weekdays.add(day)
            weekdays = tuple(sorted(parsed_weekdays))
        else:
            weekdays = ()
        if not weekdays:
            continue
        windows.append(ModelTimeWindow(weekdays=weekdays, start=start, end=end))
    return tuple(windows)


def _option_available_now(option: ModelOption, now: datetime | None = None) -> bool:
    if not option.time_windows:
        return True
    local_now = now or datetime.now().astimezone()
    current = local_now.hour * 60 + local_now.minute
    current_weekday = local_now.isoweekday()
    for window in option.time_windows:
        if current_weekday not in window.weekdays:
            continue
        if window.start < window.end:
            if window.start <= current < window.end:
                return True
        elif current >= window.start or current < window.end:
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

    This is the number of OpenCode messages that can actually run in parallel.
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
        enabled = _bool_value(_cfg_value(raw, "enabled", True), True)
        if not enabled:
            continue
        use_default_model = _bool_value(_cfg_value(raw, "use_default_model", False))
        model = "" if use_default_model else str(_cfg_value(raw, "model", "") or "").strip()
        if not use_default_model and not model:
            continue
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
    return options


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
    available = _available_options(
        options,
        global_concurrency=global_concurrency,
        prefer_high=prefer_high,
    )
    return available[0] if available else None


def _available_options(
    options: list[ModelOption],
    *,
    global_concurrency: int,
    prefer_high: bool = False,
    prefer_lowest_capability: bool = False,
) -> list[ModelOption]:
    if _global_running >= global_concurrency:
        return []
    available = [
        option for option in options
        if _running_by_model.get(option.id, 0) < option.max_concurrency
    ]
    if not available:
        return []
    if prefer_high:
        # Soft preference: pick a high-capability model when one has free
        # capacity, but never leave other eligible models idle waiting for one.
        high = [option for option in available if option.capability == "high"]
        if high:
            available = high
    return sorted(
        available,
        key=lambda option: (
            CAPABILITY_ORDER[option.capability] if prefer_lowest_capability else 0,
            _running_by_model.get(option.id, 0) / option.weight,
            _running_by_model.get(option.id, 0),
            -option.weight,
            _last_used.get(option.id, 0.0),
            option.id,
        ),
    )


def _current_request_cli_config(request: _PendingLeaseRequest) -> Any:
    return request.cli_config() if callable(request.cli_config) else request.cli_config


def _current_request_global_concurrency(request: _PendingLeaseRequest) -> int:
    value = (
        request.global_concurrency()
        if callable(request.global_concurrency)
        else request.global_concurrency
    )
    return max(1, int(value or 1))


def _request_options_locked(
    request: _PendingLeaseRequest,
) -> tuple[Any, int, list[ModelOption], list[ModelOption], bool]:
    active_cli_config = _current_request_cli_config(request)
    hard_global_concurrency = _current_request_global_concurrency(request)
    pool_enabled = _configured_model_pool_enabled(active_cli_config)
    all_options = model_options(active_cli_config, global_concurrency=hard_global_concurrency)
    _ensure_global_models_locked(all_options)
    if request.stats_scope_id:
        _ensure_scope_models_locked(request.stats_scope_id, all_options)
    active_options = _active_options(all_options) if pool_enabled else all_options
    return active_cli_config, hard_global_concurrency, all_options, active_options, pool_enabled


def _eligible_options_for_request_locked(
    request: _PendingLeaseRequest,
) -> tuple[list[ModelOption], int, list[ModelOption]]:
    _active_cli_config, hard_global_concurrency, all_options, active_options, pool_enabled = (
        _request_options_locked(request)
    )
    eligible = _eligible_options(
        active_options,
        required_capability=request.required_capability,
    )
    configured_match = _eligible_options(
        all_options,
        required_capability=request.required_capability,
    )
    if (
        not request.strict_capability
        and not eligible
        and active_options
        and (not pool_enabled or not configured_match)
    ):
        # Configuration is too restrictive for the requested capability. Fall
        # back to all currently time-eligible models, but never use a model that
        # is outside its configured time window.
        eligible = active_options
    return eligible, hard_global_concurrency, all_options


def _choose_available_for_request_locked(
    request: _PendingLeaseRequest,
) -> tuple[ModelOption | None, list[ModelOption]]:
    eligible, hard_global_concurrency, all_options = _eligible_options_for_request_locked(request)
    for option in _available_options(
        eligible,
        global_concurrency=hard_global_concurrency,
        prefer_high=request.prefer_high,
        prefer_lowest_capability=request.prefer_lowest_capability,
    ):
        if _planned_order_allows_option_locked(request, option):
            return option, all_options
    return None, all_options


def _context_queue_group(context: dict[str, Any] | None) -> str:
    if not isinstance(context, dict):
        return ""
    return str(context.get("queue_group") or "").strip()


def _context_planned_task_id(context: dict[str, Any] | None) -> str:
    if not isinstance(context, dict):
        return ""
    return str(context.get("planned_task_id") or "").strip()


def _planned_required_capability(planned: _PlannedTask) -> str:
    return normalize_requirement((planned.task_context or {}).get("required_capability"))


def _planned_order_allows_option_locked(
    request: _PendingLeaseRequest,
    option: ModelOption,
) -> bool:
    planned_task_id = _context_planned_task_id(request.task_context)
    if not planned_task_id:
        return True
    planned = _planned_tasks.get(planned_task_id)
    if planned is None:
        return True
    queue_group = _context_queue_group(planned.task_context) or _context_queue_group(request.task_context)
    if not queue_group:
        return True
    for earlier in sorted(_planned_tasks.values(), key=lambda item: item.sequence):
        if earlier.sequence >= planned.sequence:
            break
        if _context_queue_group(earlier.task_context) != queue_group:
            continue
        if capability_satisfies(option.capability, _planned_required_capability(earlier)):
            return False
    return True


def _touch_queue_locked(*scope_ids: str) -> None:
    global _global_updated_at
    now = _now_iso()
    _global_updated_at = now
    for scope_id in scope_ids:
        if scope_id:
            _scope_updated_at[scope_id] = now


def _updated_at_locked(scope_id: str = "") -> str:
    if scope_id:
        return _scope_updated_at.get(scope_id, "")
    return _global_updated_at


async def wait_for_model_pool_update(
    scope_id: str = "",
    *,
    last_updated_at: str = "",
    timeout: float | None = None,
) -> str:
    """Wait until the model-pool updated_at marker changes for a scope.

    Returns the current marker. If *timeout* expires before a matching update,
    the returned value is unchanged from *last_updated_at*.
    """
    async with _condition:
        if _updated_at_locked(scope_id) != last_updated_at:
            return _updated_at_locked(scope_id)
        if timeout is not None and timeout <= 0:
            return _updated_at_locked(scope_id)
        try:
            if timeout is None:
                await _condition.wait_for(lambda: _updated_at_locked(scope_id) != last_updated_at)
            else:
                await asyncio.wait_for(
                    _condition.wait_for(lambda: _updated_at_locked(scope_id) != last_updated_at),
                    timeout=timeout,
                )
        except asyncio.TimeoutError:
            pass
        return _updated_at_locked(scope_id)


def _remove_pending_request_locked(request: _PendingLeaseRequest) -> bool:
    try:
        _pending_requests.remove(request)
    except ValueError:
        return False
    return True


def _remove_planned_task_locked(task_id: str) -> bool:
    planned = _planned_tasks.pop(task_id, None)
    if planned is None:
        return False
    if planned.task_key:
        _planned_task_ids_by_key.pop((planned.scope_id, planned.task_key), None)
    return True


def _consume_planned_task_locked(request: _PendingLeaseRequest) -> None:
    raw_id = _context_planned_task_id(request.task_context)
    if raw_id and _remove_planned_task_locked(raw_id):
        _touch_queue_locked(request.stats_scope_id)


def _fail_no_available_model_locked(request: _PendingLeaseRequest) -> None:
    """Remove a lease request and persist its terminal no-model failure."""
    _consume_planned_task_locked(request)
    _remove_pending_request_locked(request)
    finished_at = _now_iso()
    if request.stats_scope_id:
        context = dict(request.task_context or {})
        prompt = context.get("prompt")
        if isinstance(prompt, str) and "prompt_length" not in context:
            context["prompt_length"] = len(prompt)
        elif not isinstance(prompt, str):
            context.pop("prompt", None)
        _completed_tasks_by_scope.setdefault(request.stats_scope_id, []).append(
            {
                **context,
                "task_id": request.request_id,
                "scope_id": request.stats_scope_id,
                "model_id": "",
                "model": "",
                "started_at": request.queued_at_iso,
                "finished_at": finished_at,
                "duration_seconds": max(0.0, time.monotonic() - request.queued_at),
                "outcome": "failure",
                "failure_reason": NO_AVAILABLE_MODEL_MESSAGE,
            }
        )
    _touch_queue_locked(request.stats_scope_id)
    _condition.notify_all()


async def register_planned_task(
    scope_id: str,
    task_context: dict[str, Any] | None = None,
    *,
    task_key: str = "",
) -> str:
    """Register a future OpenCode invocation that has not requested a lease yet."""
    global _planned_sequence
    context = dict(task_context or {})
    if "required_capability" in context:
        context["required_capability"] = normalize_requirement(context.get("required_capability"))
    async with _condition:
        if task_key:
            existing_id = _planned_task_ids_by_key.get((scope_id, task_key))
            if existing_id and existing_id in _planned_tasks:
                return existing_id
        _planned_sequence += 1
        task_id = uuid4().hex
        planned = _PlannedTask(
            task_id=task_id,
            task_key=task_key,
            sequence=_planned_sequence,
            scope_id=scope_id,
            task_context=context,
            planned_at_iso=_now_iso(),
        )
        _planned_tasks[task_id] = planned
        if task_key:
            _planned_task_ids_by_key[(scope_id, task_key)] = task_id
        _touch_queue_locked(scope_id)
        _condition.notify_all()
        return task_id


async def clear_planned_task(task_id: str) -> None:
    """Remove one planned OpenCode task that will not request a lease."""
    if not task_id:
        return
    async with _condition:
        planned = _planned_tasks.get(task_id)
        scope_id = planned.scope_id if planned is not None else ""
        if _remove_planned_task_locked(task_id):
            _touch_queue_locked(scope_id)
            _condition.notify_all()


async def clear_planned_tasks(scope_id: str, task_types: set[str] | None = None) -> None:
    """Remove all planned OpenCode tasks for a scope."""
    async with _condition:
        removed = False
        for task_id, planned in list(_planned_tasks.items()):
            if planned.scope_id != scope_id:
                continue
            planned_type = str((planned.task_context or {}).get("task_type") or "")
            if task_types is not None and planned_type not in task_types:
                continue
            _remove_planned_task_locked(task_id)
            removed = True
        if removed:
            _touch_queue_locked(scope_id)
            _condition.notify_all()


def _prune_cancelled_pending_locked() -> None:
    removed_scope_ids: set[str] = set()
    for request in list(_pending_requests):
        cancel_event = request.cancel_event
        if cancel_event is not None and cancel_event.is_set():
            _consume_planned_task_locked(request)
            _pending_requests.remove(request)
            removed_scope_ids.add(request.stats_scope_id)
    if removed_scope_ids:
        _touch_queue_locked(*removed_scope_ids)


def _next_runnable_pending_locked() -> tuple[_PendingLeaseRequest, ModelOption, list[ModelOption]] | None:
    _prune_cancelled_pending_locked()
    for request in sorted(
        _pending_requests,
        key=lambda item: (-item.priority, item.sequence),
    ):
        option, all_options = _choose_available_for_request_locked(request)
        if option is not None:
            return request, option, all_options
    return None


def _grant_lease_locked(
    request: _PendingLeaseRequest,
    option: ModelOption,
    all_options: list[ModelOption],
) -> ModelLease:
    global _global_running, _global_updated_at

    _consume_planned_task_locked(request)
    _global_running += 1
    _running_by_model[option.id] = _running_by_model.get(option.id, 0) + 1
    _last_used[option.id] = time.monotonic()
    started_at = time.monotonic()
    started_at_iso = _now_iso()
    task_id = request.request_id
    global_item = _global_stats_by_model[option.id]
    global_item.running += 1
    global_item.total += 1
    global_item.last_status = "running"
    global_item.last_started_at = started_at_iso
    _active_tasks[task_id] = {
        "task_id": task_id,
        "model_id": option.id,
        "scope_id": request.stats_scope_id,
        "started_at": started_at_iso,
        "context": dict(request.task_context or {}),
    }
    if request.stats_scope_id:
        stats = _ensure_scope_models_locked(request.stats_scope_id, all_options)
        item = stats[option.id]
        item.running += 1
        item.total += 1
        item.last_status = "running"
        item.last_started_at = started_at_iso
        _scope_updated_at[request.stats_scope_id] = item.last_started_at
    _global_updated_at = started_at_iso
    return ModelLease(
        option=option,
        running=_running_by_model[option.id],
        global_running=_global_running,
        stats_scope_id=request.stats_scope_id,
        started_at=started_at,
        started_at_iso=started_at_iso,
        task_id=task_id,
    )


def _stats_config_matches(current: ModelRuntimeStats, option: ModelOption) -> bool:
    return (
        current.model == option.model
        and current.capability == option.capability
        and current.weight == option.weight
        and current.max_concurrency == option.max_concurrency
    )


def _ensure_scope_models_locked(scope_id: str, options: list[ModelOption]) -> dict[str, ModelRuntimeStats]:
    stats = _stats_by_scope.setdefault(scope_id, {})
    changed = False
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
            changed = True
        elif not _stats_config_matches(current, option):
            current.model = option.model
            current.capability = option.capability
            current.weight = option.weight
            current.max_concurrency = option.max_concurrency
            changed = True
    if changed:
        _scope_updated_at[scope_id] = _now_iso()
    return stats


def _ensure_global_models_locked(options: list[ModelOption]) -> dict[str, ModelRuntimeStats]:
    global _global_updated_at
    changed = False
    for option in options:
        previous_option = _options_by_id.get(option.id)
        if previous_option != option:
            changed = True
        _options_by_id[option.id] = option
        current = _global_stats_by_model.get(option.id)
        if current is None:
            _global_stats_by_model[option.id] = ModelRuntimeStats(
                id=option.id,
                model=option.model,
                capability=option.capability,
                weight=option.weight,
                max_concurrency=option.max_concurrency,
            )
            changed = True
        elif not _stats_config_matches(current, option):
            current.model = option.model
            current.capability = option.capability
            current.weight = option.weight
            current.max_concurrency = option.max_concurrency
            changed = True
    if changed:
        _global_updated_at = _now_iso()
    return _global_stats_by_model


async def acquire_model_lease(
    cli_config: Any,
    *,
    global_concurrency: int | Any,
    required_capability: str = "any",
    prefer_high: bool = False,
    cancel_event=None,
    stats_scope_id: str = "",
    task_context: dict[str, Any] | None = None,
    priority: int = 50,
    task_id: str = "",
    revision: int = 1,
    strict_capability: bool = False,
    prefer_lowest_capability: bool = False,
    wait_when_unavailable: bool = False,
) -> ModelLease | None:
    required = normalize_requirement(required_capability)
    request: _PendingLeaseRequest | None = None
    context = dict(task_context or {})
    context.setdefault("required_capability", required)
    context.setdefault("priority", normalize_priority(priority))
    context.setdefault("revision", max(1, int(revision or 1)))

    while True:
        if cancel_event is not None and cancel_event.is_set():
            if request is not None:
                async with _condition:
                    _consume_planned_task_locked(request)
                    if _remove_pending_request_locked(request):
                        _touch_queue_locked(request.stats_scope_id)
                        _condition.notify_all()
            return None
        async with _condition:
            if request is None:
                global _pending_sequence
                _pending_sequence += 1
                queued_at_iso = _now_iso()
                request = _PendingLeaseRequest(
                    request_id=str(task_id or "").strip() or uuid4().hex,
                    sequence=_pending_sequence,
                    priority=normalize_priority(priority),
                    revision=max(1, int(revision or 1)),
                    cli_config=cli_config,
                    global_concurrency=global_concurrency,
                    required_capability=required,
                    prefer_high=prefer_high,
                    cancel_event=cancel_event,
                    stats_scope_id=stats_scope_id,
                    task_context=dict(context),
                    queued_at=time.monotonic(),
                    queued_at_iso=queued_at_iso,
                    strict_capability=bool(strict_capability),
                    prefer_lowest_capability=bool(prefer_lowest_capability),
                    wait_when_unavailable=bool(wait_when_unavailable),
                )
                option, all_options = _choose_available_for_request_locked(request)
                if not all_options and not request.wait_when_unavailable:
                    _fail_no_available_model_locked(request)
                    raise NoAvailableModelError()
                if option is not None and not _pending_requests:
                    return _grant_lease_locked(request, option, all_options)
                _pending_requests.append(request)
                _touch_queue_locked(stats_scope_id)
                _condition.notify_all()
            else:
                _, _, all_options, _, _ = _request_options_locked(request)
                if not all_options and not request.wait_when_unavailable:
                    _fail_no_available_model_locked(request)
                    raise NoAvailableModelError()

            next_runnable = _next_runnable_pending_locked()
            if next_runnable is not None:
                selected, option, all_options = next_runnable
                if selected is request:
                    _remove_pending_request_locked(request)
                    return _grant_lease_locked(request, option, all_options)
            try:
                await asyncio.wait_for(_condition.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass


async def release_model_lease(
    lease: ModelLease | None,
    *,
    outcome: str | None = None,
    duration_seconds: float | None = None,
    record_completion: bool = True,
) -> None:
    if lease is None:
        return
    global _global_running
    async with _condition:
        finished_at = _now_iso()
        active_task = _active_tasks.get(lease.task_id)
        _global_running = max(0, _global_running - 1)
        current = _running_by_model.get(lease.option.id, 0)
        if current <= 1:
            _running_by_model.pop(lease.option.id, None)
        else:
            _running_by_model[lease.option.id] = current - 1
        global_item = _global_stats_by_model.get(lease.option.id)
        if global_item is None:
            global_item = ModelRuntimeStats(
                id=lease.option.id,
                model=lease.option.model,
                capability=lease.option.capability,
                weight=lease.option.weight,
                max_concurrency=lease.option.max_concurrency,
            )
            _global_stats_by_model[lease.option.id] = global_item
        global_item.running = max(0, global_item.running - 1)
        normalized_outcome = outcome if outcome in {"success", "failure", "timeout", "cancelled"} else ""
        if normalized_outcome:
            setattr(global_item, normalized_outcome, getattr(global_item, normalized_outcome) + 1)
            global_item.last_status = normalized_outcome
        if duration_seconds is not None and duration_seconds >= 0:
            global_item.total_duration_seconds += duration_seconds
        global_item.last_finished_at = finished_at
        if record_completion and active_task is not None and lease.stats_scope_id:
            context = dict(active_task.get("context") or {})
            prompt = context.get("prompt")
            if isinstance(prompt, str) and "prompt_length" not in context:
                context["prompt_length"] = len(prompt)
            elif not isinstance(prompt, str):
                context.pop("prompt", None)
            completed = {
                **context,
                "task_id": lease.task_id,
                "scope_id": lease.stats_scope_id,
                "model_id": lease.option.id,
                "model": lease.option.model,
                "started_at": active_task.get("started_at", lease.started_at_iso),
                "finished_at": finished_at,
                "duration_seconds": duration_seconds,
                "outcome": normalized_outcome or "unknown",
            }
            _completed_tasks_by_scope.setdefault(lease.stats_scope_id, []).append(completed)
        _active_tasks.pop(lease.task_id, None)
        if lease.stats_scope_id:
            stats = _ensure_scope_models_locked(lease.stats_scope_id, [lease.option])
            item = stats[lease.option.id]
            item.running = max(0, item.running - 1)
            if normalized_outcome:
                setattr(item, normalized_outcome, getattr(item, normalized_outcome) + 1)
                item.last_status = normalized_outcome
            if duration_seconds is not None and duration_seconds >= 0:
                item.total_duration_seconds += duration_seconds
            item.last_finished_at = finished_at
            _scope_updated_at[lease.stats_scope_id] = item.last_finished_at
        global _global_updated_at
        _global_updated_at = finished_at
        _condition.notify_all()


async def clear_completed_tasks(scope_id: str) -> None:
    """Release scan-local completion history after its final snapshot is persisted."""
    if not scope_id:
        return
    async with _condition:
        _completed_tasks_by_scope.pop(scope_id, None)
        _peak_total_tasks_by_scope.pop(scope_id, None)


async def update_model_lease_context(lease: ModelLease | None, updates: dict[str, Any]) -> None:
    """Merge live metadata into the active task for a lease."""
    if lease is None or not lease.task_id or not updates:
        return
    async with _condition:
        task = _active_tasks.get(lease.task_id)
        if task is None:
            return
        context = task.setdefault("context", {})
        if not isinstance(context, dict):
            context = {}
            task["context"] = context
        changed = False
        for key, value in updates.items():
            if value in (None, ""):
                continue
            if context.get(key) != value:
                context[key] = value
                changed = True
        if not changed:
            return
        updated_at = _now_iso()
        if lease.stats_scope_id:
            _scope_updated_at[lease.stats_scope_id] = updated_at
        global _global_updated_at
        _global_updated_at = updated_at
        _condition.notify_all()


def _completed_count(item: ModelRuntimeStats) -> int:
    return item.success + item.failure + item.timeout + item.cancelled


def _format_time_windows(windows: tuple[ModelTimeWindow, ...]) -> list[dict[str, object]]:
    return [
        {
            "weekdays": list(window.weekdays),
            "start": f"{window.start // 60:02d}:{window.start % 60:02d}",
            "end": f"{window.end // 60:02d}:{window.end % 60:02d}",
        }
        for window in windows
    ]


def _stats_item_snapshot(
    item: ModelRuntimeStats,
    *,
    option: ModelOption | None = None,
    scope_id: str = "",
) -> dict[str, Any]:
    completed = _completed_count(item)
    active_tasks = [
        {
            "task_id": task["task_id"],
            "scope_id": task.get("scope_id", ""),
            "started_at": task.get("started_at", ""),
            **dict(task.get("context") or {}),
        }
        for task in _active_tasks.values()
        if task.get("model_id") == item.id and (not scope_id or task.get("scope_id") == scope_id)
    ]
    return {
        "id": item.id,
        "model": item.model,
        "use_default_model": option.use_default_model if option is not None else False,
        "capability": item.capability,
        "weight": item.weight,
        "max_concurrency": item.max_concurrency,
        "enabled": option is not None,
        "available": _option_available_now(option) if option is not None else False,
        "time_windows": _format_time_windows(option.time_windows) if option is not None else [],
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
        "active_tasks": active_tasks,
    }


def _pending_request_matches_scope(request: _PendingLeaseRequest, scope_id: str) -> bool:
    return not scope_id or request.stats_scope_id == scope_id


def _pending_request_snapshot(request: _PendingLeaseRequest) -> dict[str, Any]:
    cli_config = _current_request_cli_config(request)
    global_concurrency = _current_request_global_concurrency(request)
    all_options = model_options(cli_config, global_concurrency=global_concurrency)
    active_options = (
        _active_options(all_options)
        if _configured_model_pool_enabled(cli_config)
        else all_options
    )
    eligible = _eligible_options(
        active_options,
        required_capability=request.required_capability,
    )
    if not all_options:
        blocked_reason = NO_AVAILABLE_MODEL_MESSAGE
    elif not eligible:
        blocked_reason = (
            f"没有满足 {request.required_capability} 能力要求且当前可用的模型；"
            "等待模型配置或时间窗口变化。"
        )
    else:
        blocked_reason = ""
    return {
        "request_id": request.request_id,
        "task_id": request.request_id,
        "scope_id": request.stats_scope_id,
        "queued_at": request.queued_at_iso,
        "required_capability": request.required_capability,
        "prefer_high": request.prefer_high,
        "priority": request.priority,
        "revision": request.revision,
        "blocked_reason": blocked_reason,
        **dict(request.task_context or {}),
    }


def _planned_task_snapshot(planned: _PlannedTask) -> dict[str, Any]:
    return {
        "planned_task_id": planned.task_id,
        "scope_id": planned.scope_id,
        "planned_at": planned.planned_at_iso,
        **dict(planned.task_context or {}),
    }


def _pending_requests_snapshot(scope_id: str = "") -> list[dict[str, Any]]:
    return [
        _pending_request_snapshot(request)
        for request in sorted(
            _pending_requests,
            key=lambda item: (-item.priority, item.sequence),
        )
        if _pending_request_matches_scope(request, scope_id)
    ]


def _planned_tasks_snapshot(scope_id: str = "") -> list[dict[str, Any]]:
    pending_planned_ids = {
        _context_planned_task_id(request.task_context)
        for request in _pending_requests
    }
    return [
        _planned_task_snapshot(planned)
        for planned in sorted(_planned_tasks.values(), key=lambda item: item.sequence)
        if not scope_id or planned.scope_id == scope_id
        if planned.task_id not in pending_planned_ids
    ]


def model_pool_snapshot(scope_id: str = "") -> dict[str, Any]:
    if scope_id:
        stats = _stats_by_scope.get(scope_id, {})
        models = [
            _stats_item_snapshot(item, option=_options_by_id.get(item.id), scope_id=scope_id)
            for item in stats.values()
        ]
        queued_tasks = _pending_requests_snapshot(scope_id)
        planned_tasks = _planned_tasks_snapshot(scope_id)
        completed_tasks = list(_completed_tasks_by_scope.get(scope_id, []))
        active_task_count = sum(len(model.get("active_tasks", [])) for model in models)
        observed_total = (
            len(completed_tasks)
            + active_task_count
            + len(queued_tasks)
            + len(planned_tasks)
        )
        total_tasks = max(_peak_total_tasks_by_scope.get(scope_id, 0), observed_total)
        _peak_total_tasks_by_scope[scope_id] = total_tasks
        return {
            "scope_id": scope_id,
            "global_running": sum(item.running for item in stats.values()),
            "global_queued": len(queued_tasks),
            "total_tasks": total_tasks,
            "completed_task_count": len(completed_tasks),
            "queued_tasks": queued_tasks,
            "planned_tasks": planned_tasks,
            "completed_tasks": completed_tasks,
            "models": sorted(models, key=lambda item: item["id"]),
            "updated_at": _scope_updated_at.get(scope_id, ""),
        }
    stats = _global_stats_by_model
    models = [_stats_item_snapshot(item, option=_options_by_id.get(item.id)) for item in stats.values()]
    queued_tasks = _pending_requests_snapshot()
    planned_tasks = _planned_tasks_snapshot()
    return {
        "global_running": _global_running,
        "global_queued": len(queued_tasks),
        "total_tasks": 0,
        "completed_task_count": 0,
        "queued_tasks": queued_tasks,
        "planned_tasks": planned_tasks,
        "completed_tasks": [],
        "models": sorted(models, key=lambda item: item["id"]),
        "updated_at": _global_updated_at,
    }


async def refresh_configured_model_pool(cli_config: Any, *, global_concurrency: int) -> None:
    """Refresh configured model rows without waiting for the next task lease.

    Config changes should become visible to queued leases and dashboards
    immediately. Runtime counters are preserved for models that keep the same id.
    """
    global _global_updated_at
    async with _condition:
        options = model_options(cli_config, global_concurrency=max(1, global_concurrency))
        configured_ids = {option.id for option in options}
        for model_id in list(_options_by_id):
            if model_id not in configured_ids:
                _options_by_id.pop(model_id, None)
        _ensure_global_models_locked(options)
        now = _now_iso()
        _global_updated_at = now
        for scope_id, stats in _stats_by_scope.items():
            _ensure_scope_models_locked(scope_id, options)
            for model_id in list(stats):
                if model_id not in configured_ids and stats[model_id].running <= 0:
                    stats[model_id].last_status = "disabled"
            _scope_updated_at[scope_id] = now
        _condition.notify_all()


async def notify_model_pool_config_changed() -> None:
    """Wake queued tasks and force snapshot signatures to change after config edits."""
    global _global_updated_at
    async with _condition:
        now = _now_iso()
        _global_updated_at = now
        for scope_id in list(_stats_by_scope):
            _scope_updated_at[scope_id] = now
        _condition.notify_all()
