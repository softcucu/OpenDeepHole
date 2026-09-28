"""Capability and priority scheduling for unified OpenCode tasks."""

from __future__ import annotations

import asyncio
import copy
import inspect
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from .token_usage import OpenCodeTokenUsage, merge_token_usages


CAPABILITY_ORDER = {"low": 0, "medium": 1, "high": 2}
MODEL_HEALTH_MAX_PENALTY_LEVEL = 4
MODEL_HEALTH_RECOVERY_SECONDS = 10 * 60
MODEL_HEALTH_MIN_WEIGHT_FACTOR = 0.1
MODEL_QUOTA_BACKOFF_INITIAL_SECONDS = 30.0
MODEL_QUOTA_BACKOFF_MAX_SECONDS = 300.0
MODEL_QUOTA_CIRCUIT_MAX_WAIT_SECONDS = 300.0
NO_AVAILABLE_MODEL_MESSAGE = (
    "模型池没有已启用的模型；请先添加并启用模型。"
    "如需使用 CLI 默认模型，请显式添加“默认模型”。"
)


class NoAvailableModelError(RuntimeError):
    """Raised when no explicit, enabled model can service a lease request."""

    def __init__(self) -> None:
        super().__init__(NO_AVAILABLE_MODEL_MESSAGE)


class ModelQuotaCircuitOpenError(RuntimeError):
    """Raised when every eligible model stayed quota-blocked past the task limit."""

    def __init__(self, *, wait_limit_reached: bool = True) -> None:
        suffix = (
            "本任务已达到 5 分钟有限等待上限，请稍后重试。"
            if wait_limit_reached
            else "当前调用不等待冷却，请稍后重试。"
        )
        super().__init__(f"所有符合条件的模型仍处于 Provider 配额冷却期；{suffix}")


@dataclass
class ModelQuotaWaitBudget:
    """Mutable per-logical-task budget consumed only while all models cool."""

    total_seconds: float = MODEL_QUOTA_CIRCUIT_MAX_WAIT_SECONDS
    remaining_seconds: float = 0.0
    active_since: float | None = None

    def __post_init__(self) -> None:
        self.total_seconds = max(0.0, float(self.total_seconds))
        self.remaining_seconds = self.total_seconds

    def start(self, now: float) -> None:
        if self.active_since is None:
            self.active_since = now

    def pause(self, now: float) -> None:
        if self.active_since is None:
            return
        self.remaining_seconds = max(
            0.0,
            self.remaining_seconds - max(0.0, now - self.active_since),
        )
        self.active_since = None

    def remaining(self, now: float) -> float:
        if self.active_since is None:
            return self.remaining_seconds
        return max(
            0.0,
            self.remaining_seconds - max(0.0, now - self.active_since),
        )


logger = logging.getLogger(f"opendeephole.{__name__}")


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
    health_identity: tuple[str, bool, str, str] = ()
    health_generation: str = ""
    quota_half_open_probe: bool = False


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
class _ModelHealthState:
    identity: tuple[str, bool, str, str]
    generation: str
    penalty_level: int = 0
    last_health_failure_at: str = ""
    last_health_failure_kind: str = ""
    recovery_anchor: float | None = None
    quota_failure_count: int = 0
    quota_open_until: float | None = None
    quota_half_open_probe_in_flight: bool = False


@dataclass
class _PendingLeaseRequest:
    request_id: str
    sequence: int
    priority: int
    revision: int
    cli_config: Any
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
    record_completion_on_failure: bool = True
    avoid_model_ids: frozenset[str] = frozenset()
    avoid_model_identities: frozenset[tuple[str, bool, str, str]] = frozenset()
    quota_wait_deadline: float | None = None
    quota_wait_budget: ModelQuotaWaitBudget | None = None
    quota_wait_logged: bool = False


@dataclass
class _PlannedTask:
    task_id: str
    task_key: str
    sequence: int
    scope_id: str
    task_context: dict[str, Any]
    planned_at_iso: str


_condition = asyncio.Condition()
_change_waiters: set[asyncio.Event] = set()
_running_by_model: dict[str, int] = {}
_global_running = 0
_last_used: dict[str, float] = {}
_stats_by_scope: dict[str, dict[str, ModelRuntimeStats]] = {}
_global_stats_by_model: dict[str, ModelRuntimeStats] = {}
_options_by_id: dict[str, ModelOption] = {}
_model_health_by_id: dict[str, _ModelHealthState] = {}
_scope_updated_at: dict[str, str] = {}
_global_updated_at: str = ""
_active_tasks: dict[str, dict[str, Any]] = {}
_completed_tasks_by_scope: dict[str, list[dict[str, Any]]] = {}
_completed_task_count_by_scope: dict[str, int] = {}
_completed_task_sink: Callable[[dict[str, Any]], None] | None = None
_completed_delivery_task: asyncio.Task | None = None
COMPLETED_REPORT_RETRY_SECONDS = 2.0
_token_usage_by_scope: dict[str, OpenCodeTokenUsage] = {}
_global_token_usage: OpenCodeTokenUsage | None = None
_peak_total_tasks_by_scope: dict[str, int] = {}
_pending_requests: list[_PendingLeaseRequest] = []
_planned_tasks: dict[str, _PlannedTask] = {}
_planned_task_ids_by_key: dict[tuple[str, str], str] = {}
_pending_sequence = 0
_planned_sequence = 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_completed_task_sink(
    sink: Callable[[dict[str, Any]], None] | None,
) -> None:
    """Route terminal task history to a durable host sink when one is available."""
    global _completed_task_sink
    if sink is _completed_task_sink:
        return
    _completed_task_sink = sink
    if sink is not None:
        # A backend may gain incremental-report support after an Agent has
        # already accumulated legacy in-memory history.  Persist those rows
        # before hiding them from subsequent bounded pool snapshots.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # Legacy synchronous hosts bind outside an event loop.
            for tasks in _completed_tasks_by_scope.values():
                while tasks:
                    sink(copy.deepcopy(tasks[0]))
                    tasks.pop(0)
            _completed_tasks_by_scope.clear()
        else:
            _schedule_completed_task_delivery()


def _schedule_completed_task_delivery() -> None:
    global _completed_delivery_task
    if _completed_task_sink is not None and (
        _completed_delivery_task is None or _completed_delivery_task.done()
    ):
        _completed_delivery_task = asyncio.create_task(_deliver_completed_tasks())


async def _deliver_completed_tasks() -> None:
    """Keep undelivered history until the host has durably accepted it."""
    failed = False
    while _completed_task_sink is not None:
        selected = next((
            (scope, tasks[0]) for scope, tasks in _completed_tasks_by_scope.items() if tasks
        ), None)
        if selected is None:
            return
        scope, task = selected
        sink = _completed_task_sink
        try:
            # A host sink may use SQLite/fsync or a blocking file lock. Neither
            # model-pool locks nor the Agent loop may wait synchronously for it.
            result = await asyncio.to_thread(sink, copy.deepcopy(task))
            if inspect.isawaitable(result):
                await result
        except Exception:
            if not failed:
                logger.exception("OpenCode completion report pending; model capacity already released")
            failed = True
            await asyncio.sleep(COMPLETED_REPORT_RETRY_SECONDS)
            continue
        failed = False
        tasks = _completed_tasks_by_scope.get(scope, [])
        if tasks and tasks[0] is task:
            tasks.pop(0)
        if not tasks:
            _completed_tasks_by_scope.pop(scope, None)


async def drain_completed_task_reports(timeout: float = 10.0) -> bool:
    """Bound shutdown flushing without discarding reports after a failed write."""
    _schedule_completed_task_delivery()
    task = _completed_delivery_task
    if task is not None and not task.done():
        await asyncio.wait({task}, timeout=timeout)
    return not any(_completed_tasks_by_scope.values())


def _record_completed_task_locked(scope_id: str, task: dict[str, Any]) -> None:
    if not scope_id:
        return
    snapshot = copy.deepcopy(task)
    _completed_tasks_by_scope.setdefault(scope_id, []).append(snapshot)
    _schedule_completed_task_delivery()
    _completed_task_count_by_scope[scope_id] = (
        _completed_task_count_by_scope.get(scope_id, 0) + 1
    )


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


def configured_model_capacity(cli_config: Any) -> int:
    """Configured capacity of enabled, valid models, before time/capability filters."""
    return sum(option.max_concurrency for option in model_options(cli_config))


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


def _model_health_identity(option: ModelOption) -> tuple[str, bool, str, str]:
    """Return the fields that identify the actual model execution target."""
    return (
        option.model,
        option.use_default_model,
        option.tool,
        option.executable,
    )


def _ensure_model_health_locked(option: ModelOption) -> _ModelHealthState:
    identity = _model_health_identity(option)
    state = _model_health_by_id.get(option.id)
    if state is not None and state.identity == identity:
        return state
    state = next(
        (
            candidate
            for model_id, candidate in _model_health_by_id.items()
            if model_id != option.id and candidate.identity == identity
        ),
        None,
    )
    if state is None:
        state = _ModelHealthState(identity=identity, generation=uuid4().hex)
    _model_health_by_id[option.id] = state
    return state


def _recover_model_health_locked(
    state: _ModelHealthState,
    *,
    now: float | None = None,
) -> bool:
    if state.penalty_level <= 0 or state.recovery_anchor is None:
        return False
    current = time.monotonic() if now is None else now
    elapsed = max(0.0, current - state.recovery_anchor)
    recovery_steps = int(elapsed // MODEL_HEALTH_RECOVERY_SECONDS)
    if recovery_steps <= 0:
        return False
    state.penalty_level = max(0, state.penalty_level - recovery_steps)
    if state.penalty_level:
        state.recovery_anchor += recovery_steps * MODEL_HEALTH_RECOVERY_SECONDS
    else:
        state.recovery_anchor = None
    return True


def _effective_model_weight_locked(option: ModelOption) -> float:
    state = _ensure_model_health_locked(option)
    _recover_model_health_locked(state)
    factor = max(
        MODEL_HEALTH_MIN_WEIGHT_FACTOR,
        0.5 ** state.penalty_level,
    )
    return option.weight * factor


def _quota_circuit_available_locked(
    option: ModelOption,
    *,
    now: float | None = None,
) -> bool:
    state = _ensure_model_health_locked(option)
    if state.quota_open_until is None:
        return True
    current = time.monotonic() if now is None else now
    if current < state.quota_open_until:
        return False
    return not state.quota_half_open_probe_in_flight


def _quota_backoff_seconds(
    failure_count: int,
    retry_after_seconds: float | None,
) -> float:
    if retry_after_seconds is not None and retry_after_seconds > 0:
        return min(MODEL_QUOTA_BACKOFF_MAX_SECONDS, max(1.0, retry_after_seconds))
    exponential = MODEL_QUOTA_BACKOFF_INITIAL_SECONDS * (2 ** max(0, failure_count - 1))
    return min(MODEL_QUOTA_BACKOFF_MAX_SECONDS, exponential)


def _apply_model_health_outcome_locked(
    lease: ModelLease,
    health_outcome: str,
    *,
    quota_retry_after_seconds: float | None = None,
) -> bool:
    state = _model_health_by_id.get(lease.option.id)
    if (
        state is None
        or state.identity != lease.health_identity
        or state.generation != lease.health_generation
    ):
        state = next(
            (
                candidate
                for candidate in _model_health_by_id.values()
                if candidate.identity == lease.health_identity
                and candidate.generation == lease.health_generation
            ),
            None,
        )
        if state is None:
            # A config refresh replaced or fully removed this execution target.
            # A late release must not change the replacement model's health.
            return False
    now = time.monotonic()
    _recover_model_health_locked(state, now=now)
    if health_outcome in {"failure", "timeout", "quota"}:
        state.penalty_level = min(
            MODEL_HEALTH_MAX_PENALTY_LEVEL,
            state.penalty_level + 1,
        )
        state.last_health_failure_at = _now_iso()
        state.last_health_failure_kind = health_outcome
        state.recovery_anchor = now
        state.quota_half_open_probe_in_flight = False
        if health_outcome == "quota":
            state.quota_failure_count += 1
            delay = _quota_backoff_seconds(
                state.quota_failure_count,
                quota_retry_after_seconds,
            )
            state.quota_open_until = now + delay
            logger.warning(
                "Opened model Provider quota circuit model_id=%s model=%s "
                "cooldown_seconds=%s failure_count=%s",
                lease.option.id,
                lease.option.model or "<cli-default>",
                f"{delay:g}",
                state.quota_failure_count,
            )
        return True
    if health_outcome == "success":
        changed = False
        if state.penalty_level > 0:
            state.penalty_level -= 1
            if state.penalty_level <= 0:
                state.recovery_anchor = None
            changed = True
        if state.quota_open_until is not None or state.quota_failure_count:
            logger.info(
                "Closed model Provider quota circuit after successful request "
                "model_id=%s model=%s",
                lease.option.id,
                lease.option.model or "<cli-default>",
            )
            state.quota_failure_count = 0
            state.quota_open_until = None
            changed = True
        if state.quota_half_open_probe_in_flight:
            state.quota_half_open_probe_in_flight = False
            changed = True
        return changed
    if lease.quota_half_open_probe and state.quota_half_open_probe_in_flight:
        state.quota_half_open_probe_in_flight = False
        return True
    return False


def total_model_capacity(
    cli_config: Any,
    *,
    required_capability: str = "any",
) -> int:
    """Sum of max_concurrency across enabled models satisfying the requirement.

    Honor capability and time windows, retaining one worker to surface an
    unavailable model pool or wait for a configured model's time window.
    """
    required = normalize_requirement(required_capability)
    options = model_options(cli_config)
    if _configured_model_pool_enabled(cli_config):
        options = _active_options(options)
    eligible = [
        option for option in options
        if capability_satisfies(option.capability, required)
    ]
    if not eligible:
        all_options = model_options(cli_config)
        configured_match = _eligible_options(all_options, required_capability=required)
        if not _configured_model_pool_enabled(cli_config) or not configured_match:
            # Mirror acquire_model_lease(): an over-restrictive requirement falls
            # back to all enabled models rather than deadlocking. A configured
            # but currently out-of-window matching model should still be waited on.
            eligible = options
    capacity = sum(option.max_concurrency for option in eligible)
    return max(1, capacity)


def model_options(cli_config: Any) -> list[ModelOption]:
    raw_models = _cfg_value(cli_config, "models", None) or []
    configured_tool = "opencode"
    configured_executable = str(
        _cfg_value(cli_config, "executable", "") or "opencode"
    ).strip()
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
                    _cfg_value(raw, "max_concurrency", 1),
                    1,
                ),
                tool=configured_tool,
                executable=configured_executable,
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
    prefer_high: bool = False,
) -> ModelOption | None:
    available = _available_options(
        options,
        prefer_high=prefer_high,
    )
    return available[0] if available else None


def _available_options(
    options: list[ModelOption],
    *,
    prefer_high: bool = False,
    prefer_lowest_capability: bool = False,
) -> list[ModelOption]:
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
    effective_weights = {
        option.id: _effective_model_weight_locked(option)
        for option in available
    }
    return sorted(
        available,
        key=lambda option: (
            _running_by_model.get(option.id, 0) / effective_weights[option.id],
            _running_by_model.get(option.id, 0),
            -effective_weights[option.id],
            CAPABILITY_ORDER[option.capability] if prefer_lowest_capability else 0,
            _last_used.get(option.id, 0.0),
            option.id,
        ),
    )


def _current_request_cli_config(request: _PendingLeaseRequest) -> Any:
    return request.cli_config() if callable(request.cli_config) else request.cli_config


def _request_options_locked(
    request: _PendingLeaseRequest,
) -> tuple[list[ModelOption], list[ModelOption], bool]:
    active_cli_config = _current_request_cli_config(request)
    pool_enabled = _configured_model_pool_enabled(active_cli_config)
    all_options = model_options(active_cli_config)
    _ensure_global_models_locked(all_options)
    if request.stats_scope_id:
        _ensure_scope_models_locked(request.stats_scope_id, all_options)
    active_options = _active_options(all_options) if pool_enabled else all_options
    return all_options, active_options, pool_enabled


def _eligible_options_for_request_locked(
    request: _PendingLeaseRequest,
) -> tuple[list[ModelOption], list[ModelOption]]:
    all_options, active_options, pool_enabled = (
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
    return eligible, all_options


def _choose_available_for_request_locked(
    request: _PendingLeaseRequest,
) -> tuple[ModelOption | None, list[ModelOption]]:
    eligible, all_options = _eligible_options_for_request_locked(request)
    now = time.monotonic()
    circuit_available = [
        option
        for option in eligible
        if _quota_circuit_available_locked(option, now=now)
    ]
    untried = [
        option for option in circuit_available
        if option.id not in request.avoid_model_ids
        and _model_health_identity(option) not in request.avoid_model_identities
    ]
    # A fresh-session retry must wait for an eligible, time-active alternative
    # even when the previous model has capacity right now. Only fall back after
    # every eligible alternative has been attempted (or none exists).
    selection_options = untried or circuit_available
    for option in _available_options(
        selection_options,
        prefer_high=request.prefer_high,
        prefer_lowest_capability=request.prefer_lowest_capability,
    ):
        if _planned_order_allows_option_locked(request, option):
            return option, all_options
    return None, all_options


def _request_blocked_by_quota_circuits_locked(
    request: _PendingLeaseRequest,
) -> bool:
    eligible, _ = _eligible_options_for_request_locked(request)
    if not eligible:
        return False
    now = time.monotonic()
    return not any(
        _quota_circuit_available_locked(option, now=now)
        for option in eligible
    )


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
    expires = None if timeout is None else time.monotonic() + max(0.0, timeout)
    while True:
        async with _condition:
            remaining = None if expires is None else max(0.0, expires - time.monotonic())
            if _updated_at_locked(scope_id) != last_updated_at or remaining == 0:
                return _updated_at_locked(scope_id)
            changed = _register_change_waiter_locked()
        await _wait_for_pool_change(changed, remaining)


def _register_change_waiter_locked() -> asyncio.Event:
    changed = asyncio.Event()
    _change_waiters.add(changed)
    return changed


def _notify_pool_changed_locked() -> None:
    for changed in _change_waiters:
        changed.set()


async def _wait_for_pool_change(changed: asyncio.Event, timeout: float | None) -> None:
    # Python 3.10 wait_for creates a child task. Cancelling that child while
    # Condition.wait reacquires its lock can orphan the shared pool lock.
    # Register under the lock (no lost wakeups), but only wait outside it.
    try:
        await asyncio.wait_for(changed.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        _change_waiters.discard(changed)


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


def _fail_pending_request_locked(
    request: _PendingLeaseRequest,
    failure_reason: str,
    *,
    failure_kind: str = "execution_error",
) -> None:
    """Remove a lease request and persist its terminal scheduling failure."""
    if request.quota_wait_budget is not None:
        request.quota_wait_budget.pause(time.monotonic())
    _consume_planned_task_locked(request)
    _remove_pending_request_locked(request)
    finished_at = _now_iso()
    duration_seconds = max(0.0, time.monotonic() - request.queued_at)
    if request.stats_scope_id and request.record_completion_on_failure:
        context = dict(request.task_context or {})
        prompt = context.get("prompt")
        if isinstance(prompt, str) and "prompt_length" not in context:
            context["prompt_length"] = len(prompt)
        elif not isinstance(prompt, str):
            context.pop("prompt", None)
        raw_events = context.get("session_events")
        session_events = [
            dict(item)
            for item in raw_events
            if isinstance(item, dict)
        ] if isinstance(raw_events, list) else []
        task_phase = str(context.get("task_phase") or "").strip()
        phase = (
            "json_format"
            if task_phase == "json_format"
            else "json_retry"
            if task_phase == "json_correction"
            else "business"
        )
        session_events.append({
            "sequence": len(session_events) + 1,
            "phase": phase,
            "session_id": (
                str(context.get("serve_session_id") or "").strip()
                if phase == "json_retry"
                else ""
            ),
            "session_attempt": max(1, int(context.get("session_attempt") or 1)),
            "outcome": "failure",
            "failure_kind": failure_kind,
            "failure_reason": failure_reason,
            "started_at": request.queued_at_iso,
            "finished_at": finished_at,
            "duration_seconds": duration_seconds,
        })
        context["session_events"] = session_events
        context["failure_kind"] = failure_kind
        context["failure_reason"] = failure_reason
        _record_completed_task_locked(
            request.stats_scope_id,
            {
                **context,
                "task_id": request.request_id,
                "scope_id": request.stats_scope_id,
                "model_id": "",
                "model": "",
                "started_at": request.queued_at_iso,
                "finished_at": finished_at,
                "duration_seconds": duration_seconds,
                "outcome": "failure",
                "failure_reason": failure_reason,
            },
        )
    _touch_queue_locked(request.stats_scope_id)
    _notify_pool_changed_locked()


def _fail_no_available_model_locked(request: _PendingLeaseRequest) -> None:
    _fail_pending_request_locked(
        request,
        NO_AVAILABLE_MODEL_MESSAGE,
        failure_kind="no_available_model",
    )


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
        _notify_pool_changed_locked()
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
            _notify_pool_changed_locked()


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
            _notify_pool_changed_locked()


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
        "lease_started_at": started_at,
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
    health_state = _ensure_model_health_locked(option)
    quota_half_open_probe = bool(
        health_state.quota_open_until is not None
        and time.monotonic() >= health_state.quota_open_until
        and not health_state.quota_half_open_probe_in_flight
    )
    if quota_half_open_probe:
        health_state.quota_half_open_probe_in_flight = True
        logger.info(
            "Starting half-open model Provider quota probe model_id=%s model=%s",
            option.id,
            option.model or "<cli-default>",
        )
    return ModelLease(
        option=option,
        running=_running_by_model[option.id],
        global_running=_global_running,
        stats_scope_id=request.stats_scope_id,
        started_at=started_at,
        started_at_iso=started_at_iso,
        task_id=task_id,
        health_identity=health_state.identity,
        health_generation=health_state.generation,
        quota_half_open_probe=quota_half_open_probe,
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
        previous_health = _model_health_by_id.get(option.id)
        if (
            previous_health is None
            or previous_health.identity != _model_health_identity(option)
        ):
            _last_used.pop(option.id, None)
            changed = True
        _ensure_model_health_locked(option)
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
    record_completion_on_failure: bool = True,
    avoid_model_ids: set[str] | frozenset[str] | None = None,
    avoid_model_identities: (
        set[tuple[str, bool, str, str]]
        | frozenset[tuple[str, bool, str, str]]
        | None
    ) = None,
    quota_wait_deadline: float | None = None,
    quota_wait_budget: ModelQuotaWaitBudget | None = None,
    on_queued: Callable[[], Any] | None = None,
) -> ModelLease | None:
    required = normalize_requirement(required_capability)
    request: _PendingLeaseRequest | None = None
    context = dict(task_context or {})
    context.setdefault("required_capability", required)
    context.setdefault("priority", normalize_priority(priority))
    context.setdefault("revision", max(1, int(revision or 1)))

    try:
        while True:
            notify_queued = False
            if cancel_event is not None and cancel_event.is_set():
                if request is not None:
                    async with _condition:
                        if request.quota_wait_budget is not None:
                            request.quota_wait_budget.pause(time.monotonic())
                        _consume_planned_task_locked(request)
                        if _remove_pending_request_locked(request):
                            _touch_queue_locked(request.stats_scope_id)
                            _notify_pool_changed_locked()
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
                        record_completion_on_failure=bool(record_completion_on_failure),
                        avoid_model_ids=frozenset(
                            str(model_id).strip()
                            for model_id in (avoid_model_ids or ())
                            if str(model_id).strip()
                        ),
                        avoid_model_identities=frozenset(
                            (
                                str(identity[0]),
                                bool(identity[1]),
                                str(identity[2]),
                                str(identity[3]),
                            )
                            for identity in (avoid_model_identities or ())
                            if isinstance(identity, (tuple, list)) and len(identity) == 4
                        ),
                        quota_wait_deadline=(
                            float(quota_wait_deadline)
                            if quota_wait_deadline is not None
                            else None
                        ),
                        quota_wait_budget=quota_wait_budget,
                    )
                    option, all_options = _choose_available_for_request_locked(request)
                    if not all_options and not request.wait_when_unavailable:
                        _fail_no_available_model_locked(request)
                        raise NoAvailableModelError()
                    if option is not None and not _pending_requests:
                        return _grant_lease_locked(request, option, all_options)
                    _pending_requests.append(request)
                    _touch_queue_locked(stats_scope_id)
                    _notify_pool_changed_locked()
                    notify_queued = True
                else:
                    all_options, _, _ = _request_options_locked(request)
                    if not all_options and not request.wait_when_unavailable:
                        _fail_no_available_model_locked(request)
                        raise NoAvailableModelError()

                if notify_queued:
                    # This request can only grant itself on its next loop, so it is
                    # safe to notify outside the pool lock before execution starts.
                    pass
                else:
                    blocked_by_quota = _request_blocked_by_quota_circuits_locked(request)
                    if blocked_by_quota:
                        now = time.monotonic()
                        if request.quota_wait_budget is not None:
                            request.quota_wait_budget.start(now)
                        budget_expired = bool(
                            request.quota_wait_budget is not None
                            and request.quota_wait_budget.remaining(now) <= 0
                        )
                        if (
                            budget_expired
                            or (
                                request.quota_wait_deadline is not None
                                and now >= request.quota_wait_deadline
                            )
                            or (
                                request.quota_wait_deadline is None
                                and not request.wait_when_unavailable
                            )
                        ):
                            error = ModelQuotaCircuitOpenError(
                                wait_limit_reached=(
                                    budget_expired
                                    or request.quota_wait_deadline is not None
                                ),
                            )
                            _fail_pending_request_locked(
                                request,
                                str(error),
                                failure_kind="quota",
                            )
                            raise error
                        if not request.quota_wait_logged:
                            remaining = (
                                request.quota_wait_budget.remaining(now)
                                if request.quota_wait_budget is not None
                                else (
                                    max(0.0, request.quota_wait_deadline - now)
                                    if request.quota_wait_deadline is not None
                                    else None
                                )
                            )
                            logger.info(
                                "Waiting for model Provider quota circuit cooldown task_id=%s "
                                "remaining_limit_seconds=%s",
                                request.request_id,
                                f"{remaining:.1f}" if remaining is not None else "unbounded",
                            )
                            request.quota_wait_logged = True
                    elif request.quota_wait_budget is not None:
                        request.quota_wait_budget.pause(time.monotonic())

                    next_runnable = _next_runnable_pending_locked()
                    if next_runnable is not None:
                        selected, option, all_options = next_runnable
                        if selected is request:
                            _remove_pending_request_locked(request)
                            return _grant_lease_locked(request, option, all_options)
                    changed = _register_change_waiter_locked()
            if not notify_queued:
                await _wait_for_pool_change(changed, 0.2)
            if notify_queued and on_queued is not None:
                notified = on_queued()
                if inspect.isawaitable(notified):
                    await notified
    finally:
        if request is not None:
            # No pool critical section awaits I/O or another task. Withdrawal
            # therefore cannot wait behind a cancelled condition waiter.
            async with _condition:
                if _remove_pending_request_locked(request):
                    if request.quota_wait_budget is not None:
                        request.quota_wait_budget.pause(time.monotonic())
                    _consume_planned_task_locked(request)
                    _touch_queue_locked(request.stats_scope_id)
                    _notify_pool_changed_locked()


async def release_model_lease(
    lease: ModelLease | None,
    *,
    outcome: str | None = None,
    health_outcome: str | None = None,
    quota_retry_after_seconds: float | None = None,
    duration_seconds: float | None = None,
    record_completion: bool = True,
    context_updates: dict[str, Any] | None = None,
) -> None:
    if lease is None:
        return
    global _global_running
    async with _condition:
        finished_at = _now_iso()
        active_task = _active_tasks.get(lease.task_id)
        if active_task is None or active_task.get("lease_started_at") != lease.started_at:
            return
        if context_updates:
            _merge_lease_context_locked(active_task, context_updates)
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
        normalized_health_outcome = (
            health_outcome
            if health_outcome in {"success", "failure", "timeout", "quota"}
            else ""
        )
        if normalized_health_outcome:
            _apply_model_health_outcome_locked(
                lease,
                normalized_health_outcome,
                quota_retry_after_seconds=quota_retry_after_seconds,
            )
        elif lease.quota_half_open_probe:
            state = _model_health_by_id.get(lease.option.id)
            if (
                state is not None
                and state.identity == lease.health_identity
                and state.generation == lease.health_generation
            ):
                state.quota_half_open_probe_in_flight = False
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
            _record_completed_task_locked(lease.stats_scope_id, completed)
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
        _notify_pool_changed_locked()
    logger.info(
        "OpenCode model lease released task=%s model=%s outcome=%s terminal=%s",
        lease.task_id, lease.option.id, normalized_outcome or "unknown", record_completion,
    )


async def clear_completed_tasks(scope_id: str) -> None:
    """Release scan-local completion history after its final snapshot is persisted."""
    if not scope_id:
        return
    async with _condition:
        if _completed_task_sink is None:
            _completed_tasks_by_scope.pop(scope_id, None)
        _completed_task_count_by_scope.pop(scope_id, None)
        _token_usage_by_scope.pop(scope_id, None)
        _peak_total_tasks_by_scope.pop(scope_id, None)


async def record_model_token_usage(
    lease: ModelLease | None,
    usage: OpenCodeTokenUsage | dict[str, Any] | None,
) -> None:
    """Add one prompt's deduplicated usage to Agent and scan accumulators."""
    if lease is None or usage is None:
        return
    global _global_token_usage, _global_updated_at
    async with _condition:
        active = _active_tasks.get(lease.task_id)
        if active is None or active.get("lease_started_at") != lease.started_at:
            return
        _global_token_usage = merge_token_usages((_global_token_usage, usage))
        if lease.stats_scope_id:
            scoped_usage = merge_token_usages(
                (_token_usage_by_scope.get(lease.stats_scope_id), usage)
            )
            if scoped_usage is not None:
                _token_usage_by_scope[lease.stats_scope_id] = scoped_usage
        updated_at = _now_iso()
        _global_updated_at = updated_at
        if lease.stats_scope_id:
            _scope_updated_at[lease.stats_scope_id] = updated_at
        _notify_pool_changed_locked()


async def update_model_lease_context(lease: ModelLease | None, updates: dict[str, Any]) -> None:
    """Merge live metadata into the active task for a lease."""
    if lease is None or not lease.task_id or not updates:
        return
    async with _condition:
        task = _active_tasks.get(lease.task_id)
        if task is None or task.get("lease_started_at") != lease.started_at:
            return
        if not _merge_lease_context_locked(task, updates):
            return
        updated_at = _now_iso()
        if lease.stats_scope_id:
            _scope_updated_at[lease.stats_scope_id] = updated_at
        global _global_updated_at
        _global_updated_at = updated_at
        _notify_pool_changed_locked()


def _merge_lease_context_locked(task: dict[str, Any], updates: dict[str, Any]) -> bool:
    context = task.setdefault("context", {})
    if not isinstance(context, dict):
        context = {}
        task["context"] = context
    changed = False
    for key, value in updates.items():
        if value not in (None, "") and context.get(key) != value:
            context[key] = value
            changed = True
    return changed


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
    if option is not None:
        health = _ensure_model_health_locked(option)
        effective_weight = _effective_model_weight_locked(option)
        health_penalty_level = health.penalty_level
        last_health_failure_at = health.last_health_failure_at
        last_health_failure_kind = health.last_health_failure_kind
    else:
        effective_weight = item.weight
        health_penalty_level = 0
        last_health_failure_at = ""
        last_health_failure_kind = ""
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
        "effective_weight": effective_weight,
        "health_penalty_level": health_penalty_level,
        "last_health_failure_at": last_health_failure_at,
        "last_health_failure_kind": last_health_failure_kind,
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
    all_options = model_options(cli_config)
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
    elif not any(_quota_circuit_available_locked(option) for option in eligible):
        blocked_reason = (
            "所有满足能力要求的模型都处于 Provider 配额冷却或半开探测中；"
            "等待模型恢复。"
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
        visible_stats = dict(stats)
        for option in _options_by_id.values():
            visible_stats.setdefault(
                option.id,
                ModelRuntimeStats(
                    id=option.id,
                    model=option.model,
                    capability=option.capability,
                    weight=option.weight,
                    max_concurrency=option.max_concurrency,
                ),
            )
        models = [
            _stats_item_snapshot(item, option=_options_by_id.get(item.id), scope_id=scope_id)
            for item in visible_stats.values()
        ]
        queued_tasks = _pending_requests_snapshot(scope_id)
        planned_tasks = _planned_tasks_snapshot(scope_id)
        completed_tasks = list(_completed_tasks_by_scope.get(scope_id, []))
        completed_task_count = _completed_task_count_by_scope.get(
            scope_id,
            len(completed_tasks),
        )
        active_task_count = sum(len(model.get("active_tasks", [])) for model in models)
        observed_total = (
            completed_task_count
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
            "completed_task_count": completed_task_count,
            "queued_tasks": queued_tasks,
            "planned_tasks": planned_tasks,
            "completed_tasks": (
                completed_tasks if _completed_task_sink is None else []
            ),
            "token_usage": (
                _token_usage_by_scope[scope_id].as_dict()
                if scope_id in _token_usage_by_scope
                else None
            ),
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
        "token_usage": (
            _global_token_usage.as_dict() if _global_token_usage is not None else None
        ),
        "models": sorted(models, key=lambda item: item["id"]),
        "updated_at": _global_updated_at,
    }


async def refresh_configured_model_pool(cli_config: Any) -> None:
    """Refresh configured model rows without waiting for the next task lease.

    Config changes should become visible to queued leases and dashboards
    immediately. Runtime counters are preserved for models that keep the same id.
    """
    global _global_updated_at
    async with _condition:
        options = model_options(cli_config)
        configured_ids = {option.id for option in options}
        # Bind new ids/identities before deleting removed ids so health follows
        # an unchanged execution target across a config-row rename.
        _ensure_global_models_locked(options)
        for model_id in list(_options_by_id):
            if model_id not in configured_ids:
                _options_by_id.pop(model_id, None)
                _model_health_by_id.pop(model_id, None)
                _last_used.pop(model_id, None)
        now = _now_iso()
        _global_updated_at = now
        for scope_id, stats in _stats_by_scope.items():
            _ensure_scope_models_locked(scope_id, options)
            for model_id in list(stats):
                if model_id not in configured_ids and stats[model_id].running <= 0:
                    stats[model_id].last_status = "disabled"
            _scope_updated_at[scope_id] = now
        _notify_pool_changed_locked()


async def notify_model_pool_config_changed() -> None:
    """Wake queued tasks and force snapshot signatures to change after config edits."""
    global _global_updated_at
    async with _condition:
        now = _now_iso()
        _global_updated_at = now
        for scope_id in list(_stats_by_scope):
            _scope_updated_at[scope_id] = now
        _notify_pool_changed_locked()
