"""Agent API — endpoints for local agent daemons to connect, push events, and submit scan results.

WebSocket (preferred, v2):
  WS   /api/agent/ws              agent connects, receives task/stop/resume commands

HTTP registration (legacy, v1):
  POST /api/agent/register        register agent → agent_id
  PUT  /api/agent/heartbeat/{id}  heartbeat
  DELETE /api/agent/{id}          unregister

Scan events (called by agent during scan):
  POST /api/agent/scan/{id}/event
  POST /api/agent/scan/{id}/vulnerability
  POST /api/agent/scan/{id}/finish
  POST /api/agent/scan/{id}/processed
  GET  /api/agent/scan/{id}/processed

Other:
  GET  /api/agent/feedback
  GET  /api/agent/download
  GET  /api/agents
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import secrets
import socket
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel

from backend.api.scan import _running_scans, _scan_owners
from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.opencode_config import parse_opencode_jsonc, redact_opencode_config_content
from backend.models import (
    AgentGitHistory,
    AgentMcpConfig,
    AgentMcpProbeResult,
    AgentMcpRuntimeStatus,
    AgentMcpStatusResponse,
    AgentMcpTargetStatus,
    AgentOpenCodePoolStatus,
    AgentOpenCodeRuntimeConfigResponse,
    AgentInfo,
    AgentRemoteConfig,
    AgentValidatorCatalog,
    AgentScanCandidates,
    AgentScanFinish,
    AgentVulnerabilityValidationUpdate,
    FpReviewStatus,
    HistoryPattern,
    OpenCodePoolStatus,
    ScanEvent,
    ScanItemStatus,
    SkillReport,
    ThreatAuditTask,
    User,
    Vulnerability,
    VulnerabilityValidation,
)
from backend.store import get_scan_store
from backend.threat_data import parse_threat_analysis_data

router = APIRouter(prefix="/api/agent")
public_router = APIRouter()  # Routes not under /api/agent prefix
logger = get_logger(__name__)
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Root of the project (two levels up from this file: backend/api/ → backend/ → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory registry of connected agents
_registered_agents: dict[str, AgentInfo] = {}

# Active WebSocket connections keyed by agent_id (WebSocket mode)
_agent_ws: dict[str, WebSocket] = {}
_agent_ws_locks: dict[str, asyncio.Lock] = {}
_agent_disconnect_tasks: dict[str, asyncio.Task] = {}

# Compatibility cache.  New entries are keyed by stable agent_key; name keys
# are still read for tests and pre-v2 HTTP agents.
_agent_configs: dict[str, AgentRemoteConfig] = {}
_agent_opencode_pool_latest: dict[str, OpenCodePoolStatus] = {}


def _stored_agent_config(record: dict | None) -> AgentRemoteConfig:
    if not record:
        return AgentRemoteConfig()
    try:
        payload = json.loads(str(record.get("config_json") or "{}"))
        return AgentRemoteConfig(**payload)
    except Exception as exc:
        logger.warning("Ignoring invalid persisted Agent config: %s", exc)
        return AgentRemoteConfig()


def _stored_validator_catalog(record: dict | None) -> AgentValidatorCatalog:
    if not record:
        return AgentValidatorCatalog()
    try:
        payload = json.loads(str(record.get("validator_catalog_json") or "{}"))
        return AgentValidatorCatalog(**payload)
    except Exception as exc:
        logger.warning("Ignoring invalid persisted validator catalog: %s", exc)
        return AgentValidatorCatalog(errors=[str(exc)])


def _stored_mcp_probes(record: dict | None) -> dict[str, AgentMcpProbeResult]:
    if not record:
        return {}
    try:
        payload = json.loads(str(record.get("mcp_probe_json") or "{}"))
    except Exception as exc:
        logger.warning("Ignoring invalid persisted MCP probe results: %s", exc)
        return {}
    if not isinstance(payload, dict):
        return {}
    results: dict[str, AgentMcpProbeResult] = {}
    for target in ("code_graph", "product_info"):
        raw = payload.get(target)
        if not isinstance(raw, dict):
            continue
        try:
            results[target] = AgentMcpProbeResult(**raw)
        except Exception as exc:
            logger.warning("Ignoring invalid persisted %s MCP probe result: %s", target, exc)
    return results


def _stored_opencode_runtime_config(record: dict | None) -> dict | None:
    if not record:
        return None
    try:
        payload = json.loads(str(record.get("opencode_runtime_config_json") or "{}"))
    except Exception as exc:
        logger.warning("Ignoring invalid persisted OpenCode runtime config metadata: %s", exc)
        return None
    if not isinstance(payload, dict) or not payload.get("exists"):
        return None
    if not isinstance(payload.get("content"), str):
        return None
    return payload


def _mcp_config_fingerprint(config: AgentMcpConfig) -> str:
    from backend.opencode_config import managed_mcp_config_fingerprint

    return managed_mcp_config_fingerprint(config)


def _mcp_target_config(config: AgentRemoteConfig, target: str) -> AgentMcpConfig:
    if target == "code_graph":
        return config.code_graph
    if target == "product_info":
        return config.product_info
    raise HTTPException(status_code=422, detail="MCP 检测目标只能是 code_graph 或 product_info")


def _mcp_target_status(
    config: AgentMcpConfig,
    last_probe: AgentMcpProbeResult | None,
    runtime: AgentMcpRuntimeStatus | None = None,
) -> AgentMcpTargetStatus:
    return AgentMcpTargetStatus(
        enabled=config.enabled,
        stale=(
            last_probe is not None
            and last_probe.config_fingerprint != _mcp_config_fingerprint(config)
        ),
        last_probe=last_probe,
        runtime=runtime or AgentMcpRuntimeStatus(),
    )


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _live_agent_for_key(agent_key: str) -> tuple[str, AgentInfo] | None:
    candidates = [
        (agent_id, agent)
        for agent_id, agent in _registered_agents.items()
        if agent.agent_key == agent_key and agent_id in _agent_ws
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[1].last_seen)


def resolve_agent_connection(agent_key: str) -> tuple[str, AgentInfo] | None:
    """Resolve a stable Agent key to its current WebSocket connection."""
    return _live_agent_for_key(str(agent_key or "").strip())


def _authorize_agent_record(record: dict | None, current_user: User) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and str(record.get("user_id") or "") != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return record


def agent_config_has_explicit_model(config: AgentRemoteConfig) -> bool:
    return any(
        model.enabled and bool(str(model.model or "").strip()) and not model.use_default_model
        for model in config.model_pool.models
    )


def get_managed_agent_config(agent_key: str) -> AgentRemoteConfig:
    record = get_scan_store().get_agent_record(str(agent_key or "").strip())
    if record is None:
        return AgentRemoteConfig()
    return _stored_agent_config(record)


def _validate_managed_config(
    config: AgentRemoteConfig,
    catalog: AgentValidatorCatalog | None = None,
) -> None:
    try:
        parse_opencode_jsonc(config.opencode_config, source="OpenCode 配置")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if config.base.tool not in {"nga", "opencode"}:
        raise HTTPException(status_code=422, detail="基础配置中的工具只能是 nga 或 opencode")
    if not config.base.executable.strip():
        raise HTTPException(status_code=422, detail="工具可执行文件不能为空")
    if not 1 <= config.model_pool.global_concurrency <= 64:
        raise HTTPException(status_code=422, detail="模型池总并发数必须在 1 到 64 之间")
    seen: set[str] = set()
    for index, model in enumerate(config.model_pool.models, start=1):
        model_id = model.id.strip()
        if not model_id:
            raise HTTPException(status_code=422, detail=f"模型第 {index} 行缺少 ID")
        if model_id in seen:
            raise HTTPException(status_code=422, detail=f"模型 ID 重复：{model_id}")
        seen.add(model_id)
        if model.enabled and (model.use_default_model or not model.model.strip()):
            raise HTTPException(status_code=422, detail=f"启用模型 {model_id} 必须填写显式模型名")
        if model.capability not in {"low", "medium", "high"}:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的能力配置无效")
        if model.tool and model.tool not in {"nga", "opencode"}:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的工具覆盖无效")
        if model.weight <= 0:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的权重必须大于 0")
        if model.max_concurrency < 1:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的并发数必须大于 0")
        if model.timeout is not None and model.timeout < 1:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的超时必须大于 0")
        if model.max_retries is not None and model.max_retries < 0:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的重试次数不能小于 0")
        for window in model.time_windows:
            weekdays = window.weekdays
            if not weekdays:
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的每个使用时间段至少要选择一天",
                )
            if len(set(weekdays)) != len(weekdays) or any(day < 1 or day > 7 for day in weekdays):
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的星期配置必须为不重复的 1 到 7",
                )
            try:
                start = str(window.start or "")
                end = str(window.end or "")
                datetime.strptime(start, "%H:%M")
                datetime.strptime(end, "%H:%M")
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的使用时间窗口必须为 HH:MM-HH:MM",
                )
            if start == end:
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的使用时间窗口起止时间不能相同",
                )
    policies = {
        "漏洞挖掘": config.vulnerability_mining,
        "去误报": config.false_positive,
    }
    for environment, env_cfg in config.vulnerability_validation.environments.items():
        if not str(environment).strip():
            raise HTTPException(status_code=422, detail="验证环境名称不能为空")
        if env_cfg.concurrency < 1 or env_cfg.concurrency > 64:
            raise HTTPException(status_code=422, detail=f"验证环境 {environment} 的并发数必须在 1 到 64 之间")
        if env_cfg.validation_max_retries < 0:
            raise HTTPException(status_code=422, detail=f"验证环境 {environment} 的整体验证重试不能小于 0")
        if not any(str(item).strip() for item in env_cfg.supported_vulnerability_types):
            raise HTTPException(status_code=422, detail=f"验证环境 {environment} 至少需要一个支持的漏洞类型")
        policies[f"验证环境 {environment}"] = env_cfg.model_policy
    for label, policy in policies.items():
        if policy.required_capability not in {"low", "high"}:
            raise HTTPException(status_code=422, detail=f"{label}的模型能力无效")
        if policy.timeout_seconds < 1:
            raise HTTPException(status_code=422, detail=f"{label}的模型超时必须大于 0")
        if policy.max_retries < 0:
            raise HTTPException(status_code=422, detail=f"{label}的模型重试不能小于 0")
    for label, mcp in (("代码图谱", config.code_graph), ("产品信息", config.product_info)):
        if mcp.transport not in {"local", "remote"}:
            raise HTTPException(status_code=422, detail=f"{label} MCP 模式无效")
        if mcp.enabled and not mcp.name.strip():
            raise HTTPException(status_code=422, detail=f"{label} MCP 名称不能为空")
        if mcp.enabled and mcp.name.strip() == "deephole-code":
            raise HTTPException(status_code=422, detail=f"{label} MCP 名称不能占用 deephole-code")
        if mcp.timeout_seconds < 1:
            raise HTTPException(status_code=422, detail=f"{label} MCP 超时必须大于 0")
        if mcp.enabled and mcp.transport == "local" and not mcp.local.executable.strip():
            raise HTTPException(status_code=422, detail=f"{label} MCP 可执行文件不能为空")
        if mcp.enabled and mcp.transport == "remote" and not mcp.remote.url.strip():
            raise HTTPException(status_code=422, detail=f"{label} MCP 远端 URL 不能为空")
        seen_headers: set[str] = set()
        for raw_name, raw_value in mcp.remote.headers.items():
            raw_name_text = str(raw_name or "")
            name = raw_name_text.strip()
            lowered = name.lower()
            if (
                not name
                or name != raw_name_text
                or not _HTTP_HEADER_NAME_RE.fullmatch(name)
            ):
                raise HTTPException(status_code=422, detail=f"{label} MCP 请求头名称无效：{name or '(空)'}")
            if lowered in seen_headers:
                raise HTTPException(status_code=422, detail=f"{label} MCP 请求头名称重复：{name}")
            seen_headers.add(lowered)
            if "\r" in str(raw_value) or "\n" in str(raw_value):
                raise HTTPException(status_code=422, detail=f"{label} MCP 请求头 {name} 的值不能包含换行")
    if (
        config.code_graph.enabled
        and config.product_info.enabled
        and config.code_graph.name.strip() == config.product_info.name.strip()
    ):
        raise HTTPException(status_code=422, detail="代码图谱与产品信息不能使用相同的 MCP 名称")
    if catalog is not None:
        registrations = {item.registration_key: item for item in catalog.registrations}
        for environment, environment_config in config.vulnerability_validation.environments.items():
            for registration_key, values in environment_config.methods.items():
                registration = registrations.get(registration_key)
                if registration is None or registration.environment != environment:
                    raise HTTPException(status_code=422, detail=f"未知的验证方法配置：{registration_key}")
                schemas = {field.key: field for field in registration.fields}
                unknown = sorted(set(values) - set(schemas))
                if unknown:
                    raise HTTPException(status_code=422, detail=f"验证方法 {registration.method_label} 包含未知字段：{', '.join(unknown)}")
                for field in registration.fields:
                    value = values.get(field.key, field.default)
                    if field.required and (value is None or value == ""):
                        raise HTTPException(status_code=422, detail=f"验证方法 {registration.method_label} 缺少必填字段：{field.label}")
                    if value is None or value == "":
                        continue
                    try:
                        if field.type == "integer":
                            if isinstance(value, bool):
                                raise ValueError
                            parsed_value = int(value)
                        elif field.type == "number":
                            if isinstance(value, bool):
                                raise ValueError
                            parsed_value = float(value)
                        elif field.type == "boolean":
                            if not isinstance(value, bool):
                                raise ValueError
                            parsed_value = value
                        else:
                            parsed_value = str(value)
                    except (TypeError, ValueError):
                        raise HTTPException(
                            status_code=422,
                            detail=f"验证方法 {registration.method_label} 的字段 {field.label} 类型无效",
                        )
                    if field.type == "select" and field.options and parsed_value not in {
                        str(option) for option in field.options
                    }:
                        raise HTTPException(
                            status_code=422,
                            detail=f"验证方法 {registration.method_label} 的字段 {field.label} 选项无效",
                        )
                    if field.type in {"integer", "number"}:
                        if field.min is not None and parsed_value < field.min:
                            raise HTTPException(
                                status_code=422,
                                detail=f"验证方法 {registration.method_label} 的字段 {field.label} 小于最小值",
                            )
                        if field.max is not None and parsed_value > field.max:
                            raise HTTPException(
                                status_code=422,
                                detail=f"验证方法 {registration.method_label} 的字段 {field.label} 大于最大值",
                            )


@dataclass(frozen=True)
class _RuntimeDownload:
    runtime_hash: str
    archive_sha256: str
    manifest: dict
    data: bytes
    expires_at: float


# Short-lived tokens used by online agents to fetch runtime update archives.
_runtime_download_tokens: dict[str, _RuntimeDownload] = {}
_opencode_model_waiters: dict[str, asyncio.Future] = {}
_opencode_runtime_config_waiters: dict[str, asyncio.Future] = {}
_mcp_probe_waiters: dict[str, asyncio.Future] = {}
_mcp_status_waiters: dict[str, asyncio.Future] = {}
_mcp_reload_waiters: dict[str, asyncio.Future] = {}
_mcp_probe_persist_locks: dict[str, asyncio.Lock] = {}

# In-memory index progress store: scan_id → {status, parsed_files, total_files}
_scan_index_statuses: dict[str, dict] = {}

AGENT_DISCONNECT_ERROR = "Agent 断开连接"
_SERVER_RESTART_ERROR = "Process terminated unexpectedly"
_WEBSOCKET_AGENT_STALE_SECONDS = 120
_AGENT_DISCONNECT_GRACE_SECONDS = 120
_SERVER_STARTED_AT = datetime.now(timezone.utc)
_RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS = 300

_RUNNING_SCAN_STATUSES = (
    ScanItemStatus.PENDING,
    ScanItemStatus.ANALYZING,
    ScanItemStatus.AUDITING,
)


def _purge_expired_runtime_downloads() -> None:
    now = time.time()
    expired = [
        token
        for token, download in _runtime_download_tokens.items()
        if download.expires_at <= now
    ]
    for token in expired:
        _runtime_download_tokens.pop(token, None)


def _touch_agent(agent_id: str) -> None:
    agent = _registered_agents.get(agent_id)
    if agent is not None:
        agent.last_seen = datetime.now(timezone.utc).isoformat()
        if agent.agent_key:
            try:
                get_scan_store().touch_agent_record(agent.agent_key, agent_id, agent.last_seen)
            except (NotImplementedError, AttributeError):
                pass


def _is_agent_online(agent: AgentInfo) -> bool:
    try:
        last = datetime.fromisoformat(agent.last_seen)
        fresh = (datetime.now(timezone.utc) - last).total_seconds() < _WEBSOCKET_AGENT_STALE_SECONDS
    except Exception:
        fresh = False
    if agent.agent_id in _agent_ws:
        return fresh
    return fresh and agent.port > 0


async def _send_agent_json(agent_id: str, payload: dict) -> None:
    ws = _agent_ws.get(agent_id)
    if ws is None:
        raise RuntimeError("Agent WebSocket is not connected")
    lock = _agent_ws_locks.setdefault(agent_id, asyncio.Lock())
    async with lock:
        await ws.send_json(payload)


def _schedule_agent_disconnect_cancel(agent_id: str) -> None:
    old_task = _agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()

    async def _delayed_cancel() -> None:
        try:
            await asyncio.sleep(_AGENT_DISCONNECT_GRACE_SECONDS)
            _mark_agent_scans_cancelled(agent_id)
        except asyncio.CancelledError:
            return
        finally:
            _agent_disconnect_tasks.pop(agent_id, None)

    _agent_disconnect_tasks[agent_id] = asyncio.create_task(_delayed_cancel())


def _is_infrastructure_interruption(scan_status: ScanItemStatus, error_message: str | None) -> bool:
    """Return True for states caused by server/connection loss, not user intent."""
    if scan_status == ScanItemStatus.CANCELLED:
        return error_message == AGENT_DISCONNECT_ERROR
    if scan_status == ScanItemStatus.ERROR:
        return error_message == _SERVER_RESTART_ERROR
    return scan_status in (
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    )


def _best_running_status(scan_total_candidates: int, static_done: bool) -> ScanItemStatus:
    if static_done or scan_total_candidates > 0:
        return ScanItemStatus.AUDITING
    return ScanItemStatus.ANALYZING


def _agent_disconnect_grace_elapsed() -> bool:
    return (
        datetime.now(timezone.utc) - _SERVER_STARTED_AT
    ).total_seconds() >= _AGENT_DISCONNECT_GRACE_SECONDS


def _cancel_scan_if_agent_offline(
    scan_id: str, agent_name: str, status: ScanItemStatus
) -> tuple[bool, bool]:
    """Cancel a running scan once its owning agent is offline past the grace period.

    Returns ``(agent_online, cancelled)``.
    """
    agent_online = is_agent_name_online(agent_name)
    if agent_online or status not in _RUNNING_SCAN_STATUSES:
        return agent_online, False
    if not _agent_disconnect_grace_elapsed():
        return agent_online, False

    store = get_scan_store()
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message=AGENT_DISCONNECT_ERROR,
        clear_current_candidate=True,
    )
    store.mark_fp_reviews_for_scan_error(scan_id, AGENT_DISCONNECT_ERROR)
    _running_scans.pop(scan_id, None)
    _scan_owners.pop(scan_id, None)
    logger.info("Scan %s cancelled because agent %s is offline", scan_id, agent_name)
    return agent_online, True


def reconcile_offline_agent_scan_state(scan_id: str, scan: ScanStatus) -> ScanStatus:
    """Cancel a running scan once its owning agent is offline past the grace period."""
    if not scan.agent_name:
        return scan

    agent_online, cancelled = _cancel_scan_if_agent_offline(
        scan_id, scan.agent_name, scan.status
    )
    scan.agent_online = agent_online
    if cancelled:
        scan.status = ScanItemStatus.CANCELLED
        scan.error_message = AGENT_DISCONNECT_ERROR
        scan.current_candidate = None
    return scan


def reconcile_offline_agent_summary_state(summary: ScanSummary) -> ScanSummary:
    """Summary-level variant of reconcile that avoids loading the full ScanStatus."""
    if not summary.agent_name:
        return summary

    agent_online, cancelled = _cancel_scan_if_agent_offline(
        summary.scan_id, summary.agent_name, summary.status
    )
    summary.agent_online = agent_online
    if cancelled:
        summary.status = ScanItemStatus.CANCELLED
    return summary


def _reattach_active_agent_scans(agent_id: str, agent: AgentInfo, active_scans: list) -> None:
    """Restore server-side running state for scans still running in this agent."""
    if not active_scans:
        return

    store = get_scan_store()
    for item in active_scans:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        if not scan_id:
            continue

        loaded = store.load_scan(scan_id)
        if loaded is None:
            logger.warning("Agent %s reported unknown active scan %s", agent_id, scan_id)
            continue

        scan, meta = loaded
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active scan %s from agent %s: stored agent_name=%s",
                scan_id,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active scan %s from agent %s: owner mismatch",
                scan_id,
                agent.name,
            )
            continue
        if not _is_infrastructure_interruption(scan.status, scan.error_message):
            logger.info(
                "Ignoring active scan %s from agent %s: status=%s error=%r",
                scan_id,
                agent.name,
                scan.status.value,
                scan.error_message,
            )
            continue

        if scan.status not in _RUNNING_SCAN_STATUSES:
            scan.status = _best_running_status(scan.total_candidates, scan.static_analysis_done)
        scan.error_message = None
        scan.current_candidate = None
        scan.agent_name = agent.name
        scan.agent_online = True

        store.update_scan_agent(scan_id, agent_id, agent.name, agent.agent_key)
        store.update_scan_progress(
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        _running_scans[scan_id] = scan
        if meta.user_id:
            _scan_owners[scan_id] = meta.user_id
        logger.info("Reattached active scan %s from agent %s", scan_id, agent_id)


def _reattach_active_fp_reviews(agent_id: str, agent: AgentInfo, active_fp_reviews: list) -> None:
    """Restore server-side running state for FP reviews still running in this agent.

    Re-pointing the scan at the new agent_id also keeps the old connection's
    delayed disconnect-cancel from marking the surviving FP review as error.
    """
    if not active_fp_reviews:
        return

    store = get_scan_store()
    for item in active_fp_reviews:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        review_id = str(item.get("review_id") or "")
        if not scan_id or not review_id:
            continue

        job = store.get_fp_review_job(review_id)
        if job is None or job.scan_id != scan_id:
            logger.warning("Agent %s reported unknown active FP review %s", agent_id, review_id)
            continue

        meta = store.get_scan_meta(scan_id)
        if meta is None:
            continue
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active FP review %s from agent %s: stored agent_name=%s",
                review_id,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active FP review %s from agent %s: owner mismatch",
                review_id,
                agent.name,
            )
            continue

        from backend.api.scan import _is_agent_disconnect_error

        if job.status in (FpReviewStatus.PENDING, FpReviewStatus.RUNNING):
            pass
        elif job.status == FpReviewStatus.ERROR and _is_agent_disconnect_error(job.error_message):
            store.update_fp_review_job(review_id, status="running", error_message="")
        else:
            logger.info(
                "Ignoring active FP review %s from agent %s: status=%s error=%r",
                review_id,
                agent.name,
                job.status.value,
                job.error_message,
            )
            continue

        store.update_scan_agent(scan_id, agent_id, agent.name, agent.agent_key)
        logger.info("Reattached active FP review %s from agent %s", review_id, agent_id)


def _reattach_active_validations(agent_id: str, agent: AgentInfo, active_validations: list) -> list[dict]:
    """Restore server-side ownership for Agent validations and return stop commands for cancelled ones."""
    pending_stops: list[dict] = []
    if not active_validations:
        return pending_stops

    store = get_scan_store()
    for item in active_validations:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        try:
            vuln_index = int(item.get("vuln_index"))
        except (TypeError, ValueError):
            continue
        if not scan_id or vuln_index < 0:
            continue

        meta = store.get_scan_meta(scan_id)
        if meta is None:
            continue
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active validation %s#%s from agent %s: stored agent_name=%s",
                scan_id,
                vuln_index,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active validation %s#%s from agent %s: owner mismatch",
                scan_id,
                vuln_index,
                agent.name,
            )
            continue

        validation = next(
            (entry for entry in store.list_vulnerability_validations(scan_id) if entry.vuln_index == vuln_index),
            None,
        )
        if validation is None:
            logger.warning("Agent %s reported unknown active validation %s#%s", agent_id, scan_id, vuln_index)
            continue

        store.update_scan_agent(scan_id, agent_id, agent.name, agent.agent_key)
        if validation.status == "cancelled":
            pending_stops.append({
                "type": "vulnerability_validation_stop",
                "scan_id": scan_id,
                "vuln_index": vuln_index,
            })
            logger.info("Queued stop for cancelled active validation %s#%s from agent %s", scan_id, vuln_index, agent_id)
            continue
        if validation.running or validation.status in {"pending", "queued", "running"}:
            logger.info("Reattached active validation %s#%s from agent %s", scan_id, vuln_index, agent_id)
        else:
            logger.info(
                "Ignoring active validation %s#%s from agent %s: status=%s",
                scan_id,
                vuln_index,
                agent.name,
                validation.status,
            )
    return pending_stops


def _ensure_running_scan(scan_id: str) -> ScanStatus | None:
    """Load a recoverable scan into memory when events arrive after restart."""
    scan = _running_scans.get(scan_id)
    if scan is not None:
        return scan

    loaded = get_scan_store().load_scan(scan_id)
    if loaded is None:
        return None

    scan, meta = loaded
    if not _is_infrastructure_interruption(scan.status, scan.error_message):
        return None

    if scan.status not in _RUNNING_SCAN_STATUSES:
        scan.status = _best_running_status(scan.total_candidates, scan.static_analysis_done)
        get_scan_store().update_scan_progress(
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        scan.error_message = None
        scan.current_candidate = None

    scan.agent_name = meta.agent_name
    if meta.agent_name:
        scan.agent_online = is_agent_name_online(meta.agent_name)
    _running_scans[scan_id] = scan
    if meta.user_id:
        _scan_owners[scan_id] = meta.user_id
    return scan


def _terminal_opencode_pool_status(status: OpenCodePoolStatus | None) -> OpenCodePoolStatus | None:
    """Clear transient model-pool state while preserving historical counters."""
    if status is None:
        return None
    cleared = status.model_copy(deep=True)
    cleared.global_running = 0
    cleared.global_queued = 0
    cleared.queued_tasks = []
    cleared.planned_tasks = []
    for model in cleared.models:
        model.running = 0
        model.queued = 0
        model.active_tasks = []
        if model.last_status in {"running", "queued"}:
            model.last_status = ""
    return cleared


def _merge_completed_opencode_tasks(
    previous: OpenCodePoolStatus | None,
    current: OpenCodePoolStatus,
) -> OpenCodePoolStatus:
    """Merge scan task history so a later Agent snapshot cannot erase prior attempts."""
    merged = current.model_copy(deep=True)
    ordered: list[dict] = []
    index_by_key: dict[tuple[object, ...], int] = {}

    def task_key(task: dict) -> tuple[object, ...]:
        task_id = str(task.get("task_id") or "")
        if task_id:
            return ("task_id", task_id)
        return (
            "fallback",
            task.get("scope_id"),
            task.get("model_id"),
            task.get("started_at"),
            task.get("finished_at"),
            task.get("task_type"),
        )

    previous_tasks = previous.completed_tasks if previous is not None else []
    for task in [*previous_tasks, *merged.completed_tasks]:
        key = task_key(task)
        item = dict(task)
        if key in index_by_key:
            ordered[index_by_key[key]] = item
        else:
            index_by_key[key] = len(ordered)
            ordered.append(item)
    merged.completed_tasks = ordered
    merged.completed_task_count = len(ordered)
    current_outstanding = max(current.total_tasks - current.completed_task_count, 0)
    merged.total_tasks = max(
        previous.total_tasks if previous is not None else 0,
        len(ordered) + current_outstanding,
    )
    return merged


# ---------------------------------------------------------------------------
# WebSocket — preferred connection method (v2)
# ---------------------------------------------------------------------------


def _mark_agent_scans_cancelled(agent_id: str) -> None:
    """Mark all running scans belonging to this agent as CANCELLED.

    Called when an agent disconnects so the frontend shows the correct state.
    """
    store = get_scan_store()
    cancelled_scan_ids = set(
        store.mark_agent_scans_cancelled(agent_id, AGENT_DISCONNECT_ERROR)
    )
    fp_review_count = store.mark_fp_reviews_for_agent_error(
        agent_id,
        AGENT_DISCONNECT_ERROR,
    )

    for scan_id in list(_running_scans):
        result = store.load_scan(scan_id)
        if result is None:
            continue
        _, meta = result
        if meta.agent_id != agent_id:
            continue
        scan = _running_scans.get(scan_id)
        if scan is not None:
            scan.status = ScanItemStatus.CANCELLED
            scan.error_message = AGENT_DISCONNECT_ERROR
            scan.current_candidate = None
        cancelled_scan_ids.add(scan_id)

    for scan_id in cancelled_scan_ids:
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    if cancelled_scan_ids or fp_review_count:
        logger.info(
            "Agent %s disconnect cancelled %d scan(s) and %d FP review job(s)",
            agent_id,
            len(cancelled_scan_ids),
            fp_review_count,
        )


@router.websocket("/ws")
async def agent_websocket(websocket: WebSocket) -> None:
    """Agent connects here and receives task/stop/resume commands."""
    await websocket.accept()
    agent_id = None
    try:
        msg = await websocket.receive_json()
        if msg.get("type") != "hello":
            await websocket.close(code=4000)
            return

        name = str(msg.get("name") or socket.gethostname()).strip()
        machine_name = str(msg.get("machine_name") or name or socket.gethostname()).strip()
        owner_token = msg.get("owner_token", "")
        agent_id = uuid.uuid4().hex
        ip = websocket.client.host if websocket.client else "unknown"
        now = datetime.now(timezone.utc).isoformat()

        # Resolve owner_token to user_id
        user_id = ""
        if owner_token:
            store = get_scan_store()
            owner = store.get_user_by_agent_token(owner_token)
            if owner:
                user_id = owner.user_id

        reported_config = msg.get("config")
        try:
            initial_config = AgentRemoteConfig(**reported_config) if isinstance(reported_config, dict) else AgentRemoteConfig()
            _validate_managed_config(initial_config)
        except Exception as exc:
            logger.warning("Ignoring invalid config reported by agent %s: %s", name, exc)
            initial_config = AgentRemoteConfig()
        reported_catalog = msg.get("validator_catalog")
        try:
            catalog = (
                AgentValidatorCatalog(**reported_catalog)
                if isinstance(reported_catalog, dict)
                else AgentValidatorCatalog()
            )
        except Exception as exc:
            catalog = AgentValidatorCatalog(errors=[str(exc)])

        store = get_scan_store()
        existing = store.find_agent_record(user_id, ip, machine_name)
        stable_key = str(existing.get("agent_key") or "") if existing else uuid.uuid4().hex
        record = store.upsert_agent_record(
            agent_key=stable_key,
            user_id=user_id,
            ip=ip,
            machine_name=machine_name,
            display_name=name,
            agent_id=agent_id,
            last_seen=now,
            initial_config_json=initial_config.model_dump_json(),
            validator_catalog_json=catalog.model_dump_json(),
        )
        stable_key = str(record["agent_key"])
        cfg = _stored_agent_config(record)
        _agent_configs[stable_key] = cfg

        agent_info = AgentInfo(
            agent_id=agent_id,
            agent_key=stable_key,
            name=name,
            machine_name=machine_name,
            ip=ip,
            port=0,
            last_seen=now,
            user_id=user_id,
            runtime_hash=str(msg.get("runtime_hash") or ""),
            agent_session_id=str(msg.get("agent_session_id") or agent_id),
        )
        _registered_agents[agent_id] = agent_info
        _agent_ws[agent_id] = websocket
        _agent_ws_locks[agent_id] = asyncio.Lock()

        _reattach_active_agent_scans(agent_id, agent_info, msg.get("active_scans") or [])
        _reattach_active_fp_reviews(agent_id, agent_info, msg.get("active_fp_reviews") or [])
        pending_validation_stops = _reattach_active_validations(
            agent_id,
            agent_info,
            msg.get("active_validations") or [],
        )

        await _send_agent_json(agent_id, {
            "type": "welcome",
            "agent_id": agent_id,
            "agent_key": stable_key,
            "config": cfg.model_dump(),
        })
        for command in pending_validation_stops:
            await send_agent_command(agent_id, command)

        logger.info("Agent connected via WebSocket: %s (%s) user=%s", agent_id, name, user_id or "(none)")

        # Keep connection alive; agent sends application-level heartbeats.
        while True:
            incoming = await websocket.receive_json()
            _touch_agent(agent_id)
            if isinstance(incoming, dict) and incoming.get("type") == "heartbeat":
                await _send_agent_json(agent_id, {"type": "heartbeat_ack"})
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "opencode_models_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _opencode_model_waiters.pop(request_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(incoming)
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "opencode_runtime_config_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _opencode_runtime_config_waiters.pop(request_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(incoming)
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "mcp_probe_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _mcp_probe_waiters.pop(request_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(incoming)
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "mcp_status_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _mcp_status_waiters.pop(request_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(incoming)
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "mcp_reload_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _mcp_reload_waiters.pop(request_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(incoming)
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "skill_create_result":
                from backend.api.skills import handle_skill_create_result

                handle_skill_create_result(incoming)
                continue

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Agent WebSocket error for %s: %s", agent_id, e)
    finally:
        if agent_id:
            _schedule_agent_disconnect_cancel(agent_id)
            _agent_ws.pop(agent_id, None)
            _agent_ws_locks.pop(agent_id, None)
            _agent_opencode_pool_latest.pop(agent_id, None)
            _registered_agents.pop(agent_id, None)
            logger.info("Agent disconnected: %s", agent_id)


def is_agent_name_online(agent_name: str) -> bool:
    """Check if any registered agent with the given name has an active WebSocket."""
    for ainfo in _registered_agents.values():
        if ainfo.name == agent_name and _is_agent_online(ainfo):
            return True
    return False


async def send_agent_command(agent_id: str, command: dict) -> bool:
    """Send a JSON command to an agent via its WebSocket. Returns True on success."""
    ws = _agent_ws.get(agent_id)
    if ws is None:
        return False
    try:
        await _send_agent_json(agent_id, command)
        return True
    except Exception as e:
        logger.warning("Failed to send command to agent %s: %s", agent_id, e)
        _schedule_agent_disconnect_cancel(agent_id)
        _agent_ws.pop(agent_id, None)
        _agent_ws_locks.pop(agent_id, None)
        _registered_agents.pop(agent_id, None)
        return False


# ---------------------------------------------------------------------------
# Agent registration / heartbeat (HTTP legacy mode, v1)
# ---------------------------------------------------------------------------

class _AgentRegisterBody(BaseModel):
    port: int
    name: str = ""


class _AgentOpenCodeModelInfo(BaseModel):
    id: str
    model: str
    provider_id: str = ""
    model_id: str = ""
    name: str = ""


class _AgentOpenCodeModelsResponse(BaseModel):
    ok: bool
    message: str = ""
    models: list[_AgentOpenCodeModelInfo] = []


@router.post("/register")
async def agent_register(body: _AgentRegisterBody, request: Request) -> dict:
    """Agent calls this on startup to get an agent_id. (Legacy HTTP mode)"""
    agent_id = uuid.uuid4().hex
    ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).isoformat()
    agent_name = body.name or socket.gethostname()
    _registered_agents[agent_id] = AgentInfo(
        agent_id=agent_id,
        name=agent_name,
        ip=ip,
        port=body.port,
        last_seen=now,
    )
    logger.info("Agent registered (HTTP): %s (%s:%d)", agent_id, ip, body.port)
    cfg = _agent_configs.get(agent_name)
    return {
        "agent_id": agent_id,
        "config": cfg.model_dump(exclude_defaults=True) if cfg else None,
    }


@router.put("/heartbeat/{agent_id}")
async def agent_heartbeat(agent_id: str) -> dict:
    """Agent sends heartbeat every 30s to stay in the online list. (Legacy HTTP mode)"""
    if agent_id in _registered_agents:
        _registered_agents[agent_id].last_seen = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


@router.post("/{agent_id}/opencode-pool")
async def update_agent_opencode_pool(agent_id: str, status: OpenCodePoolStatus) -> dict:
    """Agent pushes its Agent-wide OpenCode model-pool status snapshot."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    status.agent_name = agent.name
    status.agent_session_id = status.agent_session_id or agent.agent_session_id
    _agent_opencode_pool_latest[agent_id] = status
    store = get_scan_store()
    if hasattr(store, "upsert_agent_opencode_pool_status"):
        store.upsert_agent_opencode_pool_status(
            agent_name=agent.agent_key or agent.name,
            user_id=agent.user_id,
            agent_session_id=status.agent_session_id,
            status=status,
        )
    return {"ok": True}


@router.get("/{agent_id}/opencode-pool", response_model=AgentOpenCodePoolStatus)
async def get_agent_opencode_pool(
    agent_id: str,
    current_user: User = Depends(get_current_user),
) -> AgentOpenCodePoolStatus:
    """Return persisted per-model usage for one Agent plus current active tasks."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    online = _is_agent_online(agent)
    store = get_scan_store()
    if hasattr(store, "get_agent_opencode_pool_status"):
        result = store.get_agent_opencode_pool_status(
            agent_name=agent.agent_key or agent.name,
            user_id=agent.user_id,
            agent_id=agent_id,
            agent_session_id=agent.agent_session_id,
            online=online,
        )
    else:
        result = AgentOpenCodePoolStatus(
            agent_id=agent_id,
            agent_name=agent.name,
            agent_session_id=agent.agent_session_id,
            online=online,
        )
    result.agent_name = agent.name
    latest = _agent_opencode_pool_latest.get(agent_id)
    if online and latest is not None and latest.agent_session_id == agent.agent_session_id:
        live_by_model = {model.id: model for model in latest.models}
        for model in result.models:
            live = live_by_model.get(model.id)
            if live is not None:
                # The current session snapshot owns configuration and transient
                # state.  Historical rows only contribute cumulative counters.
                model.model = live.model
                model.use_default_model = live.use_default_model
                model.capability = live.capability
                model.weight = live.weight
                model.max_concurrency = live.max_concurrency
                model.running = live.running
                model.queued = live.queued
                model.available = live.available
                model.enabled = live.enabled
                model.time_windows = live.time_windows
                model.active_tasks = live.active_tasks
                model.last_status = live.last_status
                model.last_started_at = live.last_started_at
                model.last_finished_at = live.last_finished_at
            else:
                # A live report is a complete snapshot.  Models absent from it
                # remain visible for usage history but are no longer usable.
                model.enabled = False
                model.available = False
                model.running = 0
                model.queued = 0
                model.active_tasks = []
        known_ids = {model.id for model in result.models}
        for model in latest.models:
            if model.id not in known_ids:
                result.models.append(model.model_copy(deep=True))
        result.models.sort(key=lambda model: model.id)
        result.global_running = latest.global_running
        result.global_queued = latest.global_queued
        result.queued_tasks = latest.queued_tasks
        result.planned_tasks = latest.planned_tasks
        result.updated_at = latest.updated_at or result.updated_at
    if not online:
        for model in result.models:
            model.available = False
    return result


@router.get("/{agent_id}/opencode/models", response_model=_AgentOpenCodeModelsResponse)
async def get_agent_opencode_models(
    agent_id: str,
    refresh: bool = False,
    current_user: User = Depends(get_current_user),
) -> _AgentOpenCodeModelsResponse:
    """Ask an online Agent for models visible to its OpenCode-compatible serve process."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if agent_id not in _agent_ws:
        raise HTTPException(status_code=400, detail="Agent is offline")

    request_id = uuid.uuid4().hex
    loop = asyncio.get_running_loop()
    waiter = loop.create_future()
    _opencode_model_waiters[request_id] = waiter
    ok = await send_agent_command(agent_id, {
        "type": "opencode_models",
        "request_id": request_id,
        "refresh": refresh,
    })
    if not ok:
        _opencode_model_waiters.pop(request_id, None)
        raise HTTPException(status_code=502, detail="Agent not connected")
    try:
        result = await asyncio.wait_for(waiter, timeout=60.0)
    except asyncio.TimeoutError:
        _opencode_model_waiters.pop(request_id, None)
        raise HTTPException(status_code=504, detail="OpenCode model listing timed out")
    return _AgentOpenCodeModelsResponse(
        ok=bool(result.get("ok")),
        message=str(result.get("message") or ""),
        models=[
            _AgentOpenCodeModelInfo(**item)
            for item in (result.get("models") or [])
            if isinstance(item, dict)
        ],
    )


@router.delete("/{agent_id}")
async def agent_unregister(agent_id: str) -> dict:
    """Agent calls this on graceful shutdown."""
    old_task = _agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()
    _mark_agent_scans_cancelled(agent_id)
    _registered_agents.pop(agent_id, None)
    _agent_ws.pop(agent_id, None)
    _agent_ws_locks.pop(agent_id, None)
    _agent_opencode_pool_latest.pop(agent_id, None)
    logger.info("Agent unregistered: %s", agent_id)
    return {"ok": True}


@router.get("/{agent_id}/config")
async def get_agent_config(
    agent_id: str,
    current_user: User = Depends(get_current_user),
) -> AgentRemoteConfig:
    """Return the server-managed config for an agent (defaults if not yet saved)."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        record = _authorize_agent_record(get_scan_store().get_agent_record(agent_id), current_user)
        return _stored_agent_config(record)
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    record = get_scan_store().get_agent_record(agent.agent_key) if agent.agent_key else None
    return _stored_agent_config(record) if record else _agent_configs.get(agent.name, AgentRemoteConfig())


@router.put("/{agent_id}/config")
async def update_agent_config(
    agent_id: str,
    body: AgentRemoteConfig,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Compatibility route for saving the stable Agent-managed config.

    The path may contain the current session id or the stable agent_key.  The
    stored record is always keyed by IP + machine name identity.
    """
    agent = _registered_agents.get(agent_id)
    agent_key = agent.agent_key if agent is not None else agent_id
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    _validate_managed_config(body, _stored_validator_catalog(record))
    get_scan_store().update_agent_config_record(agent_key, body.model_dump_json())
    _agent_configs[agent_key] = body
    logger.info("Config updated for stable agent %s", agent_key)
    live = _live_agent_for_key(agent_key)
    if live is not None:
        await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True}


@public_router.get("/api/agent-configs/{agent_key}", response_model=AgentRemoteConfig)
async def get_stable_agent_config(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> AgentRemoteConfig:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    return _stored_agent_config(record)


@public_router.put("/api/agent-configs/{agent_key}")
async def update_stable_agent_config(
    agent_key: str,
    body: AgentRemoteConfig,
    current_user: User = Depends(get_current_user),
) -> dict:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    _validate_managed_config(body, _stored_validator_catalog(record))
    get_scan_store().update_agent_config_record(agent_key, body.model_dump_json())
    _agent_configs[agent_key] = body
    live = _live_agent_for_key(agent_key)
    applied = False
    if live is not None:
        applied = await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True, "applied": applied}


_OPENCODE_RUNTIME_STATES = {"active", "reload_pending", "next_task"}


def _opencode_runtime_snapshot(incoming: dict) -> dict:
    content = str(incoming.get("content") or "")
    raw = content.encode("utf-8")
    runtime_state = str(incoming.get("runtime_state") or "next_task")
    if runtime_state not in _OPENCODE_RUNTIME_STATES:
        runtime_state = "next_task"
    return {
        "exists": bool(incoming.get("exists")),
        "content": content,
        "path": str(incoming.get("path") or ""),
        "captured_at": str(incoming.get("captured_at") or datetime.now(timezone.utc).isoformat()),
        "modified_at": str(incoming.get("modified_at") or ""),
        "sha256": hashlib.sha256(raw).hexdigest() if incoming.get("exists") else "",
        "size_bytes": len(raw) if incoming.get("exists") else 0,
        "runtime_state": runtime_state,
        "active_sessions": _nonnegative_int(incoming.get("active_sessions")),
    }


def _opencode_runtime_response(
    *,
    agent_key: str,
    online: bool,
    source: str,
    snapshot: dict | None,
    include_secrets: bool,
    warning: str = "",
) -> AgentOpenCodeRuntimeConfigResponse:
    payload = snapshot or {}
    exists = bool(payload.get("exists"))
    raw_content = str(payload.get("content") or "") if exists else ""
    content = (
        raw_content
        if include_secrets
        else redact_opencode_config_content(raw_content, pretty=True)
    )
    runtime_state = str(payload.get("runtime_state") or "next_task")
    if runtime_state not in _OPENCODE_RUNTIME_STATES:
        runtime_state = "next_task"
    return AgentOpenCodeRuntimeConfigResponse(
        agent_key=agent_key,
        online=online,
        exists=exists,
        source=source,
        content=content,
        redacted=not include_secrets,
        path=str(payload.get("path") or ""),
        captured_at=str(payload.get("captured_at") or ""),
        modified_at=str(payload.get("modified_at") or ""),
        sha256=str(payload.get("sha256") or ""),
        size_bytes=_nonnegative_int(payload.get("size_bytes")),
        runtime_state=runtime_state,
        active_sessions=_nonnegative_int(payload.get("active_sessions")),
        warning=str(warning or "")[:2000],
    )


async def _request_agent_opencode_runtime_config(
    agent_key: str,
) -> tuple[dict | None, str]:
    live = _live_agent_for_key(agent_key)
    if live is None:
        return None, "Agent 已离线"
    request_id = uuid.uuid4().hex
    waiter = asyncio.get_running_loop().create_future()
    _opencode_runtime_config_waiters[request_id] = waiter
    try:
        sent = await send_agent_command(live[0], {
            "type": "opencode_runtime_config",
            "request_id": request_id,
        })
        if not sent:
            return None, "无法向 Agent 发送 OpenCode 配置读取请求"
        incoming = await asyncio.wait_for(waiter, timeout=5.0)
        if not isinstance(incoming, dict):
            return None, "Agent 返回了无效的 OpenCode 配置读取结果"
        return incoming, ""
    except asyncio.TimeoutError:
        return None, "读取 Agent 当前 opencode.json 超时"
    except Exception as exc:
        logger.debug("Unable to query OpenCode runtime config for %s: %s", agent_key, exc)
        return None, "读取 Agent 当前 opencode.json 失败"
    finally:
        _opencode_runtime_config_waiters.pop(request_id, None)


@public_router.get(
    "/api/agent-configs/{agent_key}/opencode-runtime-config",
    response_model=AgentOpenCodeRuntimeConfigResponse,
)
async def get_stable_agent_opencode_runtime_config(
    agent_key: str,
    response: Response,
    refresh: bool = True,
    include_secrets: bool = False,
    current_user: User = Depends(get_current_user),
) -> AgentOpenCodeRuntimeConfigResponse:
    """Return the exact resolved opencode.json, or the latest persisted snapshot."""
    store = get_scan_store()
    record = _authorize_agent_record(store.get_agent_record(agent_key), current_user)
    response.headers["Cache-Control"] = "no-store"
    online = _live_agent_for_key(agent_key) is not None
    warning = ""

    if refresh and online:
        incoming, warning = await _request_agent_opencode_runtime_config(agent_key)
        if incoming is not None and bool(incoming.get("ok")):
            snapshot = _opencode_runtime_snapshot(incoming)
            if snapshot["exists"]:
                store.update_agent_opencode_runtime_config_record(
                    agent_key,
                    json.dumps(snapshot, ensure_ascii=False),
                )
            else:
                warning = str(incoming.get("message") or "OpenCode Serve 尚未生成 opencode.json")
            return _opencode_runtime_response(
                agent_key=agent_key,
                online=True,
                source="live",
                snapshot=snapshot,
                include_secrets=include_secrets,
                warning=warning,
            )
        if incoming is not None:
            warning = str(incoming.get("message") or "读取 Agent 当前 opencode.json 失败")

    snapshot = _stored_opencode_runtime_config(record)
    if snapshot is not None:
        if not warning and not online:
            warning = "Agent 已离线，当前显示最近一次成功读取的历史快照"
        elif warning:
            warning = f"{warning}；当前显示最近一次成功读取的历史快照"
        return _opencode_runtime_response(
            agent_key=agent_key,
            online=online,
            source="snapshot",
            snapshot=snapshot,
            include_secrets=include_secrets,
            warning=warning,
        )

    if not warning:
        warning = "尚未保存过该 Agent 的 opencode.json 快照"
    return _opencode_runtime_response(
        agent_key=agent_key,
        online=online,
        source="none",
        snapshot=None,
        include_secrets=include_secrets,
        warning=warning,
    )


async def _persist_mcp_probe(agent_key: str, result: AgentMcpProbeResult) -> None:
    lock = _mcp_probe_persist_locks.setdefault(agent_key, asyncio.Lock())
    async with lock:
        store = get_scan_store()
        record = store.get_agent_record(agent_key)
        payload: dict = {}
        if record is not None:
            try:
                parsed = json.loads(str(record.get("mcp_probe_json") or "{}"))
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                pass
        payload[result.target] = result.model_dump(mode="json")
        store.update_agent_mcp_probe_record(
            agent_key,
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
        )


_MCP_RUNTIME_STATES = {
    "connected",
    "applying",
    "failed",
    "needs_auth",
    "needs_client_registration",
    "disabled",
    "next_session",
    "offline",
    "unknown",
}


def _agent_mcp_runtime(
    config: AgentMcpConfig,
    raw: object,
    *,
    online: bool,
) -> AgentMcpRuntimeStatus:
    expected = _mcp_config_fingerprint(config)
    if not online:
        return AgentMcpRuntimeStatus(
            state="offline",
            config_fingerprint=expected,
        )
    if not isinstance(raw, dict):
        return AgentMcpRuntimeStatus(
            state="unknown",
            config_fingerprint=expected,
            error="未能读取 Agent 上的 MCP 运行状态",
        )
    fingerprint = str(raw.get("config_fingerprint") or "")
    state = str(raw.get("state") or "unknown")
    if fingerprint != expected:
        state = "applying"
    elif state not in _MCP_RUNTIME_STATES:
        state = "unknown"
    return AgentMcpRuntimeStatus(
        state=state,
        config_fingerprint=fingerprint or expected,
        updated_at=str(raw.get("updated_at") or ""),
        error=str(raw.get("error") or "")[:2000],
        loaded_directories=_nonnegative_int(raw.get("loaded_directories")),
        total_directories=_nonnegative_int(raw.get("total_directories")),
    )


async def _request_agent_mcp_runtime(agent_key: str) -> dict[str, object] | None:
    live = _live_agent_for_key(agent_key)
    if live is None:
        return None
    request_id = uuid.uuid4().hex
    waiter = asyncio.get_running_loop().create_future()
    _mcp_status_waiters[request_id] = waiter
    try:
        sent = await send_agent_command(live[0], {
            "type": "mcp_status",
            "request_id": request_id,
        })
        if not sent:
            return None
        incoming = await asyncio.wait_for(waiter, timeout=5.0)
        targets = incoming.get("targets") if isinstance(incoming, dict) else None
        return targets if isinstance(targets, dict) else None
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        logger.debug("Unable to query live MCP runtime for %s: %s", agent_key, exc)
        return None
    finally:
        _mcp_status_waiters.pop(request_id, None)


@public_router.get(
    "/api/agent-configs/{agent_key}/mcp-status",
    response_model=AgentMcpStatusResponse,
)
async def get_stable_agent_mcp_status(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> AgentMcpStatusResponse:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    config = _stored_agent_config(record)
    probes = _stored_mcp_probes(record)
    online = _live_agent_for_key(agent_key) is not None
    live_runtime = await _request_agent_mcp_runtime(agent_key) if online else None
    return AgentMcpStatusResponse(
        agent_key=agent_key,
        online=online,
        code_graph=_mcp_target_status(
            config.code_graph,
            probes.get("code_graph"),
            _agent_mcp_runtime(
                config.code_graph,
                live_runtime.get("code_graph") if live_runtime else None,
                online=online,
            ),
        ),
        product_info=_mcp_target_status(
            config.product_info,
            probes.get("product_info"),
            _agent_mcp_runtime(
                config.product_info,
                live_runtime.get("product_info") if live_runtime else None,
                online=online,
            ),
        ),
    )


@public_router.post("/api/agent-configs/{agent_key}/mcp-reload/{target}")
async def reload_stable_agent_mcp(
    agent_key: str,
    target: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    config = _stored_agent_config(record)
    mcp_config = _mcp_target_config(config, target)
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = _live_agent_for_key(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 离线，无法重新加载 MCP")
    request_id = uuid.uuid4().hex
    waiter = asyncio.get_running_loop().create_future()
    _mcp_reload_waiters[request_id] = waiter
    try:
        sent = await send_agent_command(live[0], {
            "type": "mcp_reload",
            "request_id": request_id,
            "target": target,
        })
        if not sent:
            raise HTTPException(status_code=502, detail="Agent 连接已断开")
        incoming = await asyncio.wait_for(waiter, timeout=5.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="等待 Agent 接受 MCP 重载请求超时")
    finally:
        _mcp_reload_waiters.pop(request_id, None)
    if not bool(incoming.get("ok")):
        raise HTTPException(status_code=422, detail=str(incoming.get("error") or "MCP 重载失败"))
    return {"ok": True}


@public_router.post(
    "/api/agent-configs/{agent_key}/mcp-probe/{target}",
    response_model=AgentMcpProbeResult,
)
async def probe_stable_agent_mcp(
    agent_key: str,
    target: str,
    current_user: User = Depends(get_current_user),
) -> AgentMcpProbeResult:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    config = _stored_agent_config(record)
    mcp_config = _mcp_target_config(config, target)
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = _live_agent_for_key(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 离线，无法执行 MCP 检测")

    request_id = uuid.uuid4().hex
    waiter = asyncio.get_running_loop().create_future()
    _mcp_probe_waiters[request_id] = waiter
    sent = await send_agent_command(live[0], {
        "type": "mcp_probe",
        "request_id": request_id,
        "target": target,
        "mcp_config": mcp_config.model_dump(mode="json"),
    })
    if not sent:
        _mcp_probe_waiters.pop(request_id, None)
        raise HTTPException(status_code=502, detail="Agent 连接已断开")

    wait_seconds = min(30, max(1, mcp_config.timeout_seconds)) + 5
    try:
        incoming = await asyncio.wait_for(waiter, timeout=wait_seconds)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"等待 Agent MCP 检测结果超时（{wait_seconds} 秒）",
        )
    finally:
        _mcp_probe_waiters.pop(request_id, None)

    tool_names = sorted({
        str(item)[:200]
        for item in (incoming.get("tool_names") or [])
        if str(item).strip()
    })[:200]
    runtime_state = str(incoming.get("runtime_state") or "next_task")
    if runtime_state not in {"active", "reload_pending", "next_task"}:
        runtime_state = "next_task"
    result = AgentMcpProbeResult(
        target=target,
        config_fingerprint=_mcp_config_fingerprint(mcp_config),
        success=bool(incoming.get("success")),
        checked_at=datetime.now(timezone.utc).isoformat(),
        transport=mcp_config.transport,
        protocol=(
            str(incoming.get("protocol") or "")
            if str(incoming.get("protocol") or "") in {"stdio", "streamable_http", "sse"}
            else ""
        ),
        tool_names=tool_names,
        tool_count=len(tool_names),
        duration_ms=_nonnegative_int(incoming.get("duration_ms")),
        error=str(incoming.get("error") or "")[:2000],
        runtime_state=runtime_state,
        active_sessions=_nonnegative_int(incoming.get("active_sessions")),
    )
    await _persist_mcp_probe(agent_key, result)
    return result


@public_router.get("/api/agent-configs/{agent_key}/validator-catalog", response_model=AgentValidatorCatalog)
async def get_stable_agent_validator_catalog(
    agent_key: str,
    product: str = "",
    current_user: User = Depends(get_current_user),
) -> AgentValidatorCatalog:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    catalog = _stored_validator_catalog(record)
    if not product.strip():
        return catalog
    return catalog.model_copy(update={
        "registrations": [item for item in catalog.registrations if item.product == product.strip()],
    })


@public_router.get("/api/agent-configs/{agent_key}/validation-environments")
async def get_stable_agent_validation_environments(
    agent_key: str,
    product: str = "",
    current_user: User = Depends(get_current_user),
) -> dict:
    record = _authorize_agent_record(get_scan_store().get_agent_record(agent_key), current_user)
    catalog = _stored_validator_catalog(record)
    selected_product = product.strip()
    environments = sorted({
        item.environment
        for item in catalog.registrations
        if not selected_product or item.product == selected_product
    })
    return {"validation_environments": environments}


@router.get("/agents")
async def list_agents_prefixed(
    current_user: User = Depends(get_current_user),
) -> list:
    """Return all registered agents with online status (alias for /api/agents)."""
    return await list_agents(current_user)


@public_router.get("/api/agents")
async def list_agents(current_user: User = Depends(get_current_user)) -> list:
    """Return agents with online status. Admin sees all; users see only their own.

    WebSocket agents: online = WebSocket connection is active.
    Legacy HTTP agents: online = last heartbeat < 90 seconds ago.
    """
    store = get_scan_store()
    records = store.list_agent_records(None if current_user.role == "admin" else current_user.user_id)
    result = []
    known_keys: set[str] = set()
    for record in records:
        agent_key = str(record.get("agent_key") or "")
        live = _live_agent_for_key(agent_key)
        agent = live[1] if live else None
        known_keys.add(agent_key)
        result.append({
            "agent_id": live[0] if live else str(record.get("last_agent_id") or ""),
            "agent_key": agent_key,
            "name": agent.name if agent else str(record.get("display_name") or ""),
            "machine_name": agent.machine_name if agent else str(record.get("machine_name") or ""),
            "ip": agent.ip if agent else str(record.get("ip") or ""),
            "port": agent.port if agent else 0,
            "last_seen": agent.last_seen if agent else str(record.get("last_seen") or ""),
            "user_id": str(record.get("user_id") or ""),
            "runtime_hash": agent.runtime_hash if agent else "",
            "agent_session_id": agent.agent_session_id if agent else "",
            "online": bool(agent and _is_agent_online(agent)),
        })
    # Keep legacy HTTP agents visible until they migrate to the stable catalog.
    for agent in _registered_agents.values():
        if agent.agent_key in known_keys:
            continue
        if current_user.role != "admin" and agent.user_id != current_user.user_id:
            continue
        result.append({**agent.model_dump(), "online": _is_agent_online(agent)})
    return result


# ---------------------------------------------------------------------------
# Scan events / results (called by agent during scan execution)
# ---------------------------------------------------------------------------


@router.post("/scan/{scan_id}/event")
async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    """Agent pushes a progress event. Updates in-memory scan state and DB."""
    store = get_scan_store()
    store.add_event(scan_id, event)

    scan = _ensure_running_scan(scan_id)
    if scan is None:
        return {"ok": True}

    scan.events.append(event)
    if len(scan.events) > 500:
        scan.events = scan.events[-500:]

    progress_kwargs: dict = {}

    if event.phase == "init":
        if scan.status == ScanItemStatus.PENDING:
            progress_kwargs["status"] = ScanItemStatus.PENDING

    elif event.phase == "static_analysis":
        if scan.status in (ScanItemStatus.PENDING,):
            scan.status = ScanItemStatus.ANALYZING
            progress_kwargs["status"] = ScanItemStatus.ANALYZING
        if event.candidate_index is not None:
            scan.total_candidates = event.candidate_index
            progress_kwargs["total_candidates"] = event.candidate_index

    elif event.phase == "auditing":
        if scan.status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING):
            scan.status = ScanItemStatus.AUDITING
            progress_kwargs["status"] = ScanItemStatus.AUDITING
        if not scan.static_analysis_done:
            scan.static_analysis_done = True
            progress_kwargs["static_analysis_done"] = True

    if progress_kwargs:
        store.update_scan_progress(scan_id, **progress_kwargs)

    from backend.sse import publish
    publish(scan_id, "scan_status", {
        "status": scan.status if scan else None,
        "progress": scan.progress if scan else None,
        "total_candidates": scan.total_candidates if scan else None,
        "processed_candidates": scan.processed_candidates if scan else None,
        "static_total_files": scan.static_total_files if scan else None,
        "static_scanned_files": scan.static_scanned_files if scan else None,
        "static_analysis_done": scan.static_analysis_done if scan else None,
    })
    publish(scan_id, "scan_event", {"event": event.model_dump()})

    return {"ok": True}


@router.post("/scan/{scan_id}/vulnerability")
async def agent_report_vulnerability(scan_id: str, vuln: Vulnerability) -> dict:
    """Agent pushes a single vulnerability result immediately after auditing it."""
    store = get_scan_store()
    vuln_index = store.upsert_incomplete_vulnerability(scan_id, vuln)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        if vuln_index < len(scan.vulnerabilities):
            scan.vulnerabilities[vuln_index] = vuln
        else:
            scan.vulnerabilities.append(vuln)

    from backend.sse import publish
    publish(scan_id, "scan_vulnerability", {
        "index": vuln_index,
        "vulnerability": vuln.model_dump(),
    })

    logger.debug(
        "Vulnerability reported for scan %s: %s %s:%d confirmed=%s",
        scan_id, vuln.vuln_type, vuln.file, vuln.line, vuln.confirmed,
    )
    report_markdown = ""
    fp_review_info = None
    if vuln.confirmed or vuln.ai_verdict == "confirmed":
        try:
            from backend.api.scan import (
                _ensure_fp_review_job_for_scan,
                _scan_fp_result_map,
                _vuln_report_markdown,
            )

            report_markdown = _vuln_report_markdown(
                vuln_index,
                vuln,
                _scan_fp_result_map(scan_id).get(vuln_index),
            )
            if get_config().fp_review.auto_on_complete:
                ensured = _ensure_fp_review_job_for_scan(
                    scan_id,
                    scan,
                    allow_cancelled=False,
                    publish_started=True,
                    require_unresolved=True,
                )
                if ensured is not None and not ensured.get("cancelled") and not ensured.get("no_unresolved"):
                    latest_results = ensured.get("latest_results") or {}
                    fp_review_info = {
                        "review_id": ensured["review_id"],
                        "vuln_index": vuln_index,
                        "queued": vuln_index not in latest_results,
                        "total": ensured["total"],
                        "processed": ensured["processed"],
                    }
        except Exception as exc:
            logger.warning(
                "Failed to render vulnerability report for validation scan=%s idx=%s: %s",
                scan_id,
                vuln_index,
                exc,
            )
    response = {"ok": True, "index": vuln_index, "report_markdown": report_markdown}
    if fp_review_info is not None:
        response["fp_review"] = fp_review_info
    return response


@router.post("/scan/{scan_id}/candidates")
async def agent_report_scan_candidates(scan_id: str, body: AgentScanCandidates) -> dict:
    """Agent pushes the final static-analysis candidate list for a scan."""
    static_candidates = []
    for candidate in body.candidates:
        metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
        is_threat_placeholder = (
            str(candidate.vuln_type or "").strip().lower() == "threat_audit"
            or str(metadata.get("source") or "").strip().lower() == "threat_analysis"
        )
        if not is_threat_placeholder:
            static_candidates.append(candidate)
    dropped = len(body.candidates) - len(static_candidates)
    if dropped:
        logger.warning(
            "Dropped %d threat-audit placeholder(s) from static candidates for scan %s",
            dropped,
            scan_id,
        )

    store = get_scan_store()
    candidates = store.replace_scan_candidates(scan_id, static_candidates)
    total = len(candidates)
    store.update_scan_progress(scan_id, total_candidates=total)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.candidates = candidates
        scan.total_candidates = total

    from backend.sse import publish
    publish(scan_id, "scan_candidates", {
        "candidates": [candidate.model_dump() for candidate in candidates],
    })
    publish(scan_id, "scan_status", {
        "status": scan.status if scan else None,
        "progress": scan.progress if scan else None,
        "total_candidates": total,
        "processed_candidates": scan.processed_candidates if scan else None,
        "static_total_files": scan.static_total_files if scan else None,
        "static_scanned_files": scan.static_scanned_files if scan else None,
        "static_analysis_done": scan.static_analysis_done if scan else None,
    })
    logger.info("Stored %d static candidate(s) for scan %s", total, scan_id)
    return {"ok": True, "count": total}


@router.post("/scan/{scan_id}/validation")
async def agent_report_vulnerability_validation(
    scan_id: str,
    body: AgentVulnerabilityValidationUpdate,
) -> dict:
    """Agent pushes local validation script progress/results for one vulnerability."""
    validation = VulnerabilityValidation(
        scan_id=scan_id,
        vuln_index=body.vuln_index,
        status=body.status,
        running=body.running,
        product=body.product,
        validation_environment=body.validation_environment,
        validator_name=body.validator_name,
        validation_success=body.validation_success,
        is_problem=body.is_problem,
        requires_human_intervention=body.requires_human_intervention,
        validation_code=body.validation_code,
        validation_output=body.validation_output,
        intermediate_output=body.intermediate_output,
        output_sections=body.output_sections,
        final_output=body.final_output,
        artifacts=body.artifacts,
        started_at=body.started_at,
        finished_at=body.finished_at,
        updated_at=body.updated_at,
    )
    store = get_scan_store()
    validation = store.upsert_vulnerability_validation(scan_id, validation)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        existing = next(
            (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
            None,
        )
        if existing is None:
            scan.validations.append(validation)
            scan.validations.sort(key=lambda item: item.vuln_index)
        else:
            scan.validations[existing] = validation

    from backend.sse import publish
    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })
    return {"ok": True}


@router.post("/scan/{scan_id}/git_history")
async def agent_push_git_history(scan_id: str, body: AgentGitHistory) -> dict:
    """Agent uploads the mined git-history security problem patterns for a scan."""
    store = get_scan_store()
    store.replace_git_history_patterns(scan_id, body.patterns)
    from backend.sse import publish
    publish(scan_id, "git_history", {"count": len(body.patterns)})
    logger.info("Git history patterns stored for scan %s: %d", scan_id, len(body.patterns))
    return {"ok": True}


@router.get("/scan/{scan_id}/git_history")
async def agent_get_git_history(scan_id: str) -> list[HistoryPattern]:
    """Return the mined git-history patterns for a scan (used by FP review)."""
    return get_scan_store().get_git_history_patterns(scan_id)


@router.post("/scan/{scan_id}/threat-analysis")
async def agent_push_threat_analysis(scan_id: str, body: dict) -> dict:
    """Agent uploads an opaque bundle of threat-analysis artifacts."""
    try:
        analysis = parse_threat_analysis_data(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat analysis JSON: {exc}") from exc

    store = get_scan_store()
    analysis = store.replace_threat_analysis(scan_id, analysis)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.threat_analysis = analysis

    from backend.sse import publish
    publish(scan_id, "threat_analysis", {"analysis": analysis})
    artifact_count = len(analysis.get("artifacts") or {})
    logger.info(
        "Threat analysis stored for scan %s: %d artifact(s)",
        scan_id,
        artifact_count,
    )
    return {"ok": True, "artifact_count": artifact_count}


@router.get("/scan/{scan_id}/threat-analysis", response_model=dict)
async def agent_get_threat_analysis(scan_id: str) -> dict:
    """Return the stored threat-analysis artifact bundle."""
    analysis = get_scan_store().get_threat_analysis(scan_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat analysis found for this scan")
    return analysis


@router.post("/scan/{scan_id}/threat-audit-task")
async def agent_upsert_threat_audit_task(scan_id: str, body: dict) -> dict:
    """Agent creates or updates one threat-analysis-derived audit task."""
    try:
        task = ThreatAuditTask(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat audit task: {exc}") from exc

    store = get_scan_store()
    task = store.upsert_threat_audit_task(scan_id, task)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        tasks = [item for item in scan.threat_audit_tasks if item.task_id != task.task_id]
        tasks.append(task)
        tasks.sort(key=lambda item: (item.created_at, item.task_id))
        scan.threat_audit_tasks = tasks

    from backend.sse import publish
    publish(scan_id, "threat_audit_task", {"task": task.model_dump()})
    return {"ok": True, "task": task.model_dump()}


@router.get("/scan/{scan_id}/threat-audit-tasks", response_model=list[ThreatAuditTask])
async def agent_list_threat_audit_tasks(scan_id: str) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for scan resume."""
    return get_scan_store().list_threat_audit_tasks(scan_id)


@router.post("/scan/{scan_id}/skill-report")
async def agent_replace_skill_reports(scan_id: str, body: dict) -> dict:
    """Agent replaces Markdown reports generated by one report-mode SKILL."""
    checker_name = str(body.get("checker_name") or "").strip()
    if not checker_name:
        raise HTTPException(status_code=400, detail="checker_name is required")
    raw_reports = body.get("reports") or []
    if not isinstance(raw_reports, list):
        raise HTTPException(status_code=400, detail="reports must be a list")

    reports = [
        SkillReport(
            scan_id=scan_id,
            checker_name=checker_name,
            filename=str(item.get("filename") or ""),
            title=str(item.get("title") or ""),
            content=str(item.get("content") or ""),
            created_at=str(item.get("created_at") or datetime.now(timezone.utc).isoformat()),
            output_source=item.get("output_source") or {},
        )
        for item in raw_reports
        if isinstance(item, dict) and str(item.get("filename") or "").strip()
    ]
    store = get_scan_store()
    store.replace_skill_reports(scan_id, checker_name, reports)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.skill_reports = [
            report for report in scan.skill_reports
            if report.checker_name != checker_name
        ] + reports

    logger.info(
        "Skill reports replaced for scan %s checker %s: %d report(s)",
        scan_id, checker_name, len(reports),
    )
    return {"ok": True, "count": len(reports)}


@router.post("/scan/{scan_id}/finish")
async def agent_finish_scan(scan_id: str, body: AgentScanFinish, request: Request) -> dict:
    """Agent pushes final results when the scan completes, errors, or is cancelled."""
    store = get_scan_store()

    status_map = {
        "complete": ScanItemStatus.COMPLETE,
        "cancelled": ScanItemStatus.CANCELLED,
        "error": ScanItemStatus.ERROR,
    }
    final_status = status_map.get(body.status, ScanItemStatus.ERROR)

    loaded = store.load_scan(scan_id)
    existing_scan = loaded[0] if loaded is not None else None
    final_total = body.total_candidates
    final_processed = body.processed_candidates
    if final_status != ScanItemStatus.COMPLETE and existing_scan is not None:
        if final_total == 0 and existing_scan.total_candidates > 0:
            final_total = existing_scan.total_candidates
        if (
            body.total_candidates == 0
            and body.processed_candidates == 0
            and existing_scan.processed_candidates > 0
        ):
            final_processed = existing_scan.processed_candidates

    existing_count = store.count_vulnerabilities(scan_id)
    if body.vulnerabilities and existing_count == 0:
        for vuln in body.vulnerabilities:
            store.add_vulnerability(scan_id, vuln)

    store.update_scan_progress(
        scan_id,
        status=final_status,
        progress=1.0 if final_status == ScanItemStatus.COMPLETE else None,
        total_candidates=final_total,
        processed_candidates=final_processed,
        error_message=body.error_message,
        clear_current_candidate=True,
    )

    scan = _running_scans.get(scan_id)
    final_pool = _terminal_opencode_pool_status(
        scan.opencode_pool if scan is not None else (existing_scan.opencode_pool if existing_scan is not None else None)
    )
    if final_pool is not None:
        store.update_opencode_pool_status(scan_id, final_pool)
    if scan is not None:
        scan.status = final_status
        if body.vulnerabilities and existing_count == 0:
            scan.vulnerabilities = body.vulnerabilities
        scan.total_candidates = final_total
        scan.processed_candidates = final_processed
        scan.opencode_pool = final_pool
        if body.error_message:
            scan.error_message = body.error_message
        if final_status == ScanItemStatus.COMPLETE:
            scan.progress = 1.0
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    from backend.sse import publish
    publish(scan_id, "scan_status", {
        "status": final_status,
        "progress": 1.0 if final_status == ScanItemStatus.COMPLETE else (existing_scan.progress if existing_scan else None),
        "total_candidates": final_total,
        "processed_candidates": final_processed,
        "opencode_pool": final_pool.model_dump() if final_pool is not None else None,
    })
    publish(scan_id, "scan_finish", {
        "status": body.status,
        "error_message": body.error_message,
    })

    confirmed = sum(1 for v in body.vulnerabilities if v.confirmed)
    if confirmed == 0:
        confirmed = sum(1 for v in store.get_vulnerabilities(scan_id) if v.confirmed)
    logger.info(
        "Agent finished scan %s: %s — %d confirmed / %d candidates",
        scan_id, body.status, confirmed, final_total,
    )

    # 扫描完成且存在已确认漏洞时，自动触发去误报（无需手动点击）。
    # 仅在尚无去误报任务时触发，避免 resume / 重复 finish 造成重复复核。
    if (
        final_status == ScanItemStatus.COMPLETE
        and confirmed > 0
        and get_config().fp_review.auto_on_complete
        and store.get_fp_review_by_scan(scan_id) is None
    ):
        from backend.api.scan import _start_fp_review, _server_url_from_request
        try:
            started = await _start_fp_review(
                scan_id, _server_url_from_request(request), raise_on_error=False
            )
            if started is not None:
                logger.info("Auto FP review started for scan %s after completion", scan_id)
        except Exception as exc:  # 自动触发失败不应影响扫描完成处理
            logger.warning("Auto FP review for scan %s failed: %s", scan_id, exc)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Processed keys (resume support)
# ---------------------------------------------------------------------------


@router.post("/scan/{scan_id}/processed")
async def agent_report_processed(scan_id: str, body: dict) -> dict:
    """Agent reports a successfully processed candidate key after each audit."""
    store = get_scan_store()
    try:
        key = (
            str(body["file"]),
            int(body["line"]),
            str(body["function"]),
            str(body["vuln_type"]),
        )
        store.add_processed_key(scan_id, key)
        processed = len(store.get_processed_keys(scan_id))
        loaded = store.load_scan(scan_id)
        if loaded is not None:
            scan, _meta = loaded
            processed = max(processed, scan.processed_candidates)
            progress = processed / scan.total_candidates if scan.total_candidates > 0 else None
            store.update_scan_progress(
                scan_id,
                processed_candidates=processed,
                progress=progress,
            )
            live = _running_scans.get(scan_id)
            if live is not None:
                live.processed_candidates = processed
                if progress is not None:
                    live.progress = progress
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid processed key: {e}")
    return {"ok": True}


@router.get("/scan/{scan_id}/processed")
async def agent_get_processed(scan_id: str) -> list:
    """Return all processed candidate keys for a scan (used by agent on resume)."""
    store = get_scan_store()
    keys = store.get_processed_keys(scan_id)
    return [
        {"file": f, "line": line, "function": fn, "vuln_type": vt}
        for f, line, fn, vt in keys
    ]


# ---------------------------------------------------------------------------
# Index progress (pushed by agent during code indexing phase)
# ---------------------------------------------------------------------------


class _IndexStatusBody(BaseModel):
    status: str           # "parsing" | "done" | "error"
    parsed_files: int = 0
    total_files: int = 0
    stage: str = ""
    stage_current: int = 0
    stage_total: int = 0
    stats: dict[str, int] | None = None


def _index_file_counts(body: _IndexStatusBody) -> tuple[int, int] | None:
    """Return real source-file index counts, excluding sub-stage progress."""
    if body.status == "done":
        stats_files = int((body.stats or {}).get("files") or 0)
        total = body.total_files or stats_files
        if total <= 0:
            return None
        parsed = body.parsed_files or total
        return parsed, total
    if body.status == "parsing" and body.total_files > 0:
        return body.parsed_files, body.total_files
    return None


@router.post("/scan/{scan_id}/index-status")
async def agent_push_index_status(scan_id: str, body: _IndexStatusBody) -> dict:
    """Agent pushes code-indexing progress. Stored in memory for frontend polling."""
    payload = body.model_dump(exclude_none=True)
    _scan_index_statuses[scan_id] = payload

    # Mirror counts into the running scan so the frontend can read them via the
    # existing scan-status polling endpoint (scan.static_total_files, etc.)
    file_counts = _index_file_counts(body)
    store = get_scan_store()
    scan = _ensure_running_scan(scan_id)
    if file_counts is not None:
        parsed_files, total_files = file_counts
        if scan is not None:
            scan.static_total_files = total_files
            scan.static_scanned_files = parsed_files
        store.update_scan_progress(
            scan_id,
            static_total_files=total_files,
            static_scanned_files=parsed_files,
        )

    from backend.sse import publish
    publish(scan_id, "index_status", payload)
    if scan is not None and file_counts is not None:
        publish(scan_id, "scan_status", {
            "status": scan.status,
            "progress": scan.progress,
            "total_candidates": scan.total_candidates,
            "processed_candidates": scan.processed_candidates,
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
            "static_analysis_done": scan.static_analysis_done,
        })

    return {"ok": True}


# ---------------------------------------------------------------------------
# Static analysis progress (pushed by agent during static analysis phase)
# ---------------------------------------------------------------------------


class _StaticProgressBody(BaseModel):
    scanned: int = 0
    total: int = 0
    done: bool = False


@router.post("/scan/{scan_id}/static-progress")
async def agent_push_static_progress(scan_id: str, body: _StaticProgressBody) -> dict:
    """Agent pushes static analysis progress (function/file counts)."""
    store = get_scan_store()
    scan = _ensure_running_scan(scan_id)
    loaded = store.load_scan(scan_id)
    stored_scan = loaded[0] if loaded is not None else None
    current_status = scan.status if scan is not None else (stored_scan.status if stored_scan is not None else None)
    effective_done = body.done or (scan.static_analysis_done if scan is not None else False)
    if not effective_done and stored_scan is not None:
        effective_done = stored_scan.static_analysis_done

    status = None
    if body.done and current_status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING):
        status = ScanItemStatus.AUDITING
    elif not body.done and current_status == ScanItemStatus.PENDING:
        status = ScanItemStatus.ANALYZING

    reported_total = body.total
    reported_scanned = body.scanned
    if body.done and body.total == 0 and body.scanned == 0:
        existing_total = (scan.static_total_files if scan is not None else 0) or (stored_scan.static_total_files if stored_scan is not None else 0)
        existing_scanned = (scan.static_scanned_files if scan is not None else 0) or (stored_scan.static_scanned_files if stored_scan is not None else 0)
        reported_total = existing_total
        reported_scanned = existing_scanned or existing_total

    if scan is not None:
        scan.static_total_files = reported_total
        scan.static_scanned_files = reported_scanned
        scan.static_analysis_done = effective_done
        if status is not None:
            scan.status = status

    store.update_scan_progress(
        scan_id,
        status=status,
        static_total_files=reported_total,
        static_scanned_files=reported_scanned,
        static_analysis_done=effective_done,
    )
    if scan is not None:
        from backend.sse import publish
        publish(scan_id, "scan_status", {
            "status": scan.status,
            "progress": scan.progress,
            "total_candidates": scan.total_candidates,
            "processed_candidates": scan.processed_candidates,
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
            "static_analysis_done": scan.static_analysis_done,
        })
    return {"ok": True}


@router.post("/scan/{scan_id}/opencode-pool")
async def agent_push_opencode_pool(scan_id: str, body: OpenCodePoolStatus) -> dict:
    """Agent pushes the latest OpenCode model-pool status for one scan."""
    store = get_scan_store()
    loaded = store.load_scan(scan_id)
    previous_pool = loaded[0].opencode_pool if loaded is not None else None
    body = _merge_completed_opencode_tasks(previous_pool, body)
    terminal = loaded is not None and loaded[0].status not in _RUNNING_SCAN_STATUSES
    status = _terminal_opencode_pool_status(body) if terminal else body
    store.update_opencode_pool_status(scan_id, status)

    scan = None if terminal else _ensure_running_scan(scan_id)
    if scan is not None:
        scan.opencode_pool = status

    from backend.sse import publish
    publish(scan_id, "scan_status", {
        "status": scan.status if scan else None,
        "progress": scan.progress if scan else None,
        "total_candidates": scan.total_candidates if scan else None,
        "processed_candidates": scan.processed_candidates if scan else None,
        "static_total_files": scan.static_total_files if scan else None,
        "static_scanned_files": scan.static_scanned_files if scan else None,
        "static_analysis_done": scan.static_analysis_done if scan else None,
        "opencode_pool": status.model_dump(),
    })
    return {"ok": True}


@router.get("/scan/{scan_id}/index-status")
async def agent_get_index_status(scan_id: str) -> dict:
    """Return the current code-indexing progress for an agent scan."""
    status = _scan_index_statuses.get(scan_id)
    if status is None:
        return {"status": "not_started"}
    return status


# ---------------------------------------------------------------------------
# Feedback export
# ---------------------------------------------------------------------------


@router.get("/feedback")
async def agent_get_feedback(vuln_types: Optional[str] = None) -> list:
    """Return feedback entries for the agent to enrich SKILLs."""
    store = get_scan_store()
    if vuln_types:
        names = [v.strip() for v in vuln_types.split(",") if v.strip()]
        entries = []
        for name in names:
            entries.extend(store.list_feedback(vuln_type=name))
    else:
        entries = store.list_feedback()
    return [e.model_dump() for e in entries]


# ---------------------------------------------------------------------------
# Agent package download
# ---------------------------------------------------------------------------

_AGENT_DIRS = ["deephole_client", "task_agent", "mcp_server", "backend"]
_AGENT_RUNTIME_DIRS = ["deephole_client", "task_agent", "mcp_server", "backend"]
_AGENT_TOOL_DIRS = ["ctags-p6.2.20260517.0-x64"]
_AGENT_RUNTIME_ROOT_FILES = ["requirements-agent.txt"]
_AGENT_ROOT_FILES = [
    "agent.yaml",
    "run_agent.sh",
    "run_agent.bat",
    "requirements-agent.txt",
]
_AGENT_DOWNLOAD_SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "static",
    "system_skills",
}
_AGENT_RUNTIME_SKIP_DIRS = set(_AGENT_DOWNLOAD_SKIP_DIRS)
_AGENT_SKIP_SUFFIXES = {".pyc", ".pyo"}


def _agent_runtime_hash_scope() -> dict:
    return {
        "version": 3,
        "dirs": list(_AGENT_RUNTIME_DIRS),
        "tool_dirs": list(_AGENT_TOOL_DIRS),
        "root_files": list(_AGENT_RUNTIME_ROOT_FILES),
        "skip_dirs": sorted(_AGENT_RUNTIME_SKIP_DIRS),
        "skip_suffixes": sorted(_AGENT_SKIP_SUFFIXES),
    }


def _should_skip_agent_file(path: Path, skip_dirs: set[str]) -> bool:
    return path.suffix in _AGENT_SKIP_SUFFIXES or any(part in skip_dirs for part in path.parts)


def _iter_agent_runtime_files():
    for dir_name in [*_AGENT_RUNTIME_DIRS, *_AGENT_TOOL_DIRS]:
        dir_path = _PROJECT_ROOT / dir_name
        if not dir_path.is_dir():
            continue
        # Sort by POSIX arcname to ensure consistent ordering across platforms
        # (Windows Path sorting is case-insensitive, Linux is case-sensitive).
        entries = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and not _should_skip_agent_file(file_path, _AGENT_RUNTIME_SKIP_DIRS):
                arcname = file_path.relative_to(_PROJECT_ROOT).as_posix()
                entries.append((arcname, file_path))
        entries.sort(key=lambda e: e[0])
        yield from entries
    for filename in _AGENT_RUNTIME_ROOT_FILES:
        file_path = _PROJECT_ROOT / filename
        if file_path.is_file():
            yield filename, file_path


def _agent_runtime_hash() -> str:
    digest = hashlib.sha256()
    for arcname, file_path in _iter_agent_runtime_files():
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _agent_runtime_hash_for_files(files: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for arcname, content in files:
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _agent_runtime_manifest_for_files(files: list[tuple[str, bytes]]) -> dict:
    return {
        "hash_scope": _agent_runtime_hash_scope(),
        "files": [
            {
                "path": arcname,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for arcname, content in files
        ],
    }


def _read_agent_runtime_files() -> list[tuple[str, bytes]]:
    return [(arcname, file_path.read_bytes()) for arcname, file_path in _iter_agent_runtime_files()]


def _build_agent_runtime_zip() -> bytes:
    return _build_agent_runtime_zip_from_files(_read_agent_runtime_files())


def _build_agent_runtime_zip_from_files(files: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in files:
            zf.writestr(arcname, content)
    return buf.getvalue()


def _build_agent_runtime_download() -> _RuntimeDownload:
    files = _read_agent_runtime_files()
    data = _build_agent_runtime_zip_from_files(files)
    runtime_hash = _agent_runtime_hash_for_files(files)
    manifest = _agent_runtime_manifest_for_files(files)
    manifest["runtime_hash"] = runtime_hash
    return _RuntimeDownload(
        runtime_hash=runtime_hash,
        archive_sha256=hashlib.sha256(data).hexdigest(),
        manifest=manifest,
        data=data,
        expires_at=time.time() + _RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS,
    )


def create_agent_runtime_update_payload(server_url: str) -> dict:
    _purge_expired_runtime_downloads()
    download = _build_agent_runtime_download()
    token = secrets.token_urlsafe(32)
    _runtime_download_tokens[token] = download
    return {
        "hash": download.runtime_hash,
        "archive_sha256": download.archive_sha256,
        "manifest": download.manifest,
        "hash_scope": download.manifest["hash_scope"],
        "download_url": f"{server_url.rstrip('/')}/api/agent/runtime/download",
        "token": token,
        "expires_at": int(download.expires_at),
    }


def _build_agent_zip(server_url: str = "", owner_token: str = "") -> bytes:
    """Build the agent zip in-memory from the project source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dir_name in [*_AGENT_DIRS, *_AGENT_TOOL_DIRS]:
            dir_path = _PROJECT_ROOT / dir_name
            if not dir_path.is_dir():
                continue
            for file_path in dir_path.rglob("*"):
                if file_path.is_file() and not _should_skip_agent_file(file_path, _AGENT_DOWNLOAD_SKIP_DIRS):
                    arcname = str(file_path.relative_to(_PROJECT_ROOT))
                    zf.write(file_path, arcname)

        for filename in _AGENT_ROOT_FILES:
            file_path = _PROJECT_ROOT / filename
            if not file_path.is_file():
                continue
            if filename == "agent.yaml":
                content = file_path.read_text(encoding="utf-8")
                if server_url:
                    content = content.replace(
                        'server_url: "http://your-server:8000"',
                        f'server_url: "{server_url}"',
                    )
                if owner_token:
                    content = content.replace(
                        'owner_token: ""',
                        f'owner_token: "{owner_token}"',
                    )
                zf.writestr(filename, content.encode("utf-8"))
            else:
                zf.write(file_path, filename)

        zf.writestr("README.txt", _AGENT_README.encode("utf-8"))

    return buf.getvalue()


_AGENT_README = """\
OpenDeepHole Agent
==================

Setup
-----
1. agent.yaml already contains the server_url and owner_token from the Web UI.
   Start the Agent once, then use the Web "Agent 配置" page to configure the
   tool, explicit model pool, phase policies, MCP servers and validation
   environments. A scan cannot start without an enabled explicit model.

2. Install Python 3.10+ if not already installed

3. Code-index tool:

   Linux:
     apt install universal-ctags

   macOS:
     brew install universal-ctags

   Windows:
     The Agent package includes Universal Ctags for Windows x64.
     run_agent.bat uses the bundled ctags.exe automatically.

4. Run the agent daemon:

   Linux/macOS:
     chmod +x run_agent.sh
     ./run_agent.sh

   Windows:
     run_agent.bat

Options
-------
  --server URL          Override server_url from agent.yaml
  --name NAME           Display name shown on the web UI

Usage
-----
The agent daemon connects to the server via WebSocket and waits for scan tasks.
Use the "新建扫描" button in the web UI to start a scan.
Before each scan, the agent checks whether the server has newer runtime code.
Runtime code updates, including the bundled Windows ctags directory, are
installed automatically and the scan continues after the agent restarts.
Checker and product-validator updates are installed with the required Agent
runtime update. If
run_agent.sh or run_agent.bat changes, download a new agent package.

Results appear at: <server_url> (the web interface)
"""


@router.get("/download")
async def agent_download(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Serve the agent package as a downloadable zip with server_url and owner_token pre-filled."""
    try:
        server_url = str(request.base_url).rstrip("/")
        data = _build_agent_zip(server_url, owner_token=current_user.agent_token)
    except Exception as exc:
        logger.exception("Failed to build agent zip")
        raise HTTPException(status_code=500, detail=f"Failed to build agent package: {exc}")

    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent.zip"'},
    )


@router.get("/runtime/manifest")
async def agent_runtime_manifest() -> dict:
    """Return the current server-side Agent runtime hash."""
    files = _read_agent_runtime_files()
    runtime_hash = _agent_runtime_hash_for_files(files)
    manifest = _agent_runtime_manifest_for_files(files)
    manifest["runtime_hash"] = runtime_hash
    return {
        "hash": runtime_hash,
        "hash_scope": manifest["hash_scope"],
        "manifest": manifest,
    }


@router.get("/runtime/download")
async def agent_runtime_download(request: Request) -> Response:
    """Serve a short-lived Agent runtime update archive."""
    _purge_expired_runtime_downloads()
    token = request.headers.get("X-Agent-Update-Token") or request.query_params.get("token") or ""
    download = _runtime_download_tokens.pop(token, None)
    if download is None:
        raise HTTPException(status_code=403, detail="Invalid or expired runtime update token")
    if time.time() > download.expires_at:
        raise HTTPException(status_code=403, detail="Runtime update token expired")

    return Response(
        content=download.data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent-runtime.zip"'},
    )
