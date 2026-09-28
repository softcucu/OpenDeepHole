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
import copy
import hashlib
import io
import json
import os
import re
import secrets
import socket
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, Optional
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import Response
from pydantic import BaseModel

from backend.api.scan import _running_scans, _scan_owners
from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    AgentGitHistory,
    AgentMcpConfig,
    AgentMcpLocalConfig,
    AgentMcpProbeResult,
    AgentMcpRemoteConfig,
    AgentMcpRuntimeStatus,
    AgentMcpStatusResponse,
    AgentMcpTargetStatus,
    AgentOpenCodePoolStatus,
    AgentInfo,
    AgentCandidateAuditResult,
    AgentRemoteConfig,
    AgentValidatorCatalog,
    AgentProcessedKeyBatch,
    AgentScanCandidateBatch,
    AgentScanCandidates,
    AgentScanEventBatch,
    AgentScanFinish,
    AgentScanExecutionFailure,
    AgentScanFinishV2,
    AgentVulnerabilityReconcile,
    AgentVulnerabilityValidationUpdate,
    FpReviewStatus,
    HistoryPattern,
    KnowledgeBaseProject,
    MiningEngineRunStatus,
    MiningEngineSelection,
    OpenCodePoolStatus,
    OpenCodeTaskReport,
    OpenCodeTokenUsage,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    STATIC_CANDIDATE_ENGINE_LABEL,
    SkillReport,
    THREAT_AUDIT_ENGINE_LABEL,
    ThreatAuditTask,
    ThreatAnalysisRunStatus,
    User,
    Vulnerability,
    VulnerabilityPage,
    VulnerabilityPageItem,
    VulnerabilityValidation,
)
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call
from backend.scan_event_log import (
    SCAN_EVENT_RETENTION_LIMIT,
    is_agent_local_task_output,
)
from backend.scan_runtime import (
    AGENT_DISCONNECT_ERROR,
    AGENT_RECOVERY_IN_PROGRESS,
    AGENT_RECOVERY_FAILED_PREFIX,
    is_agent_recovery_interruption,
    RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES,
    terminal_opencode_pool_status as _terminal_opencode_pool_status,
)
from backend.threat_data import parse_threat_analysis_data
from backend.vulnerability_identity import vulnerability_report_identity

from backend.report_routes import HistoricalReportRoute

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter()  # Routes not under /api/agent prefix
logger = get_logger(__name__)
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_STATIC_CANDIDATE_ENGINE_ID = "static_candidate"
_MINING_ENGINE_RUN_STATUSES = {
    "pending",
    "running",
    "success",
    "error",
    "cancelled",
    "skipped",
}
_MINING_ENGINE_TERMINAL_STATUSES = {
    "success",
    "error",
    "cancelled",
    "skipped",
}
_THREAT_ANALYSIS_RUN_STATUSES = {
    "pending",
    "running",
    "success",
    "error",
    "cancelled",
}
_THREAT_ANALYSIS_TERMINAL_STATUSES = {
    "success",
    "error",
    "cancelled",
}

# Root of the project (two levels up from this file: backend/api/ → backend/ → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory registry of connected agents
_registered_agents: dict[str, AgentInfo] = {}

# Active WebSocket connections keyed by agent_id (WebSocket mode)
_agent_ws: dict[str, WebSocket] = {}
_agent_ws_locks: dict[str, asyncio.Lock] = {}
_agent_disconnect_tasks: dict[str, asyncio.Task] = {}
_agent_touch_tasks: dict[str, asyncio.Task] = {}
_agent_touch_persisted_at: dict[str, float] = {}
_AGENT_TOUCH_PERSIST_INTERVAL_SECONDS = 10.0

# Compatibility cache.  New entries are keyed by stable agent_key; name keys
# are still read for tests and pre-v2 HTTP agents.
_agent_configs: dict[str, AgentRemoteConfig] = {}
_agent_opencode_pool_latest: dict[str, OpenCodePoolStatus] = {}


def _storage_target_fingerprint(store) -> str:
    config = get_config().storage
    database_url = str(config.database_url or "").strip()
    if database_url:
        try:
            parsed = urlsplit(database_url)
            target = (
                f"{parsed.scheme.lower()}://"
                f"{(parsed.hostname or '').lower()}:"
                f"{parsed.port or ''}{parsed.path}?{parsed.query}"
            )
        except Exception:
            target = f"{type(store).__name__}:configured-database"
    else:
        target = str((Path(config.scans_dir).resolve() / "scans.db"))
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]


def _scan_not_found(
    scan_id: str,
    *,
    endpoint: str,
    store,
) -> NoReturn:
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    if getattr(store, "distributed", False):
        try:
            from backend.distributed import WORKER_ID

            worker_id = WORKER_ID
        except Exception:
            pass
    logger.warning(
        "Agent scan lookup failed scan_id=%s endpoint=%s pid=%d "
        "worker_id=%s storage=%s storage_target=%s",
        scan_id,
        endpoint,
        os.getpid(),
        worker_id,
        type(store).__name__,
        _storage_target_fingerprint(store),
    )
    raise HTTPException(
        status_code=404,
        detail={
            "code": "scan_not_found",
            "scan_id": scan_id,
            "endpoint": endpoint,
        },
    )


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
    for target in ("product_info",):
        raw = payload.get(target)
        if not isinstance(raw, dict):
            continue
        try:
            results[target] = AgentMcpProbeResult(**raw)
        except Exception as exc:
            logger.warning("Ignoring invalid persisted %s MCP probe result: %s", target, exc)
    return results


def _mcp_config_fingerprint(config: AgentMcpConfig) -> str:
    from backend.opencode_config import managed_mcp_config_fingerprint

    return managed_mcp_config_fingerprint(config)


def _mcp_target_config(config: AgentRemoteConfig, target: str) -> AgentMcpConfig:
    if target == "product_info":
        return config.product_info
    raise HTTPException(
        status_code=422,
        detail="Agent 级 MCP 检测目标只能是 product_info；代码图谱请在创建扫描时检测",
    )


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


def _agent_info_from_shared_session(session: dict) -> AgentInfo:
    agent_id = str(session["agent_id"])
    return AgentInfo(
        agent_id=agent_id,
        agent_key=str(session["agent_key"]),
        name=str(session["name"]),
        machine_name=str(session["machine_name"] or ""),
        ip="shared-worker",
        last_seen=str(session["last_seen"]),
        user_id=str(session["user_id"] or ""),
        runtime_hash=str(session.get("runtime_hash") or ""),
        agent_session_id=str(session.get("agent_session_id") or agent_id),
        accepting_tasks=bool(session.get("accepting_tasks", 1)),
        protocol_version=int(session["protocol_version"] or 1),
    )


async def resolve_agent_connection_async(
    agent_key: str,
) -> tuple[str, AgentInfo] | None:
    """Resolve local or PostgreSQL-owned Agent sessions without blocking."""
    normalized = str(agent_key or "").strip()
    local = _live_agent_for_key(normalized)
    if local is not None:
        return local
    store = get_scan_store()
    if not getattr(store, "distributed", False):
        return None
    session = await run_store_call(
        store,
        "get_live_agent_session",
        agent_key=normalized,
        stale_seconds=_WEBSOCKET_AGENT_STALE_SECONDS,
    )
    if session is None:
        return None
    agent = _agent_info_from_shared_session(session)
    return agent.agent_id, agent


async def resolve_agent_id_connection_async(
    agent_id: str,
) -> tuple[str, AgentInfo] | None:
    normalized = str(agent_id or "").strip()
    local = _registered_agents.get(normalized)
    store = get_scan_store()
    if local is not None and (
        normalized in _agent_ws
        or local.port > 0
        or not getattr(store, "distributed", False)
    ):
        return normalized, local
    if not normalized or not getattr(store, "distributed", False):
        return None
    session = await run_store_call(
        store,
        "get_live_agent_session",
        agent_id=normalized,
        stale_seconds=_WEBSOCKET_AGENT_STALE_SECONDS,
    )
    if session is None:
        return None
    agent = _agent_info_from_shared_session(session)
    return agent.agent_id, agent


def _authorize_agent_record(record: dict | None, current_user: User) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and str(record.get("user_id") or "") != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return record


def agent_explicit_model_ids(config: AgentRemoteConfig) -> list[str]:
    """Return the ordered, deduplicated explicit models selected on platform."""
    model_ids: list[str] = []
    seen: set[str] = set()
    for model in config.model_pool.models:
        model_id = str(model.model or "").strip()
        if (
            not model.enabled
            or model.use_default_model
            or not model_id
            or model_id in seen
        ):
            continue
        seen.add(model_id)
        model_ids.append(model_id)
    return model_ids


def agent_config_has_explicit_model(config: AgentRemoteConfig) -> bool:
    return bool(agent_explicit_model_ids(config))


def get_managed_agent_config(agent_key: str) -> AgentRemoteConfig:
    record = get_scan_store().get_agent_record(str(agent_key or "").strip())
    if record is None:
        return AgentRemoteConfig()
    return _stored_agent_config(record)


async def get_managed_agent_config_async(agent_key: str) -> AgentRemoteConfig:
    """Async request-path variant that cannot wait on the store lock in-loop."""
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        str(agent_key or "").strip(),
    )
    if record is None:
        return AgentRemoteConfig()
    return _stored_agent_config(record)


async def get_scan_agent_config_async(
    agent: AgentInfo,
    agent_key: str = "",
) -> AgentRemoteConfig:
    """Resolve scan readiness config for stable and legacy Agent connections."""
    stable_key = str(agent_key or agent.agent_key or "").strip()
    if stable_key:
        record = await run_store_call(
            get_scan_store(),
            "get_agent_record",
            stable_key,
        )
        if record is not None:
            return _stored_agent_config(record)
    return (
        _agent_configs.get(stable_key)
        or _agent_configs.get(agent.name)
        or AgentRemoteConfig()
    )


def _validate_mcp_config(
    mcp,
    *,
    label: str,
    require_enabled: bool = False,
) -> None:
    if require_enabled and not mcp.enabled:
        raise HTTPException(status_code=422, detail=f"{label} MCP 必须启用")
    if mcp.transport not in {"local", "remote"}:
        raise HTTPException(status_code=422, detail=f"{label} MCP 模式无效")
    if mcp.enabled and not mcp.name.strip():
        raise HTTPException(status_code=422, detail=f"{label} MCP 名称不能为空")
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
            raise HTTPException(
                status_code=422,
                detail=f"{label} MCP 请求头名称无效：{name or '(空)'}",
            )
        if lowered in seen_headers:
            raise HTTPException(status_code=422, detail=f"{label} MCP 请求头名称重复：{name}")
        seen_headers.add(lowered)
        if "\r" in str(raw_value) or "\n" in str(raw_value):
            raise HTTPException(
                status_code=422,
                detail=f"{label} MCP 请求头 {name} 的值不能包含换行",
            )


def _normalize_scan_code_graph_mcp(
    request: AgentMcpConfig | None,
) -> AgentMcpConfig | None:
    """Keep scan code-graph input to the UI's mode/remote-only contract."""
    if request is None or not request.enabled:
        return None
    transport = str(request.transport or "").strip()
    if transport == "local":
        config = AgentMcpConfig(
            enabled=True,
            name="codegraph",
            transport="local",
            timeout_seconds=300,
            local=AgentMcpLocalConfig(
                executable="codegraph",
                args=["serve", "--mcp"],
                environment={
                    "CODEGRAPH_MCP_TOOLS": (
                        "explore,node,search,callers,callees,impact,files,status"
                    ),
                },
            ),
            remote=AgentMcpRemoteConfig(),
        )
    else:
        config = AgentMcpConfig(
            enabled=True,
            name="codegraph",
            transport=transport,
            timeout_seconds=300,
            local=AgentMcpLocalConfig(),
            remote=AgentMcpRemoteConfig(
                url=str(request.remote.url or "").strip(),
                headers={
                    str(key): str(value)
                    for key, value in request.remote.headers.items()
                },
            ),
        )
    _validate_mcp_config(config, label="扫描代码图谱", require_enabled=True)
    return config


def _normalize_scan_knowledge_base_mcp(
    *,
    enabled: bool,
    project_id: str = "",
    project_name: str = "",
    require_project: bool = True,
) -> AgentMcpConfig | None:
    """Build a scan-private snapshot from the server-owned knowledge config."""
    if not enabled:
        return None
    knowledge = get_config().knowledge_base
    normalized_project_id = str(project_id or "").strip()
    normalized_project_name = str(project_name or "").strip()
    if require_project and not normalized_project_id:
        raise HTTPException(status_code=422, detail="启用知识库后必须选择项目")
    if require_project and not normalized_project_name:
        raise HTTPException(status_code=422, detail="知识库项目名称不能为空")
    projects_tool = str(knowledge.projects_tool or "").strip()
    set_project_tool = str(knowledge.set_project_tool or "").strip()
    if not projects_tool or not set_project_tool:
        raise HTTPException(
            status_code=422,
            detail="服务端知识库 projects_tool/set_project_tool 配置不完整",
        )
    if projects_tool.casefold() == set_project_tool.casefold():
        raise HTTPException(
            status_code=422,
            detail="服务端知识库 projects_tool 与 set_project_tool 不能相同",
        )
    config = AgentMcpConfig(
        enabled=True,
        name=str(knowledge.name or "product-info").strip(),
        transport="remote",
        timeout_seconds=knowledge.timeout_seconds,
        local=AgentMcpLocalConfig(),
        remote=AgentMcpRemoteConfig(
            url=str(knowledge.url or "").strip(),
            headers={
                str(key): str(value)
                for key, value in knowledge.headers.items()
                if str(key)
            },
        ),
        project_id=normalized_project_id,
        project_name=normalized_project_name,
        projects_tool=projects_tool,
        set_project_tool=set_project_tool,
    )
    _validate_mcp_config(config, label="扫描知识库", require_enabled=True)
    return config


def _validate_managed_config(
    config: AgentRemoteConfig,
    catalog: AgentValidatorCatalog | None = None,
) -> None:
    if config.base.tool != "opencode":
        raise HTTPException(status_code=422, detail="基础配置中的工具只能是 opencode")
    if not config.base.executable.strip():
        raise HTTPException(status_code=422, detail="工具可执行文件不能为空")
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
        "威胁分析": config.threat_analysis.model_policy,
    }
    validation = config.vulnerability_validation
    if validation.concurrency < 1 or validation.concurrency > 64:
        raise HTTPException(status_code=422, detail="漏洞验证同时验证数量必须在 1 到 64 之间")
    if validation.validation_max_retries < 0:
        raise HTTPException(status_code=422, detail="漏洞验证整体验证重试不能小于 0")
    if not any(str(item).strip() for item in validation.supported_vulnerability_types):
        raise HTTPException(status_code=422, detail="漏洞验证至少需要一个支持的漏洞类型")
    policies["漏洞验证"] = validation.model_policy
    for label, policy in policies.items():
        if policy.required_capability not in {"low", "high"}:
            raise HTTPException(status_code=422, detail=f"{label}的模型能力无效")
        if policy.timeout_seconds < 1:
            raise HTTPException(status_code=422, detail=f"{label}的模型超时必须大于 0")
        if policy.max_retries < 0:
            raise HTTPException(status_code=422, detail=f"{label}的模型重试不能小于 0")
    # Dynamic method fields are validated and snapshotted by scan creation.
    del catalog


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
_mcp_probe_waiters: dict[str, asyncio.Future] = {}
_mcp_status_waiters: dict[str, asyncio.Future] = {}
_mcp_reload_waiters: dict[str, asyncio.Future] = {}
_scan_stop_waiters: dict[str, asyncio.Future] = {}
_mcp_probe_persist_locks: dict[str, asyncio.Lock] = {}
_AGENT_RESPONSE_WAITERS = {
    "opencode_models_result": _opencode_model_waiters,
    "mcp_probe_result": _mcp_probe_waiters,
    "mcp_status_result": _mcp_status_waiters,
    "mcp_reload_result": _mcp_reload_waiters,
    "scan_stop_result": _scan_stop_waiters,
}

# In-memory index progress store: scan_id → {status, parsed_files, total_files}
_scan_index_statuses: dict[str, dict] = {}

_SERVER_RESTART_ERROR = "Process terminated unexpectedly"
_WEBSOCKET_AGENT_STALE_SECONDS = 120
_AGENT_DISCONNECT_GRACE_SECONDS = 120
_SERVER_STARTED_AT = datetime.now(timezone.utc)
_RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS = 300

_RUNTIME_UPDATE_PENDING = "pending"
_RUNTIME_UPDATE_UPDATING = "updating"
_RUNTIME_UPDATE_FAILED = "failed"
_RUNTIME_UPDATE_ACTIVE_STATUSES = {
    _RUNTIME_UPDATE_PENDING,
    _RUNTIME_UPDATE_UPDATING,
}
_RUNTIME_UPDATE_POLL_SECONDS = 2
_RUNTIME_UPDATE_TIMEOUT_SECONDS = 15 * 60
_OPENCODE_MODEL_RPC_TIMEOUT_SECONDS = 120.0
_SCAN_STOP_RPC_TIMEOUT_SECONDS = 10.0
_FINAL_VULNERABILITY_CALLBACKS_CAPABILITY = "final_vulnerability_callbacks"
_INCREMENTAL_OPENCODE_TASK_REPORTS_CAPABILITY = "incremental_opencode_task_reports"


async def _complete_agent_response(
    incoming: dict,
    waiters: dict[str, asyncio.Future],
) -> None:
    request_id = str(incoming.get("request_id") or "")
    waiter = waiters.pop(request_id, None)
    if waiter is not None and not waiter.done():
        waiter.set_result(incoming)
        return
    store = get_scan_store()
    if request_id and getattr(store, "distributed", False):
        await run_store_call(
            store,
            "put_agent_rpc_response",
            request_id,
            incoming,
        )


async def _wait_agent_response(
    request_id: str,
    waiter: asyncio.Future,
    *,
    timeout: float,
) -> dict:
    # The response can arrive on the same websocket while send_agent_command()
    # is still unwinding.  Honor that in-process result before consulting the
    # distributed mailbox, which also keeps the acknowledgement path working
    # during an unrelated store hiccup.
    if waiter.done():
        return waiter.result()
    store = get_scan_store()
    if not getattr(store, "distributed", False):
        return await asyncio.wait_for(waiter, timeout=timeout)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if waiter.done():
            return waiter.result()
        response = await run_store_call(
            store,
            "pop_agent_rpc_response",
            request_id,
        )
        if response is not None:
            return response
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError
        done, _pending = await asyncio.wait(
            {waiter},
            timeout=min(0.1, remaining),
        )
        if done:
            return waiter.result()


def _runtime_update_status(record: dict | None) -> str:
    return str((record or {}).get("runtime_update_status") or "")


def is_agent_accepting_tasks(agent_key: str) -> bool:
    """Return whether a stable Agent may receive a new workload command."""
    if not agent_key:
        return True
    record = get_scan_store().get_agent_record(agent_key)
    return _runtime_update_status(record) != _RUNTIME_UPDATE_UPDATING


def ensure_agent_accepting_tasks(agent_key: str) -> None:
    if not is_agent_accepting_tasks(agent_key):
        raise HTTPException(
            status_code=409,
            detail="Agent 正在更新并等待重连，请稍后再提交任务",
        )


async def ensure_agent_accepting_tasks_async(agent_key: str) -> None:
    if not agent_key:
        return
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        agent_key,
    )
    if _runtime_update_status(record) == _RUNTIME_UPDATE_UPDATING:
        raise HTTPException(
            status_code=409,
            detail="Agent 正在更新并等待重连，请稍后再提交任务",
        )


def _runtime_update_age_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds())
    except Exception:
        return None


def _scan_belongs_to_agent(scan_id: str, agent_key: str, agent_id: str) -> bool:
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return False
    if agent_key and meta.agent_key:
        return meta.agent_key == agent_key
    return bool(agent_id and meta.agent_id == agent_id)


async def _agent_has_active_work(agent_key: str, agent_id: str) -> bool:
    """Use durable task lifecycle state to decide whether an update is safe.

    The Agent-wide OpenCode pool is intentionally not consulted here.  Its
    snapshot is observational and may briefly retain running/queued entries
    after the user has stopped a task.  Scan, FP-review, and validation rows
    are the authoritative lifecycle state for manual runtime updates.
    """
    return await run_store_call(
        get_scan_store(),
        "has_active_work_for_agent",
        agent_key,
        agent_id,
    )


async def _clear_agent_runtime_update(agent_key: str) -> None:
    store = get_scan_store()
    await run_store_call(
        store,
        "set_agent_runtime_update_record",
        agent_key,
        status="",
    )


async def _process_agent_runtime_updates() -> None:
    """Advance all durable manual Agent update requests by one scheduler tick."""
    store = get_scan_store()
    records = await run_store_call(store, "list_agent_records")
    for record in records:
        status = _runtime_update_status(record)
        if status not in _RUNTIME_UPDATE_ACTIVE_STATUSES:
            continue

        agent_key = str(record.get("agent_key") or "")
        target_hash = str(record.get("runtime_update_target_hash") or "")
        live = await resolve_agent_connection_async(agent_key)

        if live is not None and target_hash and live[1].runtime_hash == target_hash:
            await _clear_agent_runtime_update(agent_key)
            logger.info("Agent runtime update completed: agent_key=%s", agent_key)
            continue

        if status == _RUNTIME_UPDATE_UPDATING:
            age = _runtime_update_age_seconds(
                str(record.get("runtime_update_started_at") or "")
            )
            if age is not None and age > _RUNTIME_UPDATE_TIMEOUT_SECONDS:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=_RUNTIME_UPDATE_FAILED,
                    target_hash=target_hash,
                    server_url=str(record.get("runtime_update_server_url") or ""),
                    requested_at=str(record.get("runtime_update_requested_at") or ""),
                    started_at=str(record.get("runtime_update_started_at") or ""),
                    error="Agent 更新后未在规定时间内以目标版本重连",
                )
                logger.warning(
                    "Agent runtime update timed out: agent_key=%s target=%s",
                    agent_key,
                    target_hash[:12],
                )
            continue

        if live is None:
            continue
        agent_id, agent = live
        if await _agent_has_active_work(agent_key, agent_id):
            continue

        server_url = str(record.get("runtime_update_server_url") or "")
        if not server_url:
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=_RUNTIME_UPDATE_FAILED,
                target_hash=target_hash,
                requested_at=str(record.get("runtime_update_requested_at") or ""),
                error="更新请求缺少服务端地址，请重新点击更新",
            )
            continue

        try:
            target_hash = await asyncio.to_thread(_agent_runtime_hash)
            if agent.runtime_hash and agent.runtime_hash == target_hash:
                await _clear_agent_runtime_update(agent_key)
                continue
            now = datetime.now(timezone.utc).isoformat()
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=_RUNTIME_UPDATE_UPDATING,
                target_hash=target_hash,
                server_url=server_url,
                requested_at=str(record.get("runtime_update_requested_at") or now),
                started_at=now,
            )

            # Let concurrent task-creation requests observe the updating state,
            # then recheck in case one was already committed before the handoff.
            await asyncio.sleep(0)
            live = await resolve_agent_connection_async(agent_key)
            if live is None:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=_RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue
            agent_id, _agent = live
            if await _agent_has_active_work(agent_key, agent_id):
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=_RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue

            update_payload = await asyncio.to_thread(
                create_agent_runtime_update_payload,
                server_url,
            )
            sent = await send_agent_command(
                agent_id,
                {
                    "type": "task",
                    "runtime_update_only": True,
                    "agent_runtime_update": update_payload,
                },
            )
            if not sent:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=_RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue
            logger.info(
                "Agent runtime update dispatched at idle boundary: agent_key=%s target=%s",
                agent_key,
                target_hash[:12],
            )
        except Exception as exc:
            logger.exception(
                "Failed to dispatch Agent runtime update for %s",
                agent_key,
            )
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=_RUNTIME_UPDATE_FAILED,
                target_hash=target_hash,
                server_url=server_url,
                requested_at=str(record.get("runtime_update_requested_at") or ""),
                error=f"下发 Agent 更新失败：{exc}",
            )


async def run_agent_runtime_update_scheduler() -> None:
    """Continuously dispatch durable manual updates at safe idle boundaries."""
    while True:
        try:
            await _process_agent_runtime_updates()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Agent runtime update scheduler tick failed")
        await asyncio.sleep(_RUNTIME_UPDATE_POLL_SECONDS)


def _purge_expired_runtime_downloads() -> None:
    now = time.time()
    expired = [
        token
        for token, download in _runtime_download_tokens.items()
        if download.expires_at <= now
    ]
    for token in expired:
        _runtime_download_tokens.pop(token, None)


async def _persist_agent_touch(agent_id: str, delay: float) -> None:
    try:
        if delay > 0:
            await asyncio.sleep(delay)
        agent = _registered_agents.get(agent_id)
        if agent is None or not agent.agent_key:
            return
        try:
            await run_store_call(
                get_scan_store(),
                "touch_agent_record",
                agent.agent_key,
                agent_id,
                agent.last_seen,
            )
            store = get_scan_store()
            if getattr(store, "distributed", False):
                await run_store_call(
                    store,
                    "touch_agent_session",
                    agent_id,
                    agent.last_seen,
                )
            _agent_touch_persisted_at[agent_id] = time.monotonic()
        except (NotImplementedError, AttributeError):
            pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Failed to persist Agent heartbeat: %s", agent_id)
    finally:
        _agent_touch_tasks.pop(agent_id, None)


def _schedule_agent_touch_persistence(agent_id: str) -> None:
    task = _agent_touch_tasks.get(agent_id)
    if task is not None and not task.done():
        return
    elapsed = time.monotonic() - _agent_touch_persisted_at.get(agent_id, 0.0)
    delay = max(0.0, _AGENT_TOUCH_PERSIST_INTERVAL_SECONDS - elapsed)
    _agent_touch_tasks[agent_id] = asyncio.create_task(
        _persist_agent_touch(agent_id, delay)
    )


def _touch_agent(agent_id: str, *, persist: bool = True) -> None:
    agent = _registered_agents.get(agent_id)
    if agent is not None:
        agent.last_seen = datetime.now(timezone.utc).isoformat()
        if persist and agent.agent_key:
            _schedule_agent_touch_persistence(agent_id)


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
    agent_key = str(
        getattr(_registered_agents.get(agent_id), "agent_key", "") or ""
    )
    old_task = _agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()

    async def _delayed_cancel() -> None:
        try:
            await asyncio.sleep(_AGENT_DISCONNECT_GRACE_SECONDS)
            store = get_scan_store()
            if agent_key and getattr(store, "distributed", False):
                live = await run_store_call(
                    store,
                    "get_live_agent_session",
                    agent_key=agent_key,
                    stale_seconds=_WEBSOCKET_AGENT_STALE_SECONDS,
                )
                if live is not None and str(live["agent_id"]) != agent_id:
                    return
            await _mark_agent_scans_cancelled_async(agent_id)
        except asyncio.CancelledError:
            return
        finally:
            _agent_disconnect_tasks.pop(agent_id, None)

    _agent_disconnect_tasks[agent_id] = asyncio.create_task(_delayed_cancel())


def _is_infrastructure_interruption(scan_status: ScanItemStatus, error_message: str | None) -> bool:
    """Return True for states caused by server/connection loss, not user intent."""
    if is_agent_recovery_interruption(scan_status, error_message):
        return True
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
    # In PostgreSQL mode the WebSocket may belong to another Uvicorn worker.
    # The leader's durable stale-session sweep owns cancellation; a process-
    # local registry must never cancel shared work.
    if getattr(get_scan_store(), "distributed", False):
        return False, False
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
        scan.opencode_pool = _terminal_opencode_pool_status(scan.opencode_pool)
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


async def _reattach_active_agent_scans_async(
    agent_id: str,
    agent: AgentInfo,
    active_scans: list,
    pending_stops: list[dict] | None = None,
) -> list[str]:
    """Restore server-side running state for scans still running in this agent."""
    if not active_scans:
        return []

    store = get_scan_store()
    reattached_scan_ids: list[str] = []
    for item in active_scans:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        if not scan_id:
            continue

        loaded = await run_store_call(store, "load_scan", scan_id)
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
        if (
            scan.status == ScanItemStatus.CANCELLED
            and scan.error_message == "用户手动停止"
        ):
            if pending_stops is not None:
                command = {"type": "stop", "scan_id": scan_id}
                if meta.execution_revision > 0:
                    command["execution_revision"] = meta.execution_revision
                pending_stops.append(command)
            logger.warning(
                "Agent %s still reports manually stopped scan %s; resending stop",
                agent_id,
                scan_id,
            )
            continue
        if not _reported_execution_matches(item, meta.execution_revision):
            logger.info("Ignoring obsolete/stopping scan %s from agent %s", scan_id, agent_id)
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

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        _running_scans[scan_id] = scan
        if meta.user_id:
            _scan_owners[scan_id] = meta.user_id
        reattached_scan_ids.append(scan_id)
        logger.info("Reattached active scan %s from agent %s", scan_id, agent_id)
    return reattached_scan_ids


async def _reattach_active_fp_reviews_async(
    agent_id: str,
    agent: AgentInfo,
    active_fp_reviews: list,
) -> None:
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

        job = await run_store_call(store, "get_fp_review_job", review_id)
        if job is None or job.scan_id != scan_id:
            logger.warning("Agent %s reported unknown active FP review %s", agent_id, review_id)
            continue

        meta = await run_store_call(store, "get_scan_meta", scan_id)
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

        item_running = bool(item.get("item_running", True))
        reattached = False
        if item_running:
            if job.status in (FpReviewStatus.PENDING, FpReviewStatus.RUNNING):
                reattached = True
            elif (
                job.status == FpReviewStatus.ERROR
                and _is_agent_disconnect_error(job.error_message)
            ):
                await run_store_call(
                    store,
                    "update_fp_review_job",
                    review_id,
                    status="running",
                    error_message="",
                )
                reattached = True
        if not reattached:
            logger.info(
                "Ignoring active FP review %s from agent %s: "
                "item_status=%s",
                review_id,
                agent.name,
                job.status.value,
            )
            continue

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
        logger.info("Reattached active FP review %s from agent %s", review_id, agent_id)


async def _reattach_active_validations_async(
    agent_id: str,
    agent: AgentInfo,
    active_validations: list,
) -> list[dict]:
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

        meta = await run_store_call(store, "get_scan_meta", scan_id)
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

        validations = await run_store_call(
            store,
            "list_vulnerability_validations",
            scan_id,
        )
        validation = next(
            (entry for entry in validations if entry.vuln_index == vuln_index),
            None,
        )
        if validation is None:
            logger.warning("Agent %s reported unknown active validation %s#%s", agent_id, scan_id, vuln_index)
            continue

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
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


def _reported_work_ids(items: object, *keys: str) -> set[tuple[str, ...]]:
    values: set[tuple[str, ...]] = set()
    if not isinstance(items, list):
        return values
    for item in items:
        if not isinstance(item, dict):
            continue
        identity = tuple(
            str(item.get(key)) if item.get(key) is not None else ""
            for key in keys
        )
        if all(identity):
            values.add(identity)
    return values


def _reported_execution_matches(item: dict, revision: int) -> bool:
    if item.get("cancel_requested"):
        return False
    try:
        reported_revision = int(item.get("execution_revision") or 0)
    except (TypeError, ValueError):
        return False
    return reported_revision == revision


def _matching_active_execution(items: object, row: dict, *keys: str) -> bool:
    return isinstance(items, list) and any(
        isinstance(item, dict)
        and all(str(item.get(key, "")) == str(row.get(key, "")) for key in keys)
        and _reported_execution_matches(item, int(row.get("execution_revision") or 0))
        for item in items
    )


async def _adopt_reported_agent_work(agent_id: str, agent: AgentInfo, hello: dict) -> list[dict]:
    """Finish execution ownership transfer before welcome releases publishers."""
    kinds = (
        ("scan", "scans", "active_scans", ("scan_id",)),
        ("fp_review", "fp_reviews", "active_fp_reviews", ("scan_id", "review_id")),
        ("validation", "validations", "active_validations", ("scan_id", "vuln_index")),
    )
    if not any(hello.get(active) for _, _, active, _ in kinds):
        return []
    store = get_scan_store()
    inflight = await run_store_call(store, "list_agent_inflight_executions", agent.agent_key, agent_id)
    accepted_scans: list[dict] = []
    for kind, collection, active, keys in kinds:
        for row in inflight.get(collection, []):
            if not _matching_active_execution(hello.get(active), row, *keys):
                continue
            previous = str(row.get("execution_agent_session_id") or "")
            adopted = previous == agent.agent_session_id
            if not adopted:
                adopted = await run_store_call(
                    store, "adopt_active_execution", kind,
                    str(row["review_id"] if kind == "fp_review" else row["scan_id"]),
                    int(row["vuln_index"]) if kind == "validation" else None,
                    previous_session_id=previous,
                    agent_session_id=agent.agent_session_id,
                    execution_revision=int(row.get("execution_revision") or 0),
                )
            if adopted and kind == "scan":
                accepted_scans.append({
                    "scan_id": row["scan_id"],
                    "execution_revision": int(row.get("execution_revision") or 0),
                })
    return accepted_scans


async def _recover_missing_agent_work(
    agent_id: str,
    agent: AgentInfo,
    hello: dict,
    *,
    server_url: str,
) -> None:
    """Resume durable non-terminal work missing from this Agent process."""
    store = get_scan_store()
    inflight = await run_store_call(
        store,
        "list_agent_inflight_executions",
        agent.agent_key,
        agent_id,
    )
    active_scans = {
        (str(row["scan_id"]),) for row in inflight.get("scans", [])
        if _matching_active_execution(hello.get("active_scans"), row, "scan_id")
    }
    active_fp = {
        (str(row["scan_id"]), str(row["review_id"])) for row in inflight.get("fp_reviews", [])
        if _matching_active_execution(hello.get("active_fp_reviews"), row, "scan_id", "review_id")
    }
    active_validations = _reported_work_ids(
        hello.get("active_validations"),
        "scan_id",
        "vuln_index",
    )
    pending = (
        hello.get("pending_terminal_reports")
        if isinstance(hello.get("pending_terminal_reports"), dict)
        else {}
    )
    pending_scans = {
        (str(scan_id),)
        for scan_id in pending.get("scans", [])
        if str(scan_id or "")
    }
    if "scan_executions" in pending:
        pending_scans = {
            (str(row["scan_id"]),) for row in inflight.get("scans", [])
            if _matching_active_execution(pending["scan_executions"], row, "scan_id")
        }
    pending_fp = _reported_work_ids(
        pending.get("fp_reviews"),
        "scan_id",
        "review_id",
    )
    pending_validations = _reported_work_ids(
        pending.get("validations"),
        "scan_id",
        "vuln_index",
    )

    async def adopt(kind: str, work_id: str, sub_id: int | None, row: dict) -> None:
        previous_session = str(row.get("execution_agent_session_id") or "")
        if previous_session == agent.agent_session_id:
            return
        await run_store_call(
            store,
            "adopt_active_execution",
            kind,
            work_id,
            sub_id,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
            execution_revision=int(row.get("execution_revision") or 0),
        )

    async def recovery_failed(kind: str, work_id: str, scan_id: str, revision: int, exc: Exception) -> None:
        detail = str(exc.detail if isinstance(exc, HTTPException) else exc) or type(exc).__name__
        error = AGENT_RECOVERY_FAILED_PREFIX + detail[:500]
        changed = await run_store_call(
            store, "fail_scan_recovery" if kind == "scan" else "fail_fp_review_recovery", work_id,
            agent_session_id=agent.agent_session_id, execution_revision=revision, error_message=error,
        )
        logger.warning(
            "Agent recovery failed kind=%s id=%s session=%s revision=%s persisted=%s reason=%s",
            kind, work_id, agent.agent_session_id, revision, changed, detail,
        )
        if not changed:
            return
        from backend.sse import publish

        if kind == "scan":
            cached = _running_scans.get(scan_id)
            if cached is not None and cached.execution_revision == revision:
                _running_scans.pop(scan_id, None)
                _scan_owners.pop(scan_id, None)
            loaded = await run_store_call(store, "load_scan_runtime", scan_id)
            if loaded is not None:
                scan = loaded[0]
                publish(scan_id, "scan_status", {
                    "execution_revision": scan.execution_revision,
                    "status": scan.status, "error_message": scan.error_message,
                    "opencode_pool": scan.opencode_pool.model_dump(mode="json") if scan.opencode_pool else None,
                })
        else:
            publish(scan_id, "fp_review_finish", {
                "review_id": work_id, "execution_revision": revision,
                "status": "error", "error_message": error,
            })

    for row in inflight.get("scans", []):
        scan_id = str(row.get("scan_id") or "")
        identity = (scan_id,)
        if identity in active_scans:
            await adopt("scan", scan_id, None, row)
            continue
        if identity in pending_scans:
            logger.info(
                "Deferring scan recovery while its terminal outbox report is pending: %s",
                scan_id,
            )
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_scan_for_agent_recovery",
            scan_id,
            previous_session_id=previous_session,
            agent_id=agent_id,
            agent_session_id=agent.agent_session_id,
            error_message=AGENT_RECOVERY_IN_PROGRESS,
            expected_revision=int(row.get("execution_revision") or 0),
        )
        if revision is None:
            continue
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        from backend.api.scan import _continue_scan

        try:
            await _continue_scan(
                scan_id,
                None,
                User(
                    user_id=meta.user_id or agent.user_id,
                    username="agent-recovery",
                    role="admin",
                ),
                server_url_override=server_url,
                skip_owner_check=True,
                claimed_execution_revision=revision,
            )
            logger.warning(
                "Automatically resumed orphaned scan %s after Agent process restart "
                "session=%s revision=%d",
                scan_id,
                agent.agent_session_id,
                revision,
            )
        except Exception as exc:
            await recovery_failed("scan", scan_id, scan_id, revision, exc)

    for row in inflight.get("fp_reviews", []):
        scan_id = str(row.get("scan_id") or "")
        review_id = str(row.get("review_id") or "")
        identity = (scan_id, review_id)
        if identity in active_fp:
            await adopt("fp_review", review_id, None, row)
            continue
        if identity in pending_fp:
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_fp_review_for_agent_recovery",
            review_id,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
        )
        if revision is None:
            continue
        from backend.api.scan import _start_fp_review

        try:
            result = await _start_fp_review(
                scan_id,
                server_url,
                raise_on_error=True,
                require_unresolved=True,
                claimed_execution_revision=revision,
            )
            if result is None:
                raise RuntimeError("去误报恢复未启动，请再次续扫")
            logger.warning(
                "Automatically resumed orphaned FP review %s revision=%d",
                review_id,
                revision,
            )
        except Exception as exc:
            await recovery_failed("fp_review", review_id, scan_id, revision, exc)

    for row in inflight.get("validations", []):
        scan_id = str(row.get("scan_id") or "")
        vuln_index = int(row.get("vuln_index") or 0)
        identity = (scan_id, str(vuln_index))
        if identity in active_validations:
            await adopt("validation", scan_id, vuln_index, row)
            continue
        if identity in pending_validations:
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_validation_for_agent_recovery",
            scan_id,
            vuln_index,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
        )
        if revision is None:
            continue
        from backend.api.scan import _trigger_vulnerability_validation

        try:
            await _trigger_vulnerability_validation(
                scan_id,
                vuln_index,
                server_url,
                claimed_execution_revision=revision,
            )
            logger.warning(
                "Automatically resumed orphaned validation %s#%d revision=%d",
                scan_id,
                vuln_index,
                revision,
            )
        except Exception:
            logger.exception(
                "Automatic vulnerability validation recovery failed for %s#%d",
                scan_id,
                vuln_index,
            )


def _run_reconnect_helper(coroutine):
    """Keep the established synchronous test/maintenance helper contract."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    raise RuntimeError("Use the async reconnect helper from an event loop")


def _reattach_active_agent_scans(
    agent_id: str,
    agent: AgentInfo,
    active_scans: list,
    pending_stops: list[dict] | None = None,
) -> list[str]:
    return _run_reconnect_helper(
        _reattach_active_agent_scans_async(
            agent_id,
            agent,
            active_scans,
            pending_stops,
        )
    )


def _reattach_active_fp_reviews(
    agent_id: str,
    agent: AgentInfo,
    active_fp_reviews: list,
) -> None:
    return _run_reconnect_helper(
        _reattach_active_fp_reviews_async(agent_id, agent, active_fp_reviews)
    )


def _reattach_active_validations(
    agent_id: str,
    agent: AgentInfo,
    active_validations: list,
) -> list[dict]:
    return _run_reconnect_helper(
        _reattach_active_validations_async(agent_id, agent, active_validations)
    )


def _websocket_server_url(websocket: WebSocket) -> str:
    server_url = str(getattr(websocket, "base_url", "http://localhost/")).rstrip("/")
    if server_url.startswith("ws://"):
        return "http://" + server_url[len("ws://"):]
    if server_url.startswith("wss://"):
        return "https://" + server_url[len("wss://"):]
    return server_url


async def _promote_final_callback_agent_reports(
    agent_id: str,
    agent: AgentInfo,
    reattached_scan_ids: list[str],
) -> tuple[list[str], dict[str, list[int]]]:
    """Make callback reports from an upgraded Agent immediately actionable."""
    store = get_scan_store()
    provisional_scan_ids = await run_store_call(
        store,
        "list_provisional_scan_ids_for_agent",
        agent.agent_key,
    )
    candidate_scan_ids = list(dict.fromkeys([
        *reattached_scan_ids,
        *provisional_scan_ids,
    ]))
    recoverable_scan_ids: list[str] = []
    promoted_by_scan: dict[str, list[int]] = {}
    if not candidate_scan_ids:
        return recoverable_scan_ids, promoted_by_scan

    from backend.sse import publish

    for scan_id in candidate_scan_ids:
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None or not agent.agent_key or meta.agent_key != agent.agent_key:
            continue
        if (
            meta.agent_id
            and meta.agent_id != agent_id
            and meta.agent_id in _agent_ws
        ):
            logger.info(
                "Deferred provisional vulnerability promotion for scan %s: "
                "the previous Agent session is still connected",
                scan_id,
            )
            continue

        promoted_indexes = await run_store_call(
            store,
            "promote_provisional_vulnerability_indexes",
            scan_id,
        )
        recoverable_scan_ids.append(scan_id)
        if not promoted_indexes:
            continue

        vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
        live_scan = _running_scans.get(scan_id)
        if live_scan is not None:
            live_scan.vulnerabilities = vulnerabilities
        promoted_by_scan[scan_id] = promoted_indexes
        publish(scan_id, "scan_vulnerabilities_changed", {
            "count": len(vulnerabilities),
        })
        logger.info(
            "Promoted %d callback-reported vulnerability result(s) after Agent "
            "upgrade: agent_key=%s scan_id=%s",
            len(promoted_indexes),
            agent.agent_key,
            scan_id,
        )
    return recoverable_scan_ids, promoted_by_scan


async def _resume_final_callback_downstream(
    agent: AgentInfo,
    scan_ids: list[str],
    promoted_by_scan: dict[str, list[int]],
    *,
    server_url: str,
) -> None:
    """Resume unresolved FP review and validation after the upgraded handshake."""
    if not scan_ids:
        return
    from backend.api.scan import (
        _scan_fp_review_settings,
        _start_fp_review,
        _trigger_vulnerability_validation,
    )

    store = get_scan_store()
    for scan_id in scan_ids:
        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            continue
        scan, meta = loaded
        if not agent.agent_key or meta.agent_key != agent.agent_key:
            continue
        explicitly_stopped = (
            scan.status == ScanItemStatus.CANCELLED
            and not _is_infrastructure_interruption(
                scan.status,
                scan.error_message,
            )
        )
        if explicitly_stopped:
            continue

        auto_fp_review, _method = _scan_fp_review_settings(scan_id, scan)
        if auto_fp_review:
            try:
                await _start_fp_review(
                    scan_id,
                    server_url,
                    raise_on_error=False,
                    require_unresolved=True,
                    allow_cancelled=False,
                )
            except Exception as exc:
                logger.warning(
                    "Unable to resume automatic FP review after Agent upgrade "
                    "for scan %s: %s",
                    scan_id,
                    exc,
                )

        validation_config = meta.vulnerability_validation
        if (
            validation_config is None
            or not validation_config.enabled
            or not meta.product
        ):
            continue
        existing_validation_indexes = {
            item.vuln_index for item in scan.validations
        }
        for vuln_index in promoted_by_scan.get(scan_id, []):
            if vuln_index in existing_validation_indexes:
                continue
            if vuln_index < 0 or vuln_index >= len(scan.vulnerabilities):
                continue
            vulnerability = scan.vulnerabilities[vuln_index]
            if not (
                vulnerability.confirmed
                or vulnerability.ai_verdict == "confirmed"
            ):
                continue
            try:
                await _trigger_vulnerability_validation(
                    scan_id,
                    vuln_index,
                    server_url,
                )
            except Exception as exc:
                logger.warning(
                    "Unable to resume vulnerability validation after Agent "
                    "upgrade for scan %s index %d: %s",
                    scan_id,
                    vuln_index,
                    exc,
                )


async def _ensure_running_scan(scan_id: str) -> ScanStatus | None:
    """Load a recoverable scan into memory when events arrive after restart."""
    scan = _running_scans.get(scan_id)
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    if scan is not None and not distributed:
        return scan

    # Other PostgreSQL workers may have resumed or finished this scan. Runtime
    # rows are small; never reuse a worker's old lifecycle/counters as truth.
    loaded = await run_store_call(
        store,
        "load_scan_runtime" if distributed else "load_scan",
        scan_id,
    )
    if loaded is None:
        _running_scans.pop(scan_id, None)
        return None

    cached = scan
    scan, meta = loaded[:2]
    if cached is not None and cached.execution_revision == scan.execution_revision:
        # Runtime reads omit separately loaded results. Keep those collections
        # within the same execution while refreshing lifecycle and counters.
        for field in (
            "candidates", "vulnerabilities", "skill_reports", "threat_analysis",
            "threat_audit_tasks", "validations", "events",
        ):
            setattr(scan, field, getattr(cached, field))
    if not _is_infrastructure_interruption(scan.status, scan.error_message):
        _running_scans.pop(scan_id, None)
        return None

    if scan.status not in _RUNNING_SCAN_STATUSES:
        scan.status = _best_running_status(scan.total_candidates, scan.static_analysis_done)
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        scan.error_message = None
        scan.current_candidate = None

    scan.agent_name = meta.agent_name
    if distributed:
        scan.agent_online = True
    elif meta.agent_name:
        scan.agent_online = is_agent_name_online(meta.agent_name)
    _running_scans[scan_id] = scan
    if meta.user_id:
        _scan_owners[scan_id] = meta.user_id
    return scan


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

    def task_revision(task: dict) -> int:
        try:
            return max(1, int(task.get("revision") or 1))
        except (TypeError, ValueError):
            return 1

    previous_tasks = previous.completed_tasks if previous is not None else []
    for task in [*previous_tasks, *merged.completed_tasks]:
        key = task_key(task)
        item = dict(task)
        if key in index_by_key:
            previous_item = ordered[index_by_key[key]]
            previous_revision = task_revision(previous_item)
            current_revision = task_revision(item)
            if current_revision < previous_revision:
                continue
            if current_revision == previous_revision:
                previous_events = previous_item.get("session_events")
                current_events = item.get("session_events")
                if (
                    isinstance(previous_events, list)
                    and (
                        not isinstance(current_events, list)
                        or len(previous_events) > len(current_events)
                    )
                ):
                    item["session_events"] = previous_events
                preserved_fields = ["serve_session_id"]
                if item.get("outcome") != "success":
                    preserved_fields.extend(("failure_kind", "failure_reason"))
                for field in preserved_fields:
                    if not item.get(field) and previous_item.get(field):
                        item[field] = previous_item[field]
            ordered[index_by_key[key]] = item
        else:
            index_by_key[key] = len(ordered)
            ordered.append(item)
    merged.completed_tasks = ordered
    reported_completed_count = current.completed_task_count
    merged.completed_task_count = max(
        len(ordered),
        reported_completed_count,
        previous.completed_task_count if previous is not None else 0,
    )
    current_outstanding = max(current.total_tasks - reported_completed_count, 0)
    merged.total_tasks = max(
        previous.total_tasks if previous is not None else 0,
        merged.completed_task_count + current_outstanding,
    )
    return merged


# ---------------------------------------------------------------------------
# WebSocket — preferred connection method (v2)
# ---------------------------------------------------------------------------


async def _mark_agent_scans_cancelled_async(agent_id: str) -> None:
    """Mark all running scans belonging to this agent as CANCELLED.

    Called when an agent disconnects so the frontend shows the correct state.
    """
    store = get_scan_store()
    cancelled_scan_ids = set(
        await run_store_call(
            store,
            "mark_agent_scans_cancelled",
            agent_id,
            AGENT_DISCONNECT_ERROR,
        )
    )
    fp_review_count = await run_store_call(
        store,
        "mark_fp_reviews_for_agent_error",
        agent_id,
        AGENT_DISCONNECT_ERROR,
    )

    stale_local_scan_ids: set[str] = set()
    for scan_id in list(_running_scans):
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        if meta.agent_id != agent_id:
            continue
        if scan_id in cancelled_scan_ids:
            scan = _running_scans.get(scan_id)
            if scan is not None:
                scan.status = ScanItemStatus.CANCELLED
                scan.error_message = AGENT_DISCONNECT_ERROR
                scan.current_candidate = None
                scan.opencode_pool = _terminal_opencode_pool_status(
                    scan.opencode_pool,
                )
            continue
        loaded = await run_store_call(store, "load_scan_runtime", scan_id)
        if loaded is not None and loaded[0].status not in _RUNNING_SCAN_STATUSES:
            stale_local_scan_ids.add(scan_id)

    for scan_id in cancelled_scan_ids | stale_local_scan_ids:
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    if cancelled_scan_ids:
        from backend.sse import publish

        refreshed = await asyncio.gather(*(
            run_store_call(store, "load_scan_runtime", scan_id)
            for scan_id in sorted(cancelled_scan_ids)
        ))
        for scan_id, loaded in zip(sorted(cancelled_scan_ids), refreshed):
            persisted = loaded[0] if loaded is not None else None
            publish(scan_id, "scan_status", {
                "execution_revision": persisted.execution_revision if persisted else 0,
                "status": ScanItemStatus.CANCELLED,
                "error_message": AGENT_DISCONNECT_ERROR,
                "opencode_pool": (
                    persisted.opencode_pool.model_dump(mode="json")
                    if persisted is not None and persisted.opencode_pool is not None
                    else None
                ),
            })

    if cancelled_scan_ids or fp_review_count:
        logger.info(
            "Agent %s disconnect cancelled %d scan(s) and %d FP review job(s)",
            agent_id,
            len(cancelled_scan_ids),
            fp_review_count,
        )


def _mark_agent_scans_cancelled(agent_id: str) -> None:
    return _run_reconnect_helper(_mark_agent_scans_cancelled_async(agent_id))


@router.websocket("/ws")
async def agent_websocket(websocket: WebSocket) -> None:
    """Agent connects here and receives task/stop/resume commands."""
    await websocket.accept()
    agent_id = None
    recovery_task: asyncio.Task | None = None
    try:
        msg = await websocket.receive_json()
        if msg.get("type") != "hello":
            await websocket.close(code=4000)
            return

        name = str(msg.get("name") or socket.gethostname()).strip()
        machine_name = str(msg.get("machine_name") or name or socket.gethostname()).strip()
        owner_token = msg.get("owner_token", "")
        offered_protocols = msg.get("protocol_versions")
        if not isinstance(offered_protocols, list):
            offered_protocols = [1]
        protocol_version = 2 if 2 in offered_protocols else 1
        reported_capabilities = (
            msg.get("capabilities")
            if isinstance(msg.get("capabilities"), dict)
            else {}
        )
        final_vulnerability_callbacks = (
            reported_capabilities.get(
                _FINAL_VULNERABILITY_CALLBACKS_CAPABILITY,
            )
            is True
        )
        incremental_opencode_task_reports = (
            reported_capabilities.get(
                _INCREMENTAL_OPENCODE_TASK_REPORTS_CAPABILITY,
            )
            is True
        )
        agent_id = uuid.uuid4().hex
        ip = websocket.client.host if websocket.client else "unknown"
        now = datetime.now(timezone.utc).isoformat()

        # Resolve owner_token to user_id
        user_id = ""
        if owner_token:
            store = get_scan_store()
            owner = await run_store_call(
                store,
                "get_user_by_agent_token",
                owner_token,
            )
            if owner:
                user_id = owner.user_id

        reported_catalog = msg.get("validator_catalog")
        try:
            catalog = (
                AgentValidatorCatalog(**reported_catalog)
                if isinstance(reported_catalog, dict)
                else AgentValidatorCatalog()
            )
        except Exception as exc:
            catalog = AgentValidatorCatalog(errors=[str(exc)])
        reported_config = msg.get("config")
        try:
            initial_config = (
                AgentRemoteConfig(**reported_config)
                if isinstance(reported_config, dict)
                else AgentRemoteConfig()
            )
            _validate_managed_config(initial_config, catalog)
        except Exception as exc:
            logger.warning(
                "Ignoring invalid config reported by agent %s: %s",
                name,
                exc,
            )
            initial_config = AgentRemoteConfig()

        store = get_scan_store()
        existing = await run_store_call(
            store,
            "find_agent_record",
            user_id,
            ip,
            machine_name,
        )
        if existing is None:
            # A newly registered client always starts without model capacity.
            # Other reported settings are retained, while existing stable
            # records continue using their persisted model pool on reconnect.
            initial_config.model_pool.models = []
        stable_key = str(existing.get("agent_key") or "") if existing else uuid.uuid4().hex
        record = await run_store_call(
            store,
            "upsert_agent_record",
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
        reported_runtime_hash = str(msg.get("runtime_hash") or "")
        update_target_hash = str(record.get("runtime_update_target_hash") or "")
        if (
            _runtime_update_status(record)
            and update_target_hash
            and reported_runtime_hash == update_target_hash
        ):
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                stable_key,
                status="",
            )
            record = (
                await run_store_call(store, "get_agent_record", stable_key)
                or record
            )
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
            runtime_hash=reported_runtime_hash,
            agent_session_id=str(msg.get("agent_session_id") or agent_id),
            runtime_update_status=_runtime_update_status(record),
            runtime_update_target_hash=str(
                record.get("runtime_update_target_hash") or ""
            ),
            runtime_update_error=str(record.get("runtime_update_error") or ""),
            accepting_tasks=_runtime_update_status(record) != _RUNTIME_UPDATE_UPDATING,
            protocol_version=protocol_version,
        )
        _registered_agents[agent_id] = agent_info
        _agent_ws[agent_id] = websocket
        _agent_ws_locks[agent_id] = asyncio.Lock()
        if getattr(store, "distributed", False):
            from backend.distributed import WORKER_ID

            await run_store_call(
                store,
                "register_agent_session",
                agent_info,
                WORKER_ID,
            )

        pending_scan_stops: list[dict] = []
        reattached_scan_ids = await _reattach_active_agent_scans_async(
            agent_id,
            agent_info,
            msg.get("active_scans") or [],
            pending_scan_stops,
        )
        await _reattach_active_fp_reviews_async(
            agent_id,
            agent_info,
            msg.get("active_fp_reviews") or [],
        )
        pending_validation_stops = await _reattach_active_validations_async(
            agent_id,
            agent_info,
            msg.get("active_validations") or [],
        )
        recovery_scan_ids: list[str] = []
        promoted_by_scan: dict[str, list[int]] = {}
        if final_vulnerability_callbacks:
            recovery_scan_ids, promoted_by_scan = (
                await _promote_final_callback_agent_reports(
                    agent_id,
                    agent_info,
                    reattached_scan_ids,
                )
            )

        accepted_scan_executions = await _adopt_reported_agent_work(agent_id, agent_info, msg)
        await _send_agent_json(agent_id, {
            "type": "welcome",
            "agent_id": agent_id,
            "agent_key": stable_key,
            "config": cfg.model_dump(),
            "protocol_version": protocol_version,
            "scan_executions": accepted_scan_executions,
            "capabilities": {
                "candidate_batches": protocol_version >= 2,
                "event_batches": protocol_version >= 2,
                "lightweight_finish": protocol_version >= 2,
                "resume_manifest": protocol_version >= 2,
                "incremental_validation_output": reported_capabilities.get("incremental_validation_output") is True,
                "incremental_opencode_task_reports": (
                    incremental_opencode_task_reports
                ),
            },
        })
        for command in pending_scan_stops:
            await send_agent_command(agent_id, command)
        for command in pending_validation_stops:
            await send_agent_command(agent_id, command)
        async def recover_after_welcome() -> None:
            try:
                await _recover_missing_agent_work(
                    agent_id, agent_info, msg,
                    server_url=_websocket_server_url(websocket),
                )
                if final_vulnerability_callbacks:
                    await _resume_final_callback_downstream(
                        agent_info, recovery_scan_ids, promoted_by_scan,
                        server_url=_websocket_server_url(websocket),
                    )
            except Exception:
                logger.exception("Agent reconnect recovery failed for %s", agent_id)

        # Recovery can issue stop RPCs; their replies and heartbeats must be
        # received while recovery awaits them.
        recovery_task = asyncio.create_task(recover_after_welcome())

        logger.info("Agent connected via WebSocket: %s (%s) user=%s", agent_id, name, user_id or "(none)")

        # Keep connection alive; agent sends application-level heartbeats.
        while True:
            incoming = await websocket.receive_json()
            if isinstance(incoming, dict) and incoming.get("type") == "heartbeat":
                # Heartbeat health is independent from persistence latency: update
                # memory, ACK immediately, then coalesce the durable write.
                _touch_agent(agent_id, persist=False)
                await _send_agent_json(agent_id, {"type": "heartbeat_ack"})
                _schedule_agent_touch_persistence(agent_id)
                continue
            _touch_agent(agent_id)
            response_waiters = (
                _AGENT_RESPONSE_WAITERS.get(str(incoming.get("type") or ""))
                if isinstance(incoming, dict)
                else None
            )
            if response_waiters is not None:
                await _complete_agent_response(incoming, response_waiters)
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
        if recovery_task is not None:
            recovery_task.cancel()
            await asyncio.gather(recovery_task, return_exceptions=True)
        if agent_id:
            store = get_scan_store()
            if getattr(store, "distributed", False):
                try:
                    await run_store_call(
                        store,
                        "unregister_agent_session",
                        agent_id,
                    )
                except Exception:
                    logger.exception("Failed to unregister Agent session %s", agent_id)
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
        store = get_scan_store()
        if getattr(store, "distributed", False):
            command_id = await run_store_call(
                store,
                "enqueue_agent_command",
                agent_id,
                command,
            )
            return command_id is not None
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


async def request_agent_scan_stop(
    agent_id: str, scan_id: str, *, execution_revision: int | None = None,
) -> dict | None:
    """Request a scan stop and wait briefly for the Agent to confirm quiescence."""
    request_id = uuid.uuid4().hex
    waiter = asyncio.get_running_loop().create_future()
    _scan_stop_waiters[request_id] = waiter
    try:
        command = {
            "type": "stop",
            "request_id": request_id,
            "scan_id": scan_id,
        }
        if execution_revision is not None:
            command["execution_revision"] = execution_revision
        sent = await send_agent_command(agent_id, command)
        if not sent:
            logger.warning(
                "Unable to deliver scan stop request %s to agent %s for scan %s",
                request_id,
                agent_id,
                scan_id,
            )
            return None
        incoming = await _wait_agent_response(
            request_id,
            waiter,
            timeout=_SCAN_STOP_RPC_TIMEOUT_SECONDS,
        )
        if not isinstance(incoming, dict):
            return None
        if str(incoming.get("scan_id") or "") != str(scan_id):
            logger.warning(
                "Agent %s returned mismatched scan stop response %s for scan %s",
                agent_id,
                request_id,
                scan_id,
            )
            return None
        if (
            execution_revision is not None
            and "execution_revision" in incoming
            and incoming["execution_revision"] != execution_revision
        ):
            return None
        return incoming
    except asyncio.TimeoutError:
        logger.warning(
            "Timed out waiting for scan stop response from agent %s for scan %s",
            agent_id,
            scan_id,
        )
        return None
    except Exception as exc:
        logger.warning(
            "Failed waiting for scan stop response from agent %s for scan %s: %s",
            agent_id,
            scan_id,
            exc,
        )
        return None
    finally:
        _scan_stop_waiters.pop(request_id, None)


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
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if status.agent_session_id and status.agent_session_id != agent.agent_session_id:
        raise HTTPException(status_code=409, detail="stale Agent session")
    status.agent_name = agent.name
    status.agent_session_id = status.agent_session_id or agent.agent_session_id
    _agent_opencode_pool_latest[agent_id] = status
    store = get_scan_store()
    if hasattr(store, "upsert_agent_opencode_pool_status"):
        await run_store_call(
            store,
            "upsert_agent_opencode_pool_status",
            agent_name=agent.agent_key or agent.name,
            user_id=agent.user_id,
            agent_session_id=status.agent_session_id,
            status=status,
        )
    if hasattr(store, "upsert_agent_opencode_token_usage") and agent.agent_key:
        await run_store_call(
            store,
            "upsert_agent_opencode_token_usage",
            agent_key=agent.agent_key,
            user_id=agent.user_id,
            agent_session_id=status.agent_session_id,
            status=status,
        )
    return {"ok": True}


@router.post("/{agent_id}/opencode-task-report")
async def report_agent_opencode_task(
    agent_id: str,
    body: OpenCodeTaskReport,
) -> dict:
    """Persist one terminal logical task without resending prior Session history."""
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "agent_not_found", "agent_id": agent_id},
        )
    store = get_scan_store()
    loaded = await run_store_call(store, "get_scan_identity", body.scope_id)
    if loaded is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "scan_not_found",
                "scan_id": body.scope_id,
                "endpoint": "opencode-task-report",
            },
        )
    try:
        inserted = await run_store_call(
            store,
            "upsert_opencode_task_report",
            agent_key=agent.agent_key or agent.name,
            scan_id=body.scope_id,
            agent_session_id=body.agent_session_id or agent.agent_session_id,
            task_id=body.task_id,
            revision=body.revision,
            task=body.task,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    status = await run_store_call(store, "get_opencode_pool_status", body.scope_id)
    scan = _running_scans.get(body.scope_id)
    if scan is not None and status is not None:
        scan.opencode_pool = status
    if inserted:
        from backend.sse import publish

        publish(body.scope_id, "opencode_task_report", {
            "task_id": body.task_id,
            "revision": body.revision,
            "completed_task_count": status.completed_task_count if status else 0,
            "total_tasks": status.total_tasks if status else 0,
        })
    return {"ok": True, "duplicate": not inserted}


@router.get("/{agent_id}/opencode-pool", response_model=AgentOpenCodePoolStatus)
async def get_agent_opencode_pool(
    agent_id: str,
    current_user: User = Depends(get_current_user),
) -> AgentOpenCodePoolStatus:
    """Return persisted per-model usage for one Agent plus current active tasks."""
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    online = (
        _is_agent_online(agent)
        if agent_id in _agent_ws
        else resolved is not None
    )
    store = get_scan_store()
    if hasattr(store, "get_agent_opencode_pool_status"):
        result = await run_store_call(
            store,
            "get_agent_opencode_pool_status",
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
    if hasattr(store, "get_agent_opencode_token_usage") and agent.agent_key:
        result.token_usage = await run_store_call(
            store,
            "get_agent_opencode_token_usage",
            agent_key=agent.agent_key,
            user_id=agent.user_id,
        )
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
                model.effective_weight = live.effective_weight
                model.health_penalty_level = live.health_penalty_level
                model.last_health_failure_at = live.last_health_failure_at
                model.last_health_failure_kind = live.last_health_failure_kind
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
                model.effective_weight = model.weight
                model.health_penalty_level = 0
                model.last_health_failure_at = ""
                model.last_health_failure_kind = ""
        known_ids = {model.id for model in result.models}
        for model in latest.models:
            if model.id not in known_ids:
                result.models.append(model.model_copy(deep=True))
        result.models.sort(key=lambda model: model.id)
        result.global_running = latest.global_running
        result.global_queued = latest.global_queued
        result.queued_tasks = latest.queued_tasks
        result.planned_tasks = latest.planned_tasks
        if result.token_usage is None:
            result.token_usage = latest.token_usage
        result.updated_at = latest.updated_at or result.updated_at
    if not online:
        for model in result.models:
            model.available = False
    return result


def _opencode_model_diagnostic(
    summary: str,
    *,
    stage: str,
    request_id: str,
    agent_id: str,
    agent: AgentInfo,
    elapsed_seconds: float,
    detail: str = "",
) -> str:
    """Build a user-facing, correlation-friendly model-listing diagnostic."""
    lines = [
        summary,
        f"阶段：{stage}",
        f"Agent：{agent.name or '(未命名)'}",
        f"稳定标识：{agent.agent_key or '(无)'}",
        f"当前会话：{agent_id}",
        f"请求编号：{request_id}",
        f"耗时：{max(0.0, elapsed_seconds):.1f} 秒",
    ]
    normalized_detail = str(detail or "").strip()
    if normalized_detail:
        lines.extend(("", "详细信息：", normalized_detail))
    return "\n".join(lines)


async def _request_agent_opencode_models(
    *,
    agent_id: str,
    agent: AgentInfo,
    refresh: bool,
) -> _AgentOpenCodeModelsResponse:
    request_id = uuid.uuid4().hex
    started_at = time.monotonic()
    waiter = asyncio.get_running_loop().create_future()
    _opencode_model_waiters[request_id] = waiter
    try:
        sent = await send_agent_command(agent_id, {
            "type": "opencode_models",
            "request_id": request_id,
            "refresh": refresh,
        })
        if not sent:
            raise HTTPException(
                status_code=502,
                detail=_opencode_model_diagnostic(
                    "无法向 Agent 发送 OpenCode Serve 模型读取请求",
                    stage="控制端向 Agent 派发请求",
                    request_id=request_id,
                    agent_id=agent_id,
                    agent=agent,
                    elapsed_seconds=time.monotonic() - started_at,
                    detail="Agent 连接可能刚刚断开；请确认 Agent 已重连后再次读取。",
                ),
            )
        result = await _wait_agent_response(
            request_id,
            waiter,
            timeout=_OPENCODE_MODEL_RPC_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            raise TypeError(
                f"Agent returned {type(result).__name__} instead of an object"
            )
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail=_opencode_model_diagnostic(
                "等待 Agent 返回 OpenCode Serve 模型列表超时",
                stage="等待 Agent 准备 Serve 并查询 Provider",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=time.monotonic() - started_at,
                detail=(
                    f"控制端已等待 {_OPENCODE_MODEL_RPC_TIMEOUT_SECONDS:.0f} 秒。"
                    "请查看 Agent 窗口中的 Serve 启动输出、端口占用和 Provider 配置；"
                    "确认 Agent 在线后可再次读取。"
                ),
            ),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "Failed while waiting for OpenCode models request %s from agent %s",
            request_id,
            agent_id,
        )
        raise HTTPException(
            status_code=502,
            detail=_opencode_model_diagnostic(
                "读取 Agent 返回的 OpenCode Serve 模型结果失败",
                stage="控制端接收或解析 Agent 响应",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=time.monotonic() - started_at,
                detail=(
                    f"错误类型：{type(exc).__name__}。"
                    "请在服务端日志中按请求编号查找完整异常。"
                ),
            ),
        ) from exc
    finally:
        _opencode_model_waiters.pop(request_id, None)

    elapsed_seconds = time.monotonic() - started_at
    ok = bool(result.get("ok"))
    message = str(result.get("message") or "")
    if not ok:
        message = _opencode_model_diagnostic(
            "Agent 读取 OpenCode Serve 模型列表失败",
            stage="Agent 准备 Serve 或查询 Provider",
            request_id=request_id,
            agent_id=agent_id,
            agent=agent,
            elapsed_seconds=elapsed_seconds,
            detail=message or "Agent 未返回具体错误信息。",
        )
    try:
        raw_models = result.get("models") or []
        if not isinstance(raw_models, list):
            raise TypeError(
                f"models is {type(raw_models).__name__}, expected list"
            )
        models = [
            _AgentOpenCodeModelInfo(**item)
            for item in raw_models
            if isinstance(item, dict)
        ]
    except Exception as exc:
        logger.exception(
            "Invalid OpenCode models response for request %s from agent %s",
            request_id,
            agent_id,
        )
        raise HTTPException(
            status_code=502,
            detail=_opencode_model_diagnostic(
                "Agent 返回的 OpenCode Serve 模型列表格式无效",
                stage="控制端校验模型列表",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=elapsed_seconds,
                detail=(
                    f"错误类型：{type(exc).__name__}。"
                    "请在服务端日志中按请求编号查找完整异常。"
                ),
            ),
        ) from exc
    return _AgentOpenCodeModelsResponse(ok=ok, message=message, models=models)


@public_router.get(
    "/api/agent-configs/{agent_key}/opencode-models",
    response_model=_AgentOpenCodeModelsResponse,
)
async def get_stable_agent_opencode_models(
    agent_key: str,
    refresh: bool = False,
    current_user: User = Depends(get_current_user),
) -> _AgentOpenCodeModelsResponse:
    """Resolve the Agent's current connection before listing Serve models."""
    store = get_scan_store()
    _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "无法读取 OpenCode Serve 模型列表\n"
                "阶段：解析 Agent 当前连接\n"
                f"稳定标识：{agent_key}\n\n"
                "详细信息：\nAgent 当前离线或正在重连，请等待其恢复在线后再次读取。"
            ),
        )
    return await _request_agent_opencode_models(
        agent_id=live[0],
        agent=live[1],
        refresh=refresh,
    )


@router.get("/{agent_id}/opencode/models", response_model=_AgentOpenCodeModelsResponse)
async def get_agent_opencode_models(
    agent_id: str,
    refresh: bool = False,
    current_user: User = Depends(get_current_user),
) -> _AgentOpenCodeModelsResponse:
    """Compatibility route for the current Agent session identifier."""
    live = await resolve_agent_id_connection_async(agent_id)
    if live is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Agent 会话不存在或已经失效。"
                "请刷新 Agent 列表，或改用稳定 agent_key 模型读取接口。"
            ),
        )
    agent = live[1]
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return await _request_agent_opencode_models(
        agent_id=live[0],
        agent=agent,
        refresh=refresh,
    )


@router.delete("/{agent_id}")
async def agent_unregister(agent_id: str) -> dict:
    """Agent calls this on graceful shutdown."""
    old_task = _agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()
    await _mark_agent_scans_cancelled_async(agent_id)
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
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    store = get_scan_store()
    if agent is None:
        record = _authorize_agent_record(
            await run_store_call(store, "get_agent_record", agent_id),
            current_user,
        )
        return _stored_agent_config(record)
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    record = (
        await run_store_call(store, "get_agent_record", agent.agent_key)
        if agent.agent_key
        else None
    )
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
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    _validate_managed_config(
        body,
        _stored_validator_catalog(record),
    )
    await run_store_call(
        store,
        "update_agent_config_record",
        agent_key,
        body.model_dump_json(),
    )
    _agent_configs[agent_key] = body
    logger.info("Config updated for stable agent %s", agent_key)
    live = await resolve_agent_connection_async(agent_key)
    if live is not None:
        await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True}


@public_router.get("/api/agent-configs/{agent_key}", response_model=AgentRemoteConfig)
async def get_stable_agent_config(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> AgentRemoteConfig:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    return _stored_agent_config(record)


@public_router.get(
    "/api/agent-configs/{agent_key}/opencode-usage",
    response_model=OpenCodeTokenUsage | None,
)
async def get_stable_agent_opencode_usage(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> OpenCodeTokenUsage | None:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    if not hasattr(store, "get_agent_opencode_token_usage"):
        return None
    return await run_store_call(
        store,
        "get_agent_opencode_token_usage",
        agent_key=agent_key,
        user_id=str(record.get("user_id") or ""),
    )


@public_router.put("/api/agent-configs/{agent_key}")
async def update_stable_agent_config(
    agent_key: str,
    body: AgentRemoteConfig,
    current_user: User = Depends(get_current_user),
) -> dict:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    _validate_managed_config(
        body,
        _stored_validator_catalog(record),
    )
    await run_store_call(
        store,
        "update_agent_config_record",
        agent_key,
        body.model_dump_json(),
    )
    _agent_configs[agent_key] = body
    live = await resolve_agent_connection_async(agent_key)
    applied = False
    if live is not None:
        applied = await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True, "applied": applied}


@public_router.post("/api/agent-configs/{agent_key}/runtime-update")
async def request_stable_agent_runtime_update(
    agent_key: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 当前离线，无法提交更新")

    target_hash = _agent_runtime_hash()
    if live[1].runtime_hash and live[1].runtime_hash == target_hash:
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status="",
        )
        return {
            "status": "up_to_date",
            "target_hash": target_hash,
            "message": "Agent 已是最新版本",
        }

    current_status = _runtime_update_status(record)
    current_target = str(record.get("runtime_update_target_hash") or "")
    if (
        current_status in _RUNTIME_UPDATE_ACTIVE_STATUSES
        and current_target == target_hash
    ):
        return {
            "status": current_status,
            "target_hash": target_hash,
            "message": (
                "Agent 正在更新"
                if current_status == _RUNTIME_UPDATE_UPDATING
                else "更新请求已在等待 Agent 空闲"
            ),
        }

    now = datetime.now(timezone.utc).isoformat()
    await run_store_call(
        store,
        "set_agent_runtime_update_record",
        agent_key,
        status=_RUNTIME_UPDATE_PENDING,
        target_hash=target_hash,
        server_url=str(request.base_url).rstrip("/"),
        requested_at=now,
    )
    logger.info(
        "Agent runtime update requested: agent_key=%s user=%s target=%s",
        agent_key,
        current_user.username,
        target_hash[:12],
    )
    return {
        "status": _RUNTIME_UPDATE_PENDING,
        "target_hash": target_hash,
        "message": "更新请求已提交，Agent 将在全部任务空闲后自动更新",
    }


async def _persist_mcp_probe(agent_key: str, result: AgentMcpProbeResult) -> None:
    lock = _mcp_probe_persist_locks.setdefault(agent_key, asyncio.Lock())
    async with lock:
        store = get_scan_store()
        record = await run_store_call(store, "get_agent_record", agent_key)
        payload: dict = {}
        if record is not None:
            try:
                parsed = json.loads(str(record.get("mcp_probe_json") or "{}"))
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                pass
        payload[result.target] = result.model_dump(mode="json")
        await run_store_call(
            store,
            "update_agent_mcp_probe_record",
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
    live = await resolve_agent_connection_async(agent_key)
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
        incoming = await _wait_agent_response(request_id, waiter, timeout=5.0)
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
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    config = _stored_agent_config(record)
    probes = _stored_mcp_probes(record)
    online = await resolve_agent_connection_async(agent_key) is not None
    live_runtime = await _request_agent_mcp_runtime(agent_key) if online else None
    return AgentMcpStatusResponse(
        agent_key=agent_key,
        online=online,
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
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    config = _stored_agent_config(record)
    mcp_config = _mcp_target_config(config, target)
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = await resolve_agent_connection_async(agent_key)
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
        incoming = await _wait_agent_response(request_id, waiter, timeout=5.0)
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
    mcp_config: AgentMcpConfig | None = None,
) -> AgentMcpProbeResult:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    transient = target in {"scan_code_graph", "scan_knowledge_base"}
    if transient:
        if target == "scan_code_graph":
            if mcp_config is None:
                raise HTTPException(status_code=400, detail="缺少扫描级 MCP 配置")
            if not mcp_config.enabled:
                raise HTTPException(status_code=400, detail="请先启用该扫描级 MCP 配置")
            mcp_config = _normalize_scan_code_graph_mcp(mcp_config)
        else:
            mcp_config = _normalize_scan_knowledge_base_mcp(
                enabled=True,
                require_project=False,
            )
    else:
        config = _stored_agent_config(record)
        mcp_config = _mcp_target_config(config, target)
    assert mcp_config is not None
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = await resolve_agent_connection_async(agent_key)
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
        "projects_tool": (
            mcp_config.projects_tool
            if target == "scan_knowledge_base"
            else ""
        ),
    })
    if not sent:
        _mcp_probe_waiters.pop(request_id, None)
        raise HTTPException(status_code=502, detail="Agent 连接已断开")

    wait_seconds = min(30, max(1, mcp_config.timeout_seconds)) + 5
    try:
        incoming = await _wait_agent_response(
            request_id,
            waiter,
            timeout=wait_seconds,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"等待 Agent MCP 检测结果超时（{wait_seconds} 秒）",
        )
    finally:
        _mcp_probe_waiters.pop(request_id, None)

    discovered_tool_names = {
        str(item).strip()
        for item in (incoming.get("tool_names") or [])
        if str(item).strip()
    }
    tool_names = sorted(item[:200] for item in discovered_tool_names)[:200]
    probe_success = bool(incoming.get("success"))
    probe_error = str(incoming.get("error") or "")[:2000]
    if target == "scan_knowledge_base" and probe_success:
        missing_controls = [
            name
            for name in (
                mcp_config.projects_tool,
                mcp_config.set_project_tool,
            )
            if name not in discovered_tool_names
        ]
        if missing_controls:
            probe_success = False
            probe_error = (
                "知识库缺少已配置的管理工具："
                + "、".join(missing_controls)
            )
        elif not discovered_tool_names.difference({
            mcp_config.projects_tool,
            mcp_config.set_project_tool,
        }):
            probe_success = False
            probe_error = "知识库未提供可供模型使用的查询工具"
    runtime_state = str(incoming.get("runtime_state") or "next_task")
    if runtime_state not in {"active", "reload_pending", "next_task"}:
        runtime_state = "next_task"

    def normalized_project(value: object) -> KnowledgeBaseProject | None:
        if not isinstance(value, dict):
            return None
        project_id = str(value.get("id") or "").strip()
        project_name = str(value.get("name") or "").strip()
        if not project_id or not project_name:
            return None
        return KnowledgeBaseProject(
            id=project_id[:200],
            name=project_name[:500],
            path=str(value.get("path") or "")[:4000],
            current=bool(value.get("current")),
        )

    projects: list[KnowledgeBaseProject] = []
    seen_project_ids: set[str] = set()
    for raw_project in incoming.get("projects") or []:
        project = normalized_project(raw_project)
        if project is None or project.id in seen_project_ids:
            continue
        seen_project_ids.add(project.id)
        projects.append(project)
        if len(projects) >= 1000:
            break
    result = AgentMcpProbeResult(
        target=target,
        config_fingerprint=_mcp_config_fingerprint(mcp_config),
        success=probe_success,
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
        error=probe_error,
        runtime_state=runtime_state,
        active_sessions=_nonnegative_int(incoming.get("active_sessions")),
        projects=(projects if probe_success else []),
        current_project=(
            normalized_project(incoming.get("current_project"))
            if probe_success
            else None
        ),
        session_project=(
            normalized_project(incoming.get("session_project"))
            if probe_success
            else None
        ),
    )
    if not transient:
        await _persist_mcp_probe(agent_key, result)
    return result


@public_router.get("/api/agent-configs/{agent_key}/validator-catalog", response_model=AgentValidatorCatalog)
async def get_stable_agent_validator_catalog(
    agent_key: str,
    product: str = "",
    current_user: User = Depends(get_current_user),
) -> AgentValidatorCatalog:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    catalog = _stored_validator_catalog(record)
    if not product.strip():
        return catalog
    return catalog.model_copy(update={
        "methods": [
            item for item in catalog.methods
            if product.strip() in item.products
        ],
    })


@public_router.get("/api/agent-configs/{agent_key}/validation-environments")
async def get_stable_agent_validation_environments(
    agent_key: str,
    product: str = "",
    current_user: User = Depends(get_current_user),
) -> dict:
    del agent_key, product, current_user
    raise HTTPException(
        status_code=410,
        detail="验证环境接口已废弃，请使用 validator-catalog 获取验证方法",
    )


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
    records = await run_store_call(
        store,
        "list_agent_records",
        None if current_user.role == "admin" else current_user.user_id,
    )
    shared_by_key: dict[str, tuple[str, AgentInfo]] = {}
    if getattr(store, "distributed", False):
        sessions = await run_store_call(
            store,
            "list_live_agent_sessions",
            _WEBSOCKET_AGENT_STALE_SECONDS,
        )
        for session in sessions:
            agent = _agent_info_from_shared_session(session)
            shared_by_key.setdefault(agent.agent_key, (agent.agent_id, agent))
    result = []
    known_keys: set[str] = set()
    for record in records:
        agent_key = str(record.get("agent_key") or "")
        local_live = _live_agent_for_key(agent_key)
        live = local_live or shared_by_key.get(agent_key)
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
            "online": bool(
                agent
                and (
                    _is_agent_online(agent)
                    if local_live is not None
                    else live is not None
                )
            ),
            "runtime_update_status": _runtime_update_status(record),
            "runtime_update_target_hash": str(
                record.get("runtime_update_target_hash") or ""
            ),
            "runtime_update_error": str(record.get("runtime_update_error") or ""),
            "accepting_tasks": (
                _runtime_update_status(record) != _RUNTIME_UPDATE_UPDATING
            ),
            "has_explicit_model": agent_config_has_explicit_model(
                _stored_agent_config(record)
            ),
        })
    # Keep legacy HTTP agents visible until they migrate to the stable catalog.
    for agent in _registered_agents.values():
        if agent.agent_key in known_keys:
            continue
        if current_user.role != "admin" and agent.user_id != current_user.user_id:
            continue
        compatibility_config = (
            _agent_configs.get(agent.agent_key)
            or _agent_configs.get(agent.name)
            or AgentRemoteConfig()
        )
        result.append({
            **agent.model_dump(),
            "online": _is_agent_online(agent),
            "has_explicit_model": agent_config_has_explicit_model(
                compatibility_config
            ),
        })
    return result


# ---------------------------------------------------------------------------
# Scan events / results (called by agent during scan execution)
# ---------------------------------------------------------------------------


def _apply_agent_event_to_scan(scan, event: ScanEvent) -> dict:
    progress_kwargs: dict = {}
    scan.events.append(event)
    if len(scan.events) > SCAN_EVENT_RETENTION_LIMIT:
        scan.events = scan.events[-SCAN_EVENT_RETENTION_LIMIT:]

    if event.phase == "init":
        if scan.status == ScanItemStatus.PENDING:
            progress_kwargs["status"] = ScanItemStatus.PENDING
    elif event.phase == "static_analysis":
        if scan.status == ScanItemStatus.PENDING:
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
    return progress_kwargs


def _publish_agent_event_state(
    scan_id: str, scan, events: list[ScanEvent], changes: dict,
) -> None:
    from backend.sse import publish

    if changes:
        publish(scan_id, "scan_status", {
            **changes,
            "execution_revision": scan.execution_revision,
        })
    for event in events:
        publish(scan_id, "scan_event", {"event": event.model_dump()})


@router.post("/scan/{scan_id}/event")
async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    """Agent pushes a progress event. Updates in-memory scan state and DB."""
    if is_agent_local_task_output(event.message):
        return {"ok": True, "discarded": True}

    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="event", store=store)
    if not await run_store_call(store, "add_event", scan_id, event):
        _scan_not_found(scan_id, endpoint="event", store=store)

    scan = await _ensure_running_scan(scan_id)
    if scan is None:
        return {"ok": True}

    progress_kwargs = _apply_agent_event_to_scan(scan, event)

    if progress_kwargs:
        await run_store_call(store, "update_scan_progress", scan_id, **progress_kwargs)

    _publish_agent_event_state(scan_id, scan, [event], progress_kwargs)

    return {"ok": True}


@router.post("/v2/scan/{scan_id}/events")
async def agent_scan_events_v2(
    scan_id: str,
    body: AgentScanEventBatch,
) -> dict:
    """Persist a bounded event chunk in one transaction and one progress write."""
    events = [
        event for event in body.events
        if not is_agent_local_task_output(event.message)
    ]
    if not events:
        return {"ok": True, "count": 0}
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="events", store=store)
    stored_count = await run_store_call(
        store,
        "add_events_batch",
        scan_id,
        events,
    )
    if stored_count != len(events):
        _scan_not_found(scan_id, endpoint="events", store=store)
    scan = await _ensure_running_scan(scan_id)
    if scan is None:
        return {"ok": True, "count": stored_count}
    progress_kwargs: dict = {}
    for event in events:
        progress_kwargs.update(_apply_agent_event_to_scan(scan, event))
    if progress_kwargs:
        await run_store_call(store, "update_scan_progress", scan_id, **progress_kwargs)
    _publish_agent_event_state(scan_id, scan, events, progress_kwargs)
    return {"ok": True, "count": stored_count}


def _existing_reported_vulnerability(
    vulnerabilities: list[Vulnerability],
    target: Vulnerability,
) -> tuple[int, Vulnerability] | None:
    """Find an already-persisted replay for any mining engine."""
    target_identity = vulnerability_report_identity(target)
    return next(
        (
            (index, existing)
            for index, existing in enumerate(vulnerabilities)
            if vulnerability_report_identity(existing) == target_identity
        ),
        None,
    )


def _stamp_vulnerability_engine(
    scan_id: str,
    vuln: Vulnerability,
    *,
    selections: list[MiningEngineSelection] | None = None,
) -> Vulnerability:
    if selections is None:
        loaded = get_scan_store().load_scan(scan_id)
        selections = (
            loaded[1].mining_engines
            if loaded is not None
            else []
        )
    requested_id = str(vuln.engine_id or "").strip()
    if (
        str(vuln.analysis_source or "").strip() == "threat_audit"
        and requested_id in {"", "static_candidate"}
    ):
        requested_id = "threat_audit"
    if not requested_id:
        requested_id = "static_candidate"

    if selections:
        selection = next(
            (
                item
                for item in selections
                if item.engine_id == requested_id and item.enabled
            ),
            None,
        )
        if selection is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    "漏洞结果来自未启用或未知的漏洞挖掘引擎："
                    f"{requested_id}"
                ),
            )
        vuln.engine_id = selection.engine_id
        vuln.engine_label = selection.engine_label
        return vuln

    vuln.engine_id = requested_id
    if requested_id == "threat_audit":
        vuln.engine_label = THREAT_AUDIT_ENGINE_LABEL
    elif not str(vuln.engine_label or "").strip():
        vuln.engine_label = STATIC_CANDIDATE_ENGINE_LABEL
    return vuln


def _static_candidate_run_status(scan) -> str:
    return next(
        (
            str(item.status or "")
            for item in scan.mining_engine_runs
            if item.engine_id == _STATIC_CANDIDATE_ENGINE_ID
        ),
        "",
    )


def _normalize_candidate_progress(
    scan,
    *,
    candidate_count: int,
    processed: int,
    reported_total: int | None = None,
) -> tuple[int, int]:
    """Apply the scan-level candidate counter invariants.

    Persisted candidate rows own both counters once available. Older scans may
    only have the legacy counter, so retain lifecycle reconciliation solely as
    a fallback when no candidate rows exist.
    """
    stored_total = max(0, int(scan.total_candidates or 0))
    candidate_count = max(0, int(candidate_count or 0))
    total = (
        candidate_count
        if candidate_count > 0
        else max(stored_total, max(0, int(reported_total or 0)))
    )
    completed = max(0, int(processed or 0))
    if candidate_count > 0:
        return total, min(completed, total)
    run_status = _static_candidate_run_status(scan)
    if total == 0:
        return 0, 0
    if run_status == "success":
        return total, total
    if run_status in {"pending", "running"} or (
        not run_status and scan.status == ScanItemStatus.AUDITING
    ):
        return total, min(completed, total - 1)
    return total, min(completed, total)


async def _reconcile_candidate_progress(
    scan_id: str,
    *,
    reported_processed: int | None = None,
    reported_total: int | None = None,
    publish_update: bool = True,
) -> tuple[int, int]:
    """Persist candidate-row progress and refresh the matching live execution."""
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        return max(0, int(reported_processed or 0)), max(
            0,
            int(reported_total or 0),
        )
    stored_scan, meta, counts = loaded
    live = _running_scans.get(scan_id)
    scan = stored_scan
    terminal_audit_count, processed_key_count = await asyncio.gather(
        run_store_call(store, "count_terminal_candidate_audits", scan_id),
        # Legacy Agents still checkpoint location tuples. New Agents use the
        # authoritative candidate row exclusively.
        run_store_call(store, "count_processed_keys", scan_id),
    )
    if int(counts["candidates"] or 0) > 0:
        raw_processed = terminal_audit_count
    else:
        raw_processed = max(
            processed_key_count,
            int(stored_scan.processed_candidates or 0),
            max(0, int(reported_processed or 0)),
        )
    total, processed = _normalize_candidate_progress(
        scan,
        candidate_count=counts["candidates"],
        processed=raw_processed,
        reported_total=reported_total,
    )
    progress = processed / total if total > 0 else scan.progress
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
        processed_candidates=processed,
        progress=progress,
    )
    scan.total_candidates = total
    scan.processed_candidates = processed
    scan.progress = progress
    if live is not None and live.execution_revision == meta.execution_revision:
        live.total_candidates = total
        live.processed_candidates = processed
        live.progress = progress
    if publish_update:
        from backend.sse import publish

        publish(scan_id, "scan_status", {
            "execution_revision": meta.execution_revision,
            "status": scan.status,
            "progress": scan.progress,
            "total_candidates": total,
            "processed_candidates": processed,
        })
    return processed, total


def _candidate_audit_state(vulnerability: Vulnerability) -> str:
    verdict = str(vulnerability.ai_verdict or "").strip().lower()
    return "failed" if verdict in {"failed", "timeout", "no_result"} else "success"


def _same_pattern_candidate_result(vulnerability: Vulnerability) -> Vulnerability:
    if str(vulnerability.ai_verdict or "").strip().lower() != "filtered_same_pattern":
        return vulnerability
    conclusion = (
        "候选点去重：同模式代表点已被 AI 审计为非问题，"
        "本候选未再次调用模型。"
    )
    return vulnerability.model_copy(update={
        "ai_analysis": conclusion,
        "failure_reason": conclusion,
    })


def _validated_mining_engine_run(
    meta: ScanMeta,
    body: MiningEngineRunStatus,
    *,
    terminal_only: bool = False,
) -> MiningEngineRunStatus:
    allowed_statuses = (
        _MINING_ENGINE_TERMINAL_STATUSES
        if terminal_only
        else _MINING_ENGINE_RUN_STATUSES
    )
    if body.status not in allowed_statuses:
        scope = "最终" if terminal_only else ""
        raise HTTPException(
            status_code=422,
            detail=f"无效的漏洞挖掘引擎{scope}状态：{body.status}",
        )
    selection = next(
        (
            item
            for item in meta.mining_engines
            if item.engine_id == body.engine_id and item.enabled
        ),
        None,
    )
    if meta.mining_engines and selection is None:
        raise HTTPException(
            status_code=422,
            detail=f"未知或未启用的漏洞挖掘引擎：{body.engine_id}",
        )
    if selection is not None:
        return body.model_copy(update={
            "engine_label": selection.engine_label,
        })
    return body


def _validated_threat_analysis_run(
    meta: ScanMeta,
    body: ThreatAnalysisRunStatus,
    *,
    terminal_only: bool = False,
) -> ThreatAnalysisRunStatus:
    allowed_statuses = (
        _THREAT_ANALYSIS_TERMINAL_STATUSES
        if terminal_only
        else _THREAT_ANALYSIS_RUN_STATUSES
    )
    if body.status not in allowed_statuses:
        scope = "最终" if terminal_only else ""
        raise HTTPException(
            status_code=422,
            detail=f"无效的威胁分析{scope}状态：{body.status}",
        )
    if not meta.threat_analysis_enabled:
        raise HTTPException(
            status_code=422,
            detail="本次扫描未启用威胁分析",
        )
    return body


@router.post("/scan/{scan_id}/mining-engine-run")
async def agent_report_mining_engine_run(
    scan_id: str,
    body: MiningEngineRunStatus,
) -> dict:
    """Agent reports one isolated mining-engine lifecycle state."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        _scan_not_found(
            scan_id,
            endpoint="mining-engine-run",
            store=store,
        )
    body = _validated_mining_engine_run(meta, body)
    runs = await run_store_call(store, "update_mining_engine_run", scan_id, body)
    if not runs:
        _scan_not_found(
            scan_id,
            endpoint="mining-engine-run",
            store=store,
        )
    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.mining_engine_runs = runs
    if body.engine_id == _STATIC_CANDIDATE_ENGINE_ID:
        await _reconcile_candidate_progress(
            scan_id,
        )
    from backend.sse import publish

    publish(scan_id, "mining_engine_run", {
        "run": body.model_dump(mode="json"),
        "runs": [item.model_dump(mode="json") for item in runs],
    })
    return {"ok": True, "run": body.model_dump(mode="json")}


@router.post("/scan/{scan_id}/threat-analysis-run")
async def agent_report_threat_analysis_run(
    scan_id: str,
    body: ThreatAnalysisRunStatus,
) -> dict:
    """Agent reports the standalone threat-analysis lifecycle state."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        _scan_not_found(
            scan_id,
            endpoint="threat-analysis-run",
            store=store,
        )
    body = _validated_threat_analysis_run(meta, body)
    stored = await run_store_call(
        store,
        "update_threat_analysis_run",
        scan_id,
        body,
    )
    if stored is None:
        _scan_not_found(
            scan_id,
            endpoint="threat-analysis-run",
            store=store,
        )
    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.threat_analysis_run = stored
    from backend.sse import publish

    publish(scan_id, "threat_analysis_run", {
        "run": stored.model_dump(mode="json"),
    })
    return {"ok": True, "run": stored.model_dump(mode="json")}


@router.post("/scan/{scan_id}/vulnerability")
async def agent_report_vulnerability(
    scan_id: str,
    vuln: Vulnerability,
    provisional: bool = False,
    report_batch_id: str = "",
    supports_fp_review_execution_revision: bool = False,
) -> dict:
    """Agent pushes a single vulnerability result immediately after auditing it."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    vuln = _stamp_vulnerability_engine(
        scan_id,
        vuln,
        selections=meta.mining_engines if meta is not None else [],
    )
    reported_execution_session_id = str(
        vuln.output_source.agent_session_id or ""
    ).strip()
    vuln.provisional = bool(provisional)
    live_scan = _running_scans.get(scan_id)
    if provisional:
        normalized_batch_id = str(report_batch_id or "").strip()
        if not normalized_batch_id:
            raise HTTPException(
                status_code=422,
                detail="临时漏洞上报必须包含 report_batch_id",
            )
        vuln_index = await run_store_call(
            store,
            "add_provisional_vulnerability",
            scan_id,
            normalized_batch_id,
            vuln,
        )
        scan = live_scan or await _ensure_running_scan(scan_id)
        if scan is not None:
            if vuln_index < len(scan.vulnerabilities):
                scan.vulnerabilities[vuln_index] = vuln
            elif vuln_index == len(scan.vulnerabilities):
                scan.vulnerabilities.append(vuln)
            else:
                scan.vulnerabilities = await run_store_call(
                    store,
                    "get_vulnerabilities",
                    scan_id,
                )

        from backend.sse import publish

        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
        return {
            "ok": True,
            "index": vuln_index,
            "provisional": True,
            "report_markdown": vuln.vulnerability_report,
        }

    existing_vulnerabilities = (
        live_scan.vulnerabilities
        if live_scan is not None
        else await run_store_call(store, "get_vulnerabilities", scan_id)
    )
    existing_report = _existing_reported_vulnerability(
        existing_vulnerabilities,
        vuln,
    )
    is_new_report = existing_report is None
    if existing_report is None:
        vuln_index = await run_store_call(
            store,
            "upsert_incomplete_vulnerability",
            scan_id,
            vuln,
        )
    else:
        vuln_index, vuln = existing_report

    scan = live_scan or await _ensure_running_scan(scan_id)
    if scan is not None:
        if vuln_index < len(scan.vulnerabilities):
            scan.vulnerabilities[vuln_index] = vuln
        else:
            scan.vulnerabilities.append(vuln)

    from backend.sse import publish
    stored_candidate = None
    if (
        str(vuln.analysis_source or "static_candidate") == "static_candidate"
        and vuln.audit_index is not None
        and vuln.audit_index >= 0
    ):
        candidate_result = _same_pattern_candidate_result(vuln)
        stored_candidate = await run_store_call(
            store,
            "update_scan_candidate_audit",
            scan_id,
            vuln.audit_index,
            state=_candidate_audit_state(candidate_result),
            result=candidate_result,
            vulnerability_idx=vuln_index,
            dedup_decision=(
                {"method": "same_pattern"}
                if candidate_result.ai_verdict == "filtered_same_pattern"
                else {}
            ),
        )
        if stored_candidate is not None and scan is not None:
            by_index = {candidate.idx: candidate for candidate in scan.candidates}
            by_index[stored_candidate.idx] = stored_candidate
            scan.candidates = [by_index[index] for index in sorted(by_index)]
        if stored_candidate is not None:
            publish(scan_id, "scan_candidate_audit", {
                "candidate": stored_candidate.model_dump(mode="json"),
            })
    if is_new_report:
        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
    source_task_id = str(vuln.source_task_id or "").strip()
    if source_task_id and str(vuln.analysis_source or "") == "threat_audit":
        linked = await run_store_call(
            store,
            "link_threat_audit_task_vulnerability",
            scan_id,
            source_task_id,
            vuln_index,
        )
        if linked and scan is not None:
            for stored_task in scan.threat_audit_tasks:
                if stored_task.task_id != source_task_id:
                    continue
                if vuln_index not in stored_task.result_vuln_indexes:
                    stored_task.result_vuln_indexes = sorted([
                        *stored_task.result_vuln_indexes,
                        vuln_index,
                    ])
                    publish(scan_id, "threat_audit_task", {
                        "task": stored_task.model_dump(mode="json"),
                    })
                break

    logger.debug(
        "Vulnerability %s for scan %s: %s %s:%d confirmed=%s",
        "reported" if is_new_report else "replayed",
        scan_id,
        vuln.vuln_type,
        vuln.file,
        vuln.line,
        vuln.confirmed,
    )
    report_markdown = ""
    fp_review_info = None
    if vuln.confirmed or vuln.ai_verdict == "confirmed":
        try:
            from backend.api.scan import (
                _ensure_fp_review_job_for_scan,
                _fp_review_stage_titles,
                _scan_fp_result_map,
                _scan_fp_review_settings,
                _vuln_report_markdown,
            )

            report_markdown = _vuln_report_markdown(
                vuln_index,
                vuln,
                _scan_fp_result_map(scan_id).get(vuln_index),
                fp_review_stage_titles=_fp_review_stage_titles(scan_id),
            )
            auto_fp_review, fp_review_method = (
                _scan_fp_review_settings(
                    scan_id,
                    scan,
                )
            )
            reported_session_id = reported_execution_session_id
            scan_session_id = str(
                meta.execution_agent_session_id if meta is not None else ""
            ).strip()
            can_dispatch_immediately = (
                supports_fp_review_execution_revision
                and bool(reported_session_id)
                and reported_session_id == scan_session_id
            )
            if (
                supports_fp_review_execution_revision
                and reported_session_id
                and scan_session_id
                and reported_session_id != scan_session_id
            ):
                logger.warning(
                    "Skipping immediate FP review for stale scan execution "
                    "scan=%s vuln=%d reported_session=%s current_session=%s",
                    scan_id,
                    vuln_index,
                    reported_session_id,
                    scan_session_id,
                )
            if auto_fp_review and can_dispatch_immediately:
                ensured = await run_store_call(
                    store,
                    _ensure_fp_review_job_for_scan,
                    scan_id,
                    scan,
                    allow_cancelled=False,
                    publish_started=False,
                    require_unresolved=True,
                )
                if (
                    ensured is not None
                    and not ensured.get("cancelled")
                    and not ensured.get("no_unresolved")
                ):
                    latest_results = (
                        ensured.get("latest_results") or {}
                    )
                    queued = vuln_index not in latest_results
                    fp_review_info = {
                        "review_id": ensured["review_id"],
                        "method": fp_review_method,
                        "vuln_index": vuln_index,
                        "queued": queued,
                        "total": ensured["total"],
                        "processed": ensured["processed"],
                    }
                    if queued:
                        previous_status = str(
                            ensured.get("previous_status") or ""
                        )
                        execution_revision = await run_store_call(
                            store,
                            "acquire_fp_review_execution",
                            str(ensured["review_id"]),
                            agent_session_id=scan_session_id,
                            force_new=(
                                previous_status
                                not in {
                                    FpReviewStatus.PENDING.value,
                                    FpReviewStatus.RUNNING.value,
                                }
                            ),
                        )
                        fp_review_info.update({
                            "execution_agent_session_id": scan_session_id,
                            "execution_revision": execution_revision,
                        })
                        publish(scan_id, "fp_review_started", {
                            "review_id": ensured["review_id"],
                            "execution_revision": execution_revision,
                            "method": fp_review_method,
                            "status": FpReviewStatus.RUNNING.value,
                            "total": ensured["total"],
                            "processed": ensured["processed"],
                        })
        except Exception as exc:
            logger.warning(
                "Failed to prepare vulnerability downstream work scan=%s idx=%s: %s",
                scan_id,
                vuln_index,
                exc,
            )
    response = {"ok": True, "index": vuln_index, "report_markdown": report_markdown}
    if fp_review_info is not None:
        response["fp_review"] = fp_review_info
    return response


@router.post("/scan/{scan_id}/vulnerabilities/reconcile")
async def agent_reconcile_vulnerabilities(
    scan_id: str,
    body: AgentVulnerabilityReconcile,
) -> dict:
    """Replace live engine batches with the authoritative post-run result list."""
    if not any(str(value or "").strip() for value in body.report_batch_ids):
        raise HTTPException(
            status_code=422,
            detail="最终漏洞列表对账必须包含 report_batch_ids",
        )
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    stamped = []
    for raw_vuln in body.vulnerabilities:
        vuln = _stamp_vulnerability_engine(
            scan_id,
            raw_vuln,
            selections=meta.mining_engines if meta is not None else [],
        )
        vuln.provisional = False
        stamped.append(vuln)

    reconciled = await run_store_call(
        store,
        "reconcile_provisional_vulnerabilities",
        scan_id,
        body.report_batch_ids,
        stamped,
    )
    final_vulnerabilities = await run_store_call(
        store,
        "get_vulnerabilities",
        scan_id,
    )
    scan = _running_scans.get(scan_id)
    if scan is not None:
        scan.vulnerabilities = final_vulnerabilities

    from backend.api.scan import (
        _fp_review_stage_titles,
        _scan_fp_result_map,
        _vuln_report_markdown,
    )
    from backend.sse import publish

    fp_map = _scan_fp_result_map(scan_id)
    stage_titles = _fp_review_stage_titles(scan_id)
    items = []
    for vuln_index, vuln in reconciled:
        try:
            report_markdown = _vuln_report_markdown(
                vuln_index,
                vuln,
                fp_map.get(vuln_index),
                fp_review_stage_titles=stage_titles,
            )
        except Exception as exc:
            logger.warning(
                "Failed to render reconciled vulnerability report scan=%s idx=%s: %s",
                scan_id,
                vuln_index,
                exc,
            )
            report_markdown = vuln.vulnerability_report
        items.append({
            "index": vuln_index,
            "vulnerability": vuln.model_dump(mode="json"),
            "report_markdown": report_markdown,
        })

    publish(scan_id, "scan_vulnerabilities_changed", {
        "count": len(final_vulnerabilities),
    })
    return {"ok": True, "items": items, "count": len(final_vulnerabilities)}


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
    existing = await run_store_call(store, "load_scan_runtime", scan_id)
    if existing is not None and existing[0].static_analysis_done:
        existing_counts = await run_store_call(store, "get_scan_detail_counts", scan_id)
        preserved_total = max(
            int(existing_counts["candidates"] or 0),
            int(existing[0].total_candidates or 0),
        )
        logger.info(
            "Ignored replacement candidate list for finalized scan %s; "
            "preserving %d candidate(s)",
            scan_id,
            preserved_total,
        )
        return {"ok": True, "count": preserved_total, "preserved": True}
    candidates = await run_store_call(
        store,
        "replace_scan_candidates",
        scan_id,
        static_candidates,
    )
    total = len(candidates)
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
    )

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.candidates = candidates
        scan.total_candidates = total
    processed, total = await _reconcile_candidate_progress(
        scan_id,
        reported_total=total,
    )

    from backend.sse import publish
    publish(scan_id, "scan_candidates", {
        "candidates": [candidate.model_dump() for candidate in candidates],
    })
    logger.info("Stored %d static candidate(s) for scan %s", total, scan_id)
    return {"ok": True, "count": total}


@router.post("/v2/scan/{scan_id}/candidates")
async def agent_report_scan_candidates_v2(
    scan_id: str,
    body: AgentScanCandidateBatch,
) -> dict:
    """Persist one bounded candidate chunk without broadcasting the full list."""
    static_candidates = []
    for candidate in body.candidates:
        metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
        is_threat_placeholder = (
            str(candidate.vuln_type or "").strip().lower() == "threat_audit"
            or str(metadata.get("source") or "").strip().lower() == "threat_analysis"
        )
        if not is_threat_placeholder:
            static_candidates.append(candidate)

    store = get_scan_store()
    existing = await run_store_call(store, "load_scan_runtime", scan_id)
    if existing is not None and existing[0].static_analysis_done:
        existing_counts = await run_store_call(store, "get_scan_detail_counts", scan_id)
        preserved_total = max(
            int(existing_counts["candidates"] or 0),
            int(existing[0].total_candidates or 0),
        )
        logger.info(
            "Ignored candidate batch for finalized scan %s; preserving %d "
            "candidate(s)",
            scan_id,
            preserved_total,
        )
        return {
            "ok": True,
            "offset": body.offset,
            "count": 0,
            "total": preserved_total,
            "preserved": True,
        }
    persisted = await run_store_call(
        store,
        "upsert_scan_candidates_batch",
        scan_id,
        offset=body.offset,
        candidates=static_candidates,
        reset=body.reset,
        final=body.final,
        total=body.total,
    )
    total = (
        body.total
        if body.total is not None
        else body.offset + len(persisted)
    )
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
    )

    scan = _running_scans.get(scan_id)
    if scan is not None:
        if body.reset:
            scan.candidates = []
        by_index = {candidate.idx: candidate for candidate in scan.candidates}
        by_index.update({candidate.idx: candidate for candidate in persisted})
        if body.final and body.total is not None:
            by_index = {
                index: candidate
                for index, candidate in by_index.items()
                if index < body.total
            }
        scan.candidates = [by_index[index] for index in sorted(by_index)]
        scan.total_candidates = total

    if body.final:
        _processed, total = await _reconcile_candidate_progress(
            scan_id,
            reported_total=total,
            publish_update=False,
        )

    from backend.sse import publish
    publish(scan_id, "scan_candidates_changed", {
        "offset": body.offset,
        "count": len(persisted),
        "total_candidates": total,
        "final": body.final,
    })
    return {
        "ok": True,
        "offset": body.offset,
        "count": len(persisted),
        "total": total,
    }


@router.post("/scan/{scan_id}/candidate-audit")
async def agent_report_candidate_audit(
    scan_id: str,
    body: AgentCandidateAuditResult,
) -> dict:
    """Upsert the one authoritative audit result owned by candidate_idx."""
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="candidate-audit", store=store)
    if not await run_store_call(
        store,
        "execution_matches",
        "scan",
        scan_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    result = body.result
    if result is not None:
        result = _same_pattern_candidate_result(
            result.model_copy(update={"audit_index": body.candidate_idx})
        )
    store = get_scan_store()
    vulnerability_idx = body.vulnerability_idx
    dedup_decision = dict(body.dedup_decision)
    if body.state in {"success", "failed"} and (
        vulnerability_idx is None or not dedup_decision
    ):
        candidates = await run_store_call(
            store,
            "list_scan_candidates_page",
            scan_id,
            after_index=body.candidate_idx - 1,
            limit=1,
        )
        existing_candidate = next(
            (item for item in candidates if item.idx == body.candidate_idx),
            None,
        )
        if existing_candidate is not None:
            if vulnerability_idx is None:
                vulnerability_idx = existing_candidate.vulnerability_idx
            if not dedup_decision:
                dedup_decision = dict(existing_candidate.dedup_decision)
    stored = await run_store_call(
        store,
        "update_scan_candidate_audit",
        scan_id,
        body.candidate_idx,
        state=body.state,
        result=result,
        vulnerability_idx=vulnerability_idx,
        dedup_decision=dedup_decision,
    )
    if stored is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "candidate_not_found",
                "scan_id": scan_id,
                "candidate_idx": body.candidate_idx,
            },
        )

    scan = _running_scans.get(scan_id)
    if scan is not None:
        by_index = {candidate.idx: candidate for candidate in scan.candidates}
        by_index[stored.idx] = stored
        scan.candidates = [by_index[index] for index in sorted(by_index)]

    processed, total = await _reconcile_candidate_progress(
        scan_id,
        reported_processed=body.completed_candidates,
        reported_total=body.total_candidates,
    )
    from backend.sse import publish

    publish(scan_id, "scan_candidate_audit", {
        "candidate": stored.model_dump(mode="json"),
    })
    return {
        "ok": True,
        "candidate_idx": stored.idx,
        "state": stored.audit_state,
        "processed": processed,
        "total": total,
        "vulnerability_idx": stored.vulnerability_idx,
    }


@router.post("/scan/{scan_id}/validation")
async def agent_report_vulnerability_validation(
    scan_id: str,
    body: AgentVulnerabilityValidationUpdate,
) -> dict:
    """Agent pushes local validation script progress/results for one vulnerability."""
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="validation", store=store)
    if not await run_store_call(
        store,
        "execution_matches",
        "validation",
        scan_id,
        body.vuln_index,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale validation execution")
    validation = VulnerabilityValidation(
        scan_id=scan_id,
        vuln_index=body.vuln_index,
        status=body.status,
        running=body.running,
        product=body.product,
        validation_environment=body.validation_environment,
        validation_method_id=body.validation_method_id,
        validation_method_label=body.validation_method_label,
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
        execution_agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    )
    validation = await run_store_call(
        store,
        "upsert_vulnerability_validation",
        scan_id,
        validation,
    )

    scan = await _ensure_running_scan(scan_id)
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


from backend.models import AgentValidationDelta


@router.post("/v2/scan/{scan_id}/validation")
async def agent_report_validation_delta(scan_id: str, body: AgentValidationDelta) -> dict:
    try:
        result = await run_store_call(get_scan_store(), "apply_validation_delta", scan_id, body.state.model_dump(),
            [change.model_dump() for change in body.changes], body.sequence)
    except LookupError:
        _scan_not_found(scan_id, endpoint="validation-delta", store=get_scan_store())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    publish(scan_id, "resource_changed", {"resource": "validations", "index": body.state.vuln_index})
    return result


@router.post("/scan/{scan_id}/git_history")
async def agent_push_git_history(scan_id: str, body: AgentGitHistory) -> dict:
    """Agent uploads the mined git-history security problem patterns for a scan."""
    store = get_scan_store()
    await run_store_call(
        store,
        "replace_git_history_patterns",
        scan_id,
        body.patterns,
    )
    from backend.sse import publish
    publish(scan_id, "git_history", {"count": len(body.patterns)})
    logger.info("Git history patterns stored for scan %s: %d", scan_id, len(body.patterns))
    return {"ok": True}


@router.get("/scan/{scan_id}/git_history")
async def agent_get_git_history(scan_id: str) -> list[HistoryPattern]:
    """Return the mined git-history patterns for a scan (used by FP review)."""
    store = get_scan_store()
    return await run_store_call(store, "get_git_history_patterns", scan_id)


@router.post("/scan/{scan_id}/threat-analysis")
async def agent_push_threat_analysis(scan_id: str, body: dict) -> dict:
    """Agent uploads an opaque bundle of threat-analysis artifacts."""
    try:
        analysis = parse_threat_analysis_data(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat analysis JSON: {exc}") from exc

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored_scan = loaded[0]
    scan = await _ensure_running_scan(scan_id)
    previous_run = (scan or stored_scan).threat_analysis_run
    completed_run = ThreatAnalysisRunStatus(
        status="success",
        error_message="",
        started_at=previous_run.started_at if previous_run is not None else "",
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    analysis = await run_store_call(
        store,
        "replace_threat_analysis",
        scan_id,
        analysis,
    )
    stored_run = await run_store_call(
        store,
        "update_threat_analysis_run",
        scan_id,
        completed_run,
    )
    if stored_run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan is not None:
        scan.threat_analysis = analysis
        scan.threat_analysis_run = stored_run

    from backend.sse import publish
    publish(scan_id, "threat_analysis_run", {
        "run": stored_run.model_dump(mode="json"),
    })
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
    store = get_scan_store()
    analysis = await run_store_call(store, "get_threat_analysis", scan_id)
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
    if task.status == "completed" and not task.result_vuln_indexes:
        result_indexes = await run_store_call(
            store,
            "get_vulnerability_indexes_by_source_task",
            scan_id,
            task.task_id,
        )
        if result_indexes:
            task = task.model_copy(update={
                "result_vuln_indexes": result_indexes,
            })
    task = await run_store_call(
        store,
        "upsert_threat_audit_task",
        scan_id,
        task,
    )

    scan = await _ensure_running_scan(scan_id)
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
    store = get_scan_store()
    return await run_store_call(store, "list_threat_audit_tasks", scan_id)


@router.get(
    "/scan/{scan_id}/vulnerabilities",
    response_model=VulnerabilityPage,
)
async def agent_list_vulnerabilities(
    scan_id: str,
    limit: int = Query(500, ge=1, le=500),
    after: int = Query(-1, ge=-1),
) -> VulnerabilityPage:
    """Return persisted findings used by Agent resume-time deduplication."""
    rows = await run_store_call(
        get_scan_store(),
        "get_vulnerabilities_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        VulnerabilityPageItem(index=index, vulnerability=vulnerability)
        for index, vulnerability in rows
    ]
    return VulnerabilityPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].index if has_more and items else None,
    )


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
    await run_store_call(
        store,
        "replace_skill_reports",
        scan_id,
        checker_name,
        reports,
    )

    scan = await _ensure_running_scan(scan_id)
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


async def _merge_finish_stage_runs(
    scan_id: str,
    body: AgentScanFinish,
    *,
    store,
    scan,
    meta: ScanMeta,
) -> None:
    reported_threat_run = (
        _validated_threat_analysis_run(
            meta,
            body.threat_analysis_run,
            terminal_only=True,
        )
        if body.threat_analysis_run is not None
        else None
    )
    reported_engine_runs = [
        _validated_mining_engine_run(
            meta,
            run,
            terminal_only=True,
        )
        for run in body.mining_engine_runs
    ]
    if reported_threat_run is None and not reported_engine_runs:
        return

    merged_threat_run = reported_threat_run or scan.threat_analysis_run
    engine_runs_by_id = {
        run.engine_id: run
        for run in scan.mining_engine_runs
    }
    for run in reported_engine_runs:
        engine_runs_by_id[run.engine_id] = run
    merged_engine_runs = sorted(
        engine_runs_by_id.values(),
        key=lambda run: (run.engine_label, run.engine_id),
    )
    replaced = await run_store_call(
        store,
        "replace_scan_stage_runs",
        scan_id,
        merged_threat_run,
        merged_engine_runs,
    )
    if not replaced:
        _scan_not_found(
            scan_id,
            endpoint="finish-stage-runs",
            store=store,
        )

    scan.threat_analysis_run = merged_threat_run
    scan.mining_engine_runs = merged_engine_runs
    live_scan = _running_scans.get(scan_id)
    if live_scan is not None:
        live_scan.threat_analysis_run = merged_threat_run
        live_scan.mining_engine_runs = merged_engine_runs

    from backend.sse import publish

    if reported_threat_run is not None:
        publish(scan_id, "threat_analysis_run", {
            "run": reported_threat_run.model_dump(mode="json"),
        })
    for run in reported_engine_runs:
        publish(scan_id, "mining_engine_run", {
            "run": run.model_dump(mode="json"),
            "runs": [
                item.model_dump(mode="json")
                for item in merged_engine_runs
            ],
        })


@router.post("/scan/{scan_id}/execution-failed")
async def agent_scan_execution_failed(scan_id: str, body: AgentScanExecutionFailure) -> dict:
    from backend.sse import publish

    store = get_scan_store()
    changed = await run_store_call(
        store, "fail_scan_execution", scan_id,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
        error_message=body.error_message,
    )
    if changed:
        live = _running_scans.get(scan_id)
        if live is None or live.opencode_pool is None or live.opencode_pool.execution_revision <= body.execution_revision:
            _running_scans.pop(scan_id, None)
            _scan_owners.pop(scan_id, None)
        publish(scan_id, "scan_status", {
            "execution_revision": body.execution_revision,
            "status": "error", "error_message": body.error_message,
            "opencode_pool": {"execution_revision": body.execution_revision, "agent_session_id": body.agent_session_id},
        })
    return {"ok": True, "changed": changed}


@router.post("/scan/{scan_id}/finish")
async def agent_finish_scan(scan_id: str, body: AgentScanFinish, request: Request) -> dict:
    """Agent pushes final results when the scan completes, errors, or is cancelled."""
    store = get_scan_store()
    existing = await run_store_call(store, "get_scan_meta", scan_id)
    if existing is None:
        _scan_not_found(scan_id, endpoint="finish", store=store)
    if not await run_store_call(
        store,
        "execution_matches",
        "scan",
        scan_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")

    status_map = {
        "complete": ScanItemStatus.COMPLETE,
        "cancelled": ScanItemStatus.CANCELLED,
        "error": ScanItemStatus.ERROR,
    }
    final_status = status_map.get(body.status, ScanItemStatus.ERROR)

    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        _scan_not_found(
            scan_id,
            endpoint="finish",
            store=store,
        )
    existing_scan, meta, counts = loaded
    manually_stopped = (
        existing_scan.status == ScanItemStatus.CANCELLED
        and existing_scan.error_message == "用户手动停止"
    )
    if manually_stopped:
        # The stop endpoint records user intent before contacting the Agent.
        # A completion racing with that command must not revive the scan.
        final_status = ScanItemStatus.CANCELLED
    final_error_message = (
        "用户手动停止" if manually_stopped else body.error_message
    )
    await _merge_finish_stage_runs(
        scan_id,
        body,
        store=store,
        scan=existing_scan,
        meta=meta,
    )
    final_total, final_processed = _normalize_candidate_progress(
        existing_scan,
        candidate_count=counts["candidates"],
        processed=max(
            int(existing_scan.processed_candidates or 0),
            int(body.processed_candidates or 0),
        ),
        reported_total=body.total_candidates,
    )
    # Legacy scans may predate per-engine lifecycle rows, and a transient
    # lifecycle upload can leave the run marked "running".  A successful
    # finish that itself reports the full absolute count is terminal proof.
    if (
        final_status == ScanItemStatus.COMPLETE
        and (
            not _static_candidate_run_status(existing_scan)
            or int(body.processed_candidates or 0) >= final_total
        )
    ):
        final_processed = final_total

    from backend.sse import publish

    mining_engine_selections = meta.mining_engines
    replacement_batch_ids = list(dict.fromkeys(
        batch_id
        for value in body.replace_report_batch_ids
        if (batch_id := str(value or "").strip())
    ))
    if body.replace_report_batch_ids and not replacement_batch_ids:
        raise HTTPException(
            status_code=422,
            detail="replace_report_batch_ids 不能只包含空值",
        )
    reconciled_vulnerabilities: list[tuple[int, Vulnerability]] = []
    refresh_vulnerabilities = False
    if replacement_batch_ids:
        authoritative_vulnerabilities = []
        for raw_vuln in body.vulnerabilities:
            vuln = _stamp_vulnerability_engine(
                scan_id,
                raw_vuln,
                selections=mining_engine_selections,
            )
            vuln.provisional = False
            authoritative_vulnerabilities.append(vuln)
        reconciled_vulnerabilities = await run_store_call(
            store,
            "reconcile_provisional_vulnerabilities",
            scan_id,
            replacement_batch_ids,
            authoritative_vulnerabilities,
        )
        refresh_vulnerabilities = True
        final_vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
    else:
        promoted = await run_store_call(
            store,
            "promote_provisional_vulnerabilities",
            scan_id,
        )
        refresh_vulnerabilities = promoted > 0
        existing_vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
        existing_identities = {
            vulnerability_report_identity(vuln)
            for vuln in existing_vulnerabilities
        }
        for raw_vuln in body.vulnerabilities:
            vuln = _stamp_vulnerability_engine(
                scan_id,
                raw_vuln,
                selections=mining_engine_selections,
            )
            vuln.provisional = False
            identity = vulnerability_report_identity(vuln)
            if identity in existing_identities:
                continue
            vuln_index = await run_store_call(
                store,
                "upsert_incomplete_vulnerability",
                scan_id,
                vuln,
            )
            existing_identities.add(identity)
            reconciled_vulnerabilities.append((vuln_index, vuln))

        final_vulnerabilities = (
            await run_store_call(store, "get_vulnerabilities", scan_id)
            if reconciled_vulnerabilities
            else existing_vulnerabilities
        )

    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=final_status,
        progress=1.0 if final_status == ScanItemStatus.COMPLETE else None,
        total_candidates=final_total,
        processed_candidates=final_processed,
        error_message=final_error_message,
        clear_current_candidate=True,
    )

    scan = _running_scans.get(scan_id)
    previous_pool = (
        scan.opencode_pool
        if scan is not None
        else existing_scan.opencode_pool
    )
    if body.opencode_pool is not None:
        reported_pool = _merge_completed_opencode_tasks(
            previous_pool,
            body.opencode_pool,
        )
        if hasattr(store, "upsert_scan_opencode_token_usage"):
            await run_store_call(
                store,
                "upsert_scan_opencode_token_usage",
                scan_id=scan_id,
                agent_session_id=reported_pool.agent_session_id,
                status=reported_pool,
            )
        if hasattr(store, "get_scan_opencode_token_usage"):
            reported_pool.token_usage = await run_store_call(
                store,
                "get_scan_opencode_token_usage",
                scan_id,
            )
        previous_pool = reported_pool
    final_pool = await run_store_call(
        store, "normalize_scan_pool", scan_id, previous_pool, terminal_scan=True,
    )
    if final_pool is not None:
        await run_store_call(
            store,
            "update_opencode_pool_status",
            scan_id,
            final_pool,
        )
    if scan is not None:
        scan.status = final_status
        scan.vulnerabilities = final_vulnerabilities
        scan.total_candidates = final_total
        scan.processed_candidates = final_processed
        scan.opencode_pool = final_pool
        if final_error_message:
            scan.error_message = final_error_message
        if final_status == ScanItemStatus.COMPLETE:
            scan.progress = 1.0
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    for vuln_index, vuln in reconciled_vulnerabilities:
        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
    if refresh_vulnerabilities:
        publish(scan_id, "scan_vulnerabilities_changed", {
            "count": len(final_vulnerabilities),
        })
    publish(scan_id, "scan_status", {
        "execution_revision": existing.execution_revision,
        "status": final_status,
        "progress": 1.0 if final_status == ScanItemStatus.COMPLETE else (existing_scan.progress if existing_scan else None),
        "total_candidates": final_total,
        "processed_candidates": final_processed,
        "opencode_pool": final_pool.model_dump() if final_pool is not None else None,
    })
    publish(scan_id, "scan_finish", {
        "status": final_status.value,
        "error_message": final_error_message,
        "execution_revision": existing.execution_revision,
    })

    confirmed = sum(1 for vuln in final_vulnerabilities if vuln.confirmed)
    logger.info(
        "Agent finished scan %s: %s — %d confirmed / %d candidates",
        scan_id, final_status.value, confirmed, final_total,
    )

    from backend.api.scan import (
        _scan_fp_review_settings,
        _server_url_from_request,
        _start_fp_review,
    )
    auto_fp_review, _fp_review_method = _scan_fp_review_settings(scan_id, scan)

    if final_status == ScanItemStatus.COMPLETE and confirmed > 0:
        try:
            if auto_fp_review:
                started = await _start_fp_review(
                    scan_id,
                    _server_url_from_request(request),
                    raise_on_error=False,
                    require_unresolved=True,
                )
                if started is not None:
                    logger.info(
                        "Auto FP review started for scan %s after completion",
                        scan_id,
                    )
        except Exception as exc:  # 自动触发失败不应影响扫描完成处理
            logger.warning("Auto FP review for scan %s failed: %s", scan_id, exc)

    return {"ok": True}


@router.post("/v2/scan/{scan_id}/finish")
async def agent_finish_scan_v2(
    scan_id: str,
    body: AgentScanFinishV2,
    request: Request,
) -> dict:
    """Finalize a v2 scan without resending every streamed finding."""
    return await agent_finish_scan(
        scan_id,
        AgentScanFinish(
            vulnerabilities=[],
            status=body.status,
            total_candidates=body.total_candidates,
            processed_candidates=body.processed_candidates,
            error_message=body.error_message,
            threat_analysis_run=body.threat_analysis_run,
            mining_engine_runs=body.mining_engine_runs,
            opencode_pool=body.opencode_pool,
            agent_session_id=body.agent_session_id,
            execution_revision=body.execution_revision,
        ),
        request,
    )


@router.get("/v2/resume-manifests/{token}")
async def agent_get_resume_manifest_v2(token: str) -> Response:
    """Return a durable resume payload outside the Agent WebSocket frame."""
    record = await run_store_call(
        get_scan_store(),
        "get_resume_manifest",
        token,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Resume manifest not found or expired")
    payload = json.loads(record["payload_json"])
    loaded = await run_store_call(get_scan_store(), "get_scan_identity", record["scan_id"])
    if (
        loaded is None
        or str(payload.get("scan_id") or "") != record["scan_id"]
        or int(payload.get("execution_revision") or 0) != loaded["execution_revision"]
        or loaded["status"] not in _RUNNING_SCAN_STATUSES
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    return Response(
        content=str(record["payload_json"]),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            # Avoid synchronous gzip CPU on a potentially large candidate list.
            "Content-Encoding": "identity",
        },
    )


# ---------------------------------------------------------------------------
# Processed keys (resume support)
# ---------------------------------------------------------------------------


async def _refresh_processed_progress(
    scan_id: str,
    *,
    reported_processed: int | None = None,
    reported_total: int | None = None,
) -> int:
    processed, _total = await _reconcile_candidate_progress(
        scan_id,
        reported_processed=reported_processed,
        reported_total=reported_total,
    )
    return processed


@router.post("/scan/{scan_id}/processed")
async def agent_report_processed(scan_id: str, body: dict) -> dict:
    """Agent reports a terminal candidate checkpoint after each audit."""
    store = get_scan_store()
    try:
        key = (
            str(body["file"]),
            int(body["line"]),
            str(body["function"]),
            str(body["vuln_type"]),
        )
        reported_processed = (
            max(0, int(body["processed_candidates"]))
            if body.get("processed_candidates") is not None
            else None
        )
        reported_total = (
            max(0, int(body["total_candidates"]))
            if body.get("total_candidates") is not None
            else None
        )
        await run_store_call(store, "add_processed_key", scan_id, key)
        processed = await _refresh_processed_progress(
            scan_id,
            reported_processed=reported_processed,
            reported_total=reported_total,
        )
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid processed key: {e}")
    return {"ok": True, "processed": processed}


@router.post("/v2/scan/{scan_id}/processed")
async def agent_report_processed_v2(
    scan_id: str,
    body: AgentProcessedKeyBatch,
) -> dict:
    keys = [
        (item.file, item.line, item.function, item.vuln_type)
        for item in body.items
    ]
    await run_store_call(
        get_scan_store(),
        "add_processed_keys_batch",
        scan_id,
        keys,
    )
    processed = await _refresh_processed_progress(
        scan_id,
        reported_processed=body.processed_candidates,
        reported_total=body.total_candidates,
    )
    return {"ok": True, "count": len(keys), "processed": processed}


@router.get("/scan/{scan_id}/processed")
async def agent_get_processed(scan_id: str) -> list:
    """Return all processed candidate keys for a scan (used by agent on resume)."""
    store = get_scan_store()
    keys = await run_store_call(store, "get_processed_keys", scan_id)
    return [
        {"file": f, "line": line, "function": fn, "vuln_type": vt}
        for f, line, fn, vt in keys
    ]


@router.get("/scan/{scan_id}/candidate-audits/processed")
async def agent_get_processed_candidate_indexes(scan_id: str) -> list[int]:
    """Return terminal candidate indexes for idx-based resume."""
    indexes = await run_store_call(
        get_scan_store(),
        "get_processed_candidate_indexes",
        scan_id,
    )
    return sorted(indexes)


# ---------------------------------------------------------------------------
# Index progress (pushed by agent during code indexing phase)
# ---------------------------------------------------------------------------


class _IndexStatusBody(BaseModel):
    status: str           # "not_started" | "parsing" | "done" | "error" | "skipped"
    parsed_files: int = 0
    total_files: int = 0
    stage: str = ""
    stage_current: int = 0
    stage_total: int = 0
    stats: dict[str, int] | None = None
    error: str | None = None


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
    scan = await _ensure_running_scan(scan_id)
    if file_counts is not None:
        parsed_files, total_files = file_counts
        if scan is not None:
            scan.static_total_files = total_files
            scan.static_scanned_files = parsed_files
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            static_total_files=total_files,
            static_scanned_files=parsed_files,
        )

    from backend.sse import publish
    publish(scan_id, "index_status", payload)
    if scan is not None and file_counts is not None:
        publish(scan_id, "scan_status", {
            "execution_revision": scan.execution_revision,
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
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
    scan = await _ensure_running_scan(scan_id)
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
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

    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=status,
        static_total_files=reported_total,
        static_scanned_files=reported_scanned,
        static_analysis_done=effective_done,
    )
    if scan is not None:
        from backend.sse import publish
        publish(scan_id, "scan_status", {
            "execution_revision": scan.execution_revision,
            **({"status": status} if status is not None else {}),
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
            "static_analysis_done": scan.static_analysis_done,
        })
    return {"ok": True}


@router.post("/scan/{scan_id}/opencode-pool")
async def agent_push_opencode_pool(scan_id: str, body: OpenCodePoolStatus) -> dict:
    """Agent pushes the latest OpenCode model-pool status for one scan."""
    store = get_scan_store()
    loaded = await run_store_call(store, "get_scan_identity", scan_id)
    if loaded is None:
        _scan_not_found(scan_id, endpoint="opencode-pool", store=store)
    owner = body.execution_owner
    if owner is not None and owner.kind == "fp_review":
        review = await run_store_call(store, "get_fp_review_job_state", owner.id)
        if review is None or review.scan_id != scan_id:
            raise HTTPException(status_code=409, detail="stale fp_review execution")
    elif owner is not None and owner.id != scan_id:
        raise HTTPException(status_code=409, detail="stale scan execution")
    if not await run_store_call(
        store,
        "execution_matches",
        owner.kind if owner is not None else "scan",
        owner.id if owner is not None else scan_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=owner.revision if owner is not None else body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    # The source can be an independently resumed review. GET/SSE ordering still
    # uses the parent scan revision, never the review's revision counter.
    body.execution_revision = int(loaded["execution_revision"] or 0)
    if hasattr(store, "upsert_scan_opencode_token_usage"):
        await run_store_call(
            store,
            "upsert_scan_opencode_token_usage",
            scan_id=scan_id,
            agent_session_id=body.agent_session_id,
            status=body,
        )
    if hasattr(store, "get_scan_opencode_token_usage"):
        body.token_usage = await run_store_call(
            store,
            "get_scan_opencode_token_usage",
            scan_id,
        )
    terminal = loaded is not None and loaded["status"] not in _RUNNING_SCAN_STATUSES
    status = await run_store_call(
        store,
        "persist_opencode_pool",
        scan_id,
        body,
    )

    scan = None if terminal else _running_scans.get(scan_id)
    if scan is not None and scan.execution_revision == body.execution_revision:
        scan.opencode_pool = status

    from backend.sse import publish
    live_pool = status.model_dump()
    live_pool.pop("completed_tasks", None)
    publish(scan_id, "scan_status", {
        "execution_revision": status.execution_revision,
        "opencode_pool": live_pool,
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
        pages = await asyncio.gather(*(
            run_store_call(store, "list_feedback", vuln_type=name)
            for name in names
        ))
        entries = [entry for page in pages for entry in page]
    else:
        entries = await run_store_call(store, "list_feedback")
    return [e.model_dump() for e in entries]


# ---------------------------------------------------------------------------
# Agent package download
# ---------------------------------------------------------------------------

_AGENT_DIRS = [
    "deephole_client",
    "task_agent",
    "codex_sdk",
    "mcp_server",
    "backend",
]
_AGENT_RUNTIME_DIRS = [
    "deephole_client",
    "task_agent",
    "codex_sdk",
    "mcp_server",
    "backend",
]
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
        "version": 4,
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


def create_agent_task_runtime_update_payload(
    server_url: str,
    agent_key: str,
) -> dict | None:
    """Keep ordinary tasks from bypassing a queued idle-only manual update."""
    normalized_key = str(agent_key or "").strip()
    if normalized_key:
        record = get_scan_store().get_agent_record(normalized_key)
        if _runtime_update_status(record) in _RUNTIME_UPDATE_ACTIVE_STATUSES:
            return None
    return create_agent_runtime_update_payload(server_url)


async def create_agent_task_runtime_update_payload_async(
    server_url: str,
    agent_key: str,
) -> dict | None:
    """Build the runtime archive off-loop after an async durable-state check."""
    normalized_key = str(agent_key or "").strip()
    if normalized_key:
        record = await run_store_call(
            get_scan_store(),
            "get_agent_record",
            normalized_key,
        )
        if _runtime_update_status(record) in _RUNTIME_UPDATE_ACTIVE_STATUSES:
            return None
    return await asyncio.to_thread(create_agent_runtime_update_payload, server_url)


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
DeepHole 2.0 Agent
==================

Setup
-----
1. agent.yaml already contains the server_url and owner_token from the Web UI.
   Start the Agent once, then use the Web "客户端配置" page to configure the
   OpenCode-compatible executable, explicit model pool, phase policies, MCP
   servers and validation environments. A scan cannot start without an enabled
   explicit model.

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
        data = await asyncio.to_thread(
            _build_agent_zip,
            server_url,
            current_user.agent_token,
        )
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
    def build_manifest() -> dict:
        files = _read_agent_runtime_files()
        runtime_hash = _agent_runtime_hash_for_files(files)
        manifest = _agent_runtime_manifest_for_files(files)
        manifest["runtime_hash"] = runtime_hash
        return {
            "hash": runtime_hash,
            "hash_scope": manifest["hash_scope"],
            "manifest": manifest,
        }

    return await asyncio.to_thread(build_manifest)


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
