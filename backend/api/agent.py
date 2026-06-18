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
from backend.logger import get_logger
from backend.models import (
    AgentGitHistory,
    AgentInfo,
    AgentRemoteConfig,
    AgentScanFinish,
    FpReviewStatus,
    HistoryPattern,
    OpenCodePoolStatus,
    ScanEvent,
    ScanItemStatus,
    SkillReport,
    User,
    Vulnerability,
)
from backend.store import get_scan_store

router = APIRouter(prefix="/api/agent")
public_router = APIRouter()  # Routes not under /api/agent prefix
logger = get_logger(__name__)

# Root of the project (two levels up from this file: backend/api/ → backend/ → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory registry of connected agents
_registered_agents: dict[str, AgentInfo] = {}

# Active WebSocket connections keyed by agent_id (WebSocket mode)
_agent_ws: dict[str, WebSocket] = {}
_agent_ws_locks: dict[str, asyncio.Lock] = {}
_agent_disconnect_tasks: dict[str, asyncio.Task] = {}

# Agent configs persisted by agent_name (survives agent reconnects)
_agent_configs: dict[str, AgentRemoteConfig] = {}


@dataclass(frozen=True)
class _RuntimeDownload:
    runtime_hash: str
    archive_sha256: str
    manifest: dict
    data: bytes
    expires_at: float


# Short-lived tokens used by online agents to fetch runtime update archives.
_runtime_download_tokens: dict[str, _RuntimeDownload] = {}
_config_test_waiters: dict[str, asyncio.Future] = {}

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

        store.update_scan_agent(scan_id, agent_id, agent.name)
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

        store.update_scan_agent(scan_id, agent_id, agent.name)
        logger.info("Reattached active FP review %s from agent %s", review_id, agent_id)


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

        name = msg.get("name") or socket.gethostname()
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

        agent_info = AgentInfo(
            agent_id=agent_id,
            name=name,
            ip=ip,
            port=0,
            last_seen=now,
            user_id=user_id,
            runtime_hash=str(msg.get("runtime_hash") or ""),
        )
        _registered_agents[agent_id] = agent_info
        _agent_ws[agent_id] = websocket
        _agent_ws_locks[agent_id] = asyncio.Lock()

        _reattach_active_agent_scans(agent_id, agent_info, msg.get("active_scans") or [])
        _reattach_active_fp_reviews(agent_id, agent_info, msg.get("active_fp_reviews") or [])

        reported_config = msg.get("config")
        if reported_config and name not in _agent_configs:
            try:
                _agent_configs[name] = AgentRemoteConfig(**reported_config)
            except Exception as e:
                logger.warning("Ignoring invalid config reported by agent %s: %s", name, e)

        cfg = _agent_configs.get(name, AgentRemoteConfig())
        await _send_agent_json(agent_id, {
            "type": "welcome",
            "agent_id": agent_id,
            "config": cfg.model_dump(exclude_defaults=True),
        })

        logger.info("Agent connected via WebSocket: %s (%s) user=%s", agent_id, name, user_id or "(none)")

        # Keep connection alive; agent sends application-level heartbeats.
        while True:
            incoming = await websocket.receive_json()
            _touch_agent(agent_id)
            if isinstance(incoming, dict) and incoming.get("type") == "heartbeat":
                await _send_agent_json(agent_id, {"type": "heartbeat_ack"})
                continue
            if isinstance(incoming, dict) and incoming.get("type") == "config_test_result":
                request_id = str(incoming.get("request_id") or "")
                waiter = _config_test_waiters.pop(request_id, None)
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


class _AgentConfigTestResponse(BaseModel):
    ok: bool
    message: str = ""


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
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return _agent_configs.get(agent.name, AgentRemoteConfig())


@router.put("/{agent_id}/config")
async def update_agent_config(
    agent_id: str,
    body: AgentRemoteConfig,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Save the server-managed config for an agent (keyed by agent name).
    Also pushes the updated config to the agent via WebSocket if connected."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    _agent_configs[agent.name] = body
    logger.info("Config updated for agent %s (%s)", agent_id, agent.name)
    # Push update to agent immediately if connected via WebSocket
    await send_agent_command(agent_id, {"type": "config", "config": body.model_dump()})
    return {"ok": True}


@router.post("/{agent_id}/config/test", response_model=_AgentConfigTestResponse)
async def test_agent_config(
    agent_id: str,
    body: AgentRemoteConfig,
    current_user: User = Depends(get_current_user),
) -> _AgentConfigTestResponse:
    """Ask the online Agent to validate the provided LLM API config."""
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
    _config_test_waiters[request_id] = waiter
    ok = await send_agent_command(agent_id, {
        "type": "config_test",
        "request_id": request_id,
        "config": body.model_dump(),
    })
    if not ok:
        _config_test_waiters.pop(request_id, None)
        raise HTTPException(status_code=502, detail="Agent not connected")
    try:
        result = await asyncio.wait_for(waiter, timeout=20.0)
    except asyncio.TimeoutError:
        _config_test_waiters.pop(request_id, None)
        raise HTTPException(status_code=504, detail="Agent API config test timed out")
    return _AgentConfigTestResponse(
        ok=bool(result.get("ok")),
        message=str(result.get("message") or ""),
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
    result = []
    for a in _registered_agents.values():
        if current_user.role != "admin" and a.user_id != current_user.user_id:
            continue
        online = _is_agent_online(a)
        result.append({**a.model_dump(), "online": online})
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
        if event.candidate_index is not None:
            processed = event.candidate_index + 1
            if processed > scan.processed_candidates:
                scan.processed_candidates = processed
                progress_kwargs["processed_candidates"] = processed
                if scan.total_candidates > 0:
                    scan.progress = processed / scan.total_candidates
                    progress_kwargs["progress"] = scan.progress

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
async def agent_finish_scan(scan_id: str, body: AgentScanFinish) -> dict:
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
    if scan is not None:
        scan.status = final_status
        if body.vulnerabilities and existing_count == 0:
            scan.vulnerabilities = body.vulnerabilities
        scan.total_candidates = final_total
        scan.processed_candidates = final_processed
        if body.error_message:
            scan.error_message = body.error_message
        if final_status == ScanItemStatus.COMPLETE:
            scan.progress = 1.0
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    from backend.sse import publish
    publish(scan_id, "scan_finish", {
        "status": body.status,
        "error_message": body.error_message,
    })

    confirmed = sum(1 for v in body.vulnerabilities if v.confirmed)
    logger.info(
        "Agent finished scan %s: %s — %d confirmed / %d candidates",
        scan_id, body.status, confirmed, final_total,
    )
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


@router.post("/scan/{scan_id}/index-status")
async def agent_push_index_status(scan_id: str, body: _IndexStatusBody) -> dict:
    """Agent pushes code-indexing progress. Stored in memory for frontend polling."""
    _scan_index_statuses[scan_id] = body.model_dump()

    # Mirror counts into the running scan so the frontend can read them via the
    # existing scan-status polling endpoint (scan.static_total_files, etc.)
    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.static_total_files = body.total_files
        scan.static_scanned_files = body.parsed_files

    from backend.sse import publish
    publish(scan_id, "index_status", body.model_dump())

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

    if scan is not None:
        scan.static_total_files = body.total
        scan.static_scanned_files = body.scanned
        scan.static_analysis_done = effective_done
        if status is not None:
            scan.status = status

    store.update_scan_progress(
        scan_id,
        status=status,
        static_total_files=body.total,
        static_scanned_files=body.scanned,
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
    store.update_opencode_pool_status(scan_id, body)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.opencode_pool = body

    from backend.sse import publish
    publish(scan_id, "scan_status", {
        "status": scan.status if scan else None,
        "progress": scan.progress if scan else None,
        "total_candidates": scan.total_candidates if scan else None,
        "processed_candidates": scan.processed_candidates if scan else None,
        "static_total_files": scan.static_total_files if scan else None,
        "static_scanned_files": scan.static_scanned_files if scan else None,
        "static_analysis_done": scan.static_analysis_done if scan else None,
        "opencode_pool": body.model_dump(),
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

_AGENT_DIRS = ["agent", "checkers", "code_parser", "mcp_server", "backend"]
_AGENT_RUNTIME_DIRS = ["agent", "code_parser", "mcp_server", "backend"]
_AGENT_TOOL_DIRS = ["ctags-p6.2.20260517.0-x64"]
_AGENT_RUNTIME_ROOT_FILES = ["requirements-agent.txt"]
_AGENT_ROOT_FILES = [
    "agent.yaml",
    "run_agent.sh",
    "run_agent.bat",
    "requirements-agent.txt",
]
_AGENT_SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache", "static", "system_skills"}
_AGENT_SKIP_SUFFIXES = {".pyc", ".pyo"}


def _agent_runtime_hash_scope() -> dict:
    return {
        "version": 2,
        "dirs": list(_AGENT_RUNTIME_DIRS),
        "tool_dirs": list(_AGENT_TOOL_DIRS),
        "root_files": list(_AGENT_RUNTIME_ROOT_FILES),
        "skip_dirs": sorted(_AGENT_SKIP_DIRS),
        "skip_suffixes": sorted(_AGENT_SKIP_SUFFIXES),
    }


def _should_skip_agent_file(path: Path) -> bool:
    return path.suffix in _AGENT_SKIP_SUFFIXES or any(part in _AGENT_SKIP_DIRS for part in path.parts)


def _iter_agent_runtime_files():
    for dir_name in [*_AGENT_RUNTIME_DIRS, *_AGENT_TOOL_DIRS]:
        dir_path = _PROJECT_ROOT / dir_name
        if not dir_path.is_dir():
            continue
        # Sort by POSIX arcname to ensure consistent ordering across platforms
        # (Windows Path sorting is case-insensitive, Linux is case-sensitive).
        entries = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and not _should_skip_agent_file(file_path):
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
                if file_path.is_file() and not _should_skip_agent_file(file_path):
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
1. Edit agent.yaml — set server_url and llm_api.api_key

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
Checker updates are synced with each scan and do not restart the agent. If
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
