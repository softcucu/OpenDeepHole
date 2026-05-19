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
    AgentInfo,
    AgentRemoteConfig,
    AgentScanFinish,
    ScanEvent,
    ScanItemStatus,
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

# Short-lived tokens used by online agents to fetch runtime update archives.
_runtime_download_tokens: dict[str, tuple[str, float]] = {}
_config_test_waiters: dict[str, asyncio.Future] = {}

# In-memory index progress store: scan_id → {status, parsed_files, total_files}
_scan_index_statuses: dict[str, dict] = {}

_AGENT_DISCONNECT_ERROR = "Agent 断开连接"
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
        return error_message == _AGENT_DISCONNECT_ERROR
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


def reconcile_offline_agent_scan_state(scan_id: str, scan: ScanStatus) -> ScanStatus:
    """Cancel a running scan once its owning agent is offline past the grace period."""
    if not scan.agent_name:
        return scan

    agent_online = is_agent_name_online(scan.agent_name)
    scan.agent_online = agent_online
    if agent_online or scan.status not in _RUNNING_SCAN_STATUSES:
        return scan
    if not _agent_disconnect_grace_elapsed():
        return scan

    store = get_scan_store()
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message=_AGENT_DISCONNECT_ERROR,
        clear_current_candidate=True,
    )
    store.mark_fp_reviews_for_scan_error(scan_id, _AGENT_DISCONNECT_ERROR)
    scan.status = ScanItemStatus.CANCELLED
    scan.error_message = _AGENT_DISCONNECT_ERROR
    scan.current_candidate = None
    _running_scans.pop(scan_id, None)
    _scan_owners.pop(scan_id, None)
    logger.info("Scan %s cancelled because agent %s is offline", scan_id, scan.agent_name)
    return scan


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
        store.mark_agent_scans_cancelled(agent_id, _AGENT_DISCONNECT_ERROR)
    )
    fp_review_count = store.mark_fp_reviews_for_agent_error(
        agent_id,
        _AGENT_DISCONNECT_ERROR,
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
            scan.error_message = _AGENT_DISCONNECT_ERROR
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
        )
        _registered_agents[agent_id] = agent_info
        _agent_ws[agent_id] = websocket
        _agent_ws_locks[agent_id] = asyncio.Lock()

        _reattach_active_agent_scans(agent_id, agent_info, msg.get("active_scans") or [])

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

    return {"ok": True}


@router.post("/scan/{scan_id}/vulnerability")
async def agent_report_vulnerability(scan_id: str, vuln: Vulnerability) -> dict:
    """Agent pushes a single vulnerability result immediately after auditing it."""
    store = get_scan_store()
    store.add_vulnerability(scan_id, vuln)

    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.vulnerabilities.append(vuln)

    logger.debug(
        "Vulnerability reported for scan %s: %s %s:%d confirmed=%s",
        scan_id, vuln.vuln_type, vuln.file, vuln.line, vuln.confirmed,
    )
    return {"ok": True}


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
    scan = _ensure_running_scan(scan_id)
    if scan is not None:
        scan.static_total_files = body.total
        scan.static_scanned_files = body.scanned
        scan.static_analysis_done = body.done

    store = get_scan_store()
    store.update_scan_progress(
        scan_id,
        static_total_files=body.total,
        static_scanned_files=body.scanned,
        static_analysis_done=body.done,
    )
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
_AGENT_RUNTIME_ROOT_FILES = ["requirements-agent.txt"]
_AGENT_ROOT_FILES = [
    "agent.yaml",
    "run_agent.sh",
    "run_agent.bat",
    "requirements-agent.txt",
]
_AGENT_SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache", "static"}
_AGENT_SKIP_SUFFIXES = {".pyc", ".pyo"}


def _should_skip_agent_file(path: Path) -> bool:
    return path.suffix in _AGENT_SKIP_SUFFIXES or any(part in _AGENT_SKIP_DIRS for part in path.parts)


def _iter_agent_runtime_files():
    for dir_name in _AGENT_DIRS:
        dir_path = _PROJECT_ROOT / dir_name
        if not dir_path.is_dir():
            continue
        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file() and not _should_skip_agent_file(file_path):
                yield file_path.relative_to(_PROJECT_ROOT).as_posix(), file_path
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


def _build_agent_runtime_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, file_path in _iter_agent_runtime_files():
            zf.write(file_path, arcname)
    return buf.getvalue()


def create_agent_runtime_update_payload(server_url: str) -> dict:
    data = _build_agent_runtime_zip()
    runtime_hash = _agent_runtime_hash()
    token = secrets.token_urlsafe(32)
    _runtime_download_tokens[token] = (
        runtime_hash,
        time.time() + _RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS,
    )
    return {
        "hash": runtime_hash,
        "archive_sha256": hashlib.sha256(data).hexdigest(),
        "download_url": f"{server_url.rstrip('/')}/api/agent/runtime/download",
        "token": token,
        "expires_at": int(time.time() + _RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS),
    }


def _build_agent_zip(server_url: str = "", owner_token: str = "") -> bytes:
    """Build the agent zip in-memory from the project source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dir_name in _AGENT_DIRS:
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

3. Install system code-index tools:

   Linux:
     apt install universal-ctags

   macOS:
     brew install universal-ctags

   Windows:
     Install Universal Ctags, then add ctags to PATH.

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
Runtime code updates are installed automatically and the scan continues after
the agent restarts. If run_agent.sh or run_agent.bat changes, download a new
agent package.

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
    return {"hash": _agent_runtime_hash()}


@router.get("/runtime/download")
async def agent_runtime_download(request: Request) -> Response:
    """Serve a short-lived Agent runtime update archive."""
    token = request.headers.get("X-Agent-Update-Token") or request.query_params.get("token") or ""
    token_info = _runtime_download_tokens.pop(token, None)
    if token_info is None:
        raise HTTPException(status_code=403, detail="Invalid or expired runtime update token")
    expected_hash, expires_at = token_info
    if time.time() > expires_at:
        raise HTTPException(status_code=403, detail="Runtime update token expired")

    data = _build_agent_runtime_zip()
    if _agent_runtime_hash() != expected_hash:
        raise HTTPException(status_code=409, detail="Agent runtime changed; request a new scan command")
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent-runtime.zip"'},
    )
