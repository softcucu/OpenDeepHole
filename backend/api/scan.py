"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from backend.checker_sync import build_checker_packages
from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewProgress,
    AgentFpReviewResult,
    AgentFpReviewStageOutput,
    BatchMarkRequest,
    BatchUnmarkRequest,
    Candidate,
    CreateScanRequest,
    FeedbackEntry,
    FpReviewJob,
    FpReviewResult,
    FpReviewStatus,
    MarkRequest,
    ScanItemStatus,
    ScanMeta,
    ScanProductList,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    SkillReport,
    UnmarkRequest,
    UpdateScanProductRequest,
    User,
)
from backend.opencode.feedback_format import build_feedback_section
from backend.scan_metrics import (
    calculate_issue_metrics,
    is_effective_fp_review_result,
    latest_fp_review_result_map,
)
from backend.store import get_scan_store
from backend.registry import CHECKER_VISIBILITY_ADMIN, refresh_registry

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}

# Map scan_id → user_id for ownership checks on in-memory scans
_scan_owners: dict[str, str] = {}

_FINAL_USER_VERDICTS = {"confirmed", "false_positive"}
_MARK_VERDICTS = _FINAL_USER_VERDICTS | {"pending_analysis"}


def _has_final_user_verdict(vuln) -> bool:
    return vuln.user_verdict in _FINAL_USER_VERDICTS


def _is_agent_disconnect_error(error_message: str | None) -> bool:
    """Check if an error message indicates an agent disconnect (not user action)."""
    from backend.api.agent import AGENT_DISCONNECT_ERROR
    return error_message == AGENT_DISCONNECT_ERROR


def _configured_products() -> list[str]:
    products: list[str] = []
    seen: set[str] = set()
    for product in get_config().scan.products:
        normalized = str(product).strip()
        if normalized and normalized not in seen:
            products.append(normalized)
            seen.add(normalized)
    return products


def _validate_product(product: str) -> str:
    normalized = product.strip()
    if not normalized:
        return ""
    if normalized not in _configured_products():
        raise HTTPException(status_code=400, detail=f"Unknown product: {normalized}")
    return normalized


def _check_scan_owner(scan_id: str, user: User) -> None:
    """Raise 403 if the user doesn't own the scan and isn't admin."""
    if user.role == "admin":
        return
    if scan_id in _scan_owners and _scan_owners[scan_id] == user.user_id:
        return
    store = get_scan_store()
    meta = store.get_scan_meta(scan_id)
    if meta is not None and meta.user_id == user.user_id:
        return
    raise HTTPException(status_code=403, detail="Access denied")


def _latest_fp_review_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return the latest FP review result per vulnerability index for a scan."""
    store = get_scan_store()
    latest: dict[int, FpReviewResult] = {}
    for result in store.list_fp_review_results_by_scan(scan_id):
        if not is_effective_fp_review_result(result):
            continue
        latest[result.vuln_index] = result
    return latest


def _ordered_fp_review_candidates(scan: ScanStatus, latest_fp_results: dict[int, FpReviewResult]) -> list[dict]:
    """Return review candidates with unresolved findings first, then already-reviewed findings."""
    unresolved: list[dict] = []
    reviewed: list[dict] = []
    for i, v in enumerate(scan.vulnerabilities):
        if not v.confirmed or _has_final_user_verdict(v):
            continue
        item = {
            "index": i,
            "file": v.file,
            "line": v.line,
            "function": v.function,
            "vuln_type": v.vuln_type,
            "description": v.description,
            "ai_analysis": v.ai_analysis,
        }
        if i in latest_fp_results:
            reviewed.append(item)
        else:
            unresolved.append(item)
    return unresolved + reviewed


def _merge_latest_fp_review_results(job: FpReviewJob, scan_id: str) -> FpReviewJob:
    """Attach scan-wide latest per-vulnerability results to the current job."""
    latest_results = sorted(
        _latest_fp_review_result_map(scan_id).values(),
        key=lambda result: result.vuln_index,
    )
    return FpReviewJob(
        review_id=job.review_id,
        scan_id=job.scan_id,
        status=job.status,
        created_at=job.created_at,
        total=job.total,
        processed=job.processed,
        current_vuln_index=job.current_vuln_index,
        results=latest_results,
        error_message=job.error_message,
    )


def _scan_feedback_ids(scan_id: str) -> list[str]:
    scan = _running_scans.get(scan_id)
    if scan is not None:
        return scan.feedback_ids
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return []
    return meta.feedback_ids


def _selected_feedback_entries(scan_id: str, feedback_ids: list[str] | None = None) -> list[FeedbackEntry]:
    ids = feedback_ids if feedback_ids is not None else _scan_feedback_ids(scan_id)
    if not ids:
        return []
    return get_scan_store().get_feedback_by_ids(ids)


def _resolve_scan_agent_id(meta: ScanMeta) -> str | None:
    from backend.api.agent import _agent_ws, _registered_agents

    agent_id = meta.agent_id
    if agent_id and agent_id in _agent_ws:
        return agent_id
    if meta.agent_name:
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                return aid
    return None


def _server_url_from_request(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _validated_checker_names(checkers: list[str], user: User) -> list[str]:
    """Refresh checker registry and validate requested scan checkers."""
    registry = refresh_registry()
    names = list(dict.fromkeys(checkers))
    if not names:
        raise HTTPException(status_code=400, detail="No checkers selected")

    unknown = [name for name in names if name not in registry]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown checkers: {', '.join(unknown)}")

    admin_only = [
        name for name in names
        if registry[name].visibility == CHECKER_VISIBILITY_ADMIN and user.role != "admin"
    ]
    if admin_only:
        raise HTTPException(status_code=403, detail=f"Checker is admin-only: {', '.join(admin_only)}")

    return names


def _checker_packages_for(names: list[str]) -> list[dict[str, str]]:
    registry = refresh_registry()
    missing = [name for name in names if name not in registry]
    if missing:
        raise HTTPException(status_code=400, detail=f"Checker unavailable: {', '.join(missing)}")
    return build_checker_packages(registry, names)


_RETRYABLE_AI_VERDICTS = {"timeout", "no_result"}


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def _is_retryable_vuln(vuln) -> bool:
    return (
        not _has_final_user_verdict(vuln)
        and (vuln.ai_verdict or "") in _RETRYABLE_AI_VERDICTS
    )


def _retry_incomplete_candidates(scan: ScanStatus) -> list[Candidate]:
    candidates: list[Candidate] = []
    for vuln in scan.vulnerabilities:
        if not _is_retryable_vuln(vuln):
            continue
        candidates.append(
            Candidate(
                file=vuln.file,
                line=vuln.line,
                function=vuln.function,
                description=vuln.description,
                vuln_type=vuln.vuln_type,
            )
        )
    return candidates


def _retry_incomplete_count(scan: ScanStatus) -> int:
    return len(_retry_incomplete_candidates(scan))


async def _push_feedback_selection_update(scan_id: str, feedback_ids: list[str]) -> None:
    """Best-effort update of the selected feedback entries on the owning agent."""
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return
    agent_id = _resolve_scan_agent_id(meta)
    if agent_id is None:
        return
    from backend.api.agent import send_agent_command

    entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, feedback_ids)]
    await send_agent_command(agent_id, {
        "type": "feedback_selection_update",
        "scan_id": scan_id,
        "feedback_entries": entries,
    })


# ---------------------------------------------------------------------------
# Create scan (new flow: agent_id + project_path instead of upload)
# ---------------------------------------------------------------------------


async def create_agent_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User,
    *,
    checker_names: list[str] | None = None,
    public_access_token: str = "",
    enforce_agent_owner: bool = True,
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    from backend.api.agent import _registered_agents

    agent = _registered_agents.get(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{body.agent_id}' not found or not registered")

    # Verify the agent belongs to this user (or user is admin)
    if enforce_agent_owner and current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to you")

    selected_checkers = checker_names if checker_names is not None else body.checkers
    validated_checker_names = _validated_checker_names(selected_checkers, current_user)
    checker_packages = _checker_packages_for(validated_checker_names)
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    project_path = body.project_path.strip()
    if not project_path:
        raise HTTPException(status_code=400, detail="project_path is required")
    code_scan_path = body.code_scan_path.strip() or project_path
    scan_name = body.scan_name or project_path.split("/")[-1] or scan_id
    product = _validate_product(body.product)

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        product=product,
        scan_items=validated_checker_names,
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        agent_name=agent.name,
        agent_online=True,
    )
    meta = ScanMeta(
        scan_items=validated_checker_names,
        created_at=now,
        feedback_ids=body.feedback_ids,
        agent_id=body.agent_id,
        agent_name=agent.name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        scan_name=scan_name,
        product=product,
        user_id=current_user.user_id,
        public_access_token=public_access_token,
    )

    store = get_scan_store()
    store.save_scan(scan, meta)
    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    # Dispatch to agent via WebSocket
    from backend.api.agent import create_agent_runtime_update_payload, send_agent_command
    feedback_entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, body.feedback_ids)]
    ok = await send_agent_command(body.agent_id, {
        "type": "task",
        "scan_id": scan_id,
        "project_path": project_path,
        "code_scan_path": code_scan_path,
        "checkers": validated_checker_names,
        "scan_name": scan_name,
        "feedback_entries": feedback_entries,
        "checker_packages": checker_packages,
        "agent_runtime_update": create_agent_runtime_update_payload(_server_url_from_request(request)),
    })
    if not ok:
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message="Agent not connected")
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s: agent %s not connected", scan_id, body.agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s)",
        scan_id, scan_name, body.agent_id, agent.ip,
    )
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    return await create_agent_scan(body, request, current_user)


# ---------------------------------------------------------------------------
# List / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    """List scans visible to the current user (admin sees all)."""
    from backend.api.agent import (
        reconcile_offline_agent_scan_state,
        reconcile_offline_agent_summary_state,
    )

    store = get_scan_store()
    if current_user.role == "admin":
        summaries = store.list_scans()
    else:
        summaries = store.list_scans_by_user(current_user.user_id)

    stored_ids = [s.scan_id for s in summaries if s.scan_id not in _running_scans]
    vuln_stats = store.get_vuln_stats_by_scans(stored_ids)
    fp_verdicts = store.list_fp_review_verdicts_by_scans([s.scan_id for s in summaries])

    for s in summaries:
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            live.agent_name = s.agent_name or live.agent_name
            vulnerabilities = live.vulnerabilities
            live = reconcile_offline_agent_scan_state(s.scan_id, live)
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.agent_online = live.agent_online
        else:
            # status/progress 等字段与 load_scan 同源于 scans 表同一行，直接用 summary 值
            s = reconcile_offline_agent_summary_state(s)
            vulnerabilities = vuln_stats.get(s.scan_id, [])
        s.retryable_candidates_count = sum(
            1 for v in vulnerabilities if _is_retryable_vuln(v)
        )

        metrics = calculate_issue_metrics(
            vulnerabilities,
            latest_fp_review_result_map(fp_verdicts.get(s.scan_id, [])),
        )
        s.vulnerability_count = metrics.effective_issue_count
        s.human_confirmed_count = metrics.human_confirmed_count
    return summaries


@router.get("/api/scan/products", response_model=ScanProductList)
async def list_scan_products(
    _current_user: User = Depends(get_current_user),
) -> ScanProductList:
    """Return configured scan product options."""
    return ScanProductList(products=_configured_products())


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStatus:
    """Get the current status and results of a scan."""
    from backend.api.agent import reconcile_offline_agent_scan_state

    _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        store = get_scan_store()
        result = store.load_scan(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan = result[0]
        scan.agent_name = result[1].agent_name
    scan = reconcile_offline_agent_scan_state(scan_id, scan)
    scan.retryable_candidates_count = _retry_incomplete_count(scan)
    return scan


@router.put("/api/scan/{scan_id}/product")
async def update_scan_product(
    scan_id: str,
    body: UpdateScanProductRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the product associated with an existing scan."""
    _check_scan_owner(scan_id, current_user)
    product = _validate_product(body.product)
    store = get_scan_store()
    if store.get_scan_meta(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan_id in _running_scans:
        _running_scans[scan_id].product = product
    store.update_scan_product(scan_id, product)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Immediately cancel the scan, then best-effort notify the agent."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import _registered_agents

    store = get_scan_store()

    # Resolve agent_id BEFORE popping from memory
    meta = store.get_scan_meta(scan_id)
    agent_id = meta.agent_id if meta else ""

    # Immediately mark as CANCELLED in DB and in-memory
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message="用户手动停止",
        clear_current_candidate=True,
    )
    scan = _running_scans.pop(scan_id, None)
    if scan is not None:
        scan.status = ScanItemStatus.CANCELLED
        scan.error_message = "用户手动停止"
    _scan_owners.pop(scan_id, None)

    # Best-effort: send stop command to agent (fire-and-forget)
    if agent_id and _registered_agents.get(agent_id):
        from backend.api.agent import send_agent_command
        try:
            await send_agent_command(agent_id, {"type": "stop", "scan_id": scan_id})
        except Exception:
            pass

    logger.info("Scan %s cancelled immediately by user", scan_id)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Reset a cancelled/error scan to PENDING and tell the agent to resume."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import _registered_agents

    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")

    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if scan.status not in (ScanItemStatus.CANCELLED, ScanItemStatus.ERROR):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume scan with status '{scan.status.value}'",
        )

    # Only allow resume when the original agent (by name) is online
    agent_id = meta.agent_id
    agent = _registered_agents.get(agent_id) if agent_id else None

    # If original agent_id is stale (reconnected), find it by name
    if agent is None and meta.agent_name:
        from backend.api.agent import _agent_ws
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    # Update scan meta with new agent_id if it changed
    if agent_id != meta.agent_id:
        meta.agent_id = agent_id
        meta.agent_name = agent.name
        store.update_scan_agent(scan_id, agent_id, agent.name)

    # Reset status to PENDING
    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    scan.agent_name = agent.name
    scan.agent_online = True
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.PENDING,
        error_message="",
    )

    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    # Send resume command to agent via WebSocket
    from backend.api.agent import create_agent_runtime_update_payload, send_agent_command
    feedback_entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, meta.feedback_ids)]
    ok = await send_agent_command(agent_id, {
        "type": "resume",
        "scan_id": scan_id,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "checkers": meta.scan_items,
        "scan_name": meta.scan_name,
        "feedback_entries": feedback_entries,
        "checker_packages": _checker_packages_for(meta.scan_items),
        "agent_runtime_update": create_agent_runtime_update_payload(_server_url_from_request(request)),
    })
    if not ok:
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message="Agent not connected")
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to resume scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info("Resumed scan %s via agent %s", scan_id, agent_id)
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan/{scan_id}/retry-incomplete", response_model=ScanStartResponse)
async def retry_incomplete_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Retry completed timeout/no-result candidates in the original scan."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import _registered_agents

    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")

    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if scan.status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING):
        raise HTTPException(status_code=400, detail="Scan is already running")

    retry_candidates = _retry_incomplete_candidates(scan)
    if not retry_candidates:
        raise HTTPException(status_code=400, detail="没有可续扫的超时或无结果候选")

    agent_id = meta.agent_id
    agent = _registered_agents.get(agent_id) if agent_id else None
    if agent is None and meta.agent_name:
        from backend.api.agent import _agent_ws
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    if agent_id != meta.agent_id:
        meta.agent_id = agent_id
        meta.agent_name = agent.name
        store.update_scan_agent(scan_id, agent_id, agent.name)

    total_candidates = scan.total_candidates or len(scan.vulnerabilities)
    processed_offset = max(total_candidates - len(retry_candidates), 0)
    progress = processed_offset / total_candidates if total_candidates > 0 else 0.0
    retry_keys = [_candidate_key(candidate) for candidate in retry_candidates]

    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    scan.agent_name = agent.name
    scan.agent_online = True
    scan.processed_candidates = processed_offset
    scan.progress = progress
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.PENDING,
        processed_candidates=processed_offset,
        progress=progress,
        error_message="",
        clear_current_candidate=True,
    )
    store.remove_processed_keys(scan_id, retry_keys)

    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    from backend.api.agent import create_agent_runtime_update_payload, send_agent_command
    feedback_entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, meta.feedback_ids)]
    ok = await send_agent_command(agent_id, {
        "type": "resume",
        "scan_id": scan_id,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "checkers": meta.scan_items,
        "scan_name": meta.scan_name,
        "feedback_entries": feedback_entries,
        "checker_packages": _checker_packages_for(meta.scan_items),
        "retry_candidates": [candidate.model_dump() for candidate in retry_candidates],
        "retry_total_candidates": total_candidates,
        "retry_processed_offset": processed_offset,
        "agent_runtime_update": create_agent_runtime_update_payload(_server_url_from_request(request)),
    })
    if not ok:
        for key in retry_keys:
            store.add_processed_key(scan_id, key)
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message="Agent not connected")
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to retry incomplete scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Retrying %d incomplete candidate(s) for scan %s via agent %s",
        len(retry_candidates),
        scan_id,
        agent_id,
    )
    return ScanStartResponse(scan_id=scan_id)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Delete a scan record and clean up project directory if orphaned."""
    _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    store = get_scan_store()

    # Load scan to get project_id before deletion
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, _meta = result
    project_id = scan.project_id

    if not store.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    # Clean up project directory if no other scans reference it
    if store.count_scans_for_project(project_id) == 0:
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / project_id
        if project_dir.is_dir():
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.info("Cleaned up orphaned project directory: %s", project_dir)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan results as a CSV report."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["file", "line", "function", "vuln_type", "severity", "confirmed", "description", "ai_analysis"])
    for v in scan.vulnerabilities:
        writer.writerow([v.file, v.line, v.function, v.vuln_type, v.severity, v.confirmed, v.description, v.ai_analysis])
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


def _mark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
    verdict: str,
    reason: str,
    ticket_submitted: bool = False,
    ticket_id: str = "",
) -> tuple[str | None, list[str]]:
    """Mark a vulnerability. Final verdicts create feedback; pending analysis does not."""
    if verdict not in _MARK_VERDICTS:
        raise HTTPException(status_code=400, detail="Invalid verdict")
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    vuln = scan.vulnerabilities[index]
    normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""

    removed_feedback_ids: list[str] = []
    if verdict == "pending_analysis":
        removed_feedback_ids = store.clear_vulnerability_user_verdict(scan_id, index)

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = verdict
            live.vulnerabilities[index].user_verdict_reason = reason
            live.vulnerabilities[index].ticket_submitted = ticket_submitted
            live.vulnerabilities[index].ticket_id = normalized_ticket_id

    vuln.user_verdict = verdict
    vuln.user_verdict_reason = reason
    vuln.ticket_submitted = ticket_submitted
    vuln.ticket_id = normalized_ticket_id

    store.update_vulnerability(
        scan_id,
        index,
        verdict,
        reason,
        ticket_submitted,
        normalized_ticket_id,
    )

    if verdict == "pending_analysis":
        logger.info(
            "Scan %s: vulnerability %d marked as pending analysis, removed feedback IDs: %s",
            scan_id,
            index,
            removed_feedback_ids,
        )
        return None, removed_feedback_ids

    now = datetime.now(timezone.utc).isoformat()
    entry = FeedbackEntry(
        id=uuid.uuid4().hex,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        ticket_submitted=ticket_submitted,
        ticket_id=normalized_ticket_id,
        function_source=vuln.function_source,
        function_start_line=vuln.function_start_line,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    entry = store.upsert_feedback_for_report(entry)
    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, entry.id)

    # Push feedback update to the agent that ran this scan (best-effort)
    try:
        smeta = store.get_scan_meta(scan_id)
        if smeta is not None:
            from backend.api.agent import _registered_agents, _agent_ws, send_agent_command
            import asyncio
            target_id = smeta.agent_id
            # Resolve stale agent_id by name
            if (not target_id or target_id not in _agent_ws) and smeta.agent_name:
                for aid, ainfo in _registered_agents.items():
                    if ainfo.name == smeta.agent_name and aid in _agent_ws:
                        target_id = aid
                        break
            if target_id and target_id in _agent_ws:
                asyncio.create_task(send_agent_command(target_id, {
                    "type": "feedback_update",
                    "entry": entry.model_dump(),
                }))
    except Exception:
        pass

    return entry.id, removed_feedback_ids


def _remove_feedback_ids_from_scan(scan_id: str, scan: ScanStatus, feedback_ids: list[str]) -> None:
    if not feedback_ids:
        return
    removed = set(feedback_ids)
    next_ids = [fid for fid in scan.feedback_ids if fid not in removed]
    if next_ids == scan.feedback_ids:
        loaded = get_scan_store().load_scan(scan_id)
        if loaded is not None:
            next_ids = [fid for fid in loaded[1].feedback_ids if fid not in removed]
            if next_ids == loaded[1].feedback_ids:
                return
        else:
            return
    scan.feedback_ids = next_ids
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = next_ids
    get_scan_store().update_scan_feedback_ids(scan_id, next_ids)


def _unmark_single(scan_id: str, scan: ScanStatus, store, index: int) -> list[str]:
    """Clear a vulnerability's manual verdict and delete its same-source feedback."""
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = None
            live.vulnerabilities[index].user_verdict_reason = None
            live.vulnerabilities[index].ticket_submitted = False
            live.vulnerabilities[index].ticket_id = ""

    vuln = scan.vulnerabilities[index]
    vuln.user_verdict = None
    vuln.user_verdict_reason = None
    vuln.ticket_submitted = False
    vuln.ticket_id = ""

    removed_feedback_ids = store.clear_vulnerability_user_verdict(scan_id, index)
    logger.info(
        "Scan %s: vulnerability %d manual verdict cleared, removed feedback IDs: %s",
        scan_id,
        index,
        removed_feedback_ids,
    )
    return removed_feedback_ids


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Mark a vulnerability with manual triage feedback."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id, removed_feedback_ids = _mark_single(
        scan_id,
        scan,
        store,
        body.index,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_id": feedback_id, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/unmark")
async def unmark_vulnerability(
    scan_id: str,
    body: UnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear a vulnerability's manual verdict and remove its generated feedback."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids = _unmark_single(scan_id, scan, store, body.index)
    _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Batch-mark multiple vulnerabilities with manual triage feedback."""
    _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids: list[str] = []
    removed_feedback_ids: list[str] = []
    for item in body.items:
        feedback_id, removed_ids = _mark_single(
            scan_id,
            scan,
            store,
            item.index,
            item.verdict,
            item.reason,
            item.ticket_submitted,
            item.ticket_id,
        )
        if feedback_id is not None:
            feedback_ids.append(feedback_id)
        removed_feedback_ids.extend(removed_ids)
    _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_ids": feedback_ids, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-unmark")
async def batch_unmark_vulnerabilities(
    scan_id: str,
    body: BatchUnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear manual verdicts and remove generated feedback for multiple vulnerabilities."""
    _check_scan_owner(scan_id, current_user)
    if not body.indices:
        raise HTTPException(status_code=400, detail="No indices provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids: list[str] = []
    for index in dict.fromkeys(body.indices):
        removed_feedback_ids.extend(_unmark_single(scan_id, scan, store, index))
    _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


# ---------------------------------------------------------------------------
# Scan feedback endpoint (DB-only; no server-side workspace to refresh)
# ---------------------------------------------------------------------------


@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger AI false-positive review for all confirmed vulnerabilities in a scan."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import create_agent_runtime_update_payload, send_agent_command

    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    latest_fp_results = _latest_fp_review_result_map(scan_id)

    confirmed = _ordered_fp_review_candidates(scan, latest_fp_results)
    if not confirmed:
        raise HTTPException(status_code=400, detail="No confirmed vulnerabilities to review")

    meta = store.get_scan_meta(scan_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not meta.agent_id and not meta.agent_name:
        raise HTTPException(status_code=400, detail="No agent associated with this scan")

    # Resolve agent_id — may be stale if agent reconnected
    from backend.api.agent import _registered_agents, _agent_ws
    agent_id = meta.agent_id
    if not agent_id or agent_id not in _agent_ws:
        agent_id = None
        if meta.agent_name:
            for aid, ainfo in _registered_agents.items():
                if ainfo.name == meta.agent_name and aid in _agent_ws:
                    agent_id = aid
                    break
    if agent_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        store.update_scan_agent(scan_id, agent_id, meta.agent_name)

    feedback_entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, meta.feedback_ids)]
    review_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    store.create_fp_review_job(review_id, scan_id, len(confirmed), now)

    ok = await send_agent_command(agent_id, {
        "type": "fp_review",
        "scan_id": scan_id,
        "review_id": review_id,
        "project_path": meta.project_path,
        "vulnerabilities": confirmed,
        "feedback_entries": feedback_entries,
        "agent_runtime_update": create_agent_runtime_update_payload(_server_url_from_request(request)),
    })
    if not ok:
        store.update_fp_review_job(review_id, status="error", error_message="Agent not connected")
        raise HTTPException(status_code=502, detail="Agent not connected")

    store.update_fp_review_job(review_id, status="running")
    from backend.sse import publish
    publish(scan_id, "fp_review_started", {
        "review_id": review_id, "status": "running", "total": len(confirmed),
    })
    logger.info("FP review %s triggered for scan %s (%d candidates)", review_id, scan_id, len(confirmed))
    return {
        "ok": True,
        "review_id": review_id,
        "status": "running",
        "total": len(confirmed),
        "processed": 0,
    }


@router.post("/api/scan/{scan_id}/fp_review/stop")
async def stop_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel the latest running FP review job for a scan."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        return {"ok": True, "review_id": job.review_id}

    meta = store.get_scan_meta(scan_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    store.update_fp_review_job(
        job.review_id,
        status=FpReviewStatus.CANCELLED.value,
        clear_current_vuln_index=True,
        error_message="用户手动停止",
    )

    agent_id = _resolve_scan_agent_id(meta)
    if agent_id is not None:
        await send_agent_command(agent_id, {
            "type": "fp_review_stop",
            "scan_id": scan_id,
            "review_id": job.review_id,
        })

    logger.info("FP review %s for scan %s cancelled by user", job.review_id, scan_id)
    return {"ok": True, "review_id": job.review_id}


@router.get("/api/scan/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> FpReviewJob:
    """Get the latest FP review job and results for a scan."""
    _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    return _merge_latest_fp_review_results(job, scan_id)


@router.get("/api/scan/{scan_id}/events")
async def scan_events_sse(scan_id: str, token: str = Query(...)) -> StreamingResponse:
    """SSE stream for real-time scan and FP review status updates.

    The browser EventSource API does not support custom headers, so the
    JWT is passed as a query parameter.
    """
    from backend.auth import decode_token
    from backend.sse import subscribe, unsubscribe, format_sse, SSE_KEEPALIVE
    import jwt as _jwt

    try:
        payload = decode_token(token)
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get("sub", "")
    role = payload.get("role", "")
    if role != "admin":
        store = get_scan_store()
        meta = store.get_scan_meta(scan_id)
        if meta is not None:
            if meta.user_id != user_id:
                raise HTTPException(status_code=403, detail="Access denied")
        elif scan_id not in _scan_owners or _scan_owners[scan_id] != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = subscribe(scan_id)
        try:
            yield format_sse("connected", {"scan_id": scan_id})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    yield format_sse(msg["event"], msg["data"])
                except asyncio.TimeoutError:
                    yield SSE_KEEPALIVE
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/scan/{scan_id}/fp_review/progress")
async def agent_fp_review_progress(scan_id: str, body: AgentFpReviewProgress) -> dict:
    """Agent reports which vulnerability is currently being reviewed."""
    store = get_scan_store()
    job = store.get_fp_review_job(body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    # Auto-recover from agent disconnect: the agent's FP review task survived
    # the WebSocket reconnect and is still posting progress.
    if job.status == FpReviewStatus.ERROR and _is_agent_disconnect_error(job.error_message):
        store.update_fp_review_job(body.review_id, status="running", error_message="")
        logger.info("FP review %s auto-recovered from agent disconnect", body.review_id)
    store.update_fp_review_job(
        body.review_id,
        current_vuln_index=body.vuln_index,
        processed=body.processed,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_progress", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "processed": body.processed, "total": job.total,
    })
    logger.debug("FP review progress for %s: vuln[%d]", scan_id, body.vuln_index)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/result")
async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    """Agent pushes a single FP review result."""
    store = get_scan_store()
    job = store.get_fp_review_job(body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status == FpReviewStatus.ERROR and _is_agent_disconnect_error(job.error_message):
        store.update_fp_review_job(body.review_id, status="running", error_message="")
        logger.info("FP review %s auto-recovered from agent disconnect", body.review_id)
    now = datetime.now(timezone.utc).isoformat()
    severity = body.severity if body.severity in {"high", "medium", "low"} else "low"
    if body.verdict == "fp":
        severity = "low"
    elif severity == "low":
        severity = "medium"
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        severity=severity,
        reason=body.reason,
        vulnerability_report=body.vulnerability_report if body.verdict == "tp" else "",
        stage_outputs=body.stage_outputs,
        created_at=now,
    )
    store.add_fp_review_result(body.review_id, result)
    from backend.sse import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
        "stage_outputs": result.stage_outputs,
    })
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/stage-output")
async def agent_fp_review_stage_output(scan_id: str, body: AgentFpReviewStageOutput) -> dict:
    """Agent pushes one stage's Markdown output while FP review is running."""
    store = get_scan_store()
    job = store.get_fp_review_job(body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if body.stage not in {"prove_bug", "prove_fp", "final_judge"}:
        raise HTTPException(status_code=400, detail="Invalid FP review stage")
    now = datetime.now(timezone.utc).isoformat()
    store.upsert_fp_review_stage_output(
        body.review_id,
        body.vuln_index,
        body.stage,
        body.markdown,
        now,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_stage_output", {
        "review_id": body.review_id,
        "vuln_index": body.vuln_index,
        "stage": body.stage,
        "markdown": body.markdown,
    })
    logger.debug("FP review stage output for %s vuln[%d]: %s", scan_id, body.vuln_index, body.stage)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/finish")
async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    """Agent signals FP review job is complete."""
    store = get_scan_store()
    job = store.get_fp_review_job(body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    store.update_fp_review_job(
        body.review_id,
        status=body.status,
        clear_current_vuln_index=True,
        error_message=body.error_message,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_finish", {
        "review_id": body.review_id, "status": body.status,
        "error_message": body.error_message,
    })
    logger.info("FP review %s finished with status %s", body.review_id, body.status)
    return {"ok": True}


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    _check_scan_owner(scan_id, current_user)
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids
    store.update_scan_feedback_ids(scan_id, feedback_ids)
    try:
        await _push_feedback_selection_update(scan_id, feedback_ids)
    except Exception as exc:
        logger.debug("Failed to push feedback selection update for scan %s: %s", scan_id, exc)
    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(
    scan_id: str,
    vuln_type: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get the SKILL/prompt content for a vuln_type, merged with scan feedback.

    Reads directly from the checker registry (not the workspace) so it works
    regardless of where the agent runs.  Feedback entries associated with
    this scan are merged into a "历史用户经验" section, same as the agent
    workspace builder does.
    """
    from backend.registry import get_registry

    registry = get_registry()
    entry = registry.get(vuln_type)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Checker not found: {vuln_type}")

    # Read base content
    if entry.mode == "api":
        if not entry.prompt_path or not entry.prompt_path.is_file():
            raise HTTPException(status_code=404, detail=f"prompt.txt not found for {vuln_type}")
        original = entry.prompt_path.read_text(encoding="utf-8")
    else:
        if not entry.skill_path.is_file():
            raise HTTPException(status_code=404, detail=f"SKILL.md not found for {vuln_type}")
        original = entry.skill_path.read_text(encoding="utf-8")

    # Collect only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = _selected_feedback_entries(scan_id)

    # Deduplicate by id
    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        (fb for fb in unique_fb if fb.vuln_type == vuln_type),
        "以下是用户在审计过程中选择注入的经验，分析时应结合这些经验校验结论：",
    )

    return {"vuln_type": vuln_type, "content": original.rstrip() + fp_section}


@router.get("/api/scan/{scan_id}/skill-reports")
async def get_scan_skill_reports(
    scan_id: str,
    checker_name: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return Markdown reports generated by report-mode user SKILLs."""
    _check_scan_owner(scan_id, current_user)
    reports = get_scan_store().list_skill_reports(scan_id, checker_name)
    return {"reports": [report.model_dump() for report in reports]}


@router.get("/api/scan/{scan_id}/fp-review/skill")
async def get_fp_review_skill(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the FP review skill content, merged with user feedback for this scan."""
    _check_scan_owner(scan_id, current_user)
    skills_dir = Path(__file__).resolve().parent.parent.parent / "agent" / "skills"
    skill_paths = [
        ("prove-bug", skills_dir / "fp_review.md"),
        ("prove-fp", skills_dir / "fp_review_discriminator.md"),
        ("final-judge", skills_dir / "fp_review_final.md"),
    ]
    missing = [path.name for _, path in skill_paths if not path.is_file()]
    if missing:
        raise HTTPException(status_code=404, detail=f"FP review skill not found: {', '.join(missing)}")

    # Merge only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = _selected_feedback_entries(scan_id)

    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        unique_fb,
        "以下是用户在审计过程中选择注入的经验，复核时应结合这些经验校验结论：",
    )

    content = "\n\n---\n\n".join(
        f"# {name}\n\n{path.read_text(encoding='utf-8').rstrip()}"
        for name, path in skill_paths
    )
    return {"content": content + fp_section}
