"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import queue as _stdlib_queue
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
    UnmarkRequest,
    UpdateScanProductRequest,
    User,
)
from backend.opencode.feedback_format import build_feedback_section
from backend.scan_metrics import calculate_issue_metrics, is_effective_fp_review_result
from backend.store import get_scan_store
from backend.registry import CHECKER_VISIBILITY_ADMIN, refresh_registry

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}

# Map scan_id → user_id for ownership checks on in-memory scans
_scan_owners: dict[str, str] = {}


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
    result = store.load_scan(scan_id)
    if result is not None:
        _, meta = result
        if meta.user_id == user.user_id:
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
        if not v.confirmed or v.user_verdict:
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
    loaded = get_scan_store().load_scan(scan_id)
    if loaded is None:
        return []
    return loaded[1].feedback_ids


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


def _retry_incomplete_candidates(scan: ScanStatus) -> list[Candidate]:
    candidates: list[Candidate] = []
    for vuln in scan.vulnerabilities:
        if vuln.user_verdict:
            continue
        if (vuln.ai_verdict or "") not in _RETRYABLE_AI_VERDICTS:
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
    loaded = get_scan_store().load_scan(scan_id)
    if loaded is None:
        return
    _, meta = loaded
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
    from backend.api.agent import reconcile_offline_agent_scan_state

    store = get_scan_store()
    if current_user.role == "admin":
        summaries = store.list_scans()
    else:
        summaries = store.list_scans_by_user(current_user.user_id)
    for s in summaries:
        scan_for_status = None
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            live.agent_name = s.agent_name or live.agent_name
            scan_for_status = live
            vulnerabilities = live.vulnerabilities
        else:
            loaded = store.load_scan(s.scan_id)
            if loaded is not None:
                scan_for_status = loaded[0]
                scan_for_status.agent_name = loaded[1].agent_name
                vulnerabilities = scan_for_status.vulnerabilities
            else:
                vulnerabilities = []

        if scan_for_status is not None:
            scan_for_status = reconcile_offline_agent_scan_state(
                s.scan_id,
                scan_for_status,
            )
            s.status = scan_for_status.status
            s.progress = scan_for_status.progress
            s.total_candidates = scan_for_status.total_candidates
            s.processed_candidates = scan_for_status.processed_candidates
            s.agent_online = scan_for_status.agent_online
            s.retryable_candidates_count = _retry_incomplete_count(scan_for_status)

        metrics = calculate_issue_metrics(
            vulnerabilities,
            _latest_fp_review_result_map(s.scan_id),
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
    if store.load_scan(scan_id) is None:
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
    result = store.load_scan(scan_id)
    agent_id = result[1].agent_id if result else ""

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
) -> str:
    """Mark a single vulnerability and create a feedback entry. Returns feedback_id."""
    if verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    vuln = scan.vulnerabilities[index]
    normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = verdict
            live.vulnerabilities[index].user_verdict_reason = reason
            live.vulnerabilities[index].ticket_submitted = ticket_submitted
            live.vulnerabilities[index].ticket_id = normalized_ticket_id

    store.update_vulnerability(
        scan_id,
        index,
        verdict,
        reason,
        ticket_submitted,
        normalized_ticket_id,
    )

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
        scan_result = store.load_scan(scan_id)
        if scan_result is not None:
            smeta = scan_result[1]
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

    return entry.id


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
    """Mark a vulnerability as confirmed or false positive."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id = _mark_single(
        scan_id,
        scan,
        store,
        body.index,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    return {"ok": True, "feedback_id": feedback_id}


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
    """Batch-mark multiple vulnerabilities as confirmed or false positive."""
    _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids = [
        _mark_single(
            scan_id,
            scan,
            store,
            item.index,
            item.verdict,
            item.reason,
            item.ticket_submitted,
            item.ticket_id,
        )
        for item in body.items
    ]
    return {"ok": True, "feedback_ids": feedback_ids}


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

    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    meta = result[1]

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
    return {"ok": True, "review_id": review_id}


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

    loaded = store.load_scan(scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    _, meta = loaded

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
        result = store.load_scan(scan_id)
        if result is not None:
            _, meta = result
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
        created_at=now,
    )
    store.add_fp_review_result(body.review_id, result)
    from backend.sse import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
    })
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
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


# ---------------------------------------------------------------------------
# Internal: scan execution
# ---------------------------------------------------------------------------


async def _wait_for_db(
    project_dir: Path, scan: ScanStatus, emit_fn
) -> "CodeDatabase | None":
    """Wait for the code index DB to be ready, with stall detection.

    Instead of a hard 120s timeout, keeps waiting as long as indexing
    is making progress.  Only gives up after 120s of no progress.
    """
    import json as _json

    from code_parser import CodeDatabase

    status_path = project_dir / "parse_status.json"
    db_path = project_dir / "code_index.db"

    MAX_STALL_SECONDS = 120
    last_progress = 0
    stall_counter = 0

    emit_fn("init", "正在等待代码索引...")
    while True:
        if status_path.exists():
            try:
                info = _json.loads(status_path.read_text())
                s = info.get("status")
                if s == "done":
                    emit_fn("init", "代码索引完成")
                    return CodeDatabase(db_path)
                if s == "error":
                    emit_fn("init", f"代码索引失败: {info.get('error', '')} — 将在无索引状态下继续")
                    return None

                current = info.get("parsed_files", 0)
                total = info.get("total_files", 0)
                if current > last_progress:
                    last_progress = current
                    stall_counter = 0
                    emit_fn("init", f"代码索引中: {current}/{total} 文件")
                else:
                    stall_counter += 1
            except Exception:
                stall_counter += 1

        else:
            stall_counter += 1

        if stall_counter >= MAX_STALL_SECONDS:
            emit_fn("init", "代码索引超时（无进展） — 将在无索引状态下继续")
            return None

        await asyncio.sleep(1)


_QUEUE_DONE = object()  # 哨兵值：生产者完成
_CHECKER_DONE = object()  # 哨��值：当前 checker 候选产出完毕


async def _run_scan(
    scan_id: str,
    project_id: str,
    project_dir: Path,
    scan_items: list[str],
    *,
    processed_keys: set[tuple[str, int, str, str]] | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Background task: producer-consumer pipeline for static analysis + AI audit."""
    scan = _running_scans[scan_id]
    registry = get_registry()
    store = get_scan_store()
    if processed_keys is None:
        processed_keys = set()
    workspace: Path | None = None

    def emit(phase: str, message: str, candidate_index: int | None = None) -> None:
        event = ScanEvent.create(phase, message, candidate_index)
        scan.events.append(event)
        store.add_event(scan_id, event)

    try:
        # Phase 0: Initialize
        emit("init", "Initializing scan workspace...")
        logger.info("Scan %s: initializing", scan_id)

        db = await _wait_for_db(project_dir, scan, emit)

        emit("mcp_ready", "MCP Server connected")

        # Phase 1+2: Static analysis + AI audit (concurrent via queue)
        scan.status = ScanItemStatus.ANALYZING
        store.update_scan_progress(scan_id, status=ScanItemStatus.ANALYZING)

        from backend.opencode.config import create_scan_workspace
        from backend.opencode.runner import run_audit, run_audit_batch, run_project_audit

        workspace = create_scan_workspace(scan_id, project_dir=project_dir, feedback_entries=feedback_entries)
        _scan_workspaces[scan_id] = workspace
        store.update_scan_workspace(scan_id, str(workspace))
        cancel_event = _scan_cancel_events[scan_id]

        candidate_queue: asyncio.Queue = asyncio.Queue()
        producer_error: list[Exception] = []
        _ANALYSIS_DONE = object()  # 哨兵值：单个 checker 分析完成

        # ---- 生产者：静态分析，将候选放入队列 ----
        # find_candidates() 是同步阻塞调用（tree-sitter 解析 / DB 查询），
        # 在线程池中运行，通过线程安全队列桥接到 async producer，
        # 保持流式产出（静态分析与 LLM 审计并发）+ 支持取消。
        async def _producer() -> None:
            try:
                for checker_name in scan_items:
                    if cancel_event.is_set():
                        break

                    entry = registry[checker_name]
                    if not entry.analyzer:
                        if entry.mode == "opencode":
                            candidate = Candidate(
                                file=".",
                                line=1,
                                function="__project__",
                                description=f"Project-level audit for {entry.label}",
                                vuln_type=entry.name,
                            )
                            cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                            if cand_key not in processed_keys:
                                scan.total_candidates += 1
                                store.update_scan_progress(scan_id, total_candidates=scan.total_candidates)
                                await candidate_queue.put(candidate)
                                emit("static_analysis", f"{entry.label}: 生成项目级候选")
                            await candidate_queue.put(_CHECKER_DONE)
                        else:
                            emit("static_analysis", f"{entry.label}: 无静态分析器，跳过")
                        continue

                    emit("static_analysis", f"正在运行 {entry.label} 分析...")

                    analyzer = entry.analyzer

                    # 设置文件级进度回调（从线程中调用，CPython 下线程安全）
                    def _on_file_progress(current: int, total: int, label: str = entry.label) -> None:
                        scan.static_scanned_files = current
                        scan.static_total_files = total
                        emit("static_analysis", f"{label}: 已扫描 {current}/{total} 文件")
                        store.update_scan_progress(
                            scan_id,
                            static_scanned_files=current,
                            static_total_files=total,
                        )

                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = _on_file_progress
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = _on_file_progress

                    # 线程安全队列：线程中的 find_candidates → async producer
                    bridge: _stdlib_queue.Queue = _stdlib_queue.Queue(maxsize=200)

                    def _blocking_find(a=analyzer, pd=project_dir, d=db) -> None:
                        try:
                            for c in a.find_candidates(pd, db=d):
                                if cancel_event.is_set():
                                    break
                                bridge.put(c)
                        except Exception as exc:
                            bridge.put(exc)
                        finally:
                            bridge.put(_ANALYSIS_DONE)

                    loop = asyncio.get_running_loop()
                    fut = loop.run_in_executor(None, _blocking_find)

                    checker_count = 0
                    while True:
                        # 非阻塞轮询 bridge queue，交还事件循环控制权
                        try:
                            item = bridge.get_nowait()
                        except _stdlib_queue.Empty:
                            if cancel_event.is_set():
                                break
                            await asyncio.sleep(0.05)
                            continue

                        if item is _ANALYSIS_DONE:
                            break
                        if isinstance(item, Exception):
                            raise item

                        candidate = item
                        cand_key = (candidate.file, candidate.line,
                                    candidate.function, candidate.vuln_type)
                        if cand_key in processed_keys:
                            continue

                        checker_count += 1
                        scan.total_candidates += 1
                        store.update_scan_progress(
                            scan_id, total_candidates=scan.total_candidates,
                        )

                        await candidate_queue.put(candidate)

                    await asyncio.wrap_future(fut)  # 确保线程完成

                    # 清理进度回调
                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = None
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = None

                    emit("static_analysis", f"{entry.label} 完成: {checker_count} 个候选")
                    logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, checker_count)
                    await candidate_queue.put(_CHECKER_DONE)

                scan.static_analysis_done = True
                store.update_scan_progress(scan_id, static_analysis_done=True)
                emit("static_analysis", "全部静态分析完成")
            except Exception as e:
                producer_error.append(e)
                raise
            finally:
                await candidate_queue.put(_QUEUE_DONE)

        # ---- 消费者：LLM 审计，按函数分组批量调用 ----
        async def _consumer() -> None:
            candidate_index = scan.processed_candidates
            # 缓冲区：按 (file, function, vuln_type) 分组
            buffer: dict[tuple[str, str, str], list[Candidate]] = {}

            async def _flush_buffer() -> None:
                """将缓冲区中的候选按函数分组批量审计。"""
                nonlocal candidate_index

                for group_key, group in buffer.items():
                    if cancel_event.is_set():
                        break

                    # 切换�� auditing 状态
                    if scan.status == ScanItemStatus.ANALYZING:
                        scan.status = ScanItemStatus.AUDITING
                        store.update_scan_progress(scan_id, status=ScanItemStatus.AUDITING)

                    base_index = candidate_index
                    scan.current_candidate = group[0]

                    if len(group) == 1:
                        # 单候选：走原有逻辑
                        candidate = group[0]
                        i = candidate_index
                        candidate_index += 1

                        emit(
                            "auditing",
                            f"[候选 {i + 1}] 审计 {candidate.vuln_type.upper()} "
                            f"at {candidate.file}:{candidate.line} — {candidate.function}",
                            candidate_index=i,
                        )
                        logger.info(
                            "Scan %s: auditing candidate %d — %s:%d",
                            scan_id, i + 1, candidate.file, candidate.line,
                        )
                        store.update_scan_progress(scan_id, current_candidate=candidate)

                        def on_output(line: str, idx: int = i) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        if candidate.function == "__project__":
                            project_vulns = await run_project_audit(
                                workspace, candidate, project_id,
                                on_output=on_output,
                                cancel_event=cancel_event,
                                project_dir=project_dir,
                            )
                        else:
                            project_vulns = None
                            vuln = await run_audit(
                                workspace, candidate, project_id,
                                on_output=on_output,
                                cancel_event=cancel_event,
                                project_dir=project_dir,
                            )

                        if cancel_event.is_set():
                            break

                        if candidate.function == "__project__":
                            if not project_vulns:
                                project_vulns = [
                                    Vulnerability(
                                        file=candidate.file,
                                        line=candidate.line,
                                        function=candidate.function,
                                        vuln_type=candidate.vuln_type,
                                        severity="unknown",
                                        description=candidate.description,
                                        ai_analysis="No analysis result (AI did not complete analysis)",
                                        confirmed=False,
                                        ai_verdict="no_result",
                                    )
                                ]
                            for project_vuln in project_vulns:
                                scan.vulnerabilities.append(project_vuln)
                                store.add_vulnerability(scan_id, project_vuln)
                            confirmed_project = sum(1 for v in project_vulns if v.confirmed)
                            emit(
                                "auditing",
                                f"[候选 {i + 1}] Result: {confirmed_project} confirmed / {len(project_vulns)} submitted",
                                candidate_index=i,
                            )
                            cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                            scan.processed_candidates = i + 1
                            scan.progress = (i + 1) / max(scan.total_candidates, 1)
                            store.add_processed_key(scan_id, cand_key)
                            store.update_scan_progress(
                                scan_id,
                                processed_candidates=scan.processed_candidates,
                                progress=scan.progress,
                            )
                            continue

                        if vuln is None:
                            vuln = Vulnerability(
                                file=candidate.file,
                                line=candidate.line,
                                function=candidate.function,
                                vuln_type=candidate.vuln_type,
                                severity="unknown",
                                description=candidate.description,
                                ai_analysis="No analysis result (AI did not complete analysis)",
                                confirmed=False,
                                ai_verdict="no_result",
                            )
                        scan.vulnerabilities.append(vuln)
                        _vl = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "timeout": "timeout", "no_result": "no result"}
                        status = _vl.get(vuln.ai_verdict, "not confirmed")
                        emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                        cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                        scan.processed_candidates = i + 1
                        scan.progress = (i + 1) / max(scan.total_candidates, 1)
                        store.add_vulnerability(scan_id, vuln)
                        store.add_processed_key(scan_id, cand_key)
                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )
                    else:
                        # 多候选：批量审计
                        emit(
                            "auditing",
                            f"[批量] 审计 {group[0].vuln_type.upper()} "
                            f"函数 {group[0].function}（{len(group)} 个候选）",
                            candidate_index=base_index,
                        )
                        logger.info(
                            "Scan %s: batch auditing %s:%s (%d candidates)",
                            scan_id, group[0].file, group[0].function, len(group),
                        )
                        store.update_scan_progress(scan_id, current_candidate=group[0])

                        def on_batch_output(line: str, idx: int = base_index) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        vulns = await run_audit_batch(
                            workspace, group, project_id,
                            on_output=on_batch_output,
                            cancel_event=cancel_event,
                            project_dir=project_dir,
                        )

                        if cancel_event.is_set():
                            break

                        for j, (candidate, vuln) in enumerate(zip(group, vulns)):
                            i = candidate_index
                            candidate_index += 1

                            if vuln is None:
                                vuln = Vulnerability(
                                    file=candidate.file,
                                    line=candidate.line,
                                    function=candidate.function,
                                    vuln_type=candidate.vuln_type,
                                    severity="unknown",
                                    description=candidate.description,
                                    ai_analysis="No analysis result (AI did not complete analysis)",
                                    confirmed=False,
                                    ai_verdict="no_result",
                                )
                            scan.vulnerabilities.append(vuln)
                            _vl2 = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "timeout": "timeout", "no_result": "no result"}
                            status = _vl2.get(vuln.ai_verdict, "not confirmed")
                            emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                            cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                            scan.processed_candidates = i + 1
                            scan.progress = (i + 1) / max(scan.total_candidates, 1)
                            store.add_vulnerability(scan_id, vuln)
                            store.add_processed_key(scan_id, cand_key)

                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )

                buffer.clear()

            while True:
                # 带超时地等待，以便检查 cancel_event
                try:
                    item = await asyncio.wait_for(candidate_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # 超时期间如果 buffer 有数据，flush 它（实现流式并发）
                    if buffer and not cancel_event.is_set():
                        await _flush_buffer()
                    if cancel_event.is_set():
                        break
                    continue

                if item is _QUEUE_DONE:
                    await _flush_buffer()
                    break
                if item is _CHECKER_DONE:
                    await _flush_buffer()
                    continue
                if cancel_event.is_set():
                    break

                candidate = item
                key = (candidate.file, candidate.function, candidate.vuln_type)

                # 新 group key 到达时，flush 旧分组（它们已完整）
                # 同函数的候选在 find_candidates 中连续产出，
                # 新 key 说明之前的分组不会再有新成员
                if key not in buffer and buffer:
                    await _flush_buffer()

                buffer.setdefault(key, []).append(candidate)

        # ---- 并发运行生产者和消费者 ----
        producer_task = asyncio.create_task(_producer())
        consumer_task = asyncio.create_task(_consumer())

        done, pending = await asyncio.wait(
            [producer_task, consumer_task],
            return_when=asyncio.FIRST_EXCEPTION,
        )

        # 如果有异常，取消另一个任务
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # 抛出已完成任务中的异常
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc

        scan.current_candidate = None

        if cancel_event.is_set():
            scan.status = ScanItemStatus.CANCELLED
            emit("complete", f"Scan cancelled after {scan.processed_candidates} candidates")
            store.update_scan_progress(
                scan_id,
                status=ScanItemStatus.CANCELLED,
                clear_current_candidate=True,
            )
            logger.info("Scan %s: cancelled", scan_id)
            return

        confirmed = sum(1 for v in scan.vulnerabilities if v.confirmed)
        scan.status = ScanItemStatus.COMPLETE
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {scan.total_candidates} candidates")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            clear_current_candidate=True,
        )
        logger.info(
            "Scan %s: complete — %d vulnerabilities found",
            scan_id, len(scan.vulnerabilities),
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanItemStatus.ERROR
        scan.error_message = str(e)
        emit("error", f"Scan failed: {e}")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message=str(e),
        )
    finally:
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)
        _scan_cancel_events.pop(scan_id, None)
        _scan_workspaces.pop(scan_id, None)
        if workspace is not None:
            from backend.opencode.config import cleanup_workspace
            cleanup_workspace(workspace)
