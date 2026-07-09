"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import re
import shutil
import uuid
import zipfile
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
    HistoryPattern,
    MarkRequest,
    ScanItemStatus,
    ScanMeta,
    ScanProductList,
    ScanValidationEnvironmentList,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    SkillReport,
    ThreatAnalysis,
    ThreatAuditTask,
    UnmarkRequest,
    UpdateScanProductRequest,
    User,
    VulnerabilityValidation,
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


def _configured_validation_environments() -> list[str]:
    environments: list[str] = []
    seen: set[str] = set()
    for environment in get_config().scan.validation_environments:
        normalized = str(environment).strip()
        if normalized and normalized not in seen:
            environments.append(normalized)
            seen.add(normalized)
    return environments


def _default_validation_environment() -> str:
    environments = _configured_validation_environments()
    return environments[0] if environments else ""


def _validate_validation_environment(validation_environment: str) -> str:
    normalized = validation_environment.strip()
    environments = _configured_validation_environments()
    if not normalized:
        return environments[0] if environments else ""
    if normalized not in environments:
        raise HTTPException(status_code=400, detail=f"Unknown validation environment: {normalized}")
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


def _ensure_fp_review_job_for_scan(
    scan_id: str,
    scan: ScanStatus | None = None,
    *,
    allow_cancelled: bool = False,
    publish_started: bool = True,
    require_unresolved: bool = False,
) -> dict | None:
    """Create or reuse the scan-level FP review job for current confirmed findings."""
    store = get_scan_store()
    if scan is None:
        if scan_id in _running_scans:
            scan = _running_scans[scan_id]
        else:
            loaded = store.load_scan(scan_id)
            if loaded is None:
                return None
            scan = loaded[0]

    latest_fp_results = _latest_fp_review_result_map(scan_id)
    confirmed = _ordered_fp_review_candidates(scan, latest_fp_results)
    if not confirmed:
        return None

    processed = sum(1 for item in confirmed if int(item["index"]) in latest_fp_results)
    job = store.get_fp_review_by_scan(scan_id)
    created = False
    if require_unresolved and processed >= len(confirmed):
        if job is None:
            return None
        return {
            "review_id": job.review_id,
            "total": len(confirmed),
            "processed": processed,
            "confirmed": confirmed,
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": False,
            "no_unresolved": True,
        }
    if job is not None and job.status == FpReviewStatus.CANCELLED and not allow_cancelled:
        return {
            "review_id": job.review_id,
            "total": job.total,
            "processed": job.processed,
            "confirmed": confirmed,
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": True,
        }
    if job is None or (job.status == FpReviewStatus.CANCELLED and allow_cancelled):
        review_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        store.create_fp_review_job(review_id, scan_id, len(confirmed), now)
        job = store.get_fp_review_job(review_id)
        created = True
    if job is None:
        return None

    store.update_fp_review_job(
        job.review_id,
        status=FpReviewStatus.RUNNING.value,
        total=len(confirmed),
        processed=processed,
        error_message="",
    )
    if publish_started:
        from backend.sse import publish
        publish(scan_id, "fp_review_started", {
            "review_id": job.review_id,
            "status": FpReviewStatus.RUNNING.value,
            "total": len(confirmed),
            "processed": processed,
        })
    return {
        "review_id": job.review_id,
        "total": len(confirmed),
        "processed": processed,
        "confirmed": confirmed,
        "latest_results": latest_fp_results,
        "created": created,
        "cancelled": False,
        "no_unresolved": False,
    }


def _merge_latest_fp_review_results(job: FpReviewJob, scan_id: str) -> FpReviewJob:
    """Attach scan-wide latest per-vulnerability results to the current job.

    Stage outputs pushed by the current job are merged in even when no final
    result exists yet (failed or in-progress reviews), so a page reload still
    shows the per-stage Markdown instead of dropping the entry entirely.
    """
    store = get_scan_store()
    latest_map = _latest_fp_review_result_map(scan_id)
    stage_outputs_map: dict[int, dict[str, str]] = {}
    stage_output_sources_map: dict[int, dict] = {}
    stage_updated_at: dict[int, str] = {}
    for output in store.list_fp_review_stage_outputs_by_review(job.review_id):
        stage_outputs_map.setdefault(output.vuln_index, {})[output.stage] = output.markdown
        stage_output_sources_map.setdefault(output.vuln_index, {})[output.stage] = output.output_source
        stage_updated_at[output.vuln_index] = output.updated_at

    merged: list[FpReviewResult] = []
    for vuln_index, result in latest_map.items():
        current_stages = stage_outputs_map.pop(vuln_index, None)
        current_stage_sources = stage_output_sources_map.pop(vuln_index, None)
        if current_stages:
            result = result.model_copy(
                update={
                    "stage_outputs": {**result.stage_outputs, **current_stages},
                    "stage_output_sources": {
                        **(result.stage_output_sources or {}),
                        **(current_stage_sources or {}),
                    },
                }
            )
        merged.append(result)
    for vuln_index, stages in stage_outputs_map.items():
        # No final verdict for this vulnerability in any job — expose a
        # placeholder entry (same shape the SSE stage_output handler builds).
        merged.append(FpReviewResult(
            vuln_index=vuln_index,
            verdict="tp",
            severity="low",
            reason="",
            vulnerability_report="",
            stage_outputs=stages,
            stage_output_sources=stage_output_sources_map.get(vuln_index, {}),
            created_at=stage_updated_at.get(vuln_index, job.created_at),
        ))
    merged.sort(key=lambda result: result.vuln_index)

    return FpReviewJob(
        review_id=job.review_id,
        scan_id=job.scan_id,
        status=job.status,
        created_at=job.created_at,
        total=job.total,
        processed=job.processed,
        current_vuln_index=job.current_vuln_index,
        current_vuln_indices=job.current_vuln_indices,
        results=merged,
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validation_output_sections(content: str, *, updated_at: str | None = None) -> list[dict]:
    if not content:
        return []
    return [{
        "title": "中间产出",
        "content": content,
        "updated_at": updated_at or _now_iso(),
    }]


def _publish_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    from backend.sse import publish

    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })


def _update_running_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    scan = _running_scans.get(scan_id)
    if scan is None:
        return
    existing = next(
        (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
        None,
    )
    if existing is None:
        scan.validations.append(validation)
        scan.validations.sort(key=lambda item: item.vuln_index)
    else:
        scan.validations[existing] = validation


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


_RETRYABLE_AI_VERDICTS = {"timeout", "no_result", "failed"}


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
    validation_environment = _validate_validation_environment(body.validation_environment)

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        product=product,
        validation_environment=validation_environment,
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
        validation_environment=validation_environment,
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
        "product": product,
        "validation_environment": validation_environment,
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


@router.get("/api/scan/validation-environments", response_model=ScanValidationEnvironmentList)
async def list_scan_validation_environments(
    _current_user: User = Depends(get_current_user),
) -> ScanValidationEnvironmentList:
    """Return configured vulnerability validation environment options."""
    return ScanValidationEnvironmentList(
        validation_environments=_configured_validation_environments()
    )


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
        "product": meta.product,
        "validation_environment": meta.validation_environment or _default_validation_environment(),
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
        "product": meta.product,
        "validation_environment": meta.validation_environment or _default_validation_environment(),
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
    fp_map = _scan_fp_result_map(scan_id)
    writer.writerow([
        "file", "line", "function", "vuln_type", "severity", "confirmed",
        "fp_verdict", "fp_severity", "match_type", "match_reference", "variant_of",
        "description", "ai_analysis",
    ])
    for i, v in enumerate(scan.vulnerabilities):
        fp = fp_map.get(i)
        writer.writerow([
            v.file, v.line, v.function, v.vuln_type, v.severity, v.confirmed,
            fp.verdict if fp else "", fp.severity if fp else "",
            fp.match_type if fp else "", fp.match_reference if fp else "",
            v.variant_of, v.description, v.ai_analysis,
        ])
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


# Stage key -> Chinese title for the FP-review debate sections.
_FP_STAGE_TITLES = [
    ("history_match", "历史/校验匹配 (history_match)"),
    ("prove_bug", "确认漏洞 (prove_bug)"),
    ("prove_fp", "证明误报 (prove_fp)"),
    ("final_judge", "最终裁定 (final_judge)"),
]


def _scan_fp_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return a {vuln_index: FpReviewResult} map (with merged stage outputs) for a scan."""
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        return {}
    merged = _merge_latest_fp_review_results(job, scan_id)
    return {r.vuln_index: r for r in merged.results}


def _safe_filename_part(text: str) -> str:
    """Sanitize a string for safe use inside a download filename / zip entry."""
    cleaned = re.sub(r"[^\w.-]+", "_", text.strip())
    return cleaned.strip("._") or "item"


def _format_output_source(source) -> str:
    if source is None:
        return ""
    agent = source.agent_name or source.agent_id or ""
    tool = source.tool or source.backend or ""
    model = "CLI 默认模型" if source.use_default_model else (source.model or source.model_id or "")
    parts = [part for part in [agent, tool, model] if part]
    return " / ".join(parts)


def _validation_sections_for_report(validation: VulnerabilityValidation) -> list[dict]:
    sections: list[dict] = []
    for raw in validation.output_sections or []:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip() or "中间产出"
        content = str(raw.get("content") or "")
        sections.append({
            "title": title,
            "content": content,
            "updated_at": str(raw.get("updated_at") or ""),
        })
    if not sections and validation.intermediate_output:
        sections.append({
            "title": "中间产出",
            "content": validation.intermediate_output,
            "updated_at": validation.updated_at,
        })
    return sections


def _artifact_title(artifact: dict) -> str:
    return str(artifact.get("title") or "").strip() or "产物"


def _markdown_fence(content: str) -> tuple[str, str]:
    fence = "```"
    while fence in content:
        fence += "`"
    return fence, fence


def _append_fenced_block(lines: list[str], content: str) -> None:
    fence_start, fence_end = _markdown_fence(content)
    lines.append(fence_start)
    lines.append(content)
    lines.append(fence_end)
    lines.append("")


def _append_validation_markdown(lines: list[str], validation: VulnerabilityValidation | None) -> None:
    if validation is None:
        return

    lines.append("## 漏洞验证")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 状态 | {validation.status} |")
    if validation.product:
        lines.append(f"| 产品 | {validation.product} |")
    if validation.validation_environment:
        lines.append(f"| 验证环境 | {validation.validation_environment} |")
    lines.append(f"| 验证成功 | {validation.validation_success} |")
    lines.append(f"| 是否问题 | {validation.is_problem} |")
    lines.append(f"| 人工介入 | {validation.requires_human_intervention} |")
    if validation.started_at:
        lines.append(f"| 开始时间 | {validation.started_at} |")
    if validation.finished_at:
        lines.append(f"| 结束时间 | {validation.finished_at} |")
    lines.append("")

    final_output = validation.final_output or validation.validation_output
    if final_output:
        lines.append("### 最终结论")
        lines.append("")
        lines.append(final_output)
        lines.append("")

    sections = _validation_sections_for_report(validation)
    if sections:
        lines.append("### 输出栏")
        lines.append("")
        for section in sections:
            lines.append(f"#### {section['title']}")
            lines.append("")
            _append_fenced_block(lines, section["content"] or "（暂无）")

    artifacts = [item for item in (validation.artifacts or []) if isinstance(item, dict)]
    if artifacts:
        lines.append("### 验证产物")
        lines.append("")
        groups: dict[str, list[dict]] = {}
        for artifact in artifacts:
            groups.setdefault(_artifact_title(artifact), []).append(artifact)
        for title, items in groups.items():
            lines.append(f"#### {title}")
            lines.append("")
            for artifact in items:
                name = str(artifact.get("name") or "artifact")
                kind = str(artifact.get("kind") or "")
                path = str(artifact.get("path") or "")
                updated_at = str(artifact.get("updated_at") or "")
                lines.append(f"##### {name}")
                lines.append("")
                if kind:
                    lines.append(f"- **类型**：{kind}")
                if path:
                    lines.append(f"- **路径**：`{path}`")
                if updated_at:
                    lines.append(f"- **更新时间**：{updated_at}")
                content = str(artifact.get("content") or "")
                if content:
                    lines.append("")
                    _append_fenced_block(lines, content)
                else:
                    lines.append("")


def _vuln_report_markdown(
    idx,
    vuln,
    fp_result: FpReviewResult | None,
    validation: VulnerabilityValidation | None = None,
) -> str:
    """Render a single vulnerability (AI analysis + FP-review stages) as Markdown."""
    lines: list[str] = []
    lines.append(f"# 漏洞报告 — {vuln.vuln_type} @ {vuln.file}:{vuln.line}")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 文件 | {vuln.file} |")
    lines.append(f"| 行号 | {vuln.line} |")
    lines.append(f"| 函数 | {vuln.function} |")
    lines.append(f"| 类型 | {vuln.vuln_type} |")
    lines.append(f"| 严重级别 | {vuln.severity} |")
    lines.append(f"| AI 判定 | {vuln.ai_verdict or ('confirmed' if vuln.confirmed else '')} |")
    if getattr(vuln, "variant_of", ""):
        lines.append(f"| 同类变体来源 | {vuln.variant_of} |")
    source_text = _format_output_source(getattr(vuln, "output_source", None))
    if source_text:
        lines.append(f"| AI 输出来源 | {source_text} |")
    if vuln.user_verdict:
        lines.append(f"| 用户判定 | {vuln.user_verdict} |")
    lines.append("")
    lines.append("## 描述")
    lines.append("")
    lines.append(vuln.description or "（无）")
    lines.append("")
    if vuln.user_verdict_reason:
        lines.append("## 用户判定理由")
        lines.append("")
        lines.append(vuln.user_verdict_reason)
        lines.append("")
    lines.append("## AI 分析")
    lines.append("")
    lines.append(vuln.ai_analysis or "（无）")
    lines.append("")

    if fp_result is not None:
        lines.append("## 去误报复核")
        lines.append("")
        verdict_label = {"tp": "真实漏洞 (tp)", "fp": "误报 (fp)"}.get(fp_result.verdict, fp_result.verdict)
        lines.append(f"- **最终结论**：{verdict_label}")
        lines.append(f"- **严重级别**：{fp_result.severity}")
        if getattr(fp_result, "match_type", ""):
            match_label = {"history": "对应历史问题模式", "validation": "对应其它函数校验"}.get(
                fp_result.match_type, fp_result.match_type
            )
            lines.append(f"- **匹配类型**：{match_label}")
        if getattr(fp_result, "match_reference", ""):
            lines.append(f"- **对应修复/校验**：{fp_result.match_reference}")
        fp_source_text = _format_output_source(fp_result.output_source)
        if fp_source_text:
            lines.append(f"- **最终输出来源**：{fp_source_text}")
        if fp_result.reason:
            lines.append(f"- **理由**：{fp_result.reason}")
        lines.append("")
        for key, title in _FP_STAGE_TITLES:
            stage_md = (fp_result.stage_outputs or {}).get(key)
            if not stage_md:
                continue
            lines.append(f"### 阶段：{title}")
            lines.append("")
            stage_source = _format_output_source((fp_result.stage_output_sources or {}).get(key))
            if stage_source:
                lines.append(f"> 输出来源：{stage_source}")
                lines.append("")
            lines.append(stage_md)
            lines.append("")

    _append_validation_markdown(lines, validation)

    return "\n".join(lines).rstrip() + "\n"


@router.get("/api/scan/{scan_id}/vulnerability/{idx}/report")
async def download_vulnerability_report(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download a single vulnerability's report (AI analysis + FP review) as Markdown."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    fp_map = _scan_fp_result_map(scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    markdown = _vuln_report_markdown(idx, vuln, fp_map.get(idx), validation_map.get(idx))
    fname = f"vuln-{idx}-{_safe_filename_part(vuln.file)}_{vuln.line}.md"
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


async def _trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    _server_url: str,
) -> dict:
    """Start Agent-side local validation for one AI-confirmed vulnerability."""
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    loaded = store.load_scan(scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
        raise HTTPException(status_code=400, detail="Only AI-confirmed vulnerabilities can be validated")

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is not None and existing.running:
        raise HTTPException(status_code=409, detail="Validation already running")

    if not meta.agent_id and not meta.agent_name:
        raise HTTPException(status_code=400, detail="No agent associated with this scan")
    agent_id = _resolve_scan_agent_id(meta)
    if agent_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )
    if agent_id != meta.agent_id:
        store.update_scan_agent(scan_id, agent_id, meta.agent_name)

    now = _now_iso()
    queued_output = "验证任务已提交到 Agent，等待本地脚本启动。"
    validation = store.upsert_vulnerability_validation(
        scan_id,
        VulnerabilityValidation(
            scan_id=scan_id,
            vuln_index=idx,
            status="queued",
            running=True,
            product=meta.product,
            validation_environment=meta.validation_environment or _default_validation_environment(),
            intermediate_output=queued_output,
            output_sections=_validation_output_sections(queued_output, updated_at=now),
            started_at=now,
            updated_at=now,
        ),
    )
    _publish_validation(scan_id, validation)
    _update_running_validation(scan_id, validation)

    fp_map = _scan_fp_result_map(scan_id)
    ok = await send_agent_command(agent_id, {
        "type": "vulnerability_validation",
        "scan_id": scan_id,
        "vuln_index": idx,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "product": meta.product,
        "validation_environment": meta.validation_environment or _default_validation_environment(),
        "vulnerability": vuln.model_dump(),
        "report_markdown": _vuln_report_markdown(idx, vuln, fp_map.get(idx)),
    })
    if not ok:
        failed = store.upsert_vulnerability_validation(
            scan_id,
            validation.model_copy(update={
                "status": "error",
                "running": False,
                "validation_output": "Agent not connected",
                "requires_human_intervention": True,
                "finished_at": _now_iso(),
                "updated_at": _now_iso(),
            }),
        )
        _publish_validation(scan_id, failed)
        _update_running_validation(scan_id, failed)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info("Manual vulnerability validation triggered for scan %s idx %d via agent %s", scan_id, idx, agent_id)
    return {"ok": True, "vuln_index": idx}


async def _stop_vulnerability_validation(scan_id: str, idx: int) -> dict:
    """Cancel one Agent-side local validation for a vulnerability."""
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    loaded = store.load_scan(scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="Validation not found")

    active = existing.running or existing.status in {"pending", "queued", "running"}
    if active:
        now = _now_iso()
        validation = store.upsert_vulnerability_validation(
            scan_id,
            existing.model_copy(update={
                "status": "cancelled",
                "running": False,
                "validation_success": False,
                "requires_human_intervention": True,
                "validation_output": "用户手动停止",
                "final_output": "用户手动停止",
                "finished_at": now,
                "updated_at": now,
            }),
        )
        _publish_validation(scan_id, validation)
        _update_running_validation(scan_id, validation)
    else:
        validation = existing

    agent_id = _resolve_scan_agent_id(meta)
    if active and agent_id is not None:
        if agent_id != meta.agent_id:
            store.update_scan_agent(scan_id, agent_id, meta.agent_name)
        await send_agent_command(agent_id, {
            "type": "vulnerability_validation_stop",
            "scan_id": scan_id,
            "vuln_index": idx,
        })

    logger.info("Vulnerability validation for scan %s idx %d cancelled by user", scan_id, idx)
    return {"ok": True, "vuln_index": idx, "status": validation.status}


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation")
async def trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Manually start Agent-side local validation for one confirmed vulnerability."""
    _check_scan_owner(scan_id, current_user)
    return await _trigger_vulnerability_validation(scan_id, idx, _server_url_from_request(request))


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation/stop")
async def stop_vulnerability_validation(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel Agent-side local validation for one vulnerability."""
    _check_scan_owner(scan_id, current_user)
    return await _stop_vulnerability_validation(scan_id, idx)


@router.get("/api/scan/{scan_id}/report.zip")
async def download_report_zip(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download all AI-confirmed vulnerabilities as a zip of Markdown reports."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    fp_map = _scan_fp_result_map(scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}

    confirmed = [
        (i, v)
        for i, v in enumerate(scan.vulnerabilities)
        if v.confirmed or v.ai_verdict == "confirmed"
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not confirmed:
            zf.writestr("README.md", f"# 扫描 {scan_id}\n\n本次扫描没有 AI 确认为问题的漏洞。\n")
        else:
            index_lines = [f"# 扫描 {scan_id} 漏洞报告索引", "", f"共 {len(confirmed)} 个 AI 确认问题：", ""]
            for i, v in confirmed:
                entry = f"vuln-{i}-{_safe_filename_part(v.file)}_{v.line}.md"
                index_lines.append(f"- [{v.vuln_type} @ {v.file}:{v.line}]({entry})")
                zf.writestr(entry, _vuln_report_markdown(i, v, fp_map.get(i), validation_map.get(i)))
            zf.writestr("README.md", "\n".join(index_lines) + "\n")
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.zip"'},
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


async def _start_fp_review(
    scan_id: str,
    server_url: str,
    *,
    raise_on_error: bool = True,
) -> dict | None:
    """Start an AI false-positive review for all confirmed vulnerabilities in a scan.

    Shared by the manual trigger endpoint and the auto-trigger on scan completion.
    When ``raise_on_error`` is False, failures are logged and ``None`` is returned
    instead of raising — used by the auto-trigger path so a failed/blocked review
    never breaks scan-finish handling.
    """
    from backend.api.agent import (
        create_agent_runtime_update_payload,
        send_agent_command,
        _registered_agents,
        _agent_ws,
    )

    def _fail(status_code: int, detail: str) -> None:
        if raise_on_error:
            raise HTTPException(status_code=status_code, detail=detail)
        logger.warning("Auto FP review for scan %s skipped: %s", scan_id, detail)
        return None

    store = get_scan_store()
    if scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        loaded = store.load_scan(scan_id)
        if loaded is None:
            return _fail(404, "Scan not found")
        scan = loaded[0]

    fp_job_info = _ensure_fp_review_job_for_scan(
        scan_id,
        scan,
        allow_cancelled=True,
        publish_started=False,
    )
    if fp_job_info is None:
        return _fail(400, "No confirmed vulnerabilities to review")
    confirmed = fp_job_info["confirmed"]
    review_id = str(fp_job_info["review_id"])

    meta = store.get_scan_meta(scan_id)
    if meta is None:
        return _fail(404, "Scan not found")

    if not meta.agent_id and not meta.agent_name:
        return _fail(400, "No agent associated with this scan")

    # Resolve agent_id — may be stale if agent reconnected
    agent_id = meta.agent_id
    if not agent_id or agent_id not in _agent_ws:
        agent_id = None
        if meta.agent_name:
            for aid, ainfo in _registered_agents.items():
                if ainfo.name == meta.agent_name and aid in _agent_ws:
                    agent_id = aid
                    break
    if agent_id is None:
        return _fail(
            400,
            f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        store.update_scan_agent(scan_id, agent_id, meta.agent_name)

    feedback_entries = [entry.model_dump() for entry in _selected_feedback_entries(scan_id, meta.feedback_ids)]

    ok = await send_agent_command(agent_id, {
        "type": "fp_review",
        "scan_id": scan_id,
        "review_id": review_id,
        "project_path": meta.project_path,
        "vulnerabilities": confirmed,
        "feedback_entries": feedback_entries,
        "processed_offset": 0,
        "agent_runtime_update": create_agent_runtime_update_payload(server_url),
    })
    if not ok:
        store.update_fp_review_job(review_id, status="error", error_message="Agent not connected")
        return _fail(502, "Agent not connected")

    store.update_fp_review_job(review_id, status="running", processed=0)
    from backend.sse import publish
    publish(scan_id, "fp_review_started", {
        "review_id": review_id, "status": "running", "total": len(confirmed), "processed": 0,
    })
    logger.info("FP review %s triggered for scan %s (%d candidates)", review_id, scan_id, len(confirmed))
    return {
        "ok": True,
        "review_id": review_id,
        "status": "running",
        "total": len(confirmed),
        "processed": 0,
    }


@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger AI false-positive review for all confirmed vulnerabilities in a scan."""
    _check_scan_owner(scan_id, current_user)
    return await _start_fp_review(scan_id, _server_url_from_request(request), raise_on_error=True)


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


@router.get("/api/scan/{scan_id}/git_history", response_model=list[HistoryPattern])
async def get_scan_git_history(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[HistoryPattern]:
    """Return the git-history security problem patterns mined for a scan."""
    _check_scan_owner(scan_id, current_user)
    return get_scan_store().get_git_history_patterns(scan_id)


@router.get("/api/scan/{scan_id}/threat-analysis", response_model=ThreatAnalysis)
async def get_scan_threat_analysis(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ThreatAnalysis:
    """Return the attack-tree threat analysis result for a scan."""
    _check_scan_owner(scan_id, current_user)
    analysis = get_scan_store().get_threat_analysis(scan_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat analysis found for this scan")
    return analysis


@router.get("/api/scan/{scan_id}/threat-audit-tasks", response_model=list[ThreatAuditTask])
async def get_scan_threat_audit_tasks(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for a scan."""
    _check_scan_owner(scan_id, current_user)
    return get_scan_store().list_threat_audit_tasks(scan_id)


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
        current_vuln_indices=body.active_indices,
        processed=body.processed,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_progress", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "active_indices": body.active_indices,
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
    # 去误报定级简化为二元：tp 且外部可触发（或命中历史/校验匹配）为 high，其余一律 low。
    severity = "high" if (body.verdict == "tp" and body.severity == "high") else "low"
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        severity=severity,
        reason=body.reason,
        vulnerability_report=body.vulnerability_report if body.verdict == "tp" else "",
        stage_outputs=body.stage_outputs,
        match_reference=body.match_reference,
        match_type=body.match_type,
        stage_output_sources=body.stage_output_sources,
        output_source=body.output_source,
        created_at=now,
    )
    store.add_fp_review_result(body.review_id, result)
    from backend.sse import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
        "stage_outputs": result.stage_outputs,
        "match_reference": result.match_reference,
        "match_type": result.match_type,
        "stage_output_sources": {
            key: value.model_dump() for key, value in result.stage_output_sources.items()
        },
        "output_source": result.output_source.model_dump(),
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
    if job.status == FpReviewStatus.ERROR and _is_agent_disconnect_error(job.error_message):
        store.update_fp_review_job(body.review_id, status="running", error_message="")
        logger.info("FP review %s auto-recovered from agent disconnect", body.review_id)
    if body.stage not in {"history_match", "prove_bug", "prove_fp", "final_judge"}:
        raise HTTPException(status_code=400, detail="Invalid FP review stage")
    now = datetime.now(timezone.utc).isoformat()
    store.upsert_fp_review_stage_output(
        body.review_id,
        body.vuln_index,
        body.stage,
        body.markdown,
        now,
        body.output_source,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_stage_output", {
        "review_id": body.review_id,
        "vuln_index": body.vuln_index,
        "stage": body.stage,
        "markdown": body.markdown,
        "output_source": body.output_source.model_dump(),
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
