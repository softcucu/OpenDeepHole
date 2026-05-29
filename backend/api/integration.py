"""External-platform integration APIs for script-driven scans."""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.api import checkers as checkers_api
from backend.api import feedback as feedback_api
from backend.api import scan as scan_api
from backend.auth import hash_password
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    BatchMarkRequest,
    CheckerInfo,
    CreateScanRequest,
    FeedbackCreateRequest,
    FeedbackEntry,
    FeedbackUpdateRequest,
    FpReviewJob,
    MarkRequest,
    ScanStatus,
    User,
)
from backend.registry import CHECKER_VISIBILITY_PUBLIC, refresh_registry
from backend.scan_metrics import calculate_issue_metrics
from backend.store import get_scan_store

router = APIRouter()

INTEGRATION_TOKEN = "opendeephole-integration-token"
INTEGRATION_USERNAME = "opendeephole_integration"
INTEGRATION_PASSWORD = "opendeephole_integration_password"


class IntegrationScanRequest(BaseModel):
    agent_name: str
    project_path: str
    code_scan_path: str = ""
    scan_name: str = ""
    product: str = ""
    agent_config: AgentRemoteConfig = Field(default_factory=AgentRemoteConfig)


class IntegrationScanResponse(BaseModel):
    scan_id: str
    result_url: str
    progress_api_url: str
    checker_count: int
    checkers: list[str]


class PublicScanProgress(BaseModel):
    scan_id: str
    status: str
    progress: float
    total_candidates: int
    processed_candidates: int
    issue_count: int
    raw_vulnerability_count: int
    static_total_files: int
    static_scanned_files: int
    result_url: str
    error_message: str | None = None


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _result_url(request: Request, scan_id: str, token: str) -> str:
    return f"{_base_url(request)}/#/public-scan/{scan_id}?token={token}"


def _progress_api_url(request: Request, scan_id: str, token: str) -> str:
    return f"{_base_url(request)}/api/public/scans/{scan_id}/progress?token={token}"


def _ensure_integration_user() -> User:
    store = get_scan_store()
    user = store.get_user_by_username(INTEGRATION_USERNAME)
    if user is None:
        store.create_user(
            uuid.uuid4().hex,
            INTEGRATION_USERNAME,
            hash_password(INTEGRATION_PASSWORD),
            "user",
            INTEGRATION_TOKEN,
        )
        user = store.get_user_by_username(INTEGRATION_USERNAME)
    if user is None:
        raise HTTPException(status_code=500, detail="Integration user unavailable")
    return User(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        agent_token=user.agent_token,
        created_at=user.created_at,
    )


def _require_integration_token(
    token: str = Header("", alias="X-OpenDeepHole-Integration-Token"),
) -> User:
    if not secrets.compare_digest(token, INTEGRATION_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid integration token")
    return _ensure_integration_user()


def _online_agents_by_name(agent_name: str) -> list[tuple[str, AgentInfo]]:
    from backend.api import agent as agent_api

    matches: list[tuple[str, AgentInfo]] = []
    for agent_id, agent in agent_api._registered_agents.items():
        if agent.name == agent_name and agent_api._is_agent_online(agent):
            matches.append((agent_id, agent))
    return matches


def _resolve_agent_id(agent_name: str) -> str:
    name = agent_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="agent_name is required")
    matches = _online_agents_by_name(name)
    if not matches:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' is not online")
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail=f"Multiple online agents named '{name}'")
    return matches[0][0]


def _public_checker_names() -> list[str]:
    registry = refresh_registry()
    names = [
        name for name, entry in registry.items()
        if entry.visibility == CHECKER_VISIBILITY_PUBLIC
    ]
    if not names:
        raise HTTPException(status_code=400, detail="No public enabled checkers available")
    return names


async def _sync_agent_config(agent_id: str, config: AgentRemoteConfig) -> None:
    from backend.api import agent as agent_api

    agent = agent_api._registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent_api._agent_configs[agent.name] = config
    ok = await agent_api.send_agent_command(
        agent_id,
        {"type": "config", "config": config.model_dump()},
    )
    if not ok:
        raise HTTPException(status_code=502, detail="Agent not connected")


def _public_user_for_scan(scan_id: str, token: str) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Missing scan access token")
    store = get_scan_store()
    loaded = store.load_scan(scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    _, meta = loaded
    if not meta.public_access_token or not secrets.compare_digest(token, meta.public_access_token):
        raise HTTPException(status_code=403, detail="Invalid scan access token")
    owner = store.get_user_by_id(meta.user_id) if meta.user_id else None
    if owner is None:
        return User(user_id=meta.user_id, username="", role="user")
    return User(
        user_id=owner.user_id,
        username=owner.username,
        role=owner.role,
        agent_token=owner.agent_token,
        created_at=owner.created_at,
    )


def _public_user_dependency(scan_id: str, token: str = Query("")) -> User:
    return _public_user_for_scan(scan_id, token)


@router.post("/api/integration/scans", response_model=IntegrationScanResponse)
async def create_integration_scan(
    body: IntegrationScanRequest,
    request: Request,
    current_user: User = Depends(_require_integration_token),
) -> IntegrationScanResponse:
    agent_id = _resolve_agent_id(body.agent_name)
    checker_names = _public_checker_names()
    await _sync_agent_config(agent_id, body.agent_config)

    public_access_token = secrets.token_urlsafe(32)
    response = await scan_api.create_agent_scan(
        CreateScanRequest(
            agent_id=agent_id,
            project_path=body.project_path,
            code_scan_path=body.code_scan_path,
            scan_name=body.scan_name,
            product=body.product,
            checkers=checker_names,
            feedback_ids=[],
        ),
        request,
        current_user,
        checker_names=checker_names,
        public_access_token=public_access_token,
        enforce_agent_owner=False,
    )
    return IntegrationScanResponse(
        scan_id=response.scan_id,
        result_url=_result_url(request, response.scan_id, public_access_token),
        progress_api_url=_progress_api_url(request, response.scan_id, public_access_token),
        checker_count=len(checker_names),
        checkers=checker_names,
    )


@router.get("/api/public/scans/{scan_id}/progress", response_model=PublicScanProgress)
async def get_public_scan_progress(
    scan_id: str,
    request: Request,
    current_user: User = Depends(_public_user_dependency),
) -> PublicScanProgress:
    scan = await scan_api.get_scan_status(scan_id, current_user)
    metrics = calculate_issue_metrics(
        scan.vulnerabilities,
        scan_api._latest_fp_review_result_map(scan_id),
    )
    token = request.query_params.get("token", "")
    return PublicScanProgress(
        scan_id=scan.scan_id,
        status=scan.status.value,
        progress=scan.progress,
        total_candidates=scan.total_candidates,
        processed_candidates=scan.processed_candidates,
        issue_count=metrics.effective_issue_count,
        raw_vulnerability_count=len(scan.vulnerabilities),
        static_total_files=scan.static_total_files,
        static_scanned_files=scan.static_scanned_files,
        result_url=_result_url(request, scan.scan_id, token),
        error_message=scan.error_message,
    )


@router.get("/api/public/scans/{scan_id}", response_model=ScanStatus)
async def get_public_scan_status(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> ScanStatus:
    return await scan_api.get_scan_status(scan_id, current_user)


@router.post("/api/public/scans/{scan_id}/stop")
async def stop_public_scan(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.stop_scan(scan_id, current_user)


@router.get("/api/public/scans/{scan_id}/report")
async def download_public_report(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> Response:
    return await scan_api.download_report(scan_id, current_user)


@router.post("/api/public/scans/{scan_id}/mark")
async def mark_public_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.mark_vulnerability(scan_id, body, current_user)


@router.post("/api/public/scans/{scan_id}/batch-mark")
async def batch_mark_public_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.batch_mark_vulnerabilities(scan_id, body, current_user)


@router.put("/api/public/scans/{scan_id}/feedback")
async def update_public_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.update_scan_feedback(scan_id, body, current_user)


@router.get("/api/public/scans/{scan_id}/skill/{vuln_type}")
async def get_public_scan_skill(
    scan_id: str,
    vuln_type: str,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.get_scan_skill(scan_id, vuln_type, current_user)


@router.get("/api/public/scans/{scan_id}/skill-reports")
async def get_public_scan_skill_reports(
    scan_id: str,
    checker_name: str | None = None,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.get_scan_skill_reports(scan_id, checker_name, current_user)


@router.get("/api/public/scans/{scan_id}/fp-review/skill")
async def get_public_fp_review_skill(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.get_fp_review_skill(scan_id, current_user)


@router.post("/api/public/scans/{scan_id}/fp_review", response_model=dict)
async def trigger_public_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.trigger_fp_review(scan_id, request, current_user)


@router.post("/api/public/scans/{scan_id}/fp_review/stop")
async def stop_public_fp_review(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await scan_api.stop_fp_review(scan_id, current_user)


@router.get("/api/public/scans/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_public_fp_review(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> FpReviewJob:
    return await scan_api.get_fp_review(scan_id, current_user)


@router.get("/api/public/scans/{scan_id}/checkers", response_model=list[CheckerInfo])
async def list_public_checkers(
    scan_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> list[CheckerInfo]:
    return await checkers_api.list_checkers(current_user)


@router.get("/api/public/scans/{scan_id}/index-status")
async def get_public_index_status(
    scan_id: str,
    _current_user: User = Depends(_public_user_dependency),
) -> dict:
    from backend.api import agent as agent_api

    return await agent_api.agent_get_index_status(scan_id)


@router.get("/api/public/scans/{scan_id}/feedback", response_model=list[FeedbackEntry])
async def list_public_feedback(
    scan_id: str,
    vuln_type: str | None = None,
    project_id: str | None = None,
    current_user: User = Depends(_public_user_dependency),
) -> list[FeedbackEntry]:
    return await feedback_api.list_feedback(vuln_type, project_id, current_user)


@router.post("/api/public/scans/{scan_id}/feedback", response_model=FeedbackEntry)
async def create_public_feedback(
    scan_id: str,
    body: FeedbackCreateRequest,
    current_user: User = Depends(_public_user_dependency),
) -> FeedbackEntry:
    if body.source_scan_id and body.source_scan_id != scan_id:
        raise HTTPException(status_code=400, detail="source_scan_id must match scan_id")
    if body.source_scan_id is None:
        body = body.model_copy(update={"source_scan_id": scan_id})
    return await feedback_api.create_feedback(body, current_user)


@router.put("/api/public/scans/{scan_id}/feedback/{feedback_id}", response_model=FeedbackEntry)
async def update_public_feedback(
    scan_id: str,
    feedback_id: str,
    body: FeedbackUpdateRequest,
    current_user: User = Depends(_public_user_dependency),
) -> FeedbackEntry:
    return await feedback_api.update_feedback(feedback_id, body, current_user)


@router.delete("/api/public/scans/{scan_id}/feedback/{feedback_id}")
async def delete_public_feedback(
    scan_id: str,
    feedback_id: str,
    current_user: User = Depends(_public_user_dependency),
) -> dict:
    return await feedback_api.delete_feedback(feedback_id, current_user)
