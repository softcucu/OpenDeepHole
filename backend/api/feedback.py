"""Feedback API — CRUD for user feedback entries (experience database)."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from backend.auth import get_current_user
from backend.logger import get_logger
from backend.models import (
    FeedbackCreateRequest,
    FeedbackEntry,
    FeedbackUpdateRequest,
    User,
)
from backend.store import get_scan_store

router = APIRouter()
logger = get_logger(__name__)


@router.get("/api/feedback", response_model=list[FeedbackEntry])
async def list_feedback(
    vuln_type: str | None = None,
    project_id: str | None = None,
    current_user: User = Depends(get_current_user),
) -> list[FeedbackEntry]:
    """List feedback entries, optionally filtered by vuln_type and/or project_id."""
    store = get_scan_store()
    return store.list_feedback(vuln_type, project_id)


@router.post("/api/feedback", response_model=FeedbackEntry)
async def create_feedback(
    body: FeedbackCreateRequest,
    current_user: User = Depends(get_current_user),
) -> FeedbackEntry:
    """Create a new feedback entry."""
    if body.verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")

    now = datetime.now(timezone.utc).isoformat()
    entry = FeedbackEntry(
        id=uuid.uuid4().hex,
        project_id=body.project_id,
        vuln_type=body.vuln_type,
        verdict=body.verdict,
        file=body.file,
        line=body.line,
        function=body.function,
        description=body.description,
        reason=body.reason,
        ticket_submitted=body.ticket_submitted,
        ticket_id=body.ticket_id.strip() if body.ticket_submitted else "",
        function_source=body.function_source,
        function_start_line=body.function_start_line,
        source_scan_id=body.source_scan_id,
        created_at=now,
        updated_at=now,
    )
    store = get_scan_store()
    store.add_feedback(entry)
    logger.info("Created feedback %s for project %s (%s)", entry.id, body.project_id, body.vuln_type)
    return entry


@router.put("/api/feedback/{feedback_id}", response_model=FeedbackEntry)
async def update_feedback(
    feedback_id: str,
    body: FeedbackUpdateRequest,
    current_user: User = Depends(get_current_user),
) -> FeedbackEntry:
    """Update an existing feedback entry."""
    if body.verdict is not None and body.verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")

    store = get_scan_store()
    ok = store.update_feedback(
        feedback_id,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Feedback entry not found")

    # Return updated entry
    entries = store.get_feedback_by_ids([feedback_id])
    return entries[0]


@router.delete("/api/feedback/{feedback_id}")
async def delete_feedback(
    feedback_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Delete a feedback entry."""
    store = get_scan_store()
    if not store.delete_feedback(feedback_id):
        raise HTTPException(status_code=404, detail="Feedback entry not found")
    return {"ok": True}
