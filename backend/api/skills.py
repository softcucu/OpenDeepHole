"""User-created SKILL market API."""

from __future__ import annotations

import re
import base64
import hashlib
import io
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request

from backend.auth import get_current_user
from backend.config import get_config
from backend.models import (
    SkillCreateJob,
    SkillCreateRequest,
    SkillDraft,
    SkillImportRequest,
    SkillImportResponse,
    User,
)
from backend.registry import CHECKER_CATEGORY_OTHER, CHECKER_VISIBILITY_PUBLIC, refresh_registry

router = APIRouter()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SYSTEM_SKILLS_DIR = _PROJECT_ROOT / "backend" / "system_skills"
_SKILL_CREATOR_NAME = "deephole-skill-creator"
_jobs: dict[str, SkillCreateJob] = {}
_JOB_STATUSES = {"pending", "running", "completed", "error"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _market_time() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def _skill_slug(value: str, fallback: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower()).strip("_")
    if not slug:
        slug = f"skill_{fallback[:8]}"
    if not re.match(r"^[a-zA-Z_]", slug):
        slug = f"skill_{slug}"
    return slug[:64]


def _user_skills_dir() -> Path:
    return Path(get_config().storage.user_skills_dir)


def _server_url_from_request(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _strip_frontmatter(content: str) -> str:
    text = content.strip()
    if not text.startswith("---"):
        return text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return text
    return parts[2].lstrip()


def _skill_md_with_frontmatter(skill_id: str, description: str, content: str) -> str:
    body = _strip_frontmatter(content)
    frontmatter = yaml.safe_dump(
        {"name": skill_id, "description": description},
        allow_unicode=True,
        sort_keys=False,
    ).strip()
    return f"---\n{frontmatter}\n---\n\n{body.rstrip()}\n"


def _find_existing_checker(skill_id: str) -> bool:
    registry = refresh_registry()
    return skill_id in registry or (_user_skills_dir() / skill_id).exists()


def _skill_creator_package() -> dict:
    skill_dir = _SYSTEM_SKILLS_DIR / _SKILL_CREATOR_NAME
    skill_file = skill_dir / "SKILL.md"
    if not skill_file.is_file():
        raise HTTPException(status_code=500, detail="系统 deephole-skill-creator SKILL 缺失")

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(skill_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(skill_dir)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                raise HTTPException(status_code=500, detail="系统 deephole-skill-creator SKILL 路径非法")
            zf.write(file_path, rel_path.as_posix())

    data = archive.getvalue()

    return {
        "name": _SKILL_CREATOR_NAME,
        "sha256": hashlib.sha256(data).hexdigest(),
        "archive_b64": base64.b64encode(data).decode("ascii"),
    }


@router.post("/api/skills/create", response_model=SkillCreateJob)
async def create_skill(
    request: Request,
    body: SkillCreateRequest,
    current_user: User = Depends(get_current_user),
) -> SkillCreateJob:
    """Start an Agent-backed SKILL creation job."""
    from backend.api.agent import (
        _registered_agents,
        _agent_ws,
        create_agent_runtime_update_payload,
        send_agent_command,
    )

    name = body.name.strip()
    description = body.description.strip()
    user_input = body.input.strip()
    if not name:
        raise HTTPException(status_code=400, detail="名称不能为空")
    if not description:
        raise HTTPException(status_code=400, detail="描述不能为空")
    if not user_input:
        raise HTTPException(status_code=400, detail="输入不能为空")

    agent = _registered_agents.get(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if body.agent_id not in _agent_ws:
        raise HTTPException(status_code=400, detail="Agent is offline")
    skill_creator_package = _skill_creator_package()

    now = _now()
    job_id = uuid.uuid4().hex
    job = SkillCreateJob(
        job_id=job_id,
        status="pending",
        name=name,
        description=description,
        input=user_input,
        agent_id=body.agent_id,
        agent_name=agent.name,
        user_id=current_user.user_id,
        created_at=now,
        updated_at=now,
    )
    _jobs[job_id] = job

    ok = await send_agent_command(body.agent_id, {
        "type": "skill_create",
        "request_id": job_id,
        "name": name,
        "description": description,
        "input": user_input,
        "deephole_skill_creator_package": skill_creator_package,
        "skill_creator_package": skill_creator_package,
        "agent_runtime_update": create_agent_runtime_update_payload(_server_url_from_request(request)),
    })
    if not ok:
        _jobs.pop(job_id, None)
        raise HTTPException(status_code=502, detail="Agent not connected")

    current = _jobs.get(job_id, job)
    if current.status == "pending":
        current.status = "running"
        current.updated_at = _now()
        _jobs[job_id] = current
    return current


@router.get("/api/skills/create/{job_id}", response_model=SkillCreateJob)
async def get_skill_create_job(
    job_id: str,
    current_user: User = Depends(get_current_user),
) -> SkillCreateJob:
    """Return SKILL creation progress and generated draft."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="SKILL creation job not found")
    if current_user.role != "admin" and job.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return job


@router.post("/api/skills/create/{job_id}/import", response_model=SkillImportResponse)
async def import_skill(
    job_id: str,
    body: SkillImportRequest,
    current_user: User = Depends(get_current_user),
) -> SkillImportResponse:
    """Import a generated SKILL draft into the public SKILL market."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="SKILL creation job not found")
    if current_user.role != "admin" and job.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="SKILL 尚未创建完成")

    skill_md = body.skill_md.strip()
    if not skill_md:
        raise HTTPException(status_code=400, detail="SKILL 内容不能为空")

    skill_id = _skill_slug(job.name, job_id)
    if _find_existing_checker(skill_id):
        raise HTTPException(status_code=409, detail=f"SKILL 已存在: {skill_id}")

    checker_dir = _user_skills_dir() / skill_id
    checker_dir.mkdir(parents=True, exist_ok=False)
    try:
        modified_at = _market_time()
        checker_yaml = {
            "name": skill_id,
            "label": job.name,
            "description": job.description,
            "enabled": True,
            "mode": "opencode",
            "visibility": CHECKER_VISIBILITY_PUBLIC,
            "category": CHECKER_CATEGORY_OTHER,
            "modified_at": modified_at,
        }
        (checker_dir / "checker.yaml").write_text(
            yaml.safe_dump(checker_yaml, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        (checker_dir / "SKILL.md").write_text(
            _skill_md_with_frontmatter(skill_id, job.description, skill_md),
            encoding="utf-8",
        )
        scenarios_md = body.scenarios_md.strip()
        if scenarios_md:
            (checker_dir / "SCENARIOS.md").write_text(scenarios_md + "\n", encoding="utf-8")
    except Exception:
        import shutil

        shutil.rmtree(checker_dir, ignore_errors=True)
        raise

    refresh_registry()
    return SkillImportResponse(ok=True, name=skill_id)


def handle_skill_create_result(payload: dict) -> None:
    """Record a result message sent by an Agent over WebSocket."""
    job_id = str(payload.get("request_id") or "")
    job = _jobs.get(job_id)
    if job is None:
        return

    status = "completed" if payload.get("ok") else "error"
    if status not in _JOB_STATUSES:
        status = "error"
    job.status = status
    job.updated_at = _now()
    if status == "completed":
        draft_payload = payload.get("draft") or {}
        job.draft = SkillDraft(
            skill_md=str(draft_payload.get("skill_md") or ""),
            scenarios_md=str(draft_payload.get("scenarios_md") or ""),
            summary=str(draft_payload.get("summary") or ""),
        )
        job.error_message = ""
    else:
        job.error_message = str(payload.get("message") or "SKILL 创建失败")
    _jobs[job_id] = job
