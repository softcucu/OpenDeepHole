"""User-created SKILL market API."""

from __future__ import annotations

import base64
import binascii
import re
import shutil
import uuid
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
_jobs: dict[str, SkillCreateJob] = {}
_JOB_STATUSES = {"pending", "running", "completed", "error"}
_ALLOWED_RESOURCE_DIRS = {"references", "scripts", "assets"}
_MIN_TIMEOUT_SECONDS = 60
_MAX_TIMEOUT_SECONDS = 24 * 60 * 60
_SKILL_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


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


def _validate_skill_id(value: str) -> str:
    skill_id = value.strip()
    if not skill_id:
        raise HTTPException(status_code=400, detail="SKILL 标识不能为空")
    if not _SKILL_ID_RE.fullmatch(skill_id):
        raise HTTPException(
            status_code=400,
            detail="SKILL 标识只能包含字母、数字、下划线，且必须以字母或下划线开头，最长 64 个字符",
        )
    return skill_id


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


def _fixed_skill_rules() -> str:
    return """## 系统固定运行规则

以下规则由 OpenDeepHole 固定注入，用户不能修改。

### Markdown 报告保存规则

- 本 SKILL 只输出 Markdown 报告，不调用 `submit_result`，不生成结构化漏洞结果。
- 运行提示词会提供 `REPORT_DIR`，所有报告必须写入该目录。
- 每个报告必须是独立 `.md` 文件，文件名只能表达报告主题，不要包含路径穿越字符。
- 可以生成多个报告；未发现问题时也应生成一个 Markdown 报告说明检查范围和结论。

### 写权限约束

- 代码仓、上传资料和其它目录均为只读。
- 只有 `REPORT_DIR` 具备写权限。
- 不得修改项目源码、配置文件、上传资料或 OpenDeepHole 运行文件。
"""


def _skill_md_with_frontmatter(skill_id: str, description: str, content: str) -> str:
    body = _strip_frontmatter(content)
    fixed = _fixed_skill_rules()
    marker = "## 系统固定运行规则"
    marker_index = body.find(marker)
    if marker_index >= 0:
        body = body[:marker_index].rstrip()
    body = body.rstrip() + "\n\n" + fixed
    frontmatter = yaml.safe_dump(
        {"name": skill_id, "description": description},
        allow_unicode=True,
        sort_keys=False,
    ).strip()
    return f"---\n{frontmatter}\n---\n\n{body.rstrip()}\n"


def _find_existing_checker(skill_id: str) -> bool:
    registry = refresh_registry()
    return skill_id in registry or (_user_skills_dir() / skill_id).exists()


def _user_skill_dir(skill_id: str) -> Path:
    skill_id = _validate_skill_id(skill_id)
    root = _user_skills_dir().resolve()
    path = (root / skill_id).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="SKILL 标识非法") from exc
    return path


def _read_checker_yaml(checker_dir: Path) -> dict:
    yaml_path = checker_dir / "checker.yaml"
    if not yaml_path.is_file():
        raise HTTPException(status_code=404, detail="SKILL not found")
    try:
        return yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=400, detail="SKILL 元数据不可读取") from exc


def _can_delete_user_skill(meta: dict, current_user: User) -> bool:
    if current_user.role == "admin":
        return True
    owner_id = str(meta.get("created_by_user_id") or "").strip()
    return bool(owner_id) and owner_id == current_user.user_id


def _normalize_timeout(value: int) -> int:
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="运行超时必须为整数秒")
    if timeout < _MIN_TIMEOUT_SECONDS or timeout > _MAX_TIMEOUT_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=f"运行超时必须在 {_MIN_TIMEOUT_SECONDS} 到 {_MAX_TIMEOUT_SECONDS} 秒之间",
        )
    return timeout


def _skill_draft(name: str, description: str, user_input: str) -> SkillDraft:
    skill_md = f"""# {name}

## 审计目标

{user_input or description}

## 确认标准

- 能指出具体文件、函数和关键代码位置。
- 能说明问题触发路径、缺失保护和安全影响。
- 结论需要基于实际代码证据，不要只依据命名或猜测。

## 误报排除条件

- 已有权限、边界、状态或错误处理保护覆盖该路径。
- 代码位于测试、mock、stub 或不可达路径中。
- 只有风格、可维护性或理论风险，缺少可触发安全影响。

## 重点代码范围

- 入口函数、协议解析、认证授权、资源生命周期、内存读写和错误处理路径。
- 优先阅读与审计目标直接相关的文件和函数。

## 报告输出要求

- 报告使用 Markdown。
- 每个报告包含：标题、结论、影响、证据、触发条件、误报排除说明、修复建议。
- 多个独立问题可以输出多个 Markdown 文件。
"""
    scenarios_md = f"""# {name}

## 适用场景

- {description}
- 需要对项目代码做专项人工智能辅助审计时使用。

## 不适用场景

- 需要结构化漏洞列表、逐候选点复核或自动误报复核的场景。

## 使用建议

- 扫描前确认代码扫描路径覆盖目标模块。
- 可在 `references/` 中上传审计规范，在 `scripts/` 中上传只读辅助脚本说明或示例。
"""
    return SkillDraft(
        skill_md=skill_md.strip() + "\n",
        scenarios_md=scenarios_md.strip() + "\n",
        summary="已基于固定模板生成可编辑草稿",
    )


def _safe_resource_path(value: str) -> Path:
    normalized = value.replace("\\", "/").strip().lstrip("/")
    rel = Path(normalized)
    if (
        not normalized
        or rel.is_absolute()
        or ".." in rel.parts
        or len(rel.parts) < 2
        or rel.parts[0] not in _ALLOWED_RESOURCE_DIRS
    ):
        raise HTTPException(status_code=400, detail=f"上传文件路径非法: {value}")
    if rel.name in {"checker.yaml", "SKILL.md", "SCENARIOS.md"}:
        raise HTTPException(status_code=400, detail=f"不允许覆盖系统文件: {value}")
    return rel


def _write_resource_files(checker_dir: Path, files: list) -> None:
    for item in files:
        rel = _safe_resource_path(item.path)
        try:
            data = base64.b64decode(item.content_b64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError) as exc:
            raise HTTPException(status_code=400, detail=f"上传文件不是合法 base64: {item.path}") from exc
        dest = (checker_dir / rel).resolve()
        try:
            dest.relative_to(checker_dir.resolve())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"上传文件路径非法: {item.path}") from exc
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


@router.post("/api/skills/create", response_model=SkillCreateJob)
async def create_skill(
    request: Request,
    body: SkillCreateRequest,
    current_user: User = Depends(get_current_user),
) -> SkillCreateJob:
    """Create a template-based SKILL draft synchronously."""
    skill_id = _validate_skill_id(body.skill_id)
    name = body.name.strip()
    description = body.description.strip()
    user_input = body.input.strip()
    if not name:
        raise HTTPException(status_code=400, detail="名称不能为空")
    if not description:
        raise HTTPException(status_code=400, detail="描述不能为空")
    if not user_input:
        raise HTTPException(status_code=400, detail="输入不能为空")
    if _find_existing_checker(skill_id):
        raise HTTPException(status_code=409, detail=f"SKILL 已存在: {skill_id}")
    _normalize_timeout(body.timeout_seconds)

    now = _now()
    job_id = uuid.uuid4().hex
    job = SkillCreateJob(
        job_id=job_id,
        status="completed",
        skill_id=skill_id,
        name=name,
        description=description,
        input=user_input,
        agent_id="",
        agent_name="",
        user_id=current_user.user_id,
        created_at=now,
        updated_at=now,
        draft=_skill_draft(name, description, user_input),
    )
    _jobs[job_id] = job
    return job


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
    timeout_seconds = _normalize_timeout(body.timeout_seconds)

    skill_id = _validate_skill_id(job.skill_id)
    if _find_existing_checker(skill_id):
        raise HTTPException(status_code=409, detail=f"SKILL 已存在: {skill_id}")

    checker_dir = _user_skill_dir(skill_id)
    checker_dir.mkdir(parents=True, exist_ok=False)
    try:
        modified_at = _market_time()
        checker_yaml = {
            "name": skill_id,
            "label": job.name,
            "description": job.description,
            "enabled": True,
            "mode": "opencode",
            "result_mode": "markdown_reports",
            "timeout_seconds": timeout_seconds,
            "visibility": CHECKER_VISIBILITY_PUBLIC,
            "category": CHECKER_CATEGORY_OTHER,
            "modified_at": modified_at,
            "created_by_user_id": current_user.user_id,
            "created_by_username": current_user.username,
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
        _write_resource_files(checker_dir, body.files)
    except Exception:
        import shutil

        shutil.rmtree(checker_dir, ignore_errors=True)
        raise

    refresh_registry()
    return SkillImportResponse(ok=True, name=skill_id)


@router.delete("/api/skills/{skill_id}")
async def delete_skill(
    skill_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Delete a user-created SKILL from the user SKILL directory."""
    checker_dir = _user_skill_dir(skill_id)
    if not checker_dir.is_dir():
        raise HTTPException(status_code=404, detail="SKILL not found")
    meta = _read_checker_yaml(checker_dir)
    if str(meta.get("name") or "").strip() != skill_id:
        raise HTTPException(status_code=400, detail="SKILL 元数据与目录不匹配")
    if not _can_delete_user_skill(meta, current_user):
        raise HTTPException(status_code=403, detail="Access denied")
    shutil.rmtree(checker_dir)
    refresh_registry()
    return {"ok": True}


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
