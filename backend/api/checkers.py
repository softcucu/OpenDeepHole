"""Checkers API — list available vulnerability checkers."""

from pathlib import Path

import yaml
from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.models import CheckerCatalogItem, CheckerInfo, User
from backend.registry import CHECKER_VISIBILITY_ADMIN, CHECKER_VISIBILITY_PUBLIC, CHECKERS_DIR
from backend.registry import checker_category_label, checker_modified_sort_key, normalize_checker_category
from backend.registry import current_checker_dirs
from backend.registry import refresh_registry

router = APIRouter()


@router.get("/api/checkers", response_model=list[CheckerInfo])
async def list_checkers(current_user: User = Depends(get_current_user)) -> list[CheckerInfo]:
    """Return all available and enabled checkers."""
    registry = refresh_registry()
    items = [
        CheckerInfo(
            name=e.name,
            label=e.label,
            description=e.description,
            visibility=e.visibility,
            category=e.category,
            category_label=e.category_label,
            modified_at=e.modified_at,
            user_created=e.user_created,
            created_by_user_id=e.created_by_user_id,
            creator_username=e.created_by_username,
            can_delete=_can_delete_user_skill(e.user_created, e.created_by_user_id, current_user),
            result_mode=e.result_mode,
            timeout_seconds=e.timeout_seconds,
            model_capability=e.model_capability,
        )
        for e in registry.values()
        if _is_visible_to_user(e.visibility, current_user)
    ]
    items.sort(key=lambda item: (item.user_created, -checker_modified_sort_key(item.modified_at).timestamp()))
    return items


def _read_checker_intro(checker_dir: Path, skill_path: Path, description: str) -> tuple[str, str]:
    """Read the checker introduction shown in the SKILL catalog."""
    candidates = [
        ("SCENARIOS.md", checker_dir / "SCENARIOS.md"),
        ("SKILL.md", skill_path),
    ]

    checker_dir = checker_dir.resolve()
    for source, path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if not _is_relative_to(resolved, checker_dir) or not resolved.is_file():
            continue
        try:
            content = resolved.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if content:
            return content, source

    return description, "checker.yaml"


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True


def _discover_catalog_items(checkers_dir: Path | None = None) -> list[CheckerCatalogItem]:
    """Discover all checker catalog items, including disabled checkers."""
    items: list[CheckerCatalogItem] = []
    seen: set[str] = set()
    roots = [checkers_dir or CHECKERS_DIR] if checkers_dir is not None else current_checker_dirs()
    for root in roots:
        if not root.is_dir():
            continue
        is_user_dir = root.resolve() != CHECKERS_DIR.resolve()

        for checker_dir in sorted(root.iterdir()):
            if not checker_dir.is_dir():
                continue

            yaml_path = checker_dir / "checker.yaml"
            if not yaml_path.is_file():
                continue

            try:
                with open(yaml_path, encoding="utf-8") as f:
                    meta = yaml.safe_load(f) or {}
            except (OSError, yaml.YAMLError):
                continue

            name = meta.get("name")
            if not name or name in seen:
                continue
            seen.add(name)

            label = meta.get("label", str(name).upper())
            description = meta.get("description", "")
            visibility = _normalize_visibility(meta.get("visibility", CHECKER_VISIBILITY_PUBLIC))
            category = normalize_checker_category(meta.get("category"))
            introduction, source = _read_checker_intro(
                checker_dir=checker_dir,
                skill_path=checker_dir / "SKILL.md",
                description=description,
            )
            items.append(
                CheckerCatalogItem(
                    name=name,
                    label=label,
                    description=description,
                    enabled=meta.get("enabled", True),
                    visibility=visibility,
                    category=category,
                    category_label=checker_category_label(category),
                    modified_at=str(meta.get("modified_at") or "").strip(),
                    introduction=introduction,
                    introduction_source=source,
                    user_created=is_user_dir,
                    created_by_user_id=str(meta.get("created_by_user_id") or "").strip(),
                    creator_username=str(meta.get("created_by_username") or "").strip(),
                    result_mode=_normalize_result_mode(meta.get("result_mode")),
                    timeout_seconds=_normalize_timeout_seconds(meta.get("timeout_seconds")),
                    model_capability=_normalize_model_capability(meta.get("model_capability")),
                )
            )

    items.sort(key=lambda item: (item.user_created, -checker_modified_sort_key(item.modified_at).timestamp()))
    return items


@router.get("/api/checkers/catalog", response_model=list[CheckerCatalogItem])
async def list_checker_catalog(
    current_user: User = Depends(get_current_user),
) -> list[CheckerCatalogItem]:
    """Return checker/SKILL introductions for the catalog page."""
    items = _discover_catalog_items()
    return [
        item.model_copy(update={
            "can_delete": _can_delete_user_skill(item.user_created, item.created_by_user_id, current_user)
        })
        for item in items
        if _is_visible_to_user(item.visibility, current_user)
    ]


def _can_delete_user_skill(user_created: bool, owner_id: str, user: User) -> bool:
    if not user_created:
        return False
    if user.role == "admin":
        return True
    return bool(owner_id) and owner_id == user.user_id


def _normalize_visibility(value: object) -> str:
    visibility = str(value or CHECKER_VISIBILITY_PUBLIC).strip().lower()
    if visibility not in {CHECKER_VISIBILITY_PUBLIC, CHECKER_VISIBILITY_ADMIN}:
        return CHECKER_VISIBILITY_PUBLIC
    return visibility


def _normalize_result_mode(value: object) -> str:
    result_mode = str(value or "vulnerabilities").strip().lower()
    if result_mode not in {"vulnerabilities", "markdown_reports"}:
        return "vulnerabilities"
    return result_mode


def _normalize_timeout_seconds(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return None
    return timeout if timeout > 0 else None


def _normalize_model_capability(value: object) -> str:
    capability = str(value or "any").strip().lower()
    return capability if capability in {"any", "low", "medium", "high"} else "any"


def _is_visible_to_user(visibility: str, user: User) -> bool:
    return visibility != CHECKER_VISIBILITY_ADMIN or user.role == "admin"
