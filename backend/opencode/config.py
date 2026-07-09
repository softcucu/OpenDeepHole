"""opencode workspace and configuration generation."""

from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from backend.models import FeedbackEntry
from backend.opencode.feedback_format import format_feedback_experience
from backend.registry import get_registry

logger = get_logger(__name__)

# Subdirectories in checker dirs that should be symlinked into the workspace
_SKILL_RESOURCE_DIRS = {"references", "scripts", "assets"}
THREAT_AUDIT_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "agent" / "threat_audit_skills"

_workspace_locks: dict[str, threading.RLock] = {}
_workspace_locks_guard = threading.Lock()


def get_workspace_lock(workspace: Path) -> threading.RLock:
    """Return a process-local lock for opencode files in one workspace."""
    key = str(workspace.resolve())
    with _workspace_locks_guard:
        lock = _workspace_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _workspace_locks[key] = lock
        return lock


def create_scan_workspace(
    scan_id: str,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
    mcp_port: int | None = None,
) -> Path:
    """Create an opencode workspace for a scan.

    The workspace contains only OpenCode configuration and generated skills.
    It is deliberately kept outside the project directory so concurrent scans
    of the same project do not overwrite each other's MCP URL.

    Args:
        scan_id: Unique scan identifier.
        project_dir: Project directory used only for legacy feedback lookup.

    Returns:
        Path to the workspace directory.
    """
    config = get_config()
    scans_dir = Path(config.storage.scans_dir)
    if scans_dir.name == scan_id:
        workspace = scans_dir / "opencode_workspace"
    else:
        workspace = scans_dir / scan_id / "opencode_workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    with get_workspace_lock(workspace):
        _write_opencode_config(workspace, mcp_port=mcp_port)
        refresh_skills(workspace, project_dir, feedback_entries)

    logger.info("Created opencode workspace: %s", workspace)
    return workspace


def refresh_skills(
    workspace: Path,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Regenerate SKILL files in an existing workspace.

    Can be called mid-scan to hot-update skills when the user changes
    the active feedback entries.
    """
    with get_workspace_lock(workspace):
        _link_skills(workspace, project_dir, feedback_entries=feedback_entries)


def _merge_feedback_section(original: str, fp_section: str | None) -> str:
    if not fp_section:
        return original
    return (
        original.rstrip()
        + "\n\n## 历史用户经验\n\n"
        + "以下是用户在审计过程中选择注入的经验，"
        + "分析时应结合这些经验校验结论：\n"
        + fp_section
    )


def _link_skill_resources(entry, link_dir: Path) -> None:
    """Symlink checker resource directories into a generated skill directory."""
    for dir_name in _SKILL_RESOURCE_DIRS:
        src = entry.directory / dir_name
        if src.is_dir():
            link_dest = link_dir / dir_name
            if link_dest.exists() or link_dest.is_symlink():
                os.remove(link_dest)
            link_dest.symlink_to(src.resolve())


def _link_threat_audit_skills(skills_target: Path) -> int:
    """Copy Agent-local threat-audit skills into the isolated OpenCode workspace."""
    if not THREAT_AUDIT_SKILLS_DIR.is_dir():
        return 0
    count = 0
    for skill_dir in sorted(THREAT_AUDIT_SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            continue
        target_dir = skills_target / skill_dir.name
        if target_dir.exists() or target_dir.is_symlink():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "SKILL.md").write_text(
            skill_file.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        for dir_name in _SKILL_RESOURCE_DIRS:
            src = skill_dir / dir_name
            if src.is_dir():
                shutil.copytree(src, target_dir / dir_name)
        count += 1
    return count


def writable_edit_patterns(path: str | os.PathLike[str]) -> list[str]:
    normalized = str(path)
    variants = [normalized]
    slash_normalized = normalized.replace("\\", "/")
    if slash_normalized not in variants:
        variants.append(slash_normalized)
    backslash_normalized = normalized.replace("/", "\\")
    if backslash_normalized not in variants:
        variants.append(backslash_normalized)

    patterns: list[str] = []
    for variant in variants:
        patterns.append(variant)
        patterns.append(f"{variant}/**")
    return patterns


def build_opencode_config(
    mcp_url: str,
    skills_paths: list[str] | None = None,
    writable_paths: list[str] | None = None,
) -> dict:
    """Build the canonical opencode.json content for OpenDeepHole workspaces."""
    edit_permissions = {"*": "deny"} if not writable_paths else {}
    for path in writable_paths or []:
        normalized = str(Path(path).resolve())
        for pattern in writable_edit_patterns(path) + writable_edit_patterns(normalized):
            edit_permissions[pattern] = "allow"
    data = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "deephole-code": {
                "type": "remote",
                "url": mcp_url,
                "enabled": True,
            }
        },
        "permission": {
            "read": {"*": "allow"},
            "list": {"*": "allow"},
            "glob": {"*": "allow"},
            "grep": {"*": "allow"},
            "external_directory": {"*": "allow"},
            "edit": edit_permissions,
        },
    }
    if skills_paths:
        data["skills"] = {"paths": skills_paths}
    return data


def _write_opencode_config(workspace: Path, mcp_port: int | None = None) -> None:
    """Generate opencode.json with MCP server and read-only file permissions."""
    config = get_config()
    port = mcp_port if mcp_port is not None else config.mcp_server.port
    mcp_url = f"http://127.0.0.1:{port}/mcp"

    config_path = workspace / "opencode.json"
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    config_path.write_text(
        json.dumps(build_opencode_config(mcp_url, [str(skills_dir)]), indent=2),
        encoding="utf-8",
    )


def _link_skills(
    workspace: Path,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Create skill definitions from all registered checkers.

    When *feedback_entries* are provided, entries are grouped by vuln_type and
    appended to the corresponding SKILL as a "历史用户经验" section. Falls back
    to the legacy ``skill_fp/`` flat files when no entries are supplied.
    """
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    # Group feedback entries by vuln_type for quick lookup
    feedback_by_type: dict[str, list[FeedbackEntry]] = {}
    if feedback_entries:
        for fb in feedback_entries:
            feedback_by_type.setdefault(fb.vuln_type, []).append(fb)

    # Legacy fallback directory
    fp_dir = project_dir / "skill_fp" if project_dir else None

    registry = get_registry()
    for name, entry in registry.items():
        # 构建反馈内容（API 和 opencode 模式共用）
        fp_section: str | None = None
        if name in feedback_by_type:
            fp_section = format_feedback_experience(feedback_by_type[name])
        elif fp_dir:
            fp_file = fp_dir / f"{name}.md"
            if fp_file.is_file():
                fp_section = fp_file.read_text(encoding="utf-8")

        link_dir = skills_target / name
        link_dir.mkdir(exist_ok=True)

        # API 模式：将 prompt.txt（合并反馈）写入 PROMPT.md
        if entry.mode == "api":
            if entry.prompt_path and entry.prompt_path.is_file():
                prompt_dest = link_dir / "PROMPT.md"
                if prompt_dest.exists():
                    os.remove(prompt_dest)
                original = entry.prompt_path.read_text(encoding="utf-8")
                prompt_dest.write_text(
                    _merge_feedback_section(original, fp_section),
                    encoding="utf-8",
                )
                if fp_section:
                    logger.debug("Merged FP experience into prompt for checker %s", name)
            # API checker can fall back to opencode when the API is unavailable.
            # If SKILL.md exists, generate it too so opencode can use the same
            # checker name as the API-mode prompt directory.
            if entry.skill_path.is_file():
                skill_dest = link_dir / "SKILL.md"
                if skill_dest.exists():
                    os.remove(skill_dest)
                original = entry.skill_path.read_text(encoding="utf-8")
                skill_dest.write_text(
                    _merge_feedback_section(original, fp_section),
                    encoding="utf-8",
                )
                if fp_section:
                    logger.debug("Merged FP experience into fallback skill for checker %s", name)
            else:
                logger.warning(
                    "SKILL.md not found for API checker %s; opencode fallback is unavailable",
                    name,
                )
            _link_skill_resources(entry, link_dir)
            continue

        # opencode 模式：原有 SKILL.md 逻辑
        if not entry.skill_path.is_file():
            logger.warning("SKILL.md not found for checker %s", name)
            continue

        skill_dest = link_dir / "SKILL.md"
        if skill_dest.exists():
            os.remove(skill_dest)

        original = entry.skill_path.read_text(encoding="utf-8")
        skill_dest.write_text(
            _merge_feedback_section(original, fp_section),
            encoding="utf-8",
        )
        if fp_section:
            logger.debug("Merged FP experience into skill for checker %s", name)

        _link_skill_resources(entry, link_dir)

    threat_skill_count = _link_threat_audit_skills(skills_target)
    logger.debug("Linked skills for %d checkers and %d threat-audit skill(s)", len(registry), threat_skill_count)


def cleanup_workspace(workspace: Path) -> None:
    """Remove opencode artifacts written into the workspace directory.

    New scan workspaces are isolated ``opencode_workspace`` directories and can
    be removed as a whole.  The legacy selective cleanup remains as a guard in
    case callers pass a project-root workspace from an older runtime.
    """
    with get_workspace_lock(workspace):
        if workspace.name == "opencode_workspace":
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception as exc:
                logger.warning("Failed to remove opencode workspace %s: %s", workspace, exc)
            return

        checker_names = list(get_registry().keys())
        skills_dir = workspace / ".opencode" / "skills"
        try:
            if skills_dir.is_dir():
                for checker_name in checker_names:
                    skill_dir = skills_dir / checker_name
                    if skill_dir.is_symlink():
                        skill_dir.unlink()
                    elif skill_dir.is_dir():
                        shutil.rmtree(skill_dir)
        except Exception as exc:
            logger.warning("Failed to remove checker skill dirs from workspace: %s", exc)

        try:
            if skills_dir.is_dir() and not any(skills_dir.iterdir()):
                skills_dir.rmdir()
        except Exception as exc:
            logger.warning("Failed to remove empty skills dir from workspace: %s", exc)

        opencode_dir = workspace / ".opencode"
        try:
            if opencode_dir.is_dir() and not any(opencode_dir.iterdir()):
                opencode_dir.rmdir()
        except Exception as exc:
            logger.warning("Failed to remove empty .opencode dir from workspace: %s", exc)

        opencode_json = workspace / "opencode.json"
        try:
            # Keep MCP config while any skill remains, especially fp-review.
            if opencode_json.exists() and not opencode_dir.exists():
                opencode_json.unlink()
        except Exception as exc:
            logger.warning("Failed to remove opencode.json from workspace: %s", exc)

        _cleanup_copied_cli_skills(workspace, checker_names)


def _cleanup_copied_cli_skills(workspace: Path, skill_names: list[str]) -> None:
    """Remove OpenDeepHole skill copies written for Claude/Gemini-compatible CLIs."""
    for root in (workspace / ".claude" / "skills", workspace / ".gemini" / "skills"):
        try:
            if root.is_dir():
                for name in skill_names:
                    skill_dir = root / name
                    if skill_dir.is_symlink():
                        skill_dir.unlink()
                    elif skill_dir.is_dir():
                        shutil.rmtree(skill_dir)
                if not any(root.iterdir()):
                    root.rmdir()
        except Exception as exc:
            logger.warning("Failed to remove copied CLI skills from %s: %s", root, exc)

    claude_dir = workspace / ".claude"
    try:
        mcp_config = claude_dir / "opendeephole-mcp.json"
        if mcp_config.exists():
            mcp_config.unlink()
        if claude_dir.is_dir() and not any(claude_dir.iterdir()):
            claude_dir.rmdir()
    except Exception as exc:
        logger.warning("Failed to remove Claude CLI artifacts: %s", exc)


def get_skill_content(workspace: Path, vuln_type: str) -> str | None:
    """Read the current SKILL/PROMPT content for a given vuln_type from a workspace."""
    skill_dir = workspace / ".opencode" / "skills" / vuln_type
    # 优先 SKILL.md（opencode 模式），其次 PROMPT.md（API 模式）
    for filename in ("SKILL.md", "PROMPT.md"):
        path = skill_dir / filename
        if path.is_file():
            return path.resolve().read_text(encoding="utf-8")
    return None


def install_attack_tree_threat_analysis_skill(
    workspace: Path,
    skill_path: Path,
    reference_catalog_path: Path,
) -> None:
    """Install the built-in attack-tree threat-analysis skill into a workspace."""
    skill_path = skill_path.resolve()
    reference_catalog_path = reference_catalog_path.resolve()
    if not skill_path.is_file():
        raise FileNotFoundError(f"Threat analysis skill not found: {skill_path}")
    if not reference_catalog_path.is_file():
        raise FileNotFoundError(f"Attack method reference catalog not found: {reference_catalog_path}")

    with get_workspace_lock(workspace):
        skill_dir = workspace / ".opencode" / "skills" / "attack-tree-threat-analysis"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text(skill_path.read_text(encoding="utf-8"), encoding="utf-8")
        (skill_dir / "attack-method-reference-catalog.md").write_text(
            reference_catalog_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
