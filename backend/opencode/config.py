"""opencode workspace and configuration generation."""

from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from backend.registry import get_registry

logger = get_logger(__name__)

# Subdirectories in checker dirs that should be symlinked into the workspace
_SKILL_RESOURCE_DIRS = {"references", "scripts", "assets"}
_OBSOLETE_THREAT_AUDIT_SKILL_NAME = "threat-path-audit"
_GLOBAL_WORKSPACE = Path.home() / ".opendeephole" / "opencode_workspace"
_BUILTIN_AGENT_SKILLS = {
    "history-match": Path("agent/skills/fp_review_match.md"),
    "prove-bug": Path("agent/skills/fp_review.md"),
    "prove-fp": Path("agent/skills/fp_review_discriminator.md"),
    "final-judge": Path("agent/skills/fp_review_final.md"),
    "git-history-mine": Path("agent/skills/git_history_mine.md"),
    "variant-hunt": Path("agent/skills/variant_hunt.md"),
}

_workspace_locks: dict[str, threading.RLock] = {}
_workspace_locks_guard = threading.Lock()
_initialized_workspace: Path | None = None


def get_workspace_lock(workspace: Path) -> threading.RLock:
    """Return a process-local lock for opencode files in one workspace."""
    key = str(workspace.resolve())
    with _workspace_locks_guard:
        lock = _workspace_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _workspace_locks[key] = lock
        return lock


def get_global_opencode_workspace(*, mcp_port: int | None = None) -> Path:
    """Return and initialize the single Agent-wide OpenCode workspace.

    The workspace contains stable MCP/skill configuration only. Scan-specific
    state (scope, selected feedback and writable roots) is attached to each
    task by :mod:`backend.opencode.task_service` and is never written here.
    """
    global _initialized_workspace
    workspace = _GLOBAL_WORKSPACE
    workspace.mkdir(parents=True, exist_ok=True)
    with get_workspace_lock(workspace):
        # A caller that owns/has just joined the Agent-wide MCP gateway provides
        # its actual port. Without one, keep an existing config intact so a
        # task cannot accidentally replace a dynamically allocated gateway URL
        # with the configured fallback port.
        config_missing = not (workspace / "opencode.json").is_file()
        if mcp_port is not None or config_missing:
            _write_opencode_config(workspace, mcp_port=mcp_port)
        resolved_workspace = workspace.resolve()
        if (
            mcp_port is not None
            or config_missing
            or _initialized_workspace != resolved_workspace
        ):
            _link_skills(workspace)
            _install_builtin_skills(workspace)
            _initialized_workspace = resolved_workspace
    return workspace


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _install_builtin_skills(workspace: Path) -> None:
    """Materialize every repository-owned skill in the global skill root."""
    repo_root = Path(__file__).resolve().parents[2]
    skills_root = workspace / ".opencode" / "skills"
    for skill_name, relative_source in _BUILTIN_AGENT_SKILLS.items():
        source = repo_root / relative_source
        if not source.is_file():
            logger.warning("Built-in OpenCode skill source missing: %s", source)
            continue
        _write_text_atomic(
            skills_root / skill_name / "SKILL.md",
            source.read_text(encoding="utf-8"),
        )

    # The attack-tree workflow owns a main skill, six stage skills and shared
    # reference material. Register all of them up front; OpenCode discovers the
    # catalog and loads only a skill selected by the task prompt.
    from backend.threat_analysis.workspace import install_attack_tree_threat_analysis_skill

    skill_path = repo_root / "attack-tree-threat-analysis.md"
    reference_path = repo_root / "attack-method-reference-catalog.md"
    if skill_path.is_file() and reference_path.is_file():
        install_attack_tree_threat_analysis_skill(
            workspace,
            skill_path,
            reference_path,
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
) -> None:
    """Register stable definitions from all checkers in the global workspace."""
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    # Interrupted scans can leave the retired dedicated threat-audit skill in
    # their persistent workspace. Remove it whenever skills are refreshed so a
    # later continuation cannot load the stale copy.
    obsolete_threat_skill = skills_target / _OBSOLETE_THREAT_AUDIT_SKILL_NAME
    if obsolete_threat_skill.is_symlink() or obsolete_threat_skill.is_file():
        obsolete_threat_skill.unlink()
    elif obsolete_threat_skill.is_dir():
        shutil.rmtree(obsolete_threat_skill)

    registry = get_registry()
    for name, entry in registry.items():
        link_dir = skills_target / name
        link_dir.mkdir(exist_ok=True)

        # API 模式：将 prompt.txt（合并反馈）写入 PROMPT.md
        if entry.mode == "api":
            if entry.prompt_path and entry.prompt_path.is_file():
                prompt_dest = link_dir / "PROMPT.md"
                if prompt_dest.exists():
                    os.remove(prompt_dest)
                original = entry.prompt_path.read_text(encoding="utf-8")
                prompt_dest.write_text(original, encoding="utf-8")
            # Legacy API checkers are executed only through OpenCode now.  Keep
            # prompt.txt compatibility by materializing a temporary SKILL.
            if entry.skill_path.is_file():
                skill_dest = link_dir / "SKILL.md"
                if skill_dest.exists():
                    os.remove(skill_dest)
                original = entry.skill_path.read_text(encoding="utf-8")
                skill_dest.write_text(original, encoding="utf-8")
            else:
                logger.warning(
                    "Checker %s uses deprecated mode=api; wrapping prompt.txt as a temporary OpenCode SKILL",
                    name,
                )
                prompt_text = (
                    entry.prompt_path.read_text(encoding="utf-8")
                    if entry.prompt_path and entry.prompt_path.is_file()
                    else ""
                )
                skill_dest = link_dir / "SKILL.md"
                skill_dest.write_text(
                    "---\n"
                    f"name: {name}\n"
                    "description: Legacy prompt.txt checker wrapped for OpenCode execution.\n"
                    "---\n\n"
                    + prompt_text,
                    encoding="utf-8",
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
        skill_dest.write_text(original, encoding="utf-8")

        _link_skill_resources(entry, link_dir)

    logger.debug("Linked skills for %d checkers", len(registry))
