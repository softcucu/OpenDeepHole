"""OpenDeepHole integration for the self-contained Task Agent component."""

from __future__ import annotations

import hashlib
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
_MANAGED_CONFIG_FILENAME = ".opendeephole-managed-opencode.json"
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


def _config_value(value, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _disabled_source_mcp_tools(directory: Path) -> tuple[str, ...]:
    """Choose the source MCP disabled for one project using Agent state."""
    config = get_config()
    code_graph = getattr(config, "code_graph", None)
    name = str(_config_value(code_graph, "name", "codegraph") or "codegraph")
    if not bool(_config_value(code_graph, "enabled", False)):
        return (name,)
    try:
        from agent.codegraph import is_codegraph_mcp_available, is_codegraph_ready

        if is_codegraph_mcp_available(config) and is_codegraph_ready(directory):
            return ("deephole-code",)
    except Exception:
        pass
    return (name,)


def _build_session_runtime(cli_config, model_option, directory: Path):
    """Resolve the existing OpenDeepHole Serve configuration for the component."""
    from agent.task_agent import OpenCodeSessionRuntime
    from agent import opencode_workflows as runtime_helpers

    effective = runtime_helpers._effective_cli_config(cli_config, model_option)
    tool = runtime_helpers._normalize_tool(effective)
    if tool not in {"opencode", "nga"}:
        raise ValueError(f"Unsupported OpenCode serve tool: {tool}")
    if runtime_helpers._invocation_mode(effective) != "serve":
        raise ValueError("OpenCode tasks require serve invocation mode")
    executable = runtime_helpers._resolve_cli_executable(effective)
    model = str(_config_value(effective, "model", "") or "")
    workspace = get_global_opencode_workspace()
    serve_env = runtime_helpers._build_cli_env(
        workspace,
        tool,
        writable_paths=None,
        project_dir=None,
        executable=executable,
        cli_config=effective,
    )
    config_content = runtime_helpers._build_opencode_config_content(
        workspace,
        tool,
        base_env=serve_env,
        writable_paths=None,
        project_dir=None,
        executable=executable,
        cli_config=effective,
    )
    return OpenCodeSessionRuntime(
        directory=Path(directory).resolve(),
        tool=tool,
        executable=executable,
        model=model,
        config_workspace=workspace,
        config_content=config_content,
        env_overrides=runtime_helpers._opencode_process_env_overrides(serve_env),
    )


def configure_opencode_component() -> None:
    """Register OpenDeepHole host bindings without starting OpenCode Serve."""
    from agent.task_agent import OpenCodeHostBindings, configure_opencode

    configure_opencode(OpenCodeHostBindings(
        get_config=get_config,
        get_workspace=get_global_opencode_workspace,
        build_session_runtime=_build_session_runtime,
        disabled_source_mcp_tools=_disabled_source_mcp_tools,
    ))


def get_workspace_lock(workspace: Path) -> threading.RLock:
    """Return a process-local lock for opencode files in one workspace."""
    key = str(workspace.resolve())
    with _workspace_locks_guard:
        lock = _workspace_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _workspace_locks[key] = lock
        return lock


def managed_opencode_config_path(workspace: Path) -> Path:
    """Return the private OpenDeepHole-owned config layer for one workspace."""
    return workspace / _MANAGED_CONFIG_FILENAME


def opencode_runtime_config_path() -> Path:
    """Return the Agent-wide resolved Serve config path without initializing it."""
    return _GLOBAL_WORKSPACE / "opencode.json"


def get_global_opencode_workspace(*, mcp_port: int | None = None) -> Path:
    """Return and initialize the single Agent-wide OpenCode workspace.

    The workspace contains stable MCP/skill configuration only. Scan-specific
    state (scope, selected feedback and writable roots) is attached to each
    task by :mod:`agent.task_agent.task_service` and is never written here.
    """
    global _initialized_workspace
    workspace = _GLOBAL_WORKSPACE
    workspace.mkdir(parents=True, exist_ok=True)
    with get_workspace_lock(workspace):
        # A caller that owns/has just joined the Agent-wide MCP gateway provides
        # its actual port. Without one, keep an existing config intact so a
        # task cannot accidentally replace a dynamically allocated gateway URL
        # with the configured fallback port.
        config_missing = not managed_opencode_config_path(workspace).is_file()
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


def refresh_global_opencode_config() -> Path:
    """Rewrite managed MCP entries while preserving the active code gateway URL."""
    workspace = get_global_opencode_workspace()
    config_path = managed_opencode_config_path(workspace)
    mcp_url = f"http://127.0.0.1:{get_config().mcp_server.port}/mcp"
    try:
        existing = json.loads(config_path.read_text(encoding="utf-8"))
        current_url = existing.get("mcp", {}).get("deephole-code", {}).get("url")
        if current_url:
            mcp_url = str(current_url)
    except Exception:
        pass
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    with get_workspace_lock(workspace):
        _write_text_atomic(
            config_path,
            json.dumps(build_opencode_config(mcp_url, [str(skills_dir)]), indent=2),
            mode=0o600,
        )
        # Re-apply config-owned threat-analysis agents after regenerating the
        # base MCP/permission layer so a live config refresh cannot drop them.
        _install_builtin_skills(workspace)
    return workspace


def _write_text_atomic(path: Path, content: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    if mode is not None:
        temporary.chmod(mode)
    os.replace(temporary, path)
    if mode is not None:
        path.chmod(mode)


def _install_builtin_skills(workspace: Path) -> None:
    """Materialize every repository-owned skill in the global skill root."""
    repo_root = Path(__file__).resolve().parents[1]
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
    from agent.threat_analysis_workspace import install_attack_tree_threat_analysis_skill

    skill_path = repo_root / "attack-tree-threat-analysis.md"
    reference_path = repo_root / "attack-method-reference-catalog.md"
    if skill_path.is_file() and reference_path.is_file():
        install_attack_tree_threat_analysis_skill(
            workspace,
            skill_path,
            reference_path,
            config_path=managed_opencode_config_path(workspace),
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
    edit_permissions = {"*": "deny"}
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
            "external_directory": {"*": "deny"},
            "edit": edit_permissions,
            "bash": {"*": "deny"},
        },
    }
    for spec in build_managed_mcp_runtime_specs(get_config()).values():
        entry = spec.get("config")
        if spec.get("enabled") and isinstance(entry, dict) and not spec.get("error"):
            data["mcp"][str(spec["name"])] = entry
    if skills_paths:
        data["skills"] = {"paths": skills_paths}
    return data


def _managed_mcp_value(value, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def normalized_managed_mcp_config(managed) -> dict:
    """Return one stable managed-MCP payload for hashing and runtime sync."""
    local = _managed_mcp_value(managed, "local", {}) or {}
    remote = _managed_mcp_value(managed, "remote", {}) or {}
    return {
        "enabled": bool(_managed_mcp_value(managed, "enabled", False)),
        "name": str(_managed_mcp_value(managed, "name", "") or "").strip(),
        "transport": str(_managed_mcp_value(managed, "transport", "local") or "local"),
        "timeout_seconds": max(1, int(_managed_mcp_value(managed, "timeout_seconds", 300) or 300)),
        "local": {
            "executable": str(_managed_mcp_value(local, "executable", "") or "").strip(),
            "args": [str(item) for item in (_managed_mcp_value(local, "args", []) or [])],
            "environment": {
                str(key): str(value)
                for key, value in dict(_managed_mcp_value(local, "environment", {}) or {}).items()
            },
        },
        "remote": {
            "url": str(_managed_mcp_value(remote, "url", "") or "").strip(),
            "headers": {
                str(key): str(value)
                for key, value in dict(_managed_mcp_value(remote, "headers", {}) or {}).items()
            },
        },
    }


def managed_mcp_config_fingerprint(managed) -> str:
    payload = json.dumps(
        normalized_managed_mcp_config(managed),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_managed_mcp_runtime_specs(runtime_config=None) -> dict[str, dict]:
    """Build the two server-managed MCP entries used by config and hot reload."""
    runtime_config = runtime_config or get_config()
    result: dict[str, dict] = {}
    for target, managed in (
        ("code_graph", getattr(runtime_config, "code_graph", None)),
        ("product_info", getattr(runtime_config, "product_info", None)),
    ):
        normalized = normalized_managed_mcp_config(managed or {})
        enabled = normalized["enabled"]
        name = normalized["name"]
        transport = normalized["transport"]
        error = ""
        entry: dict | None = None
        if enabled and (not name or name == "deephole-code"):
            error = "MCP name is empty or reserved"
        elif enabled and transport == "remote":
            url = normalized["remote"]["url"]
            if not url:
                error = "Remote MCP URL is empty"
            else:
                entry = {
                    "type": "remote",
                    "url": url,
                    "enabled": True,
                    "timeout": normalized["timeout_seconds"] * 1000,
                    # OpenDeepHole currently supports static request-header auth.
                    # Disable OpenCode's interactive OAuth auto-discovery so a bad
                    # Bearer token is reported as a connection failure instead.
                    "oauth": False,
                }
                if normalized["remote"]["headers"]:
                    entry["headers"] = dict(normalized["remote"]["headers"])
        elif enabled and transport == "local":
            executable = normalized["local"]["executable"]
            if not executable:
                error = "Local MCP executable is empty"
            elif target == "code_graph" and not (
                shutil.which(executable) or Path(executable).is_file()
            ):
                error = f"CodeGraph executable not found: {executable}"
            else:
                entry = {
                    "type": "local",
                    "command": [executable, *normalized["local"]["args"]],
                    "enabled": True,
                    "timeout": normalized["timeout_seconds"] * 1000,
                }
                if normalized["local"]["environment"]:
                    entry["environment"] = dict(normalized["local"]["environment"])
        elif enabled:
            error = f"Unsupported MCP transport: {transport}"
        result[target] = {
            "target": target,
            "enabled": enabled,
            "name": name,
            "fingerprint": managed_mcp_config_fingerprint(normalized),
            "config": entry,
            "error": error,
        }
    return result


def _write_opencode_config(workspace: Path, mcp_port: int | None = None) -> None:
    """Generate the private OpenDeepHole-owned runtime configuration layer."""
    config = get_config()
    port = mcp_port if mcp_port is not None else config.mcp_server.port
    mcp_url = f"http://127.0.0.1:{port}/mcp"

    config_path = managed_opencode_config_path(workspace)
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    _write_text_atomic(
        config_path,
        json.dumps(build_opencode_config(mcp_url, [str(skills_dir)]), indent=2),
        mode=0o600,
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
