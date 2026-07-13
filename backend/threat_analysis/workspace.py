"""Workspace helpers for threat-analysis implementations."""

from __future__ import annotations

from pathlib import Path


_AGENT_SKILL_FILES = {
    "threat-analysis-harness": "threat-analysis-harness.md",
    "threat-asset-interface-agent": "threat-asset-interface-agent.md",
    "threat-attack-goal-agent": "threat-attack-goal-agent.md",
    "threat-attack-domain-agent": "threat-attack-domain-agent.md",
    "threat-attack-surface-agent": "threat-attack-surface-agent.md",
    "threat-method-confirm-agent": "threat-method-confirm-agent.md",
}


def install_attack_tree_threat_analysis_skill(
    workspace: Path,
    skill_path: Path,
    reference_catalog_path: Path,
) -> None:
    """Install the built-in attack-tree threat-analysis skill into a CLI workspace."""
    from backend.opencode.config import get_workspace_lock

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
        skills_root = skill_path.parent / "backend" / "threat_analysis" / "skills"
        for skill_name, filename in _AGENT_SKILL_FILES.items():
            source = skills_root / filename
            if not source.is_file():
                raise FileNotFoundError(f"Threat analysis agent skill not found: {source}")
            target = workspace / ".opencode" / "skills" / skill_name
            target.mkdir(parents=True, exist_ok=True)
            (target / "SKILL.md").write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            if skill_name in {"threat-attack-surface-agent", "threat-method-confirm-agent"}:
                (target / "attack-method-reference-catalog.md").write_text(
                    reference_catalog_path.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
