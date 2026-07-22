"""Agent-side workspace helpers for threat-analysis implementations."""

from __future__ import annotations

import json
from pathlib import Path


_AGENT_SKILL_FILES = {
    "threat-analysis-harness": "threat-analysis-harness.md",
    "threat-base-model-shard-planner": "threat-base-model-shard-planner.md",
    "threat-asset-interface-agent": "threat-asset-interface-agent.md",
    "threat-base-model-gap-review-agent": "threat-base-model-gap-review-agent.md",
    "threat-asset-enumerator": "threat-asset-enumerator.md",
    "threat-attack-goal-enumerator": "threat-attack-goal-enumerator.md",
    "threat-code-evidence-mapper": "threat-code-evidence-mapper.md",
    "threat-attack-goal-agent": "threat-attack-goal-agent.md",
    "threat-attack-domain-agent": "threat-attack-domain-agent.md",
    "threat-attack-surface-agent": "threat-attack-surface-agent.md",
    "threat-method-confirm-agent": "threat-method-confirm-agent.md",
}


_THREAT_ANALYSIS_SUBAGENTS = {
    "threat-asset-enumerator": {
        "mode": "subagent",
        "hidden": True,
        "description": "从产品信息、代码索引和目录结构识别价值资产、资产类型、关键风险和接口关联。",
        "prompt": (
            "你是威胁分析第一步基础建模协调 Agent 派发的价值资产枚举子 Agent。"
            "只做资产、风险和接口关系识别，不分析攻击方法或漏洞是否存在。"
            "当前工具只分析 C/C++ 源文件、头文件和 C/C++ 构建文件，不把非 C/C++ 文件作为依据。"
            "当调用方给出 C/C++ 目录、模块、入口类型或接口分片时，只分析该分片，并在结果中标注 shard_scope。"
            "优先使用输入中可用的产品信息 MCP 事实，并用代码索引、目录浏览、grep、read 结果补充。"
            "输出给调用方的内容必须聚焦 assets、risks、asset_interface_links 和遗漏风险，不要写项目文件。"
            "除内部 ID、JSON 字段名、枚举值、文件路径、函数名、协议名和标准缩写外，"
            "所有面向用户展示的自然语言字段必须使用中文。"
        ),
        "tools": {
            "read": True,
            "list": True,
            "glob": True,
            "grep": True,
            "task": False,
            "bash": False,
            "edit": True,
        },
        "permission": {
            "read": "allow",
            "list": "allow",
            "glob": "allow",
            "grep": "allow",
            "bash": "deny",
            "task": "deny",
        },
    },
    "threat-attack-goal-enumerator": {
        "mode": "subagent",
        "hidden": True,
        "description": "从攻击者视角为价值资产和关键风险枚举可执行、可分解的攻击目标。",
        "prompt": (
            "你是威胁分析第一步基础建模协调 Agent 派发的攻击目标枚举子 Agent。"
            "围绕输入资产、风险、外部接口和代码线索，从攻击者视角生成具体攻击目标。"
            "当前工具只分析 C/C++ 源文件、头文件和 C/C++ 构建文件，不把非 C/C++ 文件作为依据。"
            "当调用方给出资产、风险、业务域或接口族分片时，只为该 goal_scope 生成攻击目标。"
            "攻击目标必须描述攻击者想造成的资产损害结果，不能写成漏洞类型或测试动作。"
            "输出给调用方的内容必须聚焦 attack_goals、related_interface_ids、candidate_code_paths 和覆盖缺口，不要写项目文件。"
            "除内部 ID、JSON 字段名、枚举值、文件路径、函数名、协议名和标准缩写外，"
            "所有面向用户展示的自然语言字段必须使用中文。"
        ),
        "tools": {
            "read": True,
            "list": True,
            "glob": True,
            "grep": True,
            "task": False,
            "bash": False,
            "edit": True,
        },
        "permission": {
            "read": "allow",
            "list": "allow",
            "glob": "allow",
            "grep": "allow",
            "bash": "deny",
            "task": "deny",
        },
    },
    "threat-code-evidence-mapper": {
        "mode": "subagent",
        "hidden": True,
        "description": "核对资产、接口和攻击目标对应的真实代码路径，标出证据不足或路径缺失的项目。",
        "prompt": (
            "你是威胁分析第一步基础建模协调 Agent 派发的代码证据映射子 Agent。"
            "只确认资产、接口、风险和攻击目标是否有真实代码路径支撑。"
            "当前工具只分析 C/C++ 源文件、头文件和 C/C++ 构建文件，不把非 C/C++ 文件作为依据。"
            "当调用方给出候选资产、接口、攻击目标或代码路径分片时，只核对该 evidence_scope。"
            "代码路径必须来自输入代码索引、目录浏览、grep 或 read 结果；无法确认时明确返回空路径和原因。"
            "输出给调用方的内容必须聚焦 candidate_code_paths、evidence 和不确定项，不要写项目文件。"
            "除内部 ID、JSON 字段名、枚举值、文件路径、函数名、协议名和标准缩写外，"
            "所有面向用户展示的自然语言字段必须使用中文。"
        ),
        "tools": {
            "read": True,
            "list": True,
            "glob": True,
            "grep": True,
            "task": False,
            "bash": False,
            "edit": True,
        },
        "permission": {
            "read": "allow",
            "list": "allow",
            "glob": "allow",
            "grep": "allow",
            "bash": "deny",
            "task": "deny",
        },
    },
}


def install_attack_tree_threat_analysis_skill(
    workspace: Path,
    skill_path: Path,
    reference_catalog_path: Path,
    *,
    config_path: Path | None = None,
) -> None:
    """Install the built-in attack-tree threat-analysis skill into a CLI workspace."""
    from deephole_client.opencode_integration import (
        _write_text_atomic,
        get_workspace_lock,
        managed_opencode_config_path,
    )

    skill_path = skill_path.resolve()
    reference_catalog_path = reference_catalog_path.resolve()
    if not skill_path.is_file():
        raise FileNotFoundError(f"Threat analysis skill not found: {skill_path}")
    if not reference_catalog_path.is_file():
        raise FileNotFoundError(f"Attack method reference catalog not found: {reference_catalog_path}")

    with get_workspace_lock(workspace):
        _install_threat_analysis_subagents(
            config_path or managed_opencode_config_path(workspace),
            write_text_atomic=_write_text_atomic,
        )
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


def _install_threat_analysis_subagents(config_path: Path, *, write_text_atomic) -> None:
    """Register first-step threat-analysis subagents in the managed config layer."""
    try:
        data = json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}

    permission = data.setdefault("permission", {})
    if not isinstance(permission, dict):
        permission = {}
        data["permission"] = permission
    permission["task"] = {"*": "allow"}

    agents = data.setdefault("agent", {})
    if not isinstance(agents, dict):
        agents = {}
        data["agent"] = agents
    for name, agent_config in _THREAT_ANALYSIS_SUBAGENTS.items():
        agents[name] = agent_config

    write_text_atomic(
        config_path,
        json.dumps(data, ensure_ascii=False, indent=2),
        mode=0o600,
    )
