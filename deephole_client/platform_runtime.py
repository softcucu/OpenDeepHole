"""Platform adapter for Task Agent configuration.

Business-process packages never import this module. It only translates the
client's live configuration into the generic Task Agent host bindings used by
the platform coordinator.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import yaml

from .config import AgentConfig, apply_network_env


def _runtime_sections(config: AgentConfig, scan_dir: Path | None = None) -> dict:
    opencode = dataclasses.asdict(config.opencode)
    opencode["mock"] = False
    raw = {
        "opencode": opencode,
        "opencode_concurrency": config.opencode_concurrency,
        "memory_api_discovery": dataclasses.asdict(config.memory_api_discovery),
        "git_history": dataclasses.asdict(config.git_history),
        "threat_analysis": dataclasses.asdict(config.threat_analysis),
        "vulnerability_mining": dataclasses.asdict(config.vulnerability_mining),
        "false_positive": dataclasses.asdict(config.false_positive),
        "code_graph": dataclasses.asdict(config.code_graph),
        "product_info": dataclasses.asdict(config.product_info),
        "static_dedup": config.static_dedup,
        "pattern_filter": dataclasses.asdict(config.pattern_filter),
        "mcp_server": {"port": 8100},
        "no_proxy": config.no_proxy,
        "vulnerability_validation": {
            "enabled": config.vulnerability_validation.enabled,
            "environments": {
                name: dataclasses.asdict(value)
                for name, value in (
                    config.vulnerability_validation.environments.items()
                )
            },
        },
    }
    if scan_dir is not None:
        raw["storage"] = {
            "projects_dir": str(scan_dir.parent),
            "scans_dir": str(scan_dir),
        }
        raw["logging"] = {
            "level": "INFO",
            "file": str(scan_dir / "deephole_client.log"),
        }
    if config.fp_review_cli is not None:
        raw["fp_review_cli"] = dataclasses.asdict(config.fp_review_cli)
        raw["fp_review_cli"]["mock"] = False
    return raw


def refresh_platform_runtime_config(config: AgentConfig) -> None:
    """Apply live model/runtime changes to an already loaded platform adapter."""
    apply_network_env(config)
    import backend.config as backend_config

    current = backend_config._config
    if current is None:
        return
    raw = _runtime_sections(config)
    current.opencode = backend_config.OpenCodeConfig(**raw["opencode"])
    current.opencode_concurrency = int(raw["opencode_concurrency"])
    current.memory_api_discovery = backend_config.MemoryApiDiscoveryConfig(
        **raw["memory_api_discovery"],
    )
    current.git_history = backend_config.GitHistoryConfig(**raw["git_history"])
    current.threat_analysis = backend_config.ThreatAnalysisConfig(
        **raw["threat_analysis"],
    )
    current.vulnerability_mining = backend_config.ModelTaskPolicyConfig(
        **raw["vulnerability_mining"],
    )
    current.false_positive = backend_config.ModelTaskPolicyConfig(
        **raw["false_positive"],
    )
    current.code_graph = backend_config.McpConfig(**raw["code_graph"])
    current.product_info = backend_config.McpConfig(**raw["product_info"])
    current.vulnerability_validation = (
        backend_config.VulnerabilityValidationConfig(
            **raw["vulnerability_validation"],
        )
    )
    current.static_dedup = bool(raw["static_dedup"])
    current.pattern_filter = backend_config.PatternFilterConfig(
        **raw["pattern_filter"],
    )
    current.no_proxy = str(raw.get("no_proxy") or "")
    current.fp_review_cli = (
        backend_config.OpenCodeConfig(**raw["fp_review_cli"])
        if isinstance(raw.get("fp_review_cli"), dict)
        else None
    )


def configure_platform_runtime(config: AgentConfig, work_dir: Path) -> None:
    """Configure the platform's Task Agent host adapter for one operation."""
    work_dir = Path(work_dir).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    config_path = work_dir / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(_runtime_sections(config, work_dir), sort_keys=False),
        encoding="utf-8",
    )
    os.environ["CONFIG_PATH"] = str(config_path)
    apply_network_env(config)

    import backend.config as backend_config

    backend_config._config = None
    from .opencode_integration import configure_opencode_component

    configure_opencode_component()


__all__ = [
    "configure_platform_runtime",
    "refresh_platform_runtime_config",
]
