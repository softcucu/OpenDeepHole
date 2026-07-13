"""Registry for configured threat-analysis implementations."""

from __future__ import annotations

from typing import Any

from .attack_tree import AttackTreeThreatAnalysis
from .base import ThreatAnalysisImplementation

_IMPLEMENTATIONS: dict[str, ThreatAnalysisImplementation] = {
    AttackTreeThreatAnalysis.id: AttackTreeThreatAnalysis(),
    "attack-tree": AttackTreeThreatAnalysis(),
}


def available_threat_analysis_implementations() -> list[str]:
    """Return available implementation IDs for config validation and diagnostics."""
    return sorted(_IMPLEMENTATIONS)


def get_threat_analysis_implementation(config: Any | None = None) -> ThreatAnalysisImplementation:
    """Resolve the implementation selected by ``threat_analysis.implementation``."""
    section = getattr(config, "threat_analysis", None) if config is not None else None
    implementation = getattr(section, "implementation", "") if section is not None else ""
    impl_id = str(implementation or AttackTreeThreatAnalysis.id).strip()
    selected = _IMPLEMENTATIONS.get(impl_id)
    if selected is None:
        available = ", ".join(available_threat_analysis_implementations())
        raise ValueError(f"Unknown threat analysis implementation '{impl_id}'. Available: {available}")
    return selected


def threat_analysis_enabled(config: Any | None = None) -> bool:
    """Return whether the configured threat-analysis stage should run."""
    section = getattr(config, "threat_analysis", None) if config is not None else None
    if section is None:
        return True
    return bool(getattr(section, "enabled", True))
