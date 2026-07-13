"""Threat-analysis package with compatibility exports for legacy imports."""

from .attack_tree import AttackTreeThreatAnalysis
from .base import (
    ThreatAnalysisCacheResult,
    ThreatAnalysisImplementation,
    ThreatAnalysisRunContext,
)
from .parsing import (
    apply_threat_analysis_scan_scope,
    build_threat_analysis_scan_scope,
    parse_threat_analysis_data,
    parse_threat_analysis_file,
    threat_analysis_scope_matches,
    write_threat_analysis_file,
)
from .registry import (
    available_threat_analysis_implementations,
    get_threat_analysis_implementation,
    threat_analysis_enabled,
)

__all__ = [
    "AttackTreeThreatAnalysis",
    "ThreatAnalysisCacheResult",
    "ThreatAnalysisImplementation",
    "ThreatAnalysisRunContext",
    "apply_threat_analysis_scan_scope",
    "available_threat_analysis_implementations",
    "build_threat_analysis_scan_scope",
    "get_threat_analysis_implementation",
    "parse_threat_analysis_data",
    "parse_threat_analysis_file",
    "threat_analysis_enabled",
    "threat_analysis_scope_matches",
    "write_threat_analysis_file",
]
