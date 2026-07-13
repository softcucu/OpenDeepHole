"""Threat-analysis package with compatibility exports for legacy imports."""

from .attack_tree import AttackTreeThreatAnalysis
from .attack_paths import (
    append_or_merge_attack_path,
    build_analysis_from_attack_paths,
    merge_attack_paths,
    parse_attack_path_data,
    read_attack_paths_jsonl,
    write_attack_paths_jsonl,
)
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
    "append_or_merge_attack_path",
    "apply_threat_analysis_scan_scope",
    "available_threat_analysis_implementations",
    "build_analysis_from_attack_paths",
    "build_threat_analysis_scan_scope",
    "get_threat_analysis_implementation",
    "merge_attack_paths",
    "parse_attack_path_data",
    "parse_threat_analysis_data",
    "parse_threat_analysis_file",
    "read_attack_paths_jsonl",
    "threat_analysis_enabled",
    "threat_analysis_scope_matches",
    "write_attack_paths_jsonl",
    "write_threat_analysis_file",
]
