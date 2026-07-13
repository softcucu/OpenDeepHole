"""Interfaces shared by pluggable threat-analysis implementations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from backend.models import ThreatAnalysis, ThreatAttackPath


@dataclass(frozen=True)
class ThreatAnalysisCacheResult:
    """Result of checking an implementation-specific reusable artifact."""

    analysis: ThreatAnalysis | None
    message: str = ""


@dataclass(frozen=True)
class ThreatAnalysisRunContext:
    """Execution context passed to a threat-analysis implementation."""

    scan_id: str
    repo_root: Path
    project_path: Path
    code_scan_path: Path
    workspace: Path
    product: str = ""
    timeout: int | None = None
    planned_task_id: str = ""
    on_output: Callable[[str], object] | None = None
    on_attack_paths: Callable[[list[ThreatAttackPath]], object] | None = None
    cancel_event: object | None = None


class ThreatAnalysisImplementation(Protocol):
    """Contract for replaceable threat-analysis backends."""

    id: str
    label: str

    def load_cached(
        self,
        project_path: Path,
        code_scan_path: Path,
    ) -> ThreatAnalysisCacheResult:
        """Return a reusable previous analysis artifact when this implementation supports it."""

    async def run(self, context: ThreatAnalysisRunContext) -> ThreatAnalysis | None:
        """Run threat analysis and return a normalized public API result."""
