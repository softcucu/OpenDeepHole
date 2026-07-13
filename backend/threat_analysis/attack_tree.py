"""Default attack-tree threat-analysis implementation."""

from __future__ import annotations

from pathlib import Path

from backend.models import ThreatAnalysis

from .base import ThreatAnalysisCacheResult, ThreatAnalysisRunContext
from .parsing import (
    build_threat_analysis_scan_scope,
    parse_threat_analysis_file,
    threat_analysis_scope_matches,
)


class AttackTreeThreatAnalysis:
    """Threat analysis powered by the built-in attack-tree prompt and ``res.json``."""

    id = "attack_tree"
    label = "基于攻击树的威胁分析"
    skill_filename = "attack-tree-threat-analysis.md"
    reference_catalog_filename = "attack-method-reference-catalog.md"
    result_filename = "res.json"

    def result_path(self, project_path: Path) -> Path:
        return project_path / self.result_filename

    def load_cached(
        self,
        project_path: Path,
        code_scan_path: Path,
    ) -> ThreatAnalysisCacheResult:
        """Load a matching project-root ``res.json`` produced by this implementation."""
        result_path = self.result_path(project_path)
        expected = build_threat_analysis_scan_scope(project_path, code_scan_path)
        if not result_path.is_file():
            return ThreatAnalysisCacheResult(None, "")
        try:
            analysis = parse_threat_analysis_file(result_path)
        except Exception as exc:
            return ThreatAnalysisCacheResult(
                None,
                f"已有威胁分析产物解析失败，重新分析（路径: {result_path}，原因: {exc}）",
            )
        if threat_analysis_scope_matches(analysis, project_path, code_scan_path):
            scope_label = analysis.scan_scope.code_scan_relative_path or expected.code_scan_relative_path
            return ThreatAnalysisCacheResult(
                analysis,
                f"复用已有威胁分析产物（扫描范围: {scope_label}，路径: {result_path}）",
            )
        old_scope = (
            analysis.scan_scope.code_scan_relative_path
            or analysis.scan_scope.code_scan_path
            or "未标记"
        )
        return ThreatAnalysisCacheResult(
            None,
            f"已有威胁分析产物属于扫描范围 {old_scope}，当前扫描范围为 "
            f"{expected.code_scan_relative_path}，重新分析（路径: {result_path}）",
        )

    async def run(self, context: ThreatAnalysisRunContext) -> ThreatAnalysis | None:
        """Run the legacy OpenCode attack-tree implementation through the stable adapter."""
        from backend.opencode.runner import run_threat_analysis_audit

        return await run_threat_analysis_audit(
            workspace=context.workspace,
            project_id=context.scan_id,
            skill_path=context.repo_root / self.skill_filename,
            reference_catalog_path=context.repo_root / self.reference_catalog_filename,
            on_output=context.on_output,
            cancel_event=context.cancel_event,
            timeout=context.timeout,
            project_dir=context.project_path,
            code_scan_path=context.code_scan_path,
            product=context.product,
            planned_task_id=context.planned_task_id,
        )
