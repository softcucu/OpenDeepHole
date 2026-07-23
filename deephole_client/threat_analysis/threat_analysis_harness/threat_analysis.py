"""Third-party callable threat-analysis API."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.pipeline import ThreatAnalysisPipeline
from threat_analysis_harness.task_agent_submitter import TaskAgentSubmitter


def run_threat_analysis(
    code_path: str | Path,
    output_path: str | Path,
    is_resume: bool = False,
    product_mcp: str | None = None,
    attack_modes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run threat analysis and return a JSON-serializable result object.

    ``product_mcp`` and ``attack_modes`` are accepted for forward compatibility.
    The current pipeline does not consume them yet.
    """

    del product_mcp, attack_modes
    try:
        code_root = _required_path(code_path, "code_path")
        artifact_root = _required_path(output_path, "output_path")

        layout = ThreatAnalysisLayout(artifact_root)
        submitter = TaskAgentSubmitter()
        pipeline = ThreatAnalysisPipeline(
            submit_tasks=submitter.submit_tasks,
            layout=layout,
        )
        pipeline.run(input_files=[code_root], resume=bool(is_resume))

        return {
            "result": True,
            "value_asset_path": str(layout.value_assets_final_dir / "value-assets.json"),
            "attack_tree_path": str(layout.attack_trees_final_dir / "attack_trees.json"),
            "high_risk_modules_path": str(
                layout.high_risk_final_dir / "high-risk-module-merge.json"
            ),
        }
    except Exception as exc:
        return {
            "result": False,
            "reason": str(exc),
        }


def _required_path(value: str | Path, name: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{name} is required")
    return Path(raw).expanduser()
