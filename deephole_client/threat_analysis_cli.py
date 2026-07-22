"""Standalone entry point for threat-analysis implementations."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from backend.config import load_config

from backend.threat_analysis.base import ThreatAnalysisRunContext
from backend.threat_analysis.registry import get_threat_analysis_implementation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run OpenDeepHole threat analysis standalone.")
    parser.add_argument("--project", required=True, help="Project root directory")
    parser.add_argument("--code-scan-path", default="", help="Code scan directory, defaults to project")
    parser.add_argument("--workspace", default="", help="Workspace directory, defaults to .opendeephole-threat-workspace")
    parser.add_argument("--scan-id", default="standalone-threat-analysis")
    parser.add_argument("--product", default="")
    parser.add_argument("--config", default="", help="Optional config.yaml path")
    parser.add_argument("--implementation", default="", help="Override threat_analysis.implementation")
    return parser


async def _run(args: argparse.Namespace) -> int:
    config = load_config(args.config or None)
    from deephole_client.opencode_integration import configure_opencode_component
    configure_opencode_component()
    if args.implementation:
        config.threat_analysis.implementation = args.implementation
    implementation = get_threat_analysis_implementation(config)

    project_path = Path(args.project).expanduser().resolve()
    code_scan_path = Path(args.code_scan_path).expanduser().resolve() if args.code_scan_path else project_path
    workspace = (
        Path(args.workspace).expanduser().resolve()
        if args.workspace
        else project_path / ".opendeephole-threat-workspace"
    )
    workspace.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parent.parent

    from deephole_client.opencode_workflows import execute_threat_analysis_context

    analysis = await implementation.run(
        ThreatAnalysisRunContext(
            scan_id=args.scan_id,
            repo_root=repo_root,
            project_path=project_path,
            code_scan_path=code_scan_path,
            workspace=workspace,
            product=args.product,
            timeout=config.opencode.timeout,
            on_output=lambda line: print(line, flush=True),
            execute=execute_threat_analysis_context,
        )
    )
    if analysis is None:
        print("Threat analysis produced no valid result.", flush=True)
        return 1
    print(
        f"Threat analysis complete: {len(analysis.assets)} assets, "
        f"{len(analysis.attack_trees)} attack trees.",
        flush=True,
    )
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(_run(_parser().parse_args())))


if __name__ == "__main__":
    main()
