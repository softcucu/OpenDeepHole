from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_threat_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Run threat analysis without the backend")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--code-scan-path")
    parser.add_argument("--scan-id", default="standalone")
    parser.add_argument("--product", default="")
    parser.add_argument("--task-agent-config")
    parser.add_argument("--result-path")
    parser.add_argument("--no-reuse-cache", action="store_true")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_threat_analysis(
        project_path=args.project_path,
        work_dir=args.work_dir,
        code_scan_path=args.code_scan_path or args.project_path,
        scan_id=args.scan_id,
        product=args.product,
        task_agent_config=args.task_agent_config,
        result_path=args.result_path,
        reuse_cache=not args.no_reuse_cache,
        output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
