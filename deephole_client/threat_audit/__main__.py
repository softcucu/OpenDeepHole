from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_threat_audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Run threat audit without the backend")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--scan-id", default="standalone")
    parser.add_argument("--attack-tree-path", required=True)
    parser.add_argument("--high-risk-modules-path", required=True)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--required-capability",
        choices=("low", "high"),
        default="high",
    )
    parser.add_argument("--task-agent-config")
    parser.add_argument("--include-task-id", action="append", dest="include_task_ids")
    parser.add_argument("--exclude-task-id", action="append", dest="exclude_task_ids")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_threat_audit(
        project_path=args.project_path, work_dir=args.work_dir, scan_id=args.scan_id,
        attack_tree_path=args.attack_tree_path,
        high_risk_modules_path=args.high_risk_modules_path,
        concurrency=args.concurrency,
        required_capability=args.required_capability,
        task_agent_config=args.task_agent_config, include_task_ids=args.include_task_ids,
        exclude_task_ids=args.exclude_task_ids, output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
