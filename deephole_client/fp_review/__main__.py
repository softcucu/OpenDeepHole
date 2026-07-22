from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_fp_review


def main() -> None:
    parser = argparse.ArgumentParser(description="Run false-positive review without the backend")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--vulnerabilities", required=True, help="Vulnerability JSON file")
    parser.add_argument("--feedback")
    parser.add_argument("--history")
    parser.add_argument("--processed-offset", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--task-agent-config")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    def load(path: str | None) -> list:
        return json.loads(Path(path).read_text(encoding="utf-8")) if path else []

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_fp_review(
        project_path=args.project_path, work_dir=args.work_dir, scan_id=args.scan_id,
        review_id=args.review_id, vulnerabilities=load(args.vulnerabilities),
        feedback_entries=load(args.feedback), history=load(args.history),
        processed_offset=args.processed_offset, concurrency=args.concurrency,
        task_agent_config=args.task_agent_config, output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
