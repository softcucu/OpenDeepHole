from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_static_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OpenDeepHole static analysis without the backend")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--index-db-path", required=True)
    parser.add_argument("--checker-dir", action="append", required=True, dest="checker_dirs")
    parser.add_argument("--code-scan-path")
    parser.add_argument("--checker", action="append", dest="checker_names")
    parser.add_argument("--no-deduplicate", action="store_true")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_static_analysis(
        project_path=args.project_path,
        index_db_path=args.index_db_path,
        checker_dirs=args.checker_dirs,
        code_scan_path=args.code_scan_path or args.project_path,
        checker_names=args.checker_names,
        deduplicate=not args.no_deduplicate,
        output=event_output,
    ))
    serialized = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
