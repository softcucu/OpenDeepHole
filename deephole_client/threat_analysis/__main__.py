from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_threat_analysis


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the vendored threat-analysis implementation",
    )
    parser.add_argument("--code-path", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--task-agent-config")
    parser.add_argument("--product-mcp")
    parser.add_argument("--attack-modes")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    attack_modes = None
    if args.attack_modes:
        attack_modes = json.loads(args.attack_modes)
        if not isinstance(attack_modes, dict):
            parser.error("--attack-modes must be a JSON object")

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_threat_analysis(
        code_path=args.code_path,
        output_path=args.output_path,
        is_resume=args.resume,
        product_mcp=args.product_mcp,
        attack_modes=attack_modes,
        task_agent_config=args.task_agent_config,
        output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)
    raise SystemExit(0 if result.get("result") is True else 1)


if __name__ == "__main__":
    main()
