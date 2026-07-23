#!/usr/bin/env python3
"""Command line entrypoint for the third-party threat-analysis API."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_analysis_harness.threat_analysis import run_threat_analysis  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = run(args)
    except KeyboardInterrupt:
        result = {"result": False, "reason": "Interrupted."}
        exit_code = 130
    except Exception as exc:
        result = {"result": False, "reason": str(exc)}
        exit_code = 1
    else:
        exit_code = 0 if result.get("result") is True else 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ThreatAnalysis through run_threat_analysis().",
    )
    parser.add_argument(
        "--code-path",
        required=True,
        help="代码仓路径。",
    )
    parser.add_argument(
        "--output-path",
        required=True,
        help="落盘产物路径。",
    )
    parser.add_argument(
        "--product-mcp",
        default=None,
        help="产品知识 MCP 名称；当前仅透传给接口。",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="复用 output-path 下已有任务 JSON 输出。",
    )
    parser.add_argument(
        "--attack-modes",
        default=None,
        help="私有攻击模式 JSON 字符串；当前仅透传给接口。",
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    return run_threat_analysis(
        code_path=args.code_path,
        output_path=args.output_path,
        is_resume=bool(args.resume),
        product_mcp=args.product_mcp,
        attack_modes=_attack_modes(args.attack_modes),
    )


def _attack_modes(raw: str | None) -> dict[str, Any] | None:
    if raw is None or not str(raw).strip():
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("attack_modes must be a JSON object")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
