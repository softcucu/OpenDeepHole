#!/usr/bin/env python3
"""Create an OpenDeepHole scan from an external reverse-engineering platform."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

OPENDEEPHOLE_URL = "http://127.0.0.1:8000"
INTEGRATION_TOKEN = "opendeephole-integration-token"
INTEGRATION_USERNAME = "opendeephole_integration"
INTEGRATION_PASSWORD = "opendeephole_integration_password"
AGENT_NAME = "reverse-linux-agent"

PROJECT_PATH = os.getcwd()
CODE_SCAN_PATH = ""
SCAN_NAME = ""
PRODUCT = ""
WAIT_FOR_FINISH = True
POLL_INTERVAL_SECONDS = 10

AGENT_CONFIG: dict[str, Any] = {
    "no_proxy": "10.0.0.0/8,127.0.0.1,localhost",
    "llm_api": {
        "base_url": "https://api.example.com/v1",
        "api_key": "replace-with-api-key",
        "model": "claude-sonnet-4-6",
        "temperature": 0.1,
        "timeout": 300,
        "max_retries": 3,
        "stream": False,
    },
    "opencode": {
        "tool": "opencode",
        "executable": "opencode",
        "model": "anthropic/claude-sonnet-4-20250514",
        "timeout": 1200,
        "max_retries": 2,
    },
    "fp_review_cli": None,
}

DONE_STATUSES = {"complete", "error", "cancelled"}


def call(method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-OpenDeepHole-Integration-Token", INTEGRATION_TOKEN)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {detail}") from exc


def resolve_scan_paths() -> tuple[Path, Path]:
    project = Path(PROJECT_PATH).expanduser().resolve()
    scan_root = Path(CODE_SCAN_PATH or str(project)).expanduser()
    scan_root = scan_root.resolve() if scan_root.is_absolute() else (project / scan_root).resolve()
    if not project.is_dir():
        raise SystemExit(f"PROJECT_PATH is not a directory: {project}")
    if not scan_root.is_dir():
        raise SystemExit(f"CODE_SCAN_PATH is not a directory: {scan_root}")
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise SystemExit("CODE_SCAN_PATH must be inside PROJECT_PATH") from exc
    return project, scan_root


def main() -> int:
    project, scan_root = resolve_scan_paths()
    server = OPENDEEPHOLE_URL.rstrip("/")
    payload = {
        "agent_name": AGENT_NAME,
        "project_path": str(project),
        "code_scan_path": str(scan_root),
        "scan_name": SCAN_NAME or project.name,
        "product": PRODUCT,
        "agent_config": AGENT_CONFIG,
    }

    created = call("POST", f"{server}/api/integration/scans", payload)
    print(json.dumps(created, ensure_ascii=False, indent=2))
    print(f"Result URL: {created['result_url']}")

    while WAIT_FOR_FINISH:
        status = call("GET", created["progress_api_url"])
        print(
            f"{status['status']} "
            f"{status['processed_candidates']}/{status['total_candidates']} "
            f"issues={status['issue_count']}"
        )
        if status["status"] in DONE_STATUSES:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
