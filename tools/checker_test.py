#!/usr/bin/env python3
"""Run a checker locally without starting the backend service."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from backend.analyzers.base import BaseAnalyzer
from backend.models import Candidate, Vulnerability
from backend.registry import CHECKERS_DIR, CHECKERS_DIR_ENV, CheckerEntry, refresh_registry
from code_parser import CodeDatabase, CppAnalyzer
from agent.scanner import build_project_level_candidate, is_project_level_candidate


_SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


@dataclass
class CheckerTestResult:
    checker: dict[str, Any]
    project_path: str
    index_db: str
    candidates: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    audits: list[dict[str, Any]] = field(default_factory=list)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    json_mode = args.json or args.json_output is not None
    _configure_cli_logging(json_mode=json_mode, verbose=args.verbose)
    try:
        result = asyncio.run(_run(args))
    except CheckerTestError as exc:
        if json_mode:
            _emit_json_payload({"ok": False, "error": str(exc)}, args.json_output)
        else:
            print(f"[error] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[error] interrupted", file=sys.stderr)
        return 130

    if json_mode:
        payload = {
            "ok": True,
            "checker": result.checker,
            "project_path": result.project_path,
            "index_db": result.index_db,
            "candidate_count": len(result.candidates),
            "candidates": result.candidates,
            "warnings": result.warnings,
            "audits": result.audits,
        }
        _emit_json_payload(payload, args.json_output)
    else:
        _print_human_result(result, audit_requested=args.audit)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test one OpenDeepHole checker locally without a backend.",
    )
    parser.add_argument("checker", help="Checker name, e.g. memleak")
    parser.add_argument("project_path", type=Path, help="C/C++ project directory to scan")
    parser.add_argument(
        "--checkers-dir",
        type=Path,
        default=CHECKERS_DIR,
        help="Checker root directory (default: ./checkers)",
    )
    parser.add_argument(
        "--index-db",
        type=Path,
        help="Optional path for the temporary code index database",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--json-output",
        "--output",
        dest="json_output",
        type=Path,
        help=(
            "Write formatted UTF-8 JSON to this file. Chinese text is not escaped; "
            "this implies --json."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Show OpenDeepHole internal logs")
    parser.add_argument(
        "--min-candidates",
        type=int,
        help="Fail unless at least this many candidates are produced",
    )
    parser.add_argument(
        "--expect-candidates",
        type=int,
        help="Fail unless exactly this many candidates are produced",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Also run AI audit for a small number of candidates",
    )
    parser.add_argument(
        "--audit-limit",
        type=int,
        default=1,
        help="Maximum candidates to audit when --audit is set (default: 1)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("agent.yaml"),
        help="Agent-style config file used for --audit (default: ./agent.yaml)",
    )
    return parser.parse_args(argv)


def _emit_json_payload(payload: dict[str, Any], output_path: Path | None) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if output_path is None:
        print(text, end="")
        return
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def _configure_cli_logging(*, json_mode: bool, verbose: bool) -> None:
    root_logger = logging.getLogger("opendeephole")
    if not verbose:
        root_logger.setLevel(logging.WARNING)
    else:
        root_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers:
        if not verbose:
            handler.setLevel(logging.WARNING)
        else:
            handler.setLevel(logging.DEBUG)
        if (
            json_mode
            and isinstance(handler, logging.StreamHandler)
            and not isinstance(handler, logging.FileHandler)
            and getattr(handler, "stream", None) is sys.stdout
        ):
            handler.setStream(sys.stderr)


async def _run(args: argparse.Namespace) -> CheckerTestResult:
    project_path = args.project_path.resolve()
    if not project_path.is_dir():
        raise CheckerTestError(f"project path is not a directory: {project_path}")
    if args.min_candidates is not None and args.min_candidates < 0:
        raise CheckerTestError("--min-candidates must be >= 0")
    if args.expect_candidates is not None and args.expect_candidates < 0:
        raise CheckerTestError("--expect-candidates must be >= 0")
    if args.audit_limit < 1:
        raise CheckerTestError("--audit-limit must be >= 1")

    warnings: list[str] = []
    original_checkers_dir = os.environ.get(CHECKERS_DIR_ENV)
    with tempfile.TemporaryDirectory(prefix="opendeephole-checker-test-") as tmp:
        temp_root = Path(tmp) / "checkers"
        metadata = _copy_checker_for_test(
            checker_name=args.checker,
            source_root=args.checkers_dir.resolve(),
            target_root=temp_root,
            warnings=warnings,
        )
        os.environ[CHECKERS_DIR_ENV] = str(temp_root)
        try:
            registry = refresh_registry(temp_root)
            entry = registry.get(args.checker)
            if entry is None:
                raise CheckerTestError(f"checker did not load from {temp_root / args.checker}")
            if entry.analyzer is not None and not isinstance(entry.analyzer, BaseAnalyzer):
                raise CheckerTestError("Analyzer must inherit backend.analyzers.base.BaseAnalyzer")

            index_db = _build_index(project_path, args.index_db)
            candidates = _run_static_analysis(entry, project_path, index_db)
            candidate_payloads = [_candidate_payload(c) for c in candidates]
            _validate_candidates(args.checker, project_path, candidates)
            _check_candidate_count(args, len(candidates))

            audits: list[dict[str, Any]] = []
            if args.audit:
                audits = await _run_audits(
                    project_path=project_path,
                    index_db=index_db,
                    candidates=candidates[: args.audit_limit],
                    config_path=args.config,
                    warnings=warnings,
                    quiet=args.json,
                )

            return CheckerTestResult(
                checker={
                    "name": entry.name,
                    "label": entry.label,
                    "description": entry.description,
                    "enabled": bool(metadata.get("enabled", True)),
                    "visibility": entry.visibility,
                    "mode": entry.mode,
                    "directory": str((args.checkers_dir.resolve() / args.checker).resolve()),
                },
                project_path=str(project_path),
                index_db=str(index_db),
                candidates=candidate_payloads,
                warnings=warnings,
                audits=audits,
            )
        finally:
            if original_checkers_dir is None:
                os.environ.pop(CHECKERS_DIR_ENV, None)
            else:
                os.environ[CHECKERS_DIR_ENV] = original_checkers_dir
            _reset_registry_cache()


def _copy_checker_for_test(
    checker_name: str,
    source_root: Path,
    target_root: Path,
    warnings: list[str],
) -> dict[str, Any]:
    source_dir = source_root / checker_name
    if not source_dir.is_dir():
        raise CheckerTestError(f"checker directory not found: {source_dir}")
    yaml_path = source_dir / "checker.yaml"
    if not yaml_path.is_file():
        raise CheckerTestError(f"checker.yaml not found: {yaml_path}")

    with open(yaml_path, encoding="utf-8") as f:
        original_metadata = yaml.safe_load(f) or {}
    if original_metadata.get("name") != checker_name:
        raise CheckerTestError(
            f"checker.yaml name must be {checker_name!r}, got {original_metadata.get('name')!r}"
        )

    mode = original_metadata.get("mode", "opencode")
    if mode == "api" and not (source_dir / "prompt.txt").is_file():
        raise CheckerTestError("mode: api requires prompt.txt")
    if mode != "api" and not (source_dir / "SKILL.md").is_file():
        raise CheckerTestError("mode: opencode requires SKILL.md")

    target_dir = target_root / checker_name
    shutil.copytree(source_dir, target_dir, ignore=_ignore_checker_files)
    test_metadata = deepcopy(original_metadata)
    if original_metadata.get("enabled", True) is False:
        warnings.append(
            f"checker {checker_name!r} has enabled: false; local test forces it on, "
            "but the Web scan selector will still hide it."
        )
        test_metadata["enabled"] = True
        (target_dir / "checker.yaml").write_text(
            yaml.safe_dump(test_metadata, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    return original_metadata


def _ignore_checker_files(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        path = Path(name)
        if name in _SKIP_DIRS or path.suffix in _SKIP_SUFFIXES:
            ignored.add(name)
    return ignored


def _build_index(project_path: Path, index_db_arg: Path | None) -> Path:
    if index_db_arg is None:
        index_file = project_path / "code_index.db"
    else:
        index_file = index_db_arg.resolve()
    index_file.parent.mkdir(parents=True, exist_ok=True)
    _remove_sqlite_files(index_file)

    db = CodeDatabase(index_file)
    try:
        CppAnalyzer(db).analyze_directory(project_path)
        db.mark_index_complete()
        db.checkpoint()
    finally:
        db.close()
    return index_file


def _run_static_analysis(entry: CheckerEntry, project_path: Path, index_db: Path) -> list[Candidate]:
    if entry.analyzer is None:
        if entry.mode == "opencode":
            return [build_project_level_candidate(entry, project_path, project_path)]
        return []

    db = CodeDatabase(index_db)
    try:
        return list(entry.analyzer.find_candidates(project_path, db=db))
    finally:
        db.close()


def _validate_candidates(checker_name: str, project_path: Path, candidates: list[Candidate]) -> None:
    for idx, candidate in enumerate(candidates, 1):
        if candidate.vuln_type != checker_name:
            raise CheckerTestError(
                f"candidate #{idx} has vuln_type {candidate.vuln_type!r}, expected {checker_name!r}"
            )
        if not candidate.file:
            raise CheckerTestError(f"candidate #{idx} has empty file")
        if candidate.line < 1:
            raise CheckerTestError(f"candidate #{idx} has invalid line: {candidate.line}")
        if not candidate.function:
            raise CheckerTestError(f"candidate #{idx} has empty function")
        if not candidate.description:
            raise CheckerTestError(f"candidate #{idx} has empty description")
        if not is_project_level_candidate(candidate) and _resolve_candidate_file(project_path, candidate.file) is None:
            raise CheckerTestError(
                f"candidate #{idx} file is not inside project or does not exist: {candidate.file}"
            )


def _resolve_candidate_file(project_path: Path, file_path: str) -> Path | None:
    raw = Path(file_path)
    candidates = [raw] if raw.is_absolute() else [project_path / raw, raw]
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(project_path)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            return resolved
    return None


def _check_candidate_count(args: argparse.Namespace, count: int) -> None:
    if args.min_candidates is not None and count < args.min_candidates:
        raise CheckerTestError(
            f"candidate count {count} is lower than --min-candidates {args.min_candidates}"
        )
    if args.expect_candidates is not None and count != args.expect_candidates:
        raise CheckerTestError(
            f"candidate count {count} does not match --expect-candidates {args.expect_candidates}"
        )


async def _run_audits(
    project_path: Path,
    index_db: Path,
    candidates: list[Candidate],
    config_path: Path,
    warnings: list[str],
    quiet: bool = False,
) -> list[dict[str, Any]]:
    if not candidates:
        warnings.append("--audit was requested, but there are no candidates to audit.")
        return []

    original_config_path = os.environ.get("CONFIG_PATH")
    _configure_backend_from_agent_config(config_path, project_path)

    from agent import mcp_registry
    from agent.local_mcp import LocalMCPServer
    from backend.opencode.config import get_global_opencode_workspace
    from backend.opencode.runner import run_audit, run_project_audit, run_sensitive_clear_audit
    from backend.opencode.task_service import (
        reset_opencode_execution_context,
        set_opencode_execution_context,
    )

    agent_project_dir = _agent_project_dir_for_index(index_db)
    scan_id = f"checker-test-{uuid4().hex[:12]}"
    execution_context_token = set_opencode_execution_context(
        scan_id=scan_id,
        scan_work_dir=Path.home() / ".opendeephole" / "scans" / scan_id,
    )
    mcp_server = LocalMCPServer(project_dir=agent_project_dir, project_id=scan_id)
    workspace: Path | None = None
    try:
        port = mcp_server.start()
        mcp_registry.register(project_path, port, scan_id)
        workspace = get_global_opencode_workspace(mcp_port=port)
        results: list[dict[str, Any]] = []
        cancel_event = threading.Event()
        for candidate in candidates:
            if not quiet:
                print(f"[audit] {candidate.file}:{candidate.line} {candidate.function}", flush=True)
            if (
                candidate.vuln_type == "sensitive_clear"
                and isinstance(candidate.metadata, dict)
                and candidate.metadata.get("kind") == "sensitive_clear_function"
            ):
                result = await run_sensitive_clear_audit(
                    workspace,
                    candidate,
                    scan_id,
                    on_output=None if quiet else lambda line: print(f"  {line}", flush=True),
                    cancel_event=cancel_event,
                    project_dir=project_path,
                )
                if result.vulnerabilities:
                    results.extend(_audit_payload(candidate, vuln) for vuln in result.vulnerabilities)
                else:
                    results.append(_audit_payload(candidate, None))
            elif is_project_level_candidate(candidate):
                vulns = await run_project_audit(
                    workspace,
                    candidate,
                    scan_id,
                    on_output=None if quiet else lambda line: print(f"  {line}", flush=True),
                    cancel_event=cancel_event,
                    project_dir=project_path,
                )
                results.extend(_audit_payload(candidate, vuln) for vuln in vulns)
            else:
                vuln = await run_audit(
                    workspace,
                    candidate,
                    scan_id,
                    on_output=None if quiet else lambda line: print(f"  {line}", flush=True),
                    cancel_event=cancel_event,
                    project_dir=project_path,
                )
                results.append(_audit_payload(candidate, vuln))
        return results
    finally:
        mcp_registry.unregister(project_path)
        if original_config_path is None:
            os.environ.pop("CONFIG_PATH", None)
        else:
            os.environ["CONFIG_PATH"] = original_config_path
        import backend.config as backend_config
        backend_config._config = None
        mcp_server.stop()
        reset_opencode_execution_context(execution_context_token)


def _agent_project_dir_for_index(index_db: Path) -> Path:
    if index_db.name == "code_index.db":
        return index_db.parent
    target_dir = Path(tempfile.mkdtemp(prefix="opendeephole-agent-index-"))
    shutil.copy2(index_db, target_dir / "code_index.db")
    return target_dir


def _configure_backend_from_agent_config(config_path: Path, project_path: Path) -> None:
    from agent.config import load_config

    agent_cfg = load_config(config_path if config_path.is_file() else None)
    config_dir = Path(tempfile.mkdtemp(prefix="opendeephole-checker-audit-"))
    scan_dir = config_dir / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    opencode_config = asdict(agent_cfg.opencode)
    opencode_config["mock"] = False
    raw = {
        "opencode": opencode_config,
        "opencode_concurrency": agent_cfg.opencode_concurrency,
        "storage": {
            "projects_dir": str(project_path.parent),
            "scans_dir": str(scan_dir),
        },
        "logging": {
            "level": "INFO",
            "file": str(config_dir / "checker-test.log"),
        },
        "mcp_server": {
            "port": 8100,
        },
        "no_proxy": agent_cfg.no_proxy,
    }
    config_path_out = config_dir / "config.yaml"
    config_path_out.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path_out)

    import backend.config as backend_config
    import backend.registry as backend_registry

    backend_config._config = None
    backend_registry._registry = None
    backend_registry._registry_dir = None


def _reset_registry_cache() -> None:
    import backend.registry as backend_registry

    backend_registry._registry = None
    backend_registry._registry_dir = None


def _candidate_payload(candidate: Candidate) -> dict[str, Any]:
    payload = candidate.model_dump()
    description = payload.get("description") or ""
    if len(description) > 500:
        payload["description"] = description[:500] + "..."
    return payload


def _audit_payload(candidate: Candidate, vuln: Vulnerability | None) -> dict[str, Any]:
    if vuln is None:
        return {
            "file": candidate.file,
            "line": candidate.line,
            "function": candidate.function,
            "vuln_type": candidate.vuln_type,
            "result": None,
        }
    return vuln.model_dump()


def _print_human_result(result: CheckerTestResult, *, audit_requested: bool) -> None:
    checker = result.checker
    print(f"Checker: {checker['name']} ({checker['label']})")
    print(f"Mode: {checker['mode']}  Visibility: {checker['visibility']}  Enabled: {checker['enabled']}")
    print(f"Project: {result.project_path}")
    print(f"Index DB: {result.index_db}")
    for warning in result.warnings:
        print(f"[warning] {warning}")
    print(f"Candidates: {len(result.candidates)}")
    for idx, candidate in enumerate(result.candidates[:20], 1):
        print(
            f"  {idx}. {candidate['file']}:{candidate['line']} "
            f"{candidate['function']} [{candidate['vuln_type']}]"
        )
        print(f"     {candidate['description']}")
    if len(result.candidates) > 20:
        print(f"  ... {len(result.candidates) - 20} more candidate(s)")
    if audit_requested:
        print(f"Audits: {len(result.audits)}")
        for idx, audit in enumerate(result.audits, 1):
            if audit.get("result") is None:
                print(f"  {idx}. no result")
            else:
                print(
                    f"  {idx}. {audit.get('file')}:{audit.get('line')} "
                    f"verdict={audit.get('ai_verdict')} confirmed={audit.get('confirmed')}"
                )


def _remove_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass


class CheckerTestError(Exception):
    """Expected checker-test failure."""


if __name__ == "__main__":
    raise SystemExit(main())
