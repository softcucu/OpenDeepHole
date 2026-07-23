"""Platform coordinator for the independent DeepHole client processes."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Awaitable, Callable

from backend.models import (
    Candidate,
    ScanEvent,
    ThreatAuditTask,
    Vulnerability,
)
from task_agent import opencode_task_context

from .candidate_audit import run_candidate_audit
from .code_graph_build import run_code_graph_build
from .config import AgentConfig
from .platform_runtime import configure_platform_runtime
from .process_artifacts import collect_json_artifacts
from .reporter import Reporter
from .static_analysis import run_static_analysis
from .threat_analysis import run_threat_analysis
from .threat_audit import run_threat_audit


SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"
ProcessOutput = Callable[[dict[str, Any]], Awaitable[None]]


def _resolve_scan_paths(
    project_path: Path,
    code_scan_path: Path | None,
) -> tuple[Path, Path]:
    project = Path(project_path).expanduser().resolve()
    scan_root = Path(code_scan_path or project).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"Project directory does not exist: {project}")
    if not scan_root.is_dir():
        raise FileNotFoundError(
            f"Code scan directory does not exist: {scan_root}",
        )
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError(
            "code_scan_path must be inside project_path",
        ) from exc
    return project, scan_root


def _capability(value: Any, default: str = "high") -> str:
    normalized = str(value or default).strip().lower()
    return "high" if normalized in {"medium", "high"} else "low"


def _event_candidate_index(event: dict[str, Any]) -> int | None:
    data = event.get("data")
    if not isinstance(data, dict):
        return None
    for key in ("audit_index", "vuln_index", "current", "total"):
        value = data.get(key)
        if isinstance(value, int):
            return value
    return None


async def _finish_scan(
    reporter: Reporter,
    scan_id: str,
    *,
    status: str,
    vulnerabilities: list[Vulnerability],
    total: int,
    processed: int,
    error: str | None = None,
) -> None:
    await reporter.finish_scan(
        scan_id,
        vulnerabilities,
        status,
        total,
        processed,
        error_message=error,
    )


async def _report_process_vulnerabilities(
    *,
    reporter: Reporter,
    config: AgentConfig,
    scan_id: str,
    project_path: Path,
    code_scan_path: Path,
    product: str,
    validation_environment: str,
    feedback_entries: list[dict[str, Any]],
    values: list[Any],
) -> list[Vulnerability]:
    reported: list[Vulnerability] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        vulnerability = Vulnerability.model_validate(value)
        reported.append(vulnerability)
        response = await reporter.report_vulnerability(scan_id, vulnerability)
        if not isinstance(response, dict):
            continue
        fp_info = response.get("fp_review")
        if isinstance(fp_info, dict) and fp_info.get("queued"):
            from . import server as client_server

            payload = vulnerability.model_dump(mode="json")
            payload["index"] = int(fp_info["vuln_index"])
            await client_server.enqueue_fp_review(
                config=config,
                reporter=reporter,
                scan_id=scan_id,
                review_id=str(fp_info["review_id"]),
                vulnerability=payload,
                project_path=str(project_path),
                feedback_entries=feedback_entries,
                processed_offset=int(fp_info.get("processed") or 0),
            )
        if (
            config.vulnerability_validation.enabled
            and vulnerability.confirmed
            and product
            and validation_environment
            and response.get("index") is not None
        ):
            from . import server as client_server

            await client_server.enqueue_vulnerability_validation(
                config=config,
                reporter=reporter,
                scan_id=scan_id,
                vuln_index=int(response["index"]),
                vulnerability=vulnerability.model_dump(mode="json"),
                report_markdown=str(
                    response.get("report_markdown")
                    or vulnerability.vulnerability_report
                    or vulnerability.ai_analysis
                ),
                project_path=str(project_path),
                code_scan_path=str(code_scan_path),
                product=product,
                validation_environment=validation_environment,
                report_queued=True,
            )
    return reported


async def _run_threat_processes(
    *,
    config: AgentConfig,
    reporter: Reporter,
    scan_id: str,
    project_path: Path,
    code_scan_path: Path,
    scan_dir: Path,
    cancel_event: threading.Event,
    output: ProcessOutput,
    retry_task_ids: list[str] | None,
) -> dict[str, Any]:
    output_path = scan_dir / "threat_analysis"
    result = await run_threat_analysis(
        code_path=code_scan_path,
        output_path=output_path,
        is_resume=True,
        product_mcp=(
            config.product_info.name
            if config.product_info.enabled
            else None
        ),
        output=output,
        cancel_event=cancel_event,
    )
    if result.get("result") is not True:
        return result
    try:
        artifact_bundle = collect_json_artifacts(
            result,
            output_root=output_path,
        )
    except Exception as exc:
        return {
            "result": False,
            "reason": f"Threat-analysis artifact collection failed: {exc}",
        }
    await reporter.push_threat_analysis(scan_id, artifact_bundle)

    existing = await reporter.get_threat_audit_tasks(scan_id)
    completed_ids = {
        item.task_id for item in existing if item.status == "completed"
    }
    audit_result = await run_threat_audit(
        project_path=project_path,
        work_dir=scan_dir / "threat_audit",
        scan_id=scan_id,
        attack_tree_path=result["attack_tree_path"],
        high_risk_modules_path=result["high_risk_modules_path"],
        concurrency=max(1, int(config.opencode_concurrency or 1)),
        required_capability=_capability(
            config.vulnerability_mining.required_capability,
        ),
        include_task_ids=retry_task_ids,
        exclude_task_ids=sorted(completed_ids),
        output=output,
        cancel_event=cancel_event,
    )
    result_indexes: dict[str, list[int]] = {}
    for raw in audit_result.get("vulnerabilities") or []:
        if not isinstance(raw, dict):
            continue
        vulnerability = Vulnerability.model_validate(raw)
        response = await reporter.report_vulnerability(scan_id, vulnerability)
        if isinstance(response, dict) and response.get("index") is not None:
            result_indexes.setdefault(vulnerability.source_task_id, []).append(
                int(response["index"]),
            )
    for raw_task in audit_result.get("tasks") or []:
        if not isinstance(raw_task, dict):
            continue
        task_data = dict(raw_task)
        task_data["result_vuln_indexes"] = result_indexes.get(
            str(task_data.get("task_id") or ""),
            [],
        )
        await reporter.push_threat_audit_task(
            scan_id,
            ThreatAuditTask.model_validate(task_data),
        )
    return {
        **result,
        "audit_status": audit_result.get("status"),
        "audit_task_count": len(audit_result.get("tasks") or []),
    }


async def run_scan(
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path | None,
    reporter: Reporter,
    scan_name: str,
    product: str,
    validation_environment: str,
    checker_names: list[str],
    scan_id: str,
    cancel_event: threading.Event,
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
    is_resume: bool = False,
    retry_candidates: list[dict] | None = None,
    retry_total_candidates: int | None = None,
    retry_processed_offset: int = 0,
    resume_threat_analysis: bool = False,
    retry_threat_audit_task_ids: list[str] | None = None,
    scan_mode: str = SCAN_MODE_FULL,
) -> None:
    """Coordinate independent processes and report their results."""
    feedback_entries = list(feedback_entries or [])
    scan_dir = (
        Path.home() / ".opendeephole" / "scans" / str(scan_id)
    ).expanduser().resolve()
    scan_dir.mkdir(parents=True, exist_ok=True)
    project, scan_root = _resolve_scan_paths(project_path, code_scan_path)
    configure_platform_runtime(config, scan_dir)

    normalized_mode = str(scan_mode or SCAN_MODE_FULL).strip().lower()
    if normalized_mode in {"threat_only", "threat-analysis-only"}:
        normalized_mode = SCAN_MODE_THREAT_ANALYSIS_ONLY
    if normalized_mode not in {
        SCAN_MODE_FULL,
        SCAN_MODE_THREAT_ANALYSIS_ONLY,
    }:
        raise ValueError(f"Unknown scan mode: {scan_mode}")
    threat_only = normalized_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY

    async def emit(
        phase: str,
        message: str,
        candidate_index: int | None = None,
    ) -> None:
        await reporter.send_event(
            scan_id,
            ScanEvent.create(phase, message, candidate_index),
        )
        print(f"[{phase}] {message}", flush=True)

    async def process_output(event: dict[str, Any]) -> None:
        process = str(event.get("process") or "process")
        message = str(event.get("message") or "")
        if message:
            await emit(process, message, _event_candidate_index(event))
        if process == "code_graph_build":
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            if event.get("kind") == "progress":
                await reporter.send_index_status(
                    scan_id,
                    "parsing",
                    int(data.get("current") or 0),
                    int(data.get("total") or 0),
                    stage=message,
                    stage_current=int(data.get("current") or 0),
                    stage_total=int(data.get("total") or 0),
                )

    await emit("init", f"Scan started: {scan_name}")
    await emit("init", f"Project: {project}")
    await emit("init", f"Code scan path: {scan_root}")
    await emit("init", f"Scan mode: {normalized_mode}")

    static_rule_roots = [
        Path(__file__).resolve().parent / "static_analysis" / "rules",
    ]
    audit_rule_roots = [
        Path(__file__).resolve().parent / "candidate_audit" / "rules",
    ]
    if checker_packages:
        from .rule_packages import unpack_rule_packages

        static_root = scan_dir / "rules" / "static"
        audit_root = scan_dir / "rules" / "audit"
        unpacked = unpack_rule_packages(
            checker_packages,
            static_root,
            audit_root,
        )
        static_rule_roots = [static_root]
        audit_rule_roots = [audit_root]
        await emit("init", f"Loaded {len(unpacked)} transported rule package(s)")

    graph_result = await run_code_graph_build(
        project_path=project,
        code_scan_path=scan_root,
        work_dir=scan_dir / "code_graph_build",
        reuse_cache=True,
        output=process_output,
        cancel_event=cancel_event,
    )
    if graph_result.get("status") != "success":
        status = (
            "cancelled"
            if graph_result.get("status") == "cancelled"
            else "error"
        )
        await _finish_scan(
            reporter,
            scan_id,
            status=status,
            vulnerabilities=[],
            total=0,
            processed=0,
            error=str(graph_result.get("error") or "") or None,
        )
        return
    index_path = Path(str(graph_result["index_db_path"]))
    stats = dict(graph_result.get("stats") or {})
    await reporter.send_index_status(
        scan_id,
        "done",
        int(stats.get("files") or 0),
        int(stats.get("files") or 0),
        stats=stats,
    )

    mcp_server = None
    pool_stop = asyncio.Event()
    pool_task: asyncio.Task[Any] | None = None
    threat_task: asyncio.Task[dict[str, Any]] | None = None
    audited: list[Vulnerability] = []
    total = 0
    processed = 0

    def task_output(line: str) -> None:
        if line:
            print(str(line), flush=True)

    try:
        from .local_mcp import LocalMCPServer
        from . import mcp_registry

        mcp_server = LocalMCPServer(project_dir=project, project_id=scan_id)
        mcp_port = mcp_server.start()
        mcp_registry.register(project, mcp_port, scan_id)
        from .opencode_integration import get_global_opencode_workspace

        get_global_opencode_workspace(mcp_port=mcp_port)
        pool_task = asyncio.create_task(
            reporter.publish_opencode_pool_until(scan_id, pool_stop),
        )
        await emit("mcp_ready", f"Local code MCP ready on port {mcp_port}")

        with opencode_task_context(
            scan_id=scan_id,
            project_dir=project,
            work_dir=scan_dir,
            feedback_entries=feedback_entries,
            output=task_output,
            cancel_event=cancel_event,
        ):
            should_run_threat = (
                bool(config.threat_analysis.enabled)
                and (
                    not is_resume
                    or resume_threat_analysis
                    or threat_only
                )
                and not cancel_event.is_set()
            )
            if should_run_threat:
                threat_task = asyncio.create_task(_run_threat_processes(
                    config=config,
                    reporter=reporter,
                    scan_id=scan_id,
                    project_path=project,
                    code_scan_path=scan_root,
                    scan_dir=scan_dir,
                    cancel_event=cancel_event,
                    output=process_output,
                    retry_task_ids=retry_threat_audit_task_ids,
                ))

            if threat_only:
                await reporter.send_static_progress(scan_id, 0, 0, done=True)
            else:
                candidates_cache = scan_dir / "candidates.json"
                if retry_candidates is not None:
                    candidate_values = [
                        dict(value)
                        for value in retry_candidates
                        if isinstance(value, dict)
                    ]
                    total = int(retry_total_candidates or len(candidate_values))
                elif is_resume and candidates_cache.is_file():
                    loaded = json.loads(
                        candidates_cache.read_text(encoding="utf-8"),
                    )
                    candidate_values = [
                        dict(value) for value in loaded if isinstance(value, dict)
                    ]
                    total = len(candidate_values)
                else:
                    static_result = await run_static_analysis(
                        project_path=project,
                        code_scan_path=scan_root,
                        work_dir=scan_dir / "static_analysis",
                        index_db_path=index_path,
                        checker_dirs=static_rule_roots,
                        checker_names=checker_names or None,
                        deduplicate=bool(config.static_dedup),
                        output=process_output,
                        cancel_event=cancel_event,
                    )
                    candidate_values = list(
                        static_result.get("candidates") or [],
                    )
                    total = len(candidate_values)
                    candidates_cache.write_text(
                        json.dumps(
                            candidate_values,
                            ensure_ascii=False,
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )

                candidates = [
                    Candidate.model_validate(value)
                    for value in candidate_values
                ]
                await reporter.report_candidates(scan_id, candidates)
                await reporter.send_static_progress(
                    scan_id,
                    total,
                    total,
                    done=True,
                )
                processed_keys = (
                    await reporter.get_processed_keys(scan_id)
                    if is_resume and retry_candidates is None
                    else set()
                )
                remaining = [
                    item
                    for item in candidate_values
                    if (
                        str(item.get("file") or ""),
                        int(item.get("line") or 0),
                        str(item.get("function") or ""),
                        str(item.get("vuln_type") or ""),
                    )
                    not in processed_keys
                ]
                processed = (
                    max(0, int(retry_processed_offset or 0))
                    if retry_candidates is not None
                    else total - len(remaining)
                )
                if remaining and not cancel_event.is_set():
                    scope = str(config.pattern_filter.scope or "directory")
                    audit_result = await run_candidate_audit(
                        project_path=project,
                        work_dir=scan_dir / "candidate_audit",
                        scan_id=scan_id,
                        candidates=remaining,
                        checker_dirs=audit_rule_roots,
                        index_db_path=index_path,
                        checker_names=checker_names or None,
                        concurrency=max(
                            1,
                            int(config.opencode_concurrency or 1),
                        ),
                        required_capability=_capability(
                            config.vulnerability_mining.required_capability,
                        ),
                        pattern_filter_enabled=bool(
                            config.pattern_filter.enabled,
                        ),
                        pattern_filter_scope=(
                            "global"
                            if scope == "repo"
                            else "file"
                            if scope == "file"
                            else "function"
                        ),
                        feedback_entries=feedback_entries,
                        audit_index_offset=processed,
                        output=process_output,
                        cancel_event=cancel_event,
                    )
                    for checker_name, reports in (
                        audit_result.get("skill_reports") or {}
                    ).items():
                        if isinstance(reports, list):
                            await reporter.replace_skill_reports(
                                scan_id,
                                str(checker_name),
                                reports,
                            )
                    audited = await _report_process_vulnerabilities(
                        reporter=reporter,
                        config=config,
                        scan_id=scan_id,
                        project_path=project,
                        code_scan_path=scan_root,
                        product=product,
                        validation_environment=validation_environment,
                        feedback_entries=feedback_entries,
                        values=list(
                            audit_result.get("vulnerabilities") or [],
                        ),
                    )
                    for key in audit_result.get("processed_keys") or []:
                        if not isinstance(key, dict):
                            continue
                        await reporter.report_processed_key(
                            scan_id,
                            str(key.get("file") or ""),
                            int(key.get("line") or 0),
                            str(key.get("function") or ""),
                            str(key.get("vuln_type") or ""),
                        )
                    processed += len(audit_result.get("processed_keys") or [])

            threat_result = await threat_task if threat_task is not None else None
            if (
                threat_only
                and isinstance(threat_result, dict)
                and threat_result.get("result") is not True
                and not cancel_event.is_set()
            ):
                await _finish_scan(
                    reporter,
                    scan_id,
                    status="error",
                    vulnerabilities=[],
                    total=0,
                    processed=0,
                    error=str(threat_result.get("reason") or "Threat analysis failed"),
                )
                return

        status = "cancelled" if cancel_event.is_set() else "complete"
        await emit(
            "complete",
            (
                "Scan cancelled"
                if status == "cancelled"
                else f"Scan complete: {len(audited)} audit result(s)"
            ),
        )
        await _finish_scan(
            reporter,
            scan_id,
            status=status,
            vulnerabilities=audited,
            total=total,
            processed=processed,
        )
    except asyncio.CancelledError:
        cancel_event.set()
        if threat_task is not None and not threat_task.done():
            threat_task.cancel()
        await _finish_scan(
            reporter,
            scan_id,
            status="cancelled",
            vulnerabilities=audited,
            total=total,
            processed=processed,
        )
        raise
    except Exception as exc:
        cancel_event.set()
        if threat_task is not None and not threat_task.done():
            threat_task.cancel()
        await emit("error", f"Scan failed: {exc}")
        await _finish_scan(
            reporter,
            scan_id,
            status="error",
            vulnerabilities=audited,
            total=total,
            processed=processed,
            error=str(exc),
        )
    finally:
        pool_stop.set()
        if pool_task is not None:
            try:
                await pool_task
            except Exception:
                pass
        if mcp_server is not None:
            try:
                mcp_server.stop()
            except Exception:
                pass
        try:
            from . import mcp_registry

            mcp_registry.unregister(project)
        except Exception:
            pass


__all__ = ["run_scan"]
