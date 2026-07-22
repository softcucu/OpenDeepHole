"""Full local vulnerability scan pipeline for the agent."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from deephole_client.config import AgentConfig, apply_network_env
from deephole_client.reporter import Reporter
from backend.checker_sync import unpack_checker_packages
from backend.models import (
    Candidate,
    FeedbackEntry,
    ScanEvent,
    ThreatAnalysis,
    ThreatAnalysisSources,
    ThreatAttackPath,
    Vulnerability,
)
from task_agent.model_pool import NoAvailableModelError
from task_agent.output_format import with_local_timestamp
from backend.registry import CHECKERS_DIR_ENV
from backend.source_filter import source_path_has_ignored_dir


FunctionSourceSnapshot = tuple[str, int | None]
PROJECT_LEVEL_FUNCTION = "__project__"
STATIC_PROGRESS_MIN_INTERVAL_SECONDS = 0.5
STATIC_PROGRESS_MIN_PERCENT_DELTA = 1.0
FIRST_AUDIT_FUNCTION = "MC_EthBuildPayloadByFrag"
# Keep the git-history implementation and config fields in place, but do not
# execute this expensive phase from the scan pipeline for now.
GIT_HISTORY_PIPELINE_ENABLED = False
# Keep memory API discovery available as a standalone module/config surface, but
# do not run it as a scan-pipeline precondition.
MEMORY_API_DISCOVERY_PIPELINE_ENABLED = False
SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"
STREAMING_THREAT_ANALYSIS_ID_PREFIX = "STREAMING-ATA-"
SCAN_PIPELINE_OPENCODE_TASK_TYPES = {
    "",
    "audit",
    "git_history",
    "threat_analysis",
    "threat_audit",
    "variant_hunt",
}
OPENCODE_POOL_TERMINAL_DRAIN_TIMEOUT_SECONDS = 30.0


def _streaming_threat_analysis_id(scan_id: str) -> str:
    return f"{STREAMING_THREAT_ANALYSIS_ID_PREFIX}{scan_id}"


def _is_streaming_threat_analysis(analysis: ThreatAnalysis | None) -> bool:
    return bool(
        analysis
        and analysis.analysis_id.startswith(STREAMING_THREAT_ANALYSIS_ID_PREFIX)
    )


def _pool_task_type(task: Any) -> str:
    if not isinstance(task, dict):
        return ""
    return str(task.get("task_type") or "").strip()


def _pool_task_matches_types(task: Any, task_types: set[str]) -> bool:
    return _pool_task_type(task) in task_types


def _opencode_pool_has_pipeline_work(
    snapshot: dict[str, Any],
    task_types: set[str] = SCAN_PIPELINE_OPENCODE_TASK_TYPES,
) -> bool:
    for key in ("planned_tasks", "queued_tasks"):
        tasks = snapshot.get(key)
        if isinstance(tasks, list) and any(
            _pool_task_matches_types(task, task_types) for task in tasks
        ):
            return True
    models = snapshot.get("models")
    if isinstance(models, list):
        for model in models:
            if not isinstance(model, dict):
                continue
            active_tasks = model.get("active_tasks")
            if isinstance(active_tasks, list) and any(
                _pool_task_matches_types(task, task_types) for task in active_tasks
            ):
                return True
    return False


async def _wait_for_opencode_pool_pipeline_work(
    scan_id: str,
    task_types: set[str] = SCAN_PIPELINE_OPENCODE_TASK_TYPES,
    timeout_seconds: float = OPENCODE_POOL_TERMINAL_DRAIN_TIMEOUT_SECONDS,
) -> None:
    """Wait briefly for scan-pipeline OpenCode work to leave the model pool."""
    from task_agent.model_pool import model_pool_snapshot, wait_for_model_pool_update

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    snapshot = model_pool_snapshot(scan_id)
    while _opencode_pool_has_pipeline_work(snapshot, task_types):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(
                f"Warning: OpenCode pool still has scan pipeline work for {scan_id}; "
                "finishing with terminal pool cleanup",
                flush=True,
            )
            return
        last_updated_at = str(snapshot.get("updated_at") or "")
        await wait_for_model_pool_update(
            scan_id,
            last_updated_at=last_updated_at,
            timeout=min(1.0, remaining),
        )
        snapshot = model_pool_snapshot(scan_id)


async def _drain_opencode_pool_before_finish(
    scan_id: str,
    pool_status_stop: asyncio.Event,
    pool_status_task: asyncio.Task | None,
    task_types: set[str] = SCAN_PIPELINE_OPENCODE_TASK_TYPES,
) -> None:
    """Clear planned scan work and publish the final pool snapshot before finish_scan."""
    try:
        from task_agent.model_pool import clear_planned_tasks
        await clear_planned_tasks(scan_id, task_types)
    except Exception:
        pass
    try:
        await _wait_for_opencode_pool_pipeline_work(scan_id, task_types)
    except Exception as exc:
        print(f"Warning: failed to drain OpenCode pool before finish: {exc}", flush=True)
    pool_status_stop.set()
    if pool_status_task is not None:
        try:
            await pool_status_task
        except Exception:
            pass


async def _clear_finished_opencode_pool_history(scan_id: str) -> None:
    try:
        from task_agent.model_pool import clear_completed_tasks
        await clear_completed_tasks(scan_id)
    except Exception:
        pass


class _StaticProgressGate:
    """Rate-limit noisy static analyzer callbacks while preserving milestones."""

    def __init__(self, now: Callable[[], float] = time.monotonic) -> None:
        self._now = now
        self._last_sent_at: float | None = None
        self._last_percent: float | None = None

    def should_send(self, scanned: int, total: int, *, force: bool = False) -> bool:
        now = self._now()
        percent = (scanned / total * 100.0) if total > 0 else 0.0
        if (
            force
            or self._last_sent_at is None
            or (total > 0 and scanned >= total)
            or abs(percent - (self._last_percent or 0.0)) >= STATIC_PROGRESS_MIN_PERCENT_DELTA
            or now - self._last_sent_at >= STATIC_PROGRESS_MIN_INTERVAL_SECONDS
        ):
            self._last_sent_at = now
            self._last_percent = percent
            return True
        return False


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def is_project_level_candidate(candidate: Candidate) -> bool:
    return candidate.function == PROJECT_LEVEL_FUNCTION


def build_project_level_candidate(
    entry,
    project_root: Path,
    scan_root: Path,
) -> Candidate:
    """Create one synthetic candidate for a SKILL-only checker."""
    if scan_root == project_root:
        file_path = "."
    else:
        file_path = scan_root.relative_to(project_root).as_posix()
    return Candidate(
        file=file_path,
        line=1,
        function=PROJECT_LEVEL_FUNCTION,
        description=f"Project-level audit for {entry.label}",
        vuln_type=entry.name,
    )


def _should_run_git_history_phase(
    config: AgentConfig,
    *,
    ran_fresh_static: bool,
    retry_mode: bool,
    workspace: Path | None,
    cancel_event: threading.Event,
) -> bool:
    return (
        GIT_HISTORY_PIPELINE_ENABLED
        and ran_fresh_static
        and not retry_mode
        and getattr(config, "git_history", None) is not None
        and config.git_history.enabled
        and workspace is not None
        and not cancel_event.is_set()
    )


def _should_run_memory_api_phase(
    config: AgentConfig,
    *,
    workspace: Path | None,
    cancel_event: threading.Event,
) -> bool:
    return (
        MEMORY_API_DISCOVERY_PIPELINE_ENABLED
        and getattr(config, "memory_api_discovery", None) is not None
        and config.memory_api_discovery.enabled
        and workspace is not None
        and not cancel_event.is_set()
    )


def _order_candidates_for_audit(
    candidates: list[Candidate],
    checker_names: list[str],
    family_of: dict[str, str] | None = None,
) -> list[Candidate]:
    """Audit sparse checker results first while keeping per-checker order stable."""
    if len(candidates) <= 1:
        return list(candidates)

    counts: dict[str, int] = {}
    for candidate in candidates:
        counts[candidate.vuln_type] = counts.get(candidate.vuln_type, 0) + 1

    checker_order = {name: index for index, name in enumerate(checker_names)}
    fallback_order: dict[str, int] = {}

    def _checker_order(vuln_type: str) -> int:
        if vuln_type in checker_order:
            return checker_order[vuln_type]
        if vuln_type not in fallback_order:
            fallback_order[vuln_type] = len(checker_order) + len(fallback_order)
        return fallback_order[vuln_type]

    def _sort_key(item: tuple[int, Candidate]) -> tuple[int, int, int, int]:
        index, candidate = item
        return (
            0,
            counts[candidate.vuln_type],
            _checker_order(candidate.vuln_type),
            index,
        )

    ordered = sorted(
        enumerate(candidates),
        key=_sort_key,
    )
    return [candidate for _, candidate in ordered]


def _prioritize_first_audit_function(
    candidates: list[Candidate],
    original_order: dict[int, int] | None = None,
) -> list[Candidate]:
    if len(candidates) <= 1:
        return list(candidates)
    first = [candidate for candidate in candidates if candidate.function == FIRST_AUDIT_FUNCTION]
    if not first:
        return list(candidates)
    if original_order:
        first = sorted(first, key=lambda candidate: original_order.get(id(candidate), len(candidates)))
    rest = [candidate for candidate in candidates if candidate.function != FIRST_AUDIT_FUNCTION]
    return first + rest


def _prepare_audit_queue(
    candidates: list[Candidate],
    checker_names: list[str],
    *,
    family_of: dict[str, str] | None = None,
    pattern_filter_enabled: bool = False,
    pattern_filter_scope: str = "directory",
) -> list[Candidate]:
    original_order = {id(candidate): index for index, candidate in enumerate(candidates)}
    ordered = _order_candidates_for_audit(candidates, checker_names, family_of=family_of)
    if pattern_filter_enabled:
        ordered = _round_robin_by_pattern(ordered, pattern_filter_scope)
    return _prioritize_first_audit_function(ordered, original_order)


def _audit_order_summary(candidates: list[Candidate]) -> str:
    counts: dict[str, int] = {}
    order: list[str] = []
    for candidate in candidates:
        if candidate.vuln_type not in counts:
            order.append(candidate.vuln_type)
            counts[candidate.vuln_type] = 0
        counts[candidate.vuln_type] += 1
    return ", ".join(f"{name}={counts[name]}" for name in order)


_PROBLEM_LABELS = {
    "npd": "空指针解引用",
    "chain_npd": "空指针解引用",
    "mp_npd": "空指针解引用",
    "npd_funcret": "空指针解引用",
    "oob": "越界读写",
    "safe_mem_oob": "越界读写",
    "loop_mut_idx_oob": "越界读写",
    "bufoverflow": "越界读写",
    "memleak": "资源泄漏",
    "resleak": "资源泄漏",
    "multi_ptr_leak2": "资源泄漏",
    "mp_resouce_leak": "资源泄漏",
    "intoverflow": "整数溢出",
    "double_free": "重复释放",
    "inf_loop": "死循环",
    "sensitive_clear": "敏感信息未清零",
}


def _candidate_subject(candidate: Candidate) -> str:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    subject = metadata.get("subject")
    if isinstance(subject, (list, tuple, set)):
        return ", ".join(str(item).strip() for item in subject if str(item).strip())
    return str(subject or "").strip()


def _candidate_problem(candidate: Candidate) -> str:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    problem = str(metadata.get("problem") or "").strip()
    return problem or _PROBLEM_LABELS.get(candidate.vuln_type, candidate.vuln_type)


def _minimal_candidate_description(candidate: Candidate, subjects: list[str]) -> str:
    problem = _candidate_problem(candidate)
    joined = ", ".join(subjects)
    if joined:
        return (
            f"函数 `{candidate.function}` 中变量/表达式 `{joined}` "
            f"是否存在{problem}问题，请审计确认。"
        )
    return f"函数 `{candidate.function}` 是否存在{problem}问题，请审计确认。"


def _fallback_validation_report(vuln: Vulnerability) -> str:
    return "\n".join([
        f"# 漏洞报告 - {vuln.vuln_type} @ {vuln.file}:{vuln.line}",
        "",
        f"- 文件: {vuln.file}",
        f"- 行号: {vuln.line}",
        f"- 函数: {vuln.function}",
        f"- 类型: {vuln.vuln_type}",
        f"- 严重级别: {vuln.severity}",
        "",
        "## 描述",
        "",
        vuln.description or "",
        "",
        "## AI 分析",
        "",
        vuln.ai_analysis or "",
        "",
    ])


def _dedup_candidates(
    candidates: list[Candidate],
    family_of: dict[str, str],
    checker_names: list[str],
) -> tuple[list[Candidate], int]:
    """Deduplicate same-family candidates in the same function."""
    if len(candidates) <= 1:
        return list(candidates), 0

    ordered = _order_candidates_for_audit(candidates, checker_names, family_of=family_of)
    groups: dict[tuple[str, str, str], list[Candidate]] = {}
    group_order: list[tuple[str, str, str]] = []
    for candidate in ordered:
        family = family_of.get(candidate.vuln_type, candidate.vuln_type)
        key = (family, candidate.file, candidate.function)
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(candidate)

    deduped: list[Candidate] = []
    removed = 0
    for key in group_order:
        group = groups[key]
        representative = group[0]
        if len(group) == 1:
            deduped.append(representative)
            continue

        removed += len(group) - 1
        subjects: list[str] = []
        seen_subjects: set[str] = set()
        merged_from: list[dict[str, object]] = []
        for candidate in group:
            subject = _candidate_subject(candidate)
            if subject and subject not in seen_subjects:
                seen_subjects.add(subject)
                subjects.append(subject)
            merged_from.append({
                "vuln_type": candidate.vuln_type,
                "subject": subject,
                "file": candidate.file,
                "line": candidate.line,
            })

        metadata = dict(representative.metadata or {})
        metadata["merged_from"] = merged_from
        if subjects:
            metadata["subject"] = ", ".join(subjects)
        deduped.append(
            representative.model_copy(update={
                "description": _minimal_candidate_description(representative, subjects),
                "metadata": metadata,
            })
        )

    return deduped, removed


def _pattern_scope(candidate: Candidate, scope: str) -> str:
    normalized = candidate.file.replace("\\", "/")
    if scope == "repo":
        return ""
    if scope == "file":
        return normalized
    return os.path.dirname(normalized) or "."


def _candidate_pattern_key(
    candidate: Candidate,
    scope: str,
) -> tuple[tuple[object, ...], bool]:
    subject = _candidate_subject(candidate)
    if not subject:
        return ("unique", candidate.file, candidate.line, candidate.function, candidate.vuln_type), False
    return (candidate.vuln_type, subject, _pattern_scope(candidate, scope)), True


def _round_robin_by_pattern(
    candidates: list[Candidate],
    scope: str,
) -> list[Candidate]:
    if len(candidates) <= 1:
        return list(candidates)
    buckets: dict[tuple[object, ...], list[Candidate]] = {}
    order: list[tuple[object, ...]] = []
    for candidate in candidates:
        key, _ = _candidate_pattern_key(candidate, scope)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(candidate)

    result: list[Candidate] = []
    while buckets:
        for key in list(order):
            bucket = buckets.get(key)
            if not bucket:
                continue
            result.append(bucket.pop(0))
            if not bucket:
                buckets.pop(key, None)
                order.remove(key)
    return result


def _path_matches_indexed_file(indexed_path: str, candidate_file: str) -> bool:
    indexed = indexed_path.replace("\\", "/")
    candidate = candidate_file.replace("\\", "/")
    return indexed == candidate or indexed.endswith(f"/{candidate}") or candidate.endswith(f"/{indexed}")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_scan_paths(project_path: Path, code_scan_path: Path | None) -> tuple[Path, Path]:
    project_root = project_path.expanduser().resolve()
    if not project_root.is_dir():
        raise ValueError(f"项目总路径不存在或不是目录: {project_root}")

    if code_scan_path is None:
        scan_root = project_root
    else:
        raw_scan_root = code_scan_path.expanduser()
        if not str(raw_scan_root):
            scan_root = project_root
        elif raw_scan_root.is_absolute():
            scan_root = raw_scan_root.resolve()
        else:
            scan_root = (project_root / raw_scan_root).resolve()

    if not scan_root.is_dir():
        raise ValueError(f"代码扫描路径不存在或不是目录: {scan_root}")
    if not _is_relative_to(scan_root, project_root):
        raise ValueError(f"代码扫描路径必须位于项目总路径内: {scan_root} 不在 {project_root} 内")
    return project_root, scan_root


def _load_existing_threat_analysis_for_scope(
    project_root: Path,
    scan_root: Path,
) -> tuple[ThreatAnalysis | None, str]:
    """Load the default attack-tree artifact only when it belongs to this scan scope."""
    from backend.threat_analysis.attack_tree import AttackTreeThreatAnalysis

    cached = AttackTreeThreatAnalysis().load_cached(project_root, scan_root)
    return cached.analysis, cached.message


async def _run_threat_analysis_phase(
    *,
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path,
    reporter: Reporter,
    scan_id: str,
    product: str,
    workspace: Path,
    cancel_event: threading.Event,
    emit: Callable[[str, str], object],
    is_resume: bool = False,
    planned_task_id: str = "",
    retry_threat_audit_task_ids: list[str] | None = None,
) -> None:
    """Run configured threat analysis without owning the scan terminal state."""
    if cancel_event.is_set():
        return
    try:
        from backend.threat_analysis import (
            ThreatAnalysisRunContext,
            build_analysis_from_attack_paths,
            build_threat_analysis_scan_scope,
            get_threat_analysis_implementation,
            threat_analysis_enabled,
        )

        if not threat_analysis_enabled(config):
            maybe = emit("threat_analysis", "威胁分析已通过配置关闭，跳过")
            if asyncio.iscoroutine(maybe):
                await maybe
            return

        root_dir = Path(__file__).resolve().parent.parent
        implementation = get_threat_analysis_implementation(config)
        scan_scope = build_threat_analysis_scan_scope(project_path, code_scan_path)
        attack_path_audit_mode = getattr(
            config.threat_analysis,
            "attack_path_audit_mode",
            "after_analysis",
        )
        immediate_attack_path_audit = attack_path_audit_mode == "immediate"
        streamed_threat_analysis_signature: tuple[str, ...] | None = None
        streamed_threat_audit_task_ids: set[str] = set()
        streamed_threat_audit_runs: list[asyncio.Task] = []
        streaming_audit_lock = asyncio.Lock()
        retry_task_id_filter = (
            set(retry_threat_audit_task_ids)
            if retry_threat_audit_task_ids is not None
            else None
        )

        async def _publish_streaming_threat_analysis(paths: list[ThreatAttackPath]) -> None:
            nonlocal streamed_threat_analysis_signature
            if cancel_event.is_set() or not paths:
                return
            signature = tuple(sorted(path.fingerprint or path.path_id for path in paths))
            if signature == streamed_threat_analysis_signature:
                return
            streamed_threat_analysis_signature = signature
            analysis = build_analysis_from_attack_paths(
                paths,
                analysis_id=_streaming_threat_analysis_id(scan_id),
                sources=ThreatAnalysisSources(
                    repositories=[scan_scope.code_scan_relative_path or "."],
                    documents=[],
                ),
                scan_scope=scan_scope,
            )
            await reporter.push_threat_analysis(scan_id, analysis.model_dump())

        async def _schedule_streaming_threat_audits(paths: list[ThreatAttackPath]) -> None:
            if (
                not immediate_attack_path_audit
                or cancel_event.is_set()
                or not paths
            ):
                return
            from deephole_client.threat_auditor import build_threat_audit_tasks, run_threat_audit_tasks

            partial_analysis = ThreatAnalysis(
                schema_version="1.1",
                analysis_id=f"{scan_id}-streaming-threat-paths",
                scan_scope=scan_scope,
                attack_paths=paths,
            )
            tasks = build_threat_audit_tasks(scan_id, partial_analysis)
            task_ids = {task.task_id for task in tasks}
            if retry_task_id_filter is not None:
                task_ids &= retry_task_id_filter
            async with streaming_audit_lock:
                new_task_ids = task_ids - streamed_threat_audit_task_ids
                if not new_task_ids:
                    return
                streamed_threat_audit_task_ids.update(new_task_ids)
                maybe = emit(
                    "threat_audit",
                    f"攻击路径即时审计：新增 {len(new_task_ids)} 个任务",
                )
                if asyncio.iscoroutine(maybe):
                    await maybe
                streamed_threat_audit_runs.append(
                    asyncio.create_task(run_threat_audit_tasks(
                        config=config,
                        analysis=partial_analysis,
                        reporter=reporter,
                        scan_id=scan_id,
                        project_path=project_path,
                        workspace=workspace,
                        cancel_event=cancel_event,
                        emit=emit,
                        only_task_ids=new_task_ids,
                    ))
                )

        async def _handle_streamed_attack_paths(paths: list[ThreatAttackPath]) -> None:
            await _publish_streaming_threat_analysis(paths)
            await _schedule_streaming_threat_audits(paths)

        async def _wait_for_streaming_threat_audits() -> None:
            if not streamed_threat_audit_runs:
                return
            maybe = emit(
                "threat_audit",
                f"等待 {len(streamed_threat_audit_runs)} 个攻击路径即时审计批次完成...",
            )
            if asyncio.iscoroutine(maybe):
                await maybe
            await asyncio.gather(*streamed_threat_audit_runs)

        analysis = None
        reused_scan_analysis = False
        if is_resume:
            from backend.threat_analysis import threat_analysis_scope_matches

            existing_analysis = await reporter.get_threat_analysis(scan_id)
            if existing_analysis is not None:
                if _is_streaming_threat_analysis(existing_analysis):
                    maybe = emit(
                        "threat_analysis",
                        "发现上次中断的实时威胁分析快照，重新分析以生成最终结果...",
                    )
                    if asyncio.iscoroutine(maybe):
                        await maybe
                elif threat_analysis_scope_matches(existing_analysis, project_path, code_scan_path):
                    maybe = emit(
                        "threat_analysis",
                        "复用本次任务已完成的威胁分析结果，跳过重新分析",
                    )
                    if asyncio.iscoroutine(maybe):
                        await maybe
                    analysis = existing_analysis
                    reused_scan_analysis = True
                else:
                    maybe = emit(
                        "threat_analysis",
                        "本次任务已有威胁分析结果，但扫描范围与当前续扫路径不一致，重新分析...",
                    )
                    if asyncio.iscoroutine(maybe):
                        await maybe

        if analysis is None:
            cached = implementation.load_cached(project_path, code_scan_path)
            analysis, cache_message = cached.analysis, cached.message
            if cache_message:
                maybe = emit("threat_analysis", cache_message)
                if asyncio.iscoroutine(maybe):
                    await maybe
        if analysis is None:
            maybe = emit("threat_analysis", f"开始{implementation.label}...")
            if asyncio.iscoroutine(maybe):
                await maybe
            from deephole_client.opencode_workflows import execute_threat_analysis_context
            analysis = await implementation.run(
                ThreatAnalysisRunContext(
                    scan_id=scan_id,
                    repo_root=root_dir,
                    project_path=project_path,
                    code_scan_path=code_scan_path,
                    workspace=workspace,
                    product=product,
                    timeout=config.opencode.timeout,
                    planned_task_id=planned_task_id,
                    on_output=lambda line: print(
                        with_local_timestamp(line, prefix="[threat]"),
                        flush=True,
                    ),
                    on_attack_paths=_handle_streamed_attack_paths,
                    cancel_event=cancel_event,
                    execute=execute_threat_analysis_context,
                )
            )
        if analysis is not None:
            if not reused_scan_analysis:
                await reporter.push_threat_analysis(scan_id, analysis.model_dump())
                maybe = emit(
                    "threat_analysis",
                    f"威胁分析完成：识别 {len(analysis.assets)} 个关键资产，{len(analysis.attack_trees)} 棵攻击树",
                )
                if asyncio.iscoroutine(maybe):
                    await maybe
            await _wait_for_streaming_threat_audits()
            if not cancel_event.is_set():
                from deephole_client.threat_auditor import run_threat_audit_tasks

                await run_threat_audit_tasks(
                    config=config,
                    analysis=analysis,
                    reporter=reporter,
                    scan_id=scan_id,
                    project_path=project_path,
                    workspace=workspace,
                    cancel_event=cancel_event,
                    emit=emit,
                    only_task_ids=(
                        set(retry_threat_audit_task_ids)
                        if retry_threat_audit_task_ids is not None
                        else None
                    ),
                    exclude_task_ids=streamed_threat_audit_task_ids if immediate_attack_path_audit else None,
                )
        elif cancel_event.is_set():
            await _wait_for_streaming_threat_audits()
            maybe = emit("threat_analysis", "威胁分析已停止")
            if asyncio.iscoroutine(maybe):
                await maybe
        else:
            await _wait_for_streaming_threat_audits()
            maybe = emit("threat_analysis", "威胁分析未生成有效 res.json，已跳过结果展示")
            if asyncio.iscoroutine(maybe):
                await maybe
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        maybe = emit("threat_analysis", f"威胁分析异常（已跳过）: {exc}")
        if asyncio.iscoroutine(maybe):
            await maybe
    finally:
        if planned_task_id:
            from task_agent.model_pool import clear_planned_task
            await clear_planned_task(planned_task_id)


async def _wait_for_threat_analysis_task(
    task: asyncio.Task | None,
    *,
    cancel_event: threading.Event | None = None,
    emit: Callable[[str, str], object] | None = None,
    cancel_first: bool = False,
) -> None:
    """Wait for a background threat-analysis task before cleanup or terminal state."""
    if task is None:
        return
    if cancel_first and not task.done() and cancel_event is not None:
        cancel_event.set()
    if not task.done() and emit is not None:
        maybe = emit("threat_analysis", "等待威胁分析后台任务收尾...")
        if asyncio.iscoroutine(maybe):
            await maybe
    try:
        await task
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        if emit is not None:
            maybe = emit("threat_analysis", f"威胁分析后台任务异常（已跳过）: {exc}")
            if asyncio.iscoroutine(maybe):
                await maybe


async def _run_decoupled_threat_analysis_phase(
    *,
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path,
    reporter: Reporter,
    scan_id: str,
    product: str,
    workspace: Path,
    cancel_event: threading.Event,
    emit: Callable[[str, str], object],
    is_resume: bool = False,
    planned_task_id: str = "",
    retry_threat_audit_task_ids: list[str] | None = None,
) -> None:
    """Coordinate the two backend-free threat processes and report their results."""
    del workspace, is_resume
    if cancel_event.is_set():
        return
    try:
        from task_agent.task_service import get_opencode_execution_context
        from deephole_client.threat_analysis import run_threat_analysis
        from deephole_client.threat_audit import run_threat_audit

        execution = get_opencode_execution_context()
        work_dir = execution.work_dir or (Path.home() / ".opendeephole" / "scans" / scan_id)
        policy = getattr(config.threat_analysis, "model_policy", None)
        required_capability = str(getattr(policy, "required_capability", "high") or "high")
        required_capability = "high" if required_capability in {"medium", "high"} else "low"

        async def process_output(event: dict[str, Any]) -> None:
            message = str(event.get("message") or "")
            if message:
                maybe = emit(str(event.get("process") or "threat_analysis"), message)
                if asyncio.iscoroutine(maybe):
                    await maybe

        analysis_result = await run_threat_analysis(
            project_path=project_path,
            code_scan_path=code_scan_path,
            work_dir=work_dir / "threat_analysis",
            scan_id=scan_id,
            product=product,
            reuse_cache=True,
            required_capability=required_capability,
            output=process_output,
            cancel_event=cancel_event,
        )
        analysis = analysis_result.get("analysis")
        if analysis_result.get("status") != "success" or not isinstance(analysis, dict):
            maybe = emit(
                "threat_analysis",
                f"威胁分析未生成有效结果：{analysis_result.get('error') or analysis_result.get('status')}",
            )
            if asyncio.iscoroutine(maybe):
                await maybe
            return
        await reporter.push_threat_analysis(scan_id, analysis)

        audit_result = await run_threat_audit(
            project_path=project_path,
            work_dir=work_dir / "threat_audit",
            scan_id=scan_id,
            threat_analysis=analysis,
            concurrency=max(1, int(getattr(config, "opencode_concurrency", 1) or 1)),
            required_capability=required_capability,
            include_task_ids=retry_threat_audit_task_ids,
            output=process_output,
            cancel_event=cancel_event,
        )
        for raw_task in audit_result.get("tasks") or []:
            if not isinstance(raw_task, dict):
                continue
            task_payload = {
                key: value for key, value in raw_task.items()
                if key in ThreatAuditTask.model_fields
            }
            task_payload["updated_at"] = str(
                raw_task.get("finished_at") or raw_task.get("started_at") or ""
            )
            await reporter.push_threat_audit_task(scan_id, ThreatAuditTask(**task_payload))
        for raw_vulnerability in audit_result.get("vulnerabilities") or []:
            if isinstance(raw_vulnerability, dict):
                await reporter.report_vulnerability(scan_id, Vulnerability(**raw_vulnerability))
    finally:
        if planned_task_id:
            from task_agent.model_pool import clear_planned_task
            await clear_planned_task(planned_task_id)


def _candidate_path_candidates(candidate_file: str, project_root: Path, scan_root: Path) -> list[Path]:
    normalized = candidate_file.replace("\\", "/")
    raw = Path(normalized)
    if raw.is_absolute():
        return [raw]

    candidates = [scan_root / raw, project_root / raw]
    parts = raw.parts
    if parts and parts[0] == project_root.name:
        candidates.append(project_root.joinpath(*parts[1:]))
    if parts and parts[0] == scan_root.name:
        candidates.append(scan_root.joinpath(*parts[1:]))
    return candidates


def _resolve_candidate_path(candidate_file: str, project_root: Path, scan_root: Path) -> Path | None:
    candidates = _candidate_path_candidates(candidate_file, project_root, scan_root)
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.exists() and _is_relative_to(resolved, project_root):
            return resolved
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if _is_relative_to(resolved, project_root):
            return resolved
    return None


def _project_relative_file(path: Path, project_root: Path) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return path.as_posix()


def _normalize_candidate_for_project(
    candidate: Candidate,
    project_root: Path,
    scan_root: Path,
) -> Candidate:
    resolved = _resolve_candidate_path(candidate.file, project_root, scan_root)
    if resolved is None:
        return candidate.model_copy(update={"file": candidate.file.replace("\\", "/")})
    return candidate.model_copy(update={"file": _project_relative_file(resolved, project_root)})


def _candidate_in_scan_scope(candidate: Candidate, project_root: Path, scan_root: Path) -> bool:
    resolved = _resolve_candidate_path(candidate.file, project_root, scan_root)
    if resolved is not None:
        try:
            if source_path_has_ignored_dir(resolved.relative_to(project_root)):
                return False
        except ValueError:
            pass
    elif source_path_has_ignored_dir(candidate.file):
        return False

    if scan_root == project_root:
        return True
    if resolved is None:
        return candidate.file.replace("\\", "/").startswith(
            scan_root.relative_to(project_root).as_posix().rstrip("/") + "/"
        )
    return _is_relative_to(resolved, scan_root)


def _select_function_row(rows, candidate: Candidate):
    for row in rows:
        if (
            _path_matches_indexed_file(row["file_path"], candidate.file)
            and row["start_line"] <= candidate.line <= row["end_line"]
        ):
            return row
    for row in rows:
        if row["start_line"] <= candidate.line <= row["end_line"]:
            return row
    for row in rows:
        if _path_matches_indexed_file(row["file_path"], candidate.file):
            return row
    return rows[0] if rows else None


def _build_function_source_cache(
    project_path: Path,
    candidates: list[Candidate],
    db=None,
) -> dict[tuple[str, int, str, str], FunctionSourceSnapshot]:
    """Snapshot function bodies for feedback before the source tree changes."""
    source_db = db
    owned_db = None
    if source_db is None:
        db_path = project_path / "code_index.db"
        if not db_path.exists():
            return {}
        try:
            from code_parser import CodeDatabase
            owned_db = CodeDatabase(db_path)
            source_db = owned_db
        except Exception:
            return {}

    cache: dict[tuple[str, int, str, str], FunctionSourceSnapshot] = {}
    try:
        rows_by_function: dict[str, list] = {}
        for candidate in candidates:
            rows = rows_by_function.get(candidate.function)
            if rows is None:
                rows = source_db.get_functions_by_name(candidate.function)
                rows_by_function[candidate.function] = rows
            row = _select_function_row(rows, candidate)
            if row is None:
                row = source_db.get_function_by_location(candidate.file, candidate.line)
            if row is None:
                continue
            cache[(candidate.file, candidate.line, candidate.function, candidate.vuln_type)] = (
                row["body"] or "",
                row["start_line"],
            )
    finally:
        if owned_db is not None:
            owned_db.close()
    return cache


def _attach_function_source(
    vuln: Vulnerability,
    candidate: Candidate,
    source_cache: dict[tuple[str, int, str, str], FunctionSourceSnapshot],
) -> Vulnerability:
    source, start_line = source_cache.get(
        (candidate.file, candidate.line, candidate.function, candidate.vuln_type),
        ("", None),
    )
    vuln.function_source = source
    vuln.function_start_line = start_line
    return vuln


def _remove_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass


def _replace_sqlite_db(temp_path: Path, final_path: Path) -> None:
    """Atomically publish a fully checkpointed SQLite DB."""
    for suffix in ("-wal", "-shm"):
        try:
            final_path.with_name(final_path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass
    os.replace(temp_path, final_path)
    _remove_sqlite_files(temp_path)


def _backend_runtime_sections(config: AgentConfig, scan_dir: Path | None = None) -> dict:
    opencode_config = dataclasses.asdict(config.opencode)
    opencode_config["mock"] = False
    raw = {
        "opencode": opencode_config,
        "opencode_concurrency": config.opencode_concurrency,
        "memory_api_discovery": {
            "enabled": config.memory_api_discovery.enabled,
            "batch_size": config.memory_api_discovery.batch_size,
            "timeout_seconds": config.memory_api_discovery.timeout_seconds,
            "max_candidates": config.memory_api_discovery.max_candidates,
        },
        "git_history": {
            "enabled": config.git_history.enabled,
            "max_commits": config.git_history.max_commits,
            "since": config.git_history.since,
            "paths": config.git_history.paths,
            "variant_hunt": config.git_history.variant_hunt,
        },
        "threat_analysis": {
            "enabled": config.threat_analysis.enabled,
            "implementation": config.threat_analysis.implementation,
            "attack_path_audit_mode": config.threat_analysis.attack_path_audit_mode,
            "product_mcp_name": config.threat_analysis.product_mcp_name,
            "product_mcp_detection_timeout_seconds": (
                config.threat_analysis.product_mcp_detection_timeout_seconds
            ),
        },
        "threat_analysis_policy": dataclasses.asdict(config.threat_analysis.model_policy),
        "vulnerability_mining": dataclasses.asdict(config.vulnerability_mining),
        "false_positive": dataclasses.asdict(config.false_positive),
        "code_graph": dataclasses.asdict(config.code_graph),
        "product_info": dataclasses.asdict(config.product_info),
        "static_dedup": config.static_dedup,
        "pattern_filter": {
            "enabled": config.pattern_filter.enabled,
            "scope": config.pattern_filter.scope,
        },
        "mcp_server": {
            "port": 8100,  # placeholder; overridden by local_mcp if opencode mode
        },
        "no_proxy": config.no_proxy,
        "vulnerability_validation": {
            "enabled": config.vulnerability_validation.enabled,
            "environments": {
                name: dataclasses.asdict(value)
                for name, value in config.vulnerability_validation.environments.items()
            },
        },
    }
    if scan_dir is not None:
        # Keep result JSON files isolated inside this scan's directory so the
        # MCP submit path and opencode result read path cannot cross scans.
        raw["storage"] = {
            "projects_dir": str(scan_dir.parent),
            "scans_dir": str(scan_dir),
        }
        raw["logging"] = {
            "level": "INFO",
            "file": str(scan_dir / "deephole_client.log"),
        }
    if config.fp_review_cli is not None:
        fp_review_cli_config = dataclasses.asdict(config.fp_review_cli)
        fp_review_cli_config["mock"] = False
        raw["fp_review_cli"] = fp_review_cli_config
    return raw


def refresh_backend_runtime_config(config: AgentConfig) -> None:
    """Apply live AI/model config changes without changing scan storage paths."""
    apply_network_env(config)
    import backend.config as _cfg

    current = _cfg._config
    if current is None:
        return
    raw = _backend_runtime_sections(config)
    current.opencode = _cfg.OpenCodeConfig(**raw["opencode"])
    current.opencode_concurrency = int(raw["opencode_concurrency"])
    current.memory_api_discovery = _cfg.MemoryApiDiscoveryConfig(**raw["memory_api_discovery"])
    current.git_history = _cfg.GitHistoryConfig(**raw["git_history"])
    current.threat_analysis = _cfg.ThreatAnalysisConfig(**raw["threat_analysis"])
    current.threat_analysis_policy = _cfg.ModelTaskPolicyConfig(**raw["threat_analysis_policy"])
    current.vulnerability_mining = _cfg.ModelTaskPolicyConfig(**raw["vulnerability_mining"])
    current.false_positive = _cfg.ModelTaskPolicyConfig(**raw["false_positive"])
    current.code_graph = _cfg.McpConfig(**raw["code_graph"])
    current.product_info = _cfg.McpConfig(**raw["product_info"])
    current.vulnerability_validation = _cfg.VulnerabilityValidationConfig(
        **raw["vulnerability_validation"]
    )
    current.static_dedup = bool(raw["static_dedup"])
    current.pattern_filter = _cfg.PatternFilterConfig(**raw["pattern_filter"])
    current.no_proxy = str(raw.get("no_proxy") or "")
    current.fp_review_cli = (
        _cfg.OpenCodeConfig(**raw["fp_review_cli"])
        if isinstance(raw.get("fp_review_cli"), dict)
        else None
    )


def _configure_backend(config: AgentConfig, scan_dir: Path) -> None:
    """Write a temporary backend config and reset singletons so all backend
    modules use the Agent's OpenCode, storage and network settings."""
    raw = _backend_runtime_sections(config, scan_dir)
    config_path = scan_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)
    apply_network_env(config)

    # Reset config singleton so it reloads from the new file
    import backend.config as _cfg
    _cfg._config = None

    # Reset registry singleton so it re-discovers checkers
    import backend.registry as _reg
    _reg._registry = None
    _reg._registry_dirs = None

    # Register host callbacks only; the OpenCode manager and Serve process stay
    # lazy until the first run_opencode_task() call.
    from deephole_client.opencode_integration import configure_opencode_component
    configure_opencode_component()


async def run_scan(
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path | None,
    reporter: Reporter,
    scan_name: str,
    product: str,
    validation_environment: str,
    checker_names: list[str],
    scan_id: str,                    # pre-assigned by server
    cancel_event: threading.Event,   # from task_manager
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
    """Orchestrate the full local pipeline: index → static analysis → AI audit → report.

    scan_id is pre-assigned by the server. If is_resume=True, skips already-processed
    candidates fetched via reporter.get_processed_keys().
    """
    # Use a persistent scan dir (not tempfile) so resume works
    scan_dir = Path.home() / ".opendeephole" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    from task_agent.task_service import (
        clear_scan_feedback_entries,
        reset_opencode_execution_context,
        set_opencode_execution_context,
        set_scan_feedback_entries,
    )
    set_scan_feedback_entries(scan_id, feedback_entries or [])
    execution_context_token = set_opencode_execution_context(
        scan_id=scan_id,
        project_dir=project_path,
        work_dir=scan_dir,
        feedback_entries=feedback_entries or [],
        cancel_event=cancel_event,
    )

    mcp_server = None
    workspace: Optional[Path] = None
    previous_checkers_dir = os.environ.get(CHECKERS_DIR_ENV)
    pool_status_stop = asyncio.Event()
    pool_status_task: asyncio.Task | None = None
    threat_analysis_task: asyncio.Task | None = None

    async def finish_scan_after_pool_drain(
        status: str,
        total_candidates: int,
        processed_candidates: int,
        *,
        vulnerabilities: list[Vulnerability] | None = None,
        error_message: str | None = None,
    ) -> None:
        await _drain_opencode_pool_before_finish(
            scan_id,
            pool_status_stop,
            pool_status_task,
        )
        await reporter.finish_scan(
            scan_id,
            vulnerabilities or [],
            status,
            total_candidates,
            processed_candidates,
            error_message=error_message,
        )
        await _clear_finished_opencode_pool_history(scan_id)

    try:
        normalized_scan_mode = str(scan_mode or SCAN_MODE_FULL).strip().lower()
        if normalized_scan_mode in {"threat_only", "threat-analysis-only"}:
            normalized_scan_mode = SCAN_MODE_THREAT_ANALYSIS_ONLY
        if normalized_scan_mode not in {SCAN_MODE_FULL, SCAN_MODE_THREAT_ANALYSIS_ONLY}:
            raise ValueError(f"Unknown scan mode: {scan_mode}")
        threat_analysis_only = normalized_scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY

        project_path, code_scan_path = _resolve_scan_paths(project_path, code_scan_path)

        if checker_packages:
            synced_checkers_dir = scan_dir / "checkers"
            unpacked = unpack_checker_packages(checker_packages, synced_checkers_dir)
            os.environ[CHECKERS_DIR_ENV] = str(synced_checkers_dir)
            print(f"[init] Synced {len(unpacked)} checker(s): {unpacked}")

        # Setup backend config before any backend imports
        _configure_backend(config, scan_dir)
        pool_status_task = asyncio.create_task(
            reporter.publish_opencode_pool_until(scan_id, pool_status_stop)
        )

        async def emit(phase: str, message: str, candidate_index: Optional[int] = None) -> None:
            event = ScanEvent.create(phase, message, candidate_index)
            await reporter.send_event(scan_id, event)
            print(f"[{phase}] {message}")

        await emit("init", f"Scan started: {scan_name}")
        await emit("init", f"Project: {project_path}")
        await emit("init", f"Code scan path: {code_scan_path}")
        if product:
            await emit("init", f"Product: {product}")
        if validation_environment:
            await emit("init", f"Validation environment: {validation_environment}")
        await emit("init", f"Scan mode: {normalized_scan_mode}" + (" (resume)" if is_resume else ""))

        registry = {}
        family_of: dict[str, str] = {}
        audit_checker_order: list[str] = []
        if threat_analysis_only:
            await emit("init", "仅威胁分析模式：跳过检查项加载、静态分析和候选点 AI 审计")
        else:
            await emit("init", f"Checkers: {checker_names or 'all'}" + (" (resume)" if is_resume else ""))

            # Load checker registry (discovers from bundled checkers/ dir)
            from backend.registry import get_registry
            registry = get_registry(refresh=True)

            if checker_names:
                registry = {k: v for k, v in registry.items() if k in checker_names}
                unknown = set(checker_names) - set(registry.keys())
                if unknown:
                    raise ValueError(f"Unknown checkers: {unknown}")

            if not registry:
                raise ValueError("No checkers available or none matched the requested names")

            family_of = {
                name: (getattr(entry, "family", "") or name)
                for name, entry in registry.items()
            }
            audit_checker_order = checker_names or list(registry.keys())
            await emit("init", f"Loaded {len(registry)} checker(s): {list(registry.keys())}")

        candidates_cache_path = scan_dir / "candidates.json"

        # --- Phase 1: Index source code ---
        # code_index.db is stored directly in the project directory
        from deephole_client.index_store import IndexStore
        index_store = IndexStore()
        db = None
        db_path = index_store.db_path(project_path)
        # Only need the DB open if static analysis will run (no cached candidates yet)
        candidate_retry_mode = retry_candidates is not None
        need_db_open = not candidates_cache_path.exists() and not candidate_retry_mode

        def _db_is_complete(path: Path) -> bool:
            """Return True only if the DB was fully built."""
            from code_parser import CodeDatabase
            _d = None
            try:
                _d = CodeDatabase(path)
                return _d.is_index_complete()
            except Exception:
                return False
            finally:
                if _d is not None:
                    try:
                        _d.close()
                    except Exception:
                        pass

        def _index_stats(index_db) -> dict[str, int]:
            return index_db.get_index_stats()

        def _index_stats_message(stats: dict[str, int]) -> str:
            return (
                "代码索引统计: "
                f"文件 {stats['files']} 个，"
                f"函数 {stats['functions']} 个，"
                f"结构体/类/联合体 {stats['structs']} 个，"
                f"全局变量 {stats['global_variables']} 个，"
                f"函数调用关系 {stats['function_calls']} 条，"
                f"全局变量引用 {stats['global_variable_references']} 条"
            )

        async def _send_index_done(stats: dict[str, int]) -> None:
            files = int(stats.get("files") or 0)
            await reporter.send_index_status(scan_id, "done", files, files, stats=stats)

        do_index = True  # set False when a valid existing DB is found

        if db_path.exists():
            # DB already in project dir — validate it completed before trusting it
            if _db_is_complete(db_path):
                await emit("init", "跳过代码索引（使用已有 code_index.db）")
                if need_db_open:
                    from code_parser import CodeDatabase
                    db = CodeDatabase(db_path)
                    stats = _index_stats(db)
                    await emit("init", _index_stats_message(stats))
                    await _send_index_done(stats)
                else:
                    from code_parser import CodeDatabase
                    stats_db = CodeDatabase(db_path)
                    try:
                        stats = _index_stats(stats_db)
                        await emit("init", _index_stats_message(stats))
                        await _send_index_done(stats)
                    finally:
                        stats_db.close()
                do_index = False
            else:
                await emit("init", "已有代码索引不完整（需重建），重新索引...")

        if do_index:
            await emit("init", "Indexing source code (ctags/tree-sitter)...")
            await reporter.send_index_status(scan_id, "parsing", 0, 0)
            from code_parser import CodeDatabase, CppAnalyzer
            temp_db_path = db_path.with_name(f"{db_path.name}.{scan_id}.tmp")
            _remove_sqlite_files(temp_db_path)
            index_db = CodeDatabase(temp_db_path)
            db = index_db
            analyzer = CppAnalyzer(db)
            loop = asyncio.get_running_loop()
            latest_index_file_progress = {"parsed": 0, "total": 0}

            def _on_index_progress(parsed: int, total: int) -> None:
                latest_index_file_progress["parsed"] = parsed
                latest_index_file_progress["total"] = total
                pct = round(parsed / total * 100) if total else 0
                print(f"\r  [index] {parsed}/{total} files ({pct}%)", end="", flush=True)
                asyncio.run_coroutine_threadsafe(
                    reporter.send_index_status(scan_id, "parsing", parsed, total),
                    loop,
                )

            def _on_index_stage_progress(stage: str, current: int, total: int) -> None:
                pct = round(current / total * 100) if total else 0
                print(f"\r  [index] {stage}: {current}/{total} ({pct}%)", end="", flush=True)
                asyncio.run_coroutine_threadsafe(
                    reporter.send_index_status(
                        scan_id,
                        "parsing",
                        latest_index_file_progress["parsed"],
                        latest_index_file_progress["total"],
                        stage=stage,
                        stage_current=current,
                        stage_total=total,
                    ),
                    loop,
                )

            def _do_index() -> None:
                analyzer.analyze_directory(
                    project_path,
                    on_progress=_on_index_progress,
                    cancel_check=cancel_event.is_set,
                    on_stage_progress=_on_index_stage_progress,
                )
                print()  # newline after progress

            try:
                await loop.run_in_executor(None, _do_index)
            except Exception:
                index_db.close()
                _remove_sqlite_files(temp_db_path)
                db = None
                raise
            if cancel_event.is_set():
                index_db.close()
                _remove_sqlite_files(temp_db_path)
                db = None
                await emit("init", "Code indexing stopped by user")
                await finish_scan_after_pool_drain("cancelled", 0, 0)
                return
            # Flush WAL so the DB file is self-contained
            index_db.mark_index_complete()
            index_db.checkpoint()
            index_db.close()
            _replace_sqlite_db(temp_db_path, db_path)
            db = CodeDatabase(db_path)
            stats = _index_stats(db)
            await emit("init", "Code indexing complete")
            await emit("init", _index_stats_message(stats))
            await emit("init", f"代码索引已保存（路径: {db_path}）")
            await _send_index_done(stats)

        # --- Phase 2: Use selected feedback for SKILL enrichment ---
        selected_feedback = [
            FeedbackEntry(**entry)
            for entry in (feedback_entries or [])
        ]
        if selected_feedback:
            await emit("init", f"Loaded {len(selected_feedback)} selected feedback entries")

        from deephole_client.codegraph import prepare_codegraph
        await prepare_codegraph(
            config,
            project_path,
            emit=lambda message: emit("mcp_ready", message),
        )

        # --- Phase 3: Register this scan on the Agent-wide MCP gateway ---
        mcp_port = None
        needs_opencode = (
            not candidate_retry_mode
            or resume_threat_analysis
            or any(entry.mode in {"opencode", "api"} for entry in registry.values())
        )
        if needs_opencode:
            from deephole_client.local_mcp import LocalMCPServer
            from deephole_client import mcp_registry
            mcp_server = LocalMCPServer(project_dir=project_path, project_id=scan_id)
            mcp_port = await asyncio.to_thread(mcp_server.start)
            mcp_registry.register(project_path, mcp_port, scan_id)
            await emit("mcp_ready", f"Local MCP server ready on port {mcp_port}")

        # --- Phase 4: Refresh the single Agent-wide OpenCode workspace ---
        from deephole_client.opencode_integration import get_global_opencode_workspace
        workspace = await asyncio.to_thread(
            get_global_opencode_workspace,
            mcp_port=mcp_port,
        )
        await emit("init", "Global OpenCode workspace ready")

        # --- Phase 5: Configured threat analysis (fresh scans only, background) ---
        from backend.threat_analysis import threat_analysis_enabled
        if (
            (not candidate_retry_mode or resume_threat_analysis)
            and workspace is not None
            and not cancel_event.is_set()
            and threat_analysis_enabled(config)
        ):
            threat_analysis_task = asyncio.create_task(_run_decoupled_threat_analysis_phase(
                config=config,
                project_path=project_path,
                code_scan_path=code_scan_path,
                reporter=reporter,
                scan_id=scan_id,
                product=product,
                workspace=workspace,
                cancel_event=cancel_event,
                emit=lambda phase, message: emit(phase, message),
                is_resume=is_resume,
                planned_task_id="",
                retry_threat_audit_task_ids=retry_threat_audit_task_ids,
            ))

        if threat_analysis_only:
            await emit(
                "static_analysis",
                "仅威胁分析模式：跳过静态分析和候选点 AI 审计",
                candidate_index=0,
            )
            await reporter.send_static_progress(scan_id, 0, 0, done=True)
            if threat_analysis_task is None:
                await emit("threat_analysis", "威胁分析未启动：配置关闭或任务已取消")
            await _wait_for_threat_analysis_task(
                threat_analysis_task,
                cancel_event=cancel_event,
                emit=emit,
            )
            if db is not None:
                db.close()
                db = None
            if cancel_event.is_set():
                await emit("complete", "仅威胁分析任务已取消")
                await finish_scan_after_pool_drain("cancelled", 0, 0)
                return
            await emit("complete", "仅威胁分析任务完成")
            await finish_scan_after_pool_drain("complete", 0, 0)
            shutil.rmtree(scan_dir, ignore_errors=True)
            return

        # --- Phase 6: Memory allocation/free API preprocessing ---
        # Hard-disabled in the scan pipeline. The standalone module/config remain
        # available for compatibility, but this stage is no longer a precondition
        # for static analysis.

        # --- Phase 7: Static analysis (or load from cache) ---
        # Skip static analysis only when a candidates cache file already exists
        # (written by a previous run of this scan_id).  DB existence alone does
        # NOT skip this phase.
        candidates: list[Candidate] = []
        ran_fresh_static = False
        if candidate_retry_mode:
            candidates = [
                _normalize_candidate_for_project(Candidate(**d), project_path, code_scan_path)
                for d in (retry_candidates or [])
            ]
            candidates = [
                c for c in candidates
                if _candidate_in_scan_scope(c, project_path, code_scan_path)
            ]
            total = retry_total_candidates or len(candidates)
            await reporter.send_static_progress(scan_id, 0, 0, done=True)
            await emit(
                "static_analysis",
                f"续扫 {len(candidates)} 个未完成候选点",
                candidate_index=total,
            )
        elif candidates_cache_path.exists():
            await emit("static_analysis", "从缓存加载静态分析结果...")
            cached = json.loads(candidates_cache_path.read_text(encoding="utf-8"))
            candidates = [
                _normalize_candidate_for_project(Candidate(**d), project_path, code_scan_path)
                for d in cached
            ]
            candidates = [
                c for c in candidates
                if _candidate_in_scan_scope(c, project_path, code_scan_path)
            ]
            total = len(candidates)
            await emit("static_analysis", f"已加载 {total} 个缓存候选点", candidate_index=total)
        else:
            ran_fresh_static = True
            await emit("static_analysis", "Running static analyzers...")

            loop = asyncio.get_running_loop()
            pending_static_progress = []
            static_progress_gates: dict[str, _StaticProgressGate] = {}
            latest_static_progress: dict[str, tuple[int, int]] = {}

            async def _drain_static_progress(timeout: float = 5.0) -> None:
                pending = [asyncio.wrap_future(future) for future in pending_static_progress if not future.done()]
                if not pending:
                    return
                _done, still_pending = await asyncio.wait(pending, timeout=timeout)
                if still_pending:
                    print(
                        f"Warning: {len(still_pending)} static analysis progress update(s) still pending",
                        flush=True,
                    )

            def _queue_static_progress(label: str, scanned: int, total: int, *, force: bool = False) -> None:
                latest_static_progress[label] = (scanned, total)
                gate = static_progress_gates.setdefault(label, _StaticProgressGate())
                if not gate.should_send(scanned, total, force=force):
                    return
                future = asyncio.run_coroutine_threadsafe(
                    reporter.send_static_progress(scan_id, scanned, total),
                    loop,
                )
                pending_static_progress.append(future)

            def _run_static_analysis() -> tuple[list[Candidate], bool]:
                """Run all static analyzers in a thread so the event loop stays free."""
                result: list[Candidate] = []
                analyzer_entries = [(n, e) for n, e in registry.items() if e.analyzer]
                project_level_entries = [(n, e) for n, e in registry.items() if e.mode == "opencode" and not e.analyzer]
                for idx, (_name, entry) in enumerate(analyzer_entries, 1):
                    if cancel_event.is_set():
                        return result, True
                    print(f"  [static] [{idx}/{len(analyzer_entries)}] {entry.label}...", flush=True)

                    # Set file-level progress callback
                    def _on_progress(scanned: int, total: int, label: str = entry.label) -> None:
                        print(f"\r  [static] {label}: {scanned}/{total}", end="", flush=True)
                        _queue_static_progress(label, scanned, total)

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = _on_progress

                    count_before = len(result)
                    for raw_cand in entry.analyzer.find_candidates(code_scan_path, db=db):
                        if cancel_event.is_set():
                            return result, True
                        cand = _normalize_candidate_for_project(raw_cand, project_path, code_scan_path)
                        if not _candidate_in_scan_scope(cand, project_path, code_scan_path):
                            continue
                        result.append(cand)

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = None
                    progress = latest_static_progress.get(entry.label)
                    if progress is not None:
                        _queue_static_progress(entry.label, progress[0], progress[1], force=True)

                    count = len(result) - count_before
                    print(f"\n  [static] [{idx}/{len(analyzer_entries)}] {entry.label}: {count} candidate(s)", flush=True)
                for _name, entry in project_level_entries:
                    if cancel_event.is_set():
                        return result, True
                    result.append(build_project_level_candidate(entry, project_path, code_scan_path))
                    print(f"  [static] {entry.label}: generated project-level candidate", flush=True)
                return result, False

            # Static analysis is an independently runnable process.  The scan
            # coordinator only translates its events and JSON result into the
            # platform's existing reporting contract.
            from deephole_client.static_analysis import run_static_analysis

            async def _static_process_output(event: dict[str, Any]) -> None:
                message = str(event.get("message") or "")
                if message:
                    await emit("static_analysis", message)

            checker_dirs = sorted({
                Path(entry.directory).resolve().parent
                for entry in registry.values()
            })
            static_result = await run_static_analysis(
                project_path=project_path,
                code_scan_path=code_scan_path,
                index_db_path=db_path,
                checker_dirs=checker_dirs,
                checker_names=list(registry),
                deduplicate=False,
                output=_static_process_output,
                cancel_event=cancel_event,
            )
            candidates = [Candidate(**item) for item in static_result["candidates"]]
            static_cancelled = static_result.get("status") == "cancelled"

            # Mark static analysis as done on the server
            await reporter.send_static_progress(scan_id, 0, 0, done=True)

            if static_cancelled:
                await emit("static_analysis", "Static analysis stopped by user")
                if db is not None:
                    db.close()
                await _wait_for_threat_analysis_task(
                    threat_analysis_task,
                    cancel_event=cancel_event,
                    emit=emit,
                )
                await finish_scan_after_pool_drain("cancelled", 0, 0)
                return

            total = len(candidates)
            await emit("static_analysis", f"Static analysis done: {total} total candidate(s)", candidate_index=total)

            # Persist candidates so resume can skip re-indexing and re-analysis
            candidates_cache_path.write_text(
                json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                encoding="utf-8",
            )

        # --- Phase 5.5: git history mining + variant hunting (fresh scans only) ---
        # 仅在首次扫描（非续扫、非缓存命中）时运行；续扫/复核从后端读取已上报的模式。
        if _should_run_git_history_phase(
            config,
            ran_fresh_static=ran_fresh_static,
            retry_mode=candidate_retry_mode,
            workspace=workspace,
            cancel_event=cancel_event,
        ):
            try:
                from deephole_client.git_history import mine_history
                from deephole_client.variant_hunter import hunt_variants

                history_patterns = await mine_history(
                    config=config,
                    project_path=project_path,
                    scan_id=scan_id,
                    cancel_event=cancel_event,
                    emit=emit,
                )
                if history_patterns:
                    await reporter.push_git_history(scan_id, history_patterns)

                if (
                    history_patterns
                    and config.git_history.variant_hunt
                    and not cancel_event.is_set()
                ):
                    variant_candidates = await hunt_variants(
                        config=config,
                        patterns=history_patterns,
                        project_path=project_path,
                        code_scan_path=code_scan_path,
                        scan_id=scan_id,
                        checker_types=list(registry.keys()),
                        cancel_event=cancel_event,
                        emit=emit,
                    )
                    existing_keys = {
                        (c.file, c.line, c.function, c.vuln_type) for c in candidates
                    }
                    added = 0
                    for raw_vc in variant_candidates:
                        vc = _normalize_candidate_for_project(raw_vc, project_path, code_scan_path)
                        if not _candidate_in_scan_scope(vc, project_path, code_scan_path):
                            continue
                        key = (vc.file, vc.line, vc.function, vc.vuln_type)
                        if key in existing_keys:
                            continue
                        existing_keys.add(key)
                        candidates.append(vc)
                        added += 1
                    if added:
                        total = len(candidates)
                        candidates_cache_path.write_text(
                            json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                            encoding="utf-8",
                        )
                        await emit(
                            "static_analysis",
                            f"合并 {added} 个同类变体候选后共 {total} 个候选点",
                            candidate_index=total,
                        )
            except asyncio.CancelledError:
                raise
            except NoAvailableModelError:
                raise
            except Exception as exc:
                await emit("git_history", f"历史挖掘/变体排查异常（已跳过）: {exc}")

        if not candidate_retry_mode and getattr(config, "static_dedup", True):
            candidates, removed_count = _dedup_candidates(
                candidates,
                family_of,
                audit_checker_order,
            )
            if removed_count:
                total = len(candidates)
                candidates_cache_path.write_text(
                    json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                    encoding="utf-8",
                )
                await emit(
                    "static_analysis",
                    f"跨规则函数级去重过滤 {removed_count} 个候选后共 {total} 个候选点",
                    candidate_index=total,
                )

        pattern_filter_enabled = bool(getattr(config.pattern_filter, "enabled", True))
        pattern_filter_scope = getattr(config.pattern_filter, "scope", "directory")
        if pattern_filter_scope not in {"directory", "file", "repo"}:
            pattern_filter_scope = "directory"
        reported_candidates = _prepare_audit_queue(
            candidates,
            audit_checker_order,
            family_of=family_of,
            pattern_filter_enabled=pattern_filter_enabled,
            pattern_filter_scope=pattern_filter_scope,
        )
        if not candidate_retry_mode:
            await reporter.report_candidates(scan_id, reported_candidates)

        function_source_cache = await asyncio.to_thread(
            _build_function_source_cache,
            project_path,
            candidates,
            db,
        )

        if db is not None:
            db.close()

        if total == 0:
            await _wait_for_threat_analysis_task(
                threat_analysis_task,
                cancel_event=cancel_event,
                emit=emit,
            )
            await emit("complete", "No static candidates found")
            await finish_scan_after_pool_drain("complete", 0, 0)
            shutil.rmtree(scan_dir, ignore_errors=True)
            return

        # --- Phase 6: Load already-processed keys (resume support) ---
        processed_keys: set[tuple[str, int, str, str]] = set()
        if is_resume and not candidate_retry_mode:
            processed_keys = await reporter.get_processed_keys(scan_id)
            if processed_keys:
                await emit("init", f"Resume: skipping {len(processed_keys)} already-processed candidates")

        # Filter out already-processed candidates
        remaining = [
            c for c in candidates
            if _candidate_key(c) not in processed_keys
        ]
        remaining = _prepare_audit_queue(
            remaining,
            audit_checker_order,
            family_of=family_of,
            pattern_filter_enabled=pattern_filter_enabled,
            pattern_filter_scope=pattern_filter_scope,
        )
        already_done = retry_processed_offset if candidate_retry_mode else total - len(remaining)

        # Candidate auditing is a whole-stage process.  The coordinator keeps
        # persistence, queueing and HTTP reporting; the process itself only
        # consumes/returns JSON-compatible business data.
        from deephole_client.candidate_audit import run_candidate_audit
        from task_agent.model_pool import total_model_capacity

        audit_capacity = total_model_capacity(
            config.opencode,
            global_concurrency=config.opencode_concurrency,
            required_capability=config.vulnerability_mining.required_capability,
        )
        audit_concurrency = max(1, min(audit_capacity, len(remaining) or 1))
        candidate_checker_dirs = sorted({
            Path(entry.directory).resolve().parent
            for entry in registry.values()
        })
        requested_capability = str(
            config.vulnerability_mining.required_capability or "high"
        ).lower()
        requested_capability = "high" if requested_capability in {"medium", "high"} else "low"

        async def _candidate_process_output(event: dict[str, Any]) -> None:
            message = str(event.get("message") or "")
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            audit_index = data.get("audit_index")
            if message:
                await emit(
                    "auditing",
                    message,
                    candidate_index=int(audit_index) if isinstance(audit_index, int) else None,
                )

        candidate_result = await run_candidate_audit(
            project_path=project_path,
            work_dir=scan_dir / "candidate_audit",
            scan_id=scan_id,
            candidates=[candidate.model_dump() for candidate in remaining],
            checker_dirs=candidate_checker_dirs,
            index_db_path=db_path,
            checker_names=list(registry),
            concurrency=audit_concurrency,
            required_capability=requested_capability,
            pattern_filter_enabled=pattern_filter_enabled,
            pattern_filter_scope=(
                "global" if pattern_filter_scope == "repo"
                else "file" if pattern_filter_scope == "file"
                else "function"
            ),
            feedback_entries=feedback_entries or [],
            audit_index_offset=already_done,
            output=_candidate_process_output,
            cancel_event=cancel_event,
        )

        for checker_name, reports in (candidate_result.get("skill_reports") or {}).items():
            if isinstance(reports, list):
                await reporter.replace_skill_reports(scan_id, str(checker_name), reports)

        candidate_by_index = {
            already_done + index: candidate
            for index, candidate in enumerate(remaining)
        }
        audited_vulnerabilities: list[Vulnerability] = []
        for raw_vulnerability in candidate_result.get("vulnerabilities") or []:
            if not isinstance(raw_vulnerability, dict):
                continue
            vulnerability = Vulnerability(**raw_vulnerability)
            candidate = candidate_by_index.get(vulnerability.audit_index or 0)
            if candidate is not None:
                _attach_function_source(vulnerability, candidate, function_source_cache)
                if (
                    isinstance(candidate.metadata, dict)
                    and candidate.metadata.get("variant_of")
                    and not vulnerability.variant_of
                ):
                    vulnerability.variant_of = str(candidate.metadata["variant_of"])
            audited_vulnerabilities.append(vulnerability)
            response = await reporter.report_vulnerability(scan_id, vulnerability)

            if isinstance(response, dict):
                fp_info = response.get("fp_review")
                if isinstance(fp_info, dict) and fp_info.get("queued"):
                    from deephole_client import server as agent_server
                    payload = vulnerability.model_dump()
                    payload["index"] = int(fp_info["vuln_index"])
                    await agent_server.enqueue_fp_review(
                        config=config,
                        reporter=reporter,
                        scan_id=scan_id,
                        review_id=str(fp_info["review_id"]),
                        vulnerability=payload,
                        project_path=str(project_path),
                        feedback_entries=feedback_entries or [],
                        processed_offset=int(fp_info.get("processed") or 0),
                    )
                if (
                    config.vulnerability_validation.enabled
                    and vulnerability.confirmed
                    and product
                    and validation_environment
                    and response.get("index") is not None
                ):
                    from deephole_client import server as agent_server
                    await agent_server.enqueue_vulnerability_validation(
                        config=config,
                        reporter=reporter,
                        scan_id=scan_id,
                        vuln_index=int(response["index"]),
                        vulnerability=vulnerability.model_dump(),
                        report_markdown=str(response.get("report_markdown") or _fallback_validation_report(vulnerability)),
                        project_path=str(project_path),
                        code_scan_path=str(code_scan_path),
                        product=product,
                        validation_environment=validation_environment,
                        report_queued=True,
                    )

        for key in candidate_result.get("processed_keys") or []:
            if not isinstance(key, dict):
                continue
            await reporter.report_processed_key(
                scan_id,
                str(key.get("file") or ""),
                int(key.get("line") or 0),
                str(key.get("function") or ""),
                str(key.get("vuln_type") or ""),
            )

        if candidate_result.get("status") == "cancelled" or cancel_event.is_set():
            await _wait_for_threat_analysis_task(
                threat_analysis_task, cancel_event=cancel_event, emit=emit,
            )
            await finish_scan_after_pool_drain(
                "cancelled", total, already_done + len(candidate_result.get("processed_keys") or []),
            )
            return

        await _wait_for_threat_analysis_task(
            threat_analysis_task, cancel_event=cancel_event, emit=emit,
        )
        confirmed_count = sum(item.confirmed for item in audited_vulnerabilities)
        await emit(
            "complete",
            f"Scan complete: {confirmed_count} confirmed / {total} total candidates",
        )
        await finish_scan_after_pool_drain("complete", total, total)
        shutil.rmtree(scan_dir, ignore_errors=True)
        return

        # --- Phase 7: AI audit ---
        vulnerabilities: list[Vulnerability] = []
        skill_report_accumulator: dict[str, list[dict]] = {}
        processed_this_run = 0
        await emit("auditing", f"Starting AI audit of {len(remaining)} candidate(s)...")
        if remaining:
            await emit("auditing", f"Audit order: {_audit_order_summary(remaining)}")

        cancelled = False
        from task_agent.model_pool import total_model_capacity
        audit_capacity = total_model_capacity(
            config.opencode,
            global_concurrency=config.opencode_concurrency,
            required_capability=config.vulnerability_mining.required_capability,
        )
        audit_concurrency = max(1, min(audit_capacity, len(remaining) or 1))
        result_lock = asyncio.Lock()
        rejected_patterns: set[tuple[object, ...]] = set()

        for local_index, candidate in enumerate(remaining):
            global_index = already_done + local_index
            metadata = dict(candidate.metadata or {})
            metadata["_opencode_audit_index"] = global_index
            candidate.metadata = metadata

        queue: asyncio.Queue[tuple[int, Candidate]] = asyncio.Queue()
        for item in enumerate(remaining):
            queue.put_nowait(item)

        _configure_backend(config, scan_dir)

        async def schedule_validation(
            *,
            vuln: Vulnerability,
            response: dict | None,
            candidate_index: int,
        ) -> None:
            if not config.vulnerability_validation.enabled:
                return
            if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
                return
            if not str(product or "").strip() or not str(validation_environment or "").strip():
                await emit(
                    "validation",
                    f"[{candidate_index + 1}] Validation skipped: no product/environment target configured",
                    candidate_index=candidate_index,
                )
                return
            if not response or response.get("index") is None:
                await emit(
                    "validation",
                    f"[{candidate_index + 1}] Validation skipped: vulnerability index unavailable",
                    candidate_index=candidate_index,
                )
                return
            try:
                vuln_index = int(response["index"])
            except (TypeError, ValueError):
                await emit(
                    "validation",
                    f"[{candidate_index + 1}] Validation skipped: invalid vulnerability index",
                    candidate_index=candidate_index,
                )
                return
            report_markdown = str(response.get("report_markdown") or "").strip()
            if not report_markdown:
                report_markdown = _fallback_validation_report(vuln)

            from deephole_client import server as agent_server

            queued = await agent_server.enqueue_vulnerability_validation(
                config=config,
                reporter=reporter,
                scan_id=scan_id,
                vuln_index=vuln_index,
                vulnerability=vuln.model_dump(),
                report_markdown=report_markdown,
                project_path=str(project_path),
                code_scan_path=str(code_scan_path),
                product=product,
                validation_environment=validation_environment,
                report_queued=True,
            )
            await emit(
                "validation",
                (
                    f"[{candidate_index + 1}] Validation queued for vuln[{vuln_index}]"
                    if queued
                    else f"[{candidate_index + 1}] Validation skipped: Agent validation queue unavailable"
                ),
                candidate_index=candidate_index,
            )

        async def schedule_fp_review(
            *,
            vuln: Vulnerability,
            response: dict | None,
            candidate_index: int,
        ) -> None:
            fp_info = response.get("fp_review") if isinstance(response, dict) else None
            if not isinstance(fp_info, dict) or not fp_info.get("queued"):
                return
            review_id = str(fp_info.get("review_id") or "")
            if not review_id:
                return
            try:
                vuln_index = int(fp_info.get("vuln_index"))
            except (TypeError, ValueError):
                return
            from deephole_client import server as agent_server

            payload = vuln.model_dump()
            payload["index"] = vuln_index
            queued = await agent_server.enqueue_fp_review(
                config=config,
                reporter=reporter,
                scan_id=scan_id,
                review_id=review_id,
                vulnerability=payload,
                project_path=str(project_path),
                feedback_entries=feedback_entries or [],
                processed_offset=int(fp_info.get("processed") or 0),
            )
            await emit(
                "fp_review",
                (
                    f"[{candidate_index + 1}] FP review queued for vuln[{vuln_index}]"
                    if queued
                    else f"[{candidate_index + 1}] FP review skipped: duplicate or queue unavailable"
                ),
                candidate_index=candidate_index,
            )

        async def process_candidate(global_index: int, candidate: Candidate) -> None:
            nonlocal processed_this_run

            await emit(
                "auditing",
                f"[{global_index + 1}/{total}] {candidate.vuln_type.upper()} "
                f"{candidate.file}:{candidate.line} — {candidate.function}",
                candidate_index=global_index,
            )

            pattern_key: tuple[object, ...] | None = None
            pattern_can_propagate = False
            if pattern_filter_enabled:
                pattern_key, pattern_can_propagate = _candidate_pattern_key(
                    candidate,
                    pattern_filter_scope,
                )
                async with result_lock:
                    pattern_rejected = pattern_key in rejected_patterns
                if pattern_rejected:
                    planned_task_id = ""
                    if isinstance(candidate.metadata, dict):
                        planned_task_id = str(candidate.metadata.get("_opencode_planned_task_id") or "")
                    if planned_task_id:
                        from task_agent.model_pool import clear_planned_task
                        await clear_planned_task(planned_task_id)
                    vuln = Vulnerability(
                        file=candidate.file,
                        line=candidate.line,
                        function=candidate.function,
                        vuln_type=candidate.vuln_type,
                        severity="unknown",
                        description=candidate.description,
                        ai_analysis="同模式代表点已被 AI 审计否决，自动过滤（未调用 LLM）",
                        confirmed=False,
                        ai_verdict="filtered_same_pattern",
                        audit_index=global_index,
                    )
                    _attach_function_source(vuln, candidate, function_source_cache)
                    async with result_lock:
                        vulnerabilities.append(vuln)
                    await emit(
                        "auditing",
                        f"[{global_index + 1}] Result: filtered same pattern",
                        candidate_index=global_index,
                    )
                    await reporter.report_vulnerability(scan_id, vuln)
                    await reporter.report_processed_key(
                        scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                    )
                    async with result_lock:
                        processed_this_run += 1
                    return

            vuln: Optional[Vulnerability] = None
            project_vulns: list[Vulnerability] | None = None
            markdown_reports: list[dict] | None = None
            try:
                checker_entry = registry.get(candidate.vuln_type)
                candidate_timeout = (
                    checker_entry.timeout_seconds
                    if checker_entry is not None and checker_entry.timeout_seconds
                    else config.opencode.timeout
                )
                if (
                    candidate.vuln_type == "sensitive_clear"
                    and isinstance(candidate.metadata, dict)
                    and candidate.metadata.get("kind") == "sensitive_clear_function"
                ):
                    from deephole_client.opencode_workflows import run_sensitive_clear_audit
                    sensitive_result = await run_sensitive_clear_audit(
                        workspace,
                        candidate,
                        scan_id,
                        on_output=lambda line: print(with_local_timestamp(line), flush=True),
                        cancel_event=cancel_event,
                        timeout=candidate_timeout,
                        project_dir=project_path,
                    )
                    project_vulns = sensitive_result.vulnerabilities
                    if sensitive_result.complete and not project_vulns:
                        project_vulns = []
                    elif not sensitive_result.complete and not project_vulns:
                        project_vulns = None
                elif is_project_level_candidate(candidate):
                    if checker_entry is not None and checker_entry.result_mode == "markdown_reports":
                        from deephole_client.opencode_workflows import run_project_report_audit
                        report_dir = scan_dir / "skill_report_workspace" / candidate.vuln_type / "reports"
                        markdown_reports = await run_project_report_audit(
                            workspace,
                            candidate,
                            scan_id,
                            report_dir,
                            on_output=lambda line: print(with_local_timestamp(line), flush=True),
                            cancel_event=cancel_event,
                            timeout=candidate_timeout,
                            project_dir=project_path,
                        )
                    else:
                        from deephole_client.opencode_workflows import run_project_audit
                        project_vulns = await run_project_audit(
                            workspace,
                            candidate,
                            scan_id,
                            on_output=lambda line: print(with_local_timestamp(line), flush=True),
                            cancel_event=cancel_event,
                            timeout=candidate_timeout,
                            project_dir=project_path,
                        )
                else:
                    from deephole_client.opencode_workflows import run_audit
                    vuln = await run_audit(
                        workspace,
                        candidate,
                        scan_id,
                        on_output=lambda line: print(with_local_timestamp(line), flush=True),
                        cancel_event=cancel_event,
                        timeout=candidate_timeout,
                        project_dir=project_path,
                    )
            except NoAvailableModelError:
                raise
            except Exception as exc:
                await emit("auditing", f"[{global_index + 1}] Analysis error: {exc}", candidate_index=global_index)

            if cancel_event.is_set():
                await emit(
                    "auditing",
                    f"Scan stopped during candidate {global_index + 1}",
                    candidate_index=global_index,
                )
                return

            # HTTP 上报放在锁外，避免并发 worker 在结果上报阶段互相串行；
            # result_lock 只保护共享状态（vulnerabilities / processed_this_run）。
            if markdown_reports is not None:
                await reporter.replace_skill_reports(scan_id, candidate.vuln_type, markdown_reports)
                await emit(
                    "auditing",
                    f"[{global_index + 1}] Markdown reports synced: {len(markdown_reports)}",
                    candidate_index=global_index,
                )
                await reporter.report_processed_key(
                    scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                )
                async with result_lock:
                    processed_this_run += 1
                return

            if project_vulns is not None or is_project_level_candidate(candidate):
                project_vulns = project_vulns if project_vulns is not None else [
                    Vulnerability(
                        file=candidate.file,
                        line=candidate.line,
                        function=candidate.function,
                        vuln_type=candidate.vuln_type,
                        severity="unknown",
                        description=candidate.description,
                        ai_analysis="No analysis result returned",
                        confirmed=False,
                        ai_verdict="no_result",
                        audit_index=global_index,
                    )
                ]
                async with result_lock:
                    for project_vuln in project_vulns:
                        _attach_function_source(project_vuln, candidate, function_source_cache)
                        project_vuln.audit_index = global_index
                        vulnerabilities.append(project_vuln)
                for project_vuln in project_vulns:
                    response = await reporter.report_vulnerability(scan_id, project_vuln)
                    await schedule_validation(
                        vuln=project_vuln,
                        response=response,
                        candidate_index=global_index,
                    )
                    await schedule_fp_review(
                        vuln=project_vuln,
                        response=response,
                        candidate_index=global_index,
                    )
                confirmed_project = sum(1 for v in project_vulns if v.confirmed)
                await emit(
                    "auditing",
                    f"[{global_index + 1}] Result: {confirmed_project} confirmed / {len(project_vulns)} submitted",
                    candidate_index=global_index,
                )
                await reporter.report_processed_key(
                    scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                )
                async with result_lock:
                    processed_this_run += 1
                return

            if vuln is None:
                vuln = Vulnerability(
                    file=candidate.file,
                    line=candidate.line,
                    function=candidate.function,
                    vuln_type=candidate.vuln_type,
                    severity="unknown",
                    description=candidate.description,
                    ai_analysis="No analysis result returned",
                    confirmed=False,
                    ai_verdict="no_result",
                    audit_index=global_index,
                )
            _attach_function_source(vuln, candidate, function_source_cache)
            vuln.audit_index = global_index
            if (
                isinstance(candidate.metadata, dict)
                and candidate.metadata.get("variant_of")
                and not vuln.variant_of
            ):
                vuln.variant_of = str(candidate.metadata.get("variant_of"))

            async with result_lock:
                if (
                    pattern_filter_enabled
                    and pattern_can_propagate
                    and pattern_key is not None
                    and not vuln.confirmed
                    and vuln.ai_verdict == "not_confirmed"
                ):
                    rejected_patterns.add(pattern_key)
                vulnerabilities.append(vuln)
            _verdict_labels = {
                "confirmed": "CONFIRMED",
                "not_confirmed": "not confirmed",
                "timeout": "TIMEOUT",
                "no_result": "no result",
                "filtered_same_pattern": "filtered same pattern",
            }
            result_label = _verdict_labels.get(vuln.ai_verdict, "not confirmed")
            await emit("auditing", f"[{global_index + 1}] Result: {result_label}", candidate_index=global_index)
            response = await reporter.report_vulnerability(scan_id, vuln)
            await schedule_validation(
                vuln=vuln,
                response=response,
                candidate_index=global_index,
            )
            await schedule_fp_review(
                vuln=vuln,
                response=response,
                candidate_index=global_index,
            )
            await reporter.report_processed_key(
                scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
            )
            async with result_lock:
                processed_this_run += 1

        async def audit_worker() -> None:
            while not cancel_event.is_set():
                try:
                    i, candidate = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    await process_candidate(already_done + i, candidate)
                except NoAvailableModelError:
                    raise
                except Exception as exc:
                    # 单个候选的未预期异常不应杀死 worker（否则 gather 会
                    # 级联取消其余 worker，导致整批审计中断）。
                    print(f"[error] Candidate {already_done + i + 1} failed: {exc}")
                    await emit(
                        "auditing",
                        f"[{already_done + i + 1}] Unexpected error: {exc}",
                        candidate_index=already_done + i,
                    )
                finally:
                    queue.task_done()

        if cancel_event.is_set():
            await emit(
                "auditing",
                f"Scan stopped by user request after {already_done} candidates",
                candidate_index=already_done,
            )
            cancelled = True
        else:
            audit_workers = [asyncio.create_task(audit_worker()) for _ in range(audit_concurrency)]
            try:
                await asyncio.gather(*audit_workers)
            except NoAvailableModelError:
                cancel_event.set()
                for worker_task in audit_workers:
                    if not worker_task.done():
                        worker_task.cancel()
                await asyncio.gather(*audit_workers, return_exceptions=True)
                raise
            cancelled = cancel_event.is_set()

        # --- Phase 8: Report results ---
        if cancelled:
            await _wait_for_threat_analysis_task(
                threat_analysis_task,
                cancel_event=cancel_event,
                emit=emit,
            )
            await finish_scan_after_pool_drain(
                "cancelled",
                total,
                already_done + processed_this_run,
            )
            # Do NOT delete scan_dir on cancel — needed for resume
            return

        await _wait_for_threat_analysis_task(
            threat_analysis_task,
            cancel_event=cancel_event,
            emit=emit,
        )
        confirmed_count = sum(1 for v in vulnerabilities if v.confirmed)
        await emit(
            "complete",
            f"Scan complete: {confirmed_count} confirmed / {total} total candidates",
        )
        await finish_scan_after_pool_drain("complete", total, total)
        # Clean up on successful completion
        shutil.rmtree(scan_dir, ignore_errors=True)

    except Exception as exc:
        print(f"[error] Scan failed: {exc}")
        emit_func = locals().get("emit")
        try:
            await _wait_for_threat_analysis_task(
                threat_analysis_task,
                cancel_event=cancel_event,
                emit=emit_func if callable(emit_func) else None,
                cancel_first=True,
            )
        except Exception:
            pass
        try:
            await reporter.send_event(scan_id, ScanEvent.create("error", f"Scan failed: {exc}"))
            await finish_scan_after_pool_drain("error", 0, 0, error_message=str(exc))
        except Exception:
            pass
        # Clean up on error
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise

    finally:
        await _drain_opencode_pool_before_finish(
            scan_id,
            pool_status_stop,
            pool_status_task,
        )
        await _clear_finished_opencode_pool_history(scan_id)
        try:
            if mcp_server:
                from deephole_client import mcp_registry
                mcp_registry.unregister(project_path)
                await asyncio.to_thread(mcp_server.stop)
        except Exception:
            pass
        reset_opencode_execution_context(execution_context_token)
        clear_scan_feedback_entries(scan_id)
        if previous_checkers_dir is None:
            os.environ.pop(CHECKERS_DIR_ENV, None)
        else:
            os.environ[CHECKERS_DIR_ENV] = previous_checkers_dir
        import backend.registry as _reg
        _reg._registry = None
        _reg._registry_dirs = None
