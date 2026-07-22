"""Threat-analysis-derived audit task generation and execution."""

from __future__ import annotations

import asyncio
import hashlib
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from agent.config import AgentConfig
from agent.reporter import Reporter
from backend.models import (
    ThreatAnalysis,
    ThreatAttackPath,
    ThreatAttackTree,
    ThreatAttackTreeNode,
    ThreatAuditTask,
    Vulnerability,
)
from task_agent.model_pool import NoAvailableModelError
from task_agent.output_format import with_local_timestamp


COMPLETED_THREAT_AUDIT_STATUS = "completed"
RETRYABLE_THREAT_AUDIT_STATUSES = {"failed", "timeout", "no_result", "cancelled"}
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_generated_id(value: str) -> bool:
    return bool(_GENERATED_THREAT_ID_PATTERN.fullmatch(str(value or "").strip()))


def _display_label(name: str, fallback: str) -> str:
    normalized = str(name or "").strip()
    if normalized and not _looks_like_generated_id(normalized):
        return normalized
    return fallback


def _display_method_name(name: str, fallback: str = "未命名攻击方式") -> str:
    return _display_label(name, fallback)


def _stable_task_id(
    scan_id: str,
    surface_node_id: str,
    method_identity: str,
) -> str:
    raw = f"{scan_id}\0{surface_node_id}\0{method_identity}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]
    return f"threat-audit-{digest}"


def _stable_attack_path_task_id(scan_id: str, path: ThreatAttackPath) -> str:
    identity = path.fingerprint or path.path_id or (
        f"{path.asset_name}\0{path.attack_goal_name}\0{path.attack_domain_name}\0"
        f"{path.attack_surface_name}\0{path.attack_method_name}"
    )
    digest = hashlib.sha1(f"{scan_id}\0{identity}".encode("utf-8")).hexdigest()[:20]
    return f"threat-audit-{digest}"


def _child_map(tree: ThreatAttackTree) -> dict[str, list[ThreatAttackTreeNode]]:
    children: dict[str, list[ThreatAttackTreeNode]] = {}
    for node in tree.nodes:
        if node.parent_id:
            children.setdefault(node.parent_id, []).append(node)
    for group in children.values():
        group.sort(key=lambda item: item.order)
    return children


def _method_descendants(
    surface: ThreatAttackTreeNode,
    children: dict[str, list[ThreatAttackTreeNode]],
) -> list[ThreatAttackTreeNode]:
    methods: list[ThreatAttackTreeNode] = []
    stack = list(reversed(children.get(surface.node_id, [])))
    while stack:
        node = stack.pop()
        if node.node_type.lower() == "method":
            methods.append(node)
            continue
        stack.extend(reversed(children.get(node.node_id, [])))
    return methods


def _risk_lookup(analysis: ThreatAnalysis) -> dict[str, tuple[str, str, str]]:
    out: dict[str, tuple[str, str, str]] = {}
    for asset in analysis.assets:
        for risk in asset.risks:
            if risk.risk_id:
                out[risk.risk_id] = (risk.name, asset.asset_id, asset.name)
    return out


def _description(
    *,
    surface: ThreatAttackTreeNode,
    method: ThreatAttackTreeNode,
    tree: ThreatAttackTree,
) -> str:
    surface_label = _display_label(surface.name or "", "未命名攻击面")
    method_label = _display_method_name(method.name or "")
    goal_label = _display_label(tree.attack_goal or "", "未标记")
    return (
        f"审计攻击面节点 `{surface_label}`，"
        f"攻击方式 `{method_label}`。"
        f"攻击目标：{goal_label}。"
    )


def _attack_path_description(path: ThreatAttackPath) -> str:
    asset_label = _display_label(path.asset_name or "", "未标记")
    goal_label = _display_label(path.attack_goal_name or "", "未标记")
    surface_label = _display_label(path.attack_surface_name or "", "未标记")
    method_label = _display_method_name(path.attack_method_name or "", "未标记")
    return (
        f"审计攻击路径 `{path.path_id or path.fingerprint}`。"
        f"目标资产：{asset_label}；"
        f"攻击目标：{goal_label}；"
        f"攻击面：{surface_label}；"
        f"攻击方法：{method_label}。"
    )


def _method_identity(method: ThreatAttackTreeNode) -> str:
    node_id = str(method.node_id or "").strip()
    if node_id:
        return node_id
    name = str(method.name or "").strip()
    if name:
        return f"name:{name}\0order:{method.order}"
    return f"order:{method.order}\0type:{method.node_type}"


def _task_label(task: ThreatAuditTask) -> str:
    surface = _display_label(task.surface_name or "", "未标记攻击面")
    method = _display_method_name(task.method_name or "", "未标记攻击方式")
    return f"{surface} / {method}"


def _scan_path_from_analysis(analysis: ThreatAnalysis, project_path: Path) -> str:
    scope = analysis.scan_scope
    scan_path = str(scope.code_scan_path or "").strip()
    if scan_path:
        return scan_path
    relative = str(scope.code_scan_relative_path or "").strip()
    if relative and relative != ".":
        return (project_path / relative).resolve().as_posix()
    return project_path.resolve().as_posix()


def build_threat_audit_tasks(scan_id: str, analysis: ThreatAnalysis) -> list[ThreatAuditTask]:
    """Build stable audit tasks from attack-tree surface/method mappings."""
    if analysis.attack_paths:
        tasks: list[ThreatAuditTask] = []
        seen: set[str] = set()
        now = _now()
        for path in analysis.attack_paths:
            identity = path.fingerprint or path.path_id
            if identity in seen:
                continue
            seen.add(identity)
            code_path = path.code_paths[0].path if path.code_paths else ""
            code_path_description = path.code_paths[0].description if path.code_paths else ""
            tasks.append(
                ThreatAuditTask(
                    task_id=_stable_attack_path_task_id(scan_id, path),
                    scan_id=scan_id,
                    status="pending",
                    surface_node_id=path.attack_surface_id,
                    surface_name=_display_label(path.attack_surface_name or "", "未命名攻击面"),
                    method_node_id=path.attack_method_id,
                    method_name=_display_method_name(path.attack_method_name or ""),
                    attack_goal=_display_label(path.attack_goal_name or "", "未命名攻击目标"),
                    risk_id=path.risk_id,
                    risk_name=_display_label(path.risk_name or "", "未命名风险"),
                    asset_id=path.asset_id,
                    asset_name=_display_label(path.asset_name or "", "未命名资产"),
                    code_path=code_path,
                    code_path_description=code_path_description,
                    code_paths=path.code_paths,
                    attack_path_id=path.path_id,
                    attack_path_fingerprint=path.fingerprint,
                    description=_attack_path_description(path),
                    created_at=now,
                    updated_at=now,
                )
            )
        return tasks

    risk_by_id = _risk_lookup(analysis)
    trees_by_surface: dict[str, tuple[ThreatAttackTree, ThreatAttackTreeNode, list[ThreatAttackTreeNode]]] = {}
    for tree in analysis.attack_trees:
        children = _child_map(tree)
        for node in tree.nodes:
            if node.node_type.lower() != "surface":
                continue
            methods = _method_descendants(node, children)
            if not methods:
                methods = [ThreatAttackTreeNode(node_id="", node_type="method", name="未标记攻击方式")]
            trees_by_surface[node.node_id] = (tree, node, methods)

    tasks: list[ThreatAuditTask] = []
    seen: set[tuple[str, str]] = set()
    now = _now()
    for mapping in analysis.code_path_mappings:
        surface_info = trees_by_surface.get(mapping.surface_node_id)
        if surface_info is None:
            continue
        tree, surface, methods = surface_info
        risk_name, asset_id, asset_name = risk_by_id.get(tree.risk_id, ("", tree.asset_id, ""))
        for method in methods:
            method_identity = _method_identity(method)
            key = (surface.node_id, method_identity)
            if key in seen:
                continue
            seen.add(key)
            task_id = _stable_task_id(scan_id, surface.node_id, method_identity)
            tasks.append(
                ThreatAuditTask(
                    task_id=task_id,
                    scan_id=scan_id,
                    status="pending",
                    surface_node_id=surface.node_id,
                    surface_name=_display_label(surface.name or "", "未命名攻击面"),
                    method_node_id=method.node_id or method_identity,
                    method_name=_display_method_name(method.name or ""),
                    attack_goal=_display_label(tree.attack_goal or "", "未命名攻击目标"),
                    risk_id=tree.risk_id,
                    risk_name=_display_label(risk_name or "", "未命名风险"),
                    asset_id=asset_id,
                    asset_name=_display_label(asset_name or "", "未命名资产"),
                    code_path="",
                    code_path_description="",
                    description=_description(surface=surface, method=method, tree=tree),
                    created_at=now,
                    updated_at=now,
                )
            )
    return tasks


def _task_status_from_results(results: list[Vulnerability]) -> str:
    if not results:
        return "no_result"
    verdicts = {str(result.ai_verdict or "") for result in results}
    if verdicts and verdicts <= {"timeout"}:
        return "timeout"
    if verdicts and verdicts <= {"failed"}:
        return "failed"
    if verdicts and verdicts <= {"no_result"}:
        return "no_result"
    return COMPLETED_THREAT_AUDIT_STATUS


async def _maybe_emit(
    emit: Callable[[str, str], object],
    message: str,
) -> None:
    maybe = emit("threat_audit", message)
    if asyncio.iscoroutine(maybe):
        await maybe


async def run_threat_audit_tasks(
    *,
    config: AgentConfig,
    analysis: ThreatAnalysis,
    reporter: Reporter,
    scan_id: str,
    project_path: Path,
    workspace: Path,
    cancel_event: threading.Event,
    emit: Callable[[str, str], object],
    only_task_ids: set[str] | None = None,
    exclude_task_ids: set[str] | None = None,
) -> None:
    """Run threat-analysis-derived audits through the shared OpenCode queue."""
    tasks = build_threat_audit_tasks(scan_id, analysis)
    if exclude_task_ids:
        original_count = len(tasks)
        tasks = [task for task in tasks if task.task_id not in exclude_task_ids]
        if original_count and not tasks:
            await _maybe_emit(emit, "威胁审计任务已由攻击路径即时模式调度，跳过最终补跑")
            return
    if not tasks:
        await _maybe_emit(emit, "威胁分析未生成可审计的攻击面/攻击方式任务")
        return

    existing = {task.task_id: task for task in await reporter.get_threat_audit_tasks(scan_id)}
    pending = [
        task
        for task in tasks
        if only_task_ids is None or task.task_id in only_task_ids
        if existing.get(task.task_id) is None
        or existing[task.task_id].status != COMPLETED_THREAT_AUDIT_STATUS
    ]
    selected_count = len(tasks) if only_task_ids is None else sum(
        1 for task in tasks if task.task_id in only_task_ids
    )
    skipped = selected_count - len(pending)
    await _maybe_emit(
        emit,
        f"威胁分析生成 {len(tasks)} 个独立审计任务，本次执行 {selected_count} 个"
        + (f"，跳过 {skipped} 个已完成任务" if skipped else ""),
    )
    if not pending:
        return

    from task_agent.model_pool import total_model_capacity
    from agent.opencode_workflows import run_threat_audit

    scan_path = _scan_path_from_analysis(analysis, project_path)
    for task in pending:
        await reporter.push_threat_audit_task(scan_id, task)

    capacity = total_model_capacity(
        config.opencode,
        global_concurrency=config.opencode_concurrency,
        required_capability=config.vulnerability_mining.required_capability,
    )
    concurrency = max(1, min(capacity, len(pending)))
    queue: asyncio.Queue[ThreatAuditTask] = asyncio.Queue()

    final_task_ids: set[str] = set()
    for index, task in enumerate(pending):
        queued = task.model_copy(update={"status": "queued", "updated_at": _now()})
        await reporter.push_threat_audit_task(scan_id, queued)
        queue.put_nowait(queued)

    async def worker() -> None:
        while not queue.empty() and not cancel_event.is_set():
            task = await queue.get()
            try:
                started = _now()
                running = task.model_copy(update={"status": "running", "started_at": task.started_at or started, "updated_at": started})
                await reporter.push_threat_audit_task(scan_id, running)
                await _maybe_emit(
                    emit,
                    f"开始威胁审计：{_task_label(running)}",
                )
                results = await run_threat_audit(
                    workspace,
                    running,
                    scan_id,
                    on_output=lambda line: print(
                        with_local_timestamp(line, prefix="[threat-audit]"),
                        flush=True,
                    ),
                    cancel_event=cancel_event,
                    timeout=config.opencode.timeout,
                    project_dir=project_path,
                    planned_task_id="",
                    scan_path=scan_path,
                )
                result_indexes: list[int] = []
                for vuln in results:
                    response = await reporter.report_vulnerability(scan_id, vuln)
                    if isinstance(response, dict) and response.get("index") is not None:
                        try:
                            result_indexes.append(int(response["index"]))
                        except (TypeError, ValueError):
                            pass
                status = _task_status_from_results(results)
                finished = _now()
                failure_reason = ""
                if status != COMPLETED_THREAT_AUDIT_STATUS:
                    failure_reason = "\n\n".join(
                        result.failure_reason or result.ai_analysis
                        for result in results
                        if result.failure_reason or result.ai_analysis
                    )
                done = running.model_copy(
                    update={
                        "status": status,
                        "result_vuln_indexes": result_indexes,
                        "failure_reason": failure_reason,
                        "finished_at": finished,
                        "updated_at": finished,
                    }
                )
                await reporter.push_threat_audit_task(scan_id, done)
                final_task_ids.add(done.task_id)
                await _maybe_emit(
                    emit,
                    f"威胁审计完成：{_task_label(done)}，结果 {len(result_indexes)} 条，状态 {done.status}",
                )
            except asyncio.CancelledError:
                raise
            except NoAvailableModelError as exc:
                failed = task.model_copy(
                    update={
                        "status": "failed",
                        "failure_reason": str(exc),
                        "finished_at": _now(),
                        "updated_at": _now(),
                    }
                )
                await reporter.push_threat_audit_task(scan_id, failed)
                final_task_ids.add(failed.task_id)
                await _maybe_emit(emit, f"威胁审计异常：{_task_label(task)}，原因：{exc}")
                raise
            except Exception as exc:
                failed = task.model_copy(
                    update={
                        "status": "failed",
                        "failure_reason": str(exc),
                        "finished_at": _now(),
                        "updated_at": _now(),
                    }
                )
                await reporter.push_threat_audit_task(scan_id, failed)
                final_task_ids.add(failed.task_id)
                await _maybe_emit(emit, f"威胁审计异常：{_task_label(task)}，原因：{exc}")
            finally:
                queue.task_done()

    async def finish_unfinished_tasks(status: str, failure_reason: str) -> None:
        for task in pending:
            if task.task_id in final_task_ids:
                continue
            current = existing.get(task.task_id, task)
            if current.status == COMPLETED_THREAT_AUDIT_STATUS:
                continue
            terminal = task.model_copy(
                update={
                    "status": status,
                    "failure_reason": failure_reason,
                    "finished_at": _now(),
                    "updated_at": _now(),
                }
            )
            await reporter.push_threat_audit_task(scan_id, terminal)
            final_task_ids.add(terminal.task_id)

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    except NoAvailableModelError as exc:
        cancel_event.set()
        for running_worker in workers:
            if not running_worker.done():
                running_worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await finish_unfinished_tasks("failed", str(exc))
        raise
    if cancel_event.is_set():
        await finish_unfinished_tasks("cancelled", "Scan cancelled")
