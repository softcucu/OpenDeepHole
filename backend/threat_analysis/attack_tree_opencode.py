"""OpenCode runner for the built-in attack-tree threat-analysis implementation."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

from backend.models import ThreatAnalysis, ThreatAnalysisSources, ThreatAttackPath

from .attack_paths import (
    append_or_merge_attack_path,
    build_analysis_from_attack_paths,
    parse_attack_path_data,
    read_attack_paths_jsonl,
)
from .harness import (
    build_code_index,
    detect_product_mcp,
    read_json_object,
    safe_run_id,
    write_json,
)
from .parsing import (
    build_threat_analysis_scan_scope,
    parse_threat_analysis_file,
    write_threat_analysis_file,
)
from .workspace import install_attack_tree_threat_analysis_skill


_MAX_GOALS = 30
_MAX_DOMAINS = 150
_MAX_SURFACES = 300
_MAX_CONFIRMATIONS = 300
_STAGE_FAILURE_RETRIES = 3
_BASE_MODEL_TARGET_FILES_PER_AGENT = 180
_CPP_CODE_EXTENSIONS = {
    ".c",
    ".c++",
    ".cc",
    ".cpp",
    ".cxx",
    ".cu",
    ".h",
    ".h++",
    ".hh",
    ".hpp",
    ".hxx",
    ".cuh",
    ".ipp",
    ".inl",
}
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)


class _StageOutputError(RuntimeError):
    """Raised when a threat-analysis stage did not write a usable JSON object."""


def _readable_stage_label(value: object, fallback: str = "") -> str:
    normalized = str(value or "").strip()
    if normalized and not _GENERATED_THREAT_ID_PATTERN.fullmatch(normalized):
        return normalized
    return fallback


async def run_attack_tree_threat_analysis(
    workspace: Path,
    project_id: str,
    skill_path: Path,
    reference_catalog_path: Path,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
    code_scan_path: Path | None = None,
    product: str = "",
    planned_task_id: str = "",
    on_attack_paths: Callable[[list[ThreatAttackPath]], object] | None = None,
) -> ThreatAnalysis | None:
    """Run the layered threat-analysis harness and return normalized results."""
    from backend.opencode import runner as opencode_runner

    config = opencode_runner.get_config()
    if config.opencode.mock:
        await opencode_runner._clear_planned_task_id(planned_task_id)
        return ThreatAnalysis(schema_version="1.1", analysis_id=f"mock-{project_id}")

    install_attack_tree_threat_analysis_skill(workspace, skill_path, reference_catalog_path)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    analysis_root = (project_dir or workspace).resolve()
    target_path = (code_scan_path or analysis_root).resolve()
    run_dir = analysis_root / "runs" / safe_run_id(project_id)
    stream_path = run_dir / "stream" / "attack_paths.jsonl"
    contexts_dir = run_dir / "contexts"
    stages_dir = run_dir / "stages"
    result_path = run_dir / "res.json"
    legacy_result_path = analysis_root / "res.json"
    scan_scope = build_threat_analysis_scan_scope(analysis_root, target_path)

    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "stream").mkdir(parents=True, exist_ok=True)
    contexts_dir.mkdir(parents=True, exist_ok=True)
    stages_dir.mkdir(parents=True, exist_ok=True)
    stream_lock = asyncio.Lock()

    async def append_attack_paths(output: dict[str, Any], defaults: dict[str, Any] | None = None) -> None:
        async with stream_lock:
            await _append_attack_paths_from_output(
                stream_path,
                output,
                defaults=defaults,
                on_attack_paths=on_attack_paths,
            )

    threat_config = getattr(config, "threat_analysis", None)
    product_mcp_name = str(
        getattr(threat_config, "product_mcp_name", "product-info") or ""
    ).strip()
    product_mcp_detection_timeout = int(
        getattr(threat_config, "product_mcp_detection_timeout_seconds", 60) or 60
    )
    mcp_detection = detect_product_mcp(
        workspace=workspace,
        project_dir=analysis_root,
        run_dir=run_dir,
        product_mcp_name=product_mcp_name,
        timeout_seconds=product_mcp_detection_timeout,
    )
    if on_output:
        status = "可用" if mcp_detection.get("mcp_available") else "不可用"
        on_output(
            f"[威胁分析] 产品信息 MCP `{product_mcp_name or '未配置'}` 检测结果：{status}"
        )

    repo_index = build_code_index(analysis_root, target_path)
    repo_index_path = contexts_dir / "code_index.json"
    write_json(repo_index_path, repo_index)

    base_input = {
        "project_id": project_id,
        "product": product,
        "scan_scope": scan_scope.model_dump(),
        "code_index_path": repo_index_path.as_posix(),
        "code_index": repo_index,
        "product_mcp": mcp_detection,
    }
    base_input_path = contexts_dir / "base_model.input.json"
    base_output_path = stages_dir / "base_model.output.json"
    write_json(base_input_path, base_input)

    base_output = await _run_base_model_agents(
        opencode_runner=opencode_runner,
        workspace=workspace,
        analysis_root=analysis_root,
        run_dir=run_dir,
        contexts_dir=contexts_dir,
        stages_dir=stages_dir,
        base_input=base_input,
        output_path=base_output_path,
        timeout=effective_timeout,
        on_output=on_output,
        cancel_event=cancel_event,
        planned_task_id=planned_task_id,
        stats_scope_id=project_id,
    )
    await append_attack_paths(base_output)

    attack_goals = _attack_goals_from_base_output(base_output)[:_MAX_GOALS]
    if on_output and len(attack_goals) > 1:
        on_output(f"[威胁分析] 攻击树优先调度：按 {len(attack_goals)} 个攻击目标逐棵展开")
    domain_stage_count = 0
    surface_stage_count = 0
    confirmation_stage_count = 0

    async def _run_goal_stage(index: int, goal: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        input_path = contexts_dir / "goal" / f"{_stage_file_stem(goal, 'attack_goal_id', index)}.input.json"
        output_path = stages_dir / "goal" / f"{_stage_file_stem(goal, 'attack_goal_id', index)}.output.json"
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            "attack_goal": goal,
        })
        await _invoke_stage(
            opencode_runner=opencode_runner,
            workspace=workspace,
            analysis_root=analysis_root,
            run_dir=run_dir,
            skill_name="threat-attack-goal-agent",
            input_path=input_path,
            output_path=output_path,
            timeout=effective_timeout,
            on_output=on_output,
            cancel_event=cancel_event,
            planned_task_id=planned_task_id,
            stats_scope_id=project_id,
            attempt=index,
            task_label=f"攻击树 {index}/{len(attack_goals)}：攻击目标分解",
        )
        return read_json_object(output_path)

    async def _run_domain_stage(_index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        stage_index = int(task.get("_stage_index") or _index)
        local_index = int(task.get("_local_index") or _index)
        local_total = int(task.get("_local_total") or 1)
        goal_index = int(task.get("_goal_index") or 1)
        domain = task["attack_domain"]
        input_path = contexts_dir / "domain" / f"{_stage_file_stem(domain, 'domain_id', stage_index)}.input.json"
        output_path = stages_dir / "domain" / f"{_stage_file_stem(domain, 'domain_id', stage_index)}.output.json"
        stage_task = _strip_internal_stage_fields(task)
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **stage_task,
        })
        await _invoke_stage(
            opencode_runner=opencode_runner,
            workspace=workspace,
            analysis_root=analysis_root,
            run_dir=run_dir,
            skill_name="threat-attack-domain-agent",
            input_path=input_path,
            output_path=output_path,
            timeout=effective_timeout,
            on_output=on_output,
            cancel_event=cancel_event,
            planned_task_id=planned_task_id,
            stats_scope_id=project_id,
            attempt=stage_index,
            task_label=f"攻击树 {goal_index}/{len(attack_goals)}：攻击域分析 {local_index}/{local_total}",
        )
        return read_json_object(output_path)

    async def _run_surface_stage(_index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        stage_index = int(task.get("_stage_index") or _index)
        local_index = int(task.get("_local_index") or _index)
        local_total = int(task.get("_local_total") or 1)
        goal_index = int(task.get("_goal_index") or 1)
        surface = task["attack_surface"]
        input_path = contexts_dir / "surface" / f"{_stage_file_stem(surface, 'surface_id', stage_index)}.input.json"
        output_path = stages_dir / "surface" / f"{_stage_file_stem(surface, 'surface_id', stage_index)}.output.json"
        stage_task = _strip_internal_stage_fields(task)
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **stage_task,
        })
        await _invoke_stage(
            opencode_runner=opencode_runner,
            workspace=workspace,
            analysis_root=analysis_root,
            run_dir=run_dir,
            skill_name="threat-attack-surface-agent",
            input_path=input_path,
            output_path=output_path,
            timeout=effective_timeout,
            on_output=on_output,
            cancel_event=cancel_event,
            planned_task_id=planned_task_id,
            stats_scope_id=project_id,
            attempt=stage_index,
            task_label=f"攻击树 {goal_index}/{len(attack_goals)}：攻击面分析 {local_index}/{local_total}",
        )
        surface_output = read_json_object(output_path)
        await append_attack_paths(surface_output, defaults=stage_task)
        return surface_output

    async def _run_confirmation_stage(_index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        stage_index = int(task.get("_stage_index") or _index)
        local_index = int(task.get("_local_index") or _index)
        local_total = int(task.get("_local_total") or 1)
        goal_index = int(task.get("_goal_index") or 1)
        method_task = task["method_confirmation_task"]
        input_path = contexts_dir / "method" / f"{_stage_file_stem(method_task, 'task_id', stage_index)}.input.json"
        output_path = stages_dir / "method" / f"{_stage_file_stem(method_task, 'task_id', stage_index)}.output.json"
        stage_task = _strip_internal_stage_fields(task)
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **stage_task,
        })
        await _invoke_stage(
            opencode_runner=opencode_runner,
            workspace=workspace,
            analysis_root=analysis_root,
            run_dir=run_dir,
            skill_name="threat-method-confirm-agent",
            input_path=input_path,
            output_path=output_path,
            timeout=effective_timeout,
            on_output=on_output,
            cancel_event=cancel_event,
            planned_task_id=planned_task_id,
            stats_scope_id=project_id,
            attempt=stage_index,
            task_label=f"攻击树 {goal_index}/{len(attack_goals)}：方法确认 {local_index}/{local_total}",
        )
        method_output = read_json_object(output_path)
        await append_attack_paths(method_output, defaults=stage_task)
        return method_output

    for goal_index, goal in enumerate(attack_goals, start=1):
        if _cancelled(cancel_event):
            break
        goal_output = await _run_goal_stage(goal_index, goal)

        raw_domains = _dict_items(goal_output.get("domains"))
        domain_tasks: list[dict[str, Any]] = []
        for local_index, domain in enumerate(raw_domains, start=1):
            if domain_stage_count >= _MAX_DOMAINS:
                break
            domain_stage_count += 1
            domain_tasks.append({
                "attack_goal": goal,
                "attack_domain": domain,
                "_stage_index": domain_stage_count,
                "_local_index": local_index,
                "_goal_index": goal_index,
            })
        for task in domain_tasks:
            task["_local_total"] = len(domain_tasks)

        domain_concurrency = _stage_concurrency(config, len(domain_tasks))
        if on_output and len(domain_tasks) > 1:
            on_output(
                f"[威胁分析] 攻击树 {goal_index}/{len(attack_goals)}："
                f"攻击域分析并发度 {domain_concurrency}/{len(domain_tasks)}"
            )
        domain_outputs = await _run_stage_batch(
            domain_tasks,
            concurrency=domain_concurrency,
            run_one=_run_domain_stage,
        )

        surface_tasks: list[dict[str, Any]] = []
        for task, domain_output in zip(domain_tasks, domain_outputs):
            raw_surfaces = _dict_items(domain_output.get("surfaces"))
            for surface in raw_surfaces:
                if surface_stage_count >= _MAX_SURFACES:
                    break
                surface_stage_count += 1
                surface_tasks.append({
                    **_strip_internal_stage_fields(task),
                    "attack_surface": surface,
                    "_stage_index": surface_stage_count,
                    "_local_index": len(surface_tasks) + 1,
                    "_goal_index": goal_index,
                })
            if surface_stage_count >= _MAX_SURFACES:
                break
        for task in surface_tasks:
            task["_local_total"] = len(surface_tasks)

        surface_concurrency = _stage_concurrency(config, len(surface_tasks))
        if on_output and len(surface_tasks) > 1:
            on_output(
                f"[威胁分析] 攻击树 {goal_index}/{len(attack_goals)}："
                f"攻击面分析并发度 {surface_concurrency}/{len(surface_tasks)}"
            )
        surface_outputs = await _run_stage_batch(
            surface_tasks,
            concurrency=surface_concurrency,
            run_one=_run_surface_stage,
        )

        confirmation_tasks: list[dict[str, Any]] = []
        for task, surface_output in zip(surface_tasks, surface_outputs):
            for method_task in _dict_items(surface_output.get("method_confirmation_tasks")):
                if confirmation_stage_count >= _MAX_CONFIRMATIONS:
                    break
                confirmation_stage_count += 1
                confirmation_tasks.append({
                    **_strip_internal_stage_fields(task),
                    "method_confirmation_task": method_task,
                    "_stage_index": confirmation_stage_count,
                    "_local_index": len(confirmation_tasks) + 1,
                    "_goal_index": goal_index,
                })
            if confirmation_stage_count >= _MAX_CONFIRMATIONS:
                break
        for task in confirmation_tasks:
            task["_local_total"] = len(confirmation_tasks)

        confirmation_concurrency = _stage_concurrency(config, len(confirmation_tasks))
        if on_output and len(confirmation_tasks) > 1:
            on_output(
                f"[威胁分析] 攻击树 {goal_index}/{len(attack_goals)}："
                f"方法确认并发度 {confirmation_concurrency}/{len(confirmation_tasks)}"
            )
        await _run_stage_batch(
            confirmation_tasks,
            concurrency=confirmation_concurrency,
            run_one=_run_confirmation_stage,
        )

        if on_output:
            on_output(f"[威胁分析] 攻击树 {goal_index}/{len(attack_goals)} 调度完成")

    paths = read_attack_paths_jsonl(stream_path)
    sources = ThreatAnalysisSources(
        repositories=[scan_scope.code_scan_relative_path or "."],
        documents=[],
        mcp_available=bool(mcp_detection.get("mcp_available")),
        product_mcp_name=product_mcp_name,
    )
    analysis = build_analysis_from_attack_paths(
        paths,
        analysis_id=f"ATA-{uuid4().hex[:12]}",
        sources=sources,
        scan_scope=scan_scope,
    )
    write_threat_analysis_file(result_path, analysis)
    write_threat_analysis_file(legacy_result_path, analysis)
    if on_output:
        on_output(
            f"[威胁分析] 归并完成：攻击路径 {len(analysis.attack_paths)} 条，"
            f"资产 {len(analysis.assets)} 个，输出文件 {result_path}"
        )
    return parse_threat_analysis_file(result_path)


async def _run_base_model_agents(
    *,
    opencode_runner,
    workspace: Path,
    analysis_root: Path,
    run_dir: Path,
    contexts_dir: Path,
    stages_dir: Path,
    base_input: dict[str, Any],
    output_path: Path,
    timeout: int,
    on_output,
    cancel_event,
    planned_task_id: str,
    stats_scope_id: str,
) -> dict[str, Any]:
    """Run first-step shard coordinator agents and merge their JSON fragments."""
    base_context_dir = contexts_dir / "base_model"
    base_stage_dir = stages_dir / "base_model"
    shards = await _plan_base_model_agent_shards(
        opencode_runner=opencode_runner,
        workspace=workspace,
        analysis_root=analysis_root,
        run_dir=run_dir,
        contexts_dir=contexts_dir,
        stages_dir=stages_dir,
        base_input=base_input,
        timeout=timeout,
        on_output=on_output,
        cancel_event=cancel_event,
        planned_task_id=planned_task_id,
        stats_scope_id=stats_scope_id,
    )
    try:
        config = opencode_runner.get_config()
    except Exception:
        config = None
    shard_concurrency = _stage_concurrency(config, len(shards)) if config is not None else 1
    if on_output and len(shards) > 1:
        on_output(f"[威胁分析] 基础建模分片 Agent 并发度：{shard_concurrency}/{len(shards)}")

    async def _run_shard_agent(index: int, shard: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        input_path = base_context_dir / f"base_model_agent_{index:03d}.input.json"
        output_path_for_agent = base_stage_dir / f"base_model_agent_{index:03d}.output.json"
        write_json(input_path, {
            **base_input,
            "base_model_agent_scope": shard,
            "shard_scope": shard,
            "subagent_plan": {
                "allowed": True,
                "agents": [
                    "threat-asset-enumerator",
                    "threat-attack-goal-enumerator",
                    "threat-code-evidence-mapper",
                ],
                "description": (
                    "当前基础建模 Agent 可以在自己的分片范围内派发资产枚举、"
                    "攻击目标枚举和代码证据核对子 Agent，再自行合并输出完整基础模型片段。"
                ),
            },
        })
        await _invoke_stage(
            opencode_runner=opencode_runner,
            workspace=workspace,
            analysis_root=analysis_root,
            run_dir=run_dir,
            skill_name="threat-asset-interface-agent",
            input_path=input_path,
            output_path=output_path_for_agent,
            timeout=timeout,
            on_output=on_output,
            cancel_event=cancel_event,
            planned_task_id=planned_task_id,
            stats_scope_id=stats_scope_id,
            attempt=index,
            task_label=f"基础建模分片 {index}/{len(shards)}",
        )
        return read_json_object(output_path_for_agent)

    shard_outputs = await _run_stage_batch(
        shards,
        concurrency=shard_concurrency,
        run_one=_run_shard_agent,
    )

    merged = _merge_base_model_outputs(*shard_outputs)
    if not _dict_items(merged.get("attack_goals")):
        merged["attack_goals"] = _attack_goals_from_base_output(merged)
    write_json(output_path, merged)
    if on_output:
        on_output(
            "[威胁分析] 基础建模分片 Agent 结果已合并："
            f"资产 {len(_dict_items(merged.get('assets')))} 个，"
            f"高风险接口 {len(_dict_items(merged.get('high_risk_external_interfaces')))} 个，"
            f"攻击目标 {len(_dict_items(merged.get('attack_goals')))} 个"
        )
    return merged


async def _plan_base_model_agent_shards(
    *,
    opencode_runner,
    workspace: Path,
    analysis_root: Path,
    run_dir: Path,
    contexts_dir: Path,
    stages_dir: Path,
    base_input: dict[str, Any],
    timeout: int,
    on_output,
    cancel_event,
    planned_task_id: str,
    stats_scope_id: str,
) -> list[dict[str, Any]]:
    """Ask the planner Skill for semantic base-model shards, with heuristic fallback."""
    fallback_shards = _base_model_agent_shards(base_input)
    input_path = contexts_dir / "base_model_shard_plan.input.json"
    output_path = stages_dir / "base_model_shard_plan.output.json"
    write_json(input_path, {
        **base_input,
        "heuristic_shard_candidates": fallback_shards,
        "planner_contract": {
            "output_field": "shards",
            "path_scope": "仅允许 C/C++ 源文件、头文件和 C/C++ 构建相关证据",
            "decision_rule": (
                "分片数量由资产边界、外部入口族、协议/接口族、共享基础能力、"
                "产品/MCP 模块和代码耦合关系决定；目录候选只能作为参考。"
            ),
        },
    })
    await _invoke_stage(
        opencode_runner=opencode_runner,
        workspace=workspace,
        analysis_root=analysis_root,
        run_dir=run_dir,
        skill_name="threat-base-model-shard-planner",
        input_path=input_path,
        output_path=output_path,
        timeout=timeout,
        on_output=on_output,
        cancel_event=cancel_event,
        planned_task_id=planned_task_id,
        stats_scope_id=stats_scope_id,
        attempt=0,
        task_label="基础建模分片规划",
    )
    planner_output = read_json_object(output_path)
    planned_shards = _normalize_planned_base_model_shards(planner_output)
    if planned_shards:
        if on_output:
            on_output(f"[威胁分析] 基础建模分片规划完成：{len(planned_shards)} 个语义分片")
        return planned_shards
    if on_output:
        reason = str(planner_output.get("error") or "规划结果为空或不可用").strip()
        on_output(
            "[威胁分析] 基础建模分片规划不可用，使用代码索引候选兜底："
            f"{len(fallback_shards)} 个分片，原因：{reason}"
        )
    return fallback_shards


async def _invoke_stage(
    *,
    opencode_runner,
    workspace: Path,
    analysis_root: Path,
    run_dir: Path,
    skill_name: str,
    input_path: Path,
    output_path: Path,
    timeout: int,
    on_output,
    cancel_event,
    planned_task_id: str,
    stats_scope_id: str,
    attempt: int,
    task_label: str,
) -> None:
    if _cancelled(cancel_event):
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    prompt = _stage_prompt(
        skill_name=skill_name,
        input_path=input_path,
        output_path=output_path,
        task_label=task_label,
    )
    task_context = {"task_type": "threat_analysis", "stage": skill_name}
    if planned_task_id:
        task_context["planned_task_id"] = planned_task_id
    max_attempts = 1 + _STAGE_FAILURE_RETRIES
    last_error: Exception | None = None
    for stage_attempt in range(1, max_attempts + 1):
        if _cancelled(cancel_event):
            return
        try:
            output_path.unlink(missing_ok=True)
        except Exception:
            pass
        stage_prompt = prompt
        if stage_attempt > 1:
            stage_prompt += (
                "\n\n上一次执行没有写出可用的阶段 JSON。"
                "请重新读取输入文件，严格输出合法 JSON 对象，并覆盖输出文件。"
            )
        if on_output:
            retry_note = (
                f" 重试 {stage_attempt - 1}/{_STAGE_FAILURE_RETRIES}"
                if stage_attempt > 1
                else ""
            )
            on_output(f"[威胁分析] {task_label}{retry_note}")
        try:
            await opencode_runner._invoke_opencode(
                workspace,
                stage_prompt,
                timeout,
                log_path=log_dir / f"{skill_name}-{attempt}-attempt-{stage_attempt}.log",
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=analysis_root,
                writable_paths=[run_dir],
                model_capability="high",
                prefer_high_model=True,
                stats_scope_id=stats_scope_id,
                task_context=task_context,
                attempt=stage_attempt,
            )
            _validate_stage_output(skill_name, read_json_object(output_path))
            return
        except asyncio.CancelledError:
            raise
        except opencode_runner.NoAvailableModelError as exc:
            last_error = exc
            if stage_attempt >= max_attempts:
                write_json(output_path, {"error": str(exc)})
                raise
        except Exception as exc:
            last_error = exc
            if stage_attempt >= max_attempts:
                break
        if on_output:
            on_output(
                f"[威胁分析] {task_label} 第 {stage_attempt}/{max_attempts} 次失败："
                f"{last_error}，准备重试..."
            )
    failure = str(last_error or "unknown error")
    if on_output:
        on_output(
            f"[威胁分析] {task_label} 失败，已重试 {_STAGE_FAILURE_RETRIES} 次，"
            f"继续后续可用结果：{failure}"
        )
    write_json(output_path, {"error": failure})


def _validate_stage_output(skill_name: str, output: dict[str, Any]) -> None:
    if not output:
        raise _StageOutputError("stage output is empty")
    if output.get("error"):
        raise _StageOutputError(str(output.get("error")))
    required_list_fields = {
        "threat-base-model-shard-planner": ["shards"],
        "threat-asset-interface-agent": [
            "assets",
            "high_risk_external_interfaces",
            "asset_interface_links",
            "risks",
            "attack_goals",
        ],
        "threat-asset-enumerator": [
            "assets",
            "high_risk_external_interfaces",
            "asset_interface_links",
            "risks",
        ],
        "threat-attack-goal-enumerator": ["attack_goals"],
        "threat-code-evidence-mapper": [
            "assets",
            "high_risk_external_interfaces",
            "asset_interface_links",
            "risks",
            "attack_goals",
        ],
        "threat-attack-goal-agent": ["domains"],
        "threat-attack-domain-agent": ["surfaces"],
        "threat-attack-surface-agent": [
            "methods",
            "attack_paths",
            "method_confirmation_tasks",
        ],
        "threat-method-confirm-agent": ["attack_paths"],
    }.get(skill_name, [])
    missing = [field for field in required_list_fields if field not in output]
    if missing:
        raise _StageOutputError(f"stage output missing field(s): {', '.join(missing)}")
    wrong_type = [
        field
        for field in required_list_fields
        if field in output and not isinstance(output[field], list)
    ]
    if wrong_type:
        raise _StageOutputError(
            f"stage output field(s) must be arrays: {', '.join(wrong_type)}"
        )


def _stage_concurrency(config: Any, pending_count: int) -> int:
    if pending_count <= 1:
        return 1
    try:
        from backend.opencode.model_pool import total_model_capacity

        global_concurrency = int(getattr(config, "opencode_concurrency", 1) or 1)
        capacity = total_model_capacity(
            config.opencode,
            global_concurrency=max(1, global_concurrency),
            required_capability="high",
        )
    except Exception:
        capacity = 1
    return max(1, min(int(capacity or 1), pending_count))


async def _run_stage_batch(
    items: list[dict[str, Any]],
    *,
    concurrency: int,
    run_one: Callable[[int, dict[str, Any]], Awaitable[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if not items:
        return []
    concurrency = max(1, min(concurrency, len(items)))
    semaphore = asyncio.Semaphore(concurrency)

    async def _guarded(index: int, item: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        async with semaphore:
            return index, await run_one(index, item)

    tasks = [
        asyncio.create_task(_guarded(index, item))
        for index, item in enumerate(items, start=1)
    ]
    results: list[tuple[int, dict[str, Any]]] = []
    try:
        for task in asyncio.as_completed(tasks):
            results.append(await task)
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    except Exception:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    results.sort(key=lambda item: item[0])
    return [output for _index, output in results]


def _stage_prompt(
    *,
    skill_name: str,
    input_path: Path,
    output_path: Path,
    task_label: str,
) -> str:
    prompt = (
        f"使用 `{skill_name}` 技能执行威胁分析阶段：{task_label}。\n"
        f"读取输入 JSON 文件：`{input_path.resolve()}`。\n"
        f"将阶段结果写入输出 JSON 文件：`{output_path.resolve()}`。\n"
        "只处理输入文件指定的当前对象或当前阶段，不要扩展到其他阶段。\n"
        "输出文件必须是合法 JSON 对象；不要用 Markdown 代码块包裹。\n"
        "代码路径必须来自输入代码索引或实际检索结果，无法确认时输出空数组。\n"
        "本工具当前只分析 C/C++ 源文件、头文件和 C/C++ 构建文件；"
        "不要把非 C/C++ 文件作为资产、风险、攻击目标或代码证据依据。\n"
        "除内部 ID、JSON 字段名、枚举值、文件路径、函数名、协议名和标准缩写外，"
        "所有面向用户展示的自然语言字段必须使用中文；不要输出英文标题、英文描述或英文严重性标签。\n"
        "不得修改输出 JSON 文件之外的任何项目文件。\n"
    )
    if skill_name == "threat-base-model-shard-planner":
        prompt += (
            "这是威胁分析第一步之前的基础建模分片规划阶段。"
            "只分析输入代码索引、MCP 状态、启发式候选和扫描范围，输出语义分片计划。"
            "不要创建子 Agent，不要分析资产明细、攻击目标、攻击域、攻击面或攻击方法。"
            "分片数量不要按目录数量机械决定；应按价值资产边界、外部入口族、协议/接口族、"
            "共享基础能力、产品/MCP 模块、构建目标和代码耦合关系决定。"
            "输出 `shards` 数组，每项必须包含人类可读 `name`、`description`、"
            "`include_paths`、`entry_candidates` 和规划理由；路径只能来自输入代码索引。\n"
        )
    elif skill_name == "threat-asset-interface-agent":
        prompt += (
            "这是 Harness 启动的第一步基础建模分片协调 Agent。"
            "允许并建议在当前分片范围内使用 Task 派发子 Agent："
            "`threat-asset-enumerator`、`threat-attack-goal-enumerator`、`threat-code-evidence-mapper`。"
            "子 Agent 只返回分析片段，不写文件；当前 Agent 负责合并子 Agent 结果，并只写入指定输出 JSON。"
            "不要把工作扩展到输入 scope 之外，也不要做资产 × 接口 × 风险的笛卡尔积派发。\n"
        )
    elif skill_name in {
        "threat-asset-enumerator",
        "threat-attack-goal-enumerator",
        "threat-code-evidence-mapper",
    }:
        prompt += (
            "这是基础建模角色 Agent 阶段；不要再创建子 Agent，也不要再派发 Task。"
            "只完成当前 skill 和输入 scope 指定的工作，结果由 Harness 合并。\n"
        )
    return prompt


_BASE_MODEL_LIST_FIELDS = [
    "assets",
    "high_risk_external_interfaces",
    "asset_interface_links",
    "risks",
    "attack_goals",
]


def _base_model_agent_shards(base_input: dict[str, Any]) -> list[dict[str, Any]]:
    code_index = base_input.get("code_index") if isinstance(base_input.get("code_index"), dict) else {}
    scan_scope = base_input.get("scan_scope") if isinstance(base_input.get("scan_scope"), dict) else {}
    scan_relative = str(scan_scope.get("code_scan_relative_path") or "").strip()
    files = _unique_cpp_paths(code_index.get("files") or [])
    entry_candidates = _unique_cpp_paths(code_index.get("entry_candidates") or [])
    if not files and not entry_candidates:
        return [
            {
                "shard_id": "BASE-SHARD-001",
                "type": "full_scan",
                "name": "C/C++ 扫描范围",
                "description": "未在当前扫描范围发现 C/C++ 源文件，基础建模只保留产品信息和空代码索引上下文",
                "include_paths": [],
                "entry_candidates": [],
                "languages": [],
            }
        ]

    groups = _base_model_path_groups(files, entry_candidates, scan_relative, depth=1)
    shard_type = "top_level_path"
    if len(groups) <= 1:
        nested_groups = _base_model_path_groups(files, entry_candidates, scan_relative, depth=2)
        if len(nested_groups) > 1:
            groups = nested_groups
            shard_type = "module_path"

    shard_specs: list[dict[str, Any]] = []
    for group in sorted(
        groups.values(),
        key=lambda item: (-(len(item["files"]) + len(item["entry_candidates"]) * 3), item["name"]),
    ):
        shard_specs.extend(_split_base_model_group(group, shard_type))

    if not shard_specs:
        shard_specs.append({
            "type": "full_scan",
            "name": "C/C++ 扫描范围",
            "description": "分析完整 C/C++ 扫描范围内的资产、接口、风险、攻击目标和代码证据",
            "include_paths": files,
            "entry_candidates": entry_candidates,
            "languages": sorted({_language_from_index_path(path) for path in files if _language_from_index_path(path)}),
        })

    for index, shard in enumerate(shard_specs, start=1):
        shard["shard_id"] = f"BASE-SHARD-{index:03d}"
    return shard_specs


def _normalize_planned_base_model_shards(planner_output: dict[str, Any]) -> list[dict[str, Any]]:
    shards: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_index, raw in enumerate(_dict_items(planner_output.get("shards")), start=1):
        include_paths = _unique_cpp_paths(
            raw.get("include_paths")
            or raw.get("paths")
            or raw.get("files")
            or []
        )
        entry_candidates = _unique_cpp_paths(raw.get("entry_candidates") or [])
        allows_empty_scope = bool(
            raw.get("use_product_mcp")
            or raw.get("product_mcp_scope")
            or str(raw.get("type") or "").strip().lower() in {
                "product_mcp",
                "mcp_product_module",
                "product_module",
            }
        )
        if not include_paths and not entry_candidates and not allows_empty_scope:
            continue
        name = _readable_stage_label(raw.get("name"), f"语义分片 {raw_index}")
        description = _readable_stage_label(
            raw.get("description"),
            f"分析 `{name}` 范围内的 C/C++ 资产、接口、风险、攻击目标和代码证据",
        )
        languages = _planned_shard_languages(raw, include_paths)
        shard = {
            **raw,
            "shard_id": f"BASE-SHARD-{len(shards) + 1:03d}",
            "type": str(raw.get("type") or "ai_planned").strip() or "ai_planned",
            "name": name,
            "description": description,
            "include_paths": include_paths,
            "entry_candidates": entry_candidates,
            "languages": languages,
        }
        key = _planned_shard_key(shard)
        if key in seen:
            continue
        seen.add(key)
        shards.append(shard)
    return shards


def _planned_shard_languages(raw: dict[str, Any], include_paths: list[str]) -> list[str]:
    known = {"c", "cpp", "c/cpp"}
    languages = [
        str(item or "").strip()
        for item in raw.get("languages") or []
        if str(item or "").strip() in known
    ]
    if not languages:
        languages = [
            language
            for language in (_language_from_index_path(path) for path in include_paths)
            if language
        ]
    out: list[str] = []
    seen: set[str] = set()
    for language in languages:
        if language in seen:
            continue
        seen.add(language)
        out.append(language)
    return out


def _planned_shard_key(shard: dict[str, Any]) -> str:
    return json.dumps(
        {
            "type": shard.get("type"),
            "name": shard.get("name"),
            "include_paths": shard.get("include_paths") or [],
            "entry_candidates": shard.get("entry_candidates") or [],
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def _unique_cpp_paths(paths: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in paths:
        path = str(item or "").strip()
        if not path or not _is_cpp_code_path(path) or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _is_cpp_code_path(path: str) -> bool:
    return Path(path).suffix.lower() in _CPP_CODE_EXTENSIONS


def _base_model_path_groups(
    files: list[str],
    entry_candidates: list[str],
    scan_relative: str,
    *,
    depth: int,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for path in files:
        name = _shard_group_name_for_path(path, scan_relative, depth=depth)
        group = grouped.setdefault(name, {"name": name, "files": [], "entry_candidates": [], "languages": set()})
        group["files"].append(path)
        language = _language_from_index_path(path)
        if language:
            group["languages"].add(language)
    file_groups = {
        path: _shard_group_name_for_path(path, scan_relative, depth=depth)
        for path in files
    }
    for path in entry_candidates:
        name = file_groups.get(path) or _shard_group_name_for_path(path, scan_relative, depth=depth)
        group = grouped.setdefault(name, {"name": name, "files": [], "entry_candidates": [], "languages": set()})
        group["entry_candidates"].append(path)
        language = _language_from_index_path(path)
        if language:
            group["languages"].add(language)
    return grouped


def _split_base_model_group(group: dict[str, Any], shard_type: str) -> list[dict[str, Any]]:
    files = list(group.get("files") or [])
    entry_candidates = list(group.get("entry_candidates") or [])
    languages = sorted(group.get("languages") or [])
    group_name = str(group.get("name") or "C/C++ 扫描范围")
    if len(files) <= _BASE_MODEL_TARGET_FILES_PER_AGENT:
        return [{
            "type": shard_type,
            "name": group_name,
            "description": f"分析 `{group_name}` 范围内的 C/C++ 资产、接口、风险、攻击目标和代码证据",
            "include_paths": files,
            "entry_candidates": entry_candidates,
            "languages": languages,
        }]

    shards: list[dict[str, Any]] = []
    assigned_entries: set[str] = set()
    for chunk_index, start in enumerate(range(0, len(files), _BASE_MODEL_TARGET_FILES_PER_AGENT), start=1):
        chunk = files[start:start + _BASE_MODEL_TARGET_FILES_PER_AGENT]
        chunk_set = set(chunk)
        chunk_entries = [path for path in entry_candidates if path in chunk_set]
        assigned_entries.update(chunk_entries)
        shards.append({
            "type": f"{shard_type}_chunk",
            "name": f"{group_name} #{chunk_index}",
            "description": (
                f"分析 `{group_name}` 范围内第 {chunk_index} 个 C/C++ 文件批次的"
                "资产、接口、风险、攻击目标和代码证据"
            ),
            "include_paths": chunk,
            "entry_candidates": chunk_entries,
            "languages": sorted({_language_from_index_path(path) for path in chunk if _language_from_index_path(path)}),
        })

    remaining_entries = [path for path in entry_candidates if path not in assigned_entries]
    if remaining_entries:
        shards[0]["entry_candidates"] = _merge_mixed_lists(shards[0]["entry_candidates"], remaining_entries)
    return shards


def _shard_group_name_for_path(path: str, scan_relative: str, *, depth: int = 1) -> str:
    relative = path
    if scan_relative and scan_relative != ".":
        prefix = scan_relative.rstrip("/") + "/"
        if relative == scan_relative:
            relative = "."
        elif relative.startswith(prefix):
            relative = relative[len(prefix):]
    parts = [part for part in relative.split("/") if part]
    if len(parts) <= 1:
        return "."
    directories = parts[:-1]
    if not directories:
        return "."
    return "/".join(directories[:max(1, depth)])


def _language_from_index_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    by_suffix = {
        ".c": "c",
        ".c++": "cpp",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".cu": "cpp",
        ".h": "c/cpp",
        ".h++": "cpp",
        ".hh": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".cuh": "cpp",
        ".ipp": "cpp",
        ".inl": "cpp",
    }
    return by_suffix.get(suffix, "")


def _merge_base_model_outputs(*outputs: dict[str, Any]) -> dict[str, Any]:
    valid_outputs = [
        output
        for output in outputs
        if isinstance(output, dict) and not output.get("error")
    ]
    aliases = _base_model_reference_aliases(valid_outputs)
    merged: dict[str, Any] = {field: [] for field in _BASE_MODEL_LIST_FIELDS}
    for output in valid_outputs:
        output = _normalize_base_model_references(output, aliases)
        for field in _BASE_MODEL_LIST_FIELDS:
            merged[field] = _merge_object_lists(field, merged[field], _dict_items(output.get(field)))
    _attach_top_level_risks_to_assets(merged)
    return merged


def _base_model_reference_aliases(outputs: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    aliases = {
        "asset_ids": {},
        "interface_ids": {},
        "risk_ids": {},
        "attack_goal_ids": {},
    }
    asset_by_semantic: dict[str, str] = {}
    interface_by_semantic: dict[str, str] = {}
    risk_by_semantic: dict[str, str] = {}
    goal_by_semantic: dict[str, str] = {}

    for output in outputs:
        for asset in _dict_items(output.get("assets")):
            asset_id = _first_text(asset, "asset_id", "id")
            if asset_id:
                aliases["asset_ids"].setdefault(asset_id, asset_id)
            semantic = _semantic_name(asset.get("name") or asset.get("asset_name"))
            if asset_id and semantic:
                _register_semantic_alias(aliases["asset_ids"], asset_by_semantic, semantic, asset_id)

        for interface in _dict_items(output.get("high_risk_external_interfaces")):
            interface_id = _first_text(interface, "interface_id", "id")
            if interface_id:
                aliases["interface_ids"].setdefault(interface_id, interface_id)
            semantic = _interface_semantic_key(interface)
            if interface_id and semantic:
                _register_semantic_alias(aliases["interface_ids"], interface_by_semantic, semantic, interface_id)

    for output in outputs:
        for asset in _dict_items(output.get("assets")):
            asset_id = _canonical_ref(aliases, "asset_ids", _first_text(asset, "asset_id", "id"))
            for risk in _dict_items(asset.get("risks")):
                _register_risk_alias(risk, asset_id, aliases, risk_by_semantic)
        for risk in _dict_items(output.get("risks")):
            asset_id = _canonical_ref(aliases, "asset_ids", _first_text(risk, "asset_id"))
            _register_risk_alias(risk, asset_id, aliases, risk_by_semantic)

    for output in outputs:
        for goal in _dict_items(output.get("attack_goals")):
            goal_id = _first_text(goal, "attack_goal_id", "goal_id", "id")
            if goal_id:
                aliases["attack_goal_ids"].setdefault(goal_id, goal_id)
            semantic = _attack_goal_semantic_key(goal, aliases)
            if goal_id and semantic:
                _register_semantic_alias(aliases["attack_goal_ids"], goal_by_semantic, semantic, goal_id)

    for bucket in aliases.values():
        for value in list(bucket):
            bucket[value] = _resolve_alias(bucket, value)
    return aliases


def _register_risk_alias(
    risk: dict[str, Any],
    asset_id: str,
    aliases: dict[str, dict[str, str]],
    risk_by_semantic: dict[str, str],
) -> None:
    risk_id = _first_text(risk, "risk_id", "id")
    if risk_id:
        aliases["risk_ids"].setdefault(risk_id, risk_id)
    semantic = _risk_semantic_key(risk, asset_id)
    if risk_id and semantic:
        _register_semantic_alias(aliases["risk_ids"], risk_by_semantic, semantic, risk_id)


def _register_semantic_alias(
    aliases: dict[str, str],
    semantic_to_id: dict[str, str],
    semantic_key: str,
    raw_id: str,
) -> str:
    canonical = semantic_to_id.get(semantic_key)
    if not canonical:
        canonical = _resolve_alias(aliases, raw_id)
        semantic_to_id[semantic_key] = canonical
    aliases[raw_id] = canonical
    return canonical


def _normalize_base_model_references(
    output: dict[str, Any],
    aliases: dict[str, dict[str, str]],
) -> dict[str, Any]:
    return {
        "assets": [
            _normalize_asset_item(item, aliases)
            for item in _dict_items(output.get("assets"))
        ],
        "high_risk_external_interfaces": [
            _normalize_interface_item(item, aliases)
            for item in _dict_items(output.get("high_risk_external_interfaces"))
        ],
        "asset_interface_links": [
            _normalize_link_item(item, aliases)
            for item in _dict_items(output.get("asset_interface_links"))
        ],
        "risks": [
            _normalize_risk_item(item, aliases)
            for item in _dict_items(output.get("risks"))
        ],
        "attack_goals": [
            _normalize_attack_goal_item(item, aliases)
            for item in _dict_items(output.get("attack_goals"))
        ],
    }


def _normalize_asset_item(item: dict[str, Any], aliases: dict[str, dict[str, str]]) -> dict[str, Any]:
    out = dict(item)
    asset_id = _rewrite_id_field(out, "asset_id", aliases, "asset_ids")
    if not asset_id:
        asset_id = _rewrite_id_field(out, "id", aliases, "asset_ids")
    risks = [
        _normalize_risk_item(risk, aliases, asset_id=asset_id)
        for risk in _dict_items(out.get("risks"))
    ]
    if risks:
        out["risks"] = risks
    return out


def _normalize_interface_item(item: dict[str, Any], aliases: dict[str, dict[str, str]]) -> dict[str, Any]:
    out = dict(item)
    _rewrite_id_field(out, "interface_id", aliases, "interface_ids")
    _rewrite_id_field(out, "id", aliases, "interface_ids")
    for key in ("affected_asset_ids", "asset_ids"):
        if isinstance(out.get(key), list):
            out[key] = _rewrite_id_list(out[key], aliases, "asset_ids")
    return out


def _normalize_link_item(item: dict[str, Any], aliases: dict[str, dict[str, str]]) -> dict[str, Any]:
    out = dict(item)
    _rewrite_id_field(out, "asset_id", aliases, "asset_ids")
    _rewrite_id_field(out, "interface_id", aliases, "interface_ids")
    _rewrite_id_field(out, "risk_id", aliases, "risk_ids")
    _rewrite_id_field(out, "attack_goal_id", aliases, "attack_goal_ids")
    return out


def _normalize_risk_item(
    item: dict[str, Any],
    aliases: dict[str, dict[str, str]],
    *,
    asset_id: str = "",
) -> dict[str, Any]:
    out = dict(item)
    canonical_asset_id = _rewrite_id_field(out, "asset_id", aliases, "asset_ids") or asset_id
    if canonical_asset_id and not out.get("asset_id"):
        out["asset_id"] = canonical_asset_id
    _rewrite_id_field(out, "risk_id", aliases, "risk_ids")
    _rewrite_id_field(out, "id", aliases, "risk_ids")
    return out


def _normalize_attack_goal_item(item: dict[str, Any], aliases: dict[str, dict[str, str]]) -> dict[str, Any]:
    out = dict(item)
    _rewrite_id_field(out, "attack_goal_id", aliases, "attack_goal_ids")
    _rewrite_id_field(out, "goal_id", aliases, "attack_goal_ids")
    _rewrite_id_field(out, "id", aliases, "attack_goal_ids")
    _rewrite_id_field(out, "asset_id", aliases, "asset_ids")
    _rewrite_id_field(out, "risk_id", aliases, "risk_ids")
    for key in ("related_interface_ids", "interface_ids"):
        if isinstance(out.get(key), list):
            out[key] = _rewrite_id_list(out[key], aliases, "interface_ids")
    return out


def _rewrite_id_field(
    item: dict[str, Any],
    key: str,
    aliases: dict[str, dict[str, str]],
    alias_bucket: str,
) -> str:
    value = str(item.get(key) or "").strip()
    if not value:
        return ""
    canonical = _canonical_ref(aliases, alias_bucket, value)
    item[key] = canonical
    return canonical


def _rewrite_id_list(values: list[Any], aliases: dict[str, dict[str, str]], alias_bucket: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        canonical = _canonical_ref(aliases, alias_bucket, str(value or "").strip())
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


def _canonical_ref(aliases: dict[str, dict[str, str]], alias_bucket: str, value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    return _resolve_alias(aliases.get(alias_bucket, {}), value)


def _resolve_alias(aliases: dict[str, str], value: str) -> str:
    current = str(value or "").strip()
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        next_value = aliases.get(current, current)
        if next_value == current:
            return current
        current = next_value
    return current


def _first_text(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def _semantic_name(value: Any) -> str:
    readable = _readable_stage_label(value)
    return re.sub(r"\s+", " ", readable).strip().casefold()


def _interface_semantic_key(item: dict[str, Any]) -> str:
    name = _semantic_name(item.get("name") or item.get("interface_name"))
    if not name:
        return ""
    qualifiers = [
        str(item.get(key) or "").strip().casefold()
        for key in ("protocol", "endpoint", "path", "component", "module", "type")
        if str(item.get(key) or "").strip()
    ]
    return "\0".join([name, *qualifiers])


def _risk_semantic_key(item: dict[str, Any], asset_id: str = "") -> str:
    name = _semantic_name(item.get("name") or item.get("risk_name"))
    if not name:
        return ""
    return "\0".join([asset_id, name]) if asset_id else name


def _attack_goal_semantic_key(item: dict[str, Any], aliases: dict[str, dict[str, str]] | None = None) -> str:
    name = _semantic_name(item.get("name") or item.get("attack_goal") or item.get("attack_goal_name"))
    if not name:
        return ""
    aliases = aliases or {}
    asset_id = _canonical_ref(aliases, "asset_ids", _first_text(item, "asset_id"))
    risk_id = _canonical_ref(aliases, "risk_ids", _first_text(item, "risk_id"))
    return "\0".join([asset_id, risk_id, name])


def _merge_object_lists(field: str, existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in [*existing, *incoming]:
        key = _merge_item_key(field, item, len(order))
        current = by_key.get(key)
        if current is None:
            by_key[key] = _sanitize_display_names(dict(item))
            order.append(key)
        else:
            by_key[key] = _merge_dict_values(current, item)
    return [by_key[key] for key in order]


def _sanitize_display_names(item: dict[str, Any]) -> dict[str, Any]:
    if "name" in item:
        item["name"] = _readable_stage_label(item.get("name"))
    if "attack_goal" in item:
        item["attack_goal"] = _readable_stage_label(item.get("attack_goal"))
    for key in ("asset_name", "risk_name", "attack_goal_name", "attack_domain_name", "attack_surface_name", "attack_method_name"):
        if key in item:
            item[key] = _readable_stage_label(item.get(key))
    if isinstance(item.get("risks"), list):
        item["risks"] = [
            _sanitize_display_names(dict(risk))
            for risk in _dict_items(item.get("risks"))
        ]
    return item


def _merge_item_key(field: str, item: dict[str, Any], index: int) -> str:
    if field == "assets":
        name = _semantic_name(item.get("name") or item.get("asset_name"))
        if name:
            return f"{field}:name:{name}"
    elif field == "high_risk_external_interfaces":
        interface_key = _interface_semantic_key(item)
        if interface_key:
            return f"{field}:name:{interface_key}"
    elif field == "risks":
        risk_key = _risk_semantic_key(item, str(item.get("asset_id") or "").strip())
        if risk_key:
            return f"{field}:name:{risk_key}"
    elif field == "attack_goals":
        goal_key = _attack_goal_semantic_key(item)
        if goal_key:
            return f"{field}:name:{goal_key}"
    elif field == "asset_interface_links":
        link_key = "\0".join(
            str(item.get(key) or "").strip()
            for key in ("asset_id", "interface_id", "risk_id", "attack_goal_id")
        )
        if link_key.strip("\0"):
            return f"{field}:link:{link_key}"

    id_keys = {
        "assets": ("asset_id", "id"),
        "high_risk_external_interfaces": ("interface_id", "id"),
        "risks": ("risk_id", "id"),
        "attack_goals": ("attack_goal_id", "goal_id", "id"),
    }.get(field, ())
    for key in id_keys:
        value = str(item.get(key) or "").strip()
        if value:
            return f"{field}:id:{value}"
    name = _readable_stage_label(item.get("name"))
    if name:
        prefix = str(item.get("asset_id") or item.get("risk_id") or "").strip()
        return f"{field}:name:{prefix}:{name.lower()}"
    try:
        return f"{field}:json:{json.dumps(item, sort_keys=True, ensure_ascii=False)}"
    except TypeError:
        return f"{field}:index:{index}"


def _merge_dict_values(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key, value in right.items():
        current = merged.get(key)
        if key == "name":
            readable = _readable_stage_label(current)
            incoming = _readable_stage_label(value)
            merged[key] = readable or incoming
        elif key in {
            "asset_name",
            "risk_name",
            "attack_goal_name",
            "attack_domain_name",
            "attack_surface_name",
            "attack_method_name",
        }:
            readable = _readable_stage_label(current)
            incoming = _readable_stage_label(value)
            merged[key] = readable or incoming
        elif key == "risks" and isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_object_lists("risks", _dict_items(current), _dict_items(value))
        elif isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_mixed_lists(current, value)
        elif isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _merge_dict_values(current, value)
        elif _is_empty_value(current) and not _is_empty_value(value):
            merged[key] = value
    return merged


def _merge_mixed_lists(left: list[Any], right: list[Any]) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        try:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        except TypeError:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _is_empty_value(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _attach_top_level_risks_to_assets(model: dict[str, Any]) -> None:
    assets = _dict_items(model.get("assets"))
    risks = _dict_items(model.get("risks"))
    if not assets or not risks:
        return
    by_asset_id = {
        str(asset.get("asset_id") or asset.get("id") or "").strip(): asset
        for asset in assets
        if str(asset.get("asset_id") or asset.get("id") or "").strip()
    }
    for risk in risks:
        asset_id = str(risk.get("asset_id") or "").strip()
        asset = by_asset_id.get(asset_id)
        if asset is None:
            continue
        asset["risks"] = _merge_object_lists("risks", _dict_items(asset.get("risks")), [risk])


def _attack_goals_from_base_output(base_output: dict[str, Any]) -> list[dict[str, Any]]:
    goals = _dict_items(base_output.get("attack_goals"))
    if goals:
        return goals
    out: list[dict[str, Any]] = []
    assets = _dict_items(base_output.get("assets"))
    risks = _dict_items(base_output.get("risks"))
    risks_by_asset: dict[str, list[dict[str, Any]]] = {}
    for risk in risks:
        asset_id = str(risk.get("asset_id") or "").strip()
        if asset_id:
            risks_by_asset.setdefault(asset_id, []).append(risk)
    for asset_index, asset in enumerate(assets, start=1):
        asset_id = str(asset.get("asset_id") or asset.get("id") or f"ASSET-{asset_index:03d}")
        asset_risks = risks_by_asset.get(asset_id) or _dict_items(asset.get("risks"))
        for risk_index, risk in enumerate(asset_risks, start=1):
            risk_id = str(risk.get("risk_id") or risk.get("id") or f"RISK-{asset_index:03d}-{risk_index:03d}")
            risk_name = _readable_stage_label(risk.get("name"), "关键风险")
            asset_name = _readable_stage_label(asset.get("name"), "未命名资产")
            out.append({
                "attack_goal_id": f"GOAL-{asset_index:03d}-{risk_index:03d}",
                "asset_id": asset_id,
                "asset_name": asset_name,
                "risk_id": risk_id,
                "risk_name": risk_name,
                "name": f"实现风险：{risk_name}",
                "related_interface_ids": [],
                "candidate_code_paths": [],
            })
    return out


async def _append_attack_paths_from_output(
    stream_path: Path,
    output: dict[str, Any],
    defaults: dict[str, Any] | None = None,
    on_attack_paths: Callable[[list[ThreatAttackPath]], object] | None = None,
) -> None:
    defaults = defaults or {}
    latest_paths: list[ThreatAttackPath] = []
    for raw_path in _dict_items(output.get("attack_paths")):
        merged = _with_attack_path_defaults(raw_path, defaults)
        latest_paths = append_or_merge_attack_path(stream_path, parse_attack_path_data(merged))
    if latest_paths and on_attack_paths is not None:
        maybe = on_attack_paths(latest_paths)
        if inspect.isawaitable(maybe):
            await maybe


def _with_attack_path_defaults(path: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    out = dict(path)
    for source_key, prefix in (
        ("attack_goal", "attack_goal"),
        ("attack_domain", "attack_domain"),
        ("attack_surface", "attack_surface"),
    ):
        value = defaults.get(source_key)
        if not isinstance(value, dict):
            continue
        for key, mapped in (
            ("asset_id", "asset_id"),
            ("asset_name", "asset_name"),
            ("risk_id", "risk_id"),
            ("risk_name", "risk_name"),
            ("attack_goal_id", f"{prefix}_id"),
            ("domain_id", f"{prefix}_id"),
            ("surface_id", f"{prefix}_id"),
            ("name", f"{prefix}_name"),
            ("surface_type", f"{prefix}_type"),
        ):
            if mapped not in out and value.get(key):
                out[mapped] = value.get(key)
    return out


def _dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strip_internal_stage_fields(task: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in task.items() if not str(key).startswith("_")}


def _safe_id(data: dict[str, Any], key: str, index: int) -> str:
    raw = str(data.get(key) or data.get("id") or index)
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)[:80] or str(index)


def _stage_file_stem(data: dict[str, Any], key: str, index: int) -> str:
    return f"{index:04d}-{_safe_id(data, key, index)}"


def _cancelled(cancel_event) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())
