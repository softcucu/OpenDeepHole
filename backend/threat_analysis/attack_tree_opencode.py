"""OpenCode runner for the built-in attack-tree threat-analysis implementation."""

from __future__ import annotations

import asyncio
import inspect
import json
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


class _StageOutputError(RuntimeError):
    """Raised when a threat-analysis stage did not write a usable JSON object."""


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
    tool = opencode_runner._normalize_tool(config.opencode)
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
            f"[{tool}] 产品信息 MCP `{product_mcp_name or '未配置'}` 检测结果：{status}"
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

    await _invoke_stage(
        opencode_runner=opencode_runner,
        workspace=workspace,
        analysis_root=analysis_root,
        run_dir=run_dir,
        skill_name="threat-asset-interface-agent",
        input_path=base_input_path,
        output_path=base_output_path,
        timeout=effective_timeout,
        on_output=on_output,
        cancel_event=cancel_event,
        planned_task_id=planned_task_id,
        stats_scope_id=project_id,
        attempt=1,
        task_label="基础资产与接口建模",
    )
    base_output = read_json_object(base_output_path)
    await append_attack_paths(base_output)

    attack_goals = _attack_goals_from_base_output(base_output)[:_MAX_GOALS]
    goal_concurrency = _stage_concurrency(config, len(attack_goals))
    if on_output and len(attack_goals) > 1:
        on_output(f"[threat-analysis] 攻击目标分解并发度：{goal_concurrency}/{len(attack_goals)}")

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
            task_label=f"攻击目标分解 {index}/{len(attack_goals)}",
        )
        return read_json_object(output_path)

    goal_outputs = await _run_stage_batch(
        attack_goals,
        concurrency=goal_concurrency,
        run_one=_run_goal_stage,
    )

    domain_tasks: list[dict[str, Any]] = []
    for goal, goal_output in zip(attack_goals, goal_outputs):
        for domain in _dict_items(goal_output.get("domains")):
            domain_tasks.append({"attack_goal": goal, "attack_domain": domain})
            if len(domain_tasks) >= _MAX_DOMAINS:
                break
        if len(domain_tasks) >= _MAX_DOMAINS:
            break

    domain_concurrency = _stage_concurrency(config, len(domain_tasks))
    if on_output and len(domain_tasks) > 1:
        on_output(f"[threat-analysis] 攻击域分析并发度：{domain_concurrency}/{len(domain_tasks)}")

    async def _run_domain_stage(index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        domain = task["attack_domain"]
        input_path = contexts_dir / "domain" / f"{_stage_file_stem(domain, 'domain_id', index)}.input.json"
        output_path = stages_dir / "domain" / f"{_stage_file_stem(domain, 'domain_id', index)}.output.json"
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **task,
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
            attempt=index,
            task_label=f"攻击域分析 {index}/{len(domain_tasks)}",
        )
        return read_json_object(output_path)

    domain_outputs = await _run_stage_batch(
        domain_tasks,
        concurrency=domain_concurrency,
        run_one=_run_domain_stage,
    )

    surface_tasks: list[dict[str, Any]] = []
    for task, domain_output in zip(domain_tasks, domain_outputs):
        for surface in _dict_items(domain_output.get("surfaces")):
            surface_tasks.append({**task, "attack_surface": surface})
            if len(surface_tasks) >= _MAX_SURFACES:
                break
        if len(surface_tasks) >= _MAX_SURFACES:
            break

    surface_concurrency = _stage_concurrency(config, len(surface_tasks))
    if on_output and len(surface_tasks) > 1:
        on_output(f"[threat-analysis] 攻击面分析并发度：{surface_concurrency}/{len(surface_tasks)}")

    async def _run_surface_stage(index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        surface = task["attack_surface"]
        input_path = contexts_dir / "surface" / f"{_stage_file_stem(surface, 'surface_id', index)}.input.json"
        output_path = stages_dir / "surface" / f"{_stage_file_stem(surface, 'surface_id', index)}.output.json"
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **task,
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
            attempt=index,
            task_label=f"攻击面分析 {index}/{len(surface_tasks)}",
        )
        surface_output = read_json_object(output_path)
        await append_attack_paths(surface_output, defaults=task)
        return surface_output

    surface_outputs = await _run_stage_batch(
        surface_tasks,
        concurrency=surface_concurrency,
        run_one=_run_surface_stage,
    )

    confirmation_tasks: list[dict[str, Any]] = []
    for task, surface_output in zip(surface_tasks, surface_outputs):
        for method_task in _dict_items(surface_output.get("method_confirmation_tasks")):
            confirmation_tasks.append({**task, "method_confirmation_task": method_task})
            if len(confirmation_tasks) >= _MAX_CONFIRMATIONS:
                break
        if len(confirmation_tasks) >= _MAX_CONFIRMATIONS:
            break

    confirmation_concurrency = _stage_concurrency(config, len(confirmation_tasks))
    if on_output and len(confirmation_tasks) > 1:
        on_output(f"[threat-analysis] 方法确认并发度：{confirmation_concurrency}/{len(confirmation_tasks)}")

    async def _run_confirmation_stage(index: int, task: dict[str, Any]) -> dict[str, Any]:
        if _cancelled(cancel_event):
            return {}
        method_task = task["method_confirmation_task"]
        input_path = contexts_dir / "method" / f"{_stage_file_stem(method_task, 'task_id', index)}.input.json"
        output_path = stages_dir / "method" / f"{_stage_file_stem(method_task, 'task_id', index)}.output.json"
        write_json(input_path, {
            "project_id": project_id,
            "product": product,
            "scan_scope": scan_scope.model_dump(),
            "code_index_path": repo_index_path.as_posix(),
            "product_mcp": mcp_detection,
            "base_model": base_output,
            **task,
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
            attempt=index,
            task_label=f"方法确认 {index}/{len(confirmation_tasks)}",
        )
        method_output = read_json_object(output_path)
        await append_attack_paths(method_output, defaults=task)
        return method_output

    await _run_stage_batch(
        confirmation_tasks,
        concurrency=confirmation_concurrency,
        run_one=_run_confirmation_stage,
    )

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
            f"[{tool}] 威胁分析归并完成：attack_paths={len(analysis.attack_paths)} "
            f"assets={len(analysis.assets)} output={result_path}"
        )
    return parse_threat_analysis_file(result_path)


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
            on_output(f"[threat-analysis] {task_label}: {skill_name}{retry_note}")
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
                f"[threat-analysis] {task_label} 第 {stage_attempt}/{max_attempts} 次失败："
                f"{last_error}，准备重试..."
            )
    failure = str(last_error or "unknown error")
    if on_output:
        on_output(
            f"[threat-analysis] {task_label} 失败，已重试 {_STAGE_FAILURE_RETRIES} 次，"
            f"继续后续可用结果：{failure}"
        )
    write_json(output_path, {"error": failure})


def _validate_stage_output(skill_name: str, output: dict[str, Any]) -> None:
    if not output:
        raise _StageOutputError("stage output is empty")
    if output.get("error"):
        raise _StageOutputError(str(output.get("error")))
    required_list_fields = {
        "threat-asset-interface-agent": [
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
        "不得修改输出 JSON 文件之外的任何项目文件。\n"
    )
    if skill_name == "threat-asset-interface-agent":
        prompt += (
            "本阶段允许在主 Agent 内调用只读子 Agent 做交叉分析："
            "`threat-asset-enumerator`、`threat-attack-goal-enumerator`、"
            "`threat-code-evidence-mapper`。"
            "代码量较大时，可以按顶层目录、主要语言、外部入口类型、协议/接口族或 MCP 产品模块"
            "派发多个 `threat-asset-enumerator` 分片实例，再由主 Agent 合并去重。"
            "资产/风险、候选路径或接口较多时，也可以按资产组、风险类型、接口族或候选路径组"
            "派发多个 `threat-attack-goal-enumerator` 和 `threat-code-evidence-mapper` 分片实例；"
            "不要按资产×接口×风险做笛卡尔积派发。"
            "如果当前运行环境没有子 Agent/Task 能力，主 Agent 必须按相同三个角色自行完成分析。\n"
        )
    return prompt


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
            risk_name = str(risk.get("name") or "关键风险")
            asset_name = str(asset.get("name") or asset_id)
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


def _safe_id(data: dict[str, Any], key: str, index: int) -> str:
    raw = str(data.get(key) or data.get("id") or index)
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)[:80] or str(index)


def _stage_file_stem(data: dict[str, Any], key: str, index: int) -> str:
    return f"{index:04d}-{_safe_id(data, key, index)}"


def _cancelled(cancel_event) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())
