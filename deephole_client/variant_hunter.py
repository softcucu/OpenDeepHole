"""同类变体排查。

迁移自 SecAnt 的 variant recheck：对 git 历史挖掘出的**每条问题模式**派一个 agent，
理解其根因后在**全仓搜索同类代码模式**，逐一核实是否存在相同/相似缺陷，把坐实的
站点产出为新候选（Candidate），并回填 `variant_of`（来源历史问题模式）。

产出的候选并入静态分析候选集，统一进入 AI 审计与去误报；因带 `variant_of`，去误报
阶段的「历史匹配」会直接将其定级为 high。
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Awaitable, Callable, Optional
from uuid import uuid4

from backend.models import Candidate, HistoryPattern
from task_agent import run_opencode_task
from task_agent.output_format import with_local_timestamp
from task_agent.task_service import (
    bind_opencode_execution_context,
    get_opencode_execution_context,
)

EmitFn = Callable[[str, str], Awaitable[None]]

_VARIANT_FINDINGS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "description": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["file", "line", "function", "vuln_type", "description", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}


def _build_prompt(
    pattern: HistoryPattern,
    checker_types: list[str],
    project_id: str,
) -> str:
    files = ", ".join(pattern.files) if pattern.files else "(自行定位)"
    checkers = ", ".join(checker_types) if checker_types else "(无)"
    return (
        "使用 `variant-hunt` 技能，对一条 git 历史问题模式做**同类变体排查**。\n"
        f"project_id 为 `{project_id}`。\n"
        f"历史问题模式：{pattern.pattern}\n"
        f"出处提交：{pattern.source or '?'}　涉及文件：{files}\n"
        f"安全视角(lens)：{pattern.lens_hint or '未标注'}\n\n"
        "任务：理解该历史问题的根因后，在**全仓搜索同类代码模式**（用 grep/glob 枚举全仓"
        "同类站点，并阅读函数体核实），逐一判断是否存在相同或相似缺陷。"
        "这是有的放矢的定向排查，不是盲扫。\n"
        "- 逐一核实每个候选站点：该站点是否缺少历史修复所加的校验/夹紧/判空等不变量，"
        "从而存在同类缺陷；\n"
        "- 对**坐实**的站点，在最终 JSON 的 results 数组返回一项；\n"
        "- 已修复或不满足相似条件的站点不要返回。\n\n"
        f"`vuln_type` 必须从以下可选检查项中选最贴切的一个：{checkers}。\n"
        "若全仓未发现同类缺陷，返回空 results 数组。"
    )


async def hunt_variants(
    *,
    config,
    patterns: list[HistoryPattern],
    project_path: Path,
    code_scan_path: Path,
    scan_id: str,
    checker_types: list[str],
    cancel_event: Optional[threading.Event],
    emit: EmitFn,
) -> list[Candidate]:
    """对每条历史问题模式做全仓同类变体排查，返回命中候选列表。"""
    from deephole_client.opencode_workflows import _result_payloads
    from task_agent.model_pool import (
        NO_AVAILABLE_MODEL_MESSAGE,
        NoAvailableModelError,
        total_model_capacity,
    )

    if not patterns:
        return []

    await emit("variant_hunt", f"开始对 {len(patterns)} 条历史问题模式做同类变体排查...")
    found: list[Candidate] = []
    seen: set[tuple[str, int, str]] = set()
    lock = asyncio.Lock()
    processed = 0
    valid_types = set(checker_types)
    execution_context = get_opencode_execution_context()
    if execution_context.work_dir is None:
        raise RuntimeError("variant_hunt requires an Agent-bound OpenCode work_dir")
    scan_root = execution_context.work_dir
    scan_dir = scan_root / "logs"
    scan_dir.mkdir(parents=True, exist_ok=True)

    capacity = total_model_capacity(
        config.opencode,
        global_concurrency=config.opencode_concurrency,
        required_capability="low",
    )
    concurrency = max(1, min(capacity, len(patterns)))

    queue: asyncio.Queue[HistoryPattern] = asyncio.Queue()
    for p in patterns:
        queue.put_nowait(p)

    async def _hunt_one(pattern: HistoryPattern) -> None:
        nonlocal processed
        if cancel_event is not None and cancel_event.is_set():
            return
        attempt_id = uuid4().hex
        prompt = _build_prompt(pattern, checker_types, scan_id)
        log_path = scan_dir / f"variant_hunt_{attempt_id}.log"

        try:
            with bind_opencode_execution_context(
                project_dir=project_path,
                work_dir=scan_root,
                task_metadata={"pattern_source": pattern.source},
                on_output=lambda line: print(
                    with_local_timestamp(line, prefix="[variant_hunt]"),
                    flush=True,
                ),
                cancel_event=cancel_event,
            ):
                result = await run_opencode_task(
                    task_name=f"同类变体排查 {pattern.source or pattern.pattern[:30]}",
                    task_type="variant_hunt",
                    prompt=prompt,
                    required_capability="low",
                    output_schema=_VARIANT_FINDINGS_JSON_SCHEMA,
                )
            if result.status == "timeout":
                raise asyncio.TimeoutError(result.text)
            if result.status == "failure":
                if result.text == NO_AVAILABLE_MODEL_MESSAGE:
                    raise NoAvailableModelError()
                raise RuntimeError(result.text)
            payload = result.structured if isinstance(result.structured, dict) else {}
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            print(f"  [variant_hunt] 排查失败: {exc}", flush=True)
            return
        finally:
            try:
                log_path.unlink(missing_ok=True)
            except Exception:
                pass

        variant_ref = (
            f"{pattern.pattern}（出处：{pattern.source}）" if pattern.source else pattern.pattern
        )
        async with lock:
            processed += 1
            hits = 0
            for item in _result_payloads(payload):
                if item.get("kind") not in (None, "variant_finding"):
                    continue
                file = str(item.get("file") or "").strip()
                function = str(item.get("function") or "").strip()
                try:
                    line = int(item.get("line") or 0)
                except (TypeError, ValueError):
                    line = 0
                vuln_type = str(item.get("vuln_type") or "").strip()
                if not file or not vuln_type:
                    continue
                if valid_types and vuln_type not in valid_types:
                    # 归一到列表里第一个，避免命中无对应 checker 而被丢弃
                    vuln_type = checker_types[0]
                dedup_key = (file, line, function)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                description = str(item.get("description") or "").strip() or pattern.pattern
                found.append(Candidate(
                    file=file,
                    line=line,
                    function=function,
                    description=f"[同类变体排查] {description}",
                    vuln_type=vuln_type,
                    metadata={
                        "variant_of": variant_ref,
                        "match_type": "history",
                        "match_reference": variant_ref,
                        "variant_rationale": str(item.get("rationale") or ""),
                    },
                ))
                hits += 1
            if hits:
                await emit(
                    "variant_hunt",
                    f"[{processed}/{len(patterns)}] 模式「{pattern.source or pattern.pattern[:30]}」命中 {hits} 处同类站点",
                )

    async def _worker() -> None:
        while cancel_event is None or not cancel_event.is_set():
            try:
                pattern = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await _hunt_one(pattern)
            finally:
                queue.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    except NoAvailableModelError:
        if cancel_event is not None:
            cancel_event.set()
        for worker in workers:
            if not worker.done():
                worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise
    await emit("variant_hunt", f"同类变体排查完成：共命中 {len(found)} 处候选")
    return found
