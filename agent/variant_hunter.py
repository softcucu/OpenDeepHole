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

EmitFn = Callable[[str, str], Awaitable[None]]


def _ensure_skill(workspace: Path) -> None:
    skill_src = Path(__file__).parent / "skills" / "variant_hunt.md"
    skill_dir = workspace / ".opencode" / "skills" / "variant-hunt"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        skill_src.read_text(encoding="utf-8"), encoding="utf-8"
    )


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
        "- 对**坐实**的站点，调用 `submit_variant_finding` 提交（每处一次，可多次调用）；\n"
        "- 已修复或不满足相似条件的站点不要提交。\n\n"
        f"`vuln_type` 必须从以下可选检查项中选最贴切的一个：{checkers}。\n"
        "若全仓未发现同类缺陷，可以不调用提交工具直接结束。"
    )


async def hunt_variants(
    *,
    config,
    patterns: list[HistoryPattern],
    project_path: Path,
    code_scan_path: Path,
    workspace: Path,
    scan_id: str,
    checker_types: list[str],
    cancel_event: Optional[threading.Event],
    emit: EmitFn,
    cli_config,
) -> list[Candidate]:
    """对每条历史问题模式做全仓同类变体排查，返回命中候选列表。"""
    from backend.opencode.runner import (
        _invoke_opencode,
        _read_session_result_file,
        _result_payloads,
        _session_id_from_output_source,
    )
    from backend.opencode.model_pool import total_model_capacity

    if not patterns:
        return []

    await emit("variant_hunt", f"开始对 {len(patterns)} 条历史问题模式做同类变体排查...")
    _ensure_skill(workspace)

    found: list[Candidate] = []
    seen: set[tuple[str, int, str]] = set()
    lock = asyncio.Lock()
    processed = 0
    valid_types = set(checker_types)
    scan_dir = workspace.parent

    capacity = total_model_capacity(
        cli_config, global_concurrency=config.opencode_concurrency, required_capability="any"
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
        attempt_source = None

        def capture_source(source) -> None:
            nonlocal attempt_source
            attempt_source = source

        fake_candidate = Candidate(
            file="", line=0, function="", description=pattern.pattern,
            vuln_type="variant",
        )
        try:
            await _invoke_opencode(
                workspace,
                prompt,
                int(getattr(cli_config, "timeout", 1200) or 1200),
                log_path=log_path,
                on_line=lambda line: print(f"  [variant_hunt] {line}", flush=True),
                cancel_event=cancel_event,
                cli_config=cli_config,
                project_dir=project_path,
                model_capability="any",
                stats_scope_id=scan_id,
                on_invocation_metadata=capture_source,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"  [variant_hunt] 排查失败: {exc}", flush=True)
            return
        finally:
            try:
                log_path.unlink(missing_ok=True)
            except Exception:
                pass

        payload = _read_session_result_file(
            _session_id_from_output_source(attempt_source),
            fake_candidate,
            tool_name="submit_variant_finding",
        )
        if payload is None:
            payload = {}

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

    await asyncio.gather(*(_worker() for _ in range(concurrency)))
    await emit("variant_hunt", f"同类变体排查完成：共命中 {len(found)} 处候选")
    return found
