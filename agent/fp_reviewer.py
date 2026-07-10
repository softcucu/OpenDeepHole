"""False positive reviewer — re-examines confirmed vulnerabilities using opencode.

When the same project has an active scan running (its MCP server is still up),
this module reuses that MCP server and leaves the backend config untouched to
avoid conflicts. When no active scan is found, it starts its own MCP server
and configures the backend in isolation.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from uuid import uuid4

from backend.models import OutputSource, ScanEvent
from backend.opencode.result_json import (
    VULNERABILITY_RESULT_JSON_INSTRUCTION,
    parse_vulnerability_result,
)
from agent.config import effective_fp_review_cli_config


_FP_FEEDBACK_FILE = Path.home() / ".opendeephole" / "fp_feedback.json"
_FP_REVIEW_FEEDBACK: dict[str, list[dict]] = {}
# 每次复核的 git 历史问题模式快照（list[dict]，来自后端 GET .../git_history）
_FP_REVIEW_HISTORY: dict[str, list[dict]] = {}
_FP_REVIEW_SKILLS = ("history-match", "prove-bug", "prove-fp", "final-judge")
_LEGACY_FP_REVIEW_SKILLS = ("fp-review", "fp-review-discriminator")
_FP_STAGE_LABELS = {
    "history_match": "历史/校验匹配",
    "prove_bug": "正方论证",
    "prove_fp": "反方论证",
    "final_judge": "最终裁决",
}
_ISSUE_REPORT_HEADINGS = (
    "Summary",
    "Vulnerable Code",
    "Full Call Stack",
    "Root Cause",
    "Why It is Reachable",
    "Impact",
    "Evidence",
)


@dataclass(frozen=True)
class _FpStageResult:
    session_id: str
    result: object | None
    payload: dict
    markdown: str = ""
    output_source: OutputSource = dataclasses.field(default_factory=OutputSource)


class _FpStageFailure(RuntimeError):
    def __init__(
        self,
        *,
        stage: str,
        session_id: str,
        artifact_path: Path,
        log_path: Path,
        reason: str,
        output_source: OutputSource | None = None,
    ) -> None:
        super().__init__(reason)
        self.stage = stage
        self.session_id = session_id
        self.artifact_path = artifact_path
        self.log_path = log_path
        self.reason = reason
        self.output_source = output_source or OutputSource()


def load_local_feedback() -> dict:
    """Load the local FP feedback file (keyed by vuln_type)."""
    try:
        if _FP_FEEDBACK_FILE.exists():
            return json.loads(_FP_FEEDBACK_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def update_local_feedback(entry: dict) -> None:
    """Add or update an entry in the local FP feedback file."""
    try:
        feedback = load_local_feedback()
        vuln_type = entry.get("vuln_type", "unknown")
        if vuln_type not in feedback:
            feedback[vuln_type] = []
        entry_id = entry.get("id")
        replaced = False
        for index, existing in enumerate(feedback[vuln_type]):
            if entry_id and existing.get("id") == entry_id:
                feedback[vuln_type][index] = entry
                replaced = True
                break
        if not replaced:
            feedback[vuln_type].append(entry)
        _FP_FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        _FP_FEEDBACK_FILE.write_text(
            json.dumps(feedback, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        print(f"Warning: failed to update local FP feedback: {exc}")


def set_fp_review_feedback(scan_id: str, feedback_entries: list[dict]) -> None:
    """Replace the selected feedback snapshot for an active FP review."""
    _FP_REVIEW_FEEDBACK[scan_id] = feedback_entries


def get_fp_review_feedback(scan_id: str) -> list[dict]:
    """Return the latest selected feedback snapshot for an active FP review."""
    return list(_FP_REVIEW_FEEDBACK.get(scan_id, []))


def set_fp_review_history(scan_id: str, patterns: list[dict]) -> None:
    """Store the git-history problem patterns snapshot for an active FP review."""
    _FP_REVIEW_HISTORY[scan_id] = patterns


def get_fp_review_history(scan_id: str) -> list[dict]:
    """Return the git-history problem patterns snapshot for an active FP review."""
    return list(_FP_REVIEW_HISTORY.get(scan_id, []))


def _render_history_patterns(patterns: list[dict]) -> str:
    """Render history patterns as a compact numbered list for the match prompt."""
    lines: list[str] = []
    for i, p in enumerate(patterns, 1):
        source = str(p.get("source") or "").strip()
        pattern = str(p.get("pattern") or "").strip()
        lens = str(p.get("lens_hint") or "").strip()
        files = ", ".join(p.get("files") or []) if isinstance(p.get("files"), list) else ""
        head = f"{i}. [{source or '?'}]"
        if lens:
            head += f"（lens={lens}）"
        lines.append(f"{head} {pattern}" + (f"  涉及文件：{files}" if files else ""))
    return "\n".join(lines)


async def run_fp_review(
    config,
    reporter,
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
    feedback_entries: list[dict] | None = None,
    cancel_event: threading.Event | None = None,
    processed_offset: int = 0,
    finish_on_complete: bool = True,
) -> int:
    """Run FP review for a list of confirmed vulnerabilities.

    Each vulnerability dict: index, file, line, function, vuln_type,
    description, ai_analysis.

    Two modes depending on whether the same project has an active scan:

    Mode A — Active scan found (same project_path in mcp_registry):
      • Reuse the active scan's MCP server (no new process).
      • Do NOT touch the backend config singleton — the active scan owns it.
      • Use the active scan's scan_id as project_id in the opencode prompt so
        that MCP can resolve the code index via projects_dir/scan_id/code_index.db.
      • Result JSONs land in the active scan's scans_dir; UUID keys prevent collision.

    Mode B — No active scan for this project:
      • Start a fresh LocalMCPServer.
      • Bind LocalMCPServer to the directory that contains code_index.db
        (project root or the preserved scan_dir for error/cancelled scans).
      • Configure the backend in isolation: scans_dir = review_dir so result
        JSONs are isolated from any other concurrent scan of a different project.
      • Clean up backend config on exit.
    """
    project = Path(project_path)
    review_dir = Path.home() / ".opendeephole" / "fp_reviews" / review_id
    review_dir.mkdir(parents=True, exist_ok=True)
    set_fp_review_feedback(scan_id, feedback_entries or [])
    processed_reviews = 0

    # 拉取本次扫描挖掘出的 git 历史问题模式，供「历史/校验匹配」阶段使用
    try:
        history_patterns = await reporter.get_git_history(scan_id)
        set_fp_review_history(scan_id, [p.model_dump() for p in history_patterns])
    except Exception:
        set_fp_review_history(scan_id, [])

    # Detect active MCP server for this project
    from agent import mcp_registry
    active = mcp_registry.lookup(project)

    own_mcp_server = None         # only set in Mode B
    workspace: Optional[Path] = None
    _patched_cfg: bool = False    # whether we changed the backend config
    pool_status_stop = asyncio.Event()
    pool_status_task = asyncio.create_task(
        reporter.publish_opencode_pool_until(scan_id, pool_status_stop)
    )

    async def emit(phase: str, message: str) -> None:
        event = ScanEvent.create(phase, message)
        await reporter.send_event(scan_id, event)
        print(f"[fp_review] [{phase}] {message}")

    try:
        if active:
            # ------------------------------------------------------------------
            # Mode A: reuse the active scan's MCP server
            # ------------------------------------------------------------------
            mcp_port, active_scan_id = active
            # project_id tells MCP which code_index.db to open;
            # active scan's config maps: projects_dir/active_scan_id/code_index.db
            project_id_for_prompt = active_scan_id
            await emit("fp_review", f"Reusing active scan MCP (port {mcp_port}) for project '{project_path}'")
        else:
            # ------------------------------------------------------------------
            # Mode B: no active scan — start own MCP, configure backend
            # ------------------------------------------------------------------
            db_dir = _find_db_dir(project, scan_id)
            if db_dir is None:
                raise RuntimeError(
                    f"No code index found for project '{project_path}'. "
                    "The project must have been scanned at least once."
                )

            project_id_for_prompt = scan_id  # DB lookup is bound to this MCP instance.

            # Isolate result JSON files in review_dir (scans_dir = review_dir).
            # Safe because no other scan config is active for this project.
            _configure_fp_backend(config, review_dir)
            _patched_cfg = True

            from agent.local_mcp import LocalMCPServer
            own_mcp_server = LocalMCPServer(project_dir=db_dir)
            mcp_port = own_mcp_server.start()
            await emit("fp_review", f"Started own MCP server on port {mcp_port}")

        await emit("fp_review", f"Starting FP review: {len(vulnerabilities)} confirmed vulnerabilities")

        # Create an isolated config workspace with opencode.json + FP-review skills.
        workspace = _create_fp_workspace(review_dir / "opencode_workspace", mcp_port)
        await emit("fp_review", "FP review workspace ready")

        from backend.models import Candidate

        fp_cli = effective_fp_review_cli_config(config)
        await emit(
            "fp_review",
            "FP review CLI: "
            f"tool={getattr(fp_cli, 'tool', '') or 'opencode'} "
            f"executable={getattr(fp_cli, 'executable', '') or '(default)'} "
            f"model={getattr(fp_cli, 'model', '') or '(default)'} "
            f"timeout={getattr(fp_cli, 'timeout', '')} "
            f"max_retries={getattr(fp_cli, 'max_retries', '')}",
        )

        active_indices: set[int] = set()
        progress_lock = asyncio.Lock()
        review_queue: asyncio.Queue[tuple[int, dict]] = asyncio.Queue()
        for item in enumerate(vulnerabilities):
            review_queue.put_nowait(item)
        review_concurrency = max(1, min(8, len(vulnerabilities) or 1))

        async def review_one(position: int, vuln: dict) -> None:
            nonlocal processed_reviews
            vuln_index = int(vuln["index"])

            await emit(
                "fp_review",
                f"[{position + 1}] Reviewing {vuln['vuln_type'].upper()} "
                f"at {vuln['file']}:{vuln['line']} ({vuln['function']})",
            )
            async with progress_lock:
                active_indices.add(vuln_index)
                await reporter.push_fp_progress(
                    scan_id, review_id, vuln_index, processed_offset + processed_reviews, sorted(active_indices)
                )
            result_submitted = False

            try:
                vuln_workspace = _create_fp_workspace(
                    workspace / str(vuln_index),
                    mcp_port,
                    vuln_type=vuln["vuln_type"],
                    feedback_entries=get_fp_review_feedback(scan_id),
                )
                fake_candidate = Candidate(
                    file=vuln["file"],
                    line=vuln["line"],
                    function=vuln["function"],
                    vuln_type=vuln["vuln_type"],
                    description=vuln["description"],
                )
                artifact_dir = review_dir / "artifacts" / str(vuln_index)
                artifact_dir.mkdir(parents=True, exist_ok=True)
                # Write ai_analysis to file so the prompt references a path
                # instead of inlining the (potentially very long) analysis text.
                ai_analysis_path = artifact_dir / "original-ai-analysis.txt"
                ai_analysis_path.write_text(vuln.get("ai_analysis", ""), encoding="utf-8")
                stage_outputs: dict[str, str] = {}
                stage_output_sources: dict[str, OutputSource] = {}

                # --- Stage 0: 历史/校验匹配 ---
                # 若候选能与某条历史问题模式或其它函数里把校验做对了的站点对应上，
                # 直接判定 high 并跳过三阶段对抗辩论。
                history_patterns = get_fp_review_history(scan_id)
                variant_of = str(vuln.get("variant_of") or "")
                matched_high = False
                if history_patterns or variant_of:
                    current_fp_cli = effective_fp_review_cli_config(config)
                    history_match = await _run_fp_review_stage(
                        stage="history_match",
                        scan_id=scan_id,
                        workspace=vuln_workspace,
                        review_dir=review_dir,
                        review_id=review_id,
                        vuln_index=vuln_index,
                        artifact_dir=artifact_dir,
                        output_markdown_path=artifact_dir / "history-match.md",
                        vuln=vuln,
                        project_id_for_prompt=project_id_for_prompt,
                        timeout=current_fp_cli.timeout,
                        cancel_event=cancel_event,
                        cli_config=current_fp_cli,
                        project=project,
                        candidate=fake_candidate,
                        ai_analysis_path=ai_analysis_path,
                        history_patterns=history_patterns,
                        variant_of=variant_of,
                    )
                    if cancel_event is not None and cancel_event.is_set():
                        return
                    stage_outputs["history_match"] = _stage_markdown_or_placeholder("history_match", history_match)
                    stage_output_sources["history_match"] = (
                        history_match.output_source if history_match is not None else OutputSource()
                    )
                    await reporter.push_fp_stage_output(
                        scan_id,
                        review_id,
                        vuln_index,
                        "history_match",
                        stage_outputs["history_match"],
                        output_source=stage_output_sources["history_match"],
                    )
                    if history_match is not None and history_match.result is not None and history_match.result.confirmed:
                        match_type = str(history_match.payload.get("match_type") or "") or ("history" if variant_of else "history")
                        match_reference = str(history_match.payload.get("match_reference") or variant_of)
                        reason = _stage_reason(history_match) or "命中历史问题模式或其它函数的正确校验，直接判定为 high。"
                        report = _stage_report(history_match)
                        await reporter.push_fp_result(
                            scan_id,
                            review_id,
                            vuln_index,
                            "tp",
                            "high",
                            reason,
                            report,
                            stage_outputs=stage_outputs,
                            match_reference=match_reference,
                            match_type=match_type,
                            stage_output_sources=stage_output_sources,
                            output_source=stage_output_sources["history_match"],
                        )
                        result_submitted = True
                        matched_high = True
                        await emit(
                            "fp_review",
                            f"[{position + 1}] 命中历史/校验匹配（{match_type}）→ HIGH，跳过三阶段辩论",
                        )

                if not matched_high:
                    current_fp_cli = effective_fp_review_cli_config(config)
                    prove_bug = await _run_fp_review_stage(
                        stage="prove_bug",
                        scan_id=scan_id,
                        workspace=vuln_workspace,
                        review_dir=review_dir,
                        review_id=review_id,
                        vuln_index=vuln_index,
                        artifact_dir=artifact_dir,
                        output_markdown_path=artifact_dir / "prove-bug.md",
                        vuln=vuln,
                        project_id_for_prompt=project_id_for_prompt,
                        timeout=current_fp_cli.timeout,
                        cancel_event=cancel_event,
                        cli_config=current_fp_cli,
                        project=project,
                        candidate=fake_candidate,
                        ai_analysis_path=ai_analysis_path,
                    )
                    if cancel_event is not None and cancel_event.is_set():
                        return

                    stage_outputs["prove_bug"] = _stage_markdown_or_placeholder("prove_bug", prove_bug)
                    stage_output_sources["prove_bug"] = prove_bug.output_source if prove_bug is not None else OutputSource()
                    await reporter.push_fp_stage_output(
                        scan_id,
                        review_id,
                        vuln_index,
                        "prove_bug",
                        stage_outputs["prove_bug"],
                        output_source=stage_output_sources["prove_bug"],
                    )

                    if prove_bug is not None and prove_bug.result is not None and not prove_bug.result.confirmed:
                        # 正方论证已判定非问题：正式早退，直接记录误报结果，
                        # 跳过反方论证与最终裁决两个阶段。
                        reason = _stage_reason(prove_bug) or "正方论证未能证明该候选是真实问题。"
                        await reporter.push_fp_result(
                            scan_id,
                            review_id,
                            vuln_index,
                            "fp",
                            "low",
                            reason,
                            "",
                            stage_outputs=stage_outputs,
                            stage_output_sources=stage_output_sources,
                            output_source=stage_output_sources["prove_bug"],
                        )
                        result_submitted = True
                        await emit(
                            "fp_review",
                            f"[{position + 1}] FALSE POSITIVE（正方未证明问题，提前判定误报）severity=low",
                        )
                    else:
                        current_fp_cli = effective_fp_review_cli_config(config)
                        prove_fp = await _run_fp_review_stage(
                            stage="prove_fp",
                            scan_id=scan_id,
                            workspace=vuln_workspace,
                            review_dir=review_dir,
                            review_id=review_id,
                            vuln_index=vuln_index,
                            artifact_dir=artifact_dir,
                            output_markdown_path=artifact_dir / "prove-fp.md",
                            input_markdown_paths=[artifact_dir / "prove-bug.md"],
                            vuln=vuln,
                            project_id_for_prompt=project_id_for_prompt,
                            timeout=current_fp_cli.timeout,
                            cancel_event=cancel_event,
                            cli_config=current_fp_cli,
                            project=project,
                            candidate=fake_candidate,
                            prove_bug=prove_bug,
                            ai_analysis_path=ai_analysis_path,
                        )
                        if cancel_event is not None and cancel_event.is_set():
                            return
                        stage_outputs["prove_fp"] = _stage_markdown_or_placeholder("prove_fp", prove_fp)
                        stage_output_sources["prove_fp"] = prove_fp.output_source if prove_fp is not None else OutputSource()
                        await reporter.push_fp_stage_output(
                            scan_id,
                            review_id,
                            vuln_index,
                            "prove_fp",
                            stage_outputs["prove_fp"],
                            output_source=stage_output_sources["prove_fp"],
                        )

                        current_fp_cli = effective_fp_review_cli_config(config)
                        final_judge = await _run_fp_review_stage(
                            stage="final_judge",
                            scan_id=scan_id,
                            workspace=vuln_workspace,
                            review_dir=review_dir,
                            review_id=review_id,
                            vuln_index=vuln_index,
                            artifact_dir=artifact_dir,
                            output_markdown_path=artifact_dir / "final-judge.md",
                            input_markdown_paths=[
                                artifact_dir / "prove-bug.md",
                                artifact_dir / "prove-fp.md",
                            ],
                            vuln=vuln,
                            project_id_for_prompt=project_id_for_prompt,
                            timeout=current_fp_cli.timeout,
                            cancel_event=cancel_event,
                            cli_config=current_fp_cli,
                            project=project,
                            candidate=fake_candidate,
                            prove_bug=prove_bug,
                            prove_fp=prove_fp,
                            ai_analysis_path=ai_analysis_path,
                        )
                        if cancel_event is not None and cancel_event.is_set():
                            return
                        stage_outputs["final_judge"] = _stage_markdown_or_placeholder("final_judge", final_judge)
                        stage_output_sources["final_judge"] = final_judge.output_source if final_judge is not None else OutputSource()
                        await reporter.push_fp_stage_output(
                            scan_id,
                            review_id,
                            vuln_index,
                            "final_judge",
                            stage_outputs["final_judge"],
                            output_source=stage_output_sources["final_judge"],
                        )

                        if final_judge is None or final_judge.result is None:
                            await emit("fp_review", f"[{position + 1}] Final-judge returned no result — preserving any previous review result")
                        else:
                            verdict, severity, reason, vulnerability_report = _finalize_fp_review_result(final_judge)
                            await reporter.push_fp_result(
                                scan_id,
                                review_id,
                                vuln_index,
                                verdict,
                                severity,
                                reason,
                                vulnerability_report,
                                stage_outputs=stage_outputs,
                                stage_output_sources=stage_output_sources,
                                output_source=stage_output_sources["final_judge"],
                            )
                            result_submitted = True
                            await emit(
                                "fp_review",
                                f"[{position + 1}] {'TRUE POSITIVE' if verdict == 'tp' else 'FALSE POSITIVE'} severity={severity}",
                            )

            except asyncio.CancelledError:
                raise
            except _FpStageFailure as exc:
                markdown = _stage_failure_markdown(exc)
                await reporter.push_fp_stage_output(
                    scan_id,
                    review_id,
                    vuln_index,
                    exc.stage,
                    markdown,
                    output_source=exc.output_source,
                )
                await emit("fp_review", f"[{position + 1}] {exc.stage} failed: {exc.reason}")
            except Exception as exc:
                await emit("fp_review", f"[{position + 1}] Review error: {exc}")

            async with progress_lock:
                processed_reviews += 1
                active_indices.discard(vuln_index)
                await reporter.push_fp_progress(
                    scan_id, review_id, vuln_index, processed_offset + processed_reviews, sorted(active_indices)
                )
                if not result_submitted:
                    await emit("fp_review", f"[{position + 1}] No FP review result saved")

        async def review_worker() -> None:
            while cancel_event is None or not cancel_event.is_set():
                try:
                    position, vuln = review_queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    await review_one(position, vuln)
                finally:
                    review_queue.task_done()

        await asyncio.gather(*(review_worker() for _ in range(review_concurrency)))
        if cancel_event is not None and cancel_event.is_set():
            await emit("fp_review", f"FP review cancelled after reviewing {processed_reviews} items")
            if finish_on_complete:
                await reporter.finish_fp_review(scan_id, review_id, "cancelled", "用户手动停止")
            return processed_reviews

        if finish_on_complete:
            await reporter.finish_fp_review(scan_id, review_id, "complete", None)
            await emit("fp_review", f"FP review complete: {len(vulnerabilities)} vulnerabilities reviewed")
        else:
            await emit("fp_review", f"FP review item complete: {len(vulnerabilities)} vulnerability reviewed")
        return processed_reviews

    except Exception as exc:
        print(f"[fp_review] Error: {exc}")
        try:
            if finish_on_complete:
                await reporter.finish_fp_review(scan_id, review_id, "error", str(exc))
            await emit("fp_review", f"FP review failed: {exc}")
        except Exception:
            pass
        if not finish_on_complete:
            raise
        return processed_reviews

    finally:
        pool_status_stop.set()
        try:
            await pool_status_task
        except Exception:
            pass
        try:
            from backend.opencode.model_pool import clear_completed_tasks
            await clear_completed_tasks(scan_id)
        except Exception:
            pass
        if workspace is not None:
            _cleanup_fp_workspace(workspace)
        if own_mcp_server is not None:
            own_mcp_server.stop()
        if _patched_cfg:
            # Reset the config singleton so the next operation reloads cleanly.
            # Safe here because Mode B only runs when there is no active scan.
            import backend.config as _cfg_mod
            _cfg_mod._config = None
            import backend.registry as _reg_mod
            _reg_mod._registry = None
        _FP_REVIEW_FEEDBACK.pop(scan_id, None)
        _FP_REVIEW_HISTORY.pop(scan_id, None)
        shutil.rmtree(review_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_fp_review_stage(
    *,
    stage: str,
    scan_id: str,
    workspace: Path,
    review_dir: Path,
    review_id: str,
    vuln_index: int,
    artifact_dir: Path,
    output_markdown_path: Path,
    input_markdown_paths: list[Path] | None = None,
    vuln: dict,
    project_id_for_prompt: str,
    timeout: int,
    cancel_event: threading.Event | None,
    cli_config,
    project: Path,
    candidate,
    prove_bug: _FpStageResult | None = None,
    prove_fp: _FpStageResult | None = None,
    ai_analysis_path: Path | None = None,
    history_patterns: list[dict] | None = None,
    variant_of: str = "",
) -> _FpStageResult | None:
    from backend.opencode.runner import (
        _invoke_opencode,
        _read_result_from_source,
        _read_session_result_file,
        _session_id_from_output_source,
        _vulnerability_from_payload,
    )

    max_retries = max(0, int(getattr(cli_config, "max_retries", 0) or 0))
    last_failure: _FpStageFailure | None = None
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex
        submit_tool_name = "submit_match_result" if stage == "history_match" else "json_result"
        uses_json_result = stage != "history_match"

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = source
            last_source = source

        prompt = _build_fp_review_prompt(
            stage=stage,
            vuln=vuln,
            project_id_for_prompt=project_id_for_prompt,
            review_id=review_id,
            vuln_index=vuln_index,
            output_markdown_path=output_markdown_path,
            input_markdown_paths=input_markdown_paths or [],
            prove_bug=prove_bug,
            prove_fp=prove_fp,
            ai_analysis_path=ai_analysis_path,
            history_patterns=history_patterns,
            variant_of=variant_of,
        )
        if attempt > 1:
            if uses_json_result:
                prompt += (
                    "上一次尝试未写入 Markdown 工件或未输出符合 schema 的 JSON。"
                    "即使结论是非问题（confirmed=false），也必须把论证写入指定 Markdown 路径，"
                    "并在最终回复中只输出 JSON 结论。"
                )
            else:
                prompt += (
                    f"上一次尝试未写入 Markdown 工件或未调用 {submit_tool_name}。"
                    "即使结论是非问题（confirmed=false），也必须把论证写入指定 Markdown 路径，"
                    f"并调用 {submit_tool_name} 提交结论。"
                )
        log_path = review_dir / f"fp_{stage}_{attempt_id}.log"

        try:
            try:
                if output_markdown_path.exists():
                    output_markdown_path.unlink()
            except OSError:
                pass
            output_text = await _invoke_opencode(
                workspace,
                prompt,
                timeout,
                log_path=log_path,
                on_line=lambda line: print(f"  [fp_{stage}] {line}", flush=True),
                cancel_event=cancel_event,
                cli_config=cli_config,
                project_dir=project,
                writable_paths=[artifact_dir],
                model_capability="high",
                prefer_high_model=True,
                stats_scope_id=scan_id,
                task_context={
                    "task_type": "fp_review",
                    "review_id": review_id,
                    "stage": stage,
                    "vuln_index": vuln_index,
                    "checker": vuln.get("vuln_type", ""),
                    "file": vuln.get("file", ""),
                    "line": vuln.get("line", 0),
                    "function": vuln.get("function", ""),
                },
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_failure = _FpStageFailure(
                stage=stage,
                session_id=_session_id_from_output_source(attempt_source),
                artifact_path=output_markdown_path,
                log_path=log_path,
                reason=f"CLI invocation failed on attempt {attempt}/{max_retries + 1}: {exc}",
                output_source=attempt_source,
            )
            continue

        markdown = _read_stage_markdown(output_markdown_path)
        payload: dict = {}
        if uses_json_result:
            try:
                payload = parse_vulnerability_result(output_text)
                result = _vulnerability_from_payload(payload, candidate)
            except Exception:
                result = None
        else:
            result = _read_result_from_source(attempt_source, candidate, tool_name=submit_tool_name)
            payload = _read_fp_result_payload(_session_id_from_output_source(attempt_source), submit_tool_name)
        missing: list[str] = []
        if not markdown.strip():
            missing.append("Markdown artifact")
        if result is None:
            missing.append(submit_tool_name)
        if not missing:
            return _FpStageResult(
                session_id=_session_id_from_output_source(attempt_source),
                result=result,
                payload=payload,
                markdown=markdown,
                output_source=attempt_source or OutputSource(),
            )

        last_failure = _FpStageFailure(
            stage=stage,
            session_id=_session_id_from_output_source(attempt_source),
            artifact_path=output_markdown_path,
            log_path=log_path,
            reason=(
                f"Missing {' and '.join(missing)} on attempt "
                f"{attempt}/{max_retries + 1}"
            ),
            output_source=attempt_source,
        )

    if last_failure is not None:
        raise last_failure
    raise _FpStageFailure(
        stage=stage,
        session_id="",
        artifact_path=output_markdown_path,
        log_path=review_dir,
        reason="Stage did not run",
        output_source=last_source,
    )


def _build_fp_review_prompt(
    *,
    stage: str,
    vuln: dict,
    project_id_for_prompt: str,
    review_id: str = "",
    vuln_index: int = 0,
    output_markdown_path: Path | None = None,
    input_markdown_paths: list[Path] | None = None,
    prove_bug: _FpStageResult | None = None,
    prove_fp: _FpStageResult | None = None,
    ai_analysis_path: Path | None = None,
    history_patterns: list[dict] | None = None,
    variant_of: str = "",
) -> str:
    output_path = str(output_markdown_path.resolve()) if output_markdown_path else ""
    input_paths = [str(path.resolve()) for path in input_markdown_paths or []]
    ai_analysis_ref = (
        f"原始 AI 分析保存在文件 `{ai_analysis_path.resolve()}` 中，请自行读取。"
        if ai_analysis_path
        else f"原始 AI 分析：{vuln['ai_analysis']} "
    )
    if stage == "history_match":
        patterns_text = _render_history_patterns(history_patterns or [])
        variant_hint = (
            f"该候选由同类变体排查命中，疑似对应历史问题：{variant_of}。"
            f"请优先核实它与该历史问题是否同根因。"
            if variant_of else ""
        )
        prompt = (
            f"使用 `history-match` 技能，判断位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选能否与**历史问题模式**或**其它函数里把校验做对了的站点**对应上。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"review_id 为 `{review_id}`，vuln_index 为 `{vuln_index}`。"
            f"原始描述：{vuln['description']} "
            f"{ai_analysis_ref}"
            f"{variant_hint}"
            f"已挖掘的历史问题模式列表（可用 git show <出处提交> 复核根因）：\n{patterns_text or '（无）'}\n"
            f"判断标准（满足任一即视为匹配）：(a) 与某条历史问题模式**同根因**（同缺陷类型、同触发条件）；"
            f"(b) 全仓存在对**同一被调点/危险原语**把校验做对了的另一处调用站点，而本候选缺失该校验。"
            f"你必须将本阶段 Markdown 论证写入 `{output_path}`，不得写入其它路径。"
            f"分析完成后，你**必须**调用 `submit_match_result` MCP 工具提交结论："
            f"matched=true 表示对应上（match_type 填 history 或 validation，match_reference 填"
            f"历史模式根因摘要+出处提交，或正确校验站点 path:line + 一句话说明，并提交 vulnerability_report，"
            f"包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、Why It is Reachable、Impact、Evidence 七个二级标题）；"
            f"matched=false 表示无法对应（此时会转入三阶段辩论，不要勉强匹配）。不要使用 CVSS 打分。"
        )
    elif stage == "prove_bug":
        prompt = (
            f"使用 `prove-bug` 技能，作为正方论证位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选是否是真实问题。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"review_id 为 `{review_id}`，vuln_index 为 `{vuln_index}`。"
            f"原始描述：{vuln['description']} "
            f"{ai_analysis_ref}"
            f"你必须将本阶段 Markdown 论证写入 `{output_path}`，不得写入其它路径。"
            f"分析完成后，你必须在最终回复中输出 JSON 阶段结论，不要调用 submit_result。"
            f"默认假设代码是安全的；只有证明真实代码问题时才使用 confirmed=true。"
            f"severity 只分两档：外部可触发的问题使用 high；其余（无法证明外部可触发或非问题）一律使用 low。"
            f"只要 confirmed=true，"
            f"都必须在 vulnerability_report 中提交 Markdown 问题报告，"
            f"并包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、"
            f"Why It is Reachable、Impact、Evidence 七个二级标题。不要使用 CVSS 打分。"
            f"{VULNERABILITY_RESULT_JSON_INSTRUCTION}"
        )
    elif stage == "prove_fp":
        bug_summary = _stage_result_summary(prove_bug)
        prove_bug_path = input_paths[0] if input_paths else ""
        prompt = (
            f"使用 `prove-fp` 技能，作为反方论证位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选是否不是问题。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"review_id 为 `{review_id}`，vuln_index 为 `{vuln_index}`。"
            f"原始描述：{vuln['description']} "
            f"{ai_analysis_ref}"
            f"正方阶段结构化摘要：{bug_summary} "
            f"你必须先读取正方 Markdown 文件 `{prove_bug_path}`，再进行反方论证。"
            f"你必须将本阶段 Markdown 论证写入 `{output_path}`，不得写入其它路径。"
            f"分析完成后，你必须在最终回复中输出 JSON 阶段结论，不要调用 submit_result。"
            f"如果找到足以证明非问题的理由，使用 confirmed=false 且 severity=low。"
            f"如果反方未能证明非问题，仍使用 confirmed=true；severity 只分两档："
            f"外部可触发为 high，其余一律为 low。"
            f"只要 confirmed=true，"
            f"都必须提交 vulnerability_report，可沿用或修正 prove-bug 的报告。不要使用 CVSS 打分。"
            f"{VULNERABILITY_RESULT_JSON_INSTRUCTION}"
        )
    elif stage == "final_judge":
        bug_summary = _stage_result_summary(prove_bug)
        fp_summary = _stage_result_summary(prove_fp)
        bug_path = input_paths[0] if input_paths else ""
        fp_path = input_paths[1] if len(input_paths) > 1 else ""
        prompt = (
            f"使用 `final-judge` 技能，作为最终裁决 Agent，汇总位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"review_id 为 `{review_id}`，vuln_index 为 `{vuln_index}`。"
            f"原始描述：{vuln['description']} "
            f"{ai_analysis_ref}"
            f"正方阶段结构化摘要：{bug_summary} "
            f"反方阶段结构化摘要：{fp_summary} "
            f"你必须读取正方 Markdown 文件 `{bug_path}` 和反方 Markdown 文件 `{fp_path}`。"
            f"你必须将最终裁决 Markdown 写入 `{output_path}`，不得写入其它路径。"
            f"分析完成后，你必须在最终回复中输出 JSON 最终结论，不要调用 submit_result。"
            f"最终 confirmed=false 表示误报；confirmed=true 表示真实问题。"
            f"severity 只分两档：论证为外部可触发的问题使用 high；其余（无法证明外部可触发或非问题）一律使用 low。"
            f"最终 ai_analysis 必须像 memleak 输出一样包含完整代码链、关键代码片段和说明，"
            f"让读者不重新查看代码也能判断结论。"
            f"只要 confirmed=true，"
            f"都必须提交 vulnerability_report，包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、"
            f"Why It is Reachable、Impact、Evidence 七个二级标题。不要使用 CVSS 打分。"
            f"{VULNERABILITY_RESULT_JSON_INSTRUCTION}"
        )
    else:
        raise ValueError(f"Unknown FP review stage: {stage}")
    return prompt.replace("\n", " ")


def _find_db_dir(project_path: Path, scan_id: str) -> Optional[Path]:
    """Find the directory that contains code_index.db for this project.

    code_index.db is stored directly in the project directory.
    """
    resolved = project_path.resolve()
    if (resolved / "code_index.db").exists():
        return resolved
    return None


def _configure_fp_backend(config, review_dir: Path) -> None:
    """Write a temporary backend config and reset singletons.

    Sets scans_dir = review_dir so legacy submit tools write into review_dir
    when a retained stage still uses one.
    Only called in Mode B (no active scan for the project).
    """
    import yaml

    opencode_config = dataclasses.asdict(config.opencode)
    opencode_config["mock"] = False
    raw = {
        "llm_api": {
            "enabled": True,
            "base_url": config.llm_api.base_url,
            "api_key": config.llm_api.api_key,
            "model": config.llm_api.model,
            "temperature": config.llm_api.temperature,
            "timeout": config.llm_api.timeout,
            "max_retries": config.llm_api.max_retries,
            "stream": config.llm_api.stream,
        },
        "opencode": opencode_config,
        "opencode_concurrency": config.opencode_concurrency,
        "storage": {
            # Source DB lookup is bound to the local MCP instance in Mode B.
            "projects_dir": str(review_dir),
            "scans_dir": str(review_dir),
        },
        "logging": {
            "level": "INFO",
            "file": str(review_dir / "fp_review.log"),
        },
        "mcp_server": {
            "port": 8100,
        },
        "no_proxy": config.no_proxy,
    }
    if config.fp_review_cli is not None:
        fp_review_cli_config = dataclasses.asdict(config.fp_review_cli)
        fp_review_cli_config["mock"] = False
        raw["fp_review_cli"] = fp_review_cli_config
    config_path = review_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)

    import backend.config as _cfg
    _cfg._config = None
    import backend.registry as _reg
    _reg._registry = None


def _normalize_fp_severity(severity: str, verdict: str) -> str:
    # 去误报定级简化为二元：外部可触发 → high，其余 → low。
    normalized = (severity or "").strip().lower()
    if verdict == "fp":
        return "low"
    if normalized == "high":
        return "high"
    return "low"


def _finalize_fp_review_result(final_judge: _FpStageResult) -> tuple[str, str, str, str]:
    if final_judge.result is None:
        raise ValueError("Final-judge returned no JSON result")
    result = final_judge.result
    verdict = "tp" if result.confirmed else "fp"
    severity = _normalize_fp_severity(str(result.severity), verdict)
    report = _stage_report(final_judge)
    if verdict == "fp":
        severity = "low"
        report = ""
    reason = _stage_reason(final_judge) or result.description or "Final-judge 未提供详细推理。"
    return verdict, severity, reason, report


def _stage_report(stage_result: _FpStageResult) -> str:
    return str(stage_result.payload.get("vulnerability_report") or "")


def _stage_reason(stage_result: _FpStageResult) -> str:
    if stage_result.result is None:
        return ""
    result = stage_result.result
    return str(result.ai_analysis or result.description or "").strip()


def _stage_result_summary(stage_result: _FpStageResult | None) -> str:
    if stage_result is None or stage_result.result is None:
        return "未提交结构化阶段结论。"
    result = stage_result.result
    verdict = "confirmed=true" if result.confirmed else "confirmed=false"
    description = str(result.description or "").replace("\n", " ")[:800]
    return f"{verdict}, severity={result.severity}, description={description}"


def _read_stage_markdown(path: Path) -> str:
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8")
    except Exception:
        pass
    return ""


def _stage_markdown_or_placeholder(stage: str, stage_result: _FpStageResult | None) -> str:
    markdown = stage_result.markdown if stage_result is not None else ""
    if markdown.strip():
        return markdown
    label = _FP_STAGE_LABELS.get(stage, stage)
    return (
        f"# {label}\n\n"
        "本阶段未生成 Markdown 输出。\n\n"
        "## 状态\n\n"
        "阶段进程已结束，但未在指定 artifact 文件中写入内容。\n"
    )


def _stage_failure_markdown(exc: _FpStageFailure) -> str:
    label = _FP_STAGE_LABELS.get(exc.stage, exc.stage)
    return (
        f"# {label}\n\n"
        "本阶段未生成有效 Markdown 输出。\n\n"
        "## 状态\n\n"
        "阶段执行失败，后续依赖该 artifact 的 FP 复核阶段已跳过。\n\n"
        "## 失败原因\n\n"
        f"{exc.reason}\n\n"
        "## 调试信息\n\n"
        f"- stage: `{exc.stage}`\n"
        f"- session_id: `{exc.session_id}`\n"
        f"- artifact: `{exc.artifact_path}`\n"
        f"- log: `{exc.log_path}`\n"
    )


def _has_required_issue_report_sections(report: str) -> bool:
    if not report.strip():
        return False
    lowered_lines = [line.strip().lower() for line in report.splitlines()]
    for heading in _ISSUE_REPORT_HEADINGS:
        expected = f"## {heading}".lower()
        if not any(line == expected or line.startswith(expected + " ") for line in lowered_lines):
            return False
    return True


def _dummy_candidate():
    from backend.models import Candidate

    return Candidate(file="", line=0, function="", description="", vuln_type="fp_review")


def _read_fp_result_payload(session_id: str, tool_name: str) -> dict:
    """Read optional FP review fields that are not part of Vulnerability."""
    try:
        from backend.opencode.runner import _read_session_result_file

        payload = _read_session_result_file(session_id, candidate=_dummy_candidate(), tool_name=tool_name)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _create_fp_workspace(
    workspace: Path,
    mcp_port: int,
    vuln_type: str | None = None,
    feedback_entries: list[dict] | None = None,
) -> Path:
    """Ensure isolated opencode config and FP-review skills exist."""
    from backend.opencode.config import build_opencode_config, get_workspace_lock
    from backend.opencode.feedback_format import format_feedback_experience

    with get_workspace_lock(workspace):
        workspace.mkdir(parents=True, exist_ok=True)
        skills_root = (workspace / ".opencode" / "skills").resolve()
        (workspace / "opencode.json").write_text(
            json.dumps(
                build_opencode_config(
                    f"http://127.0.0.1:{mcp_port}/mcp",
                    [str(skills_root)],
                ),
                indent=2,
            ),
            encoding="utf-8",
        )

        matching_feedback = [
            entry for entry in feedback_entries or []
            if not vuln_type or entry.get("vuln_type") == vuln_type
        ]
        fp_section = format_feedback_experience(matching_feedback)
        _write_fp_skill(
            workspace,
            "history-match",
            Path(__file__).parent / "skills" / "fp_review_match.md",
            fp_section,
        )
        _write_fp_skill(
            workspace,
            "prove-bug",
            Path(__file__).parent / "skills" / "fp_review.md",
            fp_section,
        )
        _write_fp_skill(
            workspace,
            "prove-fp",
            Path(__file__).parent / "skills" / "fp_review_discriminator.md",
            fp_section,
        )
        _write_fp_skill(
            workspace,
            "final-judge",
            Path(__file__).parent / "skills" / "fp_review_final.md",
            fp_section,
        )

    return workspace


def _write_fp_skill(workspace: Path, skill_name: str, skill_src: Path, fp_section: str) -> None:
    skills_dir = workspace / ".opencode" / "skills" / skill_name
    skills_dir.mkdir(parents=True, exist_ok=True)
    content = skill_src.read_text(encoding="utf-8")
    if fp_section:
        content = content.rstrip() + (
            "\n\n## 历史用户经验\n\n"
            "以下是用户在审计过程中选择注入的经验，"
            "复核时应结合这些经验校验结论：\n"
            + fp_section
        )
    (skills_dir / "SKILL.md").write_text(content, encoding="utf-8")


def _cleanup_fp_workspace(workspace: Path) -> None:
    """Remove FP review artifacts written into the isolated config workspace."""
    from backend.opencode.config import get_workspace_lock

    with get_workspace_lock(workspace):
        if workspace.name == "opencode_workspace":
            shutil.rmtree(workspace, ignore_errors=True)
            return

        try:
            for skill_name in (*_FP_REVIEW_SKILLS, *_LEGACY_FP_REVIEW_SKILLS):
                fp_skill_dir = workspace / ".opencode" / "skills" / skill_name
                if fp_skill_dir.is_dir():
                    shutil.rmtree(fp_skill_dir)
            for root in (workspace / ".claude" / "skills", workspace / ".gemini" / "skills"):
                for skill_name in (*_FP_REVIEW_SKILLS, *_LEGACY_FP_REVIEW_SKILLS):
                    copied_fp_skill = root / skill_name
                    if copied_fp_skill.is_dir():
                        shutil.rmtree(copied_fp_skill)
                if root.is_dir() and not any(root.iterdir()):
                    root.rmdir()
            claude_mcp = workspace / ".claude" / "opendeephole-mcp.json"
            if claude_mcp.exists():
                claude_mcp.unlink()
            claude_dir = workspace / ".claude"
            if claude_dir.is_dir() and not any(claude_dir.iterdir()):
                claude_dir.rmdir()
            skills_dir = workspace / ".opencode" / "skills"
            if skills_dir.is_dir() and not any(skills_dir.iterdir()):
                skills_dir.rmdir()
            oc_dir = workspace / ".opencode"
            if oc_dir.is_dir() and not any(oc_dir.iterdir()):
                oc_dir.rmdir()
            opencode_json = workspace / "opencode.json"
            if opencode_json.exists() and not oc_dir.exists():
                opencode_json.unlink()
        except Exception:
            pass
