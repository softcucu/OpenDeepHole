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
from task_agent import run_opencode_task
from task_agent.model_pool import NO_AVAILABLE_MODEL_MESSAGE, NoAvailableModelError
from task_agent.output_format import with_local_timestamp
from task_agent.result_json import (
    VULNERABILITY_RESULT_JSON_SCHEMA,
)
from task_agent.task_service import bind_opencode_execution_context
from deephole_client.config import effective_fp_review_cli_config


_FP_FEEDBACK_FILE = Path.home() / ".opendeephole" / "fp_feedback.json"
_FP_REVIEW_FEEDBACK: dict[str, list[dict]] = {}
# 每次复核的 git 历史问题模式快照（list[dict]，来自后端 GET .../git_history）
_FP_REVIEW_HISTORY: dict[str, list[dict]] = {}
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


def _required_capability() -> str:
    from backend.config import get_config

    policy = getattr(get_config(), "false_positive", None)
    value = str(getattr(policy, "required_capability", "high") or "high").strip().lower()
    return "high" if value in {"medium", "high"} else "low"

_FP_STAGE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        **VULNERABILITY_RESULT_JSON_SCHEMA["properties"],
        "stage_markdown": {"type": "string", "minLength": 1},
        "match_type": {"type": "string"},
        "match_reference": {"type": "string"},
    },
    "required": [
        *VULNERABILITY_RESULT_JSON_SCHEMA["required"],
        "stage_markdown",
        "match_type",
        "match_reference",
    ],
    "additionalProperties": False,
}


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
    from task_agent.task_service import (
        reset_opencode_execution_context,
        set_opencode_execution_context,
    )
    execution_context_token = set_opencode_execution_context(
        scan_id=scan_id,
        project_dir=project,
        work_dir=review_dir,
        feedback_entries=feedback_entries or [],
        cancel_event=cancel_event,
    )
    processed_reviews = 0

    # 拉取本次扫描挖掘出的 git 历史问题模式，供「历史/校验匹配」阶段使用
    try:
        history_patterns = await reporter.get_git_history(scan_id)
        set_fp_review_history(scan_id, [p.model_dump() for p in history_patterns])
    except Exception:
        set_fp_review_history(scan_id, [])

    # Detect active MCP server for this project
    from deephole_client import mcp_registry
    active = mcp_registry.lookup(project)

    own_mcp_server = None         # only set in Mode B
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

            from deephole_client.local_mcp import LocalMCPServer
            own_mcp_server = LocalMCPServer(project_dir=db_dir, project_id=scan_id)
            mcp_port = own_mcp_server.start()
            await emit("fp_review", f"Started own MCP server on port {mcp_port}")

        await emit("fp_review", f"Starting FP review: {len(vulnerabilities)} confirmed vulnerabilities")

        # Register FP skills in the single Agent-wide OpenCode workspace.
        _create_fp_workspace(mcp_port)
        await emit("fp_review", "Global OpenCode workspace ready")

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
                        review_dir=review_dir,
                        review_id=review_id,
                        vuln_index=vuln_index,
                        artifact_dir=artifact_dir,
                        output_markdown_path=artifact_dir / "history-match.md",
                        vuln=vuln,
                        project_id_for_prompt=project_id_for_prompt,
                        timeout=current_fp_cli.timeout,
                        cancel_event=cancel_event,
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
                        review_dir=review_dir,
                        review_id=review_id,
                        vuln_index=vuln_index,
                        artifact_dir=artifact_dir,
                        output_markdown_path=artifact_dir / "prove-bug.md",
                        vuln=vuln,
                        project_id_for_prompt=project_id_for_prompt,
                        timeout=current_fp_cli.timeout,
                        cancel_event=cancel_event,
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
            except NoAvailableModelError:
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
            from task_agent.model_pool import clear_completed_tasks
            await clear_completed_tasks(scan_id)
        except Exception:
            pass
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
        reset_opencode_execution_context(execution_context_token)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_fp_review_stage(
    *,
    stage: str,
    scan_id: str,
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
    project: Path,
    candidate,
    prove_bug: _FpStageResult | None = None,
    prove_fp: _FpStageResult | None = None,
    ai_analysis_path: Path | None = None,
    history_patterns: list[dict] | None = None,
    variant_of: str = "",
) -> _FpStageResult | None:
    from deephole_client.opencode_workflows import (
        _session_id_from_output_source,
        _to_output_source,
        _vulnerability_from_payload,
    )

    output_source: OutputSource | None = None

    def capture_source(source: OutputSource) -> None:
        nonlocal output_source
        output_source = _to_output_source(source)

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
    log_path = review_dir / f"fp_{stage}_{uuid4().hex}.log"
    task_session_id = ""
    payload: dict = {}
    try:
        try:
            if output_markdown_path.exists():
                output_markdown_path.unlink()
        except OSError:
            pass
        with bind_opencode_execution_context(
            project_dir=project,
            work_dir=review_dir,
            task_metadata={
                "review_id": review_id,
                "stage": stage,
                "vuln_index": vuln_index,
                "checker": vuln.get("vuln_type", ""),
                "file": vuln.get("file", ""),
                "line": vuln.get("line", 0),
                "function": vuln.get("function", ""),
            },
            on_output=lambda line: print(
                with_local_timestamp(line, prefix=f"[fp_{stage}]"),
                flush=True,
            ),
            on_invocation_metadata=capture_source,
            cancel_event=cancel_event,
        ):
            task_result = await run_opencode_task(
                task_name=f"去误报复核 {stage}",
                task_type="fp_review",
                prompt=prompt,
                required_capability=_required_capability(),
                output_schema=_FP_STAGE_JSON_SCHEMA,
            )
        task_session_id = task_result.session_id
        if task_result.status == "timeout":
            raise asyncio.TimeoutError(task_result.text)
        if task_result.status == "failure":
            if task_result.text == NO_AVAILABLE_MODEL_MESSAGE:
                raise NoAvailableModelError()
            raise RuntimeError(task_result.text)
        payload = task_result.structured if isinstance(task_result.structured, dict) else {}
        if payload:
            log_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        raise _FpStageFailure(
            stage=stage,
            session_id=task_session_id or _session_id_from_output_source(output_source),
            artifact_path=output_markdown_path,
            log_path=log_path,
            reason=f"OpenCode stage failed after configured session retries: {exc}",
            output_source=output_source,
        ) from exc

    try:
        result = _vulnerability_from_payload(payload, candidate)
    except Exception:
        result = None
    markdown = str(payload.get("stage_markdown") or "")
    if markdown.strip():
        output_markdown_path.parent.mkdir(parents=True, exist_ok=True)
        output_markdown_path.write_text(markdown, encoding="utf-8")
    if result is None or not markdown.strip():
        raise _FpStageFailure(
            stage=stage,
            session_id=_session_id_from_output_source(output_source),
            artifact_path=output_markdown_path,
            log_path=log_path,
            reason="Schema-valid FP stage result could not be converted",
            output_source=output_source,
        )
    return _FpStageResult(
        session_id=task_session_id or _session_id_from_output_source(output_source),
        result=result,
        payload=payload,
        markdown=markdown,
        output_source=output_source or OutputSource(),
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
            "你必须在最终 JSON 的 stage_markdown 返回本阶段完整 Markdown 论证。"
            "分析完成后在同一个最终 JSON 中返回结论："
            "confirmed=true 表示对应上（match_type 填 history 或 validation，match_reference 填"
            f"历史模式根因摘要+出处提交，或正确校验站点 path:line + 一句话说明，并提交 vulnerability_report，"
            f"包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、Why It is Reachable、Impact、Evidence 七个二级标题）；"
            "confirmed=false 表示无法对应（此时会转入三阶段辩论，不要勉强匹配）。"
            "severity 使用 high/low；file、line、function 使用当前候选值；不要使用 CVSS 打分。"
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
            "你必须在最终 JSON 的 stage_markdown 返回本阶段完整 Markdown 论证。"
            "match_type 和 match_reference 在本阶段使用空字符串。"
            f"默认假设代码是安全的；只有证明真实代码问题时才使用 confirmed=true。"
            f"severity 只分两档：外部可触发的问题使用 high；其余（无法证明外部可触发或非问题）一律使用 low。"
            f"只要 confirmed=true，"
            f"都必须在 vulnerability_report 中提交 Markdown 问题报告，"
            f"并包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、"
            f"Why It is Reachable、Impact、Evidence 七个二级标题。不要使用 CVSS 打分。"
            "最终 JSON 同时返回 confirmed、severity、description、ai_analysis、"
            "vulnerability_report、file、line、function。"
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
            f"正方阶段 JSON 摘要：{bug_summary} "
            f"你必须先读取正方 Markdown 文件 `{prove_bug_path}`，再进行反方论证。"
            "你必须在最终 JSON 的 stage_markdown 返回本阶段完整 Markdown 论证。"
            "match_type 和 match_reference 在本阶段使用空字符串。"
            f"如果找到足以证明非问题的理由，使用 confirmed=false 且 severity=low。"
            f"如果反方未能证明非问题，仍使用 confirmed=true；severity 只分两档："
            f"外部可触发为 high，其余一律为 low。"
            f"只要 confirmed=true，"
            f"都必须提交 vulnerability_report，可沿用或修正 prove-bug 的报告。不要使用 CVSS 打分。"
            "最终 JSON 同时返回 confirmed、severity、description、ai_analysis、"
            "vulnerability_report、file、line、function。"
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
            f"正方阶段 JSON 摘要：{bug_summary} "
            f"反方阶段 JSON 摘要：{fp_summary} "
            f"你必须读取正方 Markdown 文件 `{bug_path}` 和反方 Markdown 文件 `{fp_path}`。"
            "你必须在最终 JSON 的 stage_markdown 返回最终裁决完整 Markdown。"
            "match_type 和 match_reference 在本阶段使用空字符串。"
            f"最终 confirmed=false 表示误报；confirmed=true 表示真实问题。"
            f"severity 只分两档：论证为外部可触发的问题使用 high；其余（无法证明外部可触发或非问题）一律使用 low。"
            f"最终 ai_analysis 必须像 memleak 输出一样包含完整代码链、关键代码片段和说明，"
            f"让读者不重新查看代码也能判断结论。"
            f"只要 confirmed=true，"
            f"都必须提交 vulnerability_report，包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、"
            f"Why It is Reachable、Impact、Evidence 七个二级标题。不要使用 CVSS 打分。"
            "最终 JSON 同时返回 confirmed、severity、description、ai_analysis、"
            "vulnerability_report、file、line、function。"
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
        return "未提交 JSON 阶段结论。"
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


def _create_fp_workspace(
    mcp_port: int,
) -> Path:
    """Return the Agent-wide workspace where FP skills are pre-registered."""
    from deephole_client.opencode_integration import get_global_opencode_workspace

    return get_global_opencode_workspace(mcp_port=mcp_port)
