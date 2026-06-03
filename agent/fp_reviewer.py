"""False positive reviewer — re-examines confirmed vulnerabilities using opencode.

When the same project has an active scan running (its MCP server is still up),
this module reuses that MCP server and leaves the backend config untouched to
avoid conflicts. When no active scan is found, it starts its own MCP server
and configures the backend in isolation.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from uuid import uuid4

from backend.models import ScanEvent
from agent.config import effective_fp_review_cli_config


_FP_FEEDBACK_FILE = Path.home() / ".opendeephole" / "fp_feedback.json"
_FP_REVIEW_FEEDBACK: dict[str, list[dict]] = {}
_FP_REVIEW_SKILLS = ("prove-bug", "prove-fp")
_LEGACY_FP_REVIEW_SKILLS = ("fp-review", "fp-review-discriminator")
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
    result_id: str
    result: object
    payload: dict


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


async def run_fp_review(
    config,
    reporter,
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
    feedback_entries: list[dict] | None = None,
    cancel_event: threading.Event | None = None,
) -> None:
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
      • Set AGENT_PROJECT_DIR so MCP bypasses project_id and finds the DB directly
        (via IndexStore or the preserved scan_dir for error/cancelled scans).
      • Configure the backend in isolation: scans_dir = review_dir so result
        JSONs are isolated from any other concurrent scan of a different project.
      • Clean up AGENT_PROJECT_DIR and backend config on exit.
    """
    project = Path(project_path)
    review_dir = Path.home() / ".opendeephole" / "fp_reviews" / review_id
    review_dir.mkdir(parents=True, exist_ok=True)
    set_fp_review_feedback(scan_id, feedback_entries or [])

    # Detect active MCP server for this project
    from agent import mcp_registry
    active = mcp_registry.lookup(project)

    own_mcp_server = None         # only set in Mode B
    workspace: Optional[Path] = None
    _patched_env: bool = False    # whether we changed AGENT_PROJECT_DIR
    _patched_cfg: bool = False    # whether we changed the backend config

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

            # AGENT_PROJECT_DIR makes MCP ignore project_id and use this dir directly
            os.environ["AGENT_PROJECT_DIR"] = str(db_dir)
            _patched_env = True
            project_id_for_prompt = scan_id  # content doesn't matter; env var takes priority

            # Isolate result JSON files in review_dir (scans_dir = review_dir).
            # Safe because no other scan config is active for this project.
            _configure_fp_backend(config, review_dir)
            _patched_cfg = True

            from agent.local_mcp import LocalMCPServer
            own_mcp_server = LocalMCPServer()
            mcp_port = own_mcp_server.start()
            await emit("fp_review", f"Started own MCP server on port {mcp_port}")

        await emit("fp_review", f"Starting FP review: {len(vulnerabilities)} confirmed vulnerabilities")

        # Create an isolated config workspace with opencode.json + FP-review skills.
        workspace = _create_fp_workspace(review_dir / "opencode_workspace", mcp_port)
        await emit("fp_review", "FP review workspace ready")

        from backend.models import Candidate

        fp_cli = effective_fp_review_cli_config(config)

        for position, vuln in enumerate(vulnerabilities):
            if cancel_event is not None and cancel_event.is_set():
                await emit("fp_review", f"FP review cancelled after reviewing {position} items")
                await reporter.finish_fp_review(scan_id, review_id, "cancelled", "用户手动停止")
                return

            vuln_index = int(vuln["index"])
            _create_fp_workspace(
                workspace,
                mcp_port,
                vuln_type=vuln["vuln_type"],
                feedback_entries=get_fp_review_feedback(scan_id),
            )

            await emit(
                "fp_review",
                f"[{position + 1}] Reviewing {vuln['vuln_type'].upper()} "
                f"at {vuln['file']}:{vuln['line']} ({vuln['function']})",
            )
            await reporter.push_fp_progress(scan_id, review_id, vuln_index, position)
            result_submitted = False

            try:
                fake_candidate = Candidate(
                    file=vuln["file"],
                    line=vuln["line"],
                    function=vuln["function"],
                    vuln_type=vuln["vuln_type"],
                    description=vuln["description"],
                )
                prove_bug = await _run_fp_review_stage(
                    stage="prove_bug",
                    workspace=workspace,
                    review_dir=review_dir,
                    vuln=vuln,
                    project_id_for_prompt=project_id_for_prompt,
                    timeout=fp_cli.timeout,
                    cancel_event=cancel_event,
                    cli_config=fp_cli,
                    project=project,
                    candidate=fake_candidate,
                )
                if cancel_event is not None and cancel_event.is_set():
                    await emit("fp_review", f"FP review cancelled after reviewing {position} items")
                    await reporter.finish_fp_review(scan_id, review_id, "cancelled", "用户手动停止")
                    return

                if prove_bug is None:
                    await emit("fp_review", f"[{position + 1}] Prove-bug returned no result — preserving any previous review result")
                elif not prove_bug.result.confirmed:
                    verdict, severity, reason, vulnerability_report = _finalize_fp_review_result(prove_bug, None)
                    await reporter.push_fp_result(
                        scan_id,
                        review_id,
                        vuln_index,
                        verdict,
                        severity,
                        reason,
                        vulnerability_report,
                    )
                    result_submitted = True
                    await emit("fp_review", f"[{position + 1}] FALSE POSITIVE severity={severity}")
                else:
                    prove_fp = await _run_fp_review_stage(
                        stage="prove_fp",
                        workspace=workspace,
                        review_dir=review_dir,
                        vuln=vuln,
                        project_id_for_prompt=project_id_for_prompt,
                        timeout=fp_cli.timeout,
                        cancel_event=cancel_event,
                        cli_config=fp_cli,
                        project=project,
                        candidate=fake_candidate,
                        prove_bug=prove_bug,
                    )
                    if cancel_event is not None and cancel_event.is_set():
                        await emit("fp_review", f"FP review cancelled after reviewing {position} items")
                        await reporter.finish_fp_review(scan_id, review_id, "cancelled", "用户手动停止")
                        return
                    if prove_fp is None:
                        await emit("fp_review", f"[{position + 1}] Prove-fp returned no result — preserving any previous review result")
                    else:
                        verdict, severity, reason, vulnerability_report = _finalize_fp_review_result(
                            prove_bug,
                            prove_fp,
                        )
                        await reporter.push_fp_result(
                            scan_id,
                            review_id,
                            vuln_index,
                            verdict,
                            severity,
                            reason,
                            vulnerability_report,
                        )
                        result_submitted = True
                        await emit(
                            "fp_review",
                            f"[{position + 1}] {'TRUE POSITIVE' if verdict == 'tp' else 'FALSE POSITIVE'} severity={severity}",
                        )

            except asyncio.CancelledError:
                await emit("fp_review", f"FP review cancelled after reviewing {position} items")
                await reporter.finish_fp_review(scan_id, review_id, "cancelled", "用户手动停止")
                return
            except Exception as exc:
                await emit("fp_review", f"[{position + 1}] Review error: {exc}")

            await reporter.push_fp_progress(
                scan_id,
                review_id,
                vuln_index,
                position + 1,
            )
            if not result_submitted:
                await emit("fp_review", f"[{position + 1}] No FP review result saved")

        await reporter.finish_fp_review(scan_id, review_id, "complete", None)
        await emit("fp_review", f"FP review complete: {len(vulnerabilities)} vulnerabilities reviewed")

    except Exception as exc:
        print(f"[fp_review] Error: {exc}")
        try:
            await reporter.finish_fp_review(scan_id, review_id, "error", str(exc))
            await emit("fp_review", f"FP review failed: {exc}")
        except Exception:
            pass

    finally:
        if workspace is not None:
            _cleanup_fp_workspace(workspace)
        if own_mcp_server is not None:
            own_mcp_server.stop()
        if _patched_env:
            os.environ.pop("AGENT_PROJECT_DIR", None)
        if _patched_cfg:
            # Reset the config singleton so the next operation reloads cleanly.
            # Safe here because Mode B only runs when there is no active scan.
            import backend.config as _cfg_mod
            _cfg_mod._config = None
            import backend.registry as _reg_mod
            _reg_mod._registry = None
        _FP_REVIEW_FEEDBACK.pop(scan_id, None)
        shutil.rmtree(review_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_fp_review_stage(
    *,
    stage: str,
    workspace: Path,
    review_dir: Path,
    vuln: dict,
    project_id_for_prompt: str,
    timeout: int,
    cancel_event: threading.Event | None,
    cli_config,
    project: Path,
    candidate,
    prove_bug: _FpStageResult | None = None,
) -> _FpStageResult | None:
    from backend.opencode.runner import _invoke_opencode, _read_result

    result_id = uuid4().hex
    prompt = _build_fp_review_prompt(
        stage=stage,
        vuln=vuln,
        project_id_for_prompt=project_id_for_prompt,
        result_id=result_id,
        prove_bug=prove_bug,
    )
    log_path = review_dir / f"fp_{stage}_{result_id}.log"

    await _invoke_opencode(
        workspace,
        prompt,
        timeout,
        log_path=log_path,
        on_line=lambda line: print(f"  [fp_{stage}] {line}", flush=True),
        cancel_event=cancel_event,
        cli_config=cli_config,
        project_dir=project,
    )
    result = _read_result(result_id, candidate)
    if result is None:
        return None
    return _FpStageResult(
        result_id=result_id,
        result=result,
        payload=_read_fp_result_payload(result_id),
    )


def _build_fp_review_prompt(
    *,
    stage: str,
    vuln: dict,
    project_id_for_prompt: str,
    result_id: str,
    prove_bug: _FpStageResult | None = None,
) -> str:
    if stage == "prove_bug":
        prompt = (
            f"使用 `prove-bug` 技能，作为正方论证位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选是否是真实问题。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"原始描述：{vuln['description']} "
            f"原始 AI 分析：{vuln['ai_analysis']} "
            f"你的 result_id 是 `{result_id}`。"
            f"分析完成后，你**必须**使用此 result_id 调用 submit_result MCP 工具提交结论。"
            f"默认假设代码是安全的；只有证明真实代码问题时才使用 confirmed=true。"
            f"severity 必须按外部可触发性判断：外部可触发问题使用 high；"
            f"有代码问题但未证明外部可触发使用 medium；非问题使用 low。"
            f"只要 confirmed=true，不管 severity 是 high 还是 medium，"
            f"都必须在 vulnerability_report 中提交 Markdown 问题报告，"
            f"并包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、"
            f"Why It is Reachable、Impact、Evidence 七个二级标题。不要使用 CVSS 打分。"
        )
    elif stage == "prove_fp" and prove_bug is not None:
        bug = prove_bug.result
        bug_payload = prove_bug.payload
        prompt = (
            f"使用 `prove-fp` 技能，作为反方论证位于 "
            f"{vuln['file']}:{vuln['line']} 函数 `{vuln['function']}` 中"
            f"的 {vuln['vuln_type'].upper()} 候选是否不是问题。"
            f"project_id 为 `{project_id_for_prompt}`。"
            f"原始描述：{vuln['description']} "
            f"原始 AI 分析：{vuln['ai_analysis']} "
            f"prove-bug confirmed={bool(bug.confirmed)} severity={bug.severity}。"
            f"prove-bug description：{bug.description} "
            f"prove-bug ai_analysis：{bug.ai_analysis} "
            f"prove-bug vulnerability_report：{bug_payload.get('vulnerability_report') or ''} "
            f"你的 result_id 是 `{result_id}`。"
            f"分析完成后，你**必须**使用此 result_id 调用 submit_result MCP 工具提交反方结论。"
            f"如果找到足以证明非问题的理由，使用 confirmed=false 且 severity=low。"
            f"如果反方未能证明非问题，仍使用 confirmed=true；外部可触发为 high，"
            f"仅代码问题或外部触发证据不足为 medium。"
            f"只要 confirmed=true，不管 severity 是 high 还是 medium，"
            f"都必须提交 vulnerability_report，可沿用或修正 prove-bug 的报告。不要使用 CVSS 打分。"
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

    Sets scans_dir = review_dir so the submit_result MCP tool writes result
    JSON files into review_dir, where _read_result() will find them.
    Only called in Mode B (no active scan for the project).
    """
    import yaml

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
        "opencode": {
            "tool": config.opencode.tool,
            "executable": config.opencode.executable,
            "model": config.opencode.model,
            "timeout": config.opencode.timeout,
            "max_retries": config.opencode.max_retries,
            "mock": False,
        },
        "storage": {
            # projects_dir is irrelevant in Mode B — AGENT_PROJECT_DIR overrides DB lookup
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
        raw["fp_review_cli"] = {
            "tool": config.fp_review_cli.tool,
            "executable": config.fp_review_cli.executable,
            "model": config.fp_review_cli.model,
            "timeout": config.fp_review_cli.timeout,
            "max_retries": config.fp_review_cli.max_retries,
            "mock": False,
        }
    config_path = review_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)

    import backend.config as _cfg
    _cfg._config = None
    import backend.registry as _reg
    _reg._registry = None


def _normalize_fp_severity(severity: str, verdict: str) -> str:
    normalized = (severity or "").strip().lower()
    if verdict == "fp":
        return "low"
    if normalized == "high":
        return "high"
    if normalized in {"medium", "low"}:
        return "medium"
    return "medium"


def _finalize_fp_review_result(
    prove_bug: _FpStageResult,
    prove_fp: _FpStageResult | None,
) -> tuple[str, str, str, str]:
    bug = prove_bug.result
    bug_verdict = "tp" if bug.confirmed else "fp"
    bug_severity = _normalize_fp_severity(str(bug.severity), bug_verdict)

    if prove_fp is None:
        verdict = bug_verdict
        severity = bug_severity
        report = _stage_report(prove_bug)
        final_note = (
            "Prove-bug 判定为非问题，未进入反方论证。"
            if verdict == "fp"
            else "Prove-fp 未返回结果，沿用 prove-bug 的问题结论。"
        )
    else:
        fp = prove_fp.result
        verdict = "tp" if fp.confirmed else "fp"
        severity = _normalize_fp_severity(str(fp.severity), verdict)
        report = _stage_report(prove_fp) or _stage_report(prove_bug)
        final_note = (
            "Prove-fp 未能证明非问题，保留真实代码问题结论。"
            if verdict == "tp"
            else "Prove-fp 找到足以证明非问题的理由。"
        )
        if severity == "high" and bug_severity != "high":
            severity = "medium"
            final_note += " Prove-bug 未证明完整外部触发链，最终降级为 medium。"

    if verdict == "fp":
        severity = "low"
        report = ""
    elif not report.strip():
        final_note += " 复核未提交问题报告。"

    reason = _compose_fp_reason(prove_bug, prove_fp, final_note)
    return verdict, severity, reason, report


def _stage_report(stage_result: _FpStageResult) -> str:
    return str(stage_result.payload.get("vulnerability_report") or "")


def _stage_reason(stage_result: _FpStageResult) -> str:
    result = stage_result.result
    return str(result.ai_analysis or result.description or "").strip()


def _compose_fp_reason(
    prove_bug: _FpStageResult,
    prove_fp: _FpStageResult | None,
    final_note: str,
) -> str:
    parts = [
        "[prove-bug]",
        _stage_reason(prove_bug) or "未提供详细推理。",
    ]
    if prove_fp is not None:
        parts.extend([
            "",
            "[prove-fp]",
            _stage_reason(prove_fp) or "未提供详细反驳推理。",
        ])
    parts.extend([
        "",
        "[final]",
        final_note,
    ])
    return "\n".join(parts).strip()


def _has_required_issue_report_sections(report: str) -> bool:
    if not report.strip():
        return False
    lowered_lines = [line.strip().lower() for line in report.splitlines()]
    for heading in _ISSUE_REPORT_HEADINGS:
        expected = f"## {heading}".lower()
        if not any(line == expected or line.startswith(expected + " ") for line in lowered_lines):
            return False
    return True


def _read_fp_result_payload(result_id: str) -> dict:
    """Read optional FP review fields that are not part of Vulnerability."""
    try:
        from backend.config import get_config

        result_path = Path(get_config().storage.scans_dir) / f"{result_id}.json"
        if not result_path.exists():
            return {}
        return json.loads(result_path.read_text(encoding="utf-8"))
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
