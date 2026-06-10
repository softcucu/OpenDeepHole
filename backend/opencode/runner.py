"""opencode CLI runner — invokes opencode for AI-powered vulnerability analysis."""

import asyncio
import json
import os
import re
import signal
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from backend.config import get_config
from backend.logger import get_logger
from backend.models import Candidate, Vulnerability
from backend.opencode.model_pool import (
    acquire_model_lease,
    configured_global_concurrency,
    release_model_lease,
)

logger = get_logger(__name__)

AI_CLI_TOOLS = ("nga", "opencode", "hac", "claude")
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
PROCESS_EXIT_GRACE_SECONDS = 5.0
_DEFAULT_EXECUTABLES = {
    "nga": "nga",
    "opencode": "opencode",
    "hac": "hac",
    "claude": "claude",
}


@dataclass
class SensitiveClearAuditResult:
    vulnerabilities: list[Vulnerability]
    reports: list[dict]
    complete: bool

# Regex to strip ANSI escape sequences from CLI output
_ANSI_RE = re.compile(
    r'\x1b\[[0-9;]*[a-zA-Z]'    # CSI sequences: ESC[...X
    r'|\x1b\][^\x07]*\x07'      # OSC sequences: ESC]...BEL
    r'|\x1b\[\?[0-9;]*[a-zA-Z]' # Private CSI: ESC[?...X
    r'|\x1b[()][A-Z0-9]'        # Character set selection
    r'|\x1b='                    # Keypad mode
    r'|\x1b>'                    # Keypad mode
    r'|\r'                       # Carriage return (from \r\n or spinner overwrites)
)


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and control characters from text."""
    return _ANSI_RE.sub('', text)


async def run_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> Vulnerability | None:
    """Run opencode to analyze a single candidate vulnerability.

    Supports two modes (selected via checker.yaml):
    - opencode CLI mode (default): invokes opencode subprocess with MCP tools
    - LLM API mode: direct API call with function calling

    Args:
        workspace: Path to the generated opencode config workspace.
        project_dir: Real project root used as the CLI code workspace.
        candidate: The candidate vulnerability to analyze.
        project_id: Project identifier for MCP tool calls.
        on_output: Optional callback(line: str) called for each output line in real-time.
        cancel_event: Optional threading.Event; when set, the subprocess is killed.
        timeout: Per-candidate timeout in seconds. Falls back to config if not provided.

    Returns:
        A Vulnerability if analysis succeeded, None otherwise.
    """
    config = get_config()

    if config.opencode.mock:
        return _mock_result(candidate)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout

    # 按 checker 的 mode 决定调用方式
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidate.vuln_type)
    use_api = checker_entry is not None and checker_entry.mode == "api"

    if use_api:
        from backend.opencode.llm_api_runner import (
            LLMApiUnavailableError,
            ensure_llm_api_available,
            run_audit_via_api,
        )
        try:
            await ensure_llm_api_available(on_output=on_output)
            # 优先使用 workspace 中合并了反馈的 prompt
            merged_prompt = workspace / ".opencode" / "skills" / candidate.vuln_type / "PROMPT.md"
            prompt_path = merged_prompt if merged_prompt.is_file() else checker_entry.prompt_path
            return await run_audit_via_api(
                candidate, project_id,
                prompt_path=prompt_path,
                on_output=on_output,
                cancel_event=cancel_event,
            )
        except LLMApiUnavailableError as exc:
            logger.warning(
                "LLM API unavailable for checker %s; falling back to CLI audit: %s",
                candidate.vuln_type, exc,
            )
            if on_output:
                on_output(f"[API] API 不可用，降级为 CLI 审计: {exc}")

    return await _run_audit_via_opencode(
        workspace,
        candidate,
        project_id,
        checker_entry,
        on_output=on_output,
        cancel_event=cancel_event,
        timeout=effective_timeout,
        project_dir=project_dir,
    )


async def _run_audit_via_opencode(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    checker_entry=None,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> Vulnerability | None:
    """Run the opencode CLI path regardless of checker mode."""
    config = get_config()
    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = _normalize_tool(config.opencode)

    # Skill directory is .opencode/skills/<name>/ where <name> == vuln_type.
    # Use checker_entry.skill_name if explicitly set, otherwise fall back to
    # vuln_type so the name matches the actual directory opencode will look up.
    skill_name = (
        checker_entry.skill_name
        if checker_entry and checker_entry.skill_name
        else candidate.vuln_type
    )
    max_retries = config.opencode.max_retries

    for attempt in range(1, max_retries + 2):  # attempt 1 .. max_retries+1
        result_id = f"result-{uuid4().hex}"

        prompt = (
            f"使用 `{skill_name}` 技能，分析位于 "
            f"{candidate.file}:{candidate.line} 函数 `{candidate.function}` 中"
            f"潜在的 {candidate.vuln_type.upper()} 漏洞。"
            f"project_id 为 `{project_id}`。"
            f"详情：{candidate.description} "
            f"你的 result_id 是 `{result_id}`。"
            f"分析完成后，你**必须**使用此 result_id 调用 submit_result MCP 工具提交你的结论。"
        )
        prompt = prompt.replace('\n', ' ')

        log_path = workspace / f"opencode_{result_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s audit: %s:%d (%s) result_id=%s timeout=%ds attempt=%d/%d",
            tool,
            candidate.file, candidate.line, candidate.vuln_type, result_id,
            effective_timeout, attempt, max_retries + 1,
        )

        try:
            await _invoke_opencode(
                workspace, prompt, effective_timeout,
                log_path=log_path, on_line=on_output, cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
            )
        except asyncio.TimeoutError:
            # Timeout — no retry; check if result was submitted before kill
            logger.error("%s timed out for %s:%d (timeout=%ds)", tool, candidate.file, candidate.line, effective_timeout)
            result = _read_result(result_id, candidate)
            if result is not None:
                logger.info("Result file found despite timeout — using submitted result")
                return result
            return Vulnerability(
                file=candidate.file,
                line=candidate.line,
                function=candidate.function,
                vuln_type=candidate.vuln_type,
                severity="unknown",
                description=candidate.description,
                ai_analysis="Analysis timed out",
                confirmed=False,
                ai_verdict="timeout",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Process error (e.g. certificate error, crash) — may retry
            logger.exception("%s failed for %s:%d (attempt %d)", tool, candidate.file, candidate.line, attempt)
            if attempt <= max_retries:
                logger.info("Retrying opencode for %s:%d ...", candidate.file, candidate.line)
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return None

        # Process completed — check result
        result = _read_result(result_id, candidate)
        if result is not None:
            return result

        # submit_result was not called — retry if attempts remain
        if attempt <= max_retries:
            logger.warning(
                "%s did not call submit_result for %s:%d (attempt %d), retrying...",
                tool, candidate.file, candidate.line, attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No result submitted, retrying...")
            continue

        logger.warning("%s did not call submit_result for %s:%d after %d attempts", tool, candidate.file, candidate.line, attempt)
        return None

    return None  # should not reach here


async def run_project_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> list[Vulnerability]:
    """Run a SKILL-only checker once and collect all submitted results."""
    config = get_config()
    if config.opencode.mock:
        return [_mock_result(candidate)]

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = _normalize_tool(config.opencode)
    from backend.registry import get_registry
    checker_entry = get_registry().get(candidate.vuln_type)
    skill_name = (
        checker_entry.skill_name
        if checker_entry and checker_entry.skill_name
        else candidate.vuln_type
    )
    max_retries = config.opencode.max_retries

    for attempt in range(1, max_retries + 2):
        result_id = f"result-{uuid4().hex}"
        prompt = (
            f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
            f"project_id 为 `{project_id}`。"
            f"这是项目级审计任务，不是单个候选点复核。"
            f"每发现一个真实问题，都必须使用此 result_id `{result_id}` 调用一次 submit_result MCP 工具，"
            f"并在 submit_result 参数中填写真实的 file、line、function。"
            f"如果没有发现真实问题，也必须使用此 result_id 调用一次 submit_result，confirmed=false，"
            f"file=`{candidate.file}`，line={candidate.line}，function=`{candidate.function}`。"
        ).replace("\n", " ")
        log_path = workspace / f"opencode_{result_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s project audit: %s (%s) result_id=%s timeout=%ds attempt=%d/%d",
            tool, candidate.file, candidate.vuln_type, result_id,
            effective_timeout, attempt, max_retries + 1,
        )

        try:
            await _invoke_opencode(
                workspace, prompt, effective_timeout,
                log_path=log_path, on_line=on_output, cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
            )
        except asyncio.TimeoutError:
            logger.error("%s project audit timed out for %s (timeout=%ds)", tool, candidate.vuln_type, effective_timeout)
            results = _read_results(result_id, candidate)
            if results:
                return results
            return [
                Vulnerability(
                    file=candidate.file,
                    line=candidate.line,
                    function=candidate.function,
                    vuln_type=candidate.vuln_type,
                    severity="unknown",
                    description=candidate.description,
                    ai_analysis="Analysis timed out",
                    confirmed=False,
                    ai_verdict="timeout",
                )
            ]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("%s project audit failed for %s (attempt %d)", tool, candidate.vuln_type, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return []

        results = _read_results(result_id, candidate)
        if results:
            return results
        if attempt <= max_retries:
            logger.warning(
                "%s project audit did not call submit_result for %s (attempt %d), retrying...",
                tool, candidate.vuln_type, attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No result submitted, retrying...")
            continue
        logger.warning("%s project audit did not call submit_result for %s after %d attempts", tool, candidate.vuln_type, attempt)
        return []

    return []


def _sensitive_clear_group(candidate: Candidate) -> dict:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    if metadata.get("kind") != "sensitive_clear_group":
        return {}
    pairs = metadata.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        return {}
    return metadata


def _sensitive_clear_prompt(skill_name: str, candidate: Candidate, project_id: str, result_id: str) -> str:
    group = _sensitive_clear_group(candidate)
    group_id = str(group.get("group_id") or "sensitive-clear-group")
    pairs = [
        {
            "pair_id": str(item.get("pair_id") or ""),
            "function_name": str(item.get("function_name") or ""),
            "variable_name": str(item.get("variable_name") or ""),
        }
        for item in group.get("pairs", [])
        if isinstance(item, dict)
    ]
    return (
        f"使用 `{skill_name}` 技能，审计敏感信息未清零分组 `{group_id}`。"
        f"project_id 为 `{project_id}`。"
        f"你的 result_id 是 `{result_id}`。"
        f"初始提示词只提供函数名和变量名，不包含函数体。"
        f"你必须自行按需查看代码，判断每个变量是否保存敏感信息以及最后一次敏感使用后是否显式清零。"
        f"下面 JSON 数组是必须覆盖的变量清单，每个元素都必须调用一次 submit_result，使用同一个 result_id；"
        f"ai_analysis 必须是包含 pair_id、function_name、variable_name、is_sensitive、cleared_after_last_use、confirmed、evidence、reason 的 JSON 字符串。"
        f"变量清单：{json.dumps(pairs, ensure_ascii=False)}"
    ).replace("\n", " ")


def _extract_json_object(text: str) -> dict | None:
    stripped = (text or "").strip()
    if not stripped:
        return None
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            data = json.loads(stripped[start:end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _safe_int(value, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _read_sensitive_clear_audit_result(result_id: str, candidate: Candidate) -> SensitiveClearAuditResult | None:
    group = _sensitive_clear_group(candidate)
    if not group:
        return None
    payload_data = _read_result_file(result_id, candidate)
    if payload_data is None:
        return None
    payloads = _result_payloads(payload_data)
    expected_pairs = {
        str(item.get("pair_id")): item
        for item in group.get("pairs", [])
        if isinstance(item, dict) and item.get("pair_id")
    }
    if not expected_pairs:
        return None

    seen: set[str] = set()
    normalized_results: list[dict] = []
    vulnerabilities: list[Vulnerability] = []
    for payload in payloads:
        analysis = _extract_json_object(str(payload.get("ai_analysis") or ""))
        if analysis is None:
            logger.warning("Invalid sensitive_clear ai_analysis JSON for result_id=%s", result_id)
            return None
        pair_id = str(analysis.get("pair_id") or "")
        if pair_id not in expected_pairs or pair_id in seen:
            logger.warning("Unexpected or duplicate sensitive_clear pair_id=%s result_id=%s", pair_id, result_id)
            return None
        seen.add(pair_id)
        pair = expected_pairs[pair_id]
        function_name = str(analysis.get("function_name") or pair.get("function_name") or "")
        variable_name = str(analysis.get("variable_name") or pair.get("variable_name") or "")
        confirmed = bool(payload.get("confirmed", False))
        analysis_confirmed = bool(analysis.get("confirmed", confirmed))
        if analysis_confirmed != confirmed:
            logger.warning("Mismatched sensitive_clear confirmed value for pair_id=%s", pair_id)
            return None

        normalized = {
            "pair_id": pair_id,
            "function_name": function_name,
            "variable_name": variable_name,
            "is_sensitive": bool(analysis.get("is_sensitive", False)),
            "cleared_after_last_use": bool(analysis.get("cleared_after_last_use", False)),
            "confirmed": confirmed,
            "severity": str(payload.get("severity") or ("high" if confirmed else "low")),
            "file": str(payload.get("file") or pair.get("file") or candidate.file),
            "line": _safe_int(
                payload.get("line"),
                _safe_int(pair.get("function_start_line"), candidate.line),
            ),
            "evidence": str(analysis.get("evidence") or ""),
            "reason": str(analysis.get("reason") or ""),
            "description": str(payload.get("description") or ""),
        }
        normalized_results.append(normalized)
        if confirmed:
            vulnerabilities.append(
                Vulnerability(
                    file=normalized["file"],
                    line=normalized["line"],
                    function=function_name,
                    vuln_type=candidate.vuln_type,
                    severity=normalized["severity"] or "high",
                    description=normalized["description"] or f"{function_name} 中变量 {variable_name} 保存敏感信息后未清零",
                    ai_analysis=json.dumps(normalized, ensure_ascii=False, indent=2),
                    confirmed=True,
                    ai_verdict="confirmed",
                )
            )

    missing = set(expected_pairs) - seen
    if missing:
        logger.warning("Missing sensitive_clear pair results for result_id=%s: %s", result_id, sorted(missing)[:10])
        return None

    group_id = str(group.get("group_id") or "sensitive-clear-group")
    report_data = {
        "group_id": group_id,
        "result_id": result_id,
        "total_pairs": len(expected_pairs),
        "confirmed_count": len(vulnerabilities),
        "results": sorted(normalized_results, key=lambda item: item["pair_id"]),
    }
    content = json.dumps(report_data, ensure_ascii=False, indent=2)
    now = datetime.now(timezone.utc).isoformat()
    reports = [
        {
            "checker_name": candidate.vuln_type,
            "filename": f"{group_id}.json",
            "title": f"Sensitive clear results {group_id}",
            "content": content,
            "created_at": now,
        }
    ]
    return SensitiveClearAuditResult(vulnerabilities=vulnerabilities, reports=reports, complete=True)


async def run_sensitive_clear_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> SensitiveClearAuditResult:
    """Run one sensitive_clear grouped audit and collect variable-level JSON results."""
    config = get_config()
    if config.opencode.mock:
        return SensitiveClearAuditResult(
            vulnerabilities=[],
            reports=[
                {
                    "checker_name": candidate.vuln_type,
                    "filename": f"{candidate.metadata.get('group_id', 'sensitive-clear-group')}.json",
                    "title": "Sensitive clear mock results",
                    "content": json.dumps({"results": []}, ensure_ascii=False, indent=2),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
            complete=True,
        )

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = _normalize_tool(config.opencode)
    from backend.registry import get_registry
    checker_entry = get_registry().get(candidate.vuln_type)
    skill_name = (
        checker_entry.skill_name
        if checker_entry and checker_entry.skill_name
        else candidate.vuln_type
    )
    max_retries = config.opencode.max_retries

    for attempt in range(1, max_retries + 2):
        result_id = f"result-{uuid4().hex}"
        prompt = _sensitive_clear_prompt(skill_name, candidate, project_id, result_id)
        log_path = workspace / f"opencode_{result_id}.log"
        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")
        logger.info(
            "Running %s sensitive_clear grouped audit: %s result_id=%s timeout=%ds attempt=%d/%d",
            tool, candidate.file, result_id, effective_timeout, attempt, max_retries + 1,
        )

        try:
            await _invoke_opencode(
                workspace,
                prompt,
                effective_timeout,
                log_path=log_path,
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
            )
        except asyncio.TimeoutError:
            logger.error("%s sensitive_clear audit timed out for %s", tool, candidate.file)
            parsed = _read_sensitive_clear_audit_result(result_id, candidate)
            if parsed is not None:
                return parsed
            return SensitiveClearAuditResult(
                vulnerabilities=[
                    Vulnerability(
                        file=candidate.file,
                        line=candidate.line,
                        function=candidate.function,
                        vuln_type=candidate.vuln_type,
                        severity="unknown",
                        description=candidate.description,
                        ai_analysis="Analysis timed out",
                        confirmed=False,
                        ai_verdict="timeout",
                    )
                ],
                reports=[],
                complete=False,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("%s sensitive_clear audit failed for %s (attempt %d)", tool, candidate.file, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return SensitiveClearAuditResult(vulnerabilities=[], reports=[], complete=False)

        parsed = _read_sensitive_clear_audit_result(result_id, candidate)
        if parsed is not None:
            return parsed
        if attempt <= max_retries:
            logger.warning("%s sensitive_clear audit produced invalid/incomplete results; retrying", tool)
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] Incomplete sensitive_clear JSON results, retrying...")
            continue
        return SensitiveClearAuditResult(
            vulnerabilities=[
                Vulnerability(
                    file=candidate.file,
                    line=candidate.line,
                    function=candidate.function,
                    vuln_type=candidate.vuln_type,
                    severity="unknown",
                    description=candidate.description,
                    ai_analysis="No complete variable-level result returned",
                    confirmed=False,
                    ai_verdict="no_result",
                )
            ],
            reports=[],
            complete=False,
        )

    return SensitiveClearAuditResult(vulnerabilities=[], reports=[], complete=False)


def _markdown_title(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or fallback
    return fallback


def _collect_markdown_reports(report_dir: Path, checker_name: str) -> list[dict]:
    reports: list[dict] = []
    if not report_dir.is_dir():
        return reports
    now = datetime.now(timezone.utc).isoformat()
    for path in sorted(report_dir.glob("*.md")):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            continue
        reports.append(
            {
                "checker_name": checker_name,
                "filename": path.name,
                "title": _markdown_title(content, path.stem),
                "content": content,
                "created_at": now,
            }
        )
    return reports


async def run_project_report_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    report_dir: Path,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> list[dict]:
    """Run a report-mode project SKILL and collect Markdown files from report_dir."""
    config = get_config()
    if config.opencode.mock:
        report_dir.mkdir(parents=True, exist_ok=True)
        mock_path = report_dir / f"{candidate.vuln_type}-mock-report.md"
        mock_path.write_text(
            f"# {candidate.vuln_type} mock report\n\nMock report for {candidate.file}.\n",
            encoding="utf-8",
        )
        return _collect_markdown_reports(report_dir, candidate.vuln_type)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = _normalize_tool(config.opencode)
    from backend.registry import get_registry
    checker_entry = get_registry().get(candidate.vuln_type)
    skill_name = (
        checker_entry.skill_name
        if checker_entry and checker_entry.skill_name
        else candidate.vuln_type
    )
    max_retries = config.opencode.max_retries
    report_dir.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, max_retries + 2):
        result_id = f"result-{uuid4().hex}"
        for old_report in report_dir.glob("*.md"):
            try:
                old_report.unlink()
            except OSError:
                pass
        prompt = (
            f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
            f"project_id 为 `{project_id}`。"
            f"这是用户创建的 Markdown 报告型项目级审计任务。"
            f"你的 result_id 是 `{result_id}`。"
            f"REPORT_DIR 为 `{report_dir.resolve()}`。"
            f"你必须将一个或多个 Markdown 报告写入 REPORT_DIR，文件扩展名必须是 .md。"
            f"不得修改 REPORT_DIR 之外的任何文件。"
            f"如果没有发现问题，也要写入一个 Markdown 报告说明审计范围和未发现问题的原因。"
        ).replace("\n", " ")
        log_path = workspace / f"opencode_{result_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s report audit: %s (%s) result_id=%s timeout=%ds attempt=%d/%d report_dir=%s",
            tool, candidate.file, candidate.vuln_type, result_id, effective_timeout,
            attempt, max_retries + 1, report_dir,
        )

        try:
            await _invoke_opencode(
                workspace,
                prompt,
                effective_timeout,
                log_path=log_path,
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
                writable_paths=[report_dir],
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
            )
        except asyncio.TimeoutError:
            logger.error(
                "%s report audit timed out for %s (timeout=%ds)",
                tool, candidate.vuln_type, effective_timeout,
            )
            return _collect_markdown_reports(report_dir, candidate.vuln_type)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("%s report audit failed for %s (attempt %d)", tool, candidate.vuln_type, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _collect_markdown_reports(report_dir, candidate.vuln_type)

        reports = _collect_markdown_reports(report_dir, candidate.vuln_type)
        if reports:
            return reports
        if attempt <= max_retries:
            logger.warning("%s report audit produced no Markdown files for %s; retrying", tool, candidate.vuln_type)
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No Markdown report written, retrying...")
            continue
        return []

    return []


def _cfg_value(config_obj, key: str, default=None):
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


def _effective_cli_config(cli_config, model_option) -> dict:
    data = {
        "tool": _cfg_value(cli_config, "tool", ""),
        "executable": _cfg_value(cli_config, "executable", ""),
        "model": _cfg_value(cli_config, "model", ""),
        "timeout": _cfg_value(cli_config, "timeout", 1200),
        "max_retries": _cfg_value(cli_config, "max_retries", 2),
        "models": _cfg_value(cli_config, "models", []),
    }
    if model_option.tool:
        data["tool"] = model_option.tool
    if model_option.executable:
        data["executable"] = model_option.executable
    if model_option.model:
        data["model"] = model_option.model
    if model_option.timeout is not None:
        data["timeout"] = model_option.timeout
    if model_option.max_retries is not None:
        data["max_retries"] = model_option.max_retries
    return data


def _normalize_tool(config_obj) -> str:
    tool = str(_cfg_value(config_obj, "tool", "") or "").strip().lower()
    executable = str(_cfg_value(config_obj, "executable", "") or "").strip()
    if tool in AI_CLI_TOOLS:
        return tool
    inferred = Path(executable).name.lower() if executable else ""
    if inferred in AI_CLI_TOOLS:
        return inferred
    return "opencode"


def _resolve_cli_executable(config_obj) -> str:
    """Return the full path to the configured AI CLI executable.

    Uses the name/path from config (executable, default per selected tool).
    Falls back to a bash login shell lookup so that executables installed in
    non-standard locations (e.g. ~/.bun/bin, ~/.local/bin) that are added to
    PATH by ~/.profile or ~/.bash_profile are found even when the Python
    process was started without sourcing those files.
    """
    tool = _normalize_tool(config_obj)
    name = _cfg_value(config_obj, "executable", "") or _DEFAULT_EXECUTABLES[tool]
    # Direct resolution: works when the binary is already in the current PATH
    resolved = shutil.which(name)
    if resolved:
        return resolved
    # Login-shell fallback: sources ~/.profile / ~/.bash_profile which typically
    # extend PATH for user-installed tools (npm, bun, pipx, etc.)
    if sys.platform != "win32":
        try:
            result = subprocess.run(
                ["bash", "-lc", f"command -v {shlex.quote(name)}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                if path:
                    logger.debug("%s resolved via login shell: %s", tool, path)
                    return path
        except Exception:
            pass
    raise FileNotFoundError(
        f"{tool} executable '{name}' not found in PATH. "
        "Check the Agent CLI tool executable setting in agent.yaml."
    )


def _read_opencode_config(workspace: Path) -> dict:
    try:
        data = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def _with_writable_paths(config: dict, writable_paths: list[Path] | None) -> dict:
    if not writable_paths:
        return config
    from backend.opencode.config import writable_edit_patterns

    next_config = json.loads(json.dumps(config))
    permission = next_config.setdefault("permission", {})
    edit = {}
    for path in writable_paths:
        raw = str(path)
        try:
            normalized = str(path.resolve())
        except Exception:
            normalized = str(Path(raw).resolve())
        for pattern in writable_edit_patterns(raw) + writable_edit_patterns(normalized):
            edit[pattern] = "allow"
    permission["edit"] = edit
    return next_config


def _read_mcp_url(workspace: Path) -> str:
    try:
        data = _read_opencode_config(workspace)
        server = data.get("mcp", {}).get("deephole-code", {})
        return str(server.get("url") or "")
    except Exception:
        return ""


def _copy_skill_tree(src_root: Path, dst_root: Path) -> None:
    if not src_root.is_dir():
        return
    dst_root.mkdir(parents=True, exist_ok=True)
    for src in src_root.iterdir():
        if not src.is_dir():
            continue
        dst = dst_root / src.name
        if dst.is_symlink() or dst.is_file():
            dst.unlink()
        elif dst.is_dir():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=True)


def _merge_json_file(path: Path, data: dict) -> None:
    current: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                current = loaded
        except Exception:
            current = {}
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(current.get(key), dict):
            current[key].update(value)
        else:
            current[key] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")


def _opencode_config_for_runtime(
    workspace: Path,
    skills_dir: Path,
    writable_paths: list[Path] | None = None,
) -> dict:
    config = _with_writable_paths(_read_opencode_config(workspace), writable_paths)
    if not config:
        return {}
    config["skills"] = {"paths": [str(skills_dir.resolve())]}
    return config


def _write_json_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _prepare_opencode_runtime_workspace(
    workspace: Path,
    runtime_cwd: Path,
    writable_paths: list[Path] | None = None,
) -> Path:
    """Mirror config/skills into the actual opencode CWD.

    opencode walks up from CWD to the git worktree root looking for
    ``.opencode/skills/``, so skills are placed under *runtime_cwd*.
    The runtime ``opencode.json`` is also written there for the
    ``OPENCODE_CONFIG_CONTENT`` env-var.
    """
    if runtime_cwd == workspace:
        return workspace

    source_skills = workspace / ".opencode" / "skills"
    runtime_skills = runtime_cwd / ".opencode" / "skills"
    _copy_skill_tree(source_skills, runtime_skills)

    runtime_config = _opencode_config_for_runtime(workspace, runtime_skills, writable_paths)
    if runtime_config:
        _write_json_file(runtime_cwd / "opencode.json", runtime_config)
        return runtime_cwd
    return workspace


def _prepare_cli_workspace(
    workspace: Path,
    tool: str,
    runtime_cwd: Path | None = None,
    writable_paths: list[Path] | None = None,
) -> Path:
    """Create tool-specific MCP and skill files from the canonical opencode files."""
    if tool in {"nga", "opencode"}:
        return _prepare_opencode_runtime_workspace(
            workspace,
            runtime_cwd or workspace,
            writable_paths,
        )

    mcp_url = _read_mcp_url(workspace)
    opencode_skills = workspace / ".opencode" / "skills"

    if tool == "claude":
        claude_dir = workspace / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        mcp_config = {
            "mcpServers": {
                "deephole-code": {
                    "type": "http",
                    "url": mcp_url,
                }
            }
        }
        (claude_dir / "opendeephole-mcp.json").write_text(
            json.dumps(mcp_config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        _copy_skill_tree(opencode_skills, claude_dir / "skills")
        return workspace

    if tool == "hac":
        gemini_dir = workspace / ".gemini"
        settings_path = gemini_dir / "settings.json"
        _merge_json_file(
            settings_path,
            {
                "mcpServers": {
                    "deephole-code": {
                        "httpUrl": mcp_url,
                    }
                }
            },
        )
        _copy_skill_tree(opencode_skills, gemini_dir / "skills")
    return workspace


def _build_cli_command(
    tool: str,
    executable: str,
    workspace: Path,
    prompt: str,
    model: str,
    project_dir: Path | None = None,
) -> list[str]:
    if tool in {"nga", "opencode"}:
        code_dir = project_dir or workspace
        cmd = [executable, "run", "--dir", str(code_dir)]
        if model:
            cmd += ["--model", model]
        cmd.append(prompt)
        return cmd

    if tool == "claude":
        cmd = [executable, "-p", "--mcp-config", str(workspace / ".claude" / "opendeephole-mcp.json")]
        if model:
            cmd += ["--model", model]
        cmd.append(prompt)
        return cmd

    if tool == "hac":
        cmd = [executable]
        if model:
            cmd += ["--model", model]
        cmd += ["-p", prompt]
        return cmd

    raise ValueError(f"Unsupported AI CLI tool: {tool}")


def _write_prompt_file(runtime_dir: Path, prompt: str) -> Path:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    path = runtime_dir / f"opencode_prompt_{uuid4().hex}.txt"
    path.write_text(prompt, encoding="utf-8")
    return path


def _prompt_file_message(prompt_path: Path) -> str:
    return (
        "请读取并严格执行以下提示文件中的完整任务说明；不要只回复文件内容，"
        f"必须按文件内要求完成分析、写入指定 artifact 并调用 MCP 工具：`{prompt_path.resolve()}`。"
    )


def _cleanup_prompt_file(prompt_file: Path | None) -> None:
    if prompt_file is None:
        return
    try:
        prompt_file.unlink()
    except OSError:
        pass


def _build_cli_env(
    workspace: Path,
    tool: str,
    base_env: dict[str, str] | None = None,
    writable_paths: list[Path] | None = None,
) -> dict[str, str]:
    env = dict(base_env or os.environ)
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    if tool in {"nga", "opencode"}:
        opencode_config = _with_writable_paths(_read_opencode_config(workspace), writable_paths)
        if opencode_config:
            env["OPENCODE_CONFIG_CONTENT"] = json.dumps(opencode_config, ensure_ascii=False)
    return env


def _select_cli_cwd(
    workspace: Path,
    tool: str,
    project_dir: Path | None = None,
    runtime_namespace: str | None = None,
) -> Path:
    if tool in {"nga", "opencode"} and project_dir:
        runtime_dir = project_dir / ".opendeephole" / "opencode"
        if runtime_namespace:
            safe_namespace = re.sub(r"[^A-Za-z0-9_.-]+", "_", runtime_namespace).strip("._")
            if safe_namespace:
                runtime_dir = runtime_dir / safe_namespace
        try:
            runtime_dir.mkdir(parents=True, exist_ok=True)
            return runtime_dir
        except Exception as exc:
            logger.warning(
                "Failed to create %s runtime directory %s; using workspace %s: %s",
                tool, runtime_dir, workspace, exc,
            )
    return workspace


def _close_process_stdout(proc: subprocess.Popen) -> None:
    try:
        if proc.stdout is not None:
            proc.stdout.close()
    except Exception:
        pass


def _terminate_process_tree(proc: subprocess.Popen, *, tool: str, reason: str) -> None:
    """Best-effort termination of the CLI and any child processes it spawned."""
    if proc.poll() is not None:
        return

    logger.warning(
        "Terminating %s process tree pid=%s reason=%s",
        tool, proc.pid, reason,
    )
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            if result.returncode != 0 and proc.poll() is None:
                proc.kill()
        except Exception as exc:
            logger.warning(
                "taskkill failed for %s pid=%s reason=%s: %s",
                tool, proc.pid, reason, exc,
            )
            try:
                proc.kill()
            except Exception:
                pass
        _close_process_stdout(proc)
        return

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    _close_process_stdout(proc)


async def _wait_for_stream_exit_after_termination(
    stream_future,
    *,
    tool: str,
    timed_out: bool,
    cancelled: bool,
    timeout: int,
    started: float,
    grace_seconds: float = PROCESS_EXIT_GRACE_SECONDS,
) -> None:
    elapsed = time.monotonic() - started
    logger.warning(
        "%s process termination requested after %.1fs (timeout=%ds, timed_out=%s, cancelled=%s)",
        tool, elapsed, timeout, timed_out, cancelled,
    )
    try:
        await asyncio.wait_for(asyncio.shield(stream_future), timeout=grace_seconds)
    except asyncio.TimeoutError:
        logger.error(
            "%s output reader did not exit within %.1fs after process termination",
            tool, grace_seconds,
        )


async def _invoke_opencode(
    workspace: Path,
    prompt: str,
    timeout: int,
    log_path: Path | None = None,
    on_line=None,
    cancel_event=None,
    cli_config=None,
    project_dir: Path | None = None,
    writable_paths: list[Path] | None = None,
    model_capability: str = "any",
    prefer_high_model: bool = False,
    stats_scope_id: str = "",
) -> None:
    """Invoke the configured AI CLI, stream output line-by-line, write to log file.

    Uses subprocess.Popen in a thread executor instead of
    asyncio.create_subprocess_exec to avoid the asyncio child-watcher
    requirement on Linux (which raises NotImplementedError in some
    environments regardless of Python version).
    """
    config = get_config()
    cli_config = cli_config or config.opencode
    lease = await acquire_model_lease(
        cli_config,
        global_concurrency=configured_global_concurrency(config),
        required_capability=model_capability,
        prefer_high=prefer_high_model,
        cancel_event=cancel_event,
        stats_scope_id=stats_scope_id,
    )
    if lease is None:
        return
    outcome = "failure"
    duration_seconds: float | None = None
    try:
        invoke_started = lease.started_at or time.monotonic()
        effective_cli_config = _effective_cli_config(cli_config, lease.option)
        timeout = int(_cfg_value(effective_cli_config, "timeout", timeout) or timeout)
        tool = _normalize_tool(effective_cli_config)
        executable = _resolve_cli_executable(effective_cli_config)
        model = str(_cfg_value(effective_cli_config, "model", "") or "")
        runtime_namespace = f"{lease.option.id}-{uuid4().hex[:8]}"
        cwd = _select_cli_cwd(workspace, tool, project_dir, runtime_namespace=runtime_namespace)
        if on_line:
            capability_note = model_capability or "any"
            on_line(
                f"[{tool}] model={lease.option.id} capability={lease.option.capability} "
                f"required={capability_note} running={lease.running}/{lease.global_running}"
            )
        prompt_file: Path | None = None
        # When the prompt is very long, pass a short file-reference message instead
        # of the full command-line argument to avoid hitting the Windows
        # CreateProcess 32767-character limit ([WinError 206]).
        _PROMPT_CLI_LIMIT = 8000
        prompt_arg = prompt
        if len(prompt) > _PROMPT_CLI_LIMIT:
            prompt_file = _write_prompt_file(cwd, prompt)
            prompt_arg = _prompt_file_message(prompt_file)
        cmd = _build_cli_command(
            tool, executable, workspace, prompt_arg, model,
            project_dir=project_dir,
        )

        logger.debug("%s command: %s", tool, " ".join(shlex.quote(part) for part in cmd))

        config_workspace = _prepare_cli_workspace(
            workspace,
            tool,
            runtime_cwd=cwd,
            writable_paths=writable_paths,
        )
        env = _build_cli_env(config_workspace, tool, writable_paths=writable_paths)

        kwargs: dict = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        loop = asyncio.get_running_loop()
        # Queue carries output lines; None is the end-of-stream sentinel.
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        proc_holder: list[subprocess.Popen | None] = [None]

        def _stream() -> int:
            """Blocking: run the selected CLI, push lines into the asyncio queue."""
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
                env=env,
                **kwargs,
            )
            proc_holder[0] = proc
            try:
                assert proc.stdout is not None
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        if proc.poll() is not None:
                            break
                        continue
                    line = _strip_ansi(line.rstrip())
                    if line:
                        loop.call_soon_threadsafe(queue.put_nowait, line)
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                proc.wait()
                loop.call_soon_threadsafe(queue.put_nowait, None)
            return proc.returncode

        def _terminate(reason: str) -> None:
            proc = proc_holder[0]
            if proc is not None:
                _terminate_process_tree(proc, tool=tool, reason=reason)

        stream_future = loop.run_in_executor(None, _stream)

        # Watcher: kill proc immediately when cancel_event fires.
        async def _cancel_watcher() -> None:
            if cancel_event:
                while not cancel_event.is_set():
                    await asyncio.sleep(0.2)
                _terminate("cancel")

        watcher = asyncio.create_task(_cancel_watcher()) if cancel_event else None

        log_lines: list[str] = []
        started = time.monotonic()
        deadline = asyncio.get_event_loop().time() + timeout
        timed_out = False
        cancelled = False

        try:
            while True:
                if cancel_event and cancel_event.is_set():
                    cancelled = True
                    _terminate("cancel")
                    break
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    timed_out = True
                    _terminate("timeout")
                    break
                try:
                    line = await asyncio.wait_for(queue.get(), timeout=min(remaining, 1.0))
                except asyncio.TimeoutError:
                    continue
                if line is None:  # end-of-stream sentinel
                    break
                log_lines.append(line)
                logger.debug("[%s] %s", tool, line)
                if on_line:
                    on_line(line)
        finally:
            if watcher:
                watcher.cancel()
                try:
                    await watcher
                except asyncio.CancelledError:
                    pass
            if log_path and log_lines:
                try:
                    log_path.write_text("\n".join(log_lines), encoding="utf-8")
                except Exception:
                    pass

        if timed_out or cancelled:
            await _wait_for_stream_exit_after_termination(
                stream_future,
                tool=tool,
                timed_out=timed_out,
                cancelled=cancelled,
                timeout=timeout,
                started=started,
            )
            _cleanup_prompt_file(prompt_file)
            if timed_out:
                outcome = "timeout"
                raise asyncio.TimeoutError()
            outcome = "cancelled"
            return

        try:
            await stream_future  # wait for thread to exit cleanly
        finally:
            _cleanup_prompt_file(prompt_file)

        proc = proc_holder[0]
        if proc and proc.returncode not in (0, None):
            logger.error("%s exited with code %d", tool, proc.returncode)
            raise RuntimeError(f"{tool} exited with code {proc.returncode}")
        outcome = "success"
    except asyncio.CancelledError:
        outcome = "cancelled"
        raise
    finally:
        if 'invoke_started' in locals():
            duration_seconds = time.monotonic() - invoke_started
        await release_model_lease(lease, outcome=outcome, duration_seconds=duration_seconds)


def _result_payloads(data) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return [item for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _vulnerability_from_payload(data: dict, candidate: Candidate) -> Vulnerability:
    confirmed = data.get("confirmed", False)
    file_value = str(data.get("file") or candidate.file)
    function_value = str(data.get("function") or candidate.function)
    try:
        line_value = int(data.get("line") or candidate.line)
    except (TypeError, ValueError):
        line_value = candidate.line
    if line_value < 1:
        line_value = candidate.line
    return Vulnerability(
        file=file_value,
        line=line_value,
        function=function_value,
        vuln_type=candidate.vuln_type,
        severity=data.get("severity", "unknown"),
        description=data.get("description", candidate.description),
        ai_analysis=data.get("ai_analysis", ""),
        confirmed=confirmed,
        ai_verdict="confirmed" if confirmed else "not_confirmed",
    )


def _read_result_file(result_id: str, candidate: Candidate):
    config = get_config()
    result_path = Path(config.storage.scans_dir) / f"{result_id}.json"

    if not result_path.exists():
        logger.warning(
            "submit_result was not called for %s:%d (result_id=%s, path=%s)",
            candidate.file, candidate.line, result_id, result_path,
        )
        return None

    try:
        return json.loads(result_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error(
            "Failed to parse result file for result_id=%s path=%s: %s",
            result_id, result_path, exc,
        )
        return None


def _read_results(result_id: str, candidate: Candidate) -> list[Vulnerability]:
    """Read all result payloads written for a project-level audit."""
    data = _read_result_file(result_id, candidate)
    if data is None:
        return []
    return [_vulnerability_from_payload(item, candidate) for item in _result_payloads(data)]


def _read_result(result_id: str, candidate: Candidate) -> Vulnerability | None:
    """Read one result file written by the submit_result MCP tool."""
    results = _read_results(result_id, candidate)
    if not results:
        return None
    return results[-1]


async def run_audit_batch(
    workspace: Path,
    candidates: list[Candidate],
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> list[Vulnerability | None]:
    """Run batch audit for multiple candidates in the same function.

    In LLM API mode, sends all candidates in one LLM call.
    In opencode CLI mode, falls back to sequential single-candidate calls.
    """
    config = get_config()

    if config.opencode.mock:
        return [_mock_result(c) for c in candidates]

    # 按 checker 的 mode 决定调用方式
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidates[0].vuln_type) if candidates else None
    use_api = checker_entry is not None and checker_entry.mode == "api"

    if use_api:
        from backend.opencode.llm_api_runner import (
            LLMApiUnavailableError,
            ensure_llm_api_available,
            run_batch_audit_via_api,
        )
        try:
            await ensure_llm_api_available(on_output=on_output)
            # 优先使用 workspace 中合并了反馈的 prompt
            merged_prompt = workspace / ".opencode" / "skills" / candidates[0].vuln_type / "PROMPT.md"
            prompt_path = merged_prompt if merged_prompt.is_file() else checker_entry.prompt_path
            return await run_batch_audit_via_api(
                candidates, project_id,
                prompt_path=prompt_path,
                on_output=on_output,
                cancel_event=cancel_event,
            )
        except LLMApiUnavailableError as exc:
            logger.warning(
                "LLM API unavailable for checker %s batch; falling back to CLI audit: %s",
                candidates[0].vuln_type, exc,
            )
            if on_output:
                on_output(f"[API] API 不可用，批量审计降级为 CLI 审计: {exc}")

    # CLI 模式：退化为逐个调用
    results = []
    for candidate in candidates:
        if cancel_event and cancel_event.is_set():
            results.append(None)
            continue
        vuln = await _run_audit_via_opencode(
            workspace, candidate, project_id,
            checker_entry,
            on_output=on_output,
            cancel_event=cancel_event,
            timeout=timeout,
            project_dir=project_dir,
        )
        results.append(vuln)
    return results


def _mock_result(candidate: Candidate) -> Vulnerability:
    """Return a fake analysis result for testing without opencode."""
    logger.debug("Mock opencode result for %s:%d", candidate.file, candidate.line)
    return Vulnerability(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        severity="high",
        description=candidate.description,
        ai_analysis=(
            f"[MOCK] Potential {candidate.vuln_type.upper()} detected: "
            f"{candidate.description}. "
            f"This is a mock result — configure opencode for real analysis."
        ),
        confirmed=True,
        ai_verdict="confirmed",
    )
