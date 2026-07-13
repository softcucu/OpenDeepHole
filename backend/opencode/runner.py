"""opencode CLI runner — invokes opencode for AI-powered vulnerability analysis."""

import asyncio
import copy
import hashlib
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
from backend.models import Candidate, OutputSource, ThreatAnalysis, ThreatAuditTask, Vulnerability
from backend.opencode.model_pool import (
    NoAvailableModelError,
    acquire_model_lease,
    clear_planned_task,
    configured_global_concurrency,
    release_model_lease,
    update_model_lease_context,
)
from backend.opencode.output_format import with_local_timestamp
from backend.opencode.serve_client import get_serve_manager
from backend.opencode.result_json import (
    VULNERABILITY_RESULT_JSON_INSTRUCTION,
    VULNERABILITY_RESULTS_JSON_INSTRUCTION,
    parse_vulnerability_result,
    parse_vulnerability_results,
)
from backend.threat_analysis import (
    apply_threat_analysis_scan_scope,
    parse_threat_analysis_file,
    write_threat_analysis_file,
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
_GLOBAL_OPENCODE_CONFIG_FILENAMES = ("config.json", "opencode.json", "opencode.jsonc")
_PROJECT_OPENCODE_CONFIG_FILENAMES = ("config.json", "opencode.json", "opencode.jsonc")
_OPENCODE_CONFIG_PATH_ENV = "OPENCODE_CONFIG_PATH"
_OPENCODE_PROXY_URL_ENV = "OPENCODE_PROXY_URL"
_OPENCODE_NO_PROXY_ENV = "OPENCODE_NO_PROXY"
_DEFAULT_OPENCODE_NO_PROXY = (
    "mirrors.tools.huawei.com,.athuawei.com,.hic.cloud,.huawei.com,"
    ".huaweimarine.com,.huaweimossel.com,.huaweistatic.com,.hw3static.com,"
    ".hwht.com,.hwtelcloud.com,.hwtrip.com,.inhuawei.com,.pinjiantrip.com,"
    "127.0.0.1,localhost,172.30.53.14,172.30.50.214,172.30.60.113,"
    "172.30.59.148,192.168.76.2,10.96.0.0/12,192.168.59.0/24,"
    "192.168.49.0/24,192.168.39.0/24"
)
_OPENCODE_PROCESS_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)
_OPENCODE_PROXY_CLEAR_ENV_KEYS = ("ALL_PROXY", "all_proxy")


@dataclass
class SensitiveClearAuditResult:
    vulnerabilities: list[Vulnerability]
    reports: list[dict]
    complete: bool


@dataclass(frozen=True)
class _VulnerabilityResultDefaults:
    """Fallback identity used while parsing one audit's final JSON results."""

    file: str
    line: int
    function: str
    vuln_type: str
    description: str

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
        await _clear_candidate_planned_task(candidate)
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
            await _clear_candidate_planned_task(candidate)
            return await run_audit_via_api(
                candidate, project_id,
                prompt_path=prompt_path,
                on_output=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
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
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):  # attempt 1 .. max_retries+1
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = source
            last_source = source

        prompt = (
            f"使用 `{skill_name}` 技能，分析位于 "
            f"{candidate.file}:{candidate.line} 函数 `{candidate.function}` 中"
            f"潜在的 {candidate.vuln_type.upper()} 漏洞。"
            f"project_id 为 `{project_id}`。"
            f"详情：{candidate.description} "
            f"分析完成后按最终结果返回规则输出 JSON 结论。"
        )
        if attempt > 1:
            prompt += _json_result_retry_message()
        prompt = _with_json_result_instruction(prompt.replace('\n', ' '))

        log_path = workspace / f"opencode_attempt_{attempt_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s audit: %s:%d (%s) timeout=%ds attempt=%d/%d",
            tool,
            candidate.file, candidate.line, candidate.vuln_type,
            effective_timeout, attempt, max_retries + 1,
        )

        try:
            output_text = await _invoke_opencode(
                workspace, prompt, effective_timeout,
                log_path=log_path, on_line=on_output, cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
                task_context=_candidate_task_context(candidate),
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.TimeoutError:
            # Timeout — no retry; check if result was submitted before kill
            logger.error("%s timed out for %s:%d (timeout=%ds)", tool, candidate.file, candidate.line, effective_timeout)
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
                failure_reason=_failure_reason(log_path, f"{tool} timed out after {effective_timeout} seconds"),
                output_source=attempt_source or OutputSource(),
            )
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            # Process error (e.g. certificate error, crash) — may retry
            logger.exception("%s failed for %s:%d (attempt %d)", tool, candidate.file, candidate.line, attempt)
            if attempt <= max_retries:
                logger.info("Retrying opencode for %s:%d ...", candidate.file, candidate.line)
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _apply_output_source(_failed_result(
                candidate,
                _failure_reason(log_path, f"{tool} error: {exc}"),
            ), attempt_source)

        # Process completed — parse final JSON result
        result = _parse_result_from_text(output_text, candidate)
        if result is not None:
            return _apply_output_source(result, attempt_source)

        # JSON result was not returned — retry if attempts remain
        if attempt <= max_retries:
            logger.warning(
                "%s did not return valid JSON result for %s:%d (attempt %d), retrying...",
                tool, candidate.file, candidate.line, attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No valid JSON result returned, retrying...")
            continue

        logger.warning("%s did not return valid JSON result for %s:%d after %d attempts", tool, candidate.file, candidate.line, attempt)
        return _apply_output_source(_failed_result(
            candidate,
            _failure_reason(log_path, f"{tool} completed but did not return a valid JSON result"),
            analysis="OpenCode completed without returning a valid JSON result",
        ), attempt_source)

    return _apply_output_source(_failed_result(candidate, "OpenCode did not return a result"), last_source)


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
        await _clear_candidate_planned_task(candidate)
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
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = source
            last_source = source

        prompt = (
            f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
            f"project_id 为 `{project_id}`。"
            f"这是项目级审计任务，不是单个候选点复核。"
            f"file=`{candidate.file}`，line={candidate.line}，function=`{candidate.function}`。"
        ).replace("\n", " ")
        if attempt > 1:
            prompt += _json_result_retry_message(multiple=True)
        prompt = _with_json_result_instruction(prompt, multiple=True)
        log_path = workspace / f"opencode_attempt_{attempt_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s project audit: %s (%s) timeout=%ds attempt=%d/%d",
            tool, candidate.file, candidate.vuln_type,
            effective_timeout, attempt, max_retries + 1,
        )

        try:
            output_text = await _invoke_opencode(
                workspace, prompt, effective_timeout,
                log_path=log_path, on_line=on_output, cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
                task_context=_candidate_task_context(candidate, "project_audit"),
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.TimeoutError:
            logger.error("%s project audit timed out for %s (timeout=%ds)", tool, candidate.vuln_type, effective_timeout)
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
                    failure_reason=_failure_reason(log_path, f"{tool} timed out after {effective_timeout} seconds"),
                    output_source=attempt_source or OutputSource(),
                )
            ]
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            logger.exception("%s project audit failed for %s (attempt %d)", tool, candidate.vuln_type, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _apply_output_source_to_list(
                [_failed_result(candidate, _failure_reason(log_path, f"{tool} error: {exc}"))],
                attempt_source,
            )

        results = _parse_results_from_text(output_text, candidate)
        if results:
            return _apply_output_source_to_list(results, attempt_source)
        if attempt <= max_retries:
            logger.warning(
                "%s project audit did not return valid JSON results for %s (attempt %d), retrying...",
                tool, candidate.vuln_type, attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No valid JSON results returned, retrying...")
            continue
        logger.warning("%s project audit did not return valid JSON results for %s after %d attempts", tool, candidate.vuln_type, attempt)
        return _apply_output_source_to_list([
            _failed_result(
                candidate,
                _failure_reason(log_path, f"{tool} completed but did not return valid JSON results"),
                analysis="OpenCode completed without returning valid JSON results",
            )
        ], attempt_source)

    return _apply_output_source_to_list([_failed_result(candidate, "OpenCode did not return a result")], last_source)


def _sensitive_clear_function(candidate: Candidate) -> dict:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    if metadata.get("kind") != "sensitive_clear_function":
        return {}
    function_name = str(metadata.get("function_name") or candidate.function or "")
    if not function_name:
        return {}
    return metadata


def _sensitive_clear_prompt(skill_name: str, candidate: Candidate, project_id: str) -> str:
    metadata = _sensitive_clear_function(candidate)
    function_name = str(metadata.get("function_name") or candidate.function or "")
    file_path = str(metadata.get("file") or candidate.file or "")
    return (
        f"使用 `{skill_name}` 技能分析 `{file_path}` 文件中的 `{function_name}` 函数敏感信息未清0问题。"
        f"project_id: `{project_id}`。"
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


def _sensitive_clear_audit_result_from_payload(
    payload: dict,
    candidate: Candidate,
) -> SensitiveClearAuditResult | None:
    metadata = _sensitive_clear_function(candidate)
    if not metadata:
        return None
    markdown = str(payload.get("ai_analysis") or "").strip()
    if not markdown:
        logger.warning("Empty sensitive_clear Markdown ai_analysis for %s:%d", candidate.file, candidate.line)
        return None

    function_name = str(payload.get("function") or metadata.get("function_name") or candidate.function or "")
    confirmed = bool(payload.get("confirmed", False))
    severity = str(payload.get("severity") or ("high" if confirmed else "low"))
    description = str(payload.get("description") or "")
    file_path = str(payload.get("file") or metadata.get("file") or candidate.file)
    line = _safe_int(payload.get("line"), _safe_int(metadata.get("start_line"), candidate.line))
    vulnerabilities = [
        Vulnerability(
            file=file_path,
            line=line,
            function=function_name,
            vuln_type=candidate.vuln_type,
            severity=severity or ("high" if confirmed else "low"),
            description=description or (
                f"{function_name} 中存在敏感信息生命周期结束后未清零问题"
                if confirmed
                else f"{function_name} 未确认敏感信息生命周期结束后未清零问题"
            ),
            ai_analysis=markdown,
            confirmed=confirmed,
            ai_verdict="confirmed" if confirmed else "not_confirmed",
        )
    ]

    return SensitiveClearAuditResult(vulnerabilities=vulnerabilities, reports=[], complete=True)


def _parse_sensitive_clear_audit_result(text: str, candidate: Candidate) -> SensitiveClearAuditResult | None:
    try:
        payload = parse_vulnerability_result(text)
    except Exception as exc:
        logger.warning(
            "Failed to parse sensitive_clear JSON result for %s:%d: %s",
            candidate.file, candidate.line, exc,
        )
        return None
    return _sensitive_clear_audit_result_from_payload(payload, candidate)


def _read_sensitive_clear_audit_result(session_id: str, candidate: Candidate) -> SensitiveClearAuditResult | None:
    """Legacy reader for tests/tools that still inspect submit_result sink data."""
    payload_data = _read_session_result_file(session_id, candidate, tool_name="submit_result")
    if payload_data is None:
        return None
    payloads = _result_payloads(payload_data)
    if len(payloads) != 1:
        logger.warning(
            "Expected exactly one sensitive_clear result for session_id=%s, got %d",
            session_id, len(payloads),
        )
        return None
    return _sensitive_clear_audit_result_from_payload(payloads[0], candidate)


async def run_sensitive_clear_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> SensitiveClearAuditResult:
    """Run one sensitive_clear function audit and collect one Markdown result."""
    config = get_config()
    if config.opencode.mock:
        await _clear_candidate_planned_task(candidate)
        return SensitiveClearAuditResult(
            vulnerabilities=[_mock_result(candidate)],
            reports=[],
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
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = source
            last_source = source

        prompt = _with_json_result_instruction(
            _sensitive_clear_prompt(skill_name, candidate, project_id)
        )
        if attempt > 1:
            prompt += _json_result_retry_message()
        log_path = workspace / f"opencode_attempt_{attempt_id}.log"
        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")
        logger.info(
            "Running %s sensitive_clear function audit: %s timeout=%ds attempt=%d/%d",
            tool, candidate.file, effective_timeout, attempt, max_retries + 1,
        )

        try:
            output_text = await _invoke_opencode(
                workspace,
                prompt,
                effective_timeout,
                log_path=log_path,
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability=getattr(checker_entry, "model_capability", "any"),
                stats_scope_id=project_id,
                task_context=_candidate_task_context(candidate, "sensitive_clear"),
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.TimeoutError:
            logger.error("%s sensitive_clear audit timed out for %s", tool, candidate.file)
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
                        failure_reason=_failure_reason(log_path, f"{tool} timed out after {effective_timeout} seconds"),
                        output_source=attempt_source or OutputSource(),
                    )
                ],
                reports=[],
                complete=False,
            )
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            logger.exception("%s sensitive_clear audit failed for %s (attempt %d)", tool, candidate.file, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return SensitiveClearAuditResult(
                vulnerabilities=_apply_output_source_to_list(
                    [_failed_result(candidate, _failure_reason(log_path, f"{tool} error: {exc}"))],
                    attempt_source,
                ),
                reports=[],
                complete=False,
            )

        parsed = _parse_sensitive_clear_audit_result(output_text, candidate)
        if parsed is not None:
            _apply_output_source_to_list(parsed.vulnerabilities, attempt_source)
            return parsed
        if attempt <= max_retries:
            logger.warning("%s sensitive_clear audit produced invalid/incomplete JSON result; retrying", tool)
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] Incomplete sensitive_clear JSON result, retrying...")
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
                    ai_analysis="No complete function-level JSON result returned",
                    confirmed=False,
                    ai_verdict="failed",
                    failure_reason=_failure_reason(log_path, "No complete function-level JSON result returned"),
                    output_source=attempt_source or OutputSource(),
                )
            ],
            reports=[],
            complete=False,
        )

    return SensitiveClearAuditResult(
        vulnerabilities=_apply_output_source_to_list(
            [_failed_result(candidate, "OpenCode did not return a result")],
            last_source,
        ),
        reports=[],
        complete=False,
    )


def _markdown_title(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or fallback
    return fallback


def _collect_markdown_reports(
    report_dir: Path,
    checker_name: str,
    output_source: OutputSource | None = None,
) -> list[dict]:
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
                "output_source": (output_source or OutputSource()).model_dump(),
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
        await _clear_candidate_planned_task(candidate)
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
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source
            attempt_source = source

        for old_report in report_dir.glob("*.md"):
            try:
                old_report.unlink()
            except OSError:
                pass
        prompt = (
            f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
            f"project_id 为 `{project_id}`。"
            f"这是用户创建的 Markdown 报告型项目级审计任务。"
            f"REPORT_DIR 为 `{report_dir.resolve()}`。"
            f"你必须将一个或多个 Markdown 报告写入 REPORT_DIR，文件扩展名必须是 .md。"
            f"不得修改 REPORT_DIR 之外的任何文件。"
            f"如果没有发现问题，也要写入一个 Markdown 报告说明审计范围和未发现问题的原因。"
        ).replace("\n", " ")
        log_path = workspace / f"opencode_attempt_{attempt_id}.log"

        if on_output:
            on_output(f"[{tool}] 初始提示词:\n{prompt}")

        logger.info(
            "Running %s report audit: %s (%s) timeout=%ds attempt=%d/%d report_dir=%s",
            tool, candidate.file, candidate.vuln_type, effective_timeout,
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
                task_context=_candidate_task_context(candidate, "report_audit"),
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.TimeoutError:
            logger.error(
                "%s report audit timed out for %s (timeout=%ds)",
                tool, candidate.vuln_type, effective_timeout,
            )
            return _collect_markdown_reports(report_dir, candidate.vuln_type, attempt_source)
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            logger.exception("%s report audit failed for %s (attempt %d)", tool, candidate.vuln_type, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _collect_markdown_reports(report_dir, candidate.vuln_type, attempt_source)

        reports = _collect_markdown_reports(report_dir, candidate.vuln_type, attempt_source)
        if reports:
            return reports
        if attempt <= max_retries:
            logger.warning("%s report audit produced no Markdown files for %s; retrying", tool, candidate.vuln_type)
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No Markdown report written, retrying...")
            continue
        return []

    return []


def _threat_audit_result_defaults(task: ThreatAuditTask) -> _VulnerabilityResultDefaults:
    primary_code_path = task.code_path or (task.code_paths[0].path if task.code_paths else ".")
    return _VulnerabilityResultDefaults(
        file=primary_code_path,
        line=1,
        function="__threat_path__",
        description=task.description or (
            f"Threat audit for surface `{task.surface_name}` via method `{task.method_name}` "
            f"on code path `{primary_code_path}`"
        ),
        vuln_type="threat_audit",
    )


def _annotate_threat_audit_results(
    results: list[Vulnerability],
    task: ThreatAuditTask,
) -> list[Vulnerability]:
    for vuln in results:
        vuln.analysis_source = "threat_audit"
        vuln.source_task_id = task.task_id
        vuln.threat_surface_node_id = task.surface_node_id
        vuln.threat_method_node_id = task.method_node_id
        vuln.threat_code_path = task.code_path or ", ".join(
            item.path for item in task.code_paths if item.path
        )
    return results


async def run_threat_audit(
    workspace: Path,
    task: ThreatAuditTask,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
    planned_task_id: str = "",
    scan_path: Path | str | None = None,
) -> list[Vulnerability]:
    """Run one attack-tree-derived audit task and collect submitted results."""
    config = get_config()
    defaults = _threat_audit_result_defaults(task)
    if config.opencode.mock:
        await _clear_planned_task_id(planned_task_id)
        return _annotate_threat_audit_results([_mock_result_from_defaults(defaults)], task)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = _normalize_tool(config.opencode)
    max_retries = config.opencode.max_retries
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = source
            last_source = source

        surface_label = task.surface_name or task.surface_node_id or "相关攻击面"
        method_label = task.method_name or task.method_node_id or "相关攻击方式"
        if isinstance(scan_path, Path):
            scan_path_label = scan_path.resolve().as_posix()
        else:
            scan_path_label = str(scan_path or "").strip()
        if not scan_path_label and project_dir is not None:
            scan_path_label = project_dir.resolve().as_posix()
        if not scan_path_label:
            scan_path_label = "当前扫描目录"
        code_paths_label = ", ".join(
            item.path for item in task.code_paths if item.path
        ) or task.code_path or "威胁分析未定位明确代码路径"
        prompt = (
            f"审计代码仓{scan_path_label}中{surface_label}的实现是否存在漏洞，导致{method_label}。"
            f"威胁分析给出的相关代码路径为：{code_paths_label}。"
            f"攻击路径上下文：{task.description or '未提供'}。"
        ).replace("\n", " ")
        if attempt > 1:
            prompt += _json_result_retry_message(multiple=True)
        prompt = _with_json_result_instruction(prompt, multiple=True)
        log_path = workspace / f"opencode_threat_audit_{attempt_id}.log"

        if on_output:
            on_output(f"[{tool}] 威胁审计提示词:\n{prompt}")

        logger.info(
            "Running %s threat audit: task_id=%s path=%s timeout=%ds attempt=%d/%d",
            tool, task.task_id, task.code_path, effective_timeout, attempt, max_retries + 1,
        )

        task_context = {
            "task_type": "threat_audit",
            "checker": "threat_audit",
            "file": task.code_path,
            "function": defaults.function,
            "threat_surface_node_id": task.surface_node_id,
            "threat_method_node_id": task.method_node_id,
            "threat_attack_path_id": task.attack_path_id,
            "threat_attack_path_fingerprint": task.attack_path_fingerprint,
        }
        if planned_task_id:
            task_context["planned_task_id"] = planned_task_id

        try:
            output_text = await _invoke_opencode(
                workspace,
                prompt,
                effective_timeout,
                log_path=log_path,
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
                model_capability="high",
                prefer_high_model=True,
                stats_scope_id=project_id,
                task_context=task_context,
                attempt=attempt,
                on_invocation_metadata=capture_source,
            )
        except asyncio.TimeoutError:
            logger.error("%s threat audit timed out for %s", tool, task.task_id)
            return _annotate_threat_audit_results([
                Vulnerability(
                    file=defaults.file,
                    line=defaults.line,
                    function=defaults.function,
                    vuln_type=defaults.vuln_type,
                    severity="unknown",
                    description=defaults.description,
                    ai_analysis="Threat audit timed out",
                    confirmed=False,
                    ai_verdict="timeout",
                    failure_reason=_failure_reason(log_path, f"{tool} timed out after {effective_timeout} seconds"),
                    output_source=attempt_source or OutputSource(),
                )
            ], task)
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            logger.exception("%s threat audit failed for %s (attempt %d)", tool, task.task_id, attempt)
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _annotate_threat_audit_results(
                _apply_output_source_to_list([
                    _failed_result_from_defaults(defaults, _failure_reason(log_path, f"{tool} error: {exc}"))
                ], attempt_source),
                task,
            )

        results = _parse_results_from_text_with_defaults(output_text, defaults)
        if results:
            return _annotate_threat_audit_results(
                _apply_output_source_to_list(results, attempt_source),
                task,
            )
        if attempt <= max_retries:
            logger.warning("%s threat audit did not return valid JSON results for %s (attempt %d)", tool, task.task_id, attempt)
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No valid JSON results returned, retrying...")
            continue
        return _annotate_threat_audit_results(
            _apply_output_source_to_list([
                _failed_result_from_defaults(
                    defaults,
                    _failure_reason(log_path, f"{tool} completed but did not return valid JSON threat audit results"),
                    analysis="OpenCode completed without returning valid JSON threat audit results",
                )
            ], attempt_source),
            task,
        )

    return _annotate_threat_audit_results([
        _apply_output_source(_failed_result_from_defaults(defaults, "OpenCode did not return a result"), last_source)
    ], task)


async def run_threat_analysis_audit(
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
    on_attack_paths=None,
) -> ThreatAnalysis | None:
    """Compatibility wrapper for the default attack-tree threat-analysis implementation."""
    from backend.threat_analysis.attack_tree_opencode import run_attack_tree_threat_analysis

    return await run_attack_tree_threat_analysis(
        workspace=workspace,
        project_id=project_id,
        skill_path=skill_path,
        reference_catalog_path=reference_catalog_path,
        on_output=on_output,
        cancel_event=cancel_event,
        timeout=timeout,
        project_dir=project_dir,
        code_scan_path=code_scan_path,
        product=product,
        planned_task_id=planned_task_id,
        on_attack_paths=on_attack_paths,
    )


def _read_fresh_threat_analysis_result(
    result_path: Path,
    old_mtime: float | None,
    started_at: float,
    log_path: Path | None,
    *,
    project_dir: Path | None = None,
    code_scan_path: Path | None = None,
) -> ThreatAnalysis | None:
    if not result_path.is_file():
        logger.warning("Threat analysis res.json was not written: %s", result_path)
        return None
    try:
        mtime = result_path.stat().st_mtime
    except OSError:
        return None
    fresh = old_mtime is None or mtime != old_mtime or mtime >= started_at - 0.5
    if not fresh:
        logger.warning("Ignoring stale threat analysis res.json: %s", result_path)
        return None
    try:
        analysis = parse_threat_analysis_file(result_path)
        if project_dir is not None:
            analysis = apply_threat_analysis_scan_scope(analysis, project_dir, code_scan_path)
            write_threat_analysis_file(result_path, analysis)
        return analysis
    except Exception as exc:
        logger.warning(
            "Failed to parse threat analysis res.json %s: %s\n%s",
            result_path,
            exc,
            _failure_reason(log_path, "Invalid threat analysis JSON"),
        )
        return None


def _cfg_value(config_obj, key: str, default=None):
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


def _output_source_from_invocation(
    *,
    lease,
    tool: str,
    model: str,
    required_capability: str,
    attempt: int,
) -> OutputSource:
    option = lease.option
    return OutputSource(
        backend="cli",
        tool=tool,
        model_id=option.id,
        model=model,
        use_default_model=bool(getattr(option, "use_default_model", False)),
        capability=option.capability,
        required_capability=required_capability or "any",
        task_id=str(getattr(lease, "task_id", "") or ""),
        attempt=attempt,
        started_at=str(getattr(lease, "started_at_iso", "") or ""),
    )


def _apply_output_source(vuln: Vulnerability | None, source: OutputSource | None) -> Vulnerability | None:
    if vuln is not None and source is not None:
        vuln.output_source = source
    return vuln


def _apply_output_source_to_list(
    vulns: list[Vulnerability],
    source: OutputSource | None,
) -> list[Vulnerability]:
    if source is not None:
        for vuln in vulns:
            vuln.output_source = source
    return vulns


def _failed_result(
    candidate: Candidate,
    reason: str,
    *,
    analysis: str | None = None,
) -> Vulnerability:
    return _failed_result_from_defaults(
        _candidate_result_defaults(candidate),
        reason,
        analysis=analysis,
    )


def _candidate_result_defaults(candidate: Candidate) -> _VulnerabilityResultDefaults:
    return _VulnerabilityResultDefaults(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        description=candidate.description,
    )


def _failed_result_from_defaults(
    defaults: _VulnerabilityResultDefaults,
    reason: str,
    *,
    analysis: str | None = None,
) -> Vulnerability:
    return Vulnerability(
        file=defaults.file,
        line=defaults.line,
        function=defaults.function,
        vuln_type=defaults.vuln_type,
        severity="unknown",
        description=defaults.description,
        ai_analysis=analysis or reason,
        confirmed=False,
        ai_verdict="failed",
        failure_reason=reason,
    )


def _failure_reason(log_path: Path | None, fallback: str) -> str:
    if log_path is not None:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            text = ""
        if text:
            if len(text) > 4000:
                text = text[-4000:]
            return f"{fallback}\n\nLast output:\n{text}"
    return fallback


def _effective_cli_config(cli_config, model_option) -> dict:
    data = {
        "tool": _cfg_value(cli_config, "tool", ""),
        "executable": _cfg_value(cli_config, "executable", ""),
        "model": _cfg_value(cli_config, "model", ""),
        "invocation_mode": _cfg_value(cli_config, "invocation_mode", "serve"),
        "timeout": _cfg_value(cli_config, "timeout", 1200),
        "max_retries": _cfg_value(cli_config, "max_retries", 2),
        "models": _cfg_value(cli_config, "models", []),
        "config_paths": _cfg_value(cli_config, "config_paths", []),
        "proxy_url": _cfg_value(cli_config, "proxy_url", ""),
        "no_proxy": _cfg_value(cli_config, "no_proxy", ""),
    }
    if model_option.tool:
        data["tool"] = model_option.tool
    if model_option.executable:
        data["executable"] = model_option.executable
    if getattr(model_option, "use_default_model", False):
        data["model"] = ""
    elif model_option.model:
        data["model"] = model_option.model
    if model_option.timeout is not None:
        data["timeout"] = model_option.timeout
    if model_option.max_retries is not None:
        data["max_retries"] = model_option.max_retries
    return data


def _candidate_task_context(candidate: Candidate, task_type: str = "audit") -> dict:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    context = {
        "task_type": task_type,
        "checker": candidate.vuln_type,
        "file": candidate.file,
        "line": candidate.line,
        "function": candidate.function,
    }
    planned_task_id = str(metadata.get("_opencode_planned_task_id") or "").strip()
    if planned_task_id:
        context["planned_task_id"] = planned_task_id
    if metadata.get("_opencode_audit_index") is not None:
        context["audit_index"] = metadata.get("_opencode_audit_index")
    return context


async def _clear_planned_task_id(planned_task_id: str) -> None:
    planned_task_id = str(planned_task_id or "").strip()
    if not planned_task_id:
        return
    try:
        await clear_planned_task(planned_task_id)
    except Exception as exc:
        logger.debug("clear planned task failed for %s: %s", planned_task_id, exc)


async def _clear_candidate_planned_task(candidate: Candidate) -> None:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    await _clear_planned_task_id(str(metadata.get("_opencode_planned_task_id") or ""))


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
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
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


def _invocation_mode(config_obj) -> str:
    mode = str(_cfg_value(config_obj, "invocation_mode", "serve") or "serve").strip().lower()
    return mode if mode in {"serve", "cli"} else "serve"


def _read_opencode_config(workspace: Path) -> dict:
    try:
        data = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def _strip_jsonc_comments(text: str) -> str:
    result: list[str] = []
    in_string = False
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in {"'", '"'}:
            in_string = True
            quote = char
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            result.extend("  ")
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                result.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            result.extend("  ")
            index += 2
            while index < len(text) - 1:
                if text[index] == "*" and text[index + 1] == "/":
                    result.extend("  ")
                    index += 2
                    break
                result.append("\n" if text[index] in "\r\n" else " ")
                index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _strip_jsonc_trailing_commas(text: str) -> str:
    result: list[str] = []
    in_string = False
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in {"'", '"'}:
            in_string = True
            quote = char
            result.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        result.append(char)
        index += 1
    return "".join(result)


def _read_opencode_config_file(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".jsonc":
            text = _strip_jsonc_trailing_commas(_strip_jsonc_comments(text))
        data = json.loads(text)
    except Exception as exc:
        logger.warning("Ignoring invalid OpenCode config file %s: %s", path, exc)
        return {}
    if isinstance(data, dict):
        return data
    logger.warning("Ignoring non-object OpenCode config file %s", path)
    return {}


def _deep_merge_dicts(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        current = merged.get(key)
        if key == "plugin" and isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_opencode_plugin_lists(current, value)
        elif isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_dicts(current, value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _merge_opencode_plugin_lists(*plugin_lists: list) -> list:
    merged: list = []
    seen: set[str] = set()
    for plugin_list in plugin_lists:
        for entry in plugin_list:
            try:
                key = json.dumps(entry, sort_keys=True, ensure_ascii=False)
            except TypeError:
                key = str(entry)
            if key in seen:
                continue
            seen.add(key)
            merged.append(copy.deepcopy(entry))
    return merged


def _merge_opencode_configs(*configs: dict) -> dict:
    merged: dict = {}
    for config in configs:
        if config:
            merged = _deep_merge_dicts(merged, config)
    return merged


def _config_home_from_env(env: dict[str, str]) -> Path | None:
    xdg_config_home = str(env.get("XDG_CONFIG_HOME") or "").strip()
    if xdg_config_home:
        return Path(xdg_config_home)
    home = str(env.get("HOME") or "").strip()
    if home:
        return Path(home) / ".config"
    if sys.platform == "win32":
        appdata = str(env.get("APPDATA") or "").strip()
        if appdata:
            return Path(appdata)
    return None


def _global_opencode_config_candidates(tool: str, env: dict[str, str]) -> list[tuple[str, Path]]:
    config_home = _config_home_from_env(env)
    if config_home is None:
        return []
    config_names = ["opencode"]
    if tool != "opencode":
        config_names.append(tool)
    paths: list[tuple[str, Path]] = []
    for config_name in config_names:
        config_dir = config_home / config_name
        paths.extend(("global", config_dir / filename) for filename in _GLOBAL_OPENCODE_CONFIG_FILENAMES)
    return paths


def _executable_opencode_config_candidates(executable: str | None) -> list[tuple[str, Path]]:
    executable = str(executable or "").strip()
    if not executable:
        return []
    try:
        executable_path = Path(executable)
    except TypeError:
        return []
    parent = executable_path.parent
    if not str(parent) or str(parent) == ".":
        return []
    paths: list[tuple[str, Path]] = []
    paths.extend(("executable", parent / filename) for filename in _GLOBAL_OPENCODE_CONFIG_FILENAMES)
    paths.extend(("executable", parent / ".opencode" / filename) for filename in _GLOBAL_OPENCODE_CONFIG_FILENAMES)
    return paths


def _project_opencode_config_candidates(project_dir: Path | None) -> list[tuple[str, Path]]:
    if project_dir is None:
        return []
    try:
        root = Path(project_dir)
    except TypeError:
        return []
    if not root.is_dir():
        return []
    paths: list[tuple[str, Path]] = []
    paths.extend(("project", root / filename) for filename in _PROJECT_OPENCODE_CONFIG_FILENAMES)
    paths.extend(("project", root / ".opencode" / filename) for filename in _PROJECT_OPENCODE_CONFIG_FILENAMES)
    return paths


def _split_config_path_value(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    parts: list[str] = []
    for item in text.splitlines():
        for part in item.split(os.pathsep):
            part = part.strip()
            if part:
                parts.append(part)
    return parts


def _expand_explicit_opencode_config_path(raw_path: str) -> list[Path]:
    path = Path(os.path.expandvars(raw_path)).expanduser()
    if path.is_dir():
        return [path / filename for filename in _GLOBAL_OPENCODE_CONFIG_FILENAMES]
    return [path]


def _explicit_opencode_config_candidates(
    env: dict[str, str],
    config_paths: object = None,
) -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = []
    for raw_path in _split_config_path_value(config_paths):
        paths.extend(("configured", path) for path in _expand_explicit_opencode_config_path(raw_path))
    for raw_path in _split_config_path_value(env.get(_OPENCODE_CONFIG_PATH_ENV)):
        paths.extend(("env", path) for path in _expand_explicit_opencode_config_path(raw_path))
    return paths


def _normalize_proxy_url(value: object) -> str:
    proxy = str(value or "").strip()
    if not proxy:
        return ""
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    return proxy


def _opencode_no_proxy_value(cli_config, env: dict[str, str]) -> str:
    configured = str(_cfg_value(cli_config, "no_proxy", "") if cli_config is not None else "").strip()
    if configured:
        return configured
    configured = str(env.get(_OPENCODE_NO_PROXY_ENV, "") or "").strip()
    if configured:
        return configured
    return _DEFAULT_OPENCODE_NO_PROXY


def _opencode_proxy_url_value(cli_config, env: dict[str, str]) -> str:
    for value in (
        _cfg_value(cli_config, "proxy_url", "") if cli_config is not None else "",
        env.get(_OPENCODE_PROXY_URL_ENV, ""),
        env.get("http_proxy", ""),
        env.get("https_proxy", ""),
        env.get("HTTP_PROXY", ""),
        env.get("HTTPS_PROXY", ""),
    ):
        proxy_url = _normalize_proxy_url(value)
        if proxy_url:
            return proxy_url
    return ""


def _opencode_proxy_env_overrides(cli_config, env: dict[str, str]) -> dict[str, str]:
    proxy_url = _opencode_proxy_url_value(cli_config, env)
    if not proxy_url:
        return {}
    for name in _OPENCODE_PROXY_CLEAR_ENV_KEYS:
        env.pop(name, None)
    no_proxy = _opencode_no_proxy_value(cli_config, env)
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


def _opencode_process_env_overrides(env: dict[str, str]) -> dict[str, str]:
    return {name: env[name] for name in _OPENCODE_PROCESS_ENV_KEYS if name in env}


def _log_user_opencode_config_discovery(
    *,
    tool: str,
    project_dir: Path | None,
    executable: str | None,
    details: list[dict[str, object]],
    merged: dict,
) -> None:
    loaded_keys = [
        {
            "source": detail["source"],
            "path": detail["path"],
            "keys": detail["keys"],
        }
        for detail in details
        if detail.get("status") == "loaded"
    ]
    missing_count = sum(1 for detail in details if detail.get("status") == "missing")
    logger.info(
        "OpenCode user config discovery: tool=%s project_dir=%s executable=%s "
        "candidates=%s missing=%s loaded=%s merged_top_keys=%s",
        tool,
        project_dir or "",
        executable or "",
        len(details),
        missing_count,
        loaded_keys,
        sorted(str(key) for key in merged.keys()),
    )
    if merged and "provider" not in merged and "model" not in merged:
        logger.warning(
            "OpenCode merged user config has no provider/model keys; set %s or "
            "opencode.config_paths if your CLI uses a non-standard config file",
            _OPENCODE_CONFIG_PATH_ENV,
        )


def _read_user_opencode_config(
    tool: str,
    project_dir: Path | None,
    env: dict[str, str],
    *,
    executable: str | None = None,
    config_paths: object = None,
) -> dict:
    configs: list[dict] = []
    seen: set[Path] = set()
    details: list[dict[str, object]] = []
    candidates = (
        _global_opencode_config_candidates(tool, env)
        + _executable_opencode_config_candidates(executable)
        + _project_opencode_config_candidates(project_dir)
        + _explicit_opencode_config_candidates(env, config_paths)
    )
    for source, path in candidates:
        try:
            key = path.resolve()
        except Exception:
            key = path
        if key in seen:
            continue
        seen.add(key)
        exists = path.is_file()
        config = _read_opencode_config_file(path)
        status = "loaded" if config else ("empty-or-invalid" if exists else "missing")
        details.append({
            "source": source,
            "path": str(path),
            "status": status,
            "keys": sorted(str(key) for key in config.keys()),
        })
        if config:
            configs.append(config)
    merged = _merge_opencode_configs(*configs)
    _log_user_opencode_config_discovery(
        tool=tool,
        project_dir=project_dir,
        executable=executable,
        details=details,
        merged=merged,
    )
    return merged


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
        _append_submit_result_runtime_override(dst / "SKILL.md")


_SUBMIT_RESULT_RUNTIME_OVERRIDE_MARKER = "<!-- opendeephole-json-result-override -->"
_SUBMIT_RESULT_RUNTIME_OVERRIDE = f"""

{_SUBMIT_RESULT_RUNTIME_OVERRIDE_MARKER}

## OpenDeepHole Runtime Result Rule

当前运行时不再通过 `submit_result` 返回漏洞审计结论。若上文仍要求调用
`submit_result`、或要求不要输出 JSON，以本节和本次任务初始提示词为准：

- 不要调用 `submit_result`。
- 最终回复必须输出符合本次任务初始提示词中“最终结果返回规则”的 JSON。
- `ai_analysis` 字段仍可包含人类可读 Markdown 分析。
"""


def _append_submit_result_runtime_override(skill_path: Path) -> None:
    if not skill_path.is_file():
        return
    try:
        text = skill_path.read_text(encoding="utf-8")
    except Exception:
        return
    if "submit_result" not in text or _SUBMIT_RESULT_RUNTIME_OVERRIDE_MARKER in text:
        return
    try:
        skill_path.write_text(text.rstrip() + _SUBMIT_RESULT_RUNTIME_OVERRIDE + "\n", encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to append JSON result override to %s: %s", skill_path, exc)


_OPENCODE_SESSION_PLUGIN = """\
export const OpenDeepHoleMcpSession = async () => {
  const submitTools = new Set([
    "submit_history_pattern",
    "submit_variant_finding",
    "submit_match_result",
  ])

  const isOpenDeepHoleSubmitTool = (tool: string): boolean => {
    if (!tool) return false
    const hasServerMarker = tool.includes("deephole-code") || tool.includes("deephole_code")
    for (const name of submitTools) {
      if (tool === name) return true
      if (hasServerMarker && (tool.endsWith(`__${name}`) || tool.endsWith(`_${name}`))) return true
    }
    return false
  }

  return {
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args: any },
    ) => {
      if (!isOpenDeepHoleSubmitTool(String(input.tool || ""))) return

      output.args = output.args ?? {}
      output.args.opencode_session_id = input.sessionID
      output.args.opencode_call_id = input.callID
    },
  }
}
"""


def _write_opencode_session_plugin(runtime_cwd: Path) -> Path:
    plugin_path = runtime_cwd / ".opencode" / "plugins" / "inject-mcp-session.ts"
    plugin_path.parent.mkdir(parents=True, exist_ok=True)
    if not plugin_path.is_file() or plugin_path.read_text(encoding="utf-8") != _OPENCODE_SESSION_PLUGIN:
        plugin_path.write_text(_OPENCODE_SESSION_PLUGIN, encoding="utf-8")
    return plugin_path


def _with_opencode_session_plugin(config: dict, plugin_path: Path | None) -> dict:
    if plugin_path is None:
        return config
    next_config = copy.deepcopy(config)
    plugin_entry = str(plugin_path.resolve())
    existing = next_config.get("plugin")
    if isinstance(existing, list):
        plugins = existing
    elif existing:
        plugins = [existing]
    else:
        plugins = []
    next_config["plugin"] = _merge_opencode_plugin_lists(plugins, [plugin_entry])
    return next_config


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
    plugin_path: Path | None = None,
) -> dict:
    config = _with_writable_paths(_read_opencode_config(workspace), writable_paths)
    if not config:
        return {}
    config["skills"] = {"paths": [str(skills_dir.resolve())]}
    return _with_opencode_session_plugin(config, plugin_path)


def _opencode_config_for_env(
    workspace: Path,
    tool: str,
    project_dir: Path | None,
    env: dict[str, str],
    writable_paths: list[Path] | None = None,
    executable: str | None = None,
    config_paths: object = None,
) -> dict:
    user_config = _read_user_opencode_config(
        tool,
        project_dir,
        env,
        executable=executable,
        config_paths=config_paths,
    )
    task_config = _with_writable_paths(_read_opencode_config(workspace), writable_paths)
    merged = _merge_opencode_configs(user_config, task_config)
    merged.pop("$schema", None)
    if merged and "provider" not in merged and "model" not in merged:
        logger.warning(
            "OpenCode config injected through OPENCODE_CONFIG_CONTENT has no provider/model keys; "
            "set %s or opencode.config_paths if your CLI relies on a non-standard config file",
            _OPENCODE_CONFIG_PATH_ENV,
        )
    return merged


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
    The runtime ``opencode.json`` written here contains only OpenDeepHole's
    task-local MCP, permission, and skill wiring. User provider credentials are
    merged later into ``OPENCODE_CONFIG_CONTENT`` and are not written here.
    """
    if runtime_cwd == workspace:
        plugin_path = _write_opencode_session_plugin(runtime_cwd)
        runtime_skills = runtime_cwd / ".opencode" / "skills"
        runtime_config = _opencode_config_for_runtime(
            workspace,
            runtime_skills,
            writable_paths,
            plugin_path=plugin_path,
        )
        if runtime_config:
            _write_json_file(runtime_cwd / "opencode.json", runtime_config)
        return workspace

    source_skills = workspace / ".opencode" / "skills"
    runtime_skills = runtime_cwd / ".opencode" / "skills"
    _copy_skill_tree(source_skills, runtime_skills)
    plugin_path = _write_opencode_session_plugin(runtime_cwd)

    runtime_config = _opencode_config_for_runtime(
        workspace,
        runtime_skills,
        writable_paths,
        plugin_path=plugin_path,
    )
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
        f"必须按文件内要求完成分析并输出指定结果：`{prompt_path.resolve()}`。"
    )


def _invocation_model_label(option, model: str) -> str:
    for value in (
        model,
        getattr(option, "model", ""),
        getattr(option, "id", ""),
    ):
        label = str(value or "").strip()
        if label:
            return label
    return "default"


def _with_json_result_instruction(prompt: str, *, multiple: bool = False) -> str:
    instruction = (
        VULNERABILITY_RESULTS_JSON_INSTRUCTION
        if multiple
        else VULNERABILITY_RESULT_JSON_INSTRUCTION
    )
    if instruction in prompt:
        return prompt
    return prompt.rstrip() + "\n\n" + instruction


def _json_result_retry_message(*, multiple: bool = False) -> str:
    shape = "`{\"results\": [...]}` JSON 对象" if multiple else "单个 JSON 对象"
    return (
        f"上一次尝试没有输出符合 schema 的{shape}。"
        "请重新完成分析，最终只输出符合要求的 JSON，不要调用 submit_result。"
    )


def _with_model_prefix(line: str, model_label: str) -> str:
    prefix = f"[model={model_label}]"
    if line.startswith(prefix):
        return line
    parts = line.splitlines()
    if not parts:
        return f"{prefix} {line}"
    return "\n".join(
        part if part.startswith(prefix) else f"{prefix} {part}"
        for part in parts
    )


def _model_line_emitter(on_line, model_label: str):
    if not on_line:
        return None

    def emit(line: str) -> None:
        on_line(with_local_timestamp(line, prefix=f"[model={model_label}]"))

    return emit


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
    project_dir: Path | None = None,
    executable: str | None = None,
    cli_config=None,
) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    if tool in {"nga", "opencode"}:
        env.update(_opencode_proxy_env_overrides(cli_config, env))
        opencode_config = _opencode_config_for_env(
            workspace,
            tool,
            project_dir,
            env,
            writable_paths=writable_paths,
            executable=executable,
            config_paths=_cfg_value(cli_config, "config_paths", []) if cli_config is not None else [],
        )
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


def _serve_runtime_namespace(workspace: Path) -> str:
    digest = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:12]
    return f"serve-{digest}"


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
    task_context: dict | None = None,
    attempt: int = 0,
    on_invocation_metadata=None,
) -> str:
    """Invoke the configured AI CLI, stream output line-by-line, and return captured text.

    Uses subprocess.Popen in a thread executor instead of
    asyncio.create_subprocess_exec to avoid the asyncio child-watcher
    requirement on Linux (which raises NotImplementedError in some
    environments regardless of Python version).
    """
    config = get_config()
    explicit_cli_config = cli_config is not None
    cli_config = cli_config or config.opencode
    lease_task_context = dict(task_context or {})
    lease_task_context["prompt"] = prompt
    lease_task_context["prompt_length"] = len(prompt)
    lease_cli_config = cli_config if explicit_cli_config else (lambda: get_config().opencode)
    lease_global_concurrency = (
        (lambda: configured_global_concurrency(get_config()))
        if not explicit_cli_config
        else configured_global_concurrency(config)
    )
    lease = await acquire_model_lease(
        lease_cli_config,
        global_concurrency=lease_global_concurrency,
        required_capability=model_capability,
        prefer_high=prefer_high_model,
        cancel_event=cancel_event,
        stats_scope_id=stats_scope_id,
        task_context=lease_task_context,
    )
    if lease is None:
        return ""
    outcome = "failure"
    duration_seconds: float | None = None
    try:
        invoke_started = lease.started_at or time.monotonic()
        if not explicit_cli_config:
            cli_config = get_config().opencode
        effective_cli_config = _effective_cli_config(cli_config, lease.option)
        timeout = int(_cfg_value(effective_cli_config, "timeout", timeout) or timeout)
        tool = _normalize_tool(effective_cli_config)
        executable = _resolve_cli_executable(effective_cli_config)
        model = str(_cfg_value(effective_cli_config, "model", "") or "")
        model_label = _invocation_model_label(lease.option, model)
        emit_line = _model_line_emitter(on_line, model_label)
        invocation_source = _output_source_from_invocation(
            lease=lease,
            tool=tool,
            model=model,
            required_capability=model_capability,
            attempt=attempt,
        )
        if on_invocation_metadata:
            on_invocation_metadata(invocation_source)
        invocation_mode = _invocation_mode(effective_cli_config)
        runtime_namespace = (
            _serve_runtime_namespace(workspace)
            if invocation_mode == "serve" and tool in {"nga", "opencode"}
            else f"{lease.option.id}-{uuid4().hex[:8]}"
        )
        cwd = _select_cli_cwd(workspace, tool, project_dir, runtime_namespace=runtime_namespace)
        if emit_line:
            capability_note = model_capability or "any"
            emit_line(
                f"[{tool}] model={lease.option.id} capability={lease.option.capability} "
                f"required={capability_note} running={lease.running}/{lease.global_running}"
            )
        if invocation_mode == "serve" and tool in {"nga", "opencode"}:
            config_workspace = _prepare_cli_workspace(
                workspace,
                tool,
                runtime_cwd=cwd,
                writable_paths=writable_paths,
            )
            serve_env = _build_cli_env(
                config_workspace,
                tool,
                writable_paths=writable_paths,
                project_dir=project_dir or workspace,
                executable=executable,
                cli_config=effective_cli_config,
            )

            async def record_serve_session(session_id: str) -> None:
                invocation_source.serve_session_id = session_id
                await update_model_lease_context(lease, {"serve_session_id": session_id})

            def record_response_model(actual_model: str) -> None:
                normalized_model = str(actual_model or "").strip()
                if normalized_model:
                    invocation_source.model = normalized_model

            try:
                log_lines = await get_serve_manager().run_prompt(
                    tool=tool,
                    executable=executable,
                    directory=project_dir or workspace,
                    config_workspace=config_workspace,
                    config_content=serve_env.get("OPENCODE_CONFIG_CONTENT"),
                    prompt=prompt,
                    model=model,
                    timeout=timeout,
                    on_line=emit_line,
                    on_session_id=record_serve_session,
                    on_response_model=record_response_model,
                    cancel_event=cancel_event,
                    env_overrides=_opencode_process_env_overrides(serve_env),
                )
            except asyncio.CancelledError:
                if cancel_event and cancel_event.is_set():
                    outcome = "cancelled"
                    return ""
                raise
            except asyncio.TimeoutError:
                outcome = "timeout"
                raise
            if log_path and log_lines:
                try:
                    log_path.write_text("\n".join(log_lines), encoding="utf-8")
                except Exception:
                    pass
            outcome = "success"
            return "\n".join(log_lines)
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
        env = _build_cli_env(
            config_workspace,
            tool,
            writable_paths=writable_paths,
            project_dir=project_dir or workspace,
            executable=executable,
            cli_config=effective_cli_config,
        )

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
                if emit_line:
                    emit_line(line)
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
            return ""

        try:
            await stream_future  # wait for thread to exit cleanly
        finally:
            _cleanup_prompt_file(prompt_file)

        proc = proc_holder[0]
        if proc and proc.returncode not in (0, None):
            logger.error("%s exited with code %d", tool, proc.returncode)
            raise RuntimeError(f"{tool} exited with code {proc.returncode}")
        outcome = "success"
        return "\n".join(log_lines)
    except asyncio.CancelledError:
        outcome = "cancelled"
        raise
    finally:
        if 'invoke_started' in locals():
            duration_seconds = time.monotonic() - invoke_started
        await release_model_lease(lease, outcome=outcome, duration_seconds=duration_seconds)


def _parse_result_from_text(text: str, candidate: Candidate) -> Vulnerability | None:
    defaults = _candidate_result_defaults(candidate)
    try:
        payload = parse_vulnerability_result(text)
    except Exception as exc:
        logger.warning(
            "Failed to parse JSON result for %s:%d: %s",
            candidate.file, candidate.line, exc,
        )
        return None
    return _vulnerability_from_payload_with_defaults(payload, defaults)


def _parse_results_from_text(text: str, candidate: Candidate) -> list[Vulnerability]:
    return _parse_results_from_text_with_defaults(text, _candidate_result_defaults(candidate))


def _parse_results_from_text_with_defaults(
    text: str,
    defaults: _VulnerabilityResultDefaults,
) -> list[Vulnerability]:
    try:
        payloads = parse_vulnerability_results(text)
    except Exception as multi_exc:
        try:
            payloads = [parse_vulnerability_result(text)]
        except Exception as single_exc:
            logger.warning(
                "Failed to parse JSON results for %s:%d: multi=%s single=%s",
                defaults.file, defaults.line, multi_exc, single_exc,
            )
            return []
    return [_vulnerability_from_payload_with_defaults(item, defaults) for item in payloads]


def _result_payloads(data) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return [item for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _vulnerability_from_payload(data: dict, candidate: Candidate) -> Vulnerability:
    return _vulnerability_from_payload_with_defaults(data, _candidate_result_defaults(candidate))


def _vulnerability_from_payload_with_defaults(
    data: dict,
    defaults: _VulnerabilityResultDefaults,
) -> Vulnerability:
    confirmed = data.get("confirmed", False)
    file_value = str(data.get("file") or defaults.file)
    function_value = str(data.get("function") or defaults.function)
    try:
        line_value = int(data.get("line") or defaults.line)
    except (TypeError, ValueError):
        line_value = defaults.line
    if line_value < 1:
        line_value = defaults.line
    return Vulnerability(
        file=file_value,
        line=line_value,
        function=function_value,
        vuln_type=defaults.vuln_type,
        severity=data.get("severity", "unknown"),
        description=data.get("description", defaults.description),
        ai_analysis=data.get("ai_analysis", ""),
        confirmed=confirmed,
        ai_verdict="confirmed" if confirmed else "not_confirmed",
    )


def _session_id_from_output_source(source: OutputSource | None) -> str:
    if source is None:
        return ""
    return str(getattr(source, "serve_session_id", "") or "").strip()


def _read_session_result_file(
    session_id: str,
    candidate: Candidate,
    *,
    tool_name: str = "submit_result",
):
    normalized_session = str(session_id or "").strip()
    if not normalized_session:
        logger.warning(
            "%s was not called for %s:%d (missing serve_session_id)",
            tool_name, candidate.file, candidate.line,
        )
        return None
    try:
        from backend.opencode.submit_sink import read_submissions_as_result_file

        data = read_submissions_as_result_file(normalized_session, tool_name=tool_name)
    except Exception as exc:
        logger.error(
            "Failed to read %s payloads for session_id=%s: %s",
            tool_name, normalized_session, exc,
        )
        return None
    if data is None:
        logger.warning(
            "%s was not called for %s:%d (session_id=%s)",
            tool_name, candidate.file, candidate.line, normalized_session,
        )
    return data


def _read_session_results(
    session_id: str,
    candidate: Candidate,
    *,
    tool_name: str = "submit_result",
) -> list[Vulnerability]:
    data = _read_session_result_file(session_id, candidate, tool_name=tool_name)
    if data is None:
        return []
    return [_vulnerability_from_payload(item, candidate) for item in _result_payloads(data)]


def _read_session_result(
    session_id: str,
    candidate: Candidate,
    *,
    tool_name: str = "submit_result",
) -> Vulnerability | None:
    results = _read_session_results(session_id, candidate, tool_name=tool_name)
    if not results:
        return None
    return results[-1]


def _read_result_from_source(
    source: OutputSource | None,
    candidate: Candidate,
    *,
    tool_name: str = "submit_result",
) -> Vulnerability | None:
    return _read_session_result(
        _session_id_from_output_source(source),
        candidate,
        tool_name=tool_name,
    )


def _read_results_from_source(
    source: OutputSource | None,
    candidate: Candidate,
    *,
    tool_name: str = "submit_result",
) -> list[Vulnerability]:
    return _read_session_results(
        _session_id_from_output_source(source),
        candidate,
        tool_name=tool_name,
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
        for candidate in candidates:
            await _clear_candidate_planned_task(candidate)
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
            for candidate in candidates:
                await _clear_candidate_planned_task(candidate)
            return await run_batch_audit_via_api(
                candidates, project_id,
                prompt_path=prompt_path,
                on_output=on_output,
                cancel_event=cancel_event,
                project_dir=project_dir,
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
    return _mock_result_from_defaults(_candidate_result_defaults(candidate))


def _mock_result_from_defaults(defaults: _VulnerabilityResultDefaults) -> Vulnerability:
    logger.debug("Mock opencode result for %s:%d", defaults.file, defaults.line)
    return Vulnerability(
        file=defaults.file,
        line=defaults.line,
        function=defaults.function,
        vuln_type=defaults.vuln_type,
        severity="high",
        description=defaults.description,
        ai_analysis=(
            f"[MOCK] Potential {defaults.vuln_type.upper()} detected: "
            f"{defaults.description}. "
            f"This is a mock result — configure opencode for real analysis."
        ),
        confirmed=True,
        ai_verdict="confirmed",
    )
