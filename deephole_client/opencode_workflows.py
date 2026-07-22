"""OpenDeepHole-specific workflows built on the Task Agent component."""

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
from task_agent import OpenCodeResult, run_opencode_task
from task_agent.task_service import bind_opencode_execution_context
from task_agent.model_pool import (
    NoAvailableModelError,
    clear_planned_task,
)
from task_agent.config_json import dump_opencode_config, parse_opencode_jsonc
from task_agent.output_format import with_local_timestamp
from task_agent.result_json import (
    AUDITED_VULNERABILITY_RESULT_JSON_INSTRUCTION,
    AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA,
    AUDITED_VULNERABILITY_RESULTS_JSON_INSTRUCTION,
    AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA,
    parse_audited_vulnerability_result,
    parse_audited_vulnerability_results,
)
from backend.threat_analysis import (
    apply_threat_analysis_scan_scope,
    parse_threat_analysis_file,
    write_threat_analysis_file,
)

logger = get_logger(__name__)

AI_CLI_TOOLS = ("nga", "opencode")
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
PROCESS_EXIT_GRACE_SECONDS = 5.0
_DEFAULT_EXECUTABLES = {
    "nga": "nga",
    "opencode": "opencode",
}


def _to_output_source(source) -> OutputSource:
    if isinstance(source, OutputSource):
        return source
    if hasattr(source, "model_dump"):
        value = source.model_dump()
        if isinstance(value, dict):
            return OutputSource(**value)
    if isinstance(source, dict):
        return OutputSource(**source)
    return OutputSource()


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
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)


def _threat_display_label(value: str, fallback: str) -> str:
    normalized = str(value or "").strip()
    if normalized and not _GENERATED_THREAT_ID_PATTERN.fullmatch(normalized):
        return normalized
    return fallback


_OPENCODE_PROXY_CLEAR_ENV_KEYS = ("ALL_PROXY", "all_proxy")

_MARKDOWN_REPORTS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "reports": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "title": {"type": "string"},
                    "content": {"type": "string", "minLength": 1},
                },
                "required": ["filename", "title", "content"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["reports"],
    "additionalProperties": False,
}

_SENSITIVE_CLEAR_RESULT_JSON_SCHEMA = {
    **AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA,
    "properties": {
        **AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA["properties"],
        "ai_analysis": {"type": "string", "minLength": 1},
    },
}


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

    Every checker runs through the unified OpenCode task/session service.

    Args:
        workspace: Path to the generated opencode config workspace.
        project_dir: Real project root used as the CLI code workspace.
        candidate: The candidate vulnerability to analyze.
        project_id: Project identifier for MCP tool calls.
        on_output: Optional callback(line: str) called for each output line in real-time.
        cancel_event: Optional event; when set, the OpenCode task is cancelled.
        timeout: Per-candidate timeout in seconds. Falls back to config if not provided.

    Returns:
        A Vulnerability if analysis succeeded, None otherwise.
    """
    config = get_config()

    if config.opencode.mock:
        await _clear_candidate_planned_task(candidate)
        return _mock_result(candidate)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout

    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidate.vuln_type)

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
    output_source: OutputSource | None = None

    def capture_source(source: OutputSource) -> None:
        nonlocal output_source
        output_source = _to_output_source(source)

    prompt = _with_json_result_instruction((
        f"使用 `{skill_name}` 技能，分析位于 "
        f"{candidate.file}:{candidate.line} 函数 `{candidate.function}` 中"
        f"潜在的 {candidate.vuln_type.upper()} 漏洞。"
        f"project_id 为 `{project_id}`。"
        f"详情：{candidate.description} "
        f"分析完成后按最终结果返回规则输出 JSON 结论。"
    ).replace("\n", " "))
    log_path = _scan_task_log_path(project_id, f"audit-{uuid4().hex}.log")
    if on_output:
        on_output(f"[{tool}] 初始提示词:\n{prompt}")
    logger.info(
        "Running %s audit: %s:%d (%s) timeout=%ds",
        tool,
        candidate.file,
        candidate.line,
        candidate.vuln_type,
        effective_timeout,
    )
    try:
        with bind_opencode_execution_context(
            project_dir=_required_task_project_dir(project_dir),
            work_dir=log_path.parent.parent,
            task_metadata=_candidate_task_context(candidate),
            on_output=on_output,
            on_invocation_metadata=capture_source,
            cancel_event=cancel_event,
        ):
            result = await run_opencode_task(
                task_name=f"候选点审计 {candidate.vuln_type}",
                task_type="audit",
                prompt=prompt,
                required_capability=_mining_required_capability(),
                output_schema=AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA,
            )
        output_text = _opencode_result_text(
            result,
            output_schema=AUDITED_VULNERABILITY_RESULT_JSON_SCHEMA,
            log_path=log_path,
        )
    except asyncio.TimeoutError:
        logger.error(
            "%s timed out for %s:%d (timeout=%ds)",
            tool,
            candidate.file,
            candidate.line,
            effective_timeout,
        )
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
            failure_reason=_failure_reason(
                log_path,
                f"{tool} timed out after {effective_timeout} seconds",
            ),
            output_source=output_source or OutputSource(),
        )
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        logger.exception("%s failed for %s:%d", tool, candidate.file, candidate.line)
        return _apply_output_source(_failed_result(
            candidate,
            _failure_reason(log_path, f"{tool} error: {exc}"),
        ), output_source)

    result = _parse_result_from_text(output_text, candidate)
    if result is not None:
        return _apply_output_source(result, output_source)
    return _apply_output_source(_failed_result(
        candidate,
        _failure_reason(log_path, f"{tool} completed but did not return a valid JSON result"),
        analysis="OpenCode completed without returning a valid JSON result",
    ), output_source)


async def run_project_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
) -> list[Vulnerability]:
    """Run a SKILL-only checker once and collect all returned results."""
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
    output_source: OutputSource | None = None

    def capture_source(source: OutputSource) -> None:
        nonlocal output_source
        output_source = _to_output_source(source)

    prompt = _with_json_result_instruction((
        f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
        f"project_id 为 `{project_id}`。"
        "这是项目级审计任务，不是单个候选点复核。"
        f"file=`{candidate.file}`，line={candidate.line}，function=`{candidate.function}`。"
    ).replace("\n", " "), multiple=True)
    log_path = _scan_task_log_path(project_id, f"project-audit-{uuid4().hex}.log")
    if on_output:
        on_output(f"[{tool}] 初始提示词:\n{prompt}")
    logger.info(
        "Running %s project audit: %s (%s) timeout=%ds",
        tool,
        candidate.file,
        candidate.vuln_type,
        effective_timeout,
    )
    try:
        with bind_opencode_execution_context(
            project_dir=_required_task_project_dir(project_dir),
            work_dir=log_path.parent.parent,
            task_metadata=_candidate_task_context(candidate, "project_audit"),
            on_output=on_output,
            on_invocation_metadata=capture_source,
            cancel_event=cancel_event,
        ):
            result = await run_opencode_task(
                task_name=f"项目审计 {candidate.vuln_type}",
                task_type="project_audit",
                prompt=prompt,
                required_capability=_mining_required_capability(),
                output_schema=AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA,
            )
        output_text = _opencode_result_text(
            result,
            output_schema=AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA,
            log_path=log_path,
        )
    except asyncio.TimeoutError:
        logger.error(
            "%s project audit timed out for %s (timeout=%ds)",
            tool,
            candidate.vuln_type,
            effective_timeout,
        )
        return [Vulnerability(
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
            output_source=output_source or OutputSource(),
        )]
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        logger.exception("%s project audit failed for %s", tool, candidate.vuln_type)
        return _apply_output_source_to_list(
            [_failed_result(candidate, _failure_reason(log_path, f"{tool} error: {exc}"))],
            output_source,
        )

    results = _parse_results_from_text(output_text, candidate)
    if results:
        return _apply_output_source_to_list(results, output_source)
    return _apply_output_source_to_list([
        _failed_result(
            candidate,
            _failure_reason(log_path, f"{tool} completed but did not return valid JSON results"),
            analysis="OpenCode completed without returning valid JSON results",
        )
    ], output_source)


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
    vuln_type = str(payload.get("vuln_type") or candidate.vuln_type).strip() or candidate.vuln_type
    call_chain = _normalize_call_chain(payload.get("call_chain"), function_name)
    vulnerabilities = [
        Vulnerability(
            file=file_path,
            line=line,
            function=function_name,
            call_chain=call_chain,
            vuln_type=vuln_type,
            severity=severity or ("high" if confirmed else "low"),
            description=description or (
                f"{function_name} 中存在敏感信息生命周期结束后未清零问题"
                if confirmed
                else f"{function_name} 未确认敏感信息生命周期结束后未清零问题"
            ),
            ai_analysis=markdown,
            vulnerability_report=str(payload.get("vulnerability_report") or ""),
            confirmed=confirmed,
            ai_verdict="confirmed" if confirmed else "not_confirmed",
        )
    ]

    return SensitiveClearAuditResult(vulnerabilities=vulnerabilities, reports=[], complete=True)


def _parse_sensitive_clear_audit_result(text: str, candidate: Candidate) -> SensitiveClearAuditResult | None:
    try:
        payload = parse_audited_vulnerability_result(text)
    except Exception as exc:
        logger.warning(
            "Failed to parse sensitive_clear JSON result for %s:%d: %s",
            candidate.file, candidate.line, exc,
        )
        return None
    return _sensitive_clear_audit_result_from_payload(payload, candidate)


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
    output_source: OutputSource | None = None

    def capture_source(source: OutputSource) -> None:
        nonlocal output_source
        output_source = _to_output_source(source)

    prompt = _with_json_result_instruction(
        _sensitive_clear_prompt(skill_name, candidate, project_id)
    )
    log_path = _scan_task_log_path(project_id, f"sensitive-clear-{uuid4().hex}.log")
    if on_output:
        on_output(f"[{tool}] 初始提示词:\n{prompt}")
    logger.info(
        "Running %s sensitive_clear function audit: %s timeout=%ds",
        tool,
        candidate.file,
        effective_timeout,
    )
    try:
        with bind_opencode_execution_context(
            project_dir=_required_task_project_dir(project_dir),
            work_dir=log_path.parent.parent,
            task_metadata=_candidate_task_context(candidate, "sensitive_clear"),
            on_output=on_output,
            on_invocation_metadata=capture_source,
            cancel_event=cancel_event,
        ):
            result = await run_opencode_task(
                task_name=f"敏感信息清理审计 {candidate.function}",
                task_type="sensitive_clear",
                prompt=prompt,
                required_capability=_mining_required_capability(),
                output_schema=_SENSITIVE_CLEAR_RESULT_JSON_SCHEMA,
            )
        output_text = _opencode_result_text(
            result,
            output_schema=_SENSITIVE_CLEAR_RESULT_JSON_SCHEMA,
            log_path=log_path,
        )
    except asyncio.TimeoutError:
        logger.error("%s sensitive_clear audit timed out for %s", tool, candidate.file)
        return SensitiveClearAuditResult(
            vulnerabilities=[Vulnerability(
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
                output_source=output_source or OutputSource(),
            )],
            reports=[],
            complete=False,
        )
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception as exc:
        logger.exception("%s sensitive_clear audit failed for %s", tool, candidate.file)
        return SensitiveClearAuditResult(
            vulnerabilities=_apply_output_source_to_list(
                [_failed_result(candidate, _failure_reason(log_path, f"{tool} error: {exc}"))],
                output_source,
            ),
            reports=[],
            complete=False,
        )

    parsed = _parse_sensitive_clear_audit_result(output_text, candidate)
    if parsed is not None:
        _apply_output_source_to_list(parsed.vulnerabilities, output_source)
        return parsed
    return SensitiveClearAuditResult(
        vulnerabilities=[Vulnerability(
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
            output_source=output_source or OutputSource(),
        )],
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
    report_dir.mkdir(parents=True, exist_ok=True)
    output_source: OutputSource | None = None

    def capture_source(source: OutputSource) -> None:
        nonlocal output_source
        output_source = _to_output_source(source)

    for old_report in report_dir.glob("*.md"):
        try:
            old_report.unlink()
        except OSError:
            pass
    prompt = (
        f"使用 `{skill_name}` 技能，审计代码扫描路径 `{candidate.file}` 对应的目标代码。"
        f"project_id 为 `{project_id}`。"
        "这是用户创建的 Markdown 报告型项目级审计任务。"
        "请在最终 JSON 的 reports 数组返回一个或多个 Markdown 报告；"
        "filename 必须使用 .md 扩展名，title 为报告标题，content 为完整 Markdown。"
        "如果没有发现问题，也要返回一个报告说明审计范围和未发现问题的原因。"
    ).replace("\n", " ")
    log_path = _scan_task_log_path(project_id, f"report-audit-{uuid4().hex}.log")
    if on_output:
        on_output(f"[{tool}] 初始提示词:\n{prompt}")
    logger.info(
        "Running %s report audit: %s (%s) timeout=%ds report_dir=%s",
        tool,
        candidate.file,
        candidate.vuln_type,
        effective_timeout,
        report_dir,
    )
    try:
        with bind_opencode_execution_context(
            project_dir=_required_task_project_dir(project_dir),
            work_dir=log_path.parent.parent,
            task_metadata=_candidate_task_context(candidate, "report_audit"),
            on_output=on_output,
            on_invocation_metadata=capture_source,
            cancel_event=cancel_event,
        ):
            result = await run_opencode_task(
                task_name=f"报告审计 {candidate.vuln_type}",
                task_type="report_audit",
                prompt=prompt,
                required_capability=_mining_required_capability(),
                output_schema=_MARKDOWN_REPORTS_JSON_SCHEMA,
            )
        output_text = _opencode_result_text(
            result,
            output_schema=_MARKDOWN_REPORTS_JSON_SCHEMA,
            log_path=log_path,
        )
    except asyncio.TimeoutError:
        logger.error(
            "%s report audit timed out for %s (timeout=%ds)",
            tool,
            candidate.vuln_type,
            effective_timeout,
        )
        return _collect_markdown_reports(report_dir, candidate.vuln_type, output_source)
    except asyncio.CancelledError:
        raise
    except NoAvailableModelError:
        raise
    except Exception:
        logger.exception("%s report audit failed for %s", tool, candidate.vuln_type)
        return _collect_markdown_reports(report_dir, candidate.vuln_type, output_source)

    try:
        report_payload = json.loads(output_text)
    except Exception:
        report_payload = {}
    for index, item in enumerate(report_payload.get("reports") or [], start=1):
        if not isinstance(item, dict):
            continue
        raw_name = Path(str(item.get("filename") or f"report-{index}.md")).name
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_name).strip("._")
        if not safe_name.lower().endswith(".md"):
            safe_name = f"{safe_name or f'report-{index}'}.md"
        content = str(item.get("content") or "")
        if content.strip():
            (report_dir / safe_name).write_text(content, encoding="utf-8")
    return _collect_markdown_reports(report_dir, candidate.vuln_type, output_source)


def _threat_audit_result_defaults(task: ThreatAuditTask) -> _VulnerabilityResultDefaults:
    primary_code_path = task.code_path or (task.code_paths[0].path if task.code_paths else ".")
    method_label = _threat_display_label(task.method_name, "相关攻击方式")
    return _VulnerabilityResultDefaults(
        file=primary_code_path,
        line=1,
        function="__threat_path__",
        description=task.description or (
            f"Threat audit for surface `{task.surface_name}` via method `{method_label}` "
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
    """Run one attack-tree-derived audit task and collect returned results."""
    config = get_config()
    defaults = _threat_audit_result_defaults(task)
    if config.opencode.mock:
        await _clear_planned_task_id(planned_task_id)
        return _annotate_threat_audit_results([_mock_result_from_defaults(defaults)], task)

    mining_policy = getattr(config, "vulnerability_mining", None)
    effective_timeout = int(
        getattr(mining_policy, "timeout_seconds", 0)
        or timeout
        or config.opencode.timeout
    )
    tool = _normalize_tool(config.opencode)
    # Fresh-session retries are owned by OpenCodeTaskService and the phase
    # policy.  Keep this legacy business-layer loop to one invocation.
    max_retries = 0
    last_source: OutputSource | None = None

    for attempt in range(1, max_retries + 2):
        attempt_source: OutputSource | None = None
        attempt_id = uuid4().hex

        def capture_source(source: OutputSource) -> None:
            nonlocal attempt_source, last_source
            attempt_source = _to_output_source(source)
            last_source = attempt_source

        surface_label = _threat_display_label(task.surface_name, "相关攻击面")
        method_label = _threat_display_label(task.method_name, "相关攻击方式")
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
        log_path = _scan_task_log_path(
            project_id,
            f"opencode_threat_audit_{attempt_id}.log",
        )

        if on_output:
            on_output(f"[{tool}] 威胁审计提示词:\n{prompt}")

        logger.info(
            "Running %s threat audit: task_id=%s path=%s timeout=%ds attempt=%d/%d",
            tool, task.task_id, task.code_path, effective_timeout, attempt, max_retries + 1,
        )

        task_metadata = {
            "task_type": "threat_audit",
            "checker": "threat_audit",
            "file": task.code_path,
            "function": defaults.function,
            "threat_surface_node_id": task.surface_node_id,
            "threat_method_node_id": task.method_node_id,
            "threat_attack_path_id": task.attack_path_id,
            "threat_attack_path_fingerprint": task.attack_path_fingerprint,
            "stats_scope_id": project_id,
            "audit_attempt": attempt,
        }
        if planned_task_id:
            task_metadata["planned_task_id"] = planned_task_id

        try:
            with bind_opencode_execution_context(
                project_dir=_required_task_project_dir(project_dir),
                work_dir=log_path.parent.parent,
                task_metadata=task_metadata,
                on_output=on_output,
                on_invocation_metadata=capture_source,
                cancel_event=cancel_event,
            ):
                result = await run_opencode_task(
                    task_name=f"威胁审计 {task.task_id}",
                    task_type="threat_audit",
                    prompt=prompt,
                    required_capability=_mining_required_capability(),
                    output_schema=AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA,
                )
            output_text = _opencode_result_text(
                result,
                output_schema=AUDITED_VULNERABILITY_RESULTS_JSON_SCHEMA,
                log_path=log_path,
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
                    failure_reason=_failure_reason(
                        log_path,
                        f"{tool} timed out after {effective_timeout} seconds",
                    ),
                    output_source=attempt_source or OutputSource(),
                )
            ], task)
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            logger.exception(
                "%s threat audit failed for %s (attempt %d)",
                tool,
                task.task_id,
                attempt,
            )
            if attempt <= max_retries:
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
                continue
            return _annotate_threat_audit_results(
                _apply_output_source_to_list([
                    _failed_result_from_defaults(
                        defaults,
                        _failure_reason(log_path, f"{tool} error: {exc}"),
                    )
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
            logger.warning(
                "%s threat audit did not return valid JSON results for %s (attempt %d)",
                tool,
                task.task_id,
                attempt,
            )
            if on_output:
                on_output(
                    f"[retry {attempt}/{max_retries}] "
                    "No valid JSON results returned, retrying..."
                )
            continue
        return _annotate_threat_audit_results(
            _apply_output_source_to_list([
                _failed_result_from_defaults(
                    defaults,
                    _failure_reason(
                        log_path,
                        f"{tool} completed but did not return valid JSON threat audit results",
                    ),
                    analysis=(
                        "OpenCode completed without returning valid JSON threat audit results"
                    ),
                )
            ], attempt_source),
            task,
        )

    return _annotate_threat_audit_results([
        _apply_output_source(
            _failed_result_from_defaults(defaults, "OpenCode did not return a result"),
            last_source,
        )
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
    from deephole_client.threat_analysis_opencode import run_attack_tree_threat_analysis

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


async def execute_threat_analysis_context(context) -> ThreatAnalysis | None:
    """Adapt the backend's pure threat-analysis context to Agent execution."""
    return await run_threat_analysis_audit(
        workspace=context.workspace,
        project_id=context.scan_id,
        skill_path=context.repo_root / "attack-tree-threat-analysis.md",
        reference_catalog_path=context.repo_root / "attack-method-reference-catalog.md",
        on_output=context.on_output,
        cancel_event=context.cancel_event,
        timeout=context.timeout,
        project_dir=context.project_path,
        code_scan_path=context.code_scan_path,
        product=context.product,
        planned_task_id=context.planned_task_id,
        on_attack_paths=context.on_attack_paths,
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


def _scan_task_log_path(scan_id: str, filename: str) -> Path:
    from task_agent.task_service import get_opencode_execution_context

    context = get_opencode_execution_context()
    if context.work_dir is None:
        raise RuntimeError("OpenCode work_dir is not bound for the current component")
    if scan_id and context.scan_id and context.scan_id != scan_id:
        raise RuntimeError(
            f"OpenCode scan context mismatch: expected {scan_id}, got {context.scan_id}"
        )
    root = context.work_dir / "logs"
    root.mkdir(parents=True, exist_ok=True)
    return root / filename


def _required_task_project_dir(project_dir: Path | None) -> Path:
    from task_agent.task_service import get_opencode_execution_context

    context = get_opencode_execution_context()
    resolved = Path(project_dir).resolve() if project_dir is not None else context.project_dir
    if resolved is None:
        raise RuntimeError("OpenCode project_dir is not bound for the current component")
    return resolved.resolve()


def _opencode_result_text(
    result: OpenCodeResult,
    *,
    output_schema: dict | None,
    log_path: Path | None,
) -> str:
    if result.status == "timeout":
        raise asyncio.TimeoutError(result.text)
    if result.status == "failure":
        from task_agent.model_pool import NO_AVAILABLE_MODEL_MESSAGE

        if result.text == NO_AVAILABLE_MODEL_MESSAGE:
            raise NoAvailableModelError()
        raise RuntimeError(result.text)
    output_text = (
        json.dumps(result.structured, ensure_ascii=False)
        if output_schema is not None and result.structured is not None
        else result.text
    )
    if log_path and output_text:
        try:
            log_path.write_text(output_text, encoding="utf-8")
        except Exception:
            pass
    return output_text


def _public_required_capability(value: object) -> str:
    return "high" if str(value or "").strip().lower() in {"medium", "high"} else "low"


def _mining_required_capability() -> str:
    return _public_required_capability(
        _cfg_value(getattr(get_config(), "vulnerability_mining", None), "required_capability", "low")
    )


def _effective_cli_config(cli_config, model_option) -> dict:
    data = {
        "tool": _cfg_value(cli_config, "tool", ""),
        "executable": _cfg_value(cli_config, "executable", ""),
        "model": _cfg_value(cli_config, "model", ""),
        "timeout": _cfg_value(cli_config, "timeout", 1200),
        "max_retries": _cfg_value(cli_config, "max_retries", 2),
        "models": _cfg_value(cli_config, "models", []),
        "config_paths": _cfg_value(cli_config, "config_paths", []),
        "config_jsonc": _cfg_value(cli_config, "config_jsonc", "{}"),
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
    name = str(_cfg_value(config_obj, "executable", "") or "").strip()
    if Path(name).name.lower() in {"hac", "claude"}:
        name = ""
    name = name or _DEFAULT_EXECUTABLES[tool]
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
    """OpenDeepHole model work always uses the OpenCode serve/session API."""
    return "serve"


def _read_managed_opencode_config(workspace: Path) -> dict:
    from deephole_client.opencode_integration import get_workspace_lock, managed_opencode_config_path

    path = managed_opencode_config_path(workspace)
    with get_workspace_lock(workspace):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"OpenDeepHole managed OpenCode config is unavailable: {path}") from exc
        try:
            return parse_opencode_jsonc(text, source=str(path))
        except ValueError as exc:
            raise RuntimeError(f"OpenDeepHole managed OpenCode config is invalid: {exc}") from exc


def _read_opencode_config_file(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        data = parse_opencode_jsonc(text, source=str(path))
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


def _merge_managed_opencode_config(base: dict, managed: dict) -> dict:
    """Merge the final system layer without retaining user data in reserved fields."""
    merged = _merge_opencode_configs(base, managed)
    for key in ("$schema", "skills", "permission"):
        if key in managed:
            merged[key] = copy.deepcopy(managed[key])
    for section_name in ("mcp", "agent"):
        managed_section = managed.get(section_name)
        if not isinstance(managed_section, dict):
            continue
        merged_section = merged.setdefault(section_name, {})
        if not isinstance(merged_section, dict):
            merged_section = {}
            merged[section_name] = merged_section
        for name, value in managed_section.items():
            merged_section[name] = copy.deepcopy(value)
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
    from deephole_client.opencode_integration import writable_edit_patterns

    next_config = json.loads(json.dumps(config))
    permission = next_config.setdefault("permission", {})
    edit = {"*": "deny"}
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


def _opencode_config_for_env(
    workspace: Path,
    tool: str,
    project_dir: Path | None,
    env: dict[str, str],
    writable_paths: list[Path] | None = None,
    executable: str | None = None,
    config_paths: object = None,
    config_jsonc: str = "{}",
) -> dict:
    user_config = _read_user_opencode_config(
        tool,
        project_dir,
        env,
        executable=executable,
        config_paths=config_paths,
    )
    web_config = parse_opencode_jsonc(config_jsonc, source="Web OpenCode 配置")
    task_config = _with_writable_paths(_read_managed_opencode_config(workspace), writable_paths)
    merged = _merge_managed_opencode_config(
        _merge_opencode_configs(user_config, web_config),
        task_config,
    )
    if merged and "provider" not in merged and "model" not in merged:
        logger.warning(
            "Resolved OpenCode runtime config has no provider/model keys; "
            "set %s or opencode.config_paths if your CLI relies on a non-standard config file",
            _OPENCODE_CONFIG_PATH_ENV,
        )
    return merged


def _build_opencode_config_content(
    workspace: Path,
    tool: str,
    base_env: dict[str, str] | None = None,
    writable_paths: list[Path] | None = None,
    project_dir: Path | None = None,
    executable: str | None = None,
    cli_config=None,
) -> str:
    """Build the normalized config file content for the next Serve process."""
    env = dict(os.environ if base_env is None else base_env)
    config = _opencode_config_for_env(
        workspace,
        tool,
        project_dir,
        env,
        writable_paths=writable_paths,
        executable=executable,
        config_paths=_cfg_value(cli_config, "config_paths", []) if cli_config is not None else [],
        config_jsonc=_cfg_value(cli_config, "config_jsonc", "{}") if cli_config is not None else "{}",
    )
    return dump_opencode_config(config)


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

    raise ValueError(f"Unsupported OpenCode serve tool: {tool}")


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
        AUDITED_VULNERABILITY_RESULTS_JSON_INSTRUCTION
        if multiple
        else AUDITED_VULNERABILITY_RESULT_JSON_INSTRUCTION
    )
    if instruction in prompt:
        return prompt
    return prompt.rstrip() + "\n\n" + instruction


def _json_result_retry_message(*, multiple: bool = False) -> str:
    shape = "`{\"results\": [...]}` JSON 对象" if multiple else "单个 JSON 对象"
    return (
        f"上一次尝试没有输出符合 schema 的{shape}。"
        "请重新完成分析，最终只输出符合要求的 JSON。"
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
    env.pop("OPENCODE_CONFIG_CONTENT", None)
    if tool in {"nga", "opencode"}:
        env.update(_opencode_proxy_env_overrides(cli_config, env))
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


def _parse_result_from_text(text: str, candidate: Candidate) -> Vulnerability | None:
    defaults = _candidate_result_defaults(candidate)
    try:
        payload = parse_audited_vulnerability_result(text)
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
        payloads = parse_audited_vulnerability_results(text)
    except Exception as multi_exc:
        try:
            payloads = [parse_audited_vulnerability_result(text)]
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
    vuln_type_value = str(data.get("vuln_type") or defaults.vuln_type).strip() or defaults.vuln_type
    call_chain = _normalize_call_chain(data.get("call_chain"), function_value)
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
        call_chain=call_chain,
        vuln_type=vuln_type_value,
        severity=data.get("severity", "unknown"),
        description=data.get("description", defaults.description),
        ai_analysis=data.get("ai_analysis", ""),
        vulnerability_report=str(data.get("vulnerability_report") or ""),
        confirmed=confirmed,
        ai_verdict="confirmed" if confirmed else "not_confirmed",
    )


def _normalize_call_chain(value: object, vulnerable_function: str) -> list[str]:
    chain = [
        str(item).strip()
        for item in (value if isinstance(value, list) else [])
        if str(item).strip()
    ]
    function_name = str(vulnerable_function or "").strip()
    if not chain and function_name:
        chain.append(function_name)
    elif function_name and chain[-1] != function_name:
        chain.append(function_name)
    return chain


def _session_id_from_output_source(source: OutputSource | None) -> str:
    if source is None:
        return ""
    return str(getattr(source, "serve_session_id", "") or "").strip()








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

    Candidates are submitted sequentially through the same OpenCode service.
    """
    config = get_config()

    if config.opencode.mock:
        for candidate in candidates:
            await _clear_candidate_planned_task(candidate)
        return [_mock_result(c) for c in candidates]

    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidates[0].vuln_type) if candidates else None
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
