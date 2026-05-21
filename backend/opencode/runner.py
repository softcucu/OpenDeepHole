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
from pathlib import Path
from uuid import uuid4

from backend.config import get_config
from backend.logger import get_logger
from backend.models import Candidate, Vulnerability

logger = get_logger(__name__)

AI_CLI_TOOLS = ("nga", "opencode", "hac", "claude")
_DEFAULT_EXECUTABLES = {
    "nga": "nga",
    "opencode": "opencode",
    "hac": "hac",
    "claude": "claude",
}

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
) -> Vulnerability | None:
    """Run opencode to analyze a single candidate vulnerability.

    Supports two modes (selected via checker.yaml):
    - opencode CLI mode (default): invokes opencode subprocess with MCP tools
    - LLM API mode: direct API call with function calling

    Args:
        workspace: Path to the opencode workspace (contains opencode.json + skills).
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
    )


async def _run_audit_via_opencode(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    checker_entry=None,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
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
            f"**重要：你必须直接完成所有分析工作，禁止使用子 Agent（sub-agent）或委托任何子任务。"
            f"所有 MCP 工具调用（包括 submit_result）必须由你自己直接执行。**"
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


def _cfg_value(config_obj, key: str, default=None):
    if isinstance(config_obj, dict):
        return config_obj.get(key, default)
    return getattr(config_obj, key, default)


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


def _read_mcp_url(workspace: Path) -> str:
    try:
        data = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
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


def _prepare_cli_workspace(workspace: Path, tool: str) -> None:
    """Create tool-specific MCP and skill files from the canonical opencode files."""
    if tool in {"nga", "opencode"}:
        return

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
        return

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


def _build_cli_command(tool: str, executable: str, workspace: Path, prompt: str, model: str) -> list[str]:
    if tool in {"nga", "opencode"}:
        cmd = [executable, "run", "--dir", str(workspace)]
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


async def _invoke_opencode(
    workspace: Path,
    prompt: str,
    timeout: int,
    log_path: Path | None = None,
    on_line=None,
    cancel_event=None,
    cli_config=None,
) -> None:
    """Invoke the configured AI CLI, stream output line-by-line, write to log file.

    Uses subprocess.Popen in a thread executor instead of
    asyncio.create_subprocess_exec to avoid the asyncio child-watcher
    requirement on Linux (which raises NotImplementedError in some
    environments regardless of Python version).
    """
    config = get_config()
    cli_config = cli_config or config.opencode
    tool = _normalize_tool(cli_config)
    executable = _resolve_cli_executable(cli_config)
    model = str(_cfg_value(cli_config, "model", "") or "")
    _prepare_cli_workspace(workspace, tool)
    cmd = _build_cli_command(tool, executable, workspace, prompt, model)

    logger.debug("%s command: %s", tool, " ".join(shlex.quote(part) for part in cmd))

    env = os.environ.copy()
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
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
            cwd=str(workspace),
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

    def _kill() -> None:
        proc = proc_holder[0]
        if proc is not None:
            try:
                if sys.platform != "win32":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    stream_future = loop.run_in_executor(None, _stream)

    # Watcher: kill proc immediately when cancel_event fires.
    async def _cancel_watcher() -> None:
        if cancel_event:
            while not cancel_event.is_set():
                await asyncio.sleep(0.2)
            _kill()

    watcher = asyncio.create_task(_cancel_watcher()) if cancel_event else None

    log_lines: list[str] = []
    deadline = asyncio.get_event_loop().time() + timeout
    timed_out = False

    try:
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                timed_out = True
                _kill()
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

    await stream_future  # wait for thread to exit cleanly

    if timed_out:
        raise asyncio.TimeoutError()

    proc = proc_holder[0]
    if proc and proc.returncode not in (0, None):
        logger.error("%s exited with code %d", tool, proc.returncode)
        raise RuntimeError(f"{tool} exited with code {proc.returncode}")


def _read_result(result_id: str, candidate: Candidate) -> Vulnerability | None:
    """Read the result file written by the submit_result MCP tool."""
    config = get_config()
    result_path = Path(config.storage.scans_dir) / f"{result_id}.json"

    if not result_path.exists():
        logger.warning(
            "submit_result was not called for %s:%d (result_id=%s, path=%s)",
            candidate.file, candidate.line, result_id, result_path,
        )
        return None

    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error(
            "Failed to parse result file for result_id=%s path=%s: %s",
            result_id, result_path, exc,
        )
        return None

    confirmed = data.get("confirmed", False)
    return Vulnerability(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        severity=data.get("severity", "unknown"),
        description=data.get("description", candidate.description),
        ai_analysis=data.get("ai_analysis", ""),
        confirmed=confirmed,
        ai_verdict="confirmed" if confirmed else "not_confirmed",
    )


async def run_audit_batch(
    workspace: Path,
    candidates: list[Candidate],
    project_id: str,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
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
