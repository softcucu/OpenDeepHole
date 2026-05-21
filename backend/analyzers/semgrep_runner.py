"""Shared semgrep subprocess runner for static analyzers."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from backend.logger import get_logger

_log = get_logger(__name__)

DEFAULT_SEMGREP_TIMEOUT_SECONDS = 15 * 60


@dataclass(frozen=True)
class SemgrepRunResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def _decode_output(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return ""


def _read_semgrep_json(output_path: Path, fallback: object) -> str:
    try:
        if output_path.is_file():
            text = output_path.read_text(encoding="utf-8", errors="replace")
            if text.strip():
                return text
    except OSError:
        pass
    return _decode_output(fallback)


def run_semgrep(
    project_path: Path,
    *,
    rule_file: Path,
    checker_name: str,
    timeout: int = DEFAULT_SEMGREP_TIMEOUT_SECONDS,
    heartbeat_interval: float | None = None,
) -> SemgrepRunResult | None:
    """Run semgrep non-interactively and return JSON output.

    Semgrep can otherwise inherit the Agent terminal stdin. Keeping stdin closed
    makes scans deterministic for long-running Agent sessions and terminal exits.
    """
    with tempfile.TemporaryDirectory(prefix=f"opendeephole-{checker_name}-semgrep-") as tmp:
        output_path = Path(tmp) / "semgrep.json"
        cmd = [
            "semgrep",
            "scan",
            "--config", str(rule_file),
            "--json",
            f"--json-output={output_path}",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            "--no-autofix",
            str(project_path),
        ]
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["SEMGREP_SEND_METRICS"] = "off"
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        env["XDG_CONFIG_HOME"] = str(Path(tmp) / "config")
        env["XDG_CACHE_HOME"] = str(Path(tmp) / "cache")
        env["SEMGREP_SETTINGS_FILE"] = str(Path(tmp) / "settings.yml")
        env["SEMGREP_LOG_FILE"] = str(Path(tmp) / "semgrep.log")

        print(f"  [semgrep] {checker_name} starting: {project_path}", flush=True)
        try:
            if heartbeat_interval is None:
                proc = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=timeout,
                )
            else:
                proc = _run_with_heartbeat(
                    cmd,
                    env=env,
                    timeout=timeout,
                    checker_name=checker_name,
                    heartbeat_interval=heartbeat_interval,
                )
        except subprocess.TimeoutExpired as exc:
            stdout = _read_semgrep_json(
                output_path,
                getattr(exc, "stdout", None) or getattr(exc, "output", None),
            )
            stderr = _decode_output(getattr(exc, "stderr", None))
            if stdout.strip():
                _log.warning(
                    "semgrep timed out after %s seconds for %s scan; using partial JSON output",
                    timeout,
                    checker_name,
                )
                print(
                    f"  [semgrep] {checker_name} timed out; using partial JSON output",
                    flush=True,
                )
                return SemgrepRunResult(None, stdout, stderr, timed_out=True)
            _log.warning(
                "semgrep timed out after %s seconds for %s scan and produced no JSON output",
                timeout,
                checker_name,
            )
            print(f"  [semgrep] {checker_name} timed out with no JSON output", flush=True)
            return None
        except Exception as exc:
            _log.warning("semgrep failed to run for %s scan: %s", checker_name, exc)
            print(f"  [semgrep] {checker_name} failed to start: {exc}", flush=True)
            return None

        stdout = _read_semgrep_json(output_path, proc.stdout)
        print(f"  [semgrep] {checker_name} finished: rc={proc.returncode}", flush=True)
        return SemgrepRunResult(proc.returncode, stdout, proc.stderr)


def _run_with_heartbeat(
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int,
    checker_name: str,
    heartbeat_interval: float,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    next_heartbeat = started + heartbeat_interval
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    while True:
        now = time.monotonic()
        timeout_at = started + timeout
        wait_for = max(0.1, min(next_heartbeat, timeout_at) - now)
        try:
            stdout, stderr = proc.communicate(timeout=wait_for)
            return subprocess.CompletedProcess(
                cmd,
                proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            if now >= timeout_at:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise subprocess.TimeoutExpired(
                    cmd,
                    timeout,
                    output=stdout,
                    stderr=stderr,
                )
            if now >= next_heartbeat:
                elapsed = int(now - started)
                print(f"  [semgrep] {checker_name} still running: {elapsed}s", flush=True)
                while next_heartbeat <= now:
                    next_heartbeat += heartbeat_interval
