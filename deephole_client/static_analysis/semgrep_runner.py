"""Semgrep subprocess runner owned by the static-analysis process."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .source_filter import OP_DEEP_HOLE_DIR

_log = logging.getLogger(__name__)
DEFAULT_SEMGREP_TIMEOUT_SECONDS = 15 * 60
SEMGREP_INTERNAL_EXCLUDES = (
    OP_DEEP_HOLE_DIR,
    f"{OP_DEEP_HOLE_DIR}/**",
    f"**/{OP_DEEP_HOLE_DIR}/**",
)


@dataclass(frozen=True)
class SemgrepRunResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def _decode_output(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""


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
    with tempfile.TemporaryDirectory(prefix=f"opendeephole-{checker_name}-semgrep-") as temp_dir:
        output_path = Path(temp_dir) / "semgrep.json"
        cmd = [
            "semgrep", "scan", "--config", str(rule_file), "--json",
            f"--json-output={output_path}", "--no-git-ignore", "--metrics=off",
            "--disable-version-check", "--no-autofix",
        ]
        for pattern in SEMGREP_INTERNAL_EXCLUDES:
            cmd.extend(["--exclude", pattern])
        cmd.append(str(project_path))
        env = os.environ.copy()
        env.update({
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "XDG_CONFIG_HOME": str(Path(temp_dir) / "config"),
            "XDG_CACHE_HOME": str(Path(temp_dir) / "cache"),
            "SEMGREP_SETTINGS_FILE": str(Path(temp_dir) / "settings.yml"),
            "SEMGREP_LOG_FILE": str(Path(temp_dir) / "semgrep.log"),
        })
        print(f"  [semgrep] {checker_name} starting: {project_path}", flush=True)
        try:
            if heartbeat_interval is None:
                process = subprocess.run(
                    cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", env=env, timeout=timeout,
                )
            else:
                process = _run_with_heartbeat(
                    cmd, env=env, timeout=timeout, checker_name=checker_name,
                    heartbeat_interval=heartbeat_interval,
                )
        except subprocess.TimeoutExpired as exc:
            stdout = _read_semgrep_json(
                output_path, getattr(exc, "stdout", None) or getattr(exc, "output", None),
            )
            stderr = _decode_output(getattr(exc, "stderr", None))
            if stdout.strip():
                print(
                    f"  [semgrep] {checker_name} timed out; using partial JSON output",
                    flush=True,
                )
                return SemgrepRunResult(None, stdout, stderr, timed_out=True)
            _log.warning("semgrep timed out for %s", checker_name)
            print(f"  [semgrep] {checker_name} timed out with no JSON output", flush=True)
            return None
        except Exception as exc:
            _log.warning("semgrep failed for %s: %s", checker_name, exc)
            print(f"  [semgrep] {checker_name} failed to start: {exc}", flush=True)
            return None
        print(f"  [semgrep] {checker_name} finished: rc={process.returncode}", flush=True)
        return SemgrepRunResult(
            process.returncode,
            _read_semgrep_json(output_path, process.stdout),
            process.stderr,
        )


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
    process = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", env=env,
    )
    while True:
        now = time.monotonic()
        wait_for = max(0.1, min(next_heartbeat, started + timeout) - now)
        try:
            stdout, stderr = process.communicate(timeout=wait_for)
            return subprocess.CompletedProcess(cmd, process.returncode, stdout=stdout, stderr=stderr)
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            if now >= started + timeout:
                process.kill()
                stdout, stderr = process.communicate()
                raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
            if now >= next_heartbeat:
                _log.info("semgrep %s still running after %ss", checker_name, int(now - started))
                print(
                    f"  [semgrep] {checker_name} still running: {int(now - started)}s",
                    flush=True,
                )
                while next_heartbeat <= now:
                    next_heartbeat += heartbeat_interval
