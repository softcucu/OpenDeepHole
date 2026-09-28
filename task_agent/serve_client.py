"""HTTP client and process manager for OpenCode-compatible serve mode."""

from __future__ import annotations

import atexit
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import httpx

from .bash_commands import command_binding_metadata
from .config_json import (
    is_sensitive_opencode_config_key,
    redact_opencode_config_content,
)
from .deadline import CLEANUP_TIMEOUT_SECONDS, OperationDeadline, cancel_tasks_bounded, retire_task
from .output_format import format_task_output, task_output_stage
from .token_usage import (
    OpenCodeTokenUsage,
    TokenCounters,
    parse_token_counters,
    token_usage_from_models,
)

# Keep Task Agent usable as a standalone package while still routing Serve
# diagnostics through the full Agent's configured ``opendeephole`` logger.
# Using ``__name__`` here leaves INFO records invisible in the Agent console
# because the full Agent intentionally configures only that named hierarchy.
logger = logging.getLogger(f"opendeephole.{__name__}")

_SERVE_START_TIMEOUT_SECONDS = 60.0
_SERVE_STOP_TIMEOUT_SECONDS = 5.0
_SERVE_VERSION_PROBE_TIMEOUT_SECONDS = 3.0
_COMMAND_PROBE_STOP_TIMEOUT_SECONDS = 2.0
_SERVE_REQUEST_TIMEOUT_SECONDS = 20.0
_SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS = 2.0
_SERVE_REQUEST_REAP_TIMEOUT_SECONDS = 1.0
_SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS = 5.0
_SERVE_HEALTH_POLL_INTERVAL_SECONDS = 1.0
_SERVE_HEALTH_PROGRESS_INTERVAL_SECONDS = 10.0
_SERVE_EVENT_FLUSH_INTERVAL_SECONDS = 1.0
_SERVE_EVENT_CONNECT_TIMEOUT_SECONDS = 2.0
_SERVE_EVENT_RECONNECT_DELAY_SECONDS = 1.0
_SERVE_EVENT_RECONNECT_MAX_SECONDS = 30.0
_SERVE_EVENT_FAILURE_SUMMARY_SECONDS = 30.0
_SERVE_EVENT_POLL_INTERVAL_SECONDS = 1.0
_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS = 1.0
_SERVE_EVENT_PREVIEW_LIMIT = 500
_SERVE_STARTUP_LOG_TAIL_LIMIT = 4000
_SERVE_AUTO_PORT_MAX_ATTEMPTS = 3
_SCAN_MCP_INITIAL_CONNECT_ATTEMPTS = 2
_SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS = 0.5
_SCAN_MCP_RECOVERY_COOLDOWN_SECONDS = 1.0
_DEFAULT_SERVE_PORT = 4096
_SERVE_PORT_ENV = "OPENCODE_SERVE_PORT"
_SERVE_MARKER_ENV = "OPENCODE_SERVE_MARKER"
_SERVE_MARKER_OWNER = "opendeephole-agent-serve-v1"
_SERVE_BOOTSTRAP_CWD_PREFIX = "opendeephole-opencode-serve-bootstrap"
_SERVE_ISOLATED_CONFIG_DIRNAME = ".opendeephole-xdg-config"
_SERVE_MANAGED_PLUGIN_DIRNAME = ".opendeephole-plugins"
_KNOWLEDGE_BINDING_DIRNAME = "knowledge-bindings"
_COMMAND_BINDING_DIRNAME = "command-bindings"
_COMMAND_AUDIT_DIRNAME = "command-audits"
_COMMAND_OUTPUT_TAIL_BYTES = 16 * 1024
_FILE_WRITE_PLUGIN_METADATA_KEY = "opendeepholeFileWrites"
_FILE_WRITE_PLUGIN_SOURCE = r'''import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const pluginDirectory = path.dirname(fileURLToPath(import.meta.url))
const bindingDirectory = path.join(pluginDirectory, "command-bindings")
const parents = new Map()
const digest = (value) => crypto.createHash("sha256").update(String(value || "")).digest("hex")
const bindingPath = (sessionID) => path.join(bindingDirectory, `${digest(sessionID)}.json`)
const normalizedTool = (value) => String(value || "").trim().toLowerCase().replaceAll("-", "_")
const pathText = (value) => typeof value === "string" ? value.trim() : ""

const readDirectBinding = async (sessionID) => {
  try {
    const value = JSON.parse(await fs.readFile(bindingPath(sessionID), "utf8"))
    if (!value || ![1, 2].includes(value.version) || !Array.isArray(value.allowed_commands)) return null
    if (typeof value.audit_path !== "string" || !value.audit_path.trim()) return null
    return value
  } catch (error) {
    if (error?.code === "ENOENT") return null
    throw error
  }
}

const resolveBinding = async (sessionID) => {
  let current = String(sessionID || "")
  const visited = new Set()
  for (let depth = 0; current && depth < 32 && !visited.has(current); depth += 1) {
    visited.add(current)
    const binding = await readDirectBinding(current)
    if (binding) return binding
    current = String(parents.get(current) || "")
  }
  return null
}

const commandText = (args) => pathText(args?.command) || pathText(args?.cmd)
const objectValue = (value) => value && typeof value === "object" ? value : {}
// Recognition only: the submitted command is never executed after a match.
// Keep the literal grammar aligned with task_agent/bash_commands.py.
const literalCommandArgs = (command, windows) => {
  if (/[\x00-\x08\x0a-\x1f]/.test(command)) return null
  const words = []
  let word = "", quote = "", active = false
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]
    if (windows && "$`%!".includes(char)) return null
    if (quote) {
      if (char === quote) quote = ""
      else if (quote === '"' && !windows && char === "\\") {
        if (index + 1 < command.length && '\\"$`'.includes(command[index + 1])) {
          word += command[++index]
        } else word += char
      } else if (quote === '"' && "$`".includes(char)) return null
      else word += char
    } else if (char === " " || char === "\t") {
      if (active) { words.push(word); word = ""; active = false }
    } else if (char === '"' || char === "'") {
      quote = char
      active = true
    } else if (char === "\\" && !windows) {
      if (++index === command.length) return null
      word += command[index]
      active = true
    } else if ("|&;<>(){}[]*?~$`#".includes(char)) return null
    else { word += char; active = true }
  }
  if (quote) return null
  if (active) words.push(word)
  return words
}
const absoluteCommandPath = (value, windows) => {
  const paths = windows ? path.win32 : path.posix
  if (!paths.isAbsolute(value)) return ""
  const normalized = paths.normalize(value)
  if (!windows) return normalized
  const root = paths.parse(normalized).root
  if (!root.includes(":") && !root.startsWith("\\\\")) return ""
  return normalized.toLowerCase()
}
const boundCommand = (binding, command) => {
  if (binding.allowed_commands.includes(command)) return command
  if (binding.bash_command_match_mode !== "bound_python_script") return ""
  const windows = binding.command_platform === "win32"
  const argv = literalCommandArgs(command, windows)
  if (!argv || argv.length < 2) return ""
  const pythonNames = ["python", "python3", "python.exe", "python3.exe"]
  const hostPython = absoluteCommandPath(pathText(binding.python_executable), windows)
  if (!pythonNames.includes(windows ? argv[0].toLowerCase() : argv[0])
    && !(hostPython && absoluteCommandPath(argv[0], windows) === hostPython)) return ""
  const script = absoluteCommandPath(argv[1], windows)
  if (!script) return ""
  const canonical = objectValue(binding.python_script_commands)[script]
  return typeof canonical === "string" && binding.allowed_commands.includes(canonical)
    ? canonical : ""
}
const unboundCommandError = (binding, phase) => new Error(
  `Shell command is not bound to this OpenDeepHole task (${phase}). `
  + `Copy one bound command verbatim:\n${binding.allowed_commands.join("\n")}`,
)
const commandOutputText = (output, metadata) => {
  const values = [
    output?.output,
    metadata.output,
    metadata.stdout,
    metadata.stderr,
  ].filter((value) => typeof value === "string" && value.length)
  return [...new Set(values)].join("\n")
}
const outputTail = (value, limit) => {
  const raw = Buffer.from(String(value || ""), "utf8")
  const size = Number.isFinite(Number(limit)) && Number(limit) > 0 ? Number(limit) : 0
  const truncated = size > 0 && raw.length > size
  return {
    output_tail: (truncated ? raw.subarray(raw.length - size) : raw).toString("utf8"),
    output_bytes: raw.length,
    output_truncated: truncated,
  }
}
const hasExactLine = (value, marker) => Boolean(marker) && String(value || "")
  .split(/\r?\n/)
  .some((line) => line.trim() === marker)
const appendAudit = async (binding, event) => {
  await fs.appendFile(
    binding.audit_path,
    `${JSON.stringify({ version: 1, time_ms: Date.now(), ...event })}\n`,
    { encoding: "utf8", mode: 0o600 },
  )
}

const writtenFiles = (tool, args, metadata, directory) => {
  const files = []
  const addFile = (rawPath, created = false) => {
    const value = pathText(rawPath)
    if (!value) return
    files.push({
      path: path.isAbsolute(value) ? path.normalize(value) : path.resolve(directory, value),
      created: Boolean(created),
    })
  }
  if (tool === "write" || tool === "edit") {
    const fileDiff = metadata.filediff && typeof metadata.filediff === "object"
      ? metadata.filediff
      : {}
    const rawPath = pathText(metadata.filepath)
      || pathText(metadata.filePath)
      || pathText(fileDiff.file)
      || pathText(args.filePath)
      || pathText(args.file_path)
      || pathText(args.path)
    const created = tool === "write"
      ? metadata.exists === false
      : (args.oldString ?? args.old_string) === ""
    addFile(rawPath, created)
  } else if (["apply_patch", "patch"].includes(tool)) {
    const changes = Array.isArray(metadata.files) ? metadata.files : []
    for (const item of changes) {
      if (!item || typeof item !== "object") continue
      const changeType = String(item.type || "").trim().toLowerCase()
      if (changeType === "delete") continue
      const rawPath = changeType === "move"
        ? pathText(item.movePath) || pathText(item.move_path)
        : pathText(item.filePath) || pathText(item.file_path) || pathText(item.file)
      addFile(rawPath, changeType === "add")
    }
  }
  return [...new Map(files.map((item) => [item.path, item])).values()]
}

export const OpenDeepHoleFileWriteHook = async ({ directory }) => ({
  event: async ({ event }) => {
    const info = event?.properties?.info || event?.properties?.session || {}
    const sessionID = String(info?.id || info?.sessionID || "")
    const parentID = String(info?.parentID || info?.parentId || "")
    if (sessionID && parentID) {
      parents.set(sessionID, parentID)
      if (parents.size > 4096) parents.delete(parents.keys().next().value)
    }
    if (event?.type === "session.deleted" && sessionID) parents.delete(sessionID)
  },
  "shell.env": async (input, output) => {
    const binding = await resolveBinding(input?.sessionID)
    if (!binding || !Array.isArray(binding.path_prepend) || !binding.path_prepend.length) return
    const env = objectValue(output?.env)
    const current = pathText(env.PATH) || pathText(env.Path) || pathText(process.env.PATH)
    const currentEntries = current ? current.split(path.delimiter) : []
    const prepended = binding.path_prepend.filter((value) => typeof value === "string" && value.trim())
    const normalized = new Set(prepended.map((value) => process.platform === "win32" ? value.toLowerCase() : value))
    const retained = currentEntries.filter((value) => !normalized.has(process.platform === "win32" ? value.toLowerCase() : value))
    output.env = { ...env, PATH: [...prepended, ...retained].join(path.delimiter) }
  },
  "tool.execute.before": async (input, output) => {
    const binding = await resolveBinding(input?.sessionID)
    if (!binding) return
    const tool = normalizedTool(input?.tool)
    if (!["bash", "shell"].includes(tool)) return
    const args = objectValue(output?.args)
    const command = boundCommand(binding, commandText(args))
    if (!command) throw unboundCommandError(binding, "before")
    // Mutate the same args object consumed by native permissions and execution.
    // Replacing output.args alone would leave OpenCode executing the old input.
    if (typeof args.command === "string") args.command = command
    if (typeof args.cmd === "string") args.cmd = command
  },
  "tool.execute.after": async (input, output) => {
    const tool = normalizedTool(input?.tool)
    const args = input?.args && typeof input.args === "object" ? input.args : {}
    const originalMetadata = output?.metadata && typeof output.metadata === "object"
      ? output.metadata
      : {}
    const binding = await resolveBinding(input?.sessionID)
    if (["bash", "shell"].includes(tool)) {
      if (!binding) return
      const command = commandText(args)
      if (!binding.allowed_commands.includes(command)) {
        throw unboundCommandError(binding, "after")
      }
      const outputMetadata = objectValue(output?.structured)
      const nestedMetadata = objectValue(originalMetadata.structured)
      const rawExitCode = originalMetadata.exitCode ?? originalMetadata.exit_code
        ?? originalMetadata.exit ?? originalMetadata.code ?? nestedMetadata.exit
        ?? outputMetadata.exit ?? output?.exit
      const exitCode = Number.isFinite(Number(rawExitCode)) ? Number(rawExitCode) : null
      const commandOutput = commandOutputText(output, originalMetadata)
      const marker = objectValue(binding.success_markers)[command]
      const timedOut = Boolean(
        originalMetadata.timeout ?? originalMetadata.timed_out ?? nestedMetadata.timeout
        ?? outputMetadata.timeout ?? output?.timeout
      )
      const markerMatched = exitCode === null && !timedOut && hasExactLine(commandOutput, marker)
      const success = !timedOut && (exitCode === 0 || markerMatched)
      await appendAudit(binding, {
        kind: "command",
        session_id: String(input?.sessionID || ""),
        call_id: String(input?.callID || ""),
        command,
        exit_code: exitCode,
        timed_out: timedOut,
        success,
        success_source: exitCode === 0 ? "exit_code" : markerMatched ? "output_marker" : "",
        ...outputTail(commandOutput, binding.output_tail_bytes),
      })
      return
    }
    if (!["write", "edit", "apply_patch", "patch"].includes(tool)) return
    const files = writtenFiles(tool, args, originalMetadata, directory)
    if (!files.length) return
    try {
      output.metadata = {
        ...originalMetadata,
        opendeepholeFileWrites: {
          version: 1,
          sessionID: String(input?.sessionID || ""),
          callID: String(input?.callID || ""),
          files,
        },
      }
    } catch {
      // File-write observability must never change the tool call outcome.
    }
    if (!binding) return
    for (const file of files) {
      await appendAudit(binding, {
        kind: "file_write",
        session_id: String(input?.sessionID || ""),
        call_id: String(input?.callID || ""),
        path: file.path,
      })
    }
  },
})
'''
_FILE_WRITE_PLUGIN_HASH = hashlib.sha256(
    _FILE_WRITE_PLUGIN_SOURCE.encode("utf-8")
).hexdigest()[:16]
_KNOWLEDGE_PROJECT_PLUGIN_SOURCE = r'''import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const bindingDirectory = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "knowledge-bindings",
)
const parents = new Map()
const bindingPath = (sessionID) => path.join(
  bindingDirectory,
  `${crypto.createHash("sha256").update(String(sessionID || "")).digest("hex")}.json`,
)

const readDirectBinding = async (sessionID) => {
  try {
    const value = JSON.parse(await fs.readFile(bindingPath(sessionID), "utf8"))
    if (!value || ![1, 2].includes(value.version) || typeof value.project_id !== "string") return null
    if (!value.project_id.trim()) return null
    return value
  } catch (error) {
    if (error?.code === "ENOENT") return null
    throw error
  }
}

const resolveBinding = async (sessionID) => {
  let current = String(sessionID || "")
  const visited = new Set()
  for (let depth = 0; current && depth < 32 && !visited.has(current); depth += 1) {
    visited.add(current)
    const binding = await readDirectBinding(current)
    if (binding) return binding
    current = String(parents.get(current) || "")
  }
  return null
}

export const OpenDeepHoleKnowledgeProjectHook = async () => ({
  event: async ({ event }) => {
    const info = event?.properties?.info || event?.properties?.session || {}
    const sessionID = String(info?.id || info?.sessionID || "")
    const parentID = String(info?.parentID || info?.parentId || "")
    if (sessionID && parentID) {
      parents.set(sessionID, parentID)
      if (parents.size > 4096) parents.delete(parents.keys().next().value)
    }
    if (event?.type === "session.deleted" && sessionID) parents.delete(sessionID)
  },
  "tool.execute.before": async (input, output) => {
    const binding = await resolveBinding(input?.sessionID)
    if (!binding) return
    const tool = String(input?.tool || "")
    const blocked = Array.isArray(binding.blocked_tool_ids) ? binding.blocked_tool_ids : []
    if (blocked.includes(tool)) {
      throw new Error("Knowledge-base project management tools are platform-only")
    }
    const allowed = Array.isArray(binding.allowed_tool_ids) ? binding.allowed_tool_ids : []
    const prefixes = Array.isArray(binding.tool_id_prefixes) ? binding.tool_id_prefixes : []
    if (!allowed.includes(tool) && !prefixes.some((prefix) => tool.startsWith(prefix))) return
    if (!output?.args || typeof output.args !== "object" || Array.isArray(output.args)) {
      throw new Error("Knowledge-base tool arguments must be an object")
    }
    output.args.project_id = binding.project_id
  },
})
'''
_KNOWLEDGE_PROJECT_PLUGIN_HASH = hashlib.sha256(
    _KNOWLEDGE_PROJECT_PLUGIN_SOURCE.encode("utf-8")
).hexdigest()[:16]
_MANAGED_COMPACTION_CONFIG = {
    "auto": True,
    "prune": True,
    "reserved": 20_000,
}
_MANAGED_MODEL_DEFAULT_CONTEXT = 131_072
_MANAGED_MODEL_DEFAULT_OUTPUT = 32_768
_FORMATTER_DISABLED_TOOL_IDS = frozenset({
    "apply_patch",
    "bash",
    "codesearch",
    "edit",
    "glob",
    "grep",
    "list",
    "patch",
    "question",
    "read",
    "skill",
    "task",
    "todoread",
    "todowrite",
    "webfetch",
    "websearch",
    "write",
})
_LEGACY_SCAN_CODE_GRAPH_MCP_PREFIX = "opendeephole-scan-codegraph-"
_EXPECTED_PASSWORD_WARNING = (
    "Warning: OPENCODE_SERVER_PASSWORD is not set; server is unsecured."
)
_SERVE_BIND_FAILURE_MARKERS = (
    "serveerror",
    "eaddrinuse",
    "eacces",
    "wsaeacces",
    "address already in use",
    "failed to listen",
    "failed to bind",
    "forbidden by its access permissions",
    "only one usage of each socket address",
)
_SERVE_NON_PORT_FAILURE_MARKERS = (
    "cleanup after startup failure also failed",
    "filesystem.open",
    "configerror",
    "jsonerror",
    "syntaxerror",
    "failed to parse",
    "plugin",
)
_SENSITIVE_EVENT_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|authorization|cookie|credential|"
    r"prompt|content|body)",
    re.IGNORECASE,
)
_SERVE_DEBUG_ENV_NAMES = (
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "XDG_CONFIG_HOME",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_PATH",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
)
_SERVE_PROXY_ENV_NAMES = {"http_proxy", "https_proxy", "all_proxy"}
_SERVE_NO_PROXY_ENV_NAME = "no_proxy"


@dataclass(frozen=True)
class OpenCodeServeKey:
    tool: str
    executable: str
    env_hash: str = ""
    config_hash: str = ""
    serve_port_auto: bool = False
    config_content: str = field(default="", compare=False, repr=False)
    env_overrides: tuple[tuple[str, str], ...] = field(default_factory=tuple, compare=False, repr=False)


@dataclass(frozen=True)
class OpenCodeModelInfo:
    id: str
    provider_id: str
    model_id: str
    name: str = ""
    limit_context: int | None = None
    limit_input: int | None = None
    limit_output: int | None = None


@dataclass(frozen=True)
class OpenCodeModelListResult:
    models: list[OpenCodeModelInfo]
    message: str = ""


@dataclass(frozen=True)
class _ServeHealthResult:
    healthy: bool
    status_code: int | None = None
    version: str = ""
    detail: str = ""


@dataclass(frozen=True)
class OpenCodePromptResult:
    """Result of one message appended to an OpenCode session."""

    session_id: str
    message_id: str
    lines: list[str]
    text: str
    model: str = ""
    token_usage: OpenCodeTokenUsage | None = None
    raw: Any = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class OpenCodeCommandFailure:
    failure_kind: str
    command: str = ""
    exit_code: int | None = None
    output_tail: str = ""
    output_bytes: int = 0
    output_truncated: bool = False
    timed_out: bool = False


class OpenCodeTaskQualityError(RuntimeError):
    """The model response violated a caller-required completion contract."""

    def __init__(
        self,
        message: str,
        *,
        failure_kind: str = "quality_error",
        command_failures: tuple[OpenCodeCommandFailure, ...] = (),
        validation_feedback: str = "",
    ) -> None:
        super().__init__(message)
        self.failure_kind = str(failure_kind or "quality_error")
        self.command_failures = command_failures
        self.validation_feedback = str(validation_feedback or "")
        self.prompt_result: OpenCodePromptResult | None = None


class OpenCodeServeStartupError(RuntimeError):
    """Serve failed before a model Session or message request could start."""

    def __init__(self, message: str, *, retry_kind: str = "") -> None:
        super().__init__(message)
        self.retry_kind = str(retry_kind or "").strip().lower()


class OpenCodeProviderQuotaError(RuntimeError):
    """Recoverable Provider-side quota exhaustion reported by OpenCode."""

    def __init__(
        self,
        *,
        error_code: str,
        quota_type: str = "",
        identity: str = "",
        retry_after_seconds: float | None = None,
    ) -> None:
        self.error_code = error_code
        self.quota_type = quota_type
        self.identity = identity
        self.retry_after_seconds = retry_after_seconds
        super().__init__(str(self))

    def __str__(self) -> str:
        scope = f" ({self.quota_type})" if self.quota_type else ""
        retry_note = (
            f"，建议 {self.retry_after_seconds:g} 秒后重试"
            if self.retry_after_seconds is not None
            else "，将按退避策略重试"
        )
        return (
            f"模型 Provider 请求配额暂不可用{scope}"
            f"，错误码 {self.error_code or 'unknown'}{retry_note}"
        )


@dataclass(frozen=True)
class OpenCodeFileWrite:
    """One file successfully written by a completed OpenCode tool call."""

    call_id: str
    path: str
    created: bool = False


@dataclass(frozen=True)
class _ScanMcpLease:
    directory_key: str
    state_key: str
    identity: str
    name: str
    fingerprint: str
    connected: bool
    role: str = "code_graph"
    error: str = ""


@dataclass
class _EventChannelRuntime:
    key: str
    path: str
    params: dict[str, str]
    headers: dict[str, str]
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None
    healthy: bool = False
    connected_once: bool = False
    attempts: int = 0


def split_model_id(model: str) -> tuple[str, str]:
    """Split OpenCode's provider/model identifier."""
    provider, sep, model_id = str(model or "").partition("/")
    if not sep or not provider or not model_id:
        raise ValueError(f"OpenCode serve mode requires model id in provider/model form: {model!r}")
    return provider, model_id


def _serve_port(
    env_overrides: dict[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> int:
    overrides = dict(env_overrides or ())
    raw = str(
        overrides.get(_SERVE_PORT_ENV, os.environ.get(_SERVE_PORT_ENV, ""))
    ).strip()
    if raw:
        try:
            port = int(raw)
        except ValueError as exc:
            raise ValueError(f"{_SERVE_PORT_ENV} must be an integer port: {raw!r}") from exc
        if 1 <= port <= 65535:
            return port
        raise ValueError(f"{_SERVE_PORT_ENV} must be between 1 and 65535: {raw!r}")
    return _DEFAULT_SERVE_PORT


def _port_is_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _port_bind_error(port: int) -> OSError | None:
    """Return the exclusive loopback bind error for the Serve endpoint."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_EXCLUSIVEADDRUSE,
                    1,
                )
            sock.bind(("127.0.0.1", int(port)))
    except OSError as exc:
        return exc
    return None


@dataclass(frozen=True)
class _ServePortProbe:
    connectable: bool
    bind_error: OSError | None

    @property
    def reusable(self) -> bool:
        return not self.connectable and self.bind_error is None


def _probe_serve_port(port: int) -> _ServePortProbe:
    """Return whether the endpoint responds and whether Serve can bind it."""
    return _ServePortProbe(
        connectable=_port_is_in_use(port),
        bind_error=_port_bind_error(port),
    )


def _allocate_loopback_port(excluded: set[int] | None = None) -> int:
    excluded = set(excluded or ())
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in excluded:
            return port
    raise RuntimeError("Unable to allocate a distinct loopback port for OpenCode serve")


def _run_command_text(cmd: list[str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    except Exception as exc:
        logger.debug("Failed to run %s: %s", cmd[0] if cmd else cmd, exc)
        return ""
    output = completed.stdout or completed.stderr or ""
    if completed.returncode != 0:
        logger.debug(
            "Command probe failed executable=%s exit_code=%s output=%s",
            cmd[0] if cmd else "",
            completed.returncode,
            _one_line_preview(output, 500),
        )
    return output


def _executable_argv(executable: str, *arguments: str) -> list[str]:
    """Build argv that can launch Windows .cmd/.bat shims without shell=True."""
    direct = [executable, *arguments]
    if sys.platform != "win32" or Path(executable).suffix.casefold() not in {".cmd", ".bat"}:
        return direct
    command_processor = (
        os.environ.get("COMSPEC")
        or shutil.which("cmd.exe")
        or "cmd.exe"
    )
    # Popen serializes argv on Windows. Prejoining it would escape the quotes
    # around paths with spaces a second time, which cmd.exe treats literally.
    return [
        command_processor,
        "/d",
        "/c",
        "call",
        *direct,
    ]


async def _stop_command_probe_process(
    proc: asyncio.subprocess.Process,
) -> bool:
    """Stop only the process tree created for one diagnostic command."""
    if proc.returncode is not None:
        return True
    if sys.platform == "win32":
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(proc.pid),
                "/T",
                "/F",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            try:
                taskkill_returncode = await asyncio.wait_for(
                    killer.wait(),
                    timeout=_COMMAND_PROBE_STOP_TIMEOUT_SECONDS,
                )
                if taskkill_returncode != 0:
                    logger.warning(
                        "taskkill failed for command probe pid=%s exit_code=%s",
                        proc.pid,
                        taskkill_returncode,
                    )
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    killer.kill()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(killer.wait(), timeout=0.5)
        except FileNotFoundError:
            logger.warning(
                "taskkill is unavailable while stopping command probe pid=%s",
                proc.pid,
            )
        except Exception:
            logger.warning(
                "Failed to stop command probe process tree pid=%s",
                proc.pid,
                exc_info=True,
            )
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(int(proc.pid), signal.SIGTERM)

    try:
        await asyncio.wait_for(
            proc.wait(),
            timeout=_COMMAND_PROBE_STOP_TIMEOUT_SECONDS / 2,
        )
    except asyncio.TimeoutError:
        if sys.platform == "win32":
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        else:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(
                    int(proc.pid),
                    signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM,
                )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=0.5)
    return proc.returncode is not None


async def _run_command_text_async(
    cmd: list[str],
    timeout: float = _SERVE_VERSION_PROBE_TIMEOUT_SECONDS,
) -> str:
    """Run a probe without pipe-EOF hangs or event-loop starvation.

    A timed-out Windows ``cmd.exe`` can leave its child holding inherited pipe
    handles, which makes ``subprocess.run`` wait indefinitely after killing the
    wrapper. A regular output file removes that EOF dependency, while an owned
    process group/tree gives timeout cleanup an exact target.
    """
    if not cmd:
        return ""
    fd, raw_output_path = tempfile.mkstemp(
        prefix="opendeephole-command-probe-",
        suffix=".log",
    )
    os.close(fd)
    output_path = Path(raw_output_path)
    proc: asyncio.subprocess.Process | None = None
    timed_out = False
    try:
        popen_kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            creation_flag = int(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) or 0
            )
            if creation_flag:
                popen_kwargs["creationflags"] = creation_flag
        else:
            popen_kwargs["start_new_session"] = True
        with output_path.open("wb") as output_handle:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=subprocess.DEVNULL,
                stdout=output_handle,
                stderr=subprocess.STDOUT,
                **popen_kwargs,
            )
            try:
                await asyncio.wait_for(
                    proc.wait(),
                    timeout=max(0.0, float(timeout)),
                )
            except asyncio.TimeoutError:
                timed_out = True
                logger.warning(
                    "Command probe timed out executable=%s pid=%s timeout_seconds=%s; "
                    "stopping its process tree",
                    cmd[0],
                    proc.pid,
                    timeout,
                )
                stopped = await _stop_command_probe_process(proc)
                if not stopped:
                    logger.warning(
                        "Timed-out command probe process tree may still be running pid=%s",
                        proc.pid,
                    )
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            await _stop_command_probe_process(proc)
        raise
    except FileNotFoundError:
        return ""
    except Exception as exc:
        logger.debug("Failed to run %s: %s", cmd[0], exc)
        if proc is not None and proc.returncode is None:
            await _stop_command_probe_process(proc)
        return ""
    finally:
        try:
            output = output_path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            output = ""
        _remove_file(output_path)

    if timed_out:
        return ""
    if proc is not None and proc.returncode != 0:
        logger.debug(
            "Command probe failed executable=%s exit_code=%s output=%s",
            cmd[0],
            proc.returncode,
            _one_line_preview(output, 500),
        )
        return ""
    return output


def _new_serve_startup_log_path(tool: str, port: int) -> Path:
    safe_tool = re.sub(r"[^A-Za-z0-9_.-]+", "_", tool or "opencode").strip("._") or "opencode"
    fd, raw_path = tempfile.mkstemp(
        prefix=f"opendeephole-{safe_tool}-serve-startup-",
        suffix=f"-{port}.log",
    )
    os.close(fd)
    return Path(raw_path)


def _safe_name(value: str, default: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or default).strip("._") or default


def _serve_bootstrap_cwd(tool: str) -> Path:
    try:
        root = str(Path.cwd().resolve())
    except Exception:
        root = os.getcwd()
    digest = hashlib.sha256(root.encode("utf-8", errors="replace")).hexdigest()[:12]
    safe_tool = _safe_name(tool, "opencode")
    return Path(tempfile.gettempdir()) / f"{_SERVE_BOOTSTRAP_CWD_PREFIX}-{safe_tool}-{digest}"


def _ensure_minimal_git_repo(cwd: Path) -> None:
    if (cwd / ".git").exists():
        return
    try:
        completed = subprocess.run(
            ["git", "init", "-q"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("git executable not found; OpenCode serve startup cwd remains non-git: %s", cwd)
        return
    except subprocess.TimeoutExpired:
        logger.warning("git init timed out for OpenCode serve startup cwd: %s", cwd)
        return
    except Exception as exc:
        logger.warning("Failed to initialize OpenCode serve startup cwd %s as git repo: %s", cwd, exc)
        return
    if completed.returncode != 0:
        detail = _one_line_preview(completed.stderr or completed.stdout or f"exit {completed.returncode}")
        logger.warning("Failed to initialize OpenCode serve startup cwd %s as git repo: %s", cwd, detail)


def _prepare_serve_startup_cwd(tool: str, startup_cwd: Path | None) -> Path:
    cwd = Path(startup_cwd) if startup_cwd is not None else _serve_bootstrap_cwd(tool)
    cwd.mkdir(parents=True, exist_ok=True)
    _ensure_minimal_git_repo(cwd)
    return cwd


def _write_private_text(path: Path, content: str) -> None:
    """Atomically write one private Serve-owned text file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink()


def _managed_file_write_plugin_path(cwd: Path) -> Path:
    plugin_path = (
        cwd
        / _SERVE_MANAGED_PLUGIN_DIRNAME
        / f"opendeephole-file-write-{_FILE_WRITE_PLUGIN_HASH}.mjs"
    ).resolve()
    _write_private_text(plugin_path, _FILE_WRITE_PLUGIN_SOURCE)
    return plugin_path


def _managed_knowledge_project_plugin_path(cwd: Path) -> Path:
    plugin_path = (
        cwd
        / _SERVE_MANAGED_PLUGIN_DIRNAME
        / f"opendeephole-knowledge-project-{_KNOWLEDGE_PROJECT_PLUGIN_HASH}.mjs"
    ).resolve()
    _write_private_text(plugin_path, _KNOWLEDGE_PROJECT_PLUGIN_SOURCE)
    return plugin_path


def _knowledge_binding_path(cwd: Path, session_id: str) -> Path:
    digest = hashlib.sha256(str(session_id or "").encode("utf-8")).hexdigest()
    directory = (
        Path(cwd).resolve()
        / _SERVE_MANAGED_PLUGIN_DIRNAME
        / _KNOWLEDGE_BINDING_DIRNAME
    )
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(directory, 0o700)
    return directory / f"{digest}.json"


def _private_session_file(
    cwd: Path,
    directory_name: str,
    session_id: str,
    suffix: str,
) -> Path:
    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id:
        raise ValueError("OpenCode Session ID is required")
    digest = hashlib.sha256(normalized_session_id.encode("utf-8")).hexdigest()
    directory = cwd / _SERVE_MANAGED_PLUGIN_DIRNAME / directory_name
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(directory, 0o700)
    return directory / f"{digest}.{suffix}"


def _command_binding_path(cwd: Path, session_id: str) -> Path:
    return _private_session_file(
        cwd,
        _COMMAND_BINDING_DIRNAME,
        session_id,
        "json",
    )


def _command_audit_path(cwd: Path, session_id: str) -> Path:
    return _private_session_file(
        cwd,
        _COMMAND_AUDIT_DIRNAME,
        session_id,
        "jsonl",
    )


def _write_command_binding(
    cwd: Path,
    *,
    session_id: str,
    required_commands: tuple[str, ...],
    bash_command_match_mode: str = "exact",
    success_markers: tuple[tuple[str, str], ...] = (),
    path_prepend: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    normalized_commands = tuple(dict.fromkeys(
        str(command or "").strip() for command in required_commands
    ))
    if not normalized_commands or any(not command for command in normalized_commands):
        raise ValueError("Command binding requires non-empty commands")
    if any("\n" in command or "\r" in command for command in normalized_commands):
        raise ValueError("Command binding commands cannot contain newlines")
    match_metadata = command_binding_metadata(
        normalized_commands,
        match_mode=bash_command_match_mode,
    )
    binding_path = _command_binding_path(cwd, session_id)
    audit_path = _command_audit_path(cwd, session_id)
    _remove_file(audit_path)
    _write_private_text(
        binding_path,
        json.dumps(
            {
                "version": 2,
                "session_id": str(session_id),
                "allowed_commands": list(normalized_commands),
                "audit_path": str(audit_path),
                "success_markers": dict(success_markers),
                "path_prepend": list(path_prepend),
                "output_tail_bytes": _COMMAND_OUTPUT_TAIL_BYTES,
                **match_metadata,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n",
    )
    return binding_path, audit_path


def _validate_required_command_audit(
    path: Path,
    required_commands: tuple[str, ...],
) -> None:
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise OpenCodeTaskQualityError(
            "OpenCode did not execute the required validation command",
            failure_kind="command_not_executed",
            command_failures=tuple(
                OpenCodeCommandFailure(
                    failure_kind="command_not_executed",
                    command=command,
                )
                for command in required_commands
            ),
        ) from exc
    events: list[dict[str, Any]] = []
    for line_number, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OpenCodeTaskQualityError(
                f"OpenCode command audit is invalid at line {line_number}",
                failure_kind="command_audit_invalid",
            ) from exc
        if not isinstance(value, dict) or value.get("version") != 1:
            raise OpenCodeTaskQualityError(
                f"OpenCode command audit is invalid at line {line_number}",
                failure_kind="command_audit_invalid",
            )
        events.append(value)

    successful_indexes: dict[str, list[int]] = {
        command: [] for command in required_commands
    }
    last_write_index = -1
    failures: dict[str, dict[str, Any]] = {}
    successes: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events):
        if event.get("kind") == "file_write":
            last_write_index = index
            continue
        if event.get("kind") != "command":
            continue
        command = str(event.get("command") or "")
        if command not in successful_indexes:
            continue
        if event.get("success") is True and (
            event.get("exit_code") == 0
            or event.get("success_source") == "output_marker"
        ):
            successful_indexes[command].append(index)
            successes[command] = event
        else:
            failures[command] = event

    missing = [
        command for command, indexes in successful_indexes.items() if not indexes
    ]
    if missing:
        command_failures: list[OpenCodeCommandFailure] = []
        for command in missing:
            event = failures.get(command, {})
            exit_code = event.get("exit_code")
            timed_out = event.get("timed_out") is True
            if not event:
                failure_kind = "command_not_executed"
            elif timed_out:
                failure_kind = "command_timeout"
            elif exit_code is None:
                failure_kind = "command_exit_unknown"
            else:
                failure_kind = "command_exit_failure"
            command_failures.append(OpenCodeCommandFailure(
                failure_kind=failure_kind,
                command=command,
                exit_code=(
                    int(exit_code)
                    if isinstance(exit_code, int) and not isinstance(exit_code, bool)
                    else None
                ),
                output_tail=str(event.get("output_tail") or ""),
                output_bytes=max(0, int(event.get("output_bytes") or 0)),
                output_truncated=event.get("output_truncated") is True,
                timed_out=timed_out,
            ))
        detail = ", ".join(
            f"{command!r} (exit={failures.get(command, {}).get('exit_code')!r})"
            for command in missing
        )
        raise OpenCodeTaskQualityError(
            "OpenCode required validation command did not complete successfully: "
            + detail,
            failure_kind=command_failures[0].failure_kind,
            command_failures=tuple(command_failures),
        )
    last_required_index = min(
        max(indexes) for indexes in successful_indexes.values()
    )
    if last_write_index > last_required_index:
        command_failures = tuple(
            OpenCodeCommandFailure(
                failure_kind="files_modified_after_validation",
                command=command,
                exit_code=(
                    int(successes[command].get("exit_code"))
                    if isinstance(successes.get(command, {}).get("exit_code"), int)
                    else None
                ),
                output_tail=str(successes.get(command, {}).get("output_tail") or ""),
                output_bytes=max(
                    0,
                    int(successes.get(command, {}).get("output_bytes") or 0),
                ),
                output_truncated=(
                    successes.get(command, {}).get("output_truncated") is True
                ),
            )
            for command in required_commands
        )
        raise OpenCodeTaskQualityError(
            "OpenCode modified task files after the required validation command",
            failure_kind="files_modified_after_validation",
            command_failures=command_failures,
        )


def _write_knowledge_binding(
    cwd: Path,
    *,
    session_id: str,
    project_id: str,
    mcp_name: str,
    blocked_tool_ids: list[str],
) -> Path:
    normalized_session_id = str(session_id or "").strip()
    normalized_project_id = str(project_id or "").strip()
    if not normalized_session_id or not normalized_project_id:
        raise ValueError("Knowledge-base binding requires session_id and project_id")
    tool_id_prefixes = list(_opencode_mcp_tool_prefixes(mcp_name))
    if not tool_id_prefixes:
        raise ValueError("Knowledge-base binding requires an MCP name")
    if not blocked_tool_ids:
        raise ValueError("Knowledge-base binding has no control tools")
    binding_path = _knowledge_binding_path(cwd, normalized_session_id)
    payload = {
        "version": 2,
        "session_id": normalized_session_id,
        "project_id": normalized_project_id,
        "mcp_name": str(mcp_name or "").strip(),
        "tool_id_prefixes": tool_id_prefixes,
        "blocked_tool_ids": list(dict.fromkeys(blocked_tool_ids)),
    }
    _write_private_text(
        binding_path,
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
    )
    return binding_path


def _with_managed_compaction(data: dict[str, Any]) -> dict[str, Any]:
    """Return the effective config with DeepHole's compaction policy applied."""
    resolved = dict(data)
    configured = resolved.get("compaction")
    compaction = dict(configured) if isinstance(configured, dict) else {}
    compaction.update(_MANAGED_COMPACTION_CONFIG)
    resolved["compaction"] = compaction
    return resolved


def _with_managed_model_limits(data: dict[str, Any]) -> dict[str, Any]:
    """Fill safe limits for configured models without a context limit."""
    resolved = dict(data)
    configured_providers = resolved.get("provider")
    if not isinstance(configured_providers, dict):
        return resolved

    providers = dict(configured_providers)
    providers_changed = False
    for provider_id, configured_provider in configured_providers.items():
        if not isinstance(configured_provider, dict):
            continue
        configured_models = configured_provider.get("models")
        if not isinstance(configured_models, dict):
            continue

        models = dict(configured_models)
        models_changed = False
        for model_id, configured_model in configured_models.items():
            if not isinstance(configured_model, dict):
                continue
            configured_limit = configured_model.get("limit")
            limit = dict(configured_limit) if isinstance(configured_limit, dict) else {}
            if "context" in limit:
                continue

            limit["context"] = _MANAGED_MODEL_DEFAULT_CONTEXT
            limit.setdefault("output", _MANAGED_MODEL_DEFAULT_OUTPUT)
            model = dict(configured_model)
            model["limit"] = limit
            models[model_id] = model
            models_changed = True

        if not models_changed:
            continue
        provider = dict(configured_provider)
        provider["models"] = models
        providers[provider_id] = provider
        providers_changed = True

    if providers_changed:
        resolved["provider"] = providers
    return resolved


def _with_managed_runtime_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Return the effective config after applying all managed runtime fields."""
    return _with_managed_compaction(_with_managed_model_limits(data))


def _write_serve_config_file(cwd: Path, config_content: str) -> Path:
    """Atomically publish the resolved config and managed runtime fields."""
    raw = config_content or "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Resolved OpenCode config is invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Resolved OpenCode config must be a JSON object")
    data = _with_managed_runtime_fields(data)
    configured_plugins = data.get("plugin")
    if isinstance(configured_plugins, str):
        plugins = [configured_plugins]
    elif isinstance(configured_plugins, list):
        plugins = [
            str(value)
            for value in configured_plugins
            if isinstance(value, str) and value.strip()
        ]
    elif configured_plugins is None:
        plugins = []
    else:
        raise ValueError("Resolved OpenCode config plugin must be a string or list")
    managed_plugins = [
        _managed_file_write_plugin_path(cwd).as_uri(),
        _managed_knowledge_project_plugin_path(cwd).as_uri(),
    ]
    data["plugin"] = list(dict.fromkeys([*plugins, *managed_plugins]))
    normalized = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    config_path = cwd / "opencode.json"
    _write_private_text(config_path, normalized)
    return config_path


def _config_secret_values(value: Any, *, sensitive: bool = False) -> set[str]:
    secrets: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            secrets.update(_config_secret_values(
                item,
                sensitive=sensitive or is_sensitive_opencode_config_key(str(key)),
            ))
    elif isinstance(value, list):
        for item in value:
            secrets.update(_config_secret_values(item, sensitive=sensitive))
    elif sensitive and value is not None:
        text = str(value)
        if len(text) >= 4:
            secrets.add(text)
    return secrets


def _redact_serve_startup_text(text: str, config_content: str = "") -> str:
    redacted = str(text or "")
    try:
        config = json.loads(config_content or "{}")
    except Exception:
        config = {}
    for secret in sorted(
        _config_secret_values(config),
        key=len,
        reverse=True,
    ):
        redacted = redacted.replace(secret, "***")
    redacted = re.sub(
        r"(?i)((?:api[_-]?key|apikey|token|secret|password|authorization|"
        r"cookie|credential)\s*[\"']?\s*[:=]\s*[\"']?)([^\s,\"']+)",
        r"\1***",
        redacted,
    )
    return redacted


def _read_serve_startup_log_tail(
    path: Path | None,
    *,
    config_content: str = "",
) -> str:
    if path is None:
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""
    if len(text) > _SERVE_STARTUP_LOG_TAIL_LIMIT:
        text = text[-_SERVE_STARTUP_LOG_TAIL_LIMIT:]
    return _redact_serve_startup_text(text, config_content)


def _with_serve_startup_log(
    message: str,
    path: Path | None,
    *,
    config_content: str = "",
) -> str:
    tail = _read_serve_startup_log_tail(
        path,
        config_content=config_content,
    )
    if not tail:
        return message
    warning_note = ""
    if _EXPECTED_PASSWORD_WARNING in tail:
        warning_note = (
            "\n\nNote: the OPENCODE_SERVER_PASSWORD warning is expected for "
            "the Agent-owned 127.0.0.1 listener and did not cause this exit."
        )
    return f"{message}\n\nOpenCode serve startup output:\n{tail}{warning_note}"


@dataclass
class _ServeStartupLogCursor:
    offset: int = 0
    pending: bytes = b""


def _log_serve_startup_output_updates(
    path: Path | None,
    cursor: _ServeStartupLogCursor,
    *,
    config_content: str = "",
    final: bool = False,
) -> None:
    """Forward new, redacted Serve startup lines to the Agent console logger."""
    if path is None:
        return
    try:
        size = path.stat().st_size
        if size < cursor.offset:
            cursor.offset = 0
            cursor.pending = b""
        with path.open("rb") as stream:
            stream.seek(cursor.offset)
            chunk = stream.read()
            cursor.offset = stream.tell()
    except Exception as exc:
        logger.debug("Failed to follow OpenCode serve startup output %s: %s", path, exc)
        return

    buffered = cursor.pending + chunk
    complete: list[bytes] = []
    while b"\n" in buffered:
        line, buffered = buffered.split(b"\n", 1)
        complete.append(line.rstrip(b"\r"))
    if final and buffered:
        complete.append(buffered.rstrip(b"\r"))
        buffered = b""
    elif len(buffered) > _SERVE_STARTUP_LOG_TAIL_LIMIT:
        complete.append(buffered)
        buffered = b""
    cursor.pending = buffered

    for raw_line in complete:
        line = _redact_serve_startup_text(
            raw_line.decode("utf-8", errors="replace"),
            config_content,
        ).strip()
        if line:
            logger.info("OpenCode serve startup output: %s", line)


def _serve_startup_retry_kind(error: BaseException) -> str:
    text = str(error).lower()
    if isinstance(error, OpenCodeServeStartupError) and error.retry_kind:
        return error.retry_kind
    if any(marker in text for marker in _SERVE_NON_PORT_FAILURE_MARKERS):
        return ""
    if any(marker in text for marker in _SERVE_BIND_FAILURE_MARKERS):
        return "bind"
    if "error: unexpected error" in text:
        return "generic"
    return ""


def _serve_startup_context_message(
    error: BaseException,
    *,
    auto_port: bool,
    attempted_ports: list[int],
    executable_version: str,
) -> str:
    version = executable_version or "unknown"
    return (
        f"{error}\n\nOpenCode serve startup context: "
        f"port_mode={'auto' if auto_port else 'fixed'} "
        f"attempted_ports={','.join(str(port) for port in attempted_ports)} "
        f"executable_version={version}"
    )


def _serve_debug_env_value(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if name == "OPENCODE_CONFIG_CONTENT":
        return redact_opencode_config_content(value)
    return value


def _serve_startup_env_debug(env: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for name in _SERVE_DEBUG_ENV_NAMES:
        value = _serve_debug_env_value(name, env.get(name))
        lines.append(f"    {name}={value if value is not None else '(unset)'}")
    lines.append("    OPENCODE_SERVER_PASSWORD=(cleared)")
    lines.append("    OPENCODE_SERVER_USERNAME=(cleared)")
    return lines


def _serve_startup_shell_debug(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    env_parts = [
        f"{name}={shlex.quote(_serve_debug_env_value(name, env[name]) or '')}"
        for name in _SERVE_DEBUG_ENV_NAMES
        if name in env
    ]
    prefix = " ".join(env_parts)
    command = shlex.join(cmd)
    if prefix:
        command = f"{prefix} {command}"
    return f"cd {shlex.quote(str(cwd))} && {command}"


def _log_serve_startup_debug(
    *,
    key: OpenCodeServeKey,
    cmd: list[str],
    port: int,
    cwd: Path,
    env: dict[str, str],
    startup_log_path: Path,
    popen_kwargs: dict[str, Any],
    marker_path: Path,
    config_path: Path,
    port_mode: str,
    attempt: int,
    executable_version: str,
    executable_resolved: str,
    version_argv: list[str],
) -> None:
    try:
        config_content = config_path.read_text(encoding="utf-8")
    except OSError:
        config_content = key.config_content
    lines = [
        "OpenCode serve startup debug:",
        f"  tool={key.tool}",
        f"  executable_config={key.executable}",
        f"  executable_resolved={executable_resolved}",
        f"  executable_version={executable_version or '(unknown)'}",
        f"  version_argv={json.dumps(version_argv, ensure_ascii=False)}",
        f"  port={port}",
        f"  port_mode={port_mode}",
        f"  startup_attempt={attempt}",
        f"  cwd={cwd}",
        f"  marker_path={marker_path}",
        f"  startup_log_path={startup_log_path}",
        f"  config_hash={key.config_hash or '(none)'}",
        f"  config_file_path={config_path}",
        f"  config_content_bytes={len(config_content.encode('utf-8')) if config_content else 0}",
        f"  config_content_redacted={redact_opencode_config_content(config_content)}",
        f"  argv={json.dumps(cmd, ensure_ascii=False)}",
        f"  shell={_serve_startup_shell_debug(cmd, cwd, env)}",
        "  env_overrides:",
        *_serve_startup_env_debug(env),
        f"  popen_kwargs={popen_kwargs!r}",
    ]
    # Emit one record per physical line so the Agent console formatter places a
    # timestamp on every item and Windows terminal output remains scannable.
    for line in lines:
        logger.info("%s", line)


def _remove_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("Failed to remove %s: %s", path, exc)


def _address_token_has_port(token: str, port: int) -> bool:
    value = token.strip().strip(",")
    if ":" not in value:
        return False
    suffix = f":{port}"
    if value.endswith(suffix):
        return True
    bracket_suffix = f"]:{port}"
    return value.endswith(bracket_suffix)


def _parse_listener_pids(output: str, port: int) -> set[int]:
    pids: set[int] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "LISTEN" not in line.upper():
            continue
        tokens = line.split()
        if not any(_address_token_has_port(token, port) for token in tokens):
            continue
        for match in re.finditer(r"(?:^|[^\w])pid=(\d+)(?:[^\w]|$)", line, re.IGNORECASE):
            pids.add(int(match.group(1)))
        if tokens:
            match = re.match(r"^(\d+)(?:/.*)?$", tokens[-1])
            if match:
                pids.add(int(match.group(1)))
    return pids


def _windows_listener_pids_for_port(port: int) -> set[int]:
    return _parse_listener_pids(_run_command_text(["netstat", "-ano", "-p", "tcp"]), port)


def _posix_listener_pids_for_port(port: int) -> set[int]:
    pids: set[int] = set()
    if shutil.which("lsof"):
        output = _run_command_text(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"])
        for line in output.splitlines():
            value = line.strip()
            if value.isdigit():
                pids.add(int(value))
    if shutil.which("ss"):
        pids.update(_parse_listener_pids(_run_command_text(["ss", "-ltnp", "sport", "=", f":{port}"]), port))
    if shutil.which("netstat"):
        pids.update(_parse_listener_pids(_run_command_text(["netstat", "-ltnp"]), port))
    pids.update(_proc_listener_pids_for_port(port))
    return pids


def _proc_listener_pids_for_port(port: int) -> set[int]:
    inodes: set[str] = set()
    port_hex = f"{port:04X}"
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) <= 9 or parts[3] != "0A":
                continue
            _, _, local_port = parts[1].rpartition(":")
            if local_port.upper() == port_hex:
                inodes.add(parts[9])
    if not inodes:
        return set()

    pids: set[int] = set()
    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except Exception:
        return set()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except Exception:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except Exception:
                continue
            match = re.match(r"socket:\[(\d+)\]$", target)
            if match and match.group(1) in inodes:
                pids.add(int(entry.name))
                break
    return pids


def _listener_pids_for_port(port: int) -> set[int]:
    if sys.platform == "win32":
        return _windows_listener_pids_for_port(port)
    return _posix_listener_pids_for_port(port)


def _windows_process_parent_snapshot() -> dict[int, int] | None:
    """Return a complete best-effort Windows PID -> parent PID snapshot."""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return None

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    try:
        kernel32 = ctypes.windll.kernel32
    except Exception:
        return None
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    invalid_handle = ctypes.c_void_p(-1).value
    snapshot_value = (
        snapshot
        if isinstance(snapshot, int)
        else ctypes.cast(snapshot, ctypes.c_void_p).value
    )
    if not snapshot_value or snapshot_value == invalid_handle:
        return None
    parents: dict[int, int] = {}
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(ProcessEntry32W)
        if not process_first(snapshot, ctypes.byref(entry)):
            return None
        while True:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            if not process_next(snapshot, ctypes.byref(entry)):
                break
    finally:
        close_handle(snapshot)
    return parents


def _windows_process_parent_map() -> dict[int, int]:
    """Return a best-effort Windows PID -> parent PID snapshot."""
    return _windows_process_parent_snapshot() or {}


def _windows_process_creation_time(pid: int) -> int | None:
    """Return the Windows process creation FILETIME used to detect PID reuse."""
    if pid <= 0:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class FileTime(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD),
            ]

        kernel32 = ctypes.windll.kernel32
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
        ]
        get_process_times.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        process_query_limited_information = 0x1000
        handle = open_process(
            process_query_limited_information,
            False,
            int(pid),
        )
        if not handle:
            return None
        try:
            creation = FileTime()
            exit_time = FileTime()
            kernel_time = FileTime()
            user_time = FileTime()
            if not get_process_times(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                return None
            return (
                int(creation.dwHighDateTime) << 32
            ) | int(creation.dwLowDateTime)
        finally:
            close_handle(handle)
    except Exception:
        return None


def _posix_process_stat(pid: int) -> tuple[str, int, int] | None:
    """Return process state, parent PID, and process-group ID from ``/proc``."""
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return None
    close_paren = raw.rfind(")")
    if close_paren < 0:
        return None
    fields = raw[close_paren + 1:].split()
    if len(fields) < 3:
        return None
    try:
        return fields[0], int(fields[1]), int(fields[2])
    except ValueError:
        return None


def _posix_process_parent_pid(pid: int) -> int | None:
    stat = _posix_process_stat(pid)
    return None if stat is None else stat[1]


def _posix_process_group_has_live_members(pgid: int) -> bool | None:
    """Return whether a Linux process group has a non-zombie member.

    ``None`` means ``/proc`` was unavailable or incomplete, so callers should
    fall back to ``killpg(..., 0)``. Ignoring zombies avoids waiting the full
    shutdown timeout after a hard kill while an init process reaps descendants.
    """
    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except Exception:
        return None

    incomplete = False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        stat = _posix_process_stat(int(entry.name))
        if stat is None:
            incomplete = True
            continue
        state, _, process_group_id = stat
        if process_group_id == pgid and state != "Z":
            return True
    return None if incomplete else False


def _pid_descends_from(pid: int, ancestor_pid: int) -> bool | None:
    """Return whether ``pid`` belongs to ``ancestor_pid``'s process tree.

    ``None`` means the platform did not expose enough ancestry information to
    decide. That distinction lets startup retain the old health-only fallback
    on restricted systems without accepting a listener proven to be unrelated.
    """
    pid = int(pid)
    ancestor_pid = int(ancestor_pid)
    if pid <= 0 or ancestor_pid <= 0:
        return False
    if pid == ancestor_pid:
        return True

    parents = _windows_process_parent_map() if sys.platform == "win32" else None
    current = pid
    visited: set[int] = set()
    for _ in range(64):
        if current in visited:
            return False
        visited.add(current)
        if parents is not None:
            if current not in parents:
                return None
            parent = parents[current]
        else:
            parent = _posix_process_parent_pid(current)
            if parent is None:
                return None
        if parent == ancestor_pid:
            return True
        if parent <= 0 or parent == current:
            return False
        current = parent
    return False


def _owned_listener_pids_for_launcher(
    port: int,
    launcher_pid: int,
) -> tuple[set[int], set[int], bool]:
    """Return all listeners, owned listeners, and whether ownership was decidable."""
    listeners = {
        int(pid)
        for pid in _listener_pids_for_port(port)
        if int(pid) > 0
    }
    owned: set[int] = set()
    ownership_verified = False
    for pid in listeners:
        relation = _pid_descends_from(pid, launcher_pid)
        if relation is not None:
            ownership_verified = True
        if relation:
            owned.add(pid)
    return listeners, owned, ownership_verified


@dataclass(frozen=True)
class _PortReclaimResult:
    attempted: bool
    pids: tuple[int, ...] = ()
    released: bool = False
    detail: str = ""


@dataclass(frozen=True)
class _PreviousServeCleanupResult:
    avoided_ports: tuple[int, ...] = ()
    detail: str = ""


def _reclaim_serve_port(
    port: int,
    *,
    reason: str,
    allowed_pids: set[int] | tuple[int, ...] = (),
) -> _PortReclaimResult:
    allowed = {
        int(pid)
        for pid in allowed_pids
        if int(pid) > 0 and int(pid) != os.getpid()
    }
    # Marker identity limits which listener may be terminated. Actual endpoint
    # availability is verified separately because Windows can retain a stale
    # owner-PID row after the socket has already become reusable.
    listeners = {
        int(pid)
        for pid in _listener_pids_for_port(port)
        if int(pid) > 0
    }
    pids = tuple(sorted(
        pid
        for pid in listeners
        if pid in allowed
    ))
    if not pids:
        if not listeners:
            return _PortReclaimResult(
                attempted=False,
                released=True,
                detail="owned listener pid(s) already absent",
            )
        return _PortReclaimResult(
            attempted=False,
            released=False,
            detail="listener ownership was not proven",
        )

    # Windows can retain a stale owner-PID row after the process and socket are
    # already gone. A failed TCP connection plus a successful exclusive bind is
    # the operational proof that this row cannot block the replacement Serve.
    if sys.platform == "win32":
        initial_probe = _probe_serve_port(port)
        if initial_probe.reusable:
            logger.warning(
                "Ignoring stale OpenCode listener-table pid(s)=%s on 127.0.0.1:%s; "
                "TCP connect failed and exclusive bind succeeded (%s)",
                ",".join(str(pid) for pid in pids),
                port,
                reason,
            )
            return _PortReclaimResult(
                attempted=False,
                pids=pids,
                released=True,
                detail="stale listener-table pid(s) ignored because port is reusable",
            )

    termination_failed_pids: list[int] = []
    for pid in pids:
        logger.warning(
            "Reclaiming OpenCode serve port 127.0.0.1:%s by terminating listener pid %s (%s)",
            port,
            pid,
            reason,
        )
        stopped = _terminate_process_tree(
            pid,
            is_running=(
                (
                    lambda pid=pid: (
                        pid in _listener_pids_for_port(port)
                        and not _probe_serve_port(port).reusable
                    )
                )
                if sys.platform == "win32"
                else None
            ),
        )
        if not stopped:
            termination_failed_pids.append(pid)
    remaining_listener_pids = _wait_listener_pids_released(port, set(pids))
    released = not remaining_listener_pids
    failure_note = (
        "; termination failed for listener pid(s)="
        + ",".join(str(pid) for pid in termination_failed_pids)
        if termination_failed_pids
        else ""
    )
    return _PortReclaimResult(
        attempted=True,
        pids=pids,
        released=released,
        detail=(
            "owned listener pid(s) released"
            if released
            else (
                "owned listener pid(s) still listening after termination="
                + ",".join(str(pid) for pid in sorted(remaining_listener_pids))
                + failure_note
            )
        ),
    )


def _port_busy_message(
    port: int,
    *,
    auto_port: bool = False,
    listener_pids: set[int] | tuple[int, ...] = (),
    bind_error: OSError | None = None,
) -> str:
    pids = sorted({int(pid) for pid in listener_pids if int(pid) > 0})
    pid_note = f" listener_pid(s)={','.join(str(pid) for pid in pids)}." if pids else ""
    bind_note = f" Bind error: {bind_error}." if bind_error is not None else ""
    if pids:
        cause = "is already in use by a process not proven to belong to this Agent"
    else:
        cause = (
            "cannot be bound even though no TCP listener was detected; on Windows "
            "the port may be excluded/reserved or blocked by endpoint security"
        )
    if auto_port:
        action = (
            " Automatic port recovery was exhausted; inspect the reported "
            "listeners, Windows excluded/reserved ranges, and endpoint security."
        )
        mode = "Automatic"
    else:
        action = (
            " Stop the listener or unset/change the explicit OpenCode serve "
            "port to use automatic allocation."
        )
        mode = "Configured"
    return (
        f"{mode} OpenCode serve port 127.0.0.1:{port} {cause}."
        f"{pid_note}{bind_note}{action}"
    )


def _serve_marker_path() -> Path:
    configured = os.environ.get(_SERVE_MARKER_ENV, "").strip()
    if configured:
        return Path(configured)
    try:
        suffix = str(os.getuid())
    except AttributeError:
        suffix = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return Path(tempfile.gettempdir()) / f"opendeephole-opencode-serve-{suffix}.json"


def _read_marker(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.warning("Failed to read OpenCode serve marker %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def _marker_listener_pids(marker: dict[str, Any]) -> set[int]:
    raw = marker.get("listener_pids")
    if not isinstance(raw, list):
        return set()
    return {
        int(pid)
        for pid in raw
        if str(pid).isdigit() and int(pid) > 0
    }


def _marker_process_creation_times(marker: dict[str, Any]) -> dict[int, int]:
    raw = marker.get("process_creation_times")
    if not isinstance(raw, dict):
        return {}
    result: dict[int, int] = {}
    for raw_pid, raw_creation_time in raw.items():
        try:
            pid = int(raw_pid)
            creation_time = int(raw_creation_time)
        except (TypeError, ValueError):
            continue
        if pid > 0 and creation_time > 0:
            result[pid] = creation_time
    return result


def _write_marker(
    path: Path,
    *,
    proc: Any,
    key: OpenCodeServeKey,
    port: int,
    launcher_pid: int | None = None,
    listener_pids: set[int] | tuple[int, ...] = (),
) -> None:
    pid = int(getattr(proc, "pid", 0) or 0)
    recorded_pids = {
        int(recorded_pid)
        for recorded_pid in (
            os.getpid(),
            pid,
            int(launcher_pid or pid),
            *listener_pids,
        )
        if int(recorded_pid) > 0
    }
    process_creation_times: dict[str, int] = {}
    if sys.platform == "win32":
        for recorded_pid in sorted(recorded_pids):
            creation_time = _windows_process_creation_time(recorded_pid)
            if creation_time is not None:
                process_creation_times[str(recorded_pid)] = creation_time
    data = {
        "owner": _SERVE_MARKER_OWNER,
        "agent_pid": os.getpid(),
        "pid": pid,
        "launcher_pid": int(launcher_pid or pid),
        "listener_pids": sorted({
            int(listener_pid)
            for listener_pid in listener_pids
            if int(listener_pid) > 0
        }),
        "port": int(port),
        "tool": key.tool,
        "executable": key.executable,
        "config_hash": key.config_hash,
        "created_at": time.time(),
    }
    if process_creation_times:
        data["process_creation_times"] = process_creation_times
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to write OpenCode serve marker %s: %s", path, exc)


def _remove_marker(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("Failed to remove OpenCode serve marker %s: %s", path, exc)


def _remove_marker_for_pid(path: Path, pid: int | None) -> None:
    marker = _read_marker(path)
    if marker is None:
        return
    if (
        pid is None
        or int(marker.get("pid") or 0) == int(pid)
        or int(marker.get("launcher_pid") or 0) == int(pid)
    ):
        _remove_marker(path)


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _windows_pid_is_running(pid)
    stat = _posix_process_stat(pid)
    if stat is not None:
        return stat[0] != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _windows_pid_is_running(pid: int) -> bool:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return False

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetLastError.restype = wintypes.DWORD

    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if not handle:
        return int(kernel32.GetLastError()) == 5
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return int(exit_code.value) == still_active
    finally:
        kernel32.CloseHandle(handle)


def _pid_cmdline(pid: int) -> list[str] | None:
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return [item.decode(errors="ignore") for item in raw.split(b"\0") if item]


def _marker_matches_serve_process(marker: dict[str, Any]) -> bool:
    if marker.get("owner") != _SERVE_MARKER_OWNER:
        return False
    pid = int(marker.get("pid") or 0)
    cmdline = _pid_cmdline(pid)
    if cmdline is None:
        return True
    lowered = [Path(item).name.lower() for item in cmdline] + [" ".join(cmdline).lower()]
    return any("serve" == item or item.endswith(" serve") or " serve " in item for item in lowered)


def _wait_process_exit(
    pid: int,
    timeout: float,
    wait: Callable[[float], None] | None = None,
    *,
    is_running: Callable[[], bool] | None = None,
) -> bool:
    running = is_running or (lambda: _pid_is_running(pid))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if wait is not None:
            try:
                wait(0.1)
                wait = None
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                wait = None
        if not running():
            return True
        time.sleep(0.1)
    if wait is not None:
        try:
            wait(0)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    return not running()


def _owned_process_group_id(pid: int) -> int | None:
    if sys.platform == "win32" or pid <= 0:
        return None
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None
    try:
        host_pgid = os.getpgrp()
    except OSError:
        host_pgid = None
    return pgid if pgid > 0 and pgid != host_pgid else None


def _process_group_is_running(pgid: int) -> bool:
    live_members = _posix_process_group_has_live_members(pgid)
    if live_members is not None:
        return live_members
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _terminate_process_tree(
    pid: int,
    timeout: float = _SERVE_STOP_TIMEOUT_SECONDS,
    wait: Callable[[float], None] | None = None,
    *,
    process_group_id: int | None = None,
    is_running: Callable[[], bool] | None = None,
) -> bool:
    if sys.platform == "win32":
        return _terminate_windows_process_tree(
            pid,
            timeout,
            wait=wait,
            is_running=is_running,
        )

    pgid = process_group_id or _owned_process_group_id(pid)
    use_process_group = pgid is not None
    running = is_running or (
        (lambda: _process_group_is_running(pgid))
        if pgid is not None
        else (lambda: _pid_is_running(pid))
    )
    if not running():
        return True

    def _send(sig: signal.Signals | int) -> None:
        if use_process_group and pgid is not None:
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)

    try:
        _send(signal.SIGTERM)
    except ProcessLookupError:
        return not running()
    except Exception as exc:
        logger.warning("Failed to terminate old OpenCode serve pid %s: %s", pid, exc)
        return False

    if _wait_process_exit(pid, timeout, wait=wait, is_running=running):
        return True
    try:
        _send(signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
    except ProcessLookupError:
        return not running()
    except Exception as exc:
        logger.warning("Failed to kill old OpenCode serve pid %s: %s", pid, exc)
        return False
    stopped = _wait_process_exit(pid, timeout, wait=wait, is_running=running)
    if not stopped:
        logger.warning(
            "OpenCode serve process tree pid %s is still running after forced termination",
            pid,
        )
    return stopped


def _terminate_windows_process_tree(
    pid: int,
    timeout: float,
    *,
    wait: Callable[[float], None] | None = None,
    is_running: Callable[[], bool] | None = None,
) -> bool:
    running = is_running or (lambda: _pid_is_running(pid))
    if not running():
        return True
    taskkill_succeeded = False
    try:
        completed = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        returncode = int(getattr(completed, "returncode", 0) or 0)
        taskkill_succeeded = returncode == 0
        if not taskkill_succeeded:
            raw_output = getattr(completed, "stdout", b"") or b""
            output = (
                raw_output.decode(errors="replace")
                if isinstance(raw_output, bytes)
                else str(raw_output)
            )
            logger.warning(
                "taskkill failed for OpenCode serve pid %s exit_code=%s output=%s",
                pid,
                returncode,
                _one_line_preview(output) or "<empty>",
            )
    except FileNotFoundError:
        logger.warning("taskkill is unavailable while stopping OpenCode serve pid %s", pid)
    except subprocess.TimeoutExpired:
        logger.warning("taskkill timed out while stopping OpenCode serve pid %s", pid)
    except Exception as exc:
        logger.warning("Failed to terminate old OpenCode serve process tree pid %s: %s", pid, exc)
    if not running():
        return True
    if taskkill_succeeded and _wait_process_exit(
        pid,
        timeout,
        wait=wait,
        is_running=running,
    ):
        return True
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return not running()
    except Exception as exc:
        logger.warning("Failed to kill old OpenCode serve process pid %s: %s", pid, exc)
    stopped = _wait_process_exit(
        pid,
        timeout,
        wait=wait,
        is_running=running,
    )
    if not stopped:
        logger.warning(
            "OpenCode serve process tree pid %s is still running after taskkill /T /F",
            pid,
        )
    return stopped


@dataclass(frozen=True)
class _OwnedServeProcess:
    """An exact Serve child started by this Python process."""

    owner_pid: int
    pid: int
    proc: Any
    marker_path: Path
    process_group_id: int | None = None


class _AdoptedServeProcess:
    """Popen-compatible handle for an owned listener surviving its launcher."""

    def __init__(self, pid: int) -> None:
        self.pid = int(pid)
        self.args = ["opencode", "serve"]
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if _pid_is_running(self.pid):
            return None
        self.returncode = 0
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        wait_timeout = _SERVE_STOP_TIMEOUT_SECONDS if timeout is None else max(0.0, float(timeout))
        if _wait_process_exit(self.pid, wait_timeout):
            self.returncode = 0
            return self.returncode
        raise subprocess.TimeoutExpired(self.args, wait_timeout)


_OWNED_SERVE_PROCESS_LOCK = threading.RLock()
_OWNED_SERVE_PROCESSES: dict[tuple[int, int], _OwnedServeProcess] = {}
_SERVE_ATEXIT_REGISTERED = False
_SERVE_SIGNAL_HANDLERS: dict[int, Any] = {}
_SERVE_SIGNAL_HOOK_OWNER_PID: int | None = None


def _current_owned_serve_key(pid: int) -> tuple[int, int]:
    return os.getpid(), int(pid)


def _restore_serve_signal_handlers_if_idle() -> None:
    """Restore host handlers after the last Serve owned by this process stops."""
    global _SERVE_SIGNAL_HOOK_OWNER_PID

    if threading.current_thread() is not threading.main_thread():
        return
    owner_pid = os.getpid()
    with _OWNED_SERVE_PROCESS_LOCK:
        if any(record.owner_pid == owner_pid for record in _OWNED_SERVE_PROCESSES.values()):
            return
        if _SERVE_SIGNAL_HOOK_OWNER_PID != owner_pid:
            return
        previous_handlers = dict(_SERVE_SIGNAL_HANDLERS)
        _SERVE_SIGNAL_HANDLERS.clear()
        _SERVE_SIGNAL_HOOK_OWNER_PID = None

    for signum, previous in previous_handlers.items():
        try:
            if signal.getsignal(signum) is _handle_owned_serve_signal:
                signal.signal(signum, previous)
        except (OSError, RuntimeError, ValueError):
            logger.debug("Failed to restore process signal handler %s", signum, exc_info=True)


def _marker_for_owned_serve_record(
    record: _OwnedServeProcess,
) -> dict[str, Any] | None:
    marker = _read_marker(record.marker_path)
    if marker is None or marker.get("owner") != _SERVE_MARKER_OWNER:
        return None
    marker_owner_pid = int(marker.get("agent_pid") or record.owner_pid)
    if marker_owner_pid != record.owner_pid:
        return None
    marker_pids = {
        int(marker.get("pid") or 0),
        int(marker.get("launcher_pid") or marker.get("pid") or 0),
    }
    return marker if record.pid in marker_pids else None


def _blocking_listener_pids_for_port(
    port: int,
    listener_pids: set[int],
) -> set[int]:
    """Return recorded listeners that still prevent a replacement Serve bind."""
    remaining = listener_pids & _listener_pids_for_port(port)
    if not remaining or sys.platform != "win32":
        return remaining
    if not _probe_serve_port(port).reusable:
        return remaining
    logger.warning(
        "Ignoring stale OpenCode listener-table pid(s)=%s on 127.0.0.1:%s; "
        "TCP connect failed and exclusive bind succeeded",
        ",".join(str(pid) for pid in sorted(remaining)),
        port,
    )
    return set()


def _wait_listener_pids_released(
    port: int,
    listener_pids: set[int],
    timeout: float = _SERVE_STOP_TIMEOUT_SECONDS,
) -> set[int]:
    if port <= 0 or not listener_pids:
        return set()
    deadline = time.monotonic() + timeout
    while True:
        remaining = _blocking_listener_pids_for_port(port, listener_pids)
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(0.1)


def _stop_owned_serve_record(
    record: _OwnedServeProcess,
    *,
    reason: str,
    port: int | None = None,
    listener_pids: set[int] | tuple[int, ...] = (),
) -> bool:
    """Stop one exact owned Serve tree and its verified detached listeners."""
    marker = _marker_for_owned_serve_record(record)
    effective_port = int(port or (marker or {}).get("port") or 0)
    known_listener_pids = {
        int(listener_pid)
        for listener_pid in listener_pids
        if int(listener_pid) > 0
    }
    if marker is not None:
        known_listener_pids.update(_marker_listener_pids(marker))
    if sys.platform == "win32" and marker is not None:
        return _stop_current_windows_serve_record(
            record,
            marker=marker,
            reason=reason,
            port=effective_port,
            listener_pids=known_listener_pids,
        )

    wait_method = getattr(record.proc, "wait", None)
    wait = (
        (lambda timeout, method=wait_method: method(timeout=timeout))
        if callable(wait_method)
        else None
    )
    logger.info(
        "Stopping OpenCode Serve process tree pid %s during %s",
        record.pid,
        reason,
    )
    terminate_kwargs: dict[str, Any] = {"wait": wait}
    if record.process_group_id is not None:
        terminate_kwargs["process_group_id"] = record.process_group_id
    termination_result = _terminate_process_tree(
        record.pid,
        **terminate_kwargs,
    )
    tree_stopped = termination_result is not False

    remaining_listener_pids: set[int] = set()
    if effective_port > 0 and known_listener_pids:
        remaining_listener_pids = _blocking_listener_pids_for_port(
            effective_port,
            known_listener_pids,
        )
        for listener_pid in sorted(remaining_listener_pids):
            logger.info(
                "Stopping owned OpenCode Serve listener pid %s during %s",
                listener_pid,
                reason,
            )
            _terminate_process_tree(
                listener_pid,
                is_running=(
                    (
                        lambda listener_pid=listener_pid: (
                            listener_pid
                            in _blocking_listener_pids_for_port(
                                effective_port,
                                {listener_pid},
                            )
                        )
                    )
                    if sys.platform == "win32"
                    else None
                ),
            )
        remaining_listener_pids = _wait_listener_pids_released(
            effective_port,
            known_listener_pids,
        )

    if not tree_stopped:
        tree_stopped = (
            not _process_group_is_running(record.process_group_id)
            if record.process_group_id is not None
            else not _pid_is_running(record.pid)
        )
    stopped = tree_stopped and not remaining_listener_pids
    if stopped:
        _remove_marker_for_pid(record.marker_path, record.pid)
    else:
        logger.warning(
            "OpenCode Serve cleanup incomplete pid=%s pgid=%s listener_pids=%s reason=%s; "
            "retaining ownership marker %s",
            record.pid,
            record.process_group_id or "",
            sorted(remaining_listener_pids),
            reason,
            record.marker_path,
        )
    return stopped


def _windows_marker_pid_states(
    marker: dict[str, Any],
    pids: set[int],
    *,
    listener_pids: set[int],
) -> dict[int, str]:
    """Classify marker PIDs without confusing a recycled PID with our Serve."""
    snapshot = _windows_process_parent_snapshot()
    recorded_creation_times = _marker_process_creation_times(marker)
    try:
        marker_created_at = float(marker.get("created_at") or 0)
    except (TypeError, ValueError):
        marker_created_at = 0.0
    states: dict[int, str] = {}
    for pid in sorted({int(item) for item in pids if int(item) > 0}):
        if pid == os.getpid():
            # A previous Serve can never be the current Agent interpreter.
            states[pid] = "foreign"
            continue
        if snapshot is not None and pid not in snapshot:
            states[pid] = "absent"
            continue

        recorded_creation_time = recorded_creation_times.get(pid)
        if recorded_creation_time is not None:
            current_creation_time = _windows_process_creation_time(pid)
            if current_creation_time is None:
                states[pid] = "unknown"
            elif current_creation_time == recorded_creation_time:
                states[pid] = "owned"
            else:
                states[pid] = "foreign"
            continue

        if marker_created_at > 0:
            current_creation_time = _windows_process_creation_time(pid)
            if current_creation_time is not None:
                # Windows FILETIME uses 100 ns ticks since 1601-01-01 UTC.
                process_created_at = (
                    current_creation_time / 10_000_000
                ) - 11_644_473_600
                if process_created_at > marker_created_at + 1.0:
                    states[pid] = "foreign"
                    continue

        if snapshot is not None or pid in listener_pids or _pid_is_running(pid):
            # Legacy markers have no creation token. Preserve their ownership
            # behavior while all newly written markers get PID-reuse protection.
            states[pid] = "owned-legacy"
        else:
            states[pid] = "absent"
    return states


def _stop_current_windows_serve_record(
    record: _OwnedServeProcess,
    *,
    marker: dict[str, Any],
    reason: str,
    port: int,
    listener_pids: set[int],
) -> bool:
    """Stop the live manager record using the marker's PID creation tokens."""
    tracked_pids = {record.pid, *listener_pids}
    killable_states = {"owned", "owned-legacy"}
    blocking_states = {*killable_states, "unknown"}

    def snapshot() -> tuple[set[int], dict[int, str]]:
        current_listeners = _listener_pids_for_port(port) if port > 0 else set()
        states = _windows_marker_pid_states(
            marker,
            tracked_pids,
            listener_pids=current_listeners,
        )
        return current_listeners, states

    def pid_still_blocks(pid: int, *, require_listener: bool = False) -> bool:
        current_listeners, states = snapshot()
        if require_listener and pid not in current_listeners:
            return False
        return states.get(pid, "unknown") in blocking_states

    current_listeners, pid_states = snapshot()
    primary_state = pid_states.get(record.pid, "unknown")
    if primary_state in killable_states:
        wait_method = getattr(record.proc, "wait", None)
        wait = (
            (lambda timeout, method=wait_method: method(timeout=timeout))
            if callable(wait_method)
            else None
        )
        logger.info(
            "Stopping OpenCode Serve process tree pid %s during %s pid_state=%s",
            record.pid,
            reason,
            primary_state,
        )
        _terminate_process_tree(
            record.pid,
            wait=wait,
            is_running=lambda: pid_still_blocks(record.pid),
        )
    elif primary_state == "unknown":
        logger.warning(
            "Refusing to terminate OpenCode Serve pid %s during %s because "
            "its marker creation-time identity could not be verified",
            record.pid,
            reason,
        )
    else:
        logger.info(
            "Skipping OpenCode Serve pid %s termination during %s pid_state=%s",
            record.pid,
            reason,
            primary_state,
        )

    current_listeners, pid_states = snapshot()
    listener_candidates = listener_pids & current_listeners
    for listener_pid in sorted(listener_candidates):
        listener_state = pid_states.get(listener_pid, "unknown")
        if listener_state not in killable_states:
            if listener_state == "unknown":
                logger.warning(
                    "Refusing to terminate OpenCode Serve listener pid %s during %s "
                    "because its marker creation-time identity could not be verified",
                    listener_pid,
                    reason,
                )
            continue
        logger.info(
            "Stopping owned OpenCode Serve listener pid %s during %s pid_state=%s",
            listener_pid,
            reason,
            listener_state,
        )
        _terminate_process_tree(
            listener_pid,
            is_running=lambda listener_pid=listener_pid: pid_still_blocks(
                listener_pid,
                require_listener=True,
            ),
        )

    current_listeners, pid_states = snapshot()
    primary_state = pid_states.get(record.pid, "unknown")
    # The post-termination creation-time classification is authoritative. A
    # non-zero taskkill exit can race with normal process exit, while a reused
    # foreign PID must never keep this marker alive or become a kill target.
    tree_stopped = primary_state in {"absent", "foreign"}
    remaining_listener_pids = {
        pid
        for pid in listener_pids & current_listeners
        if pid_states.get(pid, "unknown") in blocking_states
    }
    stopped = tree_stopped and not remaining_listener_pids
    if stopped:
        _remove_marker_for_pid(record.marker_path, record.pid)
    else:
        state_note = ",".join(
            f"{pid}:{pid_states.get(pid, 'unknown')}"
            for pid in sorted(tracked_pids)
        )
        logger.warning(
            "OpenCode Serve cleanup incomplete pid=%s listener_pids=%s reason=%s "
            "pid_states=%s; retaining ownership marker %s",
            record.pid,
            sorted(remaining_listener_pids),
            reason,
            state_note or "none",
            record.marker_path,
        )
    return stopped


def _stop_previous_windows_serve_marker(
    marker: dict[str, Any],
    marker_path: Path,
    fallback_port: int,
) -> _PreviousServeCleanupResult:
    """Recover one previous Windows Serve marker before starting a replacement."""
    marker_port = int(marker.get("port") or fallback_port)
    pid = int(marker.get("pid") or 0)
    launcher_pid = int(marker.get("launcher_pid") or pid)
    marker_agent_pid = int(marker.get("agent_pid") or 0)
    known_listener_pids = _marker_listener_pids(marker)

    def current_state() -> tuple[set[int], dict[int, str]]:
        current_listeners = (
            _listener_pids_for_port(marker_port)
            if marker_port > 0
            else set()
        )
        tracked_pids = {
            item
            for item in (
                marker_agent_pid,
                pid,
                launcher_pid,
                *known_listener_pids,
            )
            if item > 0
        }
        return current_listeners, _windows_marker_pid_states(
            marker,
            tracked_pids,
            listener_pids=current_listeners,
        )

    current_listeners, pid_states = current_state()
    active_states = {"owned", "owned-legacy", "unknown"}
    if (
        marker_agent_pid > 0
        and marker_agent_pid != os.getpid()
        and pid_states.get(marker_agent_pid) in active_states
    ):
        logger.info(
            "Leaving OpenCode serve marker owned by live Agent pid %s unchanged",
            marker_agent_pid,
        )
        return _PreviousServeCleanupResult()

    serve_pids = {
        item
        for item in (pid, launcher_pid, *known_listener_pids)
        if item > 0
    }

    def retire_marker(reason: str) -> _PreviousServeCleanupResult:
        probe = _probe_serve_port(marker_port) if marker_port > 0 else None
        avoided_ports = (
            (marker_port,)
            if probe is not None and not probe.reusable
            else ()
        )
        state_note = ",".join(
            f"{item}:{pid_states.get(item, 'unknown')}"
            for item in sorted(serve_pids)
        )
        detail = (
            f"{reason}; tcp_connectable={probe.connectable if probe else False} "
            f"bind_error={probe.bind_error if probe else ''} "
            f"pid_states={state_note or 'none'}"
        )
        logger.warning(
            "Retiring stale OpenCode Serve marker port=%s avoided=%s %s",
            marker_port,
            bool(avoided_ports),
            detail,
        )
        _remove_marker(marker_path)
        return _PreviousServeCleanupResult(
            avoided_ports=avoided_ports,
            detail=detail,
        )

    if not serve_pids or all(
        pid_states.get(item) in {"absent", "foreign"}
        for item in serve_pids
    ):
        return retire_marker("recorded Serve process no longer exists")

    tree_stopped = True
    primary_pids = {
        item
        for item in (pid, launcher_pid)
        if item > 0 and pid_states.get(item) in {"owned", "owned-legacy"}
    }
    for primary_pid in sorted(primary_pids):
        logger.info(
            "Stopping previous Agent-owned %s serve pid %s on 127.0.0.1:%s",
            marker.get("tool") or "opencode",
            primary_pid,
            marker_port,
        )
        if not _terminate_process_tree(primary_pid):
            tree_stopped = False

    listener_candidates = known_listener_pids | (
        {pid, launcher_pid} & current_listeners
    )
    allowed_listener_pids = {
        listener_pid
        for listener_pid in listener_candidates
        if pid_states.get(listener_pid) in {"owned", "owned-legacy"}
    }
    reclaim_result: _PortReclaimResult | None = None
    if marker_port > 0 and allowed_listener_pids:
        reclaim_result = _reclaim_serve_port(
            marker_port,
            reason="previous Agent-owned Serve marker",
            allowed_pids=allowed_listener_pids,
        )

    current_listeners, pid_states = current_state()
    if not serve_pids or all(
        pid_states.get(item) in {"absent", "foreign"}
        for item in serve_pids
    ):
        return retire_marker("recorded Serve process exited during cleanup")

    probe = _probe_serve_port(marker_port) if marker_port > 0 else None
    active_primary_pids = {
        item
        for item in (pid, launcher_pid)
        if item > 0 and pid_states.get(item) in active_states
    }
    remaining_listener_pids = {
        item
        for item in serve_pids & current_listeners
        if pid_states.get(item) in active_states
    }
    if (
        not active_primary_pids
        and reclaim_result is not None
        and reclaim_result.released
        and probe is not None
        and probe.reusable
    ):
        return retire_marker("listener-table row is stale and port is reusable")

    state_note = ",".join(
        f"{item}:{pid_states.get(item, 'unknown')}"
        for item in sorted(serve_pids)
    )
    reclaim_note = (
        f"; reclaim={reclaim_result.detail}"
        if reclaim_result is not None
        else ""
    )
    diagnostics = (
        f"; tcp_connectable={probe.connectable if probe else False} "
        f"bind_error={probe.bind_error if probe else ''} "
        f"pid_states={state_note or 'none'}"
        f"{reclaim_note}"
    )
    if active_primary_pids or not tree_stopped:
        raise RuntimeError(
            "Previous Agent-owned OpenCode Serve process tree did not stop; "
            f"pid={pid} listener_pid(s)="
            f"{','.join(str(item) for item in sorted(remaining_listener_pids))} "
            f"port={marker_port} ownership marker was retained"
            f"{diagnostics}"
        )
    raise RuntimeError(
        "Previous Agent-owned OpenCode Serve listener did not stop; "
        f"pid(s)={','.join(str(item) for item in sorted(remaining_listener_pids))} "
        f"port={marker_port} ownership marker was retained"
        f"{diagnostics}"
    )


def _cleanup_owned_serve_processes(reason: str = "process exit") -> None:
    """Synchronously terminate every Serve child started by this process.

    The captured process group remains the shutdown target after its launcher
    exits. Detached listeners are targeted only when their PIDs were recorded
    and ownership-checked during startup.
    """
    owner_pid = os.getpid()
    with _OWNED_SERVE_PROCESS_LOCK:
        owned = [
            record
            for record in _OWNED_SERVE_PROCESSES.values()
            if record.owner_pid == owner_pid
        ]
        for record in owned:
            _OWNED_SERVE_PROCESSES.pop((record.owner_pid, record.pid), None)

    failed: list[_OwnedServeProcess] = []
    for record in owned:
        try:
            if not _stop_owned_serve_record(record, reason=reason):
                failed.append(record)
        except BaseException:
            # Signal and interpreter-exit cleanup must remain best effort and
            # must never suppress the host process's original exit semantics.
            logger.warning(
                "Failed to stop OpenCode Serve process tree pid %s during %s",
                record.pid,
                reason,
                exc_info=True,
            )
            failed.append(record)

    if failed:
        with _OWNED_SERVE_PROCESS_LOCK:
            for record in failed:
                _OWNED_SERVE_PROCESSES.setdefault(
                    (record.owner_pid, record.pid),
                    record,
                )

    _restore_serve_signal_handlers_if_idle()


def _delegate_process_signal(signum: int, frame: Any, previous: Any) -> None:
    if previous == signal.SIG_IGN:
        return
    if previous in (None, signal.SIG_DFL) or previous is _handle_owned_serve_signal:
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
        return
    if callable(previous):
        previous(signum, frame)
        # asyncio.run() replaces the default SIGINT handler with Runner's
        # first-interrupt cancellation callback. Calling that callback from a
        # chained Python signal handler marks the task cancelled, but does not
        # reliably wake every selector implementation. Raising here preserves
        # Ctrl-C's exit semantics; Runner.close() still cancels and drains the
        # remaining tasks so their finally blocks execute.
        callback = getattr(previous, "func", None)
        callback_owner = getattr(callback, "__self__", None)
        if (
            signum == signal.SIGINT
            and getattr(callback, "__name__", "") == "_on_sigint"
            and type(callback_owner).__module__ == "asyncio.runners"
        ):
            raise KeyboardInterrupt


def _handle_owned_serve_signal(signum: int, frame: Any) -> None:
    with _OWNED_SERVE_PROCESS_LOCK:
        previous = _SERVE_SIGNAL_HANDLERS.get(signum, signal.SIG_DFL)
    _cleanup_owned_serve_processes(f"signal {signum}")
    _delegate_process_signal(signum, frame, previous)


def _install_serve_exit_hooks() -> None:
    """Install process-exit cleanup while preserving the host signal handlers."""
    global _SERVE_ATEXIT_REGISTERED, _SERVE_SIGNAL_HOOK_OWNER_PID

    with _OWNED_SERVE_PROCESS_LOCK:
        if not _SERVE_ATEXIT_REGISTERED:
            atexit.register(_cleanup_owned_serve_processes, "interpreter exit")
            _SERVE_ATEXIT_REGISTERED = True

    # Python only permits signal registration from the main thread. Normal
    # interpreter exit is still covered by atexit when a caller starts Serve
    # from another thread.
    if threading.current_thread() is not threading.main_thread():
        return

    owner_pid = os.getpid()
    with _OWNED_SERVE_PROCESS_LOCK:
        if _SERVE_SIGNAL_HOOK_OWNER_PID == owner_pid:
            return
        _SERVE_SIGNAL_HOOK_OWNER_PID = owner_pid

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous = signal.getsignal(signum)
            if previous is _handle_owned_serve_signal:
                continue
            with _OWNED_SERVE_PROCESS_LOCK:
                _SERVE_SIGNAL_HANDLERS[int(signum)] = previous
            signal.signal(signum, _handle_owned_serve_signal)
        except (OSError, RuntimeError, ValueError):
            logger.debug("Failed to install process signal handler %s", signum, exc_info=True)


def _register_owned_serve_process(
    proc: Any,
    marker_path: Path,
) -> _OwnedServeProcess | None:
    """Register a freshly spawned Serve child for process-exit cleanup."""
    pid = int(getattr(proc, "pid", 0) or 0)
    if pid <= 0:
        return None
    owner_pid = os.getpid()
    record = _OwnedServeProcess(
        owner_pid=owner_pid,
        pid=pid,
        proc=proc,
        marker_path=marker_path,
        process_group_id=_owned_process_group_id(pid),
    )
    with _OWNED_SERVE_PROCESS_LOCK:
        _OWNED_SERVE_PROCESSES[(owner_pid, pid)] = record
    _install_serve_exit_hooks()
    return record


def _owned_serve_process(pid: int | None) -> _OwnedServeProcess | None:
    if pid is None:
        return None
    try:
        normalized_pid = int(pid)
    except (TypeError, ValueError):
        return None
    with _OWNED_SERVE_PROCESS_LOCK:
        return _OWNED_SERVE_PROCESSES.get(
            _current_owned_serve_key(normalized_pid)
        )


def _current_process_owned_serve_pids() -> tuple[int, ...]:
    owner_pid = os.getpid()
    with _OWNED_SERVE_PROCESS_LOCK:
        pids = [
            record.pid
            for record in _OWNED_SERVE_PROCESSES.values()
            if record.owner_pid == owner_pid
        ]
    return tuple(sorted(pids))


def _unregister_owned_serve_process(pid: int | None) -> None:
    if pid is None:
        return
    try:
        normalized_pid = int(pid)
    except (TypeError, ValueError):
        return
    with _OWNED_SERVE_PROCESS_LOCK:
        _OWNED_SERVE_PROCESSES.pop(_current_owned_serve_key(normalized_pid), None)
    _restore_serve_signal_handlers_if_idle()


def _resolve_executable(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    if Path(name).is_file():
        return str(Path(name).resolve())
    raise FileNotFoundError(f"OpenCode executable '{name}' not found in PATH")


def _session_id(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("id", "sessionID", "session_id"):
            value = data.get(key)
            if value:
                return str(value)
    raise RuntimeError(f"OpenCode serve did not return a session id: {data!r}")


def _config_hash(config_content: str | None) -> str:
    content = (config_content or "").strip()
    try:
        parsed = json.loads(content or "{}")
        if isinstance(parsed, dict):
            parsed = _with_managed_runtime_fields(parsed)
        content = json.dumps(
            parsed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except Exception:
        pass
    fingerprint = (
        f"{content}"
        f"\0file-write-plugin={_FILE_WRITE_PLUGIN_HASH}"
        f"\0knowledge-project-plugin={_KNOWLEDGE_PROJECT_PLUGIN_HASH}"
    )
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def _normalized_env_overrides(env_overrides: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not env_overrides:
        return ()
    normalized: list[tuple[str, str]] = []
    for key, value in env_overrides.items():
        name = str(key).strip()
        if not name:
            continue
        if name.lower() in _SERVE_PROXY_ENV_NAMES:
            continue
        normalized.append((name, str(value)))
    return tuple(sorted(normalized))


def _append_no_proxy_env_value(existing: str | None, configured: str) -> str:
    """Append a no-proxy override to one same-case inherited variable."""
    entries: list[str] = []
    seen: set[str] = set()
    for value in (existing or "", configured):
        for item in str(value or "").split(","):
            normalized = item.strip()
            if normalized and normalized not in seen:
                entries.append(normalized)
                seen.add(normalized)
    return ",".join(entries)


def _env_hash(env_overrides: tuple[tuple[str, str], ...]) -> str:
    if not env_overrides:
        return ""
    return hashlib.sha256(
        json.dumps(env_overrides, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _extract_text(value: Any) -> list[str]:
    lines: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            lines.append(text)
        return lines
    if isinstance(value, list):
        for item in value:
            lines.extend(_extract_text(item))
        return lines
    if isinstance(value, dict):
        part_type = value.get("type")
        if part_type == "text" and isinstance(value.get("text"), str):
            text = value["text"].strip()
            if text:
                lines.append(text)
        state = value.get("state")
        if isinstance(state, dict):
            for key in ("output", "error", "title"):
                if isinstance(state.get(key), str) and state[key].strip():
                    lines.append(state[key].strip())
        for key in ("parts", "content"):
            if key in value:
                lines.extend(_extract_text(value[key]))
    return lines


def _extract_response_text(value: Any) -> list[str]:
    """Extract assistant text parts without exposing tool state/output bodies."""
    lines: list[str] = []
    if isinstance(value, str):
        text = value.strip()
        if text:
            lines.append(text)
        return lines
    if isinstance(value, list):
        for item in value:
            lines.extend(_extract_response_text(item))
        return lines
    if not isinstance(value, dict):
        return lines
    part_type = value.get("type")
    if part_type == "text" and isinstance(value.get("text"), str):
        text = value["text"].strip()
        if text:
            lines.append(text)
        return lines
    if part_type:
        return lines
    for key in ("parts", "content"):
        if key in value:
            lines.extend(_extract_response_text(value[key]))
    return lines


def _response_model(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    info = value.get("info")
    if not isinstance(info, dict):
        return ""
    provider_id = info.get("providerID")
    model_id = info.get("modelID")
    if not isinstance(provider_id, str) or not isinstance(model_id, str):
        return ""
    provider_id = provider_id.strip()
    model_id = model_id.strip()
    if not provider_id or not model_id:
        return ""
    if model_id.startswith(f"{provider_id}/"):
        return model_id
    return f"{provider_id}/{model_id}"


def _response_message_id(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("info"), dict):
        return ""
    return str(value["info"].get("id") or "").strip()


def _message_token_entries(
    session_id: str,
    message: object,
    fallback_model: str,
) -> dict[tuple[str, str, str], tuple[str, TokenCounters]]:
    if not isinstance(message, dict):
        return {}
    info = message.get("info")
    if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
        return {}
    message_id = str(info.get("id") or "").strip()
    if not message_id:
        return {}
    model = _response_model(message) or fallback_model or "unknown"
    entries: dict[tuple[str, str, str], tuple[str, TokenCounters]] = {}
    parts = message.get("parts")
    if isinstance(parts, list):
        for index, part in enumerate(parts):
            if not isinstance(part, dict) or part.get("type") != "step-finish":
                continue
            counters = parse_token_counters(part.get("tokens"))
            if counters is None:
                continue
            part_id = str(part.get("id") or f"step:{index}")
            entries[(session_id, message_id, part_id)] = (model, counters)
    if entries:
        return entries
    counters = parse_token_counters(info.get("tokens"))
    if counters is not None:
        entries[(session_id, message_id, "message")] = (model, counters)
    return entries


async def _session_tree_token_entries(
    client: httpx.AsyncClient,
    root_session_id: str,
    params: dict[str, str],
    headers: dict[str, str],
    fallback_model: str,
    *,
    deadline: OperationDeadline | None = None,
) -> tuple[dict[tuple[str, str, str], tuple[str, TokenCounters]], bool]:
    entries: dict[tuple[str, str, str], tuple[str, TokenCounters]] = {}
    complete = True
    pending = [root_session_id]
    visited: set[str] = set()
    deadline = deadline or OperationDeadline(_SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS)
    while pending:
        current = pending.pop()
        if not current or current in visited:
            continue
        visited.add(current)
        try:
            response = await deadline.wait(client.get(
                f"/session/{current}/message",
                params=params,
                headers=headers,
            ), phase="token_messages")
            response.raise_for_status()
            messages = response.json()
            if isinstance(messages, list):
                for message in messages:
                    entries.update(
                        _message_token_entries(current, message, fallback_model)
                    )
            else:
                complete = False
        except asyncio.TimeoutError:
            return entries, False
        except Exception as exc:
            complete = False
            logger.debug("Failed to collect OpenCode messages for %s: %s", current, exc)
        try:
            response = await deadline.wait(client.get(
                f"/session/{current}/children",
                params=params,
                headers=headers,
            ), phase="token_children")
            response.raise_for_status()
            children = response.json()
            if isinstance(children, list):
                for child in children:
                    if not isinstance(child, dict):
                        continue
                    child_id = str(child.get("id") or "").strip()
                    if child_id and child_id not in visited:
                        pending.append(child_id)
            else:
                complete = False
        except asyncio.TimeoutError:
            return entries, False
        except Exception as exc:
            complete = False
            logger.debug("Failed to collect OpenCode child sessions for %s: %s", current, exc)
    return entries, complete


def _token_usage_delta(
    before: dict[tuple[str, str, str], tuple[str, TokenCounters]],
    after: dict[tuple[str, str, str], tuple[str, TokenCounters]],
    *,
    complete: bool,
) -> OpenCodeTokenUsage:
    models: dict[str, TokenCounters] = {}
    for key, (model, counters) in after.items():
        if key in before:
            continue
        normalized_model = model or "unknown"
        models[normalized_model] = models.get(normalized_model, TokenCounters()) + counters
    return token_usage_from_models(models, complete=complete)


def _normalize_tool_selector(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _scan_mcp_runtime_name(configured_name: object) -> str:
    """Keep the configured MCP name unchanged in OpenCode's tool prefix."""
    name = str(configured_name or "").strip()
    if not name:
        raise ValueError("Scan code graph MCP name is empty")
    return name


def _scan_mcp_lease_identity(
    scan_id: object,
    mcp_name: object,
    fingerprint: object,
) -> str:
    """Build an internal identity without leaking it into MCP tool names."""
    normalized_scan_id = str(scan_id or "").strip()
    if not normalized_scan_id:
        raise ValueError("Scan code graph MCP requires a scan_id")
    payload = json.dumps(
        [
            normalized_scan_id,
            str(mcp_name or ""),
            str(fingerprint or ""),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _scan_mcp_runtime_spec(scan_id: object, raw: object) -> dict[str, Any]:
    if not str(scan_id or "").strip():
        raise ValueError("Scan code graph MCP requires a scan_id")
    if not isinstance(raw, dict):
        raise ValueError("Scan code graph MCP config must be an object")
    if not bool(raw.get("enabled")):
        raise ValueError("Scan code graph MCP is disabled")
    configured_name = str(raw.get("name") or "").strip()
    if not configured_name:
        raise ValueError("Scan code graph MCP name is empty")
    transport = str(raw.get("transport") or "local").strip().lower()
    raw_timeout_seconds = raw.get("timeout_seconds")
    try:
        timeout_seconds = int(
            300 if raw_timeout_seconds is None else raw_timeout_seconds
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Scan code graph MCP timeout is invalid") from exc
    if timeout_seconds < 1:
        raise ValueError("Scan code graph MCP timeout must be positive")
    # OpenCode's native MCP timeout is expressed in milliseconds and is used
    # for connection, tool discovery, and individual tool calls.
    timeout_milliseconds = timeout_seconds * 1000
    local = raw.get("local") if isinstance(raw.get("local"), dict) else {}
    remote = raw.get("remote") if isinstance(raw.get("remote"), dict) else {}
    runtime_config: dict[str, Any]
    if transport == "local":
        executable = str(local.get("executable") or "").strip()
        if not executable:
            raise ValueError("Scan code graph MCP executable is empty")
        runtime_config = {
            "type": "local",
            "command": [
                executable,
                *[str(item) for item in (local.get("args") or [])],
            ],
            "enabled": True,
            "timeout": timeout_milliseconds,
        }
        environment = local.get("environment")
        if isinstance(environment, dict) and environment:
            runtime_config["environment"] = {
                str(key): str(value)
                for key, value in environment.items()
            }
    elif transport == "remote":
        url = str(remote.get("url") or "").strip()
        if not url:
            raise ValueError("Scan code graph MCP remote URL is empty")
        runtime_config = {
            "type": "remote",
            "url": url,
            "enabled": True,
            "timeout": timeout_milliseconds,
            "oauth": False,
        }
        headers = remote.get("headers")
        if isinstance(headers, dict) and headers:
            runtime_config["headers"] = {
                str(key): str(value)
                for key, value in headers.items()
            }
    else:
        raise ValueError(f"Unsupported scan code graph MCP transport: {transport}")

    fingerprint_payload = {
        "transport": transport,
        "timeout_seconds": timeout_seconds,
        "config": runtime_config,
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "target": "scan_code_graph",
        "enabled": True,
        "name": _scan_mcp_runtime_name(configured_name),
        "fingerprint": fingerprint,
        "config": runtime_config,
        "error": "",
    }


def _sanitize_opencode_mcp_component(value: object) -> str:
    """Match OpenCode's MCP tool-name sanitizer."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(value or "").strip())


def _opencode_mcp_tool_prefixes(mcp_name: object) -> tuple[str, ...]:
    name = _sanitize_opencode_mcp_component(mcp_name)
    if not name:
        return ()
    return (
        f"{name}_",
        f"mcp__{name}__",
        f"mcp--{name}--",
    )


def _opencode_mcp_tool_ids(
    mcp_name: object,
    raw_tool_name: object,
) -> tuple[str, ...]:
    tool_name = _sanitize_opencode_mcp_component(raw_tool_name)
    if not tool_name:
        return ()
    return tuple(
        f"{prefix}{tool_name}"
        for prefix in _opencode_mcp_tool_prefixes(mcp_name)
    )


def _tool_belongs_to_mcp(tool_id: object, mcp_name: object) -> bool:
    tool = str(tool_id or "").strip().casefold()
    return any(
        tool.startswith(prefix.casefold())
        for prefix in _opencode_mcp_tool_prefixes(mcp_name)
    )


def _tool_matches_mcp_tool(
    tool_id: object,
    mcp_name: object,
    raw_tool_name: object,
) -> bool:
    tool = str(tool_id or "").strip().casefold()
    if tool in {
        candidate.casefold()
        for candidate in _opencode_mcp_tool_ids(mcp_name, raw_tool_name)
    }:
        return True
    if not _tool_belongs_to_mcp(tool_id, mcp_name):
        return False
    normalized_id = _normalize_tool_selector(tool_id)
    normalized_mcp = _normalize_tool_selector(mcp_name)
    normalized_tool = _normalize_tool_selector(raw_tool_name)
    if not normalized_mcp or not normalized_tool:
        return False
    return normalized_id in {
        f"{normalized_mcp}{normalized_tool}",
        f"mcp{normalized_mcp}{normalized_tool}",
    }


def _is_source_graph_tool(
    tool_id: object,
    source_mcp_names: set[str] | tuple[str, ...] = (),
    protected_mcp_names: set[str] | tuple[str, ...] = (),
) -> bool:
    tool = str(tool_id or "").strip().casefold()
    if any(_tool_belongs_to_mcp(tool_id, name) for name in protected_mcp_names):
        return False
    if _LEGACY_SCAN_CODE_GRAPH_MCP_PREFIX in tool:
        return True
    return any(
        _tool_belongs_to_mcp(tool_id, name)
        for name in source_mcp_names
    )


def _apply_source_graph_overrides(
    tool_ids: list[str],
    overrides: dict[str, bool],
    selected_mcp_name: str | None,
    *,
    source_mcp_names: set[str] | tuple[str, ...] = (),
    protected_mcp_names: set[str] | tuple[str, ...] = (),
    allow_undiscovered: bool = False,
) -> tuple[dict[str, bool], bool]:
    """Isolate source graph tools without changing unrelated MCP tools."""
    if selected_mcp_name is None:
        return overrides, True
    known_names = set(source_mcp_names)
    if selected_mcp_name:
        known_names.add(selected_mcp_name)
    source_ids = [
        tool_id
        for tool_id in tool_ids
        if _is_source_graph_tool(
            tool_id,
            known_names,
            protected_mcp_names,
        )
    ]
    for tool_id in source_ids:
        overrides[tool_id] = False
    if not selected_mcp_name:
        return overrides, False
    selected_ids = [
        tool_id
        for tool_id in source_ids
        if _tool_belongs_to_mcp(tool_id, selected_mcp_name)
    ]
    for tool_id in selected_ids:
        overrides[tool_id] = True
    return overrides, bool(selected_ids) or (allow_undiscovered and not source_ids)


def _mcp_tool_overrides(
    tool_ids: list[str],
    requested: list[str] | tuple[str, ...] | None,
    disabled: list[str] | tuple[str, ...] | None = None,
) -> dict[str, bool]:
    """Build message-level MCP overrides while leaving built-in tools untouched."""
    mcp_ids = [tool_id for tool_id in tool_ids if _tool_source(tool_id) == "mcp"]
    if requested is None:
        overrides = {tool_id: True for tool_id in tool_ids}
    else:
        overrides = {tool_id: False for tool_id in mcp_ids}
    unresolved: list[str] = []
    for raw_selector in requested or ():
        selector = str(raw_selector or "").strip()
        normalized = _normalize_tool_selector(selector)
        matches = [
            tool_id
            for tool_id in mcp_ids
            if selector == tool_id
            or (normalized and normalized == _normalize_tool_selector(tool_id))
            or (
                normalized
                and normalized in _normalize_tool_selector(tool_id)
                and _normalize_tool_selector(selector.rsplit("/", 1)[-1])
                in _normalize_tool_selector(tool_id)
            )
        ]
        if not matches:
            unresolved.append(selector)
            continue
        for tool_id in matches:
            overrides[tool_id] = True
    for raw_selector in disabled or ():
        selector = str(raw_selector or "").strip()
        normalized = _normalize_tool_selector(selector)
        for tool_id in mcp_ids:
            if selector == tool_id or (normalized and normalized in _normalize_tool_selector(tool_id)):
                overrides[tool_id] = False
    if unresolved:
        raise ValueError(
            "Unknown OpenCode MCP tool selector(s): " + ", ".join(unresolved)
        )
    return overrides


def _one_line_preview(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated {len(text) - limit} chars]"


def _summarize_event_value(value: object, *, max_string: int = 180) -> object:
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>"
                if _SENSITIVE_EVENT_KEY_RE.search(str(key))
                else _summarize_event_value(item, max_string=max_string)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_summarize_event_value(item, max_string=max_string) for item in value]
    if isinstance(value, str):
        preview = _one_line_preview(value, max_string)
        if len(value) > max_string or "\n" in value:
            return f"<chars={len(value)} preview={preview}>"
        return preview
    return value


def _json_one_line(value: object, limit: int = _SERVE_EVENT_PREVIEW_LIMIT) -> str:
    value = _summarize_event_value(value)
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        text = str(value)
    return _one_line_preview(text, limit)


def _tool_content_summary(value: object) -> str:
    if not isinstance(value, list):
        return "content=0"
    text_chars = 0
    files = 0
    for item in value:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            text_chars += len(str(item.get("text") or ""))
        elif item.get("type") == "file":
            files += 1
    return f"content_items={len(value)} text_chars={text_chars} files={files}"


def _tool_state_summary(value: object) -> str:
    if not isinstance(value, dict):
        return "output_chars=0 attachments=0"
    output = str(value.get("output") or "")
    attachments = value.get("attachments")
    attachment_count = len(attachments) if isinstance(attachments, list) else 0
    parts = [f"output_chars={len(output)}", f"attachments={attachment_count}"]
    timing = value.get("time")
    if isinstance(timing, dict):
        start = timing.get("start")
        end = timing.get("end")
        if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
            parts.append(f"duration_ms={round(end - start)}")
    return " ".join(parts)


def _error_summary(value: object) -> str:
    if isinstance(value, dict):
        message = _one_line_preview(value.get("message") or "")
        if message:
            return message
        name = _one_line_preview(value.get("name") or "")
        data = value.get("data")
        if isinstance(data, dict):
            nested_message = _one_line_preview(data.get("message") or "")
            if nested_message:
                return f"{name}: {nested_message}" if name else nested_message
        nested_error = value.get("error")
        if nested_error:
            nested_summary = _error_summary(nested_error)
            if nested_summary:
                return nested_summary
        if name:
            return name
        return _json_one_line(value)
    return _one_line_preview(value)


def _embedded_json_objects(value: str) -> list[object]:
    """Decode bounded JSON objects embedded in wrapper validation messages."""
    text = str(value or "")[:20_000]
    decoder = json.JSONDecoder()
    decoded: list[object] = []
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            item, _ = decoder.raw_decode(text[index:])
        except (TypeError, ValueError):
            continue
        decoded.append(item)
        if len(decoded) >= 12:
            break
    return decoded


def _provider_quota_error(value: object) -> OpenCodeProviderQuotaError | None:
    """Extract an allowlisted quota signal from nested OpenCode/Provider errors."""
    queue: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    candidates: list[dict[str, object]] = []
    while queue:
        current, depth = queue.pop(0)
        if depth > 7:
            continue
        if isinstance(current, (dict, list)):
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
        if isinstance(current, dict):
            candidates.append(current)
            for key, nested in current.items():
                if key in {
                    "error",
                    "data",
                    "cause",
                    "message",
                    "error_msg",
                    "details",
                    "value",
                }:
                    queue.append((nested, depth + 1))
        elif isinstance(current, list):
            queue.extend((item, depth + 1) for item in current[:20])
        elif isinstance(current, str):
            queue.extend(
                (item, depth + 1)
                for item in _embedded_json_objects(current)
            )

    for candidate in candidates:
        error_code = str(candidate.get("error_code") or "").strip()
        quota_type = str(candidate.get("type") or "").strip().upper()
        message = str(
            candidate.get("message")
            or candidate.get("error_msg")
            or ""
        ).strip()
        normalized_message = message.casefold()
        is_rate_limit_code = error_code.endswith(".429") or error_code == "429"
        is_quota_message = (
            "quota" in normalized_message
            or "rate limit" in normalized_message
            or quota_type in {"RPM", "TPM"}
        )
        if not (is_rate_limit_code and is_quota_message):
            continue
        detail_candidate = next(
            (
                item
                for item in candidates
                if str(item.get("type") or "").strip().upper() in {"RPM", "TPM"}
            ),
            {},
        )
        if not quota_type:
            quota_type = str(detail_candidate.get("type") or "").strip().upper()
        retry_after = candidate.get("retry_after")
        retry_after_seconds: float | None = None
        try:
            parsed_retry_after = float(retry_after)
        except (TypeError, ValueError):
            parsed_retry_after = -1
        if parsed_retry_after > 0:
            retry_after_seconds = parsed_retry_after
        return OpenCodeProviderQuotaError(
            error_code=error_code,
            quota_type=quota_type,
            identity=str(
                candidate.get("identity")
                or detail_candidate.get("identity")
                or ""
            ).strip(),
            retry_after_seconds=retry_after_seconds,
        )
    return None


def _assistant_message_error(value: object) -> object | None:
    """Return an OpenCode assistant error carried by a successful HTTP response."""
    if not isinstance(value, dict):
        return None
    info = value.get("info")
    if not isinstance(info, dict):
        return None
    return info.get("error")


def _assistant_error_affects_model_health(value: object) -> bool:
    """Exclude task-quality and explicit-abort errors from model health."""
    if not isinstance(value, dict):
        return True
    return str(value.get("name") or "") not in {
        "ContextOverflowError",
        "MessageAbortedError",
        "MessageOutputLengthError",
        "StructuredOutputError",
    }


def _tool_source(tool_name: object) -> str:
    normalized = str(tool_name or "").lower().replace("_", "-")
    if (
        _LEGACY_SCAN_CODE_GRAPH_MCP_PREFIX in normalized
        or normalized.startswith("mcp--")
    ):
        return "mcp"
    return "builtin"


def _is_skill_tool(tool_name: object) -> bool:
    normalized = str(tool_name or "").strip().casefold().replace("-", "_")
    return normalized == "skill"


def _skill_name(input_value: object) -> str:
    if not isinstance(input_value, dict):
        return "unknown"
    return _one_line_preview(
        input_value.get("name")
        or input_value.get("skill")
        or input_value.get("skill_name")
        or "unknown"
    )


def _tool_input_value(input_value: dict[str, Any], *keys: str) -> object | None:
    for key in keys:
        if key in input_value and input_value[key] is not None:
            return input_value[key]
    return None


def _tool_detail_value(value: object, *, full_string: bool = False) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if full_string:
        # Keep the complete command while escaping physical line breaks so the
        # shared task formatter can still emit exactly one console line.
        return json.dumps(text, ensure_ascii=False)
    preview = _one_line_preview(text)
    if not preview:
        return ""
    if any(char.isspace() for char in preview):
        return json.dumps(preview, ensure_ascii=False)
    return preview


def _tool_call_details(tool_name: object, input_value: object) -> str:
    if not isinstance(input_value, dict):
        return ""
    normalized = str(tool_name or "").strip().casefold().replace("-", "_")
    details: list[str] = []

    def add(
        label: str,
        *keys: str,
        full_string: bool = False,
    ) -> None:
        value = _tool_input_value(input_value, *keys)
        if value is None:
            return
        formatted = _tool_detail_value(value, full_string=full_string)
        if formatted:
            details.append(f"{label}={formatted}")

    def add_chars(label: str, *keys: str) -> None:
        value = _tool_input_value(input_value, *keys)
        if isinstance(value, str):
            details.append(f"{label}={len(value)}")

    if normalized == "read":
        add("path", "filePath", "file_path", "path")
        add("offset", "offset")
        add("limit", "limit")
    elif normalized == "write":
        add("path", "filePath", "file_path", "path")
        add_chars("content_chars", "content")
    elif normalized == "edit":
        add("path", "filePath", "file_path", "path")
        add_chars("old_chars", "oldString", "old_string")
        add_chars("new_chars", "newString", "new_string")
        add("replace_all", "replaceAll", "replace_all")
    elif normalized in {"bash", "shell"}:
        add("command", "command", "cmd", full_string=True)
        add("workdir", "workdir", "cwd")
        add("timeout", "timeout")
        add("description", "description")
    elif normalized == "grep":
        add("pattern", "pattern")
        add("path", "path")
        add("include", "include")
    elif normalized == "glob":
        add("pattern", "pattern")
        add("path", "path")
    elif normalized == "list":
        add("path", "path")

    return " ".join(details)


def _tool_input_json(input_value: object) -> str:
    """Serialize complete tool input without redaction or preview truncation."""
    try:
        return json.dumps(
            input_value,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except Exception:
        return json.dumps(str(input_value), ensure_ascii=False)


def _path_text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _completed_file_writes(
    part: dict[str, Any],
    state: dict[str, Any],
) -> list[OpenCodeFileWrite]:
    tool_name = str(part.get("tool") or "").strip().casefold().replace("-", "_")
    call_id = str(part.get("callID") or part.get("id") or tool_name or "unknown")
    input_value = state.get("input")
    input_value = input_value if isinstance(input_value, dict) else {}
    metadata: dict[str, Any] = {}
    for value in (part.get("metadata"), state.get("metadata")):
        if isinstance(value, dict):
            metadata.update(value)

    marker = metadata.get(_FILE_WRITE_PLUGIN_METADATA_KEY)
    if isinstance(marker, dict) and isinstance(marker.get("files"), list):
        marker_call_id = str(marker.get("callID") or call_id)
        marked_writes: list[OpenCodeFileWrite] = []
        seen_marked_paths: set[str] = set()
        for item in marker["files"]:
            if not isinstance(item, dict):
                continue
            path = _path_text(item.get("path"))
            if not path or path in seen_marked_paths:
                continue
            seen_marked_paths.add(path)
            marked_writes.append(OpenCodeFileWrite(
                call_id=marker_call_id,
                path=path,
                created=item.get("created") is True,
            ))
        if marked_writes:
            return marked_writes

    if tool_name in {"write", "edit"}:
        file_diff = metadata.get("filediff")
        file_diff = file_diff if isinstance(file_diff, dict) else {}
        path = (
            _path_text(metadata.get("filepath"))
            or _path_text(metadata.get("filePath"))
            or _path_text(file_diff.get("file"))
            or _path_text(input_value.get("filePath"))
            or _path_text(input_value.get("file_path"))
            or _path_text(input_value.get("path"))
        )
        if not path:
            return []
        if tool_name == "write":
            created = metadata.get("exists") is False
        else:
            old_string = _tool_input_value(input_value, "oldString", "old_string")
            created = old_string == ""
        return [OpenCodeFileWrite(call_id=call_id, path=path, created=created)]

    if tool_name not in {"apply_patch", "patch"}:
        return []
    files = metadata.get("files")
    if not isinstance(files, list):
        return []
    writes: list[OpenCodeFileWrite] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        change_type = str(item.get("type") or "").strip().casefold()
        if change_type == "delete":
            continue
        if change_type == "move":
            path = _path_text(item.get("movePath")) or _path_text(item.get("move_path"))
        else:
            path = (
                _path_text(item.get("filePath"))
                or _path_text(item.get("file_path"))
                or _path_text(item.get("file"))
            )
        if not path:
            continue
        writes.append(OpenCodeFileWrite(
            call_id=call_id,
            path=path,
            created=change_type == "add",
        ))
    return writes


def _event_session_id(props: dict[str, Any]) -> str:
    session_id = props.get("sessionID")
    if isinstance(session_id, str) and session_id:
        return session_id
    for key in ("part", "info"):
        nested = props.get(key)
        if isinstance(nested, dict):
            nested_session_id = nested.get("sessionID")
            if isinstance(nested_session_id, str) and nested_session_id:
                return nested_session_id
    return ""


def _tool_ids_from_response(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    tool_ids: list[str] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, dict):
            tool_id = str(item.get("id") or "").strip()
        else:
            tool_id = str(item or "").strip()
        if not tool_id or tool_id in seen:
            continue
        seen.add(tool_id)
        tool_ids.append(tool_id)
    return tool_ids


class _BufferedEventEmitter:
    def __init__(self, on_line, prefix: str) -> None:
        self._on_line = on_line
        self._prefix = prefix
        self._buffer = ""

    def _emit(self, text: object) -> bool:
        preview = _one_line_preview(text)
        if not preview or self._on_line is None:
            return False
        self._on_line(f"{self._prefix} {preview}")
        return True

    def emit(self, text: object) -> bool:
        return self._emit(text)

    def append(self, text: str) -> bool:
        if not text:
            return False
        self._buffer += text
        emitted = False
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            emitted = self._emit(line) or emitted
        return emitted

    def flush(self) -> bool:
        text = self._buffer
        self._buffer = ""
        return self._emit(text)


class _ServeEventState:
    def __init__(
        self,
        tool: str,
        session_id: str,
        on_line,
        *,
        on_file_write=None,
        ignored_file_message_ids: tuple[str, ...] = (),
        log_stage: str = "opencode",
        source_mcp_name: str = "",
    ) -> None:
        self.tool = tool
        self.session_id = session_id
        self.on_line = on_line
        self.on_file_write = on_file_write
        self.ignored_file_message_ids = frozenset(ignored_file_message_ids)
        self.log_stage = task_output_stage(log_stage)
        self.source_mcp_name = str(source_mcp_name or "").strip()
        self.emitted_text = False
        self.emitted_response_text = False
        self.seen_next_text_event = False
        self.seen_next_reasoning_event = False
        # Text and reasoning remain internally aggregated for the final result
        # and JSON parsing, but never reach the console output callback.
        self.text = _BufferedEventEmitter(None, "")
        self.reasoning = _BufferedEventEmitter(None, "")
        self.final_text = _BufferedEventEmitter(None, "")
        self.final_reasoning = _BufferedEventEmitter(None, "")
        self.recovery_text = _BufferedEventEmitter(None, "")
        self.recovery_reasoning = _BufferedEventEmitter(None, "")
        self.message_roles: dict[str, str] = {}
        self.part_types: dict[str, str] = {}
        self.part_message_ids: dict[str, str] = {}
        self.part_text: dict[str, str] = {}
        self.part_emitted_text: dict[str, str] = {}
        self.tool_calls_emitted: set[str] = set()
        self.tool_call_metadata: dict[str, tuple[str, object]] = {}
        self.tool_results_emitted: set[tuple[str, str]] = set()
        self.file_writes: dict[tuple[str, str], OpenCodeFileWrite] = {}
        self.session_errors_emitted: set[str] = set()
        self.event_ids_seen: set[str] = set()
        self.last_session_status = ""
        self.observed_response_text = ""
        self.observed_reasoning_text = ""
        self.next_replay_remaining = {"text": "", "reasoning": ""}
        self.final_snapshots_emitted: set[tuple[str, str]] = set()
        self.recovery_snapshots_emitted: set[tuple[str, str]] = set()
        self.session_terminal = False

    def emit(self, category: str, message: object) -> None:
        if self.on_line is None:
            return
        self.on_line(
            format_task_output(
                self.log_stage,
                self.session_id,
                category,
                message,
            )
        )

    def record_file_write(
        self,
        value: OpenCodeFileWrite,
        *,
        replay: bool = False,
    ) -> None:
        key = (value.call_id, value.path)
        previous = self.file_writes.get(key)
        if previous is not None:
            value = OpenCodeFileWrite(
                call_id=value.call_id,
                path=value.path,
                created=previous.created or value.created,
            )
            if value == previous and not replay:
                return
        if replay:
            self.file_writes.pop(key, None)
        self.file_writes[key] = value
        if self.on_file_write is None:
            return
        try:
            self.on_file_write(value)
        except Exception:
            logger.exception(
                "Failed to record OpenCode file write for session %s",
                self.session_id,
            )

    def flush(self) -> None:
        text_flushed = self.text.flush()
        self.emitted_response_text = text_flushed or self.emitted_response_text
        self.emitted_text = text_flushed or self.emitted_text
        self.emitted_text = self.reasoning.flush() or self.emitted_text

    def record_message(self, info: object) -> None:
        if not isinstance(info, dict):
            return
        message_id = str(info.get("id") or "")
        role = str(info.get("role") or "")
        if message_id and role:
            self.message_roles[message_id] = role
        if role == "assistant":
            for part_id, part_message_id in list(self.part_message_ids.items()):
                if part_message_id == message_id:
                    self._emit_part_text(part_id)
            if info.get("error") is not None:
                self.emit_session_error(info.get("error"))
            message_time = info.get("time")
            if isinstance(message_time, dict) and message_time.get("completed") is not None:
                self.session_terminal = True

    def mark_event_seen(self, event: object) -> bool:
        if not isinstance(event, dict):
            return False
        event_id = str(event.get("id") or "")
        if not event_id:
            return False
        if event_id in self.event_ids_seen:
            return True
        self.event_ids_seen.add(event_id)
        return False

    def _append_text(self, kind: str, value: object) -> None:
        text = str(value or "")
        if not text:
            return
        if kind == "reasoning":
            self.observed_reasoning_text += text
            emitted = self.reasoning.append(text)
            self.emitted_text = emitted or self.emitted_text
            return
        self.observed_response_text += text
        emitted = self.text.append(text)
        self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def _emit_part_text(self, part_id: str) -> None:
        kind = self.part_types.get(part_id, "")
        if kind not in {"text", "reasoning"}:
            return
        message_id = self.part_message_ids.get(part_id, "")
        role = self.message_roles.get(message_id, "") if message_id else "assistant"
        if role == "user":
            return
        if role != "assistant" and kind != "reasoning":
            return
        value = self.part_text.get(part_id, "")
        emitted_value = self.part_emitted_text.get(part_id, "")
        if kind == "text" and self.seen_next_text_event:
            self.part_emitted_text[part_id] = value
            return
        if kind == "reasoning" and self.seen_next_reasoning_event:
            self.part_emitted_text[part_id] = value
            return
        if not value or value == emitted_value:
            return
        if value.startswith(emitted_value):
            delta = value[len(emitted_value):]
        elif emitted_value.startswith(value):
            return
        else:
            delta = value
        self.part_emitted_text[part_id] = value
        self._append_text(kind, delta)

    def update_part_text(self, part: dict[str, Any]) -> None:
        kind = str(part.get("type") or "")
        if kind not in {"text", "reasoning"}:
            return
        part_id = str(part.get("id") or "")
        message_id = str(part.get("messageID") or "")
        if part_id:
            self.part_types[part_id] = kind
            self.part_message_ids[part_id] = message_id
        value = str(part.get("text") or "")
        previous = self.part_text.get(part_id, "") if part_id else ""
        if not value or value == previous:
            return
        if previous.startswith(value):
            return
        if part_id:
            self.part_text[part_id] = value
            self._emit_part_text(part_id)
        elif not message_id or self.message_roles.get(message_id) == "assistant" or kind == "reasoning":
            self._append_text(kind, value)

    def append_part_delta(self, props: dict[str, Any]) -> None:
        part_id = str(props.get("partID") or "")
        field = str(props.get("field") or "")
        kind = self.part_types.get(part_id, "")
        if kind not in {"text", "reasoning"}:
            if field == "reasoning":
                kind = "reasoning"
            elif field in {"text", "content"}:
                kind = "text"
            else:
                return
            if part_id:
                self.part_types[part_id] = kind
        message_id = str(props.get("messageID") or self.part_message_ids.get(part_id, ""))
        if part_id and message_id:
            self.part_message_ids[part_id] = message_id
        delta = str(props.get("delta") or "")
        if not delta:
            return
        if part_id:
            self.part_text[part_id] = self.part_text.get(part_id, "") + delta
            self._emit_part_text(part_id)
        elif not message_id or self.message_roles.get(message_id) == "assistant" or field in {"content", "reasoning"}:
            self._append_text(kind, delta)

    def append_next_delta(self, kind: str, value: object) -> None:
        delta = str(value or "")
        if not delta:
            return
        seen_attr = "seen_next_reasoning_event" if kind == "reasoning" else "seen_next_text_event"
        if not getattr(self, seen_attr):
            setattr(self, seen_attr, True)
            observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
            self.next_replay_remaining[kind] = observed
        replay = self.next_replay_remaining[kind]
        if replay:
            if replay.startswith(delta):
                self.next_replay_remaining[kind] = replay[len(delta):]
                return
            if delta.startswith(replay):
                delta = delta[len(replay):]
            self.next_replay_remaining[kind] = ""
        self._append_text(kind, delta)

    def reconcile_text(self, kind: str, value: object) -> None:
        final_text = str(value or "")
        if not final_text:
            return
        observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
        if not observed:
            self._append_text(kind, final_text)
            return
        if final_text.strip() == observed.strip() or final_text in observed:
            return
        if final_text.startswith(observed):
            self._append_text(kind, final_text[len(observed):])
            return
        snapshot_key = (kind, final_text)
        if snapshot_key in self.final_snapshots_emitted:
            return
        self.final_snapshots_emitted.add(snapshot_key)
        emitter = self.final_reasoning if kind == "reasoning" else self.final_text
        emitted = emitter.append(final_text)
        emitted = emitter.flush() or emitted
        if kind == "reasoning":
            self.observed_reasoning_text = final_text
        else:
            self.observed_response_text = final_text
            self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def reconcile_snapshot(self, kind: str, value: object) -> None:
        """Merge a cumulative polled snapshot without duplicating streamed output."""
        snapshot = str(value or "")
        if not snapshot:
            return
        observed = self.observed_reasoning_text if kind == "reasoning" else self.observed_response_text
        if not observed:
            self._append_text(kind, snapshot)
            return
        if snapshot.strip() == observed.strip() or snapshot in observed or observed.startswith(snapshot):
            return
        if snapshot.startswith(observed):
            self._append_text(kind, snapshot[len(observed):])
            return
        snapshot_key = (kind, snapshot)
        if snapshot_key in self.recovery_snapshots_emitted:
            return
        self.recovery_snapshots_emitted.add(snapshot_key)
        emitter = self.recovery_reasoning if kind == "reasoning" else self.recovery_text
        emitted = emitter.append(snapshot)
        emitted = emitter.flush() or emitted
        if kind == "reasoning":
            self.observed_reasoning_text = snapshot
        else:
            self.observed_response_text = snapshot
            self.emitted_response_text = emitted or self.emitted_response_text
        self.emitted_text = emitted or self.emitted_text

    def ingest_message_snapshot(self, message: object) -> None:
        if not isinstance(message, dict):
            return
        info = message.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            return
        self.record_message(info)
        message_id = str(info.get("id") or "")
        parts = message.get("parts")
        if not isinstance(parts, list):
            return
        snapshots = {"text": [], "reasoning": []}
        for part in parts:
            if not isinstance(part, dict):
                continue
            part_type = str(part.get("type") or "")
            if part_type in snapshots:
                text = part.get("text")
                if isinstance(text, str):
                    snapshots[part_type].append(text)
                continue
            if message_id and not part.get("messageID"):
                part = {**part, "messageID": message_id}
            self.handle_part(part)
        for kind, values in snapshots.items():
            if values:
                self.reconcile_snapshot(kind, "".join(values))

    def ingest_file_write_snapshot(self, message: object) -> None:
        """Replay completed file writes without replaying historical text or logs."""
        if not isinstance(message, dict):
            return
        info = message.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            return
        message_id = str(info.get("id") or "")
        if message_id in self.ignored_file_message_ids:
            return
        parts = message.get("parts")
        if not isinstance(parts, list):
            return
        for part in parts:
            if not isinstance(part, dict):
                continue
            state = part.get("state")
            if not isinstance(state, dict) or state.get("status") != "completed":
                continue
            if message_id and not part.get("messageID"):
                part = {**part, "messageID": message_id}
            for value in _completed_file_writes(part, state):
                self.record_file_write(value, replay=True)

    def emit_tool_call(
        self,
        *,
        call_id: object,
        tool_name: object,
        input_value: object,
        part_id: object = "",
    ) -> None:
        call = str(call_id or part_id or tool_name or "unknown")
        name = str(tool_name or "")
        if name or call not in self.tool_call_metadata:
            self.tool_call_metadata[call] = (name, input_value or {})
        if call in self.tool_calls_emitted:
            return
        self.tool_calls_emitted.add(call)
        if _is_skill_tool(name):
            self.emit("skill", f"name={_skill_name(input_value)}")
        else:
            if (
                self.source_mcp_name
                and _tool_belongs_to_mcp(name, self.source_mcp_name)
            ):
                details = f"input={_tool_input_json(input_value)}"
            else:
                details = _tool_call_details(name, input_value)
            details_note = f" {details}" if details else ""
            self.emit("tool", f"name={name or 'unknown'}{details_note}")

    def emit_tool_result(
        self,
        *,
        call_id: object,
        status: str,
        summary: str,
        tool_name: object = "",
        input_value: object = None,
        part_id: object = "",
    ) -> None:
        call = str(call_id or part_id or tool_name or "unknown")
        normalized_status = "success" if status in {"success", "completed"} else "failed"
        recorded_name, recorded_input = self.tool_call_metadata.get(call, ("", {}))
        resolved_name = str(tool_name or recorded_name or "")
        resolved_input = input_value if input_value is not None else recorded_input
        self.emit_tool_call(
            call_id=call,
            tool_name=resolved_name,
            input_value=resolved_input,
            part_id=part_id,
        )
        key = (call, normalized_status)
        if key in self.tool_results_emitted:
            return
        self.tool_results_emitted.add(key)
        if normalized_status == "success":
            return
        error = summary or "error=unknown"
        if not error.startswith("error="):
            error = f"error={error}"
        if _is_skill_tool(resolved_name):
            self.emit(
                "skill",
                f"ERROR name={_skill_name(resolved_input)} {error}",
            )
        else:
            self.emit(
                "tool",
                f"ERROR name={resolved_name or 'unknown'} {error}",
            )

    def handle_tool_part(self, part: dict[str, Any]) -> None:
        state = part.get("state")
        if not isinstance(state, dict):
            return
        status = str(state.get("status") or "")
        common = {
            "call_id": part.get("callID"),
            "tool_name": part.get("tool"),
            "input_value": state.get("input") or {},
            "part_id": part.get("id"),
        }
        if status in {"pending", "running"}:
            self.emit_tool_call(**common)
        elif status == "completed":
            message_id = str(part.get("messageID") or "")
            if not message_id or message_id not in self.ignored_file_message_ids:
                for value in _completed_file_writes(part, state):
                    self.record_file_write(value)
            self.emit_tool_result(status="success", summary=_tool_state_summary(state), **common)
        elif status == "error":
            error = _error_summary(state.get("error") or "")
            self.emit_tool_result(status="failed", summary=f"error={error}", **common)

    def emit_session_status(self, status: object) -> None:
        if isinstance(status, dict):
            status_type = str(status.get("type") or "")
            if status_type == "retry":
                signature = "|".join(
                    str(status.get(key) or "")
                    for key in ("type", "attempt", "message", "next")
                )
            else:
                signature = status_type
        else:
            status_type = str(status or "")
            signature = status_type
            status = {}
        if status_type in {"idle", "error"}:
            self.session_terminal = True
        if not status_type or signature == self.last_session_status:
            return
        self.last_session_status = signature
        details: list[str] = []
        if status_type == "retry" and isinstance(status, dict):
            if status.get("attempt") is not None:
                details.append(f"attempt={status.get('attempt')}")
            if status.get("next") is not None:
                details.append(f"next={status.get('next')}")
            message = _one_line_preview(status.get("message") or "")
            if message:
                details.append(f"message={message}")
        if status_type == "retry":
            suffix = f" {' '.join(details)}" if details else ""
            self.emit("session", f"RETRY{suffix}")
        elif status_type not in {"busy", "idle"}:
            self.emit("session", f"STATUS status={status_type}")

    def emit_session_error(self, error: object) -> None:
        self.session_terminal = True
        summary = _error_summary(error) or "unknown"
        if summary in self.session_errors_emitted:
            return
        self.session_errors_emitted.add(summary)
        self.emit("session", f"ERROR error={summary}")

    def handle_part(self, part: object) -> None:
        if not isinstance(part, dict):
            return
        part_type = str(part.get("type") or "")
        if part_type in {"text", "reasoning"}:
            self.update_part_text(part)
        elif part_type == "tool":
            self.handle_tool_part(part)
        elif part_type == "retry":
            self.emit_session_status({
                "type": "retry",
                "attempt": part.get("attempt"),
                "message": _error_summary(part.get("error") or ""),
            })


def _event_properties(event: object) -> tuple[str, dict[str, Any]]:
    if not isinstance(event, dict):
        return "", {}
    if event.get("type") == "sync":
        event_type = str(event.get("name") or "")
        properties = event.get("data")
    else:
        event_type = str(event.get("type") or "")
        properties = event.get("properties")
    event_type = re.sub(r"\.\d+$", "", event_type)
    if isinstance(properties, dict):
        return event_type, properties
    return event_type, {}


def _handle_serve_event(event: object, state: _ServeEventState) -> None:
    event_type, props = _event_properties(event)
    if _event_session_id(props) != state.session_id:
        return
    if state.mark_event_seen(event):
        return

    if event_type == "message.updated":
        state.record_message(props.get("info"))
    elif event_type == "message.part.updated":
        state.handle_part(props.get("part"))
    elif event_type == "message.part.delta":
        state.append_part_delta(props)
    elif event_type == "session.next.text.delta":
        state.append_next_delta("text", props.get("delta") or "")
    elif event_type == "session.next.text.ended":
        state.seen_next_text_event = True
        state.flush()
        state.reconcile_text("text", props.get("text") or "")
        state.flush()
    elif event_type == "session.next.reasoning.delta":
        state.append_next_delta("reasoning", props.get("delta") or "")
    elif event_type == "session.next.reasoning.ended":
        state.seen_next_reasoning_event = True
        state.flush()
        state.reconcile_text("reasoning", props.get("text") or "")
        state.flush()
    elif event_type == "session.next.tool.called":
        state.emit_tool_call(
            call_id=props.get("callID"),
            tool_name=props.get("tool"),
            input_value=props.get("input") or {},
        )
    elif event_type == "session.next.tool.success":
        state.emit_tool_result(
            call_id=props.get("callID"),
            status="success",
            summary=_tool_content_summary(props.get("content")),
        )
    elif event_type == "session.next.tool.failed":
        state.emit_tool_result(
            call_id=props.get("callID"),
            status="failed",
            summary=f"error={_error_summary(props.get('error') or '')}",
        )
    elif event_type == "session.status":
        state.emit_session_status(props.get("status"))
    elif event_type == "session.idle":
        state.emit_session_status("idle")
    elif event_type == "session.error":
        state.emit_session_error(props.get("error"))
    elif event_type == "session.next.retried":
        state.emit_session_status({
            "type": "retry",
            "attempt": props.get("attempt"),
            "message": _error_summary(props.get("error") or ""),
        })


async def _stream_sse_events(response: httpx.Response):
    data_lines: list[str] = []
    async for raw_line in response.aiter_lines():
        line = raw_line.strip("\r")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                try:
                    yield json.loads(payload)
                except Exception:
                    continue
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        try:
            yield json.loads("\n".join(data_lines))
        except Exception:
            return


async def _flush_event_state_periodically(state: _ServeEventState) -> None:
    while True:
        await asyncio.sleep(_SERVE_EVENT_FLUSH_INTERVAL_SECONDS)
        state.flush()


def _latest_assistant_message(value: object, session_id: str) -> dict[str, Any] | None:
    if not isinstance(value, list):
        return None
    for item in reversed(value):
        if not isinstance(item, dict):
            continue
        info = item.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            continue
        item_session_id = str(info.get("sessionID") or "")
        if item_session_id and item_session_id != session_id:
            continue
        return item
    return None


def _assistant_message_is_terminal(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    info = value.get("info")
    if not isinstance(info, dict):
        return False
    if info.get("error") is not None:
        return True
    message_time = info.get("time")
    if isinstance(message_time, dict) and message_time.get("completed") is not None:
        return True
    if str(info.get("finish") or "").strip():
        return True
    return False


def _prompt_response_diagnostic(response: object) -> tuple[str, int, int, str]:
    content = getattr(response, "content", b"")
    if isinstance(content, str):
        body = content.encode("utf-8", errors="replace")
    elif isinstance(content, (bytes, bytearray)):
        body = bytes(content)
    else:
        body = str(content or "").encode("utf-8", errors="replace")
    reason = "empty_body" if not body.strip() else "invalid_json"
    try:
        status_code = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status_code = 0
    headers = getattr(response, "headers", {})
    content_type = ""
    if hasattr(headers, "get"):
        content_type = _one_line_preview(headers.get("content-type") or "")
    return reason, status_code, len(body), content_type


async def _recover_prompt_response(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    params: dict[str, str],
    headers: dict[str, str],
    baseline_message_id: str,
    cancel_event: Any,
) -> tuple[dict[str, Any] | None, str]:
    poll_params = dict(params)
    poll_params["limit"] = "2"
    deadline = (
        asyncio.get_running_loop().time()
        + _SERVE_EVENT_DRAIN_TIMEOUT_SECONDS
    )
    failure_reason = "no_new_completed_assistant"
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError()
        try:
            history_response = await client.get(
                f"/session/{session_id}/message",
                params=poll_params,
                headers=headers,
            )
            history_response.raise_for_status()
            messages = history_response.json()
        except asyncio.CancelledError:
            raise
        except Exception:
            return None, "session_history_unavailable"
        if not isinstance(messages, list):
            return None, "invalid_session_history"
        candidate = _latest_assistant_message(messages, session_id)
        candidate_id = _response_message_id(candidate)
        if not candidate_id:
            failure_reason = "no_new_completed_assistant"
        elif candidate_id == baseline_message_id:
            failure_reason = "no_new_completed_assistant"
        elif _assistant_message_is_terminal(candidate):
            return candidate, ""
        else:
            failure_reason = "assistant_message_incomplete"
        now = asyncio.get_running_loop().time()
        if now >= deadline:
            return None, failure_reason
        await asyncio.sleep(min(0.05, max(0.0, deadline - now)))


def _assistant_messages_after_baseline(
    value: object,
    *,
    session_id: str,
    baseline_message_id: str,
) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None
    assistant_messages: list[dict[str, Any]] = []
    baseline_index: int | None = None
    for item in value:
        if not isinstance(item, dict):
            continue
        info = item.get("info")
        if not isinstance(info, dict) or str(info.get("role") or "") != "assistant":
            continue
        item_session_id = str(info.get("sessionID") or "")
        if item_session_id and item_session_id != session_id:
            continue
        assistant_messages.append(item)
        if str(info.get("id") or "") == baseline_message_id:
            baseline_index = len(assistant_messages) - 1
    if baseline_message_id:
        if baseline_index is None:
            return None
        return assistant_messages[baseline_index + 1:]
    return assistant_messages


async def _replay_current_prompt_file_writes(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    params: dict[str, str],
    headers: dict[str, str],
    baseline_message_id: str,
    response_message_id: str,
    state: "_ServeEventState",
) -> None:
    poll_params = dict(params)
    poll_params["limit"] = "1000"
    deadline = (
        asyncio.get_running_loop().time()
        + _SERVE_EVENT_DRAIN_TIMEOUT_SECONDS
    )
    while True:
        try:
            response = await client.get(
                f"/session/{session_id}/message",
                params=poll_params,
                headers=headers,
            )
            response.raise_for_status()
            messages = _assistant_messages_after_baseline(
                response.json(),
                session_id=session_id,
                baseline_message_id=baseline_message_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            messages = None
        if messages is not None:
            for message in messages:
                state.ingest_file_write_snapshot(message)
            observed_ids = {
                _response_message_id(message)
                for message in messages
            }
            if not response_message_id or response_message_id in observed_ids:
                return
        now = asyncio.get_running_loop().time()
        if now >= deadline:
            if messages is None:
                logger.debug(
                    "Failed to reconcile OpenCode file writes for session %s",
                    session_id,
                )
            return
        await asyncio.sleep(min(0.05, max(0.0, deadline - now)))


def _next_event_reconnect_delay(current: float) -> float:
    return min(current * 2, _SERVE_EVENT_RECONNECT_MAX_SECONDS)


def _provider_models(provider: dict[str, Any]) -> list[OpenCodeModelInfo]:
    provider_id = str(provider.get("id") or provider.get("providerID") or provider.get("name") or "").strip()
    models = provider.get("models") or {}
    result: list[OpenCodeModelInfo] = []
    if isinstance(models, dict):
        iterable = models.items()
    elif isinstance(models, list):
        iterable = [(item.get("id") if isinstance(item, dict) else item, item) for item in models]
    else:
        iterable = []
    for model_id_raw, raw in iterable:
        model_id = str(model_id_raw or "").strip()
        if not provider_id or not model_id:
            continue
        name = ""
        limit_context: int | None = None
        limit_input: int | None = None
        limit_output: int | None = None
        if isinstance(raw, dict):
            name = str(raw.get("name") or raw.get("label") or "")
            model_id = str(raw.get("id") or model_id).strip()
            limit = raw.get("limit")
            if isinstance(limit, dict):
                limit_context = _optional_int(limit.get("context"))
                limit_input = _optional_int(limit.get("input"))
                limit_output = _optional_int(limit.get("output"))
        result.append(OpenCodeModelInfo(
            id=f"{provider_id}/{model_id}",
            provider_id=provider_id,
            model_id=model_id,
            name=name,
            limit_context=limit_context,
            limit_input=limit_input,
            limit_output=limit_output,
        ))
    return result


def _optional_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class OpenCodeServeManager:
    """Manage a single Agent-wide opencode/nga serve process."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._idle = asyncio.Condition()
        self._proc: subprocess.Popen | _AdoptedServeProcess | None = None
        self._key: OpenCodeServeKey | None = None
        self._port: int | None = None
        self._auto_port: int | None = None
        self._listener_pids: set[int] = set()
        self._startup_log_path: Path | None = None
        self._startup_cwd: Path | None = None
        self._marker_path = _serve_marker_path()
        self._active_sessions = 0
        self._active_model_listings = 0
        self._event_lock = asyncio.Lock()
        self._event_states: dict[str, _ServeEventState] = {}
        self._event_directories: dict[str, str] = {}
        self._global_event_channel: _EventChannelRuntime | None = None
        self._legacy_event_channels: dict[str, _EventChannelRuntime] = {}
        self._global_event_unsupported = False
        self._degraded_event_channels: set[str] = set()
        self._event_failure_started_at = 0.0
        self._event_failure_attempts = 0
        self._event_last_failure_summary_at = 0.0
        self._event_poll_failure_reported = False
        self._dirty = False
        self._serve_config_generation = 0
        self._restart_required = False
        self._serve_failure_generation = 0
        self._model_cache: dict[
            tuple[OpenCodeServeKey, str],
            tuple[OpenCodeModelInfo, ...],
        ] = {}
        self._model_cache_generation = 0
        self._model_fetch_lock = asyncio.Lock()
        self._model_inflight: dict[
            tuple[tuple[OpenCodeServeKey, str], bool],
            asyncio.Task[OpenCodeModelListResult],
        ] = {}
        self._managed_mcp_specs: dict[str, dict[str, Any]] = {}
        self._process_generation = 0
        self._event_generation = 0
        self._managed_mcp_directories: dict[str, Path] = {}
        self._managed_mcp_status: dict[str, dict[str, dict[str, Any]]] = {}
        self._managed_mcp_applied: dict[str, dict[str, dict[str, Any]]] = {}
        self._managed_mcp_tasks: dict[tuple[str, str], asyncio.Task] = {}
        self._managed_mcp_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._managed_mcp_force_pending: set[tuple[str, str]] = set()
        # OpenCode's dynamically-added MCPs belong to one directory context,
        # not to one session.  Let concurrent tasks from the same scan share
        # their source MCP, but serialize a switch to a different scan so a
        # message can never observe another scan's graph.
        self._scan_mcp_states: dict[str, dict[str, Any]] = {}
        self._scan_mcp_conditions: dict[str, asyncio.Condition] = {}
        self._scan_mcp_names: dict[str, set[str]] = {}

    @property
    def base_url(self) -> str:
        if self._port is None:
            raise RuntimeError("OpenCode serve is not running")
        return f"http://127.0.0.1:{self._port}"

    def mark_dirty(self) -> None:
        # Keep active sessions stable, but make the next idle acquisition reload
        # the serve process and never return a model list cached before the
        # configuration update.
        self._dirty = True
        self._serve_config_generation += 1
        self._invalidate_model_cache()
        # Do not let a request created before the config update become the
        # single-flight result for callers that arrive afterwards. The old task
        # is allowed to finish for its existing waiters, but its generation can
        # no longer populate the cache.
        self._model_inflight.clear()

    def config_runtime_status(self) -> dict[str, int | str]:
        """Return whether the current serve has loaded the latest managed config."""
        running = self._proc is not None and self._proc.poll() is None
        if running and (self._dirty or self._restart_required):
            state = "reload_pending"
        elif running:
            state = "active"
        else:
            state = "next_task"
        return {
            "runtime_state": state,
            "active_sessions": self._active_sessions,
        }

    def _mark_serve_unhealthy(self, operation: str, status_code: int) -> None:
        """Require the next Session acquisition to replace a broken Serve."""
        self._mark_serve_restart_required(
            f"request {operation} returned HTTP {status_code}",
        )

    def _mark_serve_restart_required(self, reason: str) -> None:
        """Invalidate cached state after a transport or health failure."""
        self._restart_required = True
        self._serve_failure_generation += 1
        self._invalidate_model_cache()
        logger.warning(
            "OpenCode serve is unavailable (%s); "
            "the next Session attempt will restart the shared Serve",
            reason,
        )

    def _raise_for_session_control_status(
        self,
        response: httpx.Response,
        operation: str,
    ) -> None:
        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code >= 500:
            self._mark_serve_unhealthy(operation, status_code)
        response.raise_for_status()

    def update_managed_mcp_configs(self, specs: dict[str, dict[str, Any]]) -> None:
        """Install the desired managed MCP set and hot-apply it to live directories."""
        normalized = {
            str(target): dict(spec)
            for target, spec in specs.items()
            if str(target) == "product_info" and isinstance(spec, dict)
        }
        changed = {
            target
            for target in set(self._managed_mcp_specs) | set(normalized)
            if self._managed_mcp_specs.get(target) != normalized.get(target)
        }
        self._managed_mcp_specs = normalized
        if not changed:
            return
        for directory_key in self._managed_mcp_directories:
            for target in changed:
                self._managed_mcp_status.setdefault(directory_key, {}).pop(target, None)
                self._spawn_managed_mcp_sync(directory_key, target)

    def retry_managed_mcp(self, target: str) -> None:
        target = str(target or "").strip()
        if target not in self._managed_mcp_specs:
            raise ValueError(f"Unknown managed MCP target: {target}")
        for directory_key in self._managed_mcp_directories:
            self._managed_mcp_status.setdefault(directory_key, {}).pop(target, None)
            self._spawn_managed_mcp_sync(directory_key, target, force=True)

    async def ensure_managed_mcp(self, directory: Path) -> None:
        """Ensure this OpenCode request directory sees the latest managed MCPs."""
        directory = Path(directory).resolve()
        directory_key = self._event_directory_key(directory)
        self._managed_mcp_directories[directory_key] = directory
        tasks = [
            self._spawn_managed_mcp_sync(directory_key, target)
            for target in self._managed_mcp_specs
        ]
        if tasks:
            # A caller timing out must not cancel MCP synchronization shared
            # by other sessions in this directory.
            await asyncio.shield(asyncio.gather(*tasks, return_exceptions=True))

    def _spawn_managed_mcp_sync(
        self,
        directory_key: str,
        target: str,
        *,
        force: bool = False,
    ) -> asyncio.Task:
        key = (directory_key, target)
        existing = self._managed_mcp_tasks.get(key)
        if existing is not None and not existing.done():
            if force:
                self._managed_mcp_force_pending.add(key)
            return existing
        self._managed_mcp_force_pending.discard(key)
        generation = self._process_generation
        task = asyncio.create_task(
            self._sync_managed_mcp_target(directory_key, target, force=force)
        )
        self._managed_mcp_tasks[key] = task

        def done(completed: asyncio.Task) -> None:
            if generation != self._process_generation:
                with contextlib.suppress(BaseException):
                    completed.result()
                return
            if self._managed_mcp_tasks.get(key) is completed:
                self._managed_mcp_tasks.pop(key, None)
            with contextlib.suppress(BaseException):
                completed.result()
            force_retry = key in self._managed_mcp_force_pending
            self._managed_mcp_force_pending.discard(key)
            spec = self._managed_mcp_specs.get(target)
            current = self._managed_mcp_status.get(directory_key, {}).get(target)
            if (
                spec is not None
                and directory_key in self._managed_mcp_directories
                and (
                    force_retry
                    or not isinstance(current, dict)
                    or current.get("fingerprint") != spec.get("fingerprint")
                )
            ):
                self._spawn_managed_mcp_sync(
                    directory_key,
                    target,
                    force=force_retry,
                )

        task.add_done_callback(done)
        return task

    @staticmethod
    def _mcp_status_map(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        nested = value.get("status")
        return nested if isinstance(nested, dict) else value

    @staticmethod
    def _mcp_native_status(value: Any) -> tuple[str, str]:
        if not isinstance(value, dict):
            return "failed", "OpenCode returned no MCP status"
        status = str(value.get("status") or "failed")
        error = str(value.get("error") or "")
        if status not in {
            "connected",
            "disabled",
            "failed",
            "needs_auth",
            "needs_client_registration",
        }:
            return "failed", error or f"Unknown OpenCode MCP status: {status}"
        return status, error

    @staticmethod
    def _redact_managed_mcp_error(value: object, spec: dict[str, Any]) -> str:
        text = _one_line_preview(value, 2000)
        config = spec.get("config")
        secrets: set[str] = set()
        for mapping_name in ("headers", "environment"):
            mapping = config.get(mapping_name) if isinstance(config, dict) else None
            if not isinstance(mapping, dict):
                continue
            secrets.update(str(item) for item in mapping.values() if str(item))
            for name, item in mapping.items():
                parts = str(item).split(None, 1)
                if is_sensitive_opencode_config_key(name) and len(parts) == 2:
                    secrets.add(parts[1])
        if isinstance(config, dict):
            remote_url = str(config.get("url") or "")
            if remote_url:
                secrets.add(remote_url)
        if secrets:
            for secret in sorted(
                secrets,
                key=len,
                reverse=True,
            ):
                text = text.replace(secret, "***")
        return text

    def _record_managed_mcp_status(
        self,
        directory_key: str,
        target: str,
        spec: dict[str, Any],
        state: str,
        *,
        error: str = "",
    ) -> None:
        self._managed_mcp_status.setdefault(directory_key, {})[target] = {
            "state": state,
            "fingerprint": str(spec.get("fingerprint") or ""),
            "error": self._redact_managed_mcp_error(error, spec) if error else "",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _disconnect_managed_mcp(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        applied: dict[str, Any],
    ) -> None:
        generation = self._process_generation
        name = str(applied.get("name") or "").strip()
        if not name:
            return
        response = await client.post(
            f"/mcp/{quote(name, safe='')}/disconnect",
            params=_serve_context_params(directory),
            headers=_serve_context_headers(directory),
        )
        if generation != self._process_generation:
            return
        if response.status_code == 404:
            config = applied.get("config")
            if isinstance(config, dict):
                disabled = {**config, "enabled": False}
                response = await client.post(
                    "/mcp",
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                    json={"name": name, "config": disabled},
                )
        response.raise_for_status()

    async def _sync_managed_mcp_target(
        self,
        directory_key: str,
        target: str,
        *,
        force: bool = False,
    ) -> None:
        generation = self._process_generation
        lock = self._managed_mcp_locks.setdefault((directory_key, target), asyncio.Lock())
        async with lock:
            if generation != self._process_generation:
                return
            spec = self._managed_mcp_specs.get(target)
            directory = self._managed_mcp_directories.get(directory_key)
            if spec is None or directory is None:
                return
            current = self._managed_mcp_status.get(directory_key, {}).get(target)
            if (
                not force
                and isinstance(current, dict)
                and current.get("fingerprint") == spec.get("fingerprint")
                and current.get("state") in {"connected", "disabled"}
            ):
                return
            if self._proc is None or self._proc.poll() is not None or self._port is None:
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    "disabled" if not spec.get("enabled") else "next_session",
                )
                return

            self._record_managed_mcp_status(directory_key, target, spec, "applying")
            applied = self._managed_mcp_applied.get(directory_key, {}).get(target)
            timeout_ms = 0
            config = spec.get("config")
            if isinstance(config, dict):
                timeout_ms = int(config.get("timeout") or 0)
            request_timeout = max(
                _SERVE_REQUEST_TIMEOUT_SECONDS,
                (timeout_ms / 1000.0) + 5.0 if timeout_ms else 0,
            )
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=request_timeout,
                    trust_env=False,
                ) as client:
                    if generation != self._process_generation:
                        return
                    state = "disabled"
                    error = ""
                    if spec.get("enabled"):
                        if spec.get("error") or not isinstance(config, dict):
                            if applied:
                                await self._disconnect_managed_mcp(client, directory, applied)
                            raise RuntimeError(spec.get("error") or "Invalid managed MCP config")
                        response = await client.post(
                            "/mcp",
                            params=_serve_context_params(directory),
                            headers=_serve_context_headers(directory),
                            json={"name": str(spec.get("name") or ""), "config": config},
                        )
                        if generation != self._process_generation:
                            return
                        response.raise_for_status()
                        statuses = self._mcp_status_map(response.json())
                        state, error = self._mcp_native_status(
                            statuses.get(str(spec.get("name") or ""))
                        )
                        if state == "disabled":
                            state = "failed"
                            error = error or "OpenCode reported the enabled MCP as disabled"

                    if applied and (
                        not spec.get("enabled")
                        or str(applied.get("name") or "") != str(spec.get("name") or "")
                    ):
                        await self._disconnect_managed_mcp(client, directory, applied)

                    # Record what OpenCode actually accepted before checking for
                    # a newer desired fingerprint. The follow-up sync then knows
                    # which just-connected stale name/config must be replaced or
                    # disconnected.
                    if generation != self._process_generation:
                        return
                    if state == "connected":
                        self._managed_mcp_applied.setdefault(directory_key, {})[target] = dict(spec)
                    else:
                        self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)
                    latest = self._managed_mcp_specs.get(target)
                    if latest is None or latest.get("fingerprint") != spec.get("fingerprint"):
                        self._spawn_managed_mcp_sync(directory_key, target)
                        return
                    self._record_managed_mcp_status(
                        directory_key,
                        target,
                        spec,
                        state,
                        error=error,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if generation != self._process_generation:
                    return
                self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    "failed",
                    error=str(exc),
                )
                logger.warning(
                    "Failed to hot-load managed MCP %s for %s: %s",
                    target,
                    directory,
                    self._redact_managed_mcp_error(exc, spec),
                )

    def _enabled_managed_mcp_names(self) -> set[str]:
        return {
            str(spec.get("name") or "")
            for spec in self._managed_mcp_specs.values()
            if spec.get("enabled") and str(spec.get("name") or "")
        }

    def _source_graph_mcp_names(self, directory: Path) -> set[str]:
        directory_key = self._event_directory_key(Path(directory).resolve())
        names = set(self._scan_mcp_names.get(directory_key, set()))
        names.difference_update(self._enabled_managed_mcp_names())
        return names

    async def _disconnect_source_graph_mcps(
        self,
        client: httpx.AsyncClient,
        directory: Path,
    ) -> None:
        source_names = self._source_graph_mcp_names(directory)
        protected_names = self._enabled_managed_mcp_names()
        response = await client.get(
            "/mcp",
            params=_serve_context_params(directory),
            headers=_serve_context_headers(directory),
        )
        response.raise_for_status()
        statuses = self._mcp_status_map(response.json())
        for name, raw_status in statuses.items():
            if name in protected_names:
                continue
            if (
                name not in source_names
                and not str(name).casefold().startswith(
                    _LEGACY_SCAN_CODE_GRAPH_MCP_PREFIX
                )
            ):
                continue
            state, _error = self._mcp_native_status(raw_status)
            if state != "connected":
                continue
            disconnected = await client.post(
                f"/mcp/{quote(str(name), safe='')}/disconnect",
                params=_serve_context_params(directory),
                headers=_serve_context_headers(directory),
            )
            disconnected.raise_for_status()

    async def _scan_mcp_live_status(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        name: str,
    ) -> tuple[str, str, bool]:
        """Return one directory-scoped MCP's live state and registration status."""
        response = await client.get(
            "/mcp",
            params=_serve_context_params(directory),
            headers=_serve_context_headers(directory),
        )
        response.raise_for_status()
        statuses = self._mcp_status_map(response.json())
        if name not in statuses:
            return "missing", "OpenCode returned no MCP status", False
        state, error = self._mcp_native_status(statuses.get(name))
        return state, error, True

    @staticmethod
    def _scan_mcp_exception_is_retryable(exc: BaseException) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            status = int(exc.response.status_code)
            return status >= 500 or status in {408, 409, 425, 429}
        return True

    async def _connect_scan_mcp_once(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        spec: dict[str, Any],
        *,
        registered: bool,
        request_timeout: float,
    ) -> tuple[str, str, bool]:
        name = str(spec.get("name") or "")
        config = spec.get("config")
        if registered:
            response = await client.post(
                f"/mcp/{quote(name, safe='')}/connect",
                params=_serve_context_params(directory),
                headers=_serve_context_headers(directory),
                timeout=request_timeout,
            )
            if response.status_code != 404:
                response.raise_for_status()
                return await self._scan_mcp_live_status(
                    client,
                    directory,
                    name,
                )

        response = await client.post(
            "/mcp",
            params=_serve_context_params(directory),
            headers=_serve_context_headers(directory),
            json={"name": name, "config": config},
            timeout=request_timeout,
        )
        response.raise_for_status()
        statuses = self._mcp_status_map(response.json())
        if name not in statuses:
            return await self._scan_mcp_live_status(
                client,
                directory,
                name,
            )
        state, error = self._mcp_native_status(statuses.get(name))
        return state, error, True

    async def _recover_scan_mcp_connection(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        spec: dict[str, Any],
        *,
        registered: bool,
        request_timeout: float,
        max_attempts: int,
    ) -> tuple[bool, str, bool, bool, bool]:
        """Connect or reconnect a scan MCP and reconcile ambiguous responses."""
        name = str(spec.get("name") or "")
        last_error = ""
        retryable = True
        cleanup_pending = False
        attempts = max(1, int(max_attempts))
        for attempt in range(1, attempts + 1):
            try:
                native_state, native_error, registered = (
                    await self._connect_scan_mcp_once(
                        client,
                        directory,
                        spec,
                        registered=registered,
                        request_timeout=request_timeout,
                    )
                )
                cleanup_pending = False
                if native_state == "connected":
                    return True, "", True, False, True
                last_error = native_error or (
                    f"OpenCode reported MCP state {native_state}"
                )
                retryable = native_state not in {
                    "needs_auth",
                    "needs_client_registration",
                }
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = self._redact_managed_mcp_error(exc, spec)
                retryable = self._scan_mcp_exception_is_retryable(exc)
                cleanup_pending = True
                try:
                    native_state, native_error, registered = (
                        await self._scan_mcp_live_status(
                            client,
                            directory,
                            name,
                        )
                    )
                    cleanup_pending = False
                    if native_state == "connected":
                        return True, "", True, False, True
                    if native_error:
                        last_error = native_error
                    elif native_state != "missing":
                        last_error = f"OpenCode reported MCP state {native_state}"
                    if native_state in {
                        "needs_auth",
                        "needs_client_registration",
                    }:
                        retryable = False
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # The add/connect response may have been lost after OpenCode
                    # accepted it. Retain cleanup_pending so the final release
                    # still removes a possibly-live client.
                    pass

            if not retryable or attempt >= attempts:
                break
            logger.warning(
                "Scan MCP connection attempt failed "
                "name=%s directory=%s attempt=%s/%s retry_in=%.1fs error=%s",
                name,
                directory,
                attempt,
                attempts,
                _SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS,
                last_error,
            )
            await asyncio.sleep(_SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS)

        return False, last_error, retryable, cleanup_pending, registered

    async def _acquire_scan_mcp(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        scan_id: str,
        raw_config: dict[str, Any] | None,
        *,
        role: str = "code_graph",
        source_graph: bool = True,
    ) -> _ScanMcpLease:
        directory = Path(directory).resolve()
        directory_key = self._event_directory_key(directory)
        normalized_role = str(role or "scan_mcp").strip() or "scan_mcp"
        state_key = f"{directory_key}\0{normalized_role}"
        spec: dict[str, Any]
        if not str(scan_id or "").strip():
            spec = {
                "name": "",
                "fingerprint": "no-source-graph",
                "config": None,
                "error": "",
            }
        elif raw_config is None or not bool(raw_config.get("enabled")):
            spec = {
                "name": "",
                "fingerprint": "file-tools-only",
                "config": None,
                "error": "",
            }
        else:
            try:
                spec = _scan_mcp_runtime_spec(scan_id, raw_config)
            except Exception as exc:
                spec = {
                    "name": "",
                    "fingerprint": hashlib.sha256(
                        f"invalid:{scan_id}".encode("utf-8")
                    ).hexdigest(),
                    "config": None,
                    "error": _one_line_preview(exc),
                }

        name = str(spec.get("name") or "")
        fingerprint = str(spec.get("fingerprint") or "")
        identity = _scan_mcp_lease_identity(
            str(scan_id or "").strip() or "no-scan",
            name,
            fingerprint,
        )
        config = spec.get("config")
        timeout_ms = int(config.get("timeout") or 0) if isinstance(config, dict) else 0
        request_timeout = max(
            _SERVE_REQUEST_TIMEOUT_SECONDS,
            (timeout_ms / 1000.0) + 5.0 if timeout_ms else 0,
        )
        condition = self._scan_mcp_conditions.setdefault(
            state_key,
            asyncio.Condition(),
        )

        def lease_from_state(state: dict[str, Any]) -> _ScanMcpLease:
            return _ScanMcpLease(
                directory_key=directory_key,
                state_key=state_key,
                identity=identity,
                name=str(state.get("name") or name),
                fingerprint=fingerprint,
                connected=bool(state.get("connected")),
                role=normalized_role,
                error=str(state.get("error") or ""),
            )

        def retain(state: dict[str, Any]) -> _ScanMcpLease:
            state["references"] = int(state.get("references") or 0) + 1
            return lease_from_state(state)

        async with condition:
            while True:
                existing = self._scan_mcp_states.get(state_key)
                if existing is None:
                    break
                if str(existing.get("identity") or "") == identity:
                    if (
                        not name
                        or not isinstance(config, dict)
                        or existing.get("retryable") is False
                    ):
                        return retain(existing)

                    was_connected = bool(existing.get("connected"))
                    registered = bool(existing.get("registered"))
                    try:
                        live_state, live_error, registered = (
                            await self._scan_mcp_live_status(
                                client,
                                directory,
                                name,
                            )
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if was_connected:
                            logger.warning(
                                "Failed to verify connected scan MCP; "
                                "using cached state name=%s directory=%s error=%s",
                                name,
                                directory,
                                self._redact_managed_mcp_error(exc, spec),
                            )
                            return retain(existing)
                        live_state = "unknown"
                        live_error = str(existing.get("error") or "") or (
                            self._redact_managed_mcp_error(exc, spec)
                        )
                    else:
                        existing["registered"] = registered
                        existing["cleanup_pending"] = False
                        if live_state == "connected":
                            existing.update({
                                "connected": True,
                                "error": "",
                                "retryable": True,
                                "next_retry_at": 0.0,
                            })
                            if not was_connected:
                                logger.info(
                                    "Scan MCP recovered from live status "
                                    "name=%s directory=%s",
                                    name,
                                    directory,
                                )
                            return retain(existing)
                        if live_state in {
                            "needs_auth",
                            "needs_client_registration",
                        }:
                            existing.update({
                                "connected": False,
                                "error": live_error or (
                                    f"OpenCode reported MCP state {live_state}"
                                ),
                                "retryable": False,
                            })
                            return retain(existing)

                    existing.update({
                        "connected": False,
                        "error": live_error or (
                            f"OpenCode reported MCP state {live_state}"
                        ),
                        "registered": registered,
                    })
                    if time.monotonic() < float(
                        existing.get("next_retry_at") or 0.0
                    ):
                        return retain(existing)

                    logger.warning(
                        "Scan MCP connection lost; reconnecting "
                        "name=%s directory=%s previous_state=%s error=%s",
                        name,
                        directory,
                        live_state,
                        existing["error"],
                    )
                    try:
                        (
                            connected,
                            error,
                            retryable,
                            cleanup_pending,
                            registered,
                        ) = await self._recover_scan_mcp_connection(
                            client,
                            directory,
                            spec,
                            registered=registered,
                            request_timeout=request_timeout,
                            max_attempts=1,
                        )
                    except asyncio.CancelledError:
                        existing.update({
                            "connected": False,
                            "retryable": True,
                            "next_retry_at": 0.0,
                        })
                        raise
                    existing.update({
                        "connected": connected,
                        "error": error,
                        "retryable": retryable,
                        "cleanup_pending": cleanup_pending,
                        "registered": registered,
                        "next_retry_at": (
                            0.0
                            if connected or not retryable
                            else time.monotonic()
                            + _SCAN_MCP_RECOVERY_COOLDOWN_SECONDS
                        ),
                    })
                    if connected:
                        logger.info(
                            "Scan MCP reconnected name=%s directory=%s",
                            name,
                            directory,
                        )
                    else:
                        logger.warning(
                            "Scan MCP reconnect unavailable "
                            "name=%s directory=%s retryable=%s error=%s",
                            name,
                            directory,
                            retryable,
                            error,
                        )
                    return retain(existing)
                await condition.wait()

            state: dict[str, Any] = {
                "identity": identity,
                "name": name,
                "fingerprint": fingerprint,
                "references": 1,
                "connected": False,
                "error": str(spec.get("error") or ""),
                "spec": spec,
                "directory": directory,
                "directory_key": directory_key,
                "role": normalized_role,
                "source_graph": source_graph,
                "retryable": not bool(spec.get("error")),
                "next_retry_at": 0.0,
                "registered": False,
                "cleanup_pending": False,
            }
            self._scan_mcp_states[state_key] = state
            if raw_config is not None and name:
                active_names = {
                    str(item.get("name") or "")
                    for key, item in self._scan_mcp_states.items()
                    if key != state_key
                    and str(item.get("directory_key") or "") == directory_key
                    and str(item.get("name") or "")
                }
                if name in self._enabled_managed_mcp_names():
                    state["error"] = (
                        f"Scan code graph MCP name {name!r} conflicts with "
                        "an enabled global MCP"
                    )
                    state["retryable"] = False
                elif name in active_names:
                    state["error"] = (
                        f"Scan MCP name {name!r} conflicts with another active MCP"
                    )
                    state["retryable"] = False
                elif source_graph:
                    self._scan_mcp_names.setdefault(directory_key, set()).add(name)

            try:
                if source_graph:
                    try:
                        await self._disconnect_source_graph_mcps(client, directory)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning(
                            "Failed to inspect stale source MCPs before scan MCP "
                            "connect; retrying name=%s directory=%s error=%s",
                            name or "disabled",
                            directory,
                            self._redact_managed_mcp_error(exc, spec),
                        )
                        await asyncio.sleep(
                            _SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS
                        )
                        await self._disconnect_source_graph_mcps(
                            client,
                            directory,
                        )
                if state["error"]:
                    return lease_from_state(state)
                if not name:
                    state["retryable"] = False
                    return lease_from_state(state)
                (
                    connected,
                    error,
                    retryable,
                    cleanup_pending,
                    registered,
                ) = await self._recover_scan_mcp_connection(
                    client,
                    directory,
                    spec,
                    registered=False,
                    request_timeout=request_timeout,
                    max_attempts=_SCAN_MCP_INITIAL_CONNECT_ATTEMPTS,
                )
                state.update({
                    "connected": connected,
                    "error": error,
                    "retryable": retryable,
                    "cleanup_pending": cleanup_pending,
                    "registered": registered,
                    "next_retry_at": (
                        0.0
                        if connected or not retryable
                        else time.monotonic()
                        + _SCAN_MCP_RECOVERY_COOLDOWN_SECONDS
                    ),
                })
                if not connected:
                    logger.warning(
                        "Scan MCP unavailable "
                        "name=%s directory=%s retryable=%s error=%s",
                        name,
                        directory,
                        retryable,
                        error,
                    )
                return lease_from_state(state)
            except asyncio.CancelledError:
                self._scan_mcp_states.pop(state_key, None)
                condition.notify_all()
                raise
            except Exception as exc:
                error = self._redact_managed_mcp_error(exc, spec)
                retryable = self._scan_mcp_exception_is_retryable(exc)
                state.update({
                    "connected": False,
                    "error": error,
                    "retryable": retryable,
                    "next_retry_at": (
                        0.0
                        if not retryable
                        else time.monotonic()
                        + _SCAN_MCP_RECOVERY_COOLDOWN_SECONDS
                    ),
                })
                logger.warning(
                    "Scan MCP unavailable before connection "
                    "name=%s directory=%s retryable=%s error=%s",
                    name or "disabled",
                    directory,
                    retryable,
                    error,
                )
                return lease_from_state(state)

    async def _disable_scan_mcp_lease(
        self,
        client: httpx.AsyncClient,
        directory: Path,
        lease: _ScanMcpLease | None,
        error: object,
    ) -> None:
        """Fail one shared scan MCP closed before a model prompt is sent."""
        if lease is None:
            return
        condition = self._scan_mcp_conditions.get(lease.state_key)
        if condition is None:
            return
        spec: dict[str, Any] | None = None
        async with condition:
            existing = self._scan_mcp_states.get(lease.state_key)
            if (
                existing is None
                or str(existing.get("identity") or "") != lease.identity
            ):
                return
            spec = existing.get("spec")
            existing["connected"] = False
            existing["cleanup_pending"] = True
            existing["error"] = _one_line_preview(error)
            existing["retryable"] = False
            existing["next_retry_at"] = 0.0
        if isinstance(spec, dict) and str(spec.get("name") or ""):
            try:
                await self._disconnect_managed_mcp(
                    client,
                    Path(directory).resolve(),
                    spec,
                )
                async with condition:
                    existing = self._scan_mcp_states.get(lease.state_key)
                    if (
                        existing is not None
                        and str(existing.get("identity") or "") == lease.identity
                    ):
                        existing["cleanup_pending"] = False
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                config = spec.get("config")
                if isinstance(config, dict):
                    try:
                        response = await client.post(
                            "/mcp",
                            params=_serve_context_params(directory),
                            headers=_serve_context_headers(directory),
                            json={
                                "name": str(spec.get("name") or ""),
                                "config": {**config, "enabled": False},
                            },
                        )
                        response.raise_for_status()
                        async with condition:
                            existing = self._scan_mcp_states.get(lease.state_key)
                            if (
                                existing is not None
                                and str(existing.get("identity") or "") == lease.identity
                            ):
                                existing["cleanup_pending"] = False
                        return
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass
                logger.warning(
                    "Failed to disconnect disabled scan MCP name=%s directory=%s error=%s",
                    lease.name,
                    directory,
                    self._redact_managed_mcp_error(exc, spec),
                )

    async def _release_scan_mcp(
        self,
        directory: Path,
        lease: _ScanMcpLease | None,
    ) -> None:
        if lease is None:
            return
        condition = self._scan_mcp_conditions.get(lease.state_key)
        if condition is None:
            return
        spec: dict[str, Any] | None = None
        should_disconnect = False
        async with condition:
            existing = self._scan_mcp_states.get(lease.state_key)
            if (
                existing is None
                or str(existing.get("identity") or "") != lease.identity
            ):
                return
            references = max(0, int(existing.get("references") or 0) - 1)
            if references:
                existing["references"] = references
                return
            spec = existing.get("spec")
            should_disconnect = (
                bool(existing.get("connected"))
                or bool(existing.get("cleanup_pending"))
            ) and bool(existing.get("name"))
            try:
                if should_disconnect and isinstance(spec, dict):
                    async with httpx.AsyncClient(
                        base_url=self.base_url,
                        timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
                        trust_env=False,
                    ) as client:
                        await self._disconnect_managed_mcp(
                            client,
                            Path(directory).resolve(),
                            spec,
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "Failed to disconnect scan MCP name=%s directory=%s error=%s",
                    str(existing.get("name") or lease.name),
                    directory,
                    self._redact_managed_mcp_error(exc, spec or {}),
                )
            finally:
                self._scan_mcp_states.pop(lease.state_key, None)
                condition.notify_all()

    def managed_mcp_runtime_status(self) -> dict[str, dict[str, Any]]:
        running = self._proc is not None and self._proc.poll() is None
        result: dict[str, dict[str, Any]] = {}
        total = len(self._managed_mcp_directories)
        for target in ("product_info",):
            spec = self._managed_mcp_specs.get(target) or {
                "enabled": False,
                "fingerprint": "",
            }
            records = [
                statuses.get(target)
                for statuses in self._managed_mcp_status.values()
                if isinstance(statuses.get(target), dict)
                and statuses[target].get("fingerprint") == spec.get("fingerprint")
            ]
            loaded = sum(record.get("state") == "connected" for record in records)
            applying = any(
                key[1] == target and not task.done()
                for key, task in self._managed_mcp_tasks.items()
            )
            if not spec.get("enabled"):
                if applying:
                    state = "applying"
                elif any(record.get("state") == "failed" for record in records):
                    # A failed disconnect means the old MCP may still be live;
                    # never report that as successfully disabled.
                    state = "failed"
                else:
                    state = "disabled"
            elif applying:
                state = "applying"
            elif spec.get("error"):
                state = "failed"
            elif not running or total == 0:
                state = "next_session"
            elif len(records) < total:
                state = "applying"
            elif any(record.get("state") == "needs_auth" for record in records):
                state = "needs_auth"
            elif any(record.get("state") == "needs_client_registration" for record in records):
                state = "needs_client_registration"
            elif any(record.get("state") == "failed" for record in records):
                state = "failed"
            elif loaded == total:
                state = "connected"
            else:
                state = "failed"
            errors = [str(record.get("error") or "") for record in records if record.get("error")]
            spec_error = self._redact_managed_mcp_error(spec.get("error"), spec) if spec.get("error") else ""
            updated = [str(record.get("updated_at") or "") for record in records if record.get("updated_at")]
            result[target] = {
                "state": state,
                "config_fingerprint": str(spec.get("fingerprint") or ""),
                "updated_at": max(updated, default=""),
                "error": errors[0] if errors else spec_error,
                "loaded_directories": loaded,
                "total_directories": total,
            }
        return result

    async def refresh_managed_mcp_runtime_status(self) -> dict[str, dict[str, Any]]:
        """Refresh cached states from OpenCode's live /mcp endpoint."""
        if self._proc is None or self._proc.poll() is not None or self._port is None:
            return self.managed_mcp_runtime_status()

        async def refresh_directory(
            client: httpx.AsyncClient,
            directory_key: str,
            directory: Path,
        ) -> None:
            try:
                response = await client.get(
                    "/mcp",
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                )
                response.raise_for_status()
                statuses = self._mcp_status_map(response.json())
            except Exception:
                return
            for target, spec in self._managed_mcp_specs.items():
                task = self._managed_mcp_tasks.get((directory_key, target))
                if task is not None and not task.done():
                    continue
                name = str(spec.get("name") or "")
                native = statuses.get(name)
                if isinstance(native, dict):
                    state, error = self._mcp_native_status(native)
                    if spec.get("enabled") and state == "disabled":
                        state = "failed"
                        error = error or "OpenCode reported the enabled MCP as disabled"
                elif not spec.get("enabled"):
                    state, error = "disabled", ""
                else:
                    state = "failed"
                    error = f"OpenCode MCP status does not contain {name or target}"
                self._record_managed_mcp_status(
                    directory_key,
                    target,
                    spec,
                    state,
                    error=error,
                )
                if state == "connected":
                    self._managed_mcp_applied.setdefault(directory_key, {})[target] = dict(spec)
                else:
                    self._managed_mcp_applied.setdefault(directory_key, {}).pop(target, None)

        directories = list(self._managed_mcp_directories.items())
        if not directories:
            return self.managed_mcp_runtime_status()
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=2.0,
            trust_env=False,
        ) as client:
            await asyncio.gather(*(
                refresh_directory(client, directory_key, directory)
                for directory_key, directory in directories
            ))
        return self.managed_mcp_runtime_status()

    async def run_prompt(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        agent: str = "build",
        prompt: str,
        model: str,
        timeout: int,
        on_line=None,
        on_session_id=None,
        on_model_request_failure=None,
        on_response_model=None,
        on_token_usage=None,
        on_file_write=None,
        cancel_event=None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        session_id: str | None = None,
        session_title: str = "DeepHole 2.0 task",
        mcp_tools: list[str] | tuple[str, ...] | None = None,
        disabled_mcp_tools: list[str] | tuple[str, ...] | None = None,
        scan_id: str = "",
        code_graph_mcp: dict[str, Any] | None = None,
        knowledge_base_mcp: dict[str, Any] | None = None,
        system_prompt: str = "",
        permissions: list[dict[str, str]] | None = None,
        disable_all_tools: bool = False,
        return_details: bool = False,
        show_serve_status: bool = False,
        log_stage: str = "opencode",
        task_id: str = "",
        task_attempt: int = 0,
        allowed_bash_commands: tuple[str, ...] = (),
        required_bash_commands: tuple[str, ...] = (),
        bash_command_match_mode: str = "exact",
        required_bash_success_markers: tuple[tuple[str, str], ...] = (),
        required_bash_path_prepend: tuple[str, ...] = (),
    ) -> list[str] | OpenCodePromptResult:
        deadline = OperationDeadline(timeout, cancel_event=cancel_event)
        callbacks_open = True
        usage_open = True
        output_callback = on_line

        def guarded(callback):
            if callback is None:
                return None

            def invoke(*args, **kwargs):
                if callbacks_open:
                    return callback(*args, **kwargs)
                return None

            return invoke

        on_session_id = guarded(on_session_id)
        on_response_model = guarded(on_response_model)
        on_file_write = guarded(on_file_write)
        on_line = guarded(on_line)
        normalized_log_stage = task_output_stage(log_stage)
        active_session_id = str(session_id or "").strip()
        session_mode = "continued" if active_session_id else "created"

        def emit(
            category: str, message: object, *,
            current_session_id: str | None = None, final: bool = False,
        ) -> None:
            callback = output_callback if final else on_line
            if callback is None:
                return
            resolved_session_id = (
                active_session_id if current_session_id is None else current_session_id
            )
            callback(
                format_task_output(
                    normalized_log_stage,
                    resolved_session_id,
                    category,
                    message,
                )
            )

        async def emit_model_request_failure(kind: str) -> None:
            if on_model_request_failure is None:
                return
            try:
                result = on_model_request_failure(kind)
                if hasattr(result, "__await__"):
                    await result
            except Exception as exc:
                logger.warning(
                    "Failed to publish OpenCode model request failure for session %s: %s",
                    active_session_id,
                    exc,
                )

        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            serve_port_auto=bool(serve_port_auto),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        if show_serve_status and on_line:
            port_label = (
                "auto"
                if serve_port_auto
                else str(_serve_port(normalized_env_overrides))
            )
            emit(
                "task",
                f"SERVE PREPARING executable={executable} "
                f"port={port_label} "
                f"port_mode={'auto' if serve_port_auto else 'fixed'}"
            )
        serve_acquired = False
        client = None
        request = None
        message_finished = False
        response_data = None
        capture_token_usage = None
        event_state: _ServeEventState | None = None
        event_registered = False
        event_flush_task: asyncio.Task | None = None
        snapshot_poll_task: asyncio.Task | None = None
        session_started = False
        session_outcome = "failure"
        session_error = ""
        response_message_id_for_log = ""
        scan_mcp_lease: _ScanMcpLease | None = None
        knowledge_mcp_lease: _ScanMcpLease | None = None
        owned_mcp_leases: list[_ScanMcpLease] = []
        knowledge_binding_path: Path | None = None
        command_binding_path: Path | None = None
        command_audit_path: Path | None = None
        selected_source_mcp: str | None = None
        knowledge_runtime = (
            knowledge_base_mcp
            if isinstance(knowledge_base_mcp, dict)
            and bool(knowledge_base_mcp.get("enabled"))
            else None
        )
        knowledge_mcp_name = str(
            (knowledge_runtime or {}).get("name") or ""
        ).strip()
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)

        async def acquire_serve() -> str:
            nonlocal serve_acquired
            mode = await self._acquire_session(key, startup_cwd=config_workspace)
            if callbacks_open:
                serve_acquired = True
            else:
                await self._release_active_session()
            return mode

        async def acquire_mcp(*args, **kwargs) -> _ScanMcpLease:
            lease = await self._acquire_scan_mcp(*args, **kwargs)
            if callbacks_open:
                owned_mcp_leases.append(lease)
            else:
                late_cleanup = OperationDeadline(CLEANUP_TIMEOUT_SECONDS)
                await late_cleanup.wait(
                    self._release_scan_mcp(directory, lease), phase="late_mcp_release",
                )
            return lease

        try:
            try:
                serve_mode = await deadline.wait(acquire_serve(), phase="serve_preparation")
            except Exception as exc:
                if show_serve_status and on_line:
                    emit("task", "SERVE STARTUP_FAILED "
                         f"error={_one_line_preview(exc, _SERVE_STARTUP_LOG_TAIL_LIMIT + 500)}")
                raise
            if show_serve_status and on_line:
                pid = int(getattr(self._proc, "pid", 0) or 0)
                emit(
                    "task",
                    f"SERVE READY mode={serve_mode} "
                    f"url={self.base_url} pid={pid}"
                )
            await deadline.wait(self.ensure_managed_mcp(directory), phase="managed_mcp")
            client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
                trust_env=False,
            )
            await deadline.wait(client.__aenter__(), phase="http_client")
            token_baseline: dict[
                tuple[str, str, str], tuple[str, TokenCounters]
            ] = {}
            token_baseline_complete = True
            captured_token_usage: OpenCodeTokenUsage | None = None
            token_usage_captured = False

            async def capture_token_usage(
                response_message: object = None,
                *,
                timeout_seconds: float = _SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS,
            ) -> OpenCodeTokenUsage:
                nonlocal captured_token_usage, token_usage_captured
                if token_usage_captured and captured_token_usage is not None:
                    return captured_token_usage
                usage_deadline = OperationDeadline(min(
                    _SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS, timeout_seconds,
                ))
                after, after_complete = await _session_tree_token_entries(
                    client,
                    active_session_id,
                    params,
                    headers,
                    model,
                    deadline=usage_deadline,
                )
                if not token_baseline_complete:
                    # An incomplete continuation baseline cannot distinguish
                    # old child messages from this invocation's usage. Keep
                    # only the authoritative current response in that case.
                    after = {}
                if response_message is not None:
                    after.update(
                        _message_token_entries(
                            active_session_id,
                            response_message,
                            model,
                        )
                    )
                captured_token_usage = _token_usage_delta(
                    token_baseline,
                    after,
                    complete=token_baseline_complete and after_complete,
                )
                token_usage_captured = True
                if usage_open and on_token_usage is not None:
                    callback_task = None
                    try:
                        result = on_token_usage(captured_token_usage)
                        if hasattr(result, "__await__"):
                            callback_task = asyncio.ensure_future(result)
                            # Allow in-memory accounting even if HTTP collection
                            # used the budget. Never wait unboundedly for a sink.
                            await asyncio.sleep(0)
                            if callback_task.done():
                                callback_task.result()
                            else:
                                await usage_deadline.wait(callback_task, phase="token_callback")
                    except Exception as exc:
                        captured_token_usage = replace(captured_token_usage, complete=False)
                        logger.warning(
                            "OpenCode token accounting incomplete task=%s session=%s phase=%s error=%s",
                            task_id, active_session_id, usage_deadline.phase, type(exc).__name__,
                        )
                    finally:
                        if callback_task is not None and not callback_task.done():
                            callback_task.cancel()
                            retire_task(callback_task)
                if not after_complete and usage_deadline.remaining() <= 0:
                    logger.warning(
                        "OpenCode token collection incomplete task=%s session=%s phase=%s",
                        task_id, active_session_id, usage_deadline.phase,
                    )
                return captured_token_usage

            if str(scan_id or "").strip():
                scan_mcp_lease = await deadline.wait(acquire_mcp(
                    client,
                    directory,
                    str(scan_id),
                    code_graph_mcp if isinstance(code_graph_mcp, dict) else None,
                ), phase="scan_mcp")
                selected_source_mcp = (
                    scan_mcp_lease.name if scan_mcp_lease.connected else ""
                )
                if scan_mcp_lease.connected:
                    emit(
                        "session",
                        f"CODE_GRAPH_MCP connected name={scan_mcp_lease.name}",
                    )
                elif scan_mcp_lease.error:
                    emit(
                        "session",
                        "CODE_GRAPH_MCP unavailable fallback=file_tools "
                        f"error={_one_line_preview(scan_mcp_lease.error)}",
                    )
                else:
                    emit(
                        "session",
                        "CODE_GRAPH_MCP disabled mode=file_tools",
                    )
                if knowledge_runtime is not None:
                    knowledge_mcp_lease = await deadline.wait(acquire_mcp(
                        client,
                        directory,
                        str(scan_id),
                        knowledge_runtime,
                        role="knowledge_base",
                        source_graph=False,
                    ), phase="scan_mcp")
                    if knowledge_mcp_lease.connected:
                        emit(
                            "session",
                            f"KNOWLEDGE_BASE_MCP connected name={knowledge_mcp_lease.name}",
                        )
                    elif knowledge_mcp_lease.error:
                        emit(
                            "session",
                            "KNOWLEDGE_BASE_MCP unavailable "
                            f"error={_one_line_preview(knowledge_mcp_lease.error)}",
                        )
            if not active_session_id:
                create_payload: dict[str, Any] = {
                    "title": str(session_title or "").strip() or "DeepHole 2.0 task",
                }
                if permissions is not None:
                    create_payload["permission"] = permissions
                created = await deadline.wait(client.post(
                    "/session",
                    params=params,
                    headers=headers,
                    json=create_payload,
                ), phase="session_create")
                self._raise_for_session_control_status(
                    created,
                    "POST /session",
                )
                active_session_id = _session_id(created.json())
            elif permissions is not None:
                updated = await deadline.wait(client.patch(
                    f"/session/{active_session_id}",
                    params=params,
                    headers=headers,
                    json={"permission": permissions},
                ), phase="session_permissions")
                self._raise_for_session_control_status(
                    updated,
                    "PATCH /session/{session_id}",
                )
            binding_workspace = self._startup_cwd or config_workspace
            if binding_workspace is not None:
                try:
                    _remove_file(_knowledge_binding_path(
                        binding_workspace,
                        active_session_id,
                    ))
                except Exception as exc:
                    logger.warning(
                        "Failed to remove stale knowledge binding for session %s: %s",
                        active_session_id,
                        _one_line_preview(exc),
                    )
            bound_bash_commands = tuple(dict.fromkeys((
                *allowed_bash_commands,
                *required_bash_commands,
            )))
            if bound_bash_commands:
                if binding_workspace is None:
                    raise RuntimeError(
                        "Managed plugin workspace is unavailable for bound shell commands"
                    )
                command_binding_path, command_audit_path = (
                    _write_command_binding(
                        binding_workspace,
                        session_id=active_session_id,
                        required_commands=bound_bash_commands,
                        bash_command_match_mode=bash_command_match_mode,
                        success_markers=required_bash_success_markers,
                        path_prepend=required_bash_path_prepend,
                    )
                )
            elif binding_workspace is not None:
                with contextlib.suppress(Exception):
                    _remove_file(_command_binding_path(
                        binding_workspace,
                        active_session_id,
                    ))
                with contextlib.suppress(Exception):
                    _remove_file(_command_audit_path(
                        binding_workspace,
                        active_session_id,
                    ))
            if session_mode == "continued":
                token_baseline, token_baseline_complete = (
                    await deadline.wait(_session_tree_token_entries(
                        client,
                        active_session_id,
                        params,
                        headers,
                        model,
                    ), phase="token_baseline")
                )
            if on_session_id:
                result = on_session_id(active_session_id)
                if hasattr(result, "__await__"):
                    await deadline.wait(result, phase="response_callback")
            if on_line:
                config_note = f" config={config_workspace}" if config_workspace else ""
                correlation_note = (
                    f" task={task_id} attempt={task_attempt}"
                    if task_id
                    else ""
                )
                emit(
                    "session",
                    f"START mode={session_mode} directory={directory}"
                    f"{correlation_note}{config_note}",
                )
                session_started = True
            ignored_file_message_ids: tuple[str, ...] = ()
            response_baseline_known = session_mode != "continued"
            response_baseline_message_id = ""
            if session_mode == "continued":
                baseline_params = dict(params)
                baseline_params["limit"] = "2"
                try:
                    baseline_response = await deadline.wait(client.get(
                        f"/session/{active_session_id}/message",
                        params=baseline_params,
                        headers=headers,
                    ), phase="response_cleanup")
                    baseline_response.raise_for_status()
                    baseline_messages = baseline_response.json()
                    if not isinstance(baseline_messages, list):
                        raise RuntimeError(
                            "OpenCode session history did not return a message list"
                        )
                    baseline_message = _latest_assistant_message(
                        baseline_messages,
                        active_session_id,
                    )
                    response_baseline_message_id = _response_message_id(
                        baseline_message
                    )
                    response_baseline_known = True
                except Exception:
                    if on_file_write is not None:
                        raise
                    logger.debug(
                        "Failed to capture OpenCode response baseline for session %s",
                        active_session_id,
                        exc_info=True,
                    )
                if response_baseline_message_id:
                    ignored_file_message_ids = (
                        response_baseline_message_id,
                    )
            if on_line is not None or on_file_write is not None:
                event_state = _ServeEventState(
                    tool,
                    active_session_id,
                    on_line,
                    on_file_write=on_file_write,
                    ignored_file_message_ids=ignored_file_message_ids,
                    log_stage=normalized_log_stage,
                    source_mcp_name=selected_source_mcp or "",
                )
                if on_line is not None:
                    event_flush_task = asyncio.create_task(
                        _flush_event_state_periodically(event_state)
                    )
                event_registered = True
                await deadline.wait(self._register_event_state(active_session_id, directory, event_state), phase="event_registration")
            payload: dict[str, Any] = {
                "agent": agent,
                "parts": [{"type": "text", "text": prompt}],
            }
            tool_ids = await deadline.wait(self._list_tool_ids(
                client,
                params,
                headers,
                on_line=(lambda message: emit("session", message)) if on_line else None,
                tool=tool,
            ), phase="tool_discovery")
            if disable_all_tools:
                mcp_overrides = {
                    tool_id: False
                    for tool_id in sorted(
                        set(tool_ids) | set(_FORMATTER_DISABLED_TOOL_IDS)
                    )
                }
                source_available = False
            else:
                mcp_overrides = _mcp_tool_overrides(
                    tool_ids,
                    mcp_tools,
                    disabled_mcp_tools,
                )
                mcp_overrides, source_available = _apply_source_graph_overrides(
                    tool_ids,
                    mcp_overrides,
                    selected_source_mcp,
                    source_mcp_names=self._source_graph_mcp_names(directory),
                    protected_mcp_names=(
                        self._enabled_managed_mcp_names()
                        | ({knowledge_mcp_lease.name} if knowledge_mcp_lease and knowledge_mcp_lease.connected else set())
                    ),
                    allow_undiscovered=bool(
                        scan_mcp_lease is not None and scan_mcp_lease.connected
                    ),
                )
            # OpenCode 1.18.4's experimental tool-ID route only exposes
            # registry tools; MCP tools are merged later when a Session
            # resolves its tools. Build the deterministic MCP IDs instead.
            knowledge_tool_patterns = [
                f"{prefix}*"
                for prefix in _opencode_mcp_tool_prefixes(knowledge_mcp_name)
            ]
            if (
                disable_all_tools
                and knowledge_mcp_lease is not None
                and knowledge_mcp_lease.connected
            ):
                for pattern in knowledge_tool_patterns:
                    mcp_overrides[pattern] = False
            if (
                not disable_all_tools
                and knowledge_mcp_lease is not None
                and knowledge_mcp_lease.connected
            ):
                projects_tool = str(
                    (knowledge_runtime or {}).get("projects_tool") or ""
                ).strip()
                set_project_tool = str(
                    (knowledge_runtime or {}).get("set_project_tool") or ""
                ).strip()
                projects_tool_ids = list(_opencode_mcp_tool_ids(
                    knowledge_mcp_name,
                    projects_tool,
                ))
                set_project_tool_ids = list(_opencode_mcp_tool_ids(
                    knowledge_mcp_name,
                    set_project_tool,
                ))
                blocked_knowledge_tools = list(dict.fromkeys([
                    *projects_tool_ids,
                    *set_project_tool_ids,
                ]))
                binding_error = ""
                if not projects_tool or not set_project_tool:
                    binding_error = "knowledge control-tool configuration is incomplete"
                else:
                    try:
                        if binding_workspace is None:
                            raise RuntimeError("managed plugin workspace is unavailable")
                        knowledge_binding_path = _write_knowledge_binding(
                            binding_workspace,
                            session_id=active_session_id,
                            project_id=str(
                                (knowledge_runtime or {}).get("project_id") or ""
                            ),
                            mcp_name=knowledge_mcp_name,
                            blocked_tool_ids=blocked_knowledge_tools,
                        )
                    except Exception as exc:
                        binding_error = _one_line_preview(exc)
                        if binding_workspace is not None:
                            with contextlib.suppress(Exception):
                                _remove_file(_knowledge_binding_path(
                                    binding_workspace,
                                    active_session_id,
                                ))
                if binding_error:
                    for pattern in knowledge_tool_patterns:
                        mcp_overrides[pattern] = False
                    await deadline.wait(self._disable_scan_mcp_lease(
                        client,
                        directory,
                        knowledge_mcp_lease,
                        binding_error,
                    ), phase="mcp_cleanup")
                    emit(
                        "session",
                        "KNOWLEDGE_BASE_MCP disabled fallback=continue_task "
                        f"error={binding_error}",
                    )
                else:
                    for pattern in knowledge_tool_patterns:
                        mcp_overrides[pattern] = True
                    for tool_id in blocked_knowledge_tools:
                        mcp_overrides.pop(tool_id, None)
                        mcp_overrides[tool_id] = False
                    emit(
                        "session",
                        "KNOWLEDGE_BASE_MCP project_bound "
                        f"name={knowledge_mcp_name} "
                        "query_tools=dynamic",
                    )
            if scan_mcp_lease is not None and scan_mcp_lease.connected and not source_available:
                emit(
                    "session",
                    "CODE_GRAPH_MCP no_tools fallback=file_tools",
                )
            if mcp_overrides:
                payload["tools"] = mcp_overrides
            if model:
                provider_id, model_id = split_model_id(model)
                payload["model"] = {"providerID": provider_id, "modelID": model_id}
            if system_prompt:
                payload["system"] = system_prompt

            request = asyncio.create_task(
                client.post(
                    f"/session/{active_session_id}/message",
                    params=params,
                    headers=headers,
                    json=payload,
                    timeout=timeout + 30,
                )
            )
            if event_state is not None:
                snapshot_poll_task = asyncio.create_task(
                    self._poll_session_snapshots(
                        client=client,
                        session_id=active_session_id,
                        directory=directory,
                        params=params,
                        headers=headers,
                        state=event_state,
                    )
                )
            try:
                response = await deadline.wait(self._wait_for_response(
                    request=request,
                    timeout=deadline.remaining(),
                    cancel_event=cancel_event,
                ), phase="message")
                message_finished = True
            except (asyncio.TimeoutError, asyncio.CancelledError):
                raise
            except BaseException:
                await deadline.wait(emit_model_request_failure("failure"), phase="response_cleanup")
                raise
            try:
                response.raise_for_status()
            except BaseException:
                await deadline.wait(emit_model_request_failure("failure"), phase="response_cleanup")
                raise
            if event_state:
                event_drain_deadline = (
                    asyncio.get_running_loop().time()
                    + _SERVE_EVENT_DRAIN_TIMEOUT_SECONDS
                )
                while (
                    not event_state.session_terminal
                    and asyncio.get_running_loop().time() < event_drain_deadline
                ):
                    await deadline.wait(asyncio.sleep(0.01), phase="event_drain")
                if snapshot_poll_task is not None:
                    snapshot_poll_task.cancel()
                    with contextlib.suppress(BaseException):
                        await deadline.wait(snapshot_poll_task, phase="response_cleanup")
                    snapshot_poll_task = None
                if event_registered:
                    await deadline.wait(self._unregister_event_state(active_session_id), phase="event_cleanup")
                    event_registered = False
                event_state.flush()
            try:
                response_data = response.json()
            except ValueError:
                (
                    response_failure_reason,
                    response_status_code,
                    response_body_bytes,
                    response_content_type,
                ) = _prompt_response_diagnostic(response)
                recovered_response: dict[str, Any] | None = None
                recovery_failure = "baseline_unknown"
                if response_baseline_known:
                    recovered_response, recovery_failure = (
                        await deadline.wait(_recover_prompt_response(
                            client,
                            session_id=active_session_id,
                            params=params,
                            headers=headers,
                            baseline_message_id=response_baseline_message_id,
                            cancel_event=cancel_event,
                        ), phase="response_recovery")
                    )
                if recovered_response is None:
                    await deadline.wait(emit_model_request_failure("neutral"), phase="response_cleanup")
                    response_description = (
                        "an empty response body"
                        if response_failure_reason == "empty_body"
                        else "a non-JSON response"
                    )
                    content_type_note = (
                        response_content_type or "<missing>"
                    )
                    raise RuntimeError(
                        "OpenCode message endpoint returned "
                        f"{response_description} "
                        f"(status={response_status_code}, "
                        f"content_type={content_type_note}, "
                        f"bytes={response_body_bytes}); "
                        "Session recovery failed: "
                        f"{recovery_failure}"
                    ) from None
                response_data = recovered_response
                emit(
                    "session",
                    "RESPONSE_RECOVERED "
                    f"reason={response_failure_reason} "
                    "source=session_messages "
                    f"status={response_status_code} "
                    f"bytes={response_body_bytes}",
                )
            response_message_id_for_log = _response_message_id(response_data)
            response_model = _response_model(response_data)
            if response_model and on_response_model:
                result = on_response_model(response_model)
                if hasattr(result, "__await__"):
                    await deadline.wait(result, phase="response_callback")
            if event_state is not None and on_file_write is not None:
                await deadline.wait(_replay_current_prompt_file_writes(
                    client,
                    session_id=active_session_id,
                    params=params,
                    headers=headers,
                    baseline_message_id=response_baseline_message_id,
                    response_message_id=_response_message_id(response_data),
                    state=event_state,
                ), phase="file_write_replay")
            assistant_error = _assistant_message_error(response_data)
            if assistant_error is not None:
                error_name = (
                    str(assistant_error.get("name") or "")
                    if isinstance(assistant_error, dict)
                    else ""
                )
                if (
                    error_name == "MessageAbortedError"
                    and cancel_event is not None
                    and cancel_event.is_set()
                ):
                    raise asyncio.CancelledError()
                quota_error = _provider_quota_error(assistant_error)
                if quota_error is not None:
                    await deadline.wait(emit_model_request_failure("quota"), phase="response_cleanup")
                    raise quota_error
                await deadline.wait(emit_model_request_failure(
                    "failure"
                    if _assistant_error_affects_model_health(assistant_error)
                    else "neutral"
                ), phase="response_cleanup")
                raise RuntimeError(
                    _error_summary(assistant_error)
                    or "OpenCode model request failed"
                )
            # Token telemetry cannot turn a completed response into a business
            # timeout. Use only the remaining call budget and keep partial usage.
            await capture_token_usage(response_data, timeout_seconds=deadline.remaining())
            lines = _extract_text(response_data)
            response_text = _extract_response_text(response_data)
            if event_state:
                if isinstance(response_data, dict):
                    event_state.record_message(response_data.get("info"))
                    response_message_id = _response_message_id(response_data)
                    response_parts = response_data.get("parts")
                    if isinstance(response_parts, list):
                        for part in response_parts:
                            if (
                                isinstance(part, dict)
                                and response_message_id
                                and not part.get("messageID")
                            ):
                                part = {
                                    **part,
                                    "messageID": response_message_id,
                                }
                            if not isinstance(part, dict) or part.get("type") not in {
                                "text",
                                "reasoning",
                            }:
                                state = part.get("state") if isinstance(part, dict) else None
                                if (
                                    isinstance(state, dict)
                                    and state.get("status") == "completed"
                                ):
                                    for value in _completed_file_writes(part, state):
                                        event_state.record_file_write(value, replay=True)
                                event_state.handle_part(part)
                event_state.reconcile_text("text", "".join(response_text))
                event_state.flush()
            details = OpenCodePromptResult(
                session_id=active_session_id,
                message_id=_response_message_id(response_data),
                lines=lines,
                text="\n".join(response_text),
                model=response_model,
                token_usage=captured_token_usage,
                raw=response_data,
            )
            if required_bash_commands:
                if command_audit_path is None:
                    raise OpenCodeTaskQualityError(
                        "OpenCode required command audit was not initialized"
                    )
                try:
                    _validate_required_command_audit(
                        command_audit_path,
                        required_bash_commands,
                    )
                except OpenCodeTaskQualityError as exc:
                    exc.prompt_result = details
                    raise
            session_outcome = "success"
            return details if return_details else lines
        except asyncio.TimeoutError as exc:
            session_outcome = "timeout"
            session_error = str(exc) or f"OpenCode call timed out during {deadline.phase}"
            emit("task", f"TIMEOUT phase={deadline.phase} task={task_id} "
                 f"attempt={task_attempt} elapsed={time.monotonic() - deadline.started_at:.3f}s")
            if deadline.phase in {"session_create", "session_permissions", "scan_mcp"}:
                self._mark_serve_restart_required("Session preparation timed out")
            raise
        except asyncio.CancelledError:
            session_outcome = "cancelled"
            raise
        except BaseException as exc:
            session_outcome = "failure"
            session_error = str(exc) or type(exc).__name__
            raise
        finally:
            cleanup_expires = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
            cleanup_cancelled = False
            callbacks_open = False

            async def cleanup(operation, phase, limit=None):
                nonlocal cleanup_cancelled
                expires = cleanup_expires
                if limit is not None:
                    expires = min(expires, time.monotonic() + limit)
                budget = OperationDeadline(0, expires_at=expires)
                try:
                    # Even after the budget expires, enter cleanup so its
                    # local bookkeeping/finally blocks get a chance to run.
                    task = asyncio.ensure_future(operation)
                    retire_task(task)
                    await asyncio.sleep(0)
                    if task.done():
                        return True, task.result()
                    return True, await budget.wait(task, phase=phase)
                except asyncio.CancelledError:
                    if not task.done():
                        task.cancel()
                    cleanup_cancelled = True
                    return False, None
                except Exception as exc:
                    logger.warning("OpenCode cleanup incomplete session=%s phase=%s error=%s",
                                   active_session_id, phase, type(exc).__name__)
                    return False, None

            try:
                if request is not None and not request.done():
                    request.cancel()
                    retire_task(request)
                if event_state:
                    event_state.flush()
                    event_state.on_line = None
                    event_state.on_file_write = None
                if event_registered:
                    await cleanup(self._unregister_event_state(active_session_id), "event_cleanup", 1.0)
                for task in (snapshot_poll_task, event_flush_task):
                    if task is not None:
                        task.cancel()
                        await cleanup(self._cancel_request_task(task), "event_reap", 1.0)
                if session_outcome == "timeout" and deadline.phase == "message":
                    await cleanup(emit_model_request_failure("timeout"), "timeout_notification", 1.0)
                if active_session_id and client is not None and not message_finished:
                    ok, aborted = await cleanup(
                        self._abort_session(client, active_session_id, params, headers),
                        "session_abort", 5.0,
                    )
                    if not ok or not aborted:
                        self._mark_serve_restart_required("Session abort did not complete")
                if request is not None:
                    ok, reaped = await cleanup(
                        self._cancel_request_task(request), "request_reap",
                        _SERVE_REQUEST_REAP_TIMEOUT_SECONDS,
                    )
                    if not ok or not reaped:
                        self._mark_serve_restart_required("Message request did not stop")
                if active_session_id and capture_token_usage is not None:
                    await cleanup(capture_token_usage(response_data), "token_collection",
                                  _SERVE_TOKEN_COLLECTION_TIMEOUT_SECONDS + 0.1)
                usage_open = False
                for binding in (knowledge_binding_path, command_binding_path, command_audit_path):
                    if binding is not None:
                        with contextlib.suppress(Exception):
                            _remove_file(binding)
                if client is not None:
                    ok, _ = await cleanup(client.__aexit__(None, None, None), "http_close")
                    if not ok:
                        self._mark_serve_restart_required("HTTP client cleanup did not complete")
                for lease in reversed(owned_mcp_leases):
                    ok, _ = await cleanup(self._release_scan_mcp(directory, lease), "mcp_release")
                    if not ok:
                        self._mark_serve_restart_required("MCP release did not complete")
                if not await deadline.drain(expires_at=cleanup_expires):
                    self._mark_serve_restart_required("Timed out operation did not stop")
            finally:
                usage_open = False
                if serve_acquired:
                    # This condition protects only local counters; its holders
                    # never await network I/O. Release exactly once, even when
                    # remote cleanup exhausted its budget.
                    await self._release_active_session()
                if session_started:
                    error_note = f" error={_one_line_preview(session_error)}" if session_error else ""
                    correlation_note = f" task={task_id} attempt={task_attempt}" if task_id else ""
                    message_note = (
                        f" message={response_message_id_for_log}"
                        if task_id and response_message_id_for_log else ""
                    )
                    emit("session", f"STOP status={session_outcome} retained=true"
                         f"{correlation_note}{message_note}{error_note}", final=True)
            if cleanup_cancelled or (cancel_event is not None and cancel_event.is_set()):
                raise asyncio.CancelledError()

    async def _session_api_request(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path,
        method: str,
        path: str,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        json_body: Any = None,
    ) -> Any:
        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            serve_port_auto=bool(serve_port_auto),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        await self._acquire_session(key, startup_cwd=config_workspace)
        try:
            await self.ensure_managed_mcp(directory)
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
                trust_env=False,
            ) as client:
                response = await client.request(
                    method,
                    path,
                    params=_serve_context_params(directory),
                    headers=_serve_context_headers(directory),
                    json=json_body,
                )
                response.raise_for_status()
                if not response.content:
                    return None
                return response.json()
        finally:
            await self._release_active_session()

    async def get_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="GET",
            path=f"/session/{session_id}",
            **runtime,
        )

    async def get_session_messages(self, session_id: str, **runtime: Any) -> list[dict[str, Any]]:
        value = await self._session_api_request(
            method="GET",
            path=f"/session/{session_id}/message",
            **runtime,
        )
        return value if isinstance(value, list) else []

    async def get_session_children(self, session_id: str, **runtime: Any) -> list[dict[str, Any]]:
        value = await self._session_api_request(
            method="GET",
            path=f"/session/{session_id}/children",
            **runtime,
        )
        return value if isinstance(value, list) else []

    async def delete_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="DELETE",
            path=f"/session/{session_id}",
            **runtime,
        )

    async def abort_session(self, session_id: str, **runtime: Any) -> Any:
        return await self._session_api_request(
            method="POST",
            path=f"/session/{session_id}/abort",
            **runtime,
        )

    @staticmethod
    def _event_directory_key(directory: Path) -> str:
        return os.path.normcase(os.path.normpath(str(directory)))

    def _ensure_event_channel_locked(self, directory: Path) -> _EventChannelRuntime:
        if not self._global_event_unsupported:
            runtime = self._global_event_channel
            if runtime is None or runtime.task is None or runtime.task.done():
                runtime = _EventChannelRuntime(
                    key="global",
                    path="/global/event",
                    params={},
                    headers={},
                )
                runtime.task = asyncio.create_task(
                    self._run_event_channel(runtime, is_global=True)
                )
                self._global_event_channel = runtime
            return runtime

        directory_key = self._event_directory_key(directory)
        runtime = self._legacy_event_channels.get(directory_key)
        if runtime is None or runtime.task is None or runtime.task.done():
            runtime = _EventChannelRuntime(
                key=f"legacy:{directory_key}",
                path="/event",
                params=_serve_context_params(directory),
                headers=_serve_context_headers(directory),
            )
            runtime.task = asyncio.create_task(
                self._run_event_channel(runtime, is_global=False)
            )
            self._legacy_event_channels[directory_key] = runtime
        return runtime

    async def _register_event_state(
        self,
        session_id: str,
        directory: Path,
        state: _ServeEventState,
    ) -> None:
        directory_key = self._event_directory_key(directory)
        async with self._event_lock:
            self._event_states[session_id] = state
            self._event_directories[session_id] = directory_key

        deadline = asyncio.get_running_loop().time() + _SERVE_EVENT_CONNECT_TIMEOUT_SECONDS
        while True:
            async with self._event_lock:
                runtime = self._ensure_event_channel_locked(directory)
            if runtime.healthy:
                return
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(runtime.ready.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return
            if runtime.healthy:
                return
            if runtime.path != "/global/event" or not self._global_event_unsupported:
                return

    async def _unregister_event_state(self, session_id: str) -> None:
        async with self._event_lock:
            self._event_states.pop(session_id, None)
            self._event_directories.pop(session_id, None)

    def _event_channel_healthy(self, directory: Path) -> bool:
        if not self._global_event_unsupported:
            return bool(self._global_event_channel and self._global_event_channel.healthy)
        runtime = self._legacy_event_channels.get(self._event_directory_key(directory))
        return bool(runtime and runtime.healthy)

    @staticmethod
    def _global_event_payload(event: object) -> object:
        if isinstance(event, dict) and isinstance(event.get("payload"), dict):
            return event["payload"]
        return event

    def _dispatch_event(self, event: object, *, directory_key: str = "") -> bool:
        payload = self._global_event_payload(event)
        if not isinstance(payload, dict):
            return False
        event_type, props = _event_properties(payload)
        if not event_type:
            return False
        if event_type in {"server.connected", "server.heartbeat"}:
            return True
        session_id = _event_session_id(props)
        if not session_id:
            return True
        state = self._event_states.get(session_id)
        if state is None:
            return True
        if directory_key and self._event_directories.get(session_id) != directory_key:
            return True
        _handle_serve_event(payload, state)
        return True

    def _emit_event_diagnostic(self, line: str) -> None:
        state = next(iter(self._event_states.values()), None)
        if state is None:
            logger.debug("OpenCode serve event: %s", line)
            return
        state.emit("session", f"EVENT {line}")

    def _note_event_channel_connected(
        self,
        runtime: _EventChannelRuntime,
        *,
        confirmed_recovery: bool = True,
    ) -> None:
        runtime.healthy = True
        runtime.ready.set()
        runtime.connected_once = True
        runtime.attempts = 0
        if not confirmed_recovery:
            return
        if runtime.key not in self._degraded_event_channels:
            return
        self._degraded_event_channels.discard(runtime.key)
        if self._degraded_event_channels or not self._event_failure_started_at:
            return
        now = time.monotonic()
        downtime = max(0.0, now - self._event_failure_started_at)
        self._emit_event_diagnostic(
            f"status=reconnected downtime={downtime:.1f}s "
            f"attempts={self._event_failure_attempts} "
            f"active_sessions={len(self._event_states)}"
        )
        self._event_failure_started_at = 0.0
        self._event_failure_attempts = 0
        self._event_last_failure_summary_at = 0.0
        self._event_poll_failure_reported = False

    def _note_event_channel_failure(
        self,
        runtime: _EventChannelRuntime,
        *,
        error: object,
        retry_in: float,
    ) -> None:
        runtime.healthy = False
        runtime.attempts += 1
        now = time.monotonic()
        first_failure = not self._degraded_event_channels
        self._degraded_event_channels.add(runtime.key)
        self._event_failure_attempts += 1
        if first_failure:
            self._event_failure_started_at = now
            self._event_last_failure_summary_at = now
            status = "disconnected" if runtime.connected_once else "unavailable"
            self._emit_event_diagnostic(
                f"status={status} active_sessions={len(self._event_states)} "
                f"retry_in={retry_in:.1f}s fallback=polling "
                f"error={_one_line_preview(error)}"
            )
            return
        if now - self._event_last_failure_summary_at < _SERVE_EVENT_FAILURE_SUMMARY_SECONDS:
            return
        self._event_last_failure_summary_at = now
        self._emit_event_diagnostic(
            f"status=unavailable attempts={self._event_failure_attempts} "
            f"active_sessions={len(self._event_states)} retry_in={retry_in:.1f}s "
            "fallback=polling"
        )

    async def _mark_global_event_unsupported(self, runtime: _EventChannelRuntime) -> None:
        runtime.healthy = False
        runtime.ready.set()
        async with self._event_lock:
            self._global_event_unsupported = True
            self._degraded_event_channels.discard(runtime.key)
            directories = {
                directory_key
                for directory_key in self._event_directories.values()
            }
            for directory_key in directories:
                directory = Path(directory_key)
                legacy = self._ensure_event_channel_locked(directory)
                if self._event_failure_started_at:
                    self._degraded_event_channels.add(legacy.key)

    async def _run_event_channel(
        self,
        runtime: _EventChannelRuntime,
        *,
        is_global: bool,
        initial_reconnect_delay: float = _SERVE_EVENT_RECONNECT_DELAY_SECONDS,
    ) -> None:
        generation = self._event_generation
        reconnect_delay = initial_reconnect_delay
        directory_key = "" if is_global else runtime.key.removeprefix("legacy:")
        request_headers = dict(runtime.headers)
        request_headers.update({
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        })
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=None,
                trust_env=False,
            ) as client:
                while True:
                    if generation != self._event_generation:
                        return
                    try:
                        async with client.stream(
                            "GET",
                            runtime.path,
                            params=runtime.params,
                            headers=request_headers,
                        ) as response:
                            if generation != self._event_generation:
                                return
                            status_code = int(getattr(response, "status_code", 200) or 200)
                            if is_global and status_code in {404, 405, 501}:
                                await self._mark_global_event_unsupported(runtime)
                                return
                            response.raise_for_status()
                            content_type = str(
                                getattr(response, "headers", {}).get("content-type", "")
                            ).lower()
                            if content_type and "text/event-stream" not in content_type:
                                if is_global:
                                    await self._mark_global_event_unsupported(runtime)
                                    return
                                raise RuntimeError(
                                    f"unexpected content-type {content_type!r}"
                                )
                            received_event = False
                            async for event in _stream_sse_events(response):
                                if generation != self._event_generation:
                                    return
                                if not self._dispatch_event(event, directory_key=directory_key):
                                    continue
                                payload = self._global_event_payload(event)
                                event_type, _ = _event_properties(payload)
                                confirmed_recovery = event_type != "server.connected"
                                if not received_event:
                                    received_event = True
                                    self._note_event_channel_connected(
                                        runtime,
                                        confirmed_recovery=confirmed_recovery,
                                    )
                                elif confirmed_recovery:
                                    self._note_event_channel_connected(runtime)
                                if confirmed_recovery:
                                    reconnect_delay = _SERVE_EVENT_RECONNECT_DELAY_SECONDS
                            if generation != self._event_generation:
                                return
                            reason = (
                                "event stream closed"
                                if received_event
                                else "event stream closed before server.connected"
                            )
                            self._note_event_channel_failure(
                                runtime,
                                error=reason,
                                retry_in=reconnect_delay,
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if generation != self._event_generation:
                            return
                        self._note_event_channel_failure(
                            runtime,
                            error=exc,
                            retry_in=reconnect_delay,
                        )
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = _next_event_reconnect_delay(reconnect_delay)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if generation != self._event_generation:
                return
            self._note_event_channel_failure(
                runtime,
                error=exc,
                retry_in=reconnect_delay,
            )
            await asyncio.sleep(reconnect_delay)
            if generation != self._event_generation:
                return
            runtime.task = asyncio.create_task(self._run_event_channel(
                runtime,
                is_global=is_global,
                initial_reconnect_delay=_next_event_reconnect_delay(reconnect_delay),
            ))
        finally:
            runtime.healthy = False
            runtime.ready.set()

    async def _poll_session_snapshots(
        self,
        *,
        client: httpx.AsyncClient,
        session_id: str,
        directory: Path,
        params: dict[str, str],
        headers: dict[str, str],
        state: _ServeEventState,
    ) -> None:
        poll_params = dict(params)
        poll_params["limit"] = "2"
        while True:
            if self._event_channel_healthy(directory):
                await asyncio.sleep(0.1)
                continue
            try:
                response = await client.get(
                    f"/session/{session_id}/message",
                    params=poll_params,
                    headers=headers,
                )
                response.raise_for_status()
                message = _latest_assistant_message(response.json(), session_id)
                if message is not None:
                    state.ingest_message_snapshot(message)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self._event_poll_failure_reported:
                    self._event_poll_failure_reported = True
                    self._emit_event_diagnostic(
                        f"status=poll_unavailable fallback=final_response "
                        f"error={_one_line_preview(exc)}"
                    )
            await asyncio.sleep(_SERVE_EVENT_POLL_INTERVAL_SECONDS)

    async def _list_tool_ids(
        self,
        client: httpx.AsyncClient,
        params: dict[str, str],
        headers: dict[str, str],
        *,
        on_line=None,
        tool: str = "opencode",
    ) -> list[str]:
        try:
            response = await client.get("/experimental/tool/ids", params=params, headers=headers)
            response.raise_for_status()
        except Exception as exc:
            if on_line:
                on_line(f"TOOL_DISCOVERY unavailable error={_one_line_preview(exc)}")
            return []
        tool_ids = _tool_ids_from_response(response.json())
        if on_line:
            mcp_tool_ids = [tool_id for tool_id in tool_ids if _tool_source(tool_id) == "mcp"]
            mcp_note = ""
            if mcp_tool_ids:
                mcp_note = (
                    f" mcp_tools={len(mcp_tool_ids)} "
                    f"mcp_names={_one_line_preview(','.join(mcp_tool_ids))}"
                )
            on_line(f"TOOLS count={len(tool_ids)}{mcp_note}")
        return tool_ids

    async def list_models(
        self,
        *,
        tool: str,
        executable: str,
        directory: Path | None = None,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        refresh: bool = False,
    ) -> OpenCodeModelListResult:
        normalized_env_overrides = _normalized_env_overrides(env_overrides)
        key = OpenCodeServeKey(
            tool=tool,
            executable=executable,
            env_hash=_env_hash(normalized_env_overrides),
            config_hash=_config_hash(config_content),
            serve_port_auto=bool(serve_port_auto),
            config_content=config_content or "",
            env_overrides=normalized_env_overrides,
        )
        directory_key = str(directory.resolve()) if directory is not None else ""
        cache_key = (key, directory_key)
        if not refresh:
            cached = self._model_cache.get(cache_key)
            if cached is not None:
                logger.info(
                    "OpenCode serve model list source=cache models=%s config_hash=%s",
                    len(cached),
                    key.config_hash[:12],
                )
                return OpenCodeModelListResult(models=list(cached))

        inflight_key = (cache_key, bool(refresh))
        task = self._model_inflight.get(inflight_key)
        if task is None:
            if refresh:
                self._invalidate_model_cache()
            generation = self._model_cache_generation
            task = asyncio.create_task(self._load_models(
                key=key,
                cache_key=cache_key,
                cache_generation=generation,
                directory=directory,
                config_workspace=config_workspace,
                refresh=refresh,
            ))
            self._model_inflight[inflight_key] = task

            def clear_inflight(done: asyncio.Task[OpenCodeModelListResult]) -> None:
                if self._model_inflight.get(inflight_key) is done:
                    self._model_inflight.pop(inflight_key, None)

            task.add_done_callback(clear_inflight)
        return await asyncio.shield(task)

    def _invalidate_model_cache(self) -> None:
        self._model_cache.clear()
        self._model_cache_generation += 1

    async def _load_models(
        self,
        *,
        key: OpenCodeServeKey,
        cache_key: tuple[OpenCodeServeKey, str],
        cache_generation: int,
        directory: Path | None,
        config_workspace: Path | None,
        refresh: bool,
    ) -> OpenCodeModelListResult:
        async with self._model_fetch_lock:
            if not refresh:
                cached = self._model_cache.get(cache_key)
                if cached is not None:
                    return OpenCodeModelListResult(models=list(cached))

            ensure_started_at = time.monotonic()
            try:
                refresh_deferred = await self._acquire_model_listing(
                    key,
                    startup_cwd=config_workspace,
                )
            except Exception as exc:
                raise RuntimeError(
                    "OpenCode Serve 准备失败（启动或复用阶段）：\n"
                    f"{exc}"
                ) from exc
            ensure_elapsed = time.monotonic() - ensure_started_at
            request_started_at = time.monotonic()
            try:
                try:
                    models = await self._fetch_models(directory)
                except Exception as exc:
                    raise RuntimeError(
                        "OpenCode Serve 模型接口查询失败"
                        "（/provider 或 /config/providers）：\n"
                        f"{exc}"
                    ) from exc
            finally:
                await self._release_model_listing()
            request_elapsed = time.monotonic() - request_started_at
            message = ""
            if refresh_deferred:
                message = (
                    "当前有 OpenCode serve 会话运行，已返回当前模型列表；"
                    "配置重载将在会话结束后的下一次请求生效。"
                )
            if (
                not refresh_deferred
                and cache_generation == self._model_cache_generation
            ):
                self._model_cache[cache_key] = tuple(models)
            logger.info(
                "OpenCode serve model list source=serve models=%s ensure_ms=%s request_ms=%s "
                "refresh=%s refresh_deferred=%s config_hash=%s",
                len(models),
                round(ensure_elapsed * 1000),
                round(request_elapsed * 1000),
                refresh,
                refresh_deferred,
                key.config_hash[:12],
            )
            return OpenCodeModelListResult(models=models, message=message)

    async def _fetch_models(self, directory: Path | None) -> list[OpenCodeModelInfo]:
        params = _serve_context_params(directory)
        headers = _serve_context_headers(directory)
        provider_data: Any = None
        provider_error: Exception | None = None
        provider_elapsed = 0.0
        config_elapsed = 0.0
        used_config_fallback = False

        logger.info(
            "OpenCode serve provider lookup start base_url=%s directory=%s",
            self.base_url,
            directory or "(none)",
        )
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=_SERVE_REQUEST_TIMEOUT_SECONDS,
            trust_env=False,
        ) as client:
            started_at = time.monotonic()
            try:
                response = await client.get("/provider", params=params, headers=headers)
                response.raise_for_status()
                provider_data = response.json()
            except Exception as exc:
                provider_error = exc
            finally:
                provider_elapsed = time.monotonic() - started_at

            providers, provider_payload_valid = self._provider_entries(
                provider_data,
                "all",
                "providers",
            )
            connected = self._connected_provider_ids(provider_data)
            returned_provider_ids = {
                self._provider_id(provider)
                for provider in providers
                if self._provider_id(provider)
            }
            missing_connected = connected - returned_provider_ids
            needs_config_fallback = (
                not provider_payload_valid
                or not providers
                or bool(missing_connected)
            )
            config_providers: list[dict[str, Any]] = []
            config_payload_valid = False
            config_error: Exception | None = None
            if needs_config_fallback:
                used_config_fallback = True
                started_at = time.monotonic()
                try:
                    config_response = await client.get(
                        "/config/providers",
                        params=params,
                        headers=headers,
                        timeout=_SERVE_MODEL_FALLBACK_TIMEOUT_SECONDS,
                    )
                    config_response.raise_for_status()
                    config_data = config_response.json()
                    config_providers, config_payload_valid = self._provider_entries(
                        config_data,
                        "providers",
                    )
                except Exception as exc:
                    config_error = exc
                finally:
                    config_elapsed = time.monotonic() - started_at

        if not provider_payload_valid and not config_payload_valid:
            details = []
            if provider_error is not None:
                details.append(f"/provider: {_one_line_preview(provider_error)}")
            elif provider_data is not None:
                details.append("/provider: invalid response")
            if config_error is not None:
                details.append(f"/config/providers: {_one_line_preview(config_error)}")
            else:
                details.append("/config/providers: invalid response")
            logger.warning(
                "OpenCode serve provider lookup failed provider_ms=%s config_ms=%s "
                "fallback=%s detail=%s",
                round(provider_elapsed * 1000),
                round(config_elapsed * 1000),
                used_config_fallback,
                "; ".join(details),
            )
            raise RuntimeError("OpenCode model listing failed (" + "; ".join(details) + ")")
        if config_error is not None and provider_payload_valid:
            logger.warning(
                "OpenCode config provider fallback unavailable: %s",
                _one_line_preview(config_error),
            )

        models: dict[str, OpenCodeModelInfo] = {}
        for provider in providers + config_providers:
            for item in _provider_models(provider):
                models[item.id] = item
        result = sorted(models.values(), key=lambda item: item.id)
        logger.info(
            "OpenCode serve provider lookup provider_ms=%s config_ms=%s fallback=%s models=%s",
            round(provider_elapsed * 1000),
            round(config_elapsed * 1000),
            used_config_fallback,
            len(result),
        )
        return result

    @staticmethod
    def _provider_entries(data: Any, *keys: str) -> tuple[list[dict[str, Any]], bool]:
        if not isinstance(data, dict):
            return [], False
        for key in keys:
            raw = data.get(key)
            if isinstance(raw, list):
                return [item for item in raw if isinstance(item, dict)], True
        return [], False

    @staticmethod
    def _provider_id(provider: dict[str, Any]) -> str:
        return str(
            provider.get("id")
            or provider.get("providerID")
            or provider.get("name")
            or ""
        ).strip()

    @staticmethod
    def _connected_provider_ids(data: Any) -> set[str]:
        if not isinstance(data, dict) or not isinstance(data.get("connected"), list):
            return set()
        return {
            str(item).strip()
            for item in data["connected"]
            if str(item).strip()
        }

    async def shutdown(self) -> None:
        async with self._lock:
            await self._stop_locked()
        self._dirty = False
        self._restart_required = False
        self._invalidate_model_cache()

    async def update_skill_catalog(
        self,
        needs_update: Callable[[], bool],
        publish: Callable[[], None],
        *,
        cancel_event: Any = None,
    ) -> bool:
        """Drain sessions before publishing Skills; block new acquisitions meanwhile."""
        if not needs_update():
            return False
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError
            try:
                await asyncio.wait_for(self._lock.acquire(), timeout=0.2)
                break
            except asyncio.TimeoutError:
                pass
        try:
            if not needs_update():
                return False
            logger.info("OpenCode Skill update waiting for %s active session(s)", self._active_sessions)
            while self._active_sessions or self._active_model_listings:
                if cancel_event is not None and cancel_event.is_set():
                    raise asyncio.CancelledError
                try:
                    await asyncio.wait_for(self._wait_until_idle_locked(), timeout=0.2)
                except asyncio.TimeoutError:
                    pass
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError
            await self._stop_locked(reason="skill catalog updated")
            # No await between publication and invalidation: cancellation must
            # never leave a live Serve serving a partially updated catalog.
            publish()
            self.mark_dirty()
            logger.info("OpenCode Skill update published; next acquisition loads the new catalog")
            return True
        finally:
            self._lock.release()

    async def _acquire_session(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        async with self._lock:
            serve_mode = await self._ensure_started_locked(key, startup_cwd=startup_cwd)
            async with self._idle:
                self._active_sessions += 1
            return serve_mode

    async def _acquire_model_listing(
        self,
        key: OpenCodeServeKey,
        *,
        startup_cwd: Path | None = None,
    ) -> bool:
        """Acquire a short-lived serve operation and report a deferred reload."""
        async with self._lock:
            if self._proc is not None and self._proc.poll() is not None:
                if not await self._try_adopt_owned_listener_locked():
                    _unregister_owned_serve_process(getattr(self._proc, "pid", None))
                    await self._reset_managed_mcp_process_state()
                    await self._stop_event_hub()
                    self._proc = None
                    self._key = None
                    self._port = None
                    self._listener_pids.clear()
                    self._startup_cwd = None

            refresh_deferred = False
            compatible_process = (
                self._proc is not None
                and self._same_process_key(self._key, key)
            )
            if (
                self._proc is not None
                and self._active_sessions > 0
                and (
                    self._dirty
                    or self._restart_required
                    or not compatible_process
                )
            ):
                # Never make a model picker wait for a scan to finish. Query the
                # current live serve now and keep the reload pending for the next
                # idle acquisition, even when proxy/tool/executable changes make
                # the requested process key incompatible.
                if not self._dirty:
                    self._dirty = True
                    self._serve_config_generation += 1
                    self._invalidate_model_cache()
                refresh_deferred = True
                logger.info(
                    "Deferring %s serve model config reload while %s session(s) are active",
                    key.tool,
                    self._active_sessions,
                )
            elif (
                compatible_process
                and not self._dirty
                and not self._restart_required
            ):
                # Model enumeration reflects the current serve process. Task-local
                # MCP/SKILL config hash churn must not restart an otherwise
                # compatible process just to show the picker.
                pass
            else:
                await self._ensure_started_locked(key, startup_cwd=startup_cwd)
                if self._dirty:
                    refresh_deferred = True

            # A live process handle isn't sufficient evidence that the local
            # endpoint can serve requests. Always gate /provider enumeration on
            # the documented health response, including the reuse path.
            await self._ensure_model_listing_health_locked(
                key,
                startup_cwd=startup_cwd,
            )
            async with self._idle:
                self._active_model_listings += 1
            return refresh_deferred

    async def _release_active_session(self) -> None:
        async with self._idle:
            self._active_sessions = max(0, self._active_sessions - 1)
            if self._active_sessions == 0 and self._active_model_listings == 0:
                self._idle.notify_all()

    async def _release_model_listing(self) -> None:
        async with self._idle:
            self._active_model_listings = max(0, self._active_model_listings - 1)
            if self._active_sessions == 0 and self._active_model_listings == 0:
                self._idle.notify_all()

    async def _wait_for_response(
        self,
        *,
        request: asyncio.Task[httpx.Response],
        timeout: int,
        cancel_event,
    ) -> httpx.Response:
        started = time.monotonic()
        while True:
            if cancel_event and cancel_event.is_set():
                raise asyncio.CancelledError()
            if request.done():
                return await request
            if time.monotonic() - started > timeout:
                raise asyncio.TimeoutError()
            await asyncio.sleep(0.2)

    @staticmethod
    async def _cancel_request_task(request: asyncio.Future) -> bool:
        """Reap cooperative requests without letting transport cleanup stall retry."""
        if not request.done():
            request.cancel()
            retire_task(request)
            await asyncio.wait({request}, timeout=_SERVE_REQUEST_REAP_TIMEOUT_SECONDS)
        if not request.done():
            retire_task(request)
            return False
        with contextlib.suppress(BaseException):
            request.result()
        return True

    @staticmethod
    async def _serve_health_ready(port: int) -> bool:
        try:
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{int(port)}",
                timeout=2.0,
                trust_env=False,
            ) as client:
                response = await client.get("/global/health")
                return response.status_code < 500
        except Exception:
            return False

    async def _probe_model_listing_health(self) -> _ServeHealthResult:
        """Require the documented healthy response before provider enumeration."""
        url = f"{self.base_url}/global/health"
        started_at = time.monotonic()
        logger.info("OpenCode serve model preflight start endpoint=%s", url)
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=2.0,
                trust_env=False,
            ) as client:
                response = await client.get("/global/health")
        except Exception as exc:
            result = _ServeHealthResult(
                healthy=False,
                detail=f"{type(exc).__name__}: {_one_line_preview(exc)}",
            )
        else:
            status_code = int(getattr(response, "status_code", 0) or 0)
            try:
                payload = response.json()
            except Exception as exc:
                result = _ServeHealthResult(
                    healthy=False,
                    status_code=status_code,
                    detail=f"响应不是有效 JSON：{type(exc).__name__}: {_one_line_preview(exc)}",
                )
            else:
                healthy = (
                    status_code == 200
                    and isinstance(payload, dict)
                    and payload.get("healthy") is True
                )
                version = (
                    str(payload.get("version") or "").strip()
                    if isinstance(payload, dict)
                    else ""
                )
                if status_code != 200:
                    detail = f"HTTP {status_code}"
                elif not isinstance(payload, dict):
                    detail = f"响应类型为 {type(payload).__name__}，预期为对象"
                elif payload.get("healthy") is not True:
                    detail = f"healthy={payload.get('healthy')!r}，预期为 true"
                else:
                    detail = ""
                result = _ServeHealthResult(
                    healthy=healthy,
                    status_code=status_code,
                    version=version,
                    detail=detail,
                )

        logger.info(
            "OpenCode serve model preflight result healthy=%s status=%s version=%s "
            "elapsed_ms=%s detail=%s",
            result.healthy,
            result.status_code if result.status_code is not None else "(none)",
            result.version or "(unknown)",
            round((time.monotonic() - started_at) * 1000),
            result.detail or "(none)",
        )
        return result

    async def _ensure_model_listing_health_locked(
        self,
        key: OpenCodeServeKey,
        *,
        startup_cwd: Path | None,
    ) -> None:
        """Health-gate provider lookup and recover one idle unhealthy Serve."""
        result = await self._probe_model_listing_health()
        if result.healthy:
            return

        detail = result.detail or "未返回 healthy=true"
        self._mark_serve_restart_required(
            f"GET /global/health failed before model listing: {detail}",
        )
        if self._active_sessions > 0:
            raise RuntimeError(
                "OpenCode Serve 模型拉取前健康检查失败：\n"
                f"GET /global/health: {detail}\n"
                f"当前仍有 {self._active_sessions} 个活动 Session；"
                "为避免中断任务，本次不重启 Serve，也不会请求 Provider。"
            )

        logger.warning(
            "OpenCode serve model preflight failed while idle; restarting once before "
            "provider lookup detail=%s",
            detail,
        )
        await self._ensure_started_locked(key, startup_cwd=startup_cwd)
        retry = await self._probe_model_listing_health()
        if retry.healthy:
            return

        retry_detail = retry.detail or "未返回 healthy=true"
        self._mark_serve_restart_required(
            f"GET /global/health still failed after restart: {retry_detail}",
        )
        raise RuntimeError(
            "OpenCode Serve 模型拉取前健康检查失败：\n"
            f"GET /global/health: {retry_detail}\n"
            "Serve 已在空闲状态下重启一次，但仍不可用；未请求 Provider。"
        )

    def _record_owned_listener_pids(
        self,
        *,
        launcher_pid: int,
        listener_pids: set[int],
    ) -> None:
        if (
            self._proc is None
            or self._key is None
            or self._port is None
            or not listener_pids
        ):
            return
        self._listener_pids = {
            int(pid)
            for pid in listener_pids
            if int(pid) > 0
        }
        _write_marker(
            self._marker_path,
            proc=self._proc,
            key=self._key,
            port=self._port,
            launcher_pid=launcher_pid,
            listener_pids=self._listener_pids,
        )

    async def _try_adopt_owned_listener_locked(self) -> bool:
        """Adopt a healthy listener left behind by an exited launcher process."""
        proc = self._proc
        key = self._key
        port = self._port
        if proc is None or key is None or port is None or proc.poll() is None:
            return False
        launcher_pid = int(getattr(proc, "pid", 0) or 0)
        if launcher_pid <= 0:
            return False

        marker = _read_marker(self._marker_path)
        if marker is None or marker.get("owner") != _SERVE_MARKER_OWNER:
            return False
        marker_agent_pid = int(marker.get("agent_pid") or 0)
        if marker_agent_pid not in {0, os.getpid()}:
            return False
        if int(marker.get("port") or 0) != port:
            return False
        if launcher_pid not in {
            int(marker.get("pid") or 0),
            int(marker.get("launcher_pid") or 0),
        }:
            return False

        current_listeners = await asyncio.to_thread(_listener_pids_for_port, port)
        known_listeners = set(self._listener_pids)
        raw_marker_listeners = marker.get("listener_pids")
        if isinstance(raw_marker_listeners, list):
            known_listeners.update(
                int(pid)
                for pid in raw_marker_listeners
                if str(pid).isdigit() and int(pid) > 0
            )
        candidates = {
            int(pid)
            for pid in current_listeners
            if int(pid) in known_listeners
        }
        if not candidates:
            _, candidates, _ = await asyncio.to_thread(
                _owned_listener_pids_for_launcher,
                port,
                launcher_pid,
            )
        if not candidates or not await self._serve_health_ready(port):
            return False

        listener_pid = min(candidates)
        _unregister_owned_serve_process(launcher_pid)
        adopted = _AdoptedServeProcess(listener_pid)
        self._proc = adopted
        self._listener_pids = set(candidates)
        _register_owned_serve_process(adopted, self._marker_path)
        _write_marker(
            self._marker_path,
            proc=adopted,
            key=key,
            port=port,
            launcher_pid=launcher_pid,
            listener_pids=self._listener_pids,
        )
        logger.info(
            "OpenCode serve launcher pid %s exited; adopted healthy owned listener pid %s "
            "on 127.0.0.1:%s",
            launcher_pid,
            listener_pid,
            port,
        )
        return True

    async def _ensure_started(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        async with self._lock:
            return await self._ensure_started_locked(key, startup_cwd=startup_cwd)

    async def _ensure_started_locked(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> str:
        had_process = self._proc is not None
        if self._proc is not None and self._proc.poll() is not None:
            if not await self._try_adopt_owned_listener_locked():
                _unregister_owned_serve_process(getattr(self._proc, "pid", None))
                await self._reset_managed_mcp_process_state()
                await self._stop_event_hub()
                self._proc = None
                self._key = None
                self._port = None
                self._listener_pids.clear()
                self._startup_cwd = None
        if (
            self._proc is not None
            and self._key == key
            and not self._dirty
            and not self._restart_required
        ):
            return "reused"
        if (
            self._proc is not None
            and self._same_process_key(self._key, key)
            and self._active_sessions > 0
            and not self._restart_required
        ):
            logger.info(
                "Reusing active %s serve on 127.0.0.1:%s despite pending config change",
                key.tool,
                self._port,
            )
            return "reused"
        reload_generation = self._serve_config_generation
        await self._wait_until_idle_locked()
        failure_generation = self._serve_failure_generation
        config_changed = bool(
            self._key is not None
            and self._key.config_hash != key.config_hash
        )
        if self._restart_required:
            restart_reason = "previous Serve request failure"
        elif self._dirty or config_changed:
            restart_reason = "runtime config changed"
        elif self._proc is not None:
            restart_reason = "Serve runtime key changed"
        else:
            restart_reason = "Serve startup preparation"
        await self._stop_locked(reason=restart_reason, requested_key=key)
        await self._start_locked(key, startup_cwd=startup_cwd)
        if self._serve_config_generation == reload_generation:
            self._dirty = False
        if self._serve_failure_generation == failure_generation:
            self._restart_required = False
        return "restarted" if had_process else "started"

    @staticmethod
    def _same_process_key(current: OpenCodeServeKey | None, requested: OpenCodeServeKey) -> bool:
        return (
            current is not None
            and current.tool == requested.tool
            and current.executable == requested.executable
            and current.env_hash == requested.env_hash
            and current.serve_port_auto == requested.serve_port_auto
        )

    async def _wait_until_idle_locked(self) -> None:
        while self._active_sessions > 0 or self._active_model_listings > 0:
            async with self._idle:
                await self._idle.wait()

    async def _start_locked(
        self,
        key: OpenCodeServeKey,
        startup_cwd: Path | None = None,
    ) -> None:
        resolve_started_at = time.monotonic()
        logger.info(
            "OpenCode serve startup preparation step=resolve_executable status=start "
            "executable_config=%s",
            key.executable,
        )
        executable = _resolve_executable(key.executable)
        logger.info(
            "OpenCode serve startup preparation step=resolve_executable status=complete "
            "executable_resolved=%s elapsed_ms=%s",
            executable,
            round((time.monotonic() - resolve_started_at) * 1000),
        )
        requested_port = _serve_port(key.env_overrides)
        explicit_auto_port = (
            key.serve_port_auto
            and _SERVE_PORT_ENV in dict(key.env_overrides)
        )
        preferred_auto_port = (
            self._auto_port
            if key.serve_port_auto and self._auto_port is not None
            else requested_port
            if explicit_auto_port
            else None
        )
        cleanup_port = preferred_auto_port or requested_port
        cleanup_started_at = time.monotonic()
        logger.info(
            "OpenCode serve startup preparation step=previous_serve_cleanup status=start "
            "port=%s port_mode=%s",
            cleanup_port,
            "auto" if key.serve_port_auto else "fixed",
        )
        cleanup_result = await self._stop_owned_serve_on_port(
            cleanup_port,
        )
        logger.info(
            "OpenCode serve startup preparation step=previous_serve_cleanup "
            "status=complete port=%s elapsed_ms=%s",
            cleanup_port,
            round((time.monotonic() - cleanup_started_at) * 1000),
        )
        excluded_ports = set(cleanup_result.avoided_ports)
        config_started_at = time.monotonic()
        logger.info(
            "OpenCode serve startup preparation step=publish_config status=start "
            "workspace=%s",
            startup_cwd or "(bootstrap)",
        )
        prepared_cwd = _prepare_serve_startup_cwd(key.tool, startup_cwd)
        config_path = _write_serve_config_file(prepared_cwd, key.config_content)
        logger.info(
            "OpenCode serve startup preparation step=publish_config status=complete "
            "config_file_path=%s elapsed_ms=%s",
            config_path,
            round((time.monotonic() - config_started_at) * 1000),
        )

        version_argv = _executable_argv(executable, "--version")
        version_started_at = time.monotonic()
        logger.info(
            "OpenCode serve startup preparation step=version_probe status=start "
            "timeout_seconds=%s",
            _SERVE_VERSION_PROBE_TIMEOUT_SECONDS,
        )
        version_output = await _run_command_text_async(
            version_argv,
            _SERVE_VERSION_PROBE_TIMEOUT_SECONDS,
        )
        executable_version = _one_line_preview(version_output, 200)
        logger.info(
            "OpenCode serve startup preparation step=version_probe status=%s "
            "executable_version=%s elapsed_ms=%s",
            "complete" if executable_version else "unavailable",
            executable_version or "(unknown)",
            round((time.monotonic() - version_started_at) * 1000),
        )
        attempted_ports: list[int] = []
        generic_retry_used = False
        port = (
            preferred_auto_port
            if key.serve_port_auto and preferred_auto_port is not None
            else _allocate_loopback_port(excluded_ports)
            if key.serve_port_auto
            else requested_port
        )

        if key.serve_port_auto and port in excluded_ports:
            attempted_ports.append(port)
            next_port = _allocate_loopback_port(
                set(attempted_ports) | excluded_ports,
            )
            logger.warning(
                "OpenCode auto port 127.0.0.1:%s is still draining after its "
                "previous Serve exited; retrying on 127.0.0.1:%s cleanup=%s",
                port,
                next_port,
                cleanup_result.detail,
            )
            port = next_port

        while True:
            probe = _probe_serve_port(port)
            listeners = (
                set(_listener_pids_for_port(port))
                if probe.connectable
                else set()
            )
            if not probe.reusable:
                attempted_ports.append(port)
                if (
                    key.serve_port_auto
                    and len(attempted_ports) < _SERVE_AUTO_PORT_MAX_ATTEMPTS
                ):
                    next_port = _allocate_loopback_port(
                        set(attempted_ports) | excluded_ports,
                    )
                    logger.warning(
                        "OpenCode auto port 127.0.0.1:%s is unavailable; "
                        "retrying on 127.0.0.1:%s listeners=%s bind_error=%s",
                        port,
                        next_port,
                        sorted(listeners),
                        probe.bind_error or "",
                    )
                    port = next_port
                    continue
                error = RuntimeError(_port_busy_message(
                    port,
                    auto_port=key.serve_port_auto,
                    listener_pids=listeners,
                    bind_error=probe.bind_error,
                ))
                raise RuntimeError(_serve_startup_context_message(
                    error,
                    auto_port=key.serve_port_auto,
                    attempted_ports=attempted_ports,
                    executable_version=executable_version,
                )) from error

            attempted_ports.append(port)
            try:
                await self._start_once_locked(
                    key,
                    executable=executable,
                    executable_version=executable_version,
                    port=port,
                    prepared_cwd=prepared_cwd,
                    config_path=config_path,
                    attempt=len(attempted_ports),
                )
            except Exception as exc:
                retry_kind = _serve_startup_retry_kind(exc)
                can_retry = (
                    key.serve_port_auto
                    and len(attempted_ports) < _SERVE_AUTO_PORT_MAX_ATTEMPTS
                    and (
                        retry_kind == "bind"
                        or retry_kind == "health"
                        or (retry_kind == "generic" and not generic_retry_used)
                    )
                )
                if can_retry:
                    if retry_kind == "generic":
                        generic_retry_used = True
                    next_port = _allocate_loopback_port(
                        set(attempted_ports) | excluded_ports,
                    )
                    logger.warning(
                        "OpenCode serve startup failed on auto port %s (%s); "
                        "retrying on port %s",
                        port,
                        retry_kind,
                        next_port,
                    )
                    port = next_port
                    continue
                if key.serve_port_auto:
                    # Do not pin a later task to the endpoint whose replacement
                    # never passed the health gate.
                    self._auto_port = None
                context_message = _serve_startup_context_message(
                    exc,
                    auto_port=key.serve_port_auto,
                    attempted_ports=attempted_ports,
                    executable_version=executable_version,
                )
                if isinstance(exc, OpenCodeServeStartupError):
                    raise OpenCodeServeStartupError(
                        context_message,
                        retry_kind=exc.retry_kind,
                    ) from exc
                raise RuntimeError(context_message) from exc

            if key.serve_port_auto:
                self._auto_port = port
            return

    async def _start_once_locked(
        self,
        key: OpenCodeServeKey,
        *,
        executable: str,
        executable_version: str,
        port: int,
        prepared_cwd: Path,
        config_path: Path,
        attempt: int,
    ) -> None:
        existing_pids = _current_process_owned_serve_pids()
        if self._proc is not None or self._port is not None or existing_pids:
            raise RuntimeError(
                "Refusing to start a second Agent-owned OpenCode Serve; "
                f"manager_pid={getattr(self._proc, 'pid', '')} "
                f"manager_port={self._port or ''} "
                f"registered_pid(s)={','.join(str(pid) for pid in existing_pids)}"
            )
        env = {
            name: value
            for name, value in os.environ.items()
            if name.lower() not in _SERVE_PROXY_ENV_NAMES
        }
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        for name, value in key.env_overrides:
            if name.lower() in _SERVE_PROXY_ENV_NAMES:
                continue
            if name.lower() == _SERVE_NO_PROXY_ENV_NAME:
                env[name] = _append_no_proxy_env_value(env.get(name), value)
            else:
                env[name] = value
        # The resolved config is file-backed. Environment overrides are never
        # allowed to re-introduce content injection or ambient user config.
        for name in (
            "OPENCODE_CONFIG",
            "OPENCODE_CONFIG_PATH",
            "OPENCODE_CONFIG_CONTENT",
        ):
            env.pop(name, None)
        isolated_config_home = prepared_cwd / _SERVE_ISOLATED_CONFIG_DIRNAME
        isolated_config_home.mkdir(parents=True, exist_ok=True)
        env["XDG_CONFIG_HOME"] = str(isolated_config_home)
        env["OPENCODE_CONFIG_DIR"] = str(prepared_cwd)
        env[_SERVE_PORT_ENV] = str(port)
        env.pop("OPENCODE_SERVER_PASSWORD", None)
        env.pop("OPENCODE_SERVER_USERNAME", None)
        cmd = _executable_argv(
            executable,
            "serve",
            "--hostname",
            "127.0.0.1",
            "--port",
            str(port),
        )
        kwargs: dict[str, Any] = {}
        if sys.platform != "win32":
            kwargs["start_new_session"] = True
        startup_log_path = _new_serve_startup_log_path(key.tool, port)
        self._startup_log_path = startup_log_path
        _log_serve_startup_debug(
            key=key,
            cmd=cmd,
            port=port,
            cwd=prepared_cwd,
            env=env,
            startup_log_path=startup_log_path,
            popen_kwargs=kwargs,
            marker_path=self._marker_path,
            config_path=config_path,
            port_mode="auto" if key.serve_port_auto else "fixed",
            attempt=attempt,
            executable_version=executable_version,
            executable_resolved=executable,
            version_argv=_executable_argv(executable, "--version"),
        )
        try:
            with startup_log_path.open("ab") as startup_log:
                self._proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=startup_log,
                    stderr=subprocess.STDOUT,
                    env=env,
                    cwd=str(prepared_cwd),
                    **kwargs,
                )
        except Exception:
            self._startup_log_path = None
            _remove_file(startup_log_path)
            raise
        self._listener_pids.clear()
        _register_owned_serve_process(self._proc, self._marker_path)
        self._key = key
        self._port = port
        self._startup_cwd = prepared_cwd
        _write_marker(self._marker_path, proc=self._proc, key=key, port=port)
        try:
            await self._wait_health_locked(startup_log_path)
        except Exception as startup_error:
            try:
                await self._stop_locked(reason="startup health failure cleanup")
            except Exception as cleanup_error:
                raise RuntimeError(
                    f"{startup_error}\n\n"
                    "OpenCode Serve cleanup after startup failure also failed: "
                    f"{cleanup_error}"
                ) from startup_error
            raise
        _remove_file(startup_log_path)
        config_note = f" config_hash={key.config_hash[:12]}" if key.config_hash else ""
        logger.info(
            "Started %s serve on 127.0.0.1:%s cwd=%s port_mode=%s%s",
            key.tool,
            port,
            prepared_cwd,
            "auto" if key.serve_port_auto else "fixed",
            config_note,
        )

    async def _stop_owned_serve_on_port(
        self,
        port: int,
    ) -> _PreviousServeCleanupResult:
        marker = _read_marker(self._marker_path)
        if marker is None or marker.get("owner") != _SERVE_MARKER_OWNER:
            return _PreviousServeCleanupResult()
        if sys.platform == "win32":
            return await asyncio.to_thread(
                _stop_previous_windows_serve_marker,
                marker,
                self._marker_path,
                port,
            )
        marker_agent_pid = int(marker.get("agent_pid") or 0)
        if (
            marker_agent_pid > 0
            and marker_agent_pid != os.getpid()
            and _pid_is_running(marker_agent_pid)
        ):
            logger.info(
                "Leaving OpenCode serve marker owned by live Agent pid %s unchanged",
                marker_agent_pid,
            )
            return _PreviousServeCleanupResult()
        marker_port = int(marker.get("port") or port)
        pid = int(marker.get("pid") or 0)
        known_listener_pids = _marker_listener_pids(marker)
        if not _pid_is_running(pid):
            reclaim_result: _PortReclaimResult | None = None
            if marker_port > 0 and known_listener_pids:
                reclaim_result = await asyncio.to_thread(
                    _reclaim_serve_port,
                    marker_port,
                    reason="stale Agent-owned serve marker",
                    allowed_pids=known_listener_pids,
                )
            remaining_listener_pids = (
                set()
                if reclaim_result is not None and reclaim_result.released
                else (
                    await asyncio.to_thread(
                        _blocking_listener_pids_for_port,
                        marker_port,
                        known_listener_pids,
                    )
                    if marker_port > 0 and known_listener_pids
                    else set()
                )
            )
            if remaining_listener_pids:
                raise RuntimeError(
                    "Previous Agent-owned OpenCode Serve listener did not stop; "
                    f"pid(s)={','.join(str(item) for item in sorted(remaining_listener_pids))} "
                    f"port={marker_port} ownership marker was retained"
                    + (
                        f"; reclaim={reclaim_result.detail}"
                        if reclaim_result is not None
                        else ""
                    )
                )
            _remove_marker(self._marker_path)
            return _PreviousServeCleanupResult()
        if not _marker_matches_serve_process(marker):
            return _PreviousServeCleanupResult()
        logger.info(
            "Stopping previous Agent-owned %s serve pid %s on 127.0.0.1:%s",
            marker.get("tool") or "opencode",
            pid,
            marker_port,
        )
        tree_stopped = await asyncio.to_thread(_terminate_process_tree, pid)
        reclaim_result = None
        if marker_port > 0 and known_listener_pids:
            reclaim_result = await asyncio.to_thread(
                _reclaim_serve_port,
                marker_port,
                reason="Agent-owned serve process tree left listener behind",
                allowed_pids=known_listener_pids,
            )
        remaining_listener_pids = (
            set()
            if reclaim_result is not None and reclaim_result.released
            else (
                await asyncio.to_thread(
                    _blocking_listener_pids_for_port,
                    marker_port,
                    known_listener_pids,
                )
                if marker_port > 0 and known_listener_pids
                else set()
            )
        )
        if tree_stopped is False or remaining_listener_pids:
            raise RuntimeError(
                "Previous Agent-owned OpenCode Serve process tree did not stop; "
                f"pid={pid} listener_pid(s)="
                f"{','.join(str(item) for item in sorted(remaining_listener_pids))} "
                f"port={marker_port} ownership marker was retained"
                + (
                    f"; reclaim={reclaim_result.detail}"
                    if reclaim_result is not None
                    else ""
                )
            )
        _remove_marker(self._marker_path)
        return _PreviousServeCleanupResult()

    async def _wait_health_locked(self, startup_log_path: Path | None = None) -> None:
        started_at = time.monotonic()
        deadline = started_at + _SERVE_START_TIMEOUT_SECONDS
        next_progress_at = started_at + _SERVE_HEALTH_PROGRESS_INTERVAL_SECONDS
        output_cursor = _ServeStartupLogCursor()
        config_content = self._key.config_content if self._key else ""
        last_health_detail = "尚未收到响应"

        def forward_startup_output(*, final: bool = False) -> None:
            _log_serve_startup_output_updates(
                startup_log_path,
                output_cursor,
                config_content=config_content,
                final=final,
            )

        try:
            while time.monotonic() < deadline:
                forward_startup_output()
                if self._proc is not None and self._proc.poll() is not None:
                    if await self._try_adopt_owned_listener_locked():
                        return
                    cwd_note = f" startup_cwd={self._startup_cwd}" if self._startup_cwd else ""
                    raise RuntimeError(_with_serve_startup_log(
                        f"OpenCode serve exited during startup with code {self._proc.returncode}{cwd_note}",
                        startup_log_path,
                        config_content=config_content,
                    ))
                try:
                    async with httpx.AsyncClient(
                        base_url=self.base_url,
                        timeout=2.0,
                        trust_env=False,
                    ) as client:
                        response = await client.get("/global/health")
                        last_health_detail = f"HTTP {response.status_code}"
                        health_payload: object = None
                        if response.status_code == 200:
                            try:
                                health_payload = response.json()
                            except (TypeError, ValueError) as exc:
                                last_health_detail = (
                                    f"HTTP 200, invalid JSON: {_one_line_preview(exc)}"
                                )
                            else:
                                if not (
                                    isinstance(health_payload, dict)
                                    and health_payload.get("healthy") is True
                                ):
                                    last_health_detail = (
                                        "HTTP 200, healthy flag is not true"
                                    )
                        if (
                            response.status_code == 200
                            and isinstance(health_payload, dict)
                            and health_payload.get("healthy") is True
                        ):
                            proc = self._proc
                            launcher_pid = int(getattr(proc, "pid", 0) or 0)
                            ownership_mismatch = False
                            if launcher_pid > 0 and self._port is not None:
                                listeners, owned, ownership_verified = await asyncio.to_thread(
                                    _owned_listener_pids_for_launcher,
                                    self._port,
                                    launcher_pid,
                                )
                                ownership_mismatch = (
                                    bool(listeners)
                                    and ownership_verified
                                    and not owned
                                )
                                if owned:
                                    self._record_owned_listener_pids(
                                        launcher_pid=launcher_pid,
                                        listener_pids=owned,
                                    )
                            if ownership_mismatch:
                                last_health_detail = (
                                    f"HTTP {response.status_code}, listener ownership mismatch"
                                )
                                logger.debug(
                                    "Ignoring OpenCode health response on 127.0.0.1:%s "
                                    "because its listener is outside launcher pid %s's process tree",
                                    self._port,
                                    launcher_pid,
                                )
                            else:
                                if self._proc is not None and self._proc.poll() is not None:
                                    if await self._try_adopt_owned_listener_locked():
                                        return
                                    cwd_note = (
                                        f" startup_cwd={self._startup_cwd}"
                                        if self._startup_cwd
                                        else ""
                                    )
                                    raise RuntimeError(_with_serve_startup_log(
                                        "OpenCode serve exited during startup with code "
                                        f"{self._proc.returncode}{cwd_note}",
                                        startup_log_path,
                                        config_content=config_content,
                                    ))
                                logger.info(
                                    "OpenCode serve startup health ready endpoint=%s/global/health "
                                    "status=%s elapsed_ms=%s",
                                    self.base_url,
                                    response.status_code,
                                    round((time.monotonic() - started_at) * 1000),
                                )
                                return
                except Exception as exc:
                    last_health_detail = f"{type(exc).__name__}: {_one_line_preview(exc)}"
                    if self._proc is not None and self._proc.poll() is not None:
                        if await self._try_adopt_owned_listener_locked():
                            return
                        cwd_note = (
                            f" startup_cwd={self._startup_cwd}"
                            if self._startup_cwd
                            else ""
                        )
                        raise RuntimeError(_with_serve_startup_log(
                            "OpenCode serve exited during startup with code "
                            f"{self._proc.returncode}{cwd_note}",
                            startup_log_path,
                            config_content=config_content,
                        ))

                now = time.monotonic()
                if now >= next_progress_at:
                    logger.info(
                        "OpenCode serve startup waiting endpoint=%s/global/health "
                        "elapsed_s=%.1f pid=%s last_health=%s startup_log_path=%s",
                        self.base_url,
                        now - started_at,
                        int(getattr(self._proc, "pid", 0) or 0),
                        last_health_detail,
                        startup_log_path or "(none)",
                    )
                    next_progress_at = now + _SERVE_HEALTH_PROGRESS_INTERVAL_SECONDS
                await asyncio.sleep(_SERVE_HEALTH_POLL_INTERVAL_SECONDS)
            cwd_note = f" startup_cwd={self._startup_cwd}" if self._startup_cwd else ""
            raise OpenCodeServeStartupError(_with_serve_startup_log(
                f"OpenCode serve did not become healthy{cwd_note}; "
                f"last_health={last_health_detail}",
                startup_log_path,
                config_content=config_content,
            ), retry_kind="health")
        finally:
            forward_startup_output(final=True)

    async def _abort_session(
        self,
        client: httpx.AsyncClient,
        session_id: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> bool:
        try:
            response = await client.post(
                f"/session/{session_id}/abort",
                params=params,
                headers=headers,
                timeout=5.0,
            )
            response.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Failed to abort OpenCode session %s: %s", session_id, exc)
            return False

    async def _stop_event_hub(self, *, expires_at: float | None = None) -> None:
        self._event_generation += 1
        async with self._event_lock:
            channels = [
                channel
                for channel in (
                    [self._global_event_channel]
                    + list(self._legacy_event_channels.values())
                )
                if channel is not None
            ]
            tasks = [
                channel.task
                for channel in channels
                if channel.task is not None and not channel.task.done()
            ]
            self._global_event_channel = None
            self._legacy_event_channels.clear()
            self._global_event_unsupported = False
            self._event_states.clear()
            self._event_directories.clear()
            self._degraded_event_channels.clear()
            self._event_failure_started_at = 0.0
            self._event_failure_attempts = 0
            self._event_last_failure_summary_at = 0.0
            self._event_poll_failure_reported = False
        if not await cancel_tasks_bounded(
            tasks, expires_at=expires_at if expires_at is not None else time.monotonic() + CLEANUP_TIMEOUT_SECONDS,
        ):
            logger.warning("OpenCode event cleanup timed out; retired old event channels")

    async def _reset_managed_mcp_process_state(self, *, expires_at: float | None = None) -> None:
        self._process_generation += 1
        tasks = [task for task in self._managed_mcp_tasks.values() if not task.done()]
        self._managed_mcp_tasks.clear()
        # Clear directory ownership before cancellation callbacks run. Otherwise
        # a cancelled sync with no recorded status can schedule a replacement
        # task against the serve process that is currently being stopped.
        self._managed_mcp_directories.clear()
        self._managed_mcp_status.clear()
        self._managed_mcp_applied.clear()
        self._managed_mcp_locks.clear()
        self._managed_mcp_force_pending.clear()
        self._scan_mcp_states.clear()
        self._scan_mcp_conditions.clear()
        self._scan_mcp_names.clear()
        if not await cancel_tasks_bounded(
            tasks, expires_at=expires_at if expires_at is not None else time.monotonic() + CLEANUP_TIMEOUT_SECONDS,
        ):
            logger.warning("OpenCode MCP cleanup timed out; retired old MCP synchronization")

    async def _stop_locked(
        self,
        *,
        reason: str = "serve shutdown",
        requested_key: OpenCodeServeKey | None = None,
    ) -> None:
        cleanup_expires = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        await self._reset_managed_mcp_process_state(expires_at=cleanup_expires)
        await self._stop_event_hub(expires_at=cleanup_expires)
        proc = self._proc
        port = self._port
        listener_pids = set(self._listener_pids)
        startup_log_path = self._startup_log_path
        self._startup_log_path = None
        if proc is None:
            _remove_file(startup_log_path)
            return
        pid = int(getattr(proc, "pid", 0) or 0)
        current_config_hash = self._key.config_hash if self._key is not None else ""
        requested_config_hash = (
            requested_key.config_hash if requested_key is not None else ""
        )
        logger.info(
            "OpenCode Serve stop requested pid=%s port=%s reason=%s dirty=%s "
            "restart_required=%s config_changed=%s current_config_hash=%s "
            "requested_config_hash=%s",
            pid,
            port or "",
            reason,
            self._dirty,
            self._restart_required,
            bool(
                requested_key is not None
                and current_config_hash != requested_config_hash
            ),
            current_config_hash[:12] or "(none)",
            requested_config_hash[:12] or "(none)",
        )
        stopped = True
        try:
            if pid > 0:
                stopped = False
                record = _owned_serve_process(pid) or _OwnedServeProcess(
                    owner_pid=os.getpid(),
                    pid=pid,
                    proc=proc,
                    marker_path=self._marker_path,
                    process_group_id=_owned_process_group_id(pid),
                )
                stopped = await asyncio.to_thread(
                    _stop_owned_serve_record,
                    record,
                    reason=reason,
                    port=port,
                    listener_pids=listener_pids,
                )
        except BaseException:
            self._restart_required = True
            raise
        finally:
            _remove_file(startup_log_path)
        if not stopped:
            self._restart_required = True
            raise RuntimeError(
                "OpenCode Serve process tree did not stop completely; "
                f"pid={pid} port={port or ''} ownership marker was retained"
            )
        _unregister_owned_serve_process(pid)
        self._proc = None
        self._port = None
        self._key = None
        self._listener_pids.clear()
        self._startup_cwd = None


_manager: OpenCodeServeManager | None = None


def _serve_context_params(
    directory: Path | None,
) -> dict[str, str]:
    params: dict[str, str] = {}
    if directory is not None:
        params["directory"] = str(directory)
    return params


def _serve_context_headers(directory: Path | None) -> dict[str, str]:
    if directory is None:
        return {}
    return {"x-opencode-directory": quote(str(directory), safe="/:\\")}


def get_serve_manager() -> OpenCodeServeManager:
    """Return the process singleton without starting the Serve child yet."""
    global _manager
    if _manager is None:
        _manager = OpenCodeServeManager()
    return _manager


def mark_serve_config_dirty() -> None:
    if _manager is not None:
        _manager.mark_dirty()


async def shutdown_serve_manager() -> None:
    """Stop and discard the singleton so a later task can recreate it."""
    global _manager
    manager = _manager
    _manager = None
    if manager is not None:
        await manager.shutdown()
