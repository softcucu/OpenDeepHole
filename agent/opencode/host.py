"""Host configuration boundary for the standalone OpenCode component.

The component owns task scheduling, sessions and the Serve process.  A host
only supplies configuration data and the small pieces that are inherently
application-specific, such as the resolved workspace and MCP selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class OpenCodeInvocationMetadata:
    """Portable description of the runtime that handled one model request."""

    agent_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    backend: str = ""
    tool: str = ""
    model_id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    required_capability: str = ""
    task_id: str = ""
    attempt: int = 0
    started_at: str = ""
    serve_session_id: str = ""

    def model_dump(self) -> dict[str, Any]:
        """Match the small serialization surface used by OpenDeepHole callers."""
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
        }


@dataclass(frozen=True)
class OpenCodeSessionRuntime:
    """Fully resolved inputs needed to acquire and call one Serve process."""

    directory: Path
    tool: str
    executable: str
    model: str = ""
    config_workspace: Path | None = None
    config_content: str | None = None
    env_overrides: dict[str, str] = field(default_factory=dict)

    def kwargs(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "executable": self.executable,
            "directory": self.directory,
            "config_workspace": self.config_workspace,
            "config_content": self.config_content,
            "env_overrides": dict(self.env_overrides),
        }


@dataclass(frozen=True)
class OpenCodeHostBindings:
    """Callbacks required by the framework without importing its host."""

    get_config: Callable[[], Any]
    get_workspace: Callable[[], Path]
    build_session_runtime: Callable[[Any, Any, Path], OpenCodeSessionRuntime]
    disabled_source_mcp_tools: Callable[[Path], tuple[str, ...]] = lambda _directory: ()


_bindings: OpenCodeHostBindings | None = None
_binding_source = ""
_binding_identity: Path | None = None
_binding_context: Any = None


def _set_opencode_configuration(
    bindings: OpenCodeHostBindings,
    *,
    source: str,
    identity: Path | None = None,
    context: Any = None,
) -> None:
    if not isinstance(bindings, OpenCodeHostBindings):
        raise TypeError("bindings must be an OpenCodeHostBindings instance")
    global _bindings, _binding_source, _binding_identity, _binding_context
    _bindings = bindings
    _binding_source = source
    _binding_identity = identity
    _binding_context = context


def configure_opencode(bindings: OpenCodeHostBindings) -> None:
    """Register host configuration without creating a manager or Serve process."""
    _set_opencode_configuration(bindings, source="host")


def _configure_standalone_opencode(
    bindings: OpenCodeHostBindings,
    *,
    config_path: Path,
    context: Any,
) -> None:
    """Register file-backed bindings owned by the standalone bootstrap."""
    _set_opencode_configuration(
        bindings,
        source="standalone",
        identity=config_path.resolve(),
        context=context,
    )


def _get_opencode_configuration_state() -> tuple[str, Path | None, Any]:
    return _binding_source, _binding_identity, _binding_context


def get_host_bindings() -> OpenCodeHostBindings:
    bindings = _bindings
    if bindings is None:
        raise RuntimeError(
            "OpenCode component is not configured; call configure_opencode() "
            "before run_opencode_task()"
        )
    return bindings


def reset_opencode_configuration() -> None:
    """Clear host bindings for tests or complete host teardown."""
    global _bindings, _binding_source, _binding_identity, _binding_context
    _bindings = None
    _binding_source = ""
    _binding_identity = None
    _binding_context = None


def _reset_standalone_opencode_configuration() -> None:
    """Clear configuration only when it came from the standalone YAML file."""
    if _binding_source == "standalone":
        reset_opencode_configuration()
