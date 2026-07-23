"""Self-contained Task Agent framework backed by OpenCode-compatible Serve."""

from .api import (
    OpenCodeResult,
    opencode_task_context,
    run_opencode_task,
    run_sync_component,
)
from .host import OpenCodeHostBindings, OpenCodeSessionRuntime, configure_opencode


async def shutdown_opencode() -> None:
    """Stop the managed Serve process and reset lazy component singletons."""
    from .host import _reset_standalone_opencode_configuration
    from .serve_client import shutdown_serve_manager
    from .task_service import reset_opencode_task_service

    await shutdown_serve_manager()
    reset_opencode_task_service()
    _reset_standalone_opencode_configuration()


__all__ = [
    "OpenCodeHostBindings",
    "OpenCodeResult",
    "OpenCodeSessionRuntime",
    "configure_opencode",
    "opencode_task_context",
    "run_opencode_task",
    "run_sync_component",
    "shutdown_opencode",
]
