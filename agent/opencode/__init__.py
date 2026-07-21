"""Self-contained OpenCode task and serve management component."""

from .api import OpenCodeResult, run_opencode_task
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
    "run_opencode_task",
    "shutdown_opencode",
]
