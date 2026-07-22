"""Global registry of active MCP servers.

Allows the FP reviewer to reuse an already-running MCP server when the
same project is currently being scanned, instead of starting a second one
and conflicting with the scanner's backend config.

Maps resolved project_path → (mcp_port, scan_id).
scan_id is the ID of the scan that owns the MCP server; it is needed so
the FP reviewer can pass the correct project_id in its opencode prompt
(the MCP resolves the code index as {projects_dir}/{scan_id}/code_index.db).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

# project_path (resolved str) → (mcp_port, scan_id)
_registry: dict[str, tuple[int, str]] = {}


def register(project_path: Path, mcp_port: int, scan_id: str) -> None:
    """Called by scanner when it successfully starts a local MCP server."""
    _registry[str(project_path.resolve())] = (mcp_port, scan_id)


def unregister(project_path: Path) -> None:
    """Called by scanner in its finally block when the MCP server is stopped."""
    _registry.pop(str(project_path.resolve()), None)


def lookup(project_path: Path) -> Optional[tuple[int, str]]:
    """Return (mcp_port, scan_id) if a scan is actively serving MCP for this project.

    Returns None if no active scan is using MCP for this project path.
    """
    return _registry.get(str(project_path.resolve()))
