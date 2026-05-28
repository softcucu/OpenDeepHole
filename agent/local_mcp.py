"""Local MCP server for agent opencode mode.

Starts the MCP server in-process on a background thread so that opencode CLI
can call the code-query tools against the locally indexed source.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalMCPServer:
    """Runs the MCP server in-process on a background daemon thread."""

    def __init__(self) -> None:
        self.port: int = _find_free_port()
        self._server = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the server and block until it is ready. Returns port number."""
        import uvicorn
        from mcp.server.fastmcp import FastMCP
        from mcp_server.tools import register_tools

        mcp = FastMCP("OpenDeepHole Code Tools")
        register_tools(mcp)
        app = mcp.streamable_http_app()

        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()

        self._wait_ready()
        return self.port

    def _wait_ready(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)

    def stop(self) -> None:
        from mcp_server.tools import clear_db_cache
        clear_db_cache()
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
