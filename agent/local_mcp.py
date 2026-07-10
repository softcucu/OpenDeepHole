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

    def __init__(self, project_dir: Path | str | None = None) -> None:
        self.port: int = _find_free_port()
        self.project_dir = Path(project_dir).resolve() if project_dir is not None else None
        self._server = None
        self._thread: threading.Thread | None = None
        self._thread_error: BaseException | None = None

    def start(self) -> int:
        """Start the server and block until it is ready. Returns port number."""
        import uvicorn
        from mcp_server.factory import create_mcp_server

        mcp = create_mcp_server(project_dir=self.project_dir)
        app = mcp.streamable_http_app()

        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self._server = uvicorn.Server(config)
        self._thread_error = None
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()

        try:
            self._wait_ready()
        except Exception:
            self.stop()
            raise
        return self.port

    def _run_server(self) -> None:
        try:
            self._server.run()
        except BaseException as exc:
            self._thread_error = exc

    def _wait_ready(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._thread is not None and not self._thread.is_alive():
                error = RuntimeError(
                    f"Local MCP server exited before readiness on 127.0.0.1:{self.port}"
                )
                if self._thread_error is not None:
                    raise error from self._thread_error
                raise error
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        if self._thread is not None and not self._thread.is_alive():
            error = RuntimeError(
                f"Local MCP server exited before readiness on 127.0.0.1:{self.port}"
            )
            if self._thread_error is not None:
                raise error from self._thread_error
            raise error
        raise TimeoutError(
            f"Timed out after {timeout:.1f}s waiting for local MCP server "
            f"on 127.0.0.1:{self.port}"
        )

    def stop(self) -> None:
        from mcp_server.tools import clear_db_cache
        clear_db_cache(self.project_dir)
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        self._thread_error = None

    def restart(self) -> int:
        """Restart the in-process MCP server while keeping the same port."""
        self.stop()
        return self.start()
