"""Agent-owned shared MCP gateway for OpenCode source-query tools."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path


_gateway_lock = threading.RLock()
_gateway_port: int | None = None
_gateway_server = None
_gateway_thread: threading.Thread | None = None
_gateway_thread_error: BaseException | None = None


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalMCPServer:
    """Runs the MCP server in-process on a background daemon thread."""

    def __init__(
        self,
        project_dir: Path | str | None = None,
        project_id: str | None = None,
    ) -> None:
        self.port: int = _gateway_port or _find_free_port()
        self.project_dir = Path(project_dir).resolve() if project_dir is not None else None
        self.project_id = str(project_id or "").strip() or "*"
        self._server = None
        self._thread: threading.Thread | None = None
        self._thread_error: BaseException | None = None

    def start(self) -> int:
        """Register this scan and return the single Agent-wide gateway port."""
        global _gateway_port, _gateway_server, _gateway_thread, _gateway_thread_error
        import uvicorn
        from mcp_server.factory import create_mcp_server
        from mcp_server.tools import register_project_path

        with _gateway_lock:
            if _gateway_server is None:
                self.port = _gateway_port or self.port
                mcp = create_mcp_server()
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
                    if self._server:
                        self._server.should_exit = True
                    if self._thread:
                        self._thread.join(timeout=5)
                    raise
                _gateway_port = self.port
                _gateway_server = self._server
                _gateway_thread = self._thread
                _gateway_thread_error = self._thread_error
            else:
                self.port = int(_gateway_port or self.port)
                self._server = _gateway_server
                self._thread = _gateway_thread
                self._thread_error = _gateway_thread_error
            if self.project_dir is not None:
                register_project_path(self.project_id, self.project_dir)
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
        """Unregister this scan; the Agent-wide gateway remains alive."""
        from mcp_server.tools import unregister_project_path
        unregister_project_path(self.project_id, self.project_dir)

    def restart(self) -> int:
        """Refresh this scan's route while keeping the shared gateway alive."""
        self.stop()
        return self.start()


def shutdown_local_mcp_gateway() -> None:
    """Stop the shared gateway during Agent process shutdown or tests."""
    global _gateway_port, _gateway_server, _gateway_thread, _gateway_thread_error
    from mcp_server.tools import clear_db_cache, clear_project_paths

    with _gateway_lock:
        if _gateway_server is not None:
            _gateway_server.should_exit = True
        if _gateway_thread is not None:
            _gateway_thread.join(timeout=5)
        _gateway_port = None
        _gateway_server = None
        _gateway_thread = None
        _gateway_thread_error = None
        clear_project_paths()
        clear_db_cache()
