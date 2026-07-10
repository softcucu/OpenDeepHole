"""Shared construction for OpenDeepHole MCP server instances."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError as PydanticValidationError

from mcp_server.tools import _mcp_log_error, register_tools


MCP_SERVER_NAME = "OpenDeepHole Code Tools"
MCP_SERVER_INSTRUCTIONS = (
    "源码查询规则：当需要阅读或定位源码时，优先使用 deephole-code MCP Server 提供的 "
    "`view_function_code`、`view_struct_code`、`view_global_variable_definition` 工具。"
    "仅当代码索引不可用、查询未命中，或需要进行目录级枚举/全文文本搜索时，才回退使用内置的 "
    "`read`、`grep`、`glob` 等文件工具。"
)


def _is_argument_validation_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, PydanticValidationError):
            return True
        current = current.__cause__
    return False


class _LoggingFastMCP(FastMCP):
    """FastMCP boundary that makes rejected and failed calls visible."""

    async def call_tool(self, name: str, arguments: dict):
        known_tool = self._tool_manager.get_tool(name) is not None
        argument_map = arguments if isinstance(arguments, dict) else {}
        try:
            return await super().call_tool(name, arguments)
        except Exception as exc:
            if not known_tool:
                detail = "status=unknown_tool"
            elif _is_argument_validation_error(exc):
                arg_names = ",".join(sorted(str(key) for key in argument_map)) or "(none)"
                detail = f"status=invalid_arguments, arg_names={arg_names}"
            else:
                cause = exc.__cause__ or exc
                detail = (
                    "status=execution_error, "
                    f"error={type(cause).__name__}: {cause}"
                )
            _mcp_log_error(name, detail)
            raise


def create_mcp_server(project_dir: Path | str | None = None) -> FastMCP:
    """Create an MCP server with shared instructions and registered tools."""
    mcp = _LoggingFastMCP(MCP_SERVER_NAME, instructions=MCP_SERVER_INSTRUCTIONS)
    register_tools(mcp, project_dir=project_dir)
    return mcp
