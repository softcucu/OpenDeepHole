from mcp_server.tools import register_tools


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: list[str] = []

    def tool(self):
        def decorator(func):
            self.tools.append(func.__name__)
            return func

        return decorator


def test_reference_lookup_helpers_are_not_registered_as_mcp_tools() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    assert "view_function_code" in mcp.tools
    assert "view_struct_code" in mcp.tools
    assert "view_global_variable_definition" in mcp.tools
    assert "submit_result" in mcp.tools
    assert "find_function_references" not in mcp.tools
    assert "find_global_variable_references" not in mcp.tools
