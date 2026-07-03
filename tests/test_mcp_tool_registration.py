import inspect
from pathlib import Path

from code_parser import CodeDatabase
from mcp_server.tools import clear_db_cache, register_tools


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func

        return decorator


def _write_code_index(project_dir: Path, body: str) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.c")
    db.insert_function(
        name="target",
        signature="int target(void)",
        return_type="int",
        file_id=file_id,
        start_line=1,
        end_line=3,
        is_static=False,
        linkage="external",
        body=body,
    )
    db.mark_index_complete()
    db.checkpoint()
    db.close()


def test_reference_lookup_helpers_are_not_registered_as_mcp_tools() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    assert "view_function_code" in mcp.tools
    assert "view_struct_code" in mcp.tools
    assert "view_global_variable_definition" in mcp.tools
    assert "submit_result" in mcp.tools
    assert "find_function_references" not in mcp.tools
    assert "find_global_variable_references" not in mcp.tools


def test_registered_mcp_tools_do_not_expose_caller_model() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    for name in (
        "view_function_code",
        "view_struct_code",
        "view_global_variable_definition",
        "submit_result",
        "submit_history_pattern",
        "submit_variant_finding",
        "submit_match_result",
    ):
        assert "caller_model" not in inspect.signature(mcp.tools[name]).parameters


def test_source_lookup_tools_describe_deephole_code_priority() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    for name in (
        "view_function_code",
        "view_struct_code",
        "view_global_variable_definition",
    ):
        doc = inspect.getdoc(mcp.tools[name]) or ""
        assert "优先使用本 deephole-code MCP 工具" in doc
        assert "read/grep/glob" in doc


def test_bound_project_dir_isolated_from_agent_project_env(tmp_path, monkeypatch) -> None:
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    _write_code_index(project_a, "int target(void) { return 1; }")
    _write_code_index(project_b, "int target(void) { return 2; }")
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(project_b))

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project_a)

    result = mcp.tools["view_function_code"]("scan-a", "target")

    assert "return 1" in result
    assert "return 2" not in result
    clear_db_cache()


def test_mcp_tool_log_summarizes_source_lookup(tmp_path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    result = mcp.tools["view_function_code"]("scan-a", "target")

    assert "return 1" in result
    output = capsys.readouterr().out
    assert "[MCP ▶] view_function_code" in output
    assert "[MCP ◀] view_function_code" in output
    assert "1 match(es)" in output
    assert "return 1" not in output
    clear_db_cache()


def test_mcp_tool_log_has_no_model_placeholder(tmp_path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    mcp.tools["view_function_code"]("scan-a", "target")

    output = capsys.readouterr().out
    assert "[MCP ▶] view_function_code" in output
    assert "[MCP ◀] view_function_code" in output
    assert "model=" not in output
    clear_db_cache()


def test_mcp_submit_log_summarizes_long_fields(tmp_path, monkeypatch, capsys) -> None:
    class FakeStorage:
        scans_dir = str(tmp_path / "scans")

    class FakeConfig:
        storage = FakeStorage()

    monkeypatch.setattr("mcp_server.tools._get_config", lambda: FakeConfig())
    mcp = _FakeMCP()
    register_tools(mcp, project_dir=tmp_path)

    mcp.tools["submit_result"](
        "result-1",
        True,
        "high",
        "desc",
        "line 1\n" + "A" * 500,
        vulnerability_report="report\n" + "B" * 500,
    )

    output = capsys.readouterr().out
    assert output.count("submit_result") == 2
    assert "[MCP ▶] submit_result" in output
    assert "[MCP ◀] submit_result" in output
    assert "<chars=" in output
    assert "[truncated" in output
    assert "AAAAA" in output


def test_code_index_cache_reopens_after_db_replacement(tmp_path) -> None:
    project = tmp_path / "project"
    replacement = tmp_path / "replacement"
    project.mkdir()
    replacement.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    first = mcp.tools["view_function_code"]("scan-1", "target")
    assert "return 1" in first

    _write_code_index(replacement, "int target(void) { return 2; }")
    (replacement / "code_index.db").replace(project / "code_index.db")

    second = mcp.tools["view_function_code"]("scan-1", "target")

    assert "return 2" in second
    assert "return 1" not in second
    clear_db_cache()
