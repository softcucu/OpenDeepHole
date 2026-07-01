from pathlib import Path

from backend.models import Candidate
from backend.opencode import llm_api_runner
from code_parser import CodeDatabase


def _write_code_index(project_dir: Path) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.c")
    db.insert_function(
        name="leaky",
        signature="leaky(int mode)",
        return_type="void",
        file_id=file_id,
        start_line=10,
        end_line=17,
        is_static=False,
        linkage="extern",
        body=(
            "void leaky(int mode) {\n"
            "    char *p = malloc(8);\n"
            "    if (mode) {\n"
            "        return;\n"
            "    }\n"
            "    cleanup(p);\n"
            "}"
        ),
    )
    db.insert_function(
        name="cleanup",
        signature="cleanup(char *p)",
        return_type="void",
        file_id=file_id,
        start_line=20,
        end_line=22,
        is_static=False,
        linkage="extern",
        body=(
            "void cleanup(char *p) {\n"
            "    free(p);\n"
            "}"
        ),
    )
    db.commit()
    db.mark_index_complete()
    db.checkpoint()
    db.close()


def _write_cpp_code_index(project_dir: Path) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.cpp")
    db.insert_function(
        name="ru_emu_dpdk_transmitter::send",
        signature="ru_emu_dpdk_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=30,
        end_line=35,
        is_static=False,
        linkage="extern",
        body=(
            "int ru_emu_dpdk_transmitter::send(int mode) {\n"
            "    char *p = malloc(8);\n"
            "    if (mode) return 1;\n"
            "    free(p);\n"
            "    return 0;\n"
            "}"
        ),
    )
    db.insert_function(
        name="other_transmitter::send",
        signature="other_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=40,
        end_line=42,
        is_static=False,
        linkage="extern",
        body="int other_transmitter::send(int mode) {\n    return mode;\n}",
    )
    db.commit()
    db.mark_index_complete()
    db.checkpoint()
    db.close()


def test_emit_initial_api_prompt_outputs_complete_single_candidate_messages() -> None:
    outputs: list[str] = []
    messages = [
        {"role": "system", "content": "system prompt\nline 2"},
        {"role": "user", "content": "unique single candidate detail\nline 2"},
    ]

    llm_api_runner._emit_initial_api_prompt(outputs.append, messages)

    assert len(outputs) == 1
    logged = "\n".join(outputs)
    assert "[API] 初始提示词" in logged
    assert "--- system ---" in logged
    assert "--- user ---" in logged
    assert "system prompt" in logged
    assert "line 2" in logged
    assert "unique single candidate detail" in logged


def test_emit_initial_api_prompt_outputs_complete_batch_messages() -> None:
    outputs: list[str] = []
    messages = [
        {"role": "system", "content": "batch system prompt"},
        {
            "role": "user",
            "content": (
                "候选漏洞点（共 2 个）\n"
                "first batch candidate detail\n"
                "second batch candidate detail"
            ),
        },
    ]

    llm_api_runner._emit_initial_api_prompt(outputs.append, messages)

    logged = "\n".join(outputs)
    assert "[API] 初始提示词" in logged
    assert "--- system ---" in logged
    assert "--- user ---" in logged
    assert "候选漏洞点（共 2 个）" in logged
    assert "first batch candidate detail" in logged
    assert "second batch candidate detail" in logged
    assert "secret-api-key" not in logged


def test_api_log_section_keeps_key_content_and_marks_truncation() -> None:
    outputs: list[str] = []
    long_text = "A" * (llm_api_runner._API_LOG_TEXT_LIMIT + 5)

    llm_api_runner._emit_api_section(outputs.append, "test-model", "[API] LLM 回复", long_text)

    logged = "\n".join(outputs)
    assert "[model=test-model] [API] LLM 回复" in logged
    assert "A" * 200 in logged
    assert "[API log truncated: 5 chars omitted" in logged


def test_api_tool_log_helpers_render_tool_names_and_capped_arguments() -> None:
    tools = [
        {"type": "function", "function": {"name": "view_function_code"}},
        {"type": "function", "function": {"name": "submit_result"}},
    ]
    args = {"content": "B" * (llm_api_runner._API_LOG_ARGS_LIMIT + 3)}

    assert llm_api_runner._tool_names_for_log(tools) == "view_function_code, submit_result"
    logged = llm_api_runner._json_for_log(args)
    assert '"content"' in logged
    assert "\n" not in logged
    assert "<chars=" in logged
    assert "preview=" in logged


def test_api_stream_printer_emits_middle_llm_output() -> None:
    outputs: list[str] = []
    printer = llm_api_runner._ApiStreamPrinter(outputs.append, "test-model")

    printer.append("first line\nsecond")
    printer.append(" line")
    printer.flush()

    logged = "\n".join(outputs)
    assert "[model=test-model] [API] LLM 流式输出: first line" in logged
    assert "[model=test-model] [API] LLM 流式输出: second line" in logged


def test_user_prompt_uses_agent_project_dir_code_index(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidate = Candidate(
        file="sample.c",
        line=13,
        function="leaky",
        description="candidate issue",
        vuln_type="memleak",
        related_functions=["cleanup"],
    )

    prompt = llm_api_runner._build_user_prompt(candidate, "scan-id-without-index")

    assert "代码索引不可用" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt
    assert "## 相关函数源码" in prompt
    assert "  20 | void cleanup(char *p) {" in prompt


def test_user_prompt_project_dir_overrides_agent_project_env(tmp_path, monkeypatch) -> None:
    env_project = tmp_path / "env-project"
    explicit_project = tmp_path / "explicit-project"
    env_project.mkdir()
    explicit_project.mkdir()
    _write_code_index(env_project)
    _write_cpp_code_index(explicit_project)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(env_project))

    candidate = Candidate(
        file="sample.cpp",
        line=32,
        function="ru_emu_dpdk_transmitter::send",
        description="candidate issue",
        vuln_type="memleak",
    )

    prompt = llm_api_runner._build_user_prompt(
        candidate,
        "scan-id-without-index",
        project_dir=explicit_project,
    )

    assert "## 函数源码 (sample.cpp:30)" in prompt
    assert "ru_emu_dpdk_transmitter::send" in prompt
    assert "void leaky(int mode)" not in prompt


def test_user_prompt_uses_cpp_qualified_function_name(tmp_path, monkeypatch) -> None:
    _write_cpp_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidate = Candidate(
        file="sample.cpp",
        line=32,
        function="ru_emu_dpdk_transmitter::send",
        description="candidate issue",
        vuln_type="memleak",
    )

    prompt = llm_api_runner._build_user_prompt(candidate, "scan-id-without-index")

    assert "代码索引中未找到函数" not in prompt
    assert "## 函数源码 (sample.cpp:30)" in prompt
    assert "  30 | int ru_emu_dpdk_transmitter::send(int mode) {" in prompt
    assert "other_transmitter::send" not in prompt


def test_user_prompt_falls_back_to_file_line_when_function_name_misses(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidate = Candidate(
        file="sample.c",
        line=13,
        function="missing_static_name",
        description="candidate issue",
        vuln_type="memleak",
    )

    prompt = llm_api_runner._build_user_prompt(candidate, "scan-id-without-index")

    assert "代码索引中未找到函数" not in prompt
    assert "代码索引不可用" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt


def test_user_prompt_uses_empty_source_when_lookup_fails(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidate = Candidate(
        file="missing.c",
        line=99,
        function="missing_static_name",
        description="candidate issue",
        vuln_type="memleak",
    )

    prompt = llm_api_runner._build_user_prompt(candidate, "scan-id-without-index")

    assert "代码索引中未找到函数" not in prompt
    assert "代码索引不可用" not in prompt
    assert "## 函数源码" in prompt
    assert "void leaky" not in prompt


def test_batch_user_prompt_uses_agent_project_dir_code_index(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidates = [
        Candidate(
            file="sample.c",
            line=13,
            function="leaky",
            description="first leak candidate",
            vuln_type="memleak",
        ),
        Candidate(
            file="sample.c",
            line=15,
            function="leaky",
            description="second leak candidate",
            vuln_type="memleak",
        ),
    ]

    prompt = llm_api_runner._build_batch_user_prompt(candidates, "scan-id-without-index")

    assert "代码索引不可用" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt
    assert "候选漏洞点（共 2 个）" in prompt
    assert "first leak candidate" in prompt
    assert "second leak candidate" in prompt


def test_batch_user_prompt_uses_cpp_qualified_function_name(tmp_path, monkeypatch) -> None:
    _write_cpp_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidates = [
        Candidate(
            file="sample.cpp",
            line=32,
            function="ru_emu_dpdk_transmitter::send",
            description="first leak candidate",
            vuln_type="memleak",
        ),
        Candidate(
            file="sample.cpp",
            line=33,
            function="ru_emu_dpdk_transmitter::send",
            description="second leak candidate",
            vuln_type="memleak",
        ),
    ]

    prompt = llm_api_runner._build_batch_user_prompt(candidates, "scan-id-without-index")

    assert "代码索引中未找到函数" not in prompt
    assert "## 函数源码 (sample.cpp:30)" in prompt
    assert "  30 | int ru_emu_dpdk_transmitter::send(int mode) {" in prompt
    assert "other_transmitter::send" not in prompt


def test_batch_user_prompt_falls_back_to_file_line_when_function_name_misses(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidates = [
        Candidate(
            file="sample.c",
            line=13,
            function="missing_static_name",
            description="first leak candidate",
            vuln_type="memleak",
        )
    ]

    prompt = llm_api_runner._build_batch_user_prompt(candidates, "scan-id-without-index")

    assert "代码索引中未找到函数" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt
