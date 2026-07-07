from pathlib import Path

from checkers.memleak.analyzer import Analyzer, _collect_source_files

MEMLEAK_CASES_DIR = Path(__file__).parent / "test_data" / "memleak_cases"


def _write_source(tmp_path: Path, content: str) -> None:
    (tmp_path / "sample.c").write_text(content, encoding="utf-8")


def test_memleak_source_collection_excludes_project_opendeephole(tmp_path: Path) -> None:
    _write_source(tmp_path, "int kept(void) { return 0; }\n")
    internal = tmp_path / ".opendeephole" / "opencode" / "generated.c"
    internal.parent.mkdir(parents=True)
    internal.write_text("int generated(void) { return 0; }\n", encoding="utf-8")

    assert [path.relative_to(tmp_path).as_posix() for path in _collect_source_files(tmp_path)] == [
        "sample.c"
    ]


def test_memleak_candidates_are_grouped_by_function(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
void grouped(int mode) {
    char *p = malloc(8);
    char *q = malloc(16);
    if (mode == 1) {
        return;
    }
    if (mode == 2) {
        return;
    }
    release_buffer(p);
    destroy_buffer(q);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.function == "grouped"
    assert candidate.vuln_type == "memleak"
    assert "共有 2 个待核实位置" in candidate.description
    assert "相关线索" in candidate.description
    assert "1. 第" in candidate.description
    assert "2. 第" in candidate.description
    assert "release_buffer" in candidate.related_functions
    assert "destroy_buffer" in candidate.related_functions


def test_memleak_candidates_keep_different_functions_separate(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
void first(int flag) {
    char *p = malloc(8);
    if (flag) {
        return;
    }
    free(p);
}

void second(int flag) {
    char *q = malloc(16);
    if (flag) {
        return;
    }
    free(q);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 2
    assert [candidate.function for candidate in candidates] == ["first", "second"]
    assert all("共有 1 个待核实位置" in c.description for c in candidates)


def test_memleak_path_sensitive_cases_use_single_auditable_c_file() -> None:
    candidates = list(Analyzer().find_candidates(MEMLEAK_CASES_DIR))

    by_function = {candidate.function: candidate for candidate in candidates}

    assert set(by_function) == {
        "report_return_leak",
        "report_branch_leak",
        "report_continue_leak",
        "report_partial_multi",
        "report_null_initialized_before_allocation",
        "report_cleanup_object_early_returns",
        "report_switch_case_split",
        "report_state_completion_case_split",
        "report_switch_fallthrough_leak",
    }
    assert "异常分支" in by_function["report_return_leak"].description
    assert "异常分支" in by_function["report_branch_leak"].description
    assert "循环中 continue 前未释放" in by_function["report_continue_leak"].description
    assert "q" in by_function["report_partial_multi"].description
    assert "p" in by_function["report_null_initialized_before_allocation"].description
    assert "ip_data" in by_function["report_cleanup_object_early_returns"].description
    assert by_function["report_cleanup_object_early_returns"].description.count("ip_data") >= 3
    assert "p" in by_function["report_switch_case_split"].description
    assert "Request_Invoke_ID" in by_function["report_state_completion_case_split"].description
    assert "状态机完成前未释放" in by_function["report_state_completion_case_split"].description
    assert "p" in by_function["report_switch_fallthrough_leak"].description
    assert "bacfile_object_name_set" not in by_function
    assert "ok_switch_case_releases" not in by_function
    assert "ok_state_completion_after_free" not in by_function
