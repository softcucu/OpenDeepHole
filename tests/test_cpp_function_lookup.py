import subprocess
from pathlib import Path

from code_parser import CodeDatabase
from code_parser.cpp_analyzer import CppAnalyzer
from code_parser.cpp_analyzer import _CscopeCall


def _index_source(
    tmp_path: Path,
    source: str,
    entries: list[dict],
    cscope_calls: dict[str, list[_CscopeCall]] | None = None,
) -> CodeDatabase:
    (tmp_path / "sample.cpp").write_text(source, encoding="utf-8")
    db = CodeDatabase(tmp_path / "code_index.db")
    analyzer = CppAnalyzer(db)
    analyzer._ensure_tools_available = lambda: None
    analyzer._run_ctags_json = lambda _root, _files, _work_dir: entries
    analyzer._build_cscope_database = lambda _root, _files, temp_dir: temp_dir / "cscope.out"
    analyzer._query_cscope_callers = (
        lambda _db_path, symbol, _root: (cscope_calls or {}).get(symbol, [])
    )
    analyzer.analyze_directory(tmp_path)
    return db


def test_cpp_qualified_member_lookup_does_not_match_other_class_send(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
class ru_emu_dpdk_transmitter { public: int send(int mode); };
class other_transmitter { public: int send(int mode); };

int ru_emu_dpdk_transmitter::send(int mode) {
    return mode;
}

int other_transmitter::send(int mode) {
    return mode + 1;
}
""",
        [
            {
                "_type": "tag",
                "name": "send",
                "path": "sample.cpp",
                "line": 5,
                "end": 7,
                "kind": "function",
                "scope": "ru_emu_dpdk_transmitter",
                "signature": "(int mode)",
            },
            {
                "_type": "tag",
                "name": "send",
                "path": "sample.cpp",
                "line": 9,
                "end": 11,
                "kind": "function",
                "scope": "other_transmitter",
                "signature": "(int mode)",
            },
        ],
    )
    try:
        rows = db.get_functions_by_name("ru_emu_dpdk_transmitter::send")

        assert len(rows) == 1
        assert rows[0]["name"] == "ru_emu_dpdk_transmitter::send"
        assert "other_transmitter::send" not in rows[0]["body"]
    finally:
        db.close()


def test_cpp_inline_member_function_is_indexed_by_short_name(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
class transmitter {
public:
    int send(int mode) {
        return mode;
    }
};
""",
        [
            {
                "_type": "tag",
                "name": "send",
                "path": "sample.cpp",
                "line": 4,
                "end": 6,
                "kind": "function",
                "scope": "transmitter",
                "signature": "(int mode)",
            }
        ],
    )
    try:
        rows = db.get_functions_by_name("send")

        assert len(rows) == 1
        assert rows[0]["name"] == "transmitter::send"
        assert "int send(int mode)" in rows[0]["body"]
    finally:
        db.close()


def test_qualified_lookup_supports_old_short_name_index_when_signature_matches(tmp_path: Path) -> None:
    db = CodeDatabase(tmp_path / "code_index.db")
    file_id = db.get_or_create_file("sample.cpp")
    db.insert_function(
        name="send",
        signature="ru_emu_dpdk_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=10,
        end_line=12,
        is_static=False,
        linkage="extern",
        body="int ru_emu_dpdk_transmitter::send(int mode) {\n    return mode;\n}",
    )
    db.insert_function(
        name="send",
        signature="other_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=20,
        end_line=22,
        is_static=False,
        linkage="extern",
        body="int other_transmitter::send(int mode) {\n    return mode + 1;\n}",
    )
    db.commit()
    try:
        rows = db.get_functions_by_name("ru_emu_dpdk_transmitter::send")

        assert len(rows) == 1
        assert rows[0]["start_line"] == 10
        assert "ru_emu_dpdk_transmitter::send" in rows[0]["signature"]
    finally:
        db.close()


def test_function_lookup_by_file_and_line_uses_range_index(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
int first(void) {
    return 1;
}

int second(void) {
    return 2;
}
""",
        [
            {
                "_type": "tag",
                "name": "first",
                "path": "sample.cpp",
                "line": 2,
                "end": 4,
                "kind": "function",
                "signature": "(void)",
            },
            {
                "_type": "tag",
                "name": "second",
                "path": "sample.cpp",
                "line": 6,
                "end": 8,
                "kind": "function",
                "signature": "(void)",
            },
        ],
    )
    try:
        row = db.get_function_by_location("sample.cpp", 7)

        assert row is not None
        assert row["name"] == "second"
        assert "return 2" in row["body"]
    finally:
        db.close()


def test_code_index_complete_marker_controls_reuse(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
int demo(void) {
    return 1;
}
""",
        [
            {
                "_type": "tag",
                "name": "demo",
                "path": "sample.cpp",
                "line": 2,
                "end": 4,
                "kind": "function",
                "signature": "(void)",
            }
        ],
    )
    try:
        assert not db.is_index_complete()
        db.mark_index_complete()
        assert db.is_index_complete()
    finally:
        db.close()


def test_code_index_without_current_indexer_marker_is_not_reused(tmp_path: Path) -> None:
    db = CodeDatabase(tmp_path / "code_index.db")
    try:
        db.set_metadata("status", db.COMPLETE_STATUS)
        db.commit()

        assert not db.is_index_complete()
    finally:
        db.close()


def test_struct_lookup_uses_ctags_definition_and_short_name_fallback(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
namespace ns {
struct Header {
    int len;
};
}
""",
        [
            {
                "_type": "tag",
                "name": "Header",
                "path": "sample.cpp",
                "line": 3,
                "end": 5,
                "kind": "struct",
                "scope": "ns",
            }
        ],
    )
    try:
        rows = db.get_structs_by_name("Header")

        assert len(rows) == 1
        assert rows[0]["name"] == "ns::Header"
        assert "int len" in rows[0]["definition"]
    finally:
        db.close()


def test_ctags_file_list_uses_project_work_dir_relative_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "sample.cpp").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    captured: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        assert kwargs["cwd"] == tmp_path
        list_arg = cmd[cmd.index("-L") + 1]
        assert not Path(list_arg).is_absolute()
        assert ":" not in list_arg
        assert "\\" not in list_arg
        list_path = tmp_path / list_arg
        assert list_path.parent.name.startswith(".opendeephole-index-")
        assert list_path.read_text(encoding="utf-8") == "sample.cpp\n"
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    db = CodeDatabase(tmp_path / "code_index.db")
    analyzer = CppAnalyzer(db)
    analyzer._ensure_tools_available = lambda: None
    analyzer._index_cscope_calls = lambda *_args, **_kwargs: None
    try:
        analyzer.analyze_directory(tmp_path)
    finally:
        db.close()

    assert captured
    assert not any(
        path.name.startswith(".opendeephole-index-")
        for path in tmp_path.iterdir()
    )


def test_cscope_uses_project_work_dir_relative_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "sample.cpp"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    work_dir = tmp_path / ".opendeephole-index-test"
    work_dir.mkdir()
    captured: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        assert kwargs["cwd"] == tmp_path
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    db = CodeDatabase(tmp_path / "code_index.db")
    try:
        analyzer = CppAnalyzer(db)
        db_path = analyzer._build_cscope_database(tmp_path, [source], work_dir)
    finally:
        db.close()

    assert db_path == work_dir / "cscope.out"
    assert captured
    cmd = captured[0]
    files_arg = cmd[cmd.index("-i") + 1]
    db_arg = cmd[cmd.index("-f") + 1]
    assert files_arg == ".opendeephole-index-test/cscope.files"
    assert db_arg == ".opendeephole-index-test/cscope.out"
    assert ":" not in files_arg + db_arg
    assert "\\" not in files_arg + db_arg
    assert (work_dir / "cscope.files").read_text(encoding="utf-8") == "sample.cpp\n"


def test_function_reference_index_uses_cscope_callers(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
int cleanup(void) {
    return 0;
}

int caller(void) {
    return cleanup();
}
""",
        [
            {
                "_type": "tag",
                "name": "cleanup",
                "path": "sample.cpp",
                "line": 2,
                "end": 4,
                "kind": "function",
                "signature": "(void)",
            },
            {
                "_type": "tag",
                "name": "caller",
                "path": "sample.cpp",
                "line": 6,
                "end": 8,
                "kind": "function",
                "signature": "(void)",
            },
        ],
        {
            "cleanup": [
                _CscopeCall(
                    file_path="sample.cpp",
                    caller_name="caller",
                    line=7,
                    text="return cleanup();",
                )
            ]
        },
    )
    try:
        rows = db.get_call_sites_by_name("cleanup")

        assert len(rows) == 1
        assert rows[0]["caller_name"] == "caller"
        assert rows[0]["file_path"] == "sample.cpp"
        assert rows[0]["line"] == 7
    finally:
        db.close()


def test_code_index_reports_ctags_and_cscope_stage_progress(tmp_path: Path) -> None:
    (tmp_path / "sample.cpp").write_text(
        """
int cleanup(void) {
    return 0;
}

int caller(void) {
    return cleanup();
}
""",
        encoding="utf-8",
    )
    entries = [
        {
            "_type": "tag",
            "name": "cleanup",
            "path": "sample.cpp",
            "line": 2,
            "end": 4,
            "kind": "function",
            "signature": "(void)",
        },
        {
            "_type": "tag",
            "name": "caller",
            "path": "sample.cpp",
            "line": 6,
            "end": 8,
            "kind": "function",
            "signature": "(void)",
        },
    ]
    progress: list[tuple[str, int, int]] = []
    db = CodeDatabase(tmp_path / "code_index.db")
    analyzer = CppAnalyzer(db)
    analyzer._ensure_tools_available = lambda: None
    analyzer._run_ctags_json = lambda _root, _files, _work_dir: entries
    analyzer._build_cscope_database = lambda _root, _files, temp_dir: temp_dir / "cscope.out"
    analyzer._query_cscope_callers = lambda _db_path, _symbol, _root: []

    try:
        analyzer.analyze_directory(
            tmp_path,
            on_stage_progress=lambda stage, current, total: progress.append(
                (stage, current, total)
            ),
        )
    finally:
        db.close()

    assert ("ctags scan", 0, 1) in progress
    assert ("ctags scan", 1, 1) in progress
    assert ("ctags entries", 2, 2) in progress
    assert ("cscope database", 0, 1) in progress
    assert ("cscope database", 1, 1) in progress
    assert ("cscope symbols", 2, 2) in progress
