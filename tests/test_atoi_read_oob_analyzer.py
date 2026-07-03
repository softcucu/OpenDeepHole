from __future__ import annotations

from pathlib import Path

from checkers.atoi_read_oob.analyzer import Analyzer


class _FakeDb:
    def __init__(self, functions):
        self._functions = functions

    def get_all_functions(self):
        return self._functions


def test_atoi_read_oob_finds_direct_and_qualified_calls(tmp_path: Path) -> None:
    body = """int parse(char *p, char *q) {
    int a = atoi(p);
    int b = std::atoi(q + 1);
    const char *s = "atoi(nope)";
    // atoi(commented);
    obj.atoi(q);
    return a + b;
}
"""
    db = _FakeDb([
        {
            "name": "parse",
            "file_path": "sample.cpp",
            "start_line": 20,
            "body": body,
        }
    ])

    candidates = Analyzer().find_candidates(tmp_path, db)

    assert len(candidates) == 2
    assert [candidate.line for candidate in candidates] == [21, 22]
    assert all(candidate.function == "parse" for candidate in candidates)
    assert all(candidate.vuln_type == "atoi_read_oob" for candidate in candidates)
    assert candidates[0].metadata["argument"] == "p"
    assert candidates[1].metadata["argument"] == "q + 1"
    assert "obj.atoi" not in "\n".join(candidate.description for candidate in candidates)


def test_atoi_read_oob_returns_empty_without_code_index(tmp_path: Path) -> None:
    assert Analyzer().find_candidates(tmp_path, None) == []
