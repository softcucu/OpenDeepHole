from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from checkers.loop_mut_idx_oob.analyzer import Analyzer as LoopMutIdxOobAnalyzer


pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep CLI is not installed",
)


def test_loop_mut_idx_oob_semgrep_rules_find_direct_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe_direct.c"
    source.write_text(
        """
typedef unsigned long size_t;
typedef struct {
    int value;
} Item;

void memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);

void array_access(char *dst, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        dst[idx] = src[idx];
        idx++;
        remain--;
    }
}

void pointer_deref(char *ptr, unsigned len) {
    unsigned idx = 0;
    for (; len != 0; len--, idx++) {
        *(ptr + idx) = 0;
    }
}

void field_access(Item *items, unsigned len) {
    unsigned idx = 0;
    while (len != 0) {
        (items + idx)->value = 1;
        idx++;
        len--;
    }
}

void memory_call(char *dst, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        memcpy_s(dst + idx, 16, src, 1);
        idx++;
        remain--;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "越界访问问题" in descriptions
    assert "array" not in descriptions
    assert "memory-call" not in descriptions
    assert "array_access" not in descriptions
    assert len(candidates) >= 3


def test_loop_mut_idx_oob_semgrep_rules_find_taint_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe_taint.c"
    source.write_text(
        """
typedef unsigned long size_t;
void memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);

void derived_deref(char *base, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        char *tmp = base + idx;
        *tmp = 0;
        idx++;
        remain--;
    }
}

void derived_memfunc(char *base, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        char *tmp = &base[idx];
        memcpy_s(tmp, 8, src, 1);
        idx++;
        remain--;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "越界访问问题" in descriptions
    assert "derived-pointer" not in descriptions
    assert "local memory sink" not in descriptions
    assert len(candidates) >= 2


def test_loop_mut_idx_oob_semgrep_rules_find_unchecked_loop_bound_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unchecked_bound.c"
    code = """
typedef unsigned long uintptr_t;

typedef struct {
    uintptr_t packet;
    unsigned len;
} FragInfo;

void frag_access(FragInfo *fragInfo, unsigned fragNum) {
    unsigned fragId;
    for (fragId = 0; fragId < fragNum; fragId++) {
        (void)(uintptr_t)(fragInfo[fragId].packet);
        (void)fragInfo[fragId].len;
    }
}

void pointer_offset(char *ptr, unsigned count) {
    unsigned idx;
    for (idx = 0; idx < count; idx++) {
        *(ptr + idx) = 0;
    }
}
"""
    source.write_text(code, encoding="utf-8")

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    candidate_lines = {candidate.line for candidate in candidates}
    lines = code.splitlines()
    packet_line = lines.index("        (void)(uintptr_t)(fragInfo[fragId].packet);") + 1
    len_line = lines.index("        (void)fragInfo[fragId].len;") + 1
    pointer_line = lines.index("        *(ptr + idx) = 0;") + 1

    assert packet_line in candidate_lines
    assert len_line in candidate_lines
    assert pointer_line in candidate_lines


def test_loop_mut_idx_oob_semgrep_rules_ignore_loop_bound_after_prior_comparison(tmp_path: Path) -> None:
    source = tmp_path / "checked_bound.c"
    code = """
typedef unsigned long uintptr_t;

typedef struct {
    uintptr_t packet;
    unsigned len;
} FragInfo;

void checked_direct(FragInfo *fragInfo, unsigned fragNum, unsigned maxFrags) {
    unsigned fragId;
    if (fragNum > maxFrags) return;
    for (fragId = 0; fragId < fragNum; fragId++) {
        (void)(uintptr_t)(fragInfo[fragId].packet);
    }
}

void checked_reverse(FragInfo *fragInfo, unsigned fragNum, unsigned maxFrags) {
    unsigned fragId;
    if (maxFrags < fragNum) {
        return;
    }
    for (fragId = 0; fragId < fragNum; fragId++) {
        (void)fragInfo[fragId].len;
    }
}
"""
    source.write_text(code, encoding="utf-8")

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    candidate_lines = {candidate.line for candidate in candidates}
    lines = code.splitlines()
    direct_line = lines.index("        (void)(uintptr_t)(fragInfo[fragId].packet);") + 1
    reverse_line = lines.index("        (void)fragInfo[fragId].len;") + 1

    assert direct_line not in candidate_lines
    assert reverse_line not in candidate_lines


def test_loop_mut_idx_oob_semgrep_rules_ignore_basic_safe_shapes(tmp_path: Path) -> None:
    source = tmp_path / "safe.c"
    source.write_text(
        """
void direct_condition(char *dst, unsigned len, unsigned cap) {
    if (len > cap) {
        return;
    }
    for (unsigned idx = 0; idx < len; idx++) {
        dst[idx] = 0;
    }
}

void guarded(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        if (idx < cap) {
            dst[idx] = 0;
        }
        idx++;
        remain--;
    }
}

void fail_fast(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        if (idx >= cap) return;
        dst[idx] = 0;
        idx++;
        remain--;
    }
}

void macro_checked(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        CHECK_RET(idx < cap, -1);
        dst[idx] = 0;
        idx++;
        remain--;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))

    assert candidates == []
