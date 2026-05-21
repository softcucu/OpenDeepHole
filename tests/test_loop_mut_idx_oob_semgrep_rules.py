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

    assert "array" in descriptions
    assert "pointer" in descriptions
    assert "memory-call" in descriptions
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

    assert "derived-pointer" in descriptions
    assert "local memory sink" in descriptions
    assert len(candidates) >= 2


def test_loop_mut_idx_oob_semgrep_rules_ignore_basic_safe_shapes(tmp_path: Path) -> None:
    source = tmp_path / "safe.c"
    source.write_text(
        """
void direct_condition(char *dst, unsigned len) {
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
