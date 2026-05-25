from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from checkers.intoverflow.analyzer import Analyzer as IntOverflowAnalyzer


pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep CLI is not installed",
)


def test_intoverflow_semgrep_rules_find_high_risk_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.c"
    source.write_text(
        """
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned long size_t;
typedef struct {
    int value;
} Item;

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void memcpy(void *dst, const void *src, size_t count);
void memset(void *dst, int value, size_t count);

void header_subtract(char *dst, char *src, uint32_t packet_len) {
    uint32_t body_len = packet_len - 8;
    memcpy(dst, src, body_len);
}

void direct_sink(char *dst, char *src, uint32_t off, uint32_t len) {
    memcpy(dst + off, src, len + off);
}

void array_index(Item *items, uint32_t base, uint32_t delta) {
    items[base + delta].value = 1;
}

void pointer_offset(char *ptr, uint32_t off, uint32_t len) {
    *(ptr + (off + len)) = 0;
}

void multiply_alloc(uint32_t count) {
    size_t bytes = count * sizeof(Item);
    char *buf = malloc(bytes);
    (void)buf;
}

void narrow_then_copy(char *dst, char *src, uint32_t a, uint32_t b) {
    uint16_t n = a + b;
    memcpy(dst, src, n);
}

void loop_bound(char *dst, uint32_t count) {
    uint32_t limit = count - 1;
    for (uint32_t i = 0; i < limit; i++) {
        dst[i] = 0;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(IntOverflowAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "header-subtract-sink" in descriptions
    assert "direct-arith-sink" in descriptions
    assert "direct-arith-access-sink" in descriptions
    assert "assigned-arith-to-sink" in descriptions
    assert "assigned-arith-access-sink" in descriptions
    assert "multiply-size-to-allocation" in descriptions
    assert "narrowed-arith-to-sink" in descriptions
    assert "Function=`array_index`" in descriptions
    assert "Function=`pointer_offset`" in descriptions
    assert "Function=`loop_bound`" in descriptions
    assert "复核重点" in descriptions
    assert len(candidates) >= 7


def test_intoverflow_semgrep_rules_ignore_basic_safe_shapes(tmp_path: Path) -> None:
    source = tmp_path / "safe.c"
    source.write_text(
        """
typedef unsigned int uint32_t;
typedef unsigned long size_t;

void *malloc(size_t size);
void memcpy(void *dst, const void *src, size_t count);

void guarded_subtract(char *dst, char *src, uint32_t packet_len) {
    if (packet_len < 8) return;
    uint32_t body_len = packet_len - 8;
    memcpy(dst, src, body_len);
}

void builtin_checked(uint32_t a, uint32_t b) {
    uint32_t bytes;
    if (__builtin_mul_overflow(a, b, &bytes)) {
        return;
    }
    char *buf = malloc(bytes);
    (void)buf;
}

void constants_only(char *dst, char *src) {
    uint32_t len = 64 - 8;
    memcpy(dst, src, len);
}

void no_sink(uint32_t total, uint32_t used) {
    uint32_t remaining = total - used;
    (void)remaining;
}
""",
        encoding="utf-8",
    )

    candidates = list(IntOverflowAnalyzer().find_candidates(tmp_path))

    assert candidates == []
