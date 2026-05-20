from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from checkers.safe_mem_oob.analyzer import Analyzer as SafeMemOobAnalyzer


pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep CLI is not installed",
)


def test_safe_mem_oob_semgrep_rules_find_high_risk_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.c"
    source.write_text(
        """
typedef unsigned long size_t;
typedef int errno_t;
typedef struct {
    int type;
    char payload[64];
    char name[16];
    char chunks[4][16];
} Msg;

errno_t memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);
errno_t memmove_s(void *dst, size_t dstsz, const void *src, size_t count);
errno_t memset_s(void *dst, size_t dstsz, int value, size_t count);
errno_t strcpy_s(char *dst, size_t dstsz, const char *src);
errno_t strncpy_s(char *dst, size_t dstsz, const char *src, size_t count);
errno_t strncat_s(char *dst, size_t dstsz, const char *src, size_t count);
errno_t wcscpy_s(void *dst, size_t dstsz, const void *src);
errno_t sprintf_s(char *dst, size_t dstsz, const char *fmt, ...);
errno_t snprintf_s(char *dst, size_t dstsz, size_t count, const char *fmt, ...);
errno_t vsprintf_s(char *dst, size_t dstsz, const char *fmt, void *args);
errno_t vsnprintf_s(char *dst, size_t dstsz, size_t count, const char *fmt, void *args);

void member_parent(Msg msg, const char *src, size_t len) {
    memcpy_s(msg.payload, sizeof(msg), src, len);
}

void offset_full(char *src, size_t len, size_t off) {
    char buf[128];
    memcpy_s(buf + off, sizeof(buf), src, len);
}

void member_offset(Msg *msg, const char *src, size_t len, size_t off) {
    memmove_s(msg->payload + off, sizeof(msg->payload), src, len);
}

void pointer_sizeof(char *src, size_t len) {
    char *buf;
    memcpy_s(buf, sizeof(buf), src, len);
}

void pointer_param(char *dst, const char *src, size_t len) {
    memcpy_s(dst, sizeof(dst), src, len);
}

void memset_bad(Msg *msg, size_t len) {
    memset_s(msg->payload, sizeof(*msg), 0, len);
}

void string_member_parent(Msg msg, const char *src) {
    strcpy_s(msg.name, sizeof(msg), src);
}

void string_offset_full(const char *src, size_t off) {
    char buf[128];
    strncpy_s(buf + off, sizeof(buf), src, 16);
}

void offset_cast_parentheses(const char *src, size_t off, size_t len) {
    char buf[128];
    memcpy_s((char *)(buf + off), sizeof(buf), src, len);
}

void member_subarray(Msg *msg, const char *src, size_t row, size_t len) {
    memcpy_s(msg->chunks[row], sizeof(msg->chunks), src, len);
}

void wide_string_member_parent(Msg *msg, const void *src) {
    wcscpy_s(msg->name, sizeof(*msg), src);
}

void format_member_parent(Msg msg, int code) {
    sprintf_s(msg.name, sizeof(msg), "code=%d", code);
}

void format_offset_full(int code, size_t off) {
    char buf[128];
    snprintf_s(buf + off, sizeof(buf), 32, "code=%d", code);
}

void format_pointer_param(char *dst, int code) {
    sprintf_s(dst, sizeof(dst), "code=%d", code);
}

void vformat_member_parent(Msg *msg, void *args) {
    vsnprintf_s(msg->name, sizeof(*msg), 16, "%s", args);
}

void vformat_s_member_parent(Msg *msg, void *args) {
    vsprintf_s(msg->name, sizeof(*msg), "%s", args);
}
""",
        encoding="utf-8",
    )

    candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "member-non-member-size" in descriptions
    assert "offset-full-size" in descriptions
    assert "member-offset-full-member-size" in descriptions
    assert "pointer-sizeof-dst" in descriptions
    assert "multidim-array-full-size" in descriptions
    assert "pointer_param" in descriptions
    assert "offset_cast_parentheses" in descriptions
    assert "member_subarray" in descriptions
    assert "format_member_parent" in descriptions
    assert "format_offset_full" in descriptions
    assert "format_pointer_param" in descriptions
    assert "vformat_member_parent" in descriptions
    assert "vformat_s_member_parent" in descriptions
    assert "identical-size-array-dst" not in descriptions
    assert "identical-size-member-dst" not in descriptions
    assert "identical-size-source-named" not in descriptions
    assert "strcpy_s" in descriptions
    assert "strncpy_s" in descriptions
    assert "wcscpy_s" in descriptions
    assert "sprintf_s" in descriptions
    assert "snprintf_s" in descriptions
    assert "vsprintf_s" in descriptions
    assert "vsnprintf_s" in descriptions
    assert len(candidates) >= 5


def test_safe_mem_oob_semgrep_rules_ignore_basic_safe_shapes(tmp_path: Path) -> None:
    source = tmp_path / "safe.c"
    source.write_text(
        """
typedef unsigned long size_t;
typedef int errno_t;
typedef struct {
    int type;
    char payload[64];
} Msg;

errno_t memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);
errno_t memset_s(void *dst, size_t dstsz, int value, size_t count);
errno_t strcpy_s(char *dst, size_t dstsz, const char *src);
errno_t strncpy_s(char *dst, size_t dstsz, const char *src, size_t count);
errno_t sprintf_s(char *dst, size_t dstsz, const char *fmt, ...);
errno_t snprintf_s(char *dst, size_t dstsz, size_t count, const char *fmt, ...);

void safe_array(const char *src, size_t len) {
    char buf[128];
    memcpy_s(buf, sizeof(buf), src, len);
}

void safe_object(const char *src, size_t len) {
    Msg msg;
    memcpy_s(&msg, sizeof(msg), src, len);
}

void safe_member(Msg *msg, const char *src, size_t len) {
    memcpy_s(msg->payload, sizeof(msg->payload), src, len);
    memset_s(msg->payload, sizeof(msg->payload), 0, len);
}

void same_sizeof_array(const char *src) {
    char buf[128];
    memcpy_s(buf, sizeof(buf), src, sizeof(buf));
}

void same_sizeof_object(const char *src) {
    Msg msg;
    memcpy_s(&msg, sizeof(msg), src, sizeof(msg));
}

void same_sizeof_member(Msg *msg, const char *src) {
    memcpy_s(msg->payload, sizeof(msg->payload), src, sizeof(msg->payload));
}

void same_dst_named(char *dst, const char *src, size_t dst_len) {
    memcpy_s(dst, dst_len, src, dst_len);
}

void safe_string_array(const char *src) {
    char buf[128];
    strcpy_s(buf, sizeof(buf), src);
}

void safe_string_member(Msg *msg, const char *src) {
    strcpy_s(msg->payload, sizeof(msg->payload), src);
}

void safe_string_same_dst_named(char *dst, const char *src, size_t dst_len) {
    strncpy_s(dst, dst_len, src, dst_len);
}

void safe_format_array(int code) {
    char buf[128];
    sprintf_s(buf, sizeof(buf), "code=%d", code);
}

void safe_format_member(Msg *msg, int code) {
    sprintf_s(msg->payload, sizeof(msg->payload), "code=%d", code);
}

void safe_snprintf_dst_named(char *dst, size_t dst_len, int code) {
    snprintf_s(dst, dst_len, dst_len - 1, "code=%d", code);
}
""",
        encoding="utf-8",
    )

    candidates = list(SafeMemOobAnalyzer().find_candidates(tmp_path))

    assert candidates == []
