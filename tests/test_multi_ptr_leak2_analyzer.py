from pathlib import Path

from checkers.multi_ptr_leak2.analyzer import Analyzer, _collect_source_files


def _write_source(tmp_path: Path, content: str, name: str = "sample.c") -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_multi_ptr_leak2_source_collection_excludes_project_opendeephole(tmp_path: Path) -> None:
    _write_source(tmp_path, "int kept(void) { return 0; }\n")
    internal = tmp_path / ".opendeephole" / "opencode" / "generated.c"
    internal.parent.mkdir(parents=True)
    internal.write_text("int generated(void) { return 0; }\n", encoding="utf-8")

    assert [path.relative_to(tmp_path).as_posix() for path in _collect_source_files(tmp_path)] == [
        "sample.c"
    ]


def test_multi_ptr_leak2_detects_outer_struct_free(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

typedef struct Packet {
    char *payload;
    int len;
} Packet;

void release_packet(Packet *pkt) {
    free(pkt);
}

void release_buf(char *buf) {
    free(buf);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.function == "release_packet"
    assert candidate.vuln_type == "multi_ptr_leak2"
    assert "free(pkt)" in candidate.description
    assert "结构体: Packet" in candidate.description
    assert "payload: char*" in candidate.description
    assert candidate.related_functions == ["free"]


def test_multi_ptr_leak2_detects_release_wrapper_and_field_argument(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

struct Session {
    char *buf;
};

struct Ctx {
    struct Session *session;
};

void destroy_session(struct Session *s) {
    free(s);
}

void clear_ctx(struct Ctx *ctx) {
    destroy_session(ctx->session);
    free(ctx);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    calls = {(candidate.function, candidate.line, candidate.related_functions[0]) for candidate in candidates}

    assert len(candidates) == 3
    assert ("destroy_session", 13, "free") in calls
    assert ("clear_ctx", 17, "destroy_session") in calls
    assert ("clear_ctx", 18, "free") in calls


def test_multi_ptr_leak2_skips_struct_without_pointer_members(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

struct Plain {
    int value;
};

void release_plain(struct Plain *plain) {
    free(plain);
}
""",
    )

    assert list(Analyzer().find_candidates(tmp_path)) == []


def test_multi_ptr_leak2_detects_cpp_delete_and_delete_array(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
class Record {
public:
    char *data;
    size_t len;
};

class Batch {
public:
    Record *items;
};

void release_record(Record *record) {
    delete record;
}

void release_batch(Batch *batch) {
    delete[] batch->items;
}
""",
        name="sample.cpp",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    calls = {(c.function, c.related_functions[0]) for c in candidates}

    assert ("release_record", "delete") in calls
    assert ("release_batch", "delete[]") in calls


def test_multi_ptr_leak2_handles_anonymous_typedef_alias(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

typedef struct {
    char *name;
    int id;
} Node;

void destroy_node(Node *node) {
    free(node);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.function == "destroy_node"
    assert "结构体: Node" in candidate.description
    assert "name: char*" in candidate.description


def test_multi_ptr_leak2_handles_forward_typedef_alias(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

typedef struct Session Session_t;

struct Session {
    char *buf;
};

void destroy_session(Session_t *s) {
    free(s);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.function == "destroy_session"
    assert "结构体: Session" in candidate.description


class _FakeDb:
    def __init__(
        self,
        functions: list[dict],
        structs: list[dict],
        *,
        complete: bool = False,
    ) -> None:
        self._functions = functions
        self._structs = structs
        self._complete = complete

    def get_all_functions(self):
        return self._functions

    def get_all_structs(self):
        return self._structs

    def is_index_complete(self):
        return self._complete


def test_multi_ptr_leak2_db_path_uses_indexed_functions_and_structs(tmp_path: Path) -> None:
    db = _FakeDb(
        functions=[
            {
                "file_path": "src/release.c",
                "start_line": 10,
                "body": "void release_packet(Packet *pkt) {\n    free(pkt);\n}\n",
            },
        ],
        structs=[
            {
                "file_path": "include/packet.h",
                "start_line": 5,
                "name": "Packet",
                "definition": "struct Packet {\n    char *payload;\n    int len;\n};\n",
            },
        ],
    )

    candidates = list(Analyzer().find_candidates(tmp_path, db=db))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.function == "release_packet"
    assert candidate.file == "src/release.c"
    assert candidate.line == 11
    assert "src/release.c:10" in candidate.description
    assert "include/packet.h:5" in candidate.description
    assert "payload: char*" in candidate.description


def test_multi_ptr_leak2_method_no_arg_release_analyses_receiver(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
class Packet {
public:
    char *payload;
    int len;
    void destroy();
};

void caller(Packet *pkt) {
    pkt->destroy();
}
""",
        name="sample.cpp",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    method_candidates = [c for c in candidates if c.function == "caller"]

    assert len(method_candidates) == 1
    candidate = method_candidates[0]
    assert "调用形式: method_call" in candidate.description
    assert "释放实参: receiver" in candidate.description
    assert "receiver: pkt" in candidate.description
    assert "结构体: Packet" in candidate.description


def test_multi_ptr_leak2_method_with_arg_keeps_first_arg(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
struct Resource {
    char *data;
};

struct Pool {
    int slot;
};

void use(Pool *pool, Resource *res) {
    pool->release(res);
}
""",
        name="sample.cpp",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    assert len(candidates) == 1
    candidate = candidates[0]
    assert "调用形式: method_call" in candidate.description
    assert "释放实参: first_argument" in candidate.description
    assert "receiver: pool" in candidate.description
    assert "结构体: Resource" in candidate.description


def test_multi_ptr_leak2_method_skips_weak_business_methods(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
class Cache {
public:
    char *items;
    void reset();
    void close();
    void clear();
};

void use(Cache *c) {
    c->reset();
    c->close();
    c->clear();
}
""",
        name="sample.cpp",
    )

    assert list(Analyzer().find_candidates(tmp_path)) == []


def test_multi_ptr_leak2_method_strong_name_fallbacks_to_receiver(tmp_path: Path) -> None:
    # 显式参数 `count` 不是结构体；method 名 `destroy` 是强释放词
    # → fallback 分析 receiver `pkt`。
    _write_source(
        tmp_path,
        """
class Packet {
public:
    char *payload;
    void destroy(int count);
};

void use(Packet *pkt) {
    pkt->destroy(1);
}
""",
        name="sample.cpp",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    assert len(candidates) == 1
    candidate = candidates[0]
    assert "释放实参: receiver" in candidate.description
    assert "receiver: pkt" in candidate.description


def test_multi_ptr_leak2_db_and_file_merge(tmp_path: Path) -> None:
    # DB 给一个 struct + 一个 function；文件里再写一个 struct + 一个 function。
    # 期望两侧的候选都被产出，证明 merge 生效而不是 replace。
    _write_source(
        tmp_path,
        """
typedef struct OnDiskOnly {
    char *bytes;
} OnDiskOnly;

void destroy_on_disk(OnDiskOnly *o) {
    free(o);
}
""",
        name="extra.c",
    )

    db = _FakeDb(
        functions=[
            {
                "file_path": "src/release.c",
                "start_line": 10,
                "body": "void destroy_packet(Packet *pkt) {\n    free(pkt);\n}\n",
            },
        ],
        structs=[
            {
                "file_path": "include/packet.h",
                "start_line": 5,
                "name": "Packet",
                "definition": "struct Packet {\n    char *payload;\n};\n",
            },
        ],
    )

    candidates = list(Analyzer().find_candidates(tmp_path, db=db))
    functions = sorted({c.function for c in candidates})

    assert "destroy_packet" in functions
    assert "destroy_on_disk" in functions


def test_multi_ptr_leak2_complete_db_skips_file_fallback(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
typedef struct OnDiskOnly {
    char *bytes;
} OnDiskOnly;

void destroy_on_disk(OnDiskOnly *o) {
    free(o);
}
""",
        name="extra.c",
    )

    db = _FakeDb(
        functions=[
            {
                "file_path": "src/release.c",
                "start_line": 10,
                "body": "void destroy_packet(Packet *pkt) {\n    free(pkt);\n}\n",
            },
        ],
        structs=[
            {
                "file_path": "include/packet.h",
                "start_line": 5,
                "name": "Packet",
                "definition": "struct Packet {\n    char *payload;\n};\n",
            },
        ],
        complete=True,
    )

    candidates = list(Analyzer().find_candidates(tmp_path, db=db))
    functions = sorted({c.function for c in candidates})

    assert functions == ["destroy_packet"]


def test_multi_ptr_leak2_description_uses_renamed_keyword_field(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

typedef struct Packet {
    char *payload;
} Packet;

void destroy_packet(Packet *pkt) {
    free(pkt);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    assert len(candidates) == 1
    candidate = candidates[0]
    assert "释放调用: free(pkt)" in candidate.description
    assert "调用形式: function_call" in candidate.description
    assert "释放实参: first_argument" in candidate.description


def test_multi_ptr_leak2_reports_correct_line_in_nested_if_for(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
#include <stdlib.h>

typedef struct Packet {
    char *payload;
} Packet;

void process(Packet *pkt, int n, int retry) {
    for (int i = 0; i < n; i++) {
        if (retry) {
            free(pkt);
            continue;
        }
        free(pkt);
    }
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))
    lines = sorted(c.line for c in candidates)

    assert lines == [11, 14]
    for c in candidates:
        assert c.function == "process"
        assert "free(pkt)" in c.description
