# 多层指针成员资源泄露检测 — 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 代码中由 **多层指针成员（`ctx->session->buf` 形式）** 引起的资源泄露（CWE-401 / CWE-772），共 5 条规则，覆盖五种典型失误模式：

1. **acquire-no-release-in-function**：多层成员被赋为资源获取函数返回值，但当前函数内未看到任何对该成员的后续操作
2. **overwrite-without-release**：多层成员被两次资源赋值覆盖，中间没有释放
3. **null-without-release**：多层成员被直接置 NULL，置空前未释放原资源
4. **direct-realloc-result-lost**：多层成员直接接收 realloc 类返回值，失败时旧指针丢失
5. **temp-resource-stored-into-multi-ptr-member-no-release**：临时变量持有资源后赋值给多层成员，当前函数内未释放该成员

---

## 正例场景（工具可检测并确认的资源泄露）

### 场景 1：函数内分配后既未释放也无 owner 销毁路径（规则 1）

```c
int load_record(Context *ctx, const char *key) {
    ctx->session->buf = VOS_Malloc(MAX_RECORD);   // 分配
    if (read_record(key, ctx->session->buf) < 0) {
        return -1;                                // ← 错误返回，未 free
    }
    return 0;
}
```

且 `Session` / `Context` 都**没有**配套的 destroy 函数会释放 `buf` 字段。

**规则**：`multi-ptr-member-resource-acquire-no-release-in-function`
**LLM 分析**：`view_struct_code` 查 `Session`，无 destroy；`find_function_references` 查 `load_record`，caller 不调 destroy。判定为真实漏洞。

---

### 场景 2：错误返回路径漏 free（规则 1 的常见子形态）

```c
int init_session(Context *ctx) {
    ctx->session->buf = malloc(1024);
    if (open_socket(&ctx->session->fd) < 0) {
        free(ctx->session->buf);                 // 已 free
        return -1;
    }
    if (handshake(ctx->session) < 0) {           // ← 这条错误路径漏 free buf
        return -2;
    }
    return 0;
}
```

**LLM 分析**：函数错误路径并不一致，第二条 return 路径上 buf 未释放且 caller 不会调 destroy。判定为真实漏洞。

---

### 场景 3：覆盖前未释放（规则 2）

```c
int reload_buffer(Context *ctx, size_t a, size_t b) {
    ctx->session->buf = VOS_Malloc(a);
    ...
    ctx->session->buf = VOS_Malloc(b);   // ← 旧 buf 丢失
    return 0;
}
```

**规则**：`multi-ptr-member-resource-overwrite-without-release`，severity=ERROR
**说明**：两次资源赋值之间没有任何对 `ctx->session->buf` 的函数调用，旧资源直接泄露。

---

### 场景 4：直接置 NULL，置空前未释放（规则 3）

```c
void reset_session(Context *ctx) {
    ctx->session->state = STATE_IDLE;
    ctx->session->buf = NULL;            // ← 原 buf 丢失
}
```

**规则**：`multi-ptr-member-null-without-release`
**LLM 分析**：reset 函数典型职责是释放并清空，但本例只清空不释放。判定为真实漏洞。

---

### 场景 5：直接接收 realloc 返回值（规则 4，确定性 UB）

```c
int grow_buffer(Context *ctx, size_t new_size) {
    ctx->session->buf = realloc(ctx->session->buf, new_size);
    // ← realloc 失败返回 NULL，旧 buf 指针丢失
    if (!ctx->session->buf) return -1;
    return 0;
}
```

**规则**：`multi-ptr-member-direct-realloc-result-lost`，severity=ERROR
**LLM 分析**：标准 realloc 失败语义明确，OOM 场景一定泄露。判定为真实漏洞，severity=high。

---

### 场景 6：临时变量赋值给多层成员后未释放（规则 5）

```c
int attach_buffer(Context *ctx, size_t len) {
    uint8_t *buf = VOS_Malloc(len);
    if (fill_buffer(buf, len) < 0) {
        // ← 错误路径未 free buf；也没赋给 ctx->session->buf
        return -1;
    }
    ctx->session->buf = buf;             // 转交
    // ← 函数返回，caller 是否会通过 destroy_session 释放？
    return 0;
}
```

**规则**：`temp-resource-stored-into-multi-ptr-member-no-release`
**LLM 分析**：转交后由 owner 销毁是正常架构，但如果 caller 不会调 destroy 或错误路径未回滚，则泄露。需要查 caller 与 destroy_session 实现。

---

### 场景 7：cleanup 顺序错误（规则 3 的常见子形态）

```c
void clear_state(Context *ctx) {
    ctx->session->buf = NULL;            // ← 先 NULL，下面已经访问不到原指针
    free(ctx->session->buf);             // free(NULL)，无效操作
}
```

**LLM 分析**：明显的代码顺序错误，资源完全丢失。判定为真实漏洞。

---

## 反例场景（semgrep 检出但工具正确过滤的误报）

### 反例 1：owner 链有配套 destroy 函数级联释放（最常见误报）

```c
struct session { uint8_t *buf; int fd; };

void destroy_session(Session *s) {     // 配套销毁函数
    if (!s) return;
    free(s->buf);
    close(s->fd);
    free(s);
}

int alloc_session_resources(Context *ctx) {
    ctx->session->buf = malloc(1024);   // 此处 semgrep 报告"未释放"
    ctx->session->fd  = open(...);
    return 0;
}
```

**LLM 分析**：用 `find_function_references` / 全工程搜索发现存在 `destroy_session`，且 caller 在生命周期结束时一定调用。`alloc_session_resources` 是初始化函数，所有权转移给 caller，判定为误报。

---

### 反例 2：宏内完成释放

```c
#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)

int reload(Context *ctx, size_t n) {
    SAFE_FREE(ctx->session->buf);        // semgrep 看不见宏内的 free
    ctx->session->buf = malloc(n);
    return 0;
}
```

**LLM 分析**：查看 `SAFE_FREE` 宏定义，确认内部已 free，判定为误报。

---

### 反例 3：通过 wrapper 函数释放

```c
int reload(Context *ctx, size_t n) {
    free_session_buf(ctx->session);      // wrapper 内部 free(s->buf); s->buf = NULL;
    ctx->session->buf = malloc(n);
    return 0;
}
```

**LLM 分析**：`view_function_code` 查 `free_session_buf`，确认其释放该成员。判定为误报。

注意：semgrep 的 `pattern-not` 是 `$ANY($FIELD, ...)`，要求字段表达式**字面**出现在参数列表中。`free_session_buf(ctx->session)` 传的是 `ctx->session` 而非 `ctx->session->buf`，不匹配 `$ANY($FIELD, ...)`，因此会误报。

---

### 反例 4：借用语义（多层成员只是别名）

```c
extern uint8_t g_global_buf[];

void attach_global(Context *ctx) {
    ctx->session->buf = g_global_buf;    // 借用全局缓冲区
    // 不应该 free
}
```

**LLM 分析**：`g_global_buf` 是全局，由编译器/运行时管理，不应当作动态资源处理。判定为误报。

---

### 反例 5：realloc wrapper 失败 abort

```c
// 项目使用的 wrapper：失败时 abort 而非返回 NULL
void *xrealloc(void *p, size_t n);

int grow(Context *ctx, size_t n) {
    ctx->session->buf = xrealloc(ctx->session->buf, n);   // 失败时 abort，不会丢指针
    return 0;
}
```

**LLM 分析**：`view_function_code` 查 `xrealloc` 实现，确认其失败时 `abort()`。判定为误报。

---

### 反例 6：两次赋值之间通过临时变量已转交

```c
int rotate(Context *ctx) {
    ctx->session->buf = VOS_Malloc(SMALL);
    uint8_t *tmp = ctx->session->buf;
    cache_old_buf(tmp);                  // 转交给全局缓存
    ctx->session->buf = VOS_Malloc(LARGE);
    return 0;
}
```

**LLM 分析**：第二次赋值前 `ctx->session->buf` 已经通过 `tmp` 被全局缓存接管。判定为误报。但要注意：`cache_old_buf` 是真接管所有权还是只是借引用？需要看其实现。

---

### 反例 7：当前函数是纯 getter / 计算函数，没有写入意图

某些规则误报源于代码本身的 dead code 或测试桩，比如：

```c
// tests/mock_session.c
void mock_init(Context *ctx) {
    ctx->session->buf = malloc(64);   // 测试桩，无释放
}
```

**LLM 分析**：路径含 `tests/` / `mock`，且 mock 生命周期由测试框架管理。判定为误报。

---

## 不支持的场景（超出工具检测范围）

- **跨函数所有权追踪**：函数 A 分配并赋给 `ctx->session->buf`，函数 B 在另一时机释放；本规则只看单函数内
- **回调注册后由回调释放**：将多层成员注册到 callback list，由回调中释放
- **异步释放**：通过 worker queue / event loop 异步释放
- **C++ 析构链中的释放**：本规则面向 C 风格的 destroy 函数，C++ 析构函数中的 `delete` 由 `double_free` 类规则覆盖
- **更深层指针**（4 层以上）：本规则只覆盖 2-4 层 `->` 链，更深层结构需扩展
- **数组下标形式的成员**：`ctx->sessions[i].buf = malloc(...)` 不被 `->$F1->$F2` 模式匹配
- **通过函数指针调用的释放**：`ctx->ops->free(ctx->session->buf)`，因为 `$ANY` 是字面函数名，间接调用可能仍能匹配，但 wrapper 内调用看不见
- **realloc 成功路径上的相邻泄露**：realloc 收缩时旧 buf 一般在内部释放，规则不关心；扩张时如果只是用 wrapper 失败保留旧值，需要看 wrapper
