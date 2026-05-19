# 多层指针空指针解引用检测 — 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 代码中由 **多层指针**（`ctx->session->buf` 形式）引起的空指针解引用（CWE-476），共 3 条规则，覆盖三类典型失误：

1. **multi-layer-pointer-use-before-null-check**：多层指针使用前未做任何完整判空（最宽泛规则）
2. **multi-layer-pointer-root-checked-child-unchecked**：根指针已判空，但中间层指针未判空（confidence=high）
3. **multi-layer-pointer-used-as-argument-before-null-check**：多层指针作为函数参数传入前未完整判空

---

## 正例场景（工具可检测并确认的空指针解引用）

### 场景 1：完全未判空，直接使用（规则 1）

```c
int handle_request(Context *ctx) {
    size_t len = ctx->session->buf_len;     // ← ctx 与 ctx->session 均未判空
    memcpy(out, ctx->session->buf, len);
    return 0;
}
```

**规则**：`multi-layer-pointer-use-before-null-check`
**LLM 分析**：`view_function_code` 看不到任何判空；`find_function_references` 发现 `handle_request` 由网络协议解码层直接调用，`Context *ctx` 来自请求帧，攻击者可构造 `ctx->session == NULL` 触发崩溃。判定为真实漏洞，severity=high。

---

### 场景 2：根指针已检查但中间层缺失（规则 2，confidence=high）

```c
int process(Context *ctx) {
    if (ctx) {                              // 只检查了根指针
        size_t n = ctx->session->len;       // ← session 可能为 NULL
        return handle(ctx->session->buf, n);
    }
    return 0;
}
```

**规则**：`multi-layer-pointer-root-checked-child-unchecked`
**LLM 分析**：`view_struct_code` 看 `Context`，发现 `session` 字段是延迟初始化（只有调用 `attach_session` 后才非空）。`process` 可能在 attach 前被调用。判定为真实漏洞。

---

### 场景 3：多层指针作为函数参数（规则 3）

```c
void encode(Context *ctx) {
    write_bytes(ctx->session->buf, ctx->session->len);   // ← 调用前已解引用
}
```

**规则**：`multi-layer-pointer-used-as-argument-before-null-check`
**LLM 分析**：即便 `write_bytes` 内部检查参数为 NULL，解引用 `ctx->session->buf` 已在调用前完成。函数入口处无任何校验，caller 也不保证。判定为真实漏洞。

---

### 场景 4：错误处理路径上漏判空（规则 1 的典型子形态）

```c
int rpc_handler(Request *req) {
    if (!req) return -1;
    if (req->state == STATE_ERROR) {
        log_error(req->payload->reason);    // ← 错误状态下 payload 可能为 NULL
        return -1;
    }
    process(req->payload->data);
    return 0;
}
```

**LLM 分析**：错误分支访问 `req->payload->reason` 前，未校验 `req->payload`。在 `STATE_ERROR` 设置时 `payload` 可能未被分配。判定为真实漏洞。

---

### 场景 5：reset 期间被并发调用导致中间层为 NULL（规则 2）

```c
void reader_thread(Context *ctx) {
    if (ctx) {
        read_data(ctx->session->fd);   // ← 若 main 线程已调 reset_session 把 session 置 NULL，崩溃
    }
}

void reset_session(Context *ctx) {
    free(ctx->session);
    ctx->session = NULL;
}
```

**LLM 分析**：多线程下 `session` 可能在 reader 访问期间被置 NULL。判定为真实漏洞。

---

### 场景 6：二级指针解引用后访问多层成员（规则 1）

```c
int hand_off(Item **pp) {
    return (*pp)->owner->id;        // ← *pp 与 (*pp)->owner 均未判空
}
```

**LLM 分析**：函数入口无校验。判定为真实漏洞。

---

## 反例场景（semgrep 检出但工具正确过滤的误报）

### 反例 1：入口集中判空（最常见误报）

```c
int handle(Context *ctx) {
    if (!ctx || !ctx->session) {
        return -EINVAL;                 // semgrep 的 pattern-not 已识别
    }
    use(ctx->session->buf);             // 不会报告
    return 0;
}
```

### 反例 2：判空通过项目自定义宏完成

```c
#define CHECK_NULL_RET(p, v) do { if (!(p)) return (v); } while (0)

int handle(Context *ctx) {
    CHECK_NULL_RET(ctx, -1);
    CHECK_NULL_RET(ctx->session, -1);
    use(ctx->session->buf);             // ← semgrep 看不到宏内 if，会误报
    return 0;
}
```

**LLM 分析**：`view_function_code` 查 `CHECK_NULL_RET` 宏，确认其内部做了非空校验并 return，判定为误报。

---

### 反例 3：判空发生在 inline 函数 / 防御函数内

```c
static inline void must_session(Context *ctx) {
    assert(ctx && ctx->session);
}

void op(Context *ctx) {
    must_session(ctx);                  // semgrep 看不到 inline 内 assert
    use(ctx->session->buf);             // ← 会误报
}
```

**LLM 分析**：进入 `must_session` 看到 `assert(ctx && ctx->session)`，判定为误报。

---

### 反例 4：结构体不变量保证中间层非空

```c
typedef struct {
    Session *session;     // 构造函数必填，destroy 才释放
} Context;

Context *create_ctx(void) {
    Context *c = malloc(sizeof(*c));
    c->session = create_session();
    return c;
}

void op(Context *ctx) {       // 调用方持有 create_ctx 的返回，且未 destroy
    if (ctx) {
        use(ctx->session->buf);   // ← regex 误报；语义上 session 不可能为 NULL
    }
}
```

**LLM 分析**：`view_struct_code` + 查 `create_ctx` / `destroy_ctx`，确认 `session` 在对象有效期内永远非空。判定为误报。

---

### 反例 5：所有 caller 都已校验

```c
// 当前函数无判空
void hot_op(Context *ctx) {
    use(ctx->session->buf);
}

// 唯一 caller
void dispatch(Context *ctx) {
    if (!ctx || !ctx->session) return;
    hot_op(ctx);                        // caller 已保证
}
```

**LLM 分析**：`find_function_references` 查 `hot_op`，确认所有 caller 都在判空保护下调用。判定为误报。

---

### 反例 6：嵌套但中间夹杂语句的判空

```c
void op(Context *ctx) {
    if (ctx) {
        log("got ctx");
        validate(ctx);                   // 此处可能 abort
        if (ctx->session) {
            use(ctx->session->buf);      // ← semgrep 的"嵌套 if 判空"模式可能匹配，
                                         //   也可能因夹了 validate(ctx) 失败
        }
    }
}
```

**LLM 分析**：实际看代码发现嵌套判空仍有效，判定为误报。

---

### 反例 7：测试 / mock 代码

```c
// tests/mock_ctx.c
void mock_use(Context *ctx) {
    return ctx->session->buf;
}
```

**LLM 分析**：路径在 `tests/`，且测试上下文中 `Context` 由测试夹具构造，`session` 已初始化。判定为误报。

---

## 不支持的场景（超出工具检测范围）

- **跨函数判空追踪**：判空在调用者，使用在被调函数；需要 LLM 通过 `find_function_references` 手动确认（属"误报由 LLM 过滤"而非工具支持）
- **数据流敏感分析**：`if (ctx->session) { ... } ... use(ctx->session->buf);` 中"..."里 session 是否被某个调用置 NULL，semgrep 无法跟踪
- **路径敏感分析**：某条 if 分支保证非空、另一条不保证，semgrep 仅做结构匹配
- **数组下标形式的成员**：`ctx->sessions[i].buf` 不被 `->$F1->$F2` 模式匹配
- **更深层指针**（5 层以上）：本规则只覆盖 2-4 层 `->` 链
- **C++ 智能指针 / 引用语义**：`ctx->session->buf`（其中 session 是 `std::unique_ptr<Session>`）虽语法相同，但 NULL 检查方式不同；本规则按 C 风格指针处理
- **函数指针调用结果再访问成员**：`ctx->get_session()->buf`，语法不同，本规则不覆盖
