# 内存泄漏检测 — 可扫描场景

## 检测规则概述

本检查器基于 tree-sitter 静态分析，检测 C/C++ 代码中异常分支（错误路径）的内存泄漏，并交由 opencode 复核。
核心思路：如果函数中某个变量在正常路径上被释放，但在某个异常退出点之前未被释放，则报告为候选泄漏。静态阶段会对 `if` 的 then/else 分支分别传播路径状态，过滤明显判空、所有权转移和循环内正常释放后的函数尾部 return 误报；初始化是否成功由 opencode 复核阶段判断。

---

## 正例场景（可检测到的泄漏模式）

### 场景 1：错误分支 return 前未释放

```c
void process_data() {
    char *buf = malloc(1024);
    char *tmp = malloc(256);

    if (init_failed()) {
        free(buf);
        return;  // ← tmp 未释放
    }

    // 正常路径
    use(buf, tmp);
    free(buf);
    free(tmp);
}
```

**检测原理**：`tmp` 在正常路径的第 10 行被释放，但在第 6 行的 return 之前未被释放。

### 场景 2：goto 错误处理缺少某个分配的释放

```c
int do_work() {
    Resource *r1 = acquire_resource();
    Resource *r2 = acquire_resource();
    Resource *r3 = acquire_resource();

    if (!r3)
        goto cleanup;  // ← r2 可能未在 cleanup 中释放

    process(r1, r2, r3);

cleanup:
    release_resource(r1);
    release_resource(r3);  // 漏了 r2
    return 0;
}
```

**检测原理**：`r2` 在函数中有 `release_resource` 调用（如果存在的话），但在 goto cleanup 路径中未被释放。

### 场景 3：循环中 continue 前未释放

```c
void process_list(Item *items, int count) {
    for (int i = 0; i < count; i++) {
        char *data = fetch_data(items[i].id);
        if (data == NULL)
            continue;

        if (validate(data) < 0) {
            continue;  // ← data 未释放
        }

        use(data);
        free(data);
    }
}
```

**检测原理**：`data` 在循环正常路径的末尾被释放，但在第 8 行 continue 之前未被释放。

### 场景 4：多重分配只释放部分

```c
int init_module() {
    Config *cfg = load_config();
    Logger *log = create_logger();
    Cache *cache = init_cache();

    if (!cache) {
        destroy_logger(log);
        return -1;  // ← cfg 未释放
    }

    // 正常路径全部使用并释放
    run(cfg, log, cache);
    free_config(cfg);
    destroy_logger(log);
    destroy_cache(cache);
    return 0;
}
```

**检测原理**：`cfg` 在正常路径有 `free_config` 释放，但在错误分支 return 前被遗漏。

---

## 反例场景（不会误报的情况）

### 反例 1：判空分支的 return（已过滤）

```c
void foo() {
    char *p = malloc(100);
    if (p == NULL)
        return;  // ← 不报告：p 此时是 NULL，无需释放
    use(p);
    free(p);
}
```

### 反例 2：返回值所有权转移（已过滤）

```c
char *create_buffer() {
    char *buf = malloc(1024);
    if (!buf)
        return NULL;
    fill(buf);
    return buf;  // ← 不报告：所有权转移给调用者
}
```

### 反例 3：仅在判空分支中调用释放（dead free，已过滤）

```c
void bar() {
    Resource *r = get_resource();
    if (r == NULL) {
        release(r);  // ← 此 free 被识别为 dead null free，不算有效释放
    }
    // 正常路径无释放（因为 r 可能由外部管理）
}
```

### 反例 4：赋给函数参数或参数成员（已过滤）

```c
int create_buffer(Owner *owner, char **out, int mode) {
    char *buf = malloc(1024);
    if (!buf)
        return -1;

    if (mode == 1) {
        *out = buf;      // 所有权传给调用者
        return 0;
    }
    if (mode == 2) {
        owner->buf = buf;  // 所有权传给参数成员
        return 0;
    }

    free(buf);
    return 0;
}
```

### 反例 5：循环内正常释放后函数返回（已过滤）

```c
int process_all(int count) {
    for (int i = 0; i < count; i++) {
        char *buf = malloc(128);
        if (buf == PRODUCT_NULL)
            continue;
        use(buf);
        free(buf);
    }
    return 0;  // 不要求再次释放循环内每轮资源
}
```

---

## 不支持的场景（超出静态分析能力，需 LLM 辅助判断）

- **RAII / 智能指针**：`std::unique_ptr`、`std::shared_ptr` 等自动管理内存
- **自定义引用计数**：通过 `AddRef()`/`Release()` 管理的对象
- **析构函数释放**：C++ 对象在作用域结束时自动析构
- **回调/异步释放**：资源由框架在回调中释放
- **条件式所有权**：根据运行时条件决定谁负责释放

这些场景会被静态分析报告为候选，但 LLM 复审阶段会判定为误报。
