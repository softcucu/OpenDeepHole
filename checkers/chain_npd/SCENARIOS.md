# 链式指针空指针解引用检测 -- 可扫描场景

## 检测规则概述

本检查器基于 tree-sitter AST 分析，检测 C/C++ 代码中链式指针解引用中间层指针未判空的问题（CWE-476）。

覆盖范围（与已有检查器去重）：
- 含 `[]` 下标的混合链：`arr[i]->field->sub`、`ctx->sessions[idx]->buf`
- 4 层及以上深链：`a->b->c->d->e`
- 纯 `->` 二三层链由 `mp_npd`（semgrep）覆盖，根指针由 `npd` 覆盖

---

## 正例场景（可检测）

### 场景 1：数组下标 + 箭头混合链未判空

```c
void process(Connection **conns, int idx) {
    conns[idx]->session->handle(conns[idx]->session->buf);
    // conns[idx]->session 未判空
}
```

### 场景 2：四层深链仅检查了根指针

```c
void deep_access(Context *ctx) {
    if (ctx) {
        int val = ctx->conn->session->data->len;
        // ctx->conn、ctx->conn->session、ctx->conn->session->data 均未判空
    }
}
```

### 场景 3：循环内数组元素指针链

```c
void batch_process(Task **tasks, int count) {
    for (int i = 0; i < count; i++) {
        tasks[i]->worker->execute(tasks[i]->worker->ctx);
        // tasks[i]->worker 未判空
    }
}
```

### 场景 4：错误处理路径上的深层链

```c
int cleanup(Engine *eng) {
    if (eng->pipeline->stage->cleanup_fn) {
        eng->pipeline->stage->cleanup_fn(eng->pipeline->stage->ctx);
    }
    // eng->pipeline 和 eng->pipeline->stage 均未判空
    return 0;
}
```

### 场景 5：函数参数为数组下标链

```c
void send_data(Server *srv, int client_id) {
    write(srv->clients[client_id]->socket->fd,
          srv->clients[client_id]->socket->buf,
          srv->clients[client_id]->socket->len);
    // srv->clients[client_id]->socket 未判空
}
```

---

## 反例场景（正确过滤的误报）

### 反例 1：入口集中判空

```c
void handle(Context *ctx) {
    if (!ctx || !ctx->conn || !ctx->conn->session || !ctx->conn->session->data) {
        return;
    }
    int val = ctx->conn->session->data->len;  // 安全，已判空
}
```

### 反例 2：assert 保护

```c
void process(Context *ctx) {
    assert(ctx->conn->session);
    ctx->conn->session->data->len;  // assert 已保护中间层
}
```

### 反例 3：`.` 操作符不构成解引用

```c
void read(Context *ctx) {
    if (ctx) {
        int len = ctx->header.options.timeout;
        // header 和 options 是结构体成员（.），不是指针解引用
    }
}
```

### 反例 4：sizeof 内的表达式不实际解引用

```c
void alloc(Context *ctx) {
    size_t sz = sizeof(ctx->conn->session->data);
    // sizeof 内不实际解引用
}
```

### 反例 5：纯 -> 二三层链（mp_npd 已覆盖）

```c
void simple(Context *ctx) {
    ctx->session->buf;
    // 纯 -> 两层链，总深度 2，由 mp_npd semgrep 规则覆盖
}
```

---

## 不支持的场景

- **跨函数判空追踪**：判空在调用方完成（由 AI SKILL 在复核阶段处理）
- **宏内判空**：`CHECK_NULL(ctx->session)` 等自定义宏（tree-sitter 无法展开宏）
- **C++ 智能指针**：`shared_ptr`、`unique_ptr` 等 RAII 类型
- **函数调用结果链**：`get_ctx()->session->buf` 中 `get_ctx()` 返回值作为链根
