# 多层指针外层释放遗漏成员检测 — 可扫描场景

## 检测规则概述

`multi_ptr_leak2` 用 tree-sitter 做静态预过滤，目标是发现 C/C++ 中释放结构体、类或联合体最外层对象时，可能遗漏释放内部指针成员的资源泄露场景（CWE-401 / CWE-772）。

静态阶段只做候选筛选：

1. 遍历全仓 C/C++ 函数，收集释放函数名，例如 `free`、`destroy_*`、`release_*`、`cleanup_*`、`clear_*`、`put_*`、`delete` 等。
2. 收集含指针成员的 `struct` / `class` / `union` 定义。
3. 遍历所有释放函数调用点，解析第一个实参类型。
4. 如果实参是含指针成员的结构体对象或结构体指针，则生成候选，交给 opencode skill 判断是否真实漏洞。

该 checker 的静态结果是高召回候选，不直接确认漏洞。真实结论依赖 LLM 查看释放函数实现、结构体所有权和调用链。

---

## 正例场景（应确认的资源泄露）

### 场景 1：destroy 函数只 free 外层对象

```c
typedef struct Packet {
    char *payload;
    char *owner;
    int len;
} Packet;

void destroy_packet(Packet *pkt) {
    if (!pkt) {
        return;
    }
    free(pkt);                 // payload / owner 未释放
}
```

**静态候选**：`free(pkt)`，`Packet` 含 `payload`、`owner` 指针成员。  
**LLM 分析**：`view_struct_code` 确认字段为 owned buffer；`view_function_code` 确认 `destroy_packet` 没有释放成员。判定为真实漏洞，severity 通常为 `medium`。

---

### 场景 2：错误路径释放半初始化对象，遗漏已分配成员

```c
typedef struct Session {
    char *buf;
    int fd;
} Session;

int create_session(Session **out) {
    Session *s = calloc(1, sizeof(*s));
    s->buf = malloc(4096);

    if (open_fd(&s->fd) < 0) {
        free(s);               // 错误路径只释放外层对象
        return -1;
    }

    *out = s;
    return 0;
}
```

**静态候选**：`free(s)`。  
**LLM 分析**：`buf` 在失败前已分配，错误路径未调用 `free(s->buf)` 或 `destroy_session(s)`。判定为真实漏洞，severity 通常为 `medium`；如果外部输入可频繁触发失败路径，可升为 `high`。

---

### 场景 3：cleanup wrapper 语义不完整

```c
typedef struct Cache {
    char *key;
    void *value;
} Cache;

void cleanup_cache(Cache *cache) {
    if (cache == NULL) {
        return;
    }
    memset(cache, 0, sizeof(*cache));
    free(cache);               // key / value 已被清零，原指针丢失
}
```

**静态候选**：`free(cache)`。  
**LLM 分析**：`memset` 发生在释放成员之前，导致 `key`、`value` 原指针丢失。判定为真实漏洞。

---

### 场景 4：多层 owner 只释放中间层，遗漏中间层内部成员

```c
typedef struct Channel {
    char *name;
    uint8_t *rx_buf;
} Channel;

typedef struct Context {
    Channel *channel;
} Context;

void destroy_context(Context *ctx) {
    if (!ctx) {
        return;
    }
    free(ctx->channel);        // Channel.name / Channel.rx_buf 未释放
    free(ctx);
}
```

**静态候选**：`free(ctx->channel)` 和 `free(ctx)` 都可能命中。  
**LLM 分析**：重点查看 `Channel` 定义和是否存在 `destroy_channel`。如果没有级联释放 `name`、`rx_buf`，`free(ctx->channel)` 是真实漏洞。

---

### 场景 5：C++ delete 裸指针对象，但类没有析构释放成员

```cpp
class Record {
public:
    char *data;
    size_t len;
};

void release_record(Record *record) {
    delete record;             // data 未释放
}
```

**静态候选**：`delete record`。  
**LLM 分析**：查看 `Record` 是否有析构函数、基类析构或智能指针成员。若 `data` 是 owned 裸指针且无析构释放，判定为真实漏洞。

---

## 反例场景（应判为误报）

### 反例 1：释放函数已先释放所有 owned 指针成员

```c
typedef struct Packet {
    char *payload;
    char *owner;
} Packet;

void destroy_packet(Packet *pkt) {
    if (!pkt) {
        return;
    }
    free(pkt->payload);
    free(pkt->owner);
    free(pkt);
}
```

**静态候选**：`free(pkt)` 仍会被预过滤命中。  
**LLM 分析**：完整函数内已释放所有 owned 指针成员，判定为误报。

---

### 反例 2：通过子 cleanup 函数级联释放

```c
typedef struct Session {
    char *buf;
} Session;

typedef struct Context {
    Session *session;
} Context;

void destroy_session(Session *s) {
    if (!s) return;
    free(s->buf);
    free(s);
}

void destroy_context(Context *ctx) {
    if (!ctx) return;
    destroy_session(ctx->session);
    free(ctx);
}
```

**静态候选**：`destroy_session(ctx->session)` 和 `free(ctx)`。  
**LLM 分析**：进入 `destroy_session` 可确认 `Session.buf` 已释放；`Context.session` 也已通过子 cleanup 释放。判定为误报。

---

### 反例 3：指针成员是 borrowed pointer，不由该结构体释放

```c
typedef struct View {
    const char *name;           // 指向全局配置，不拥有
    const uint8_t *data;        // 指向 caller buffer，不拥有
} View;

void destroy_view(View *view) {
    free(view);
}
```

**静态候选**：`free(view)`。  
**LLM 分析**：查看字段注释、初始化函数和调用方可确认 `name` / `data` 是借用指针，不应由 `View` 释放。判定为误报。

---

### 反例 4：C++ 析构函数释放裸指针成员

```cpp
class Buffer {
public:
    char *data;

    ~Buffer() {
        delete[] data;
    }
};

void release_buffer(Buffer *buffer) {
    delete buffer;
}
```

**静态候选**：`delete buffer`。  
**LLM 分析**：`delete buffer` 会调用析构函数，析构函数已释放 `data`。判定为误报。

---

### 反例 5：成员由外层 arena / pool 统一释放

```c
typedef struct Node {
    char *name;                 // 从 arena 分配
} Node;

void destroy_node(Node *node) {
    free(node);
}

void destroy_arena(Arena *arena) {
    arena_free_all(arena);      // 统一释放所有 name
}
```

**静态候选**：`free(node)`。  
**LLM 分析**：如果 `name` 明确来自 arena，且 arena 生命周期覆盖所有 `Node`，`destroy_node` 不释放 `name` 是设计行为。判定为误报。

---

## LLM 复审要点

1. 第一优先级是查看候选函数完整源码，确认释放调用前后是否已有成员释放。
2. 如果释放调用是 wrapper，例如 `destroy_ctx(ctx)`，必须查看 wrapper 实现，而不是只看函数名。
3. 查看结构体定义和初始化路径，判断指针成员是否 owned。
4. 对 C++ 类型，检查析构函数、基类析构、智能指针成员和容器成员。
5. 对多层 owner，沿 `destroy_*` / `cleanup_*` 链继续追踪一级到两级，确认是否级联释放。
6. 如果字段是 borrowed pointer、全局对象、字符串字面量、arena/pool 分配对象，应倾向误报。

## 严重程度建议

- `high`: 常规请求路径或循环路径反复释放对象并稳定泄露，或泄露大块 buffer / 句柄 / 显存等关键资源。
- `medium`: 错误路径、重置路径或对象生命周期结束时泄露，触发频率中等。
- `low`: 一次性初始化失败、进程退出路径或测试代码中的小量泄露。

## 静态阶段已知限制 (known limitations)

以下情况静态阶段当前**不会产出 candidate**，是设计取舍而非 bug。修复需要扩展
`analyzer.py` 中相应的解析路径，且必须同步更新本节。

1. **数组下标 / 取地址实参**：`free(arr[i])`、`delete[] arr[i]`、`free(&obj)`
   等表达式不被 `_field_type_from_expr` 识别。多层嵌套 cast（例如
   `free((Foo*)(void*)expr)` 里的 `expr` 仍含 cast）同样跳过。如果遇到容器
   owner 场景下因此漏报，需要扩展 `_field_type_from_expr` 而不是依赖 LLM 兜底
   —— 静态阶段跳过 → candidate 不会生成 → LLM 也拿不到 description。
2. **解引用 `*pp` 实参**：`free(*pp)` 在 `_field_type_from_expr` 里只能拿到
   `pp` 的类型（而不是解引用一次后的类型），结构体若是 `Foo **pp` 形式会
   错过。
3. **同名 struct 跨 namespace / 跨文件**：`structs_by_name` 用别名做主键
   `setdefault`，同名类型仅保留第一个定义。C++ 项目中的 `ns::Foo` 与
   `other::Foo` 不区分；这是 high-recall pre-filter 的边界，精确判定交给
   SKILL 阶段。
4. **前向 typedef 定义和使用跨文件**：`typedef struct X X_t;` 在 `a.h`、
   `struct X { ... }` 在 `b.h` 的情况下，文件单文件 fallback 路径无法把两者
   合并，必须由 DB 路径喂全所有 `type_definition` 节点。
5. **无扩展名头文件**：Linux kernel 风格的 `include/asm/atomic` 之类不带
   `.h` 后缀的头文件不会被 `_collect_source_files` 收集。
6. **同名 short release wrapper 的歧义**：当项目里存在多个同名 short release
   函数（不同 namespace 或 file-scope static），candidate 描述里不区分调用
   的是哪一个。LLM 调用 `view_function_code` 时需要按 `所在函数` 的文件路径
   反推；通常 MCP 工具的模糊匹配能 cover。

## 候选 description 字段说明

description 头部固定包含以下几个结构化字段，LLM 应直接读取而不是从代码片段
反推：

- `所在函数: <name> (<file>:<func_start_line>)` —— 候选函数定义位置。
- `调用形式: function_call | method_call | delete_expression` —— 释放调用
  在 AST 上的形态。
- `静态分析实参: first_argument | receiver | delete_operand` —— 静态阶段
  解析为含指针成员结构体的"那个表达式"。**这非常重要**：method 调用下，
  candidate 命中的可能是 receiver（`obj->destroy()` 类）而不是第一个显式
  参数。LLM 必须按这个字段判断释放语义。
- `receiver: <expr>`（仅 method_call）—— receiver 表达式文本，供 LLM 在
  `pool->release(t)` 类场景里判断"释放的是 receiver 还是显式参数"。
- `释放调用命中关键字: <keyword>` —— **指 callee 名字命中了哪个释放关键字**
  （例如 `destroy_session` 命中 `destroy`），不是"为什么这个函数被认定为
  释放函数"。仅用于辅助理解 callee 语义。
- `释放调用: <callee>(<arg_text>)` —— 原始调用文本。
- `实参类型: <type>` —— 静态分析实参的类型（带 `*` 表示指针）。
- `结构体: <name> (<file>:<line>)` —— 实参解析后命中的结构体定义位置。
- `指针成员: <field>: <type>*, ...` —— 该结构体的所有指针成员清单（owned
  / borrowed 区分由 LLM 判定）。
- `调用点上下文:` —— 释放调用点周围 ±4 行源码。
