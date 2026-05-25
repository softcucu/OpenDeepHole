# 整数溢出/翻转 - 可检测场景

## 概述

本检查器使用 Semgrep 扫描 C/C++ 代码中的高风险整数溢出/翻转候选，再由 opencode/LLM 做语义确认。Semgrep 只负责召回语法形态，不再做 tree-sitter 调用链追溯，也不要求静态证明候选来自入口函数。

LLM 复核必须确认外部可控性、真实类型和值域、有效 guard、可达性和危险 sink。

## 检测范围

### 危险使用点

- 内存分配大小：`malloc(size)`、`realloc(ptr, size)`、`kmalloc(size)` 等。
- 拷贝/填充长度：`memcpy(dst, src, len)`、`memset(dst, value, len)`、`memcpy_s(...)` 等。
- 数组下标：`arr[index]`。
- 指针偏移：`*(ptr + offset)`、`*(ptr - offset)`。
- 循环边界：`for (...; i < bound; ...)`。

### 算术形态

- 加法上溢：`a + b`。
- 减法下溢：`len - header`、`count - 1`。
- 乘法上溢：`count * sizeof(T)`、`width * height`。
- 窄化截断：`uint16_t n = a + b`、`(uint8_t)(len + off)`。

## 可检测的漏洞场景

### 场景一：长度减 header 后进入 memcpy

```c
void parse_packet(char *dst, const char *src, uint32_t packet_len) {
    uint32_t body_len = packet_len - 8;
    memcpy(dst, src, body_len);
}
```

当 `packet_len < 8` 且没有有效下界检查时，无符号下溢会让 `body_len` 变成巨大值。

### 场景二：加法结果直接作为下标或偏移

```c
void write_at(char *buf, uint32_t base, uint32_t delta) {
    buf[base + delta] = 0;
}
```

`base + delta` 可能上溢回绕，或超过真实缓冲区容量。LLM 需要确认 `base/delta` 来源和值域。

### 场景三：乘法 size 计算后分配

```c
void alloc_items(uint32_t count) {
    size_t bytes = count * sizeof(Item);
    Item *items = malloc(bytes);
    init_items(items, count);
}
```

如果 `count * sizeof(Item)` 溢出，分配可能过小，后续按 `count` 初始化会越界。

### 场景四：窄化转换后进入危险 sink

```c
void copy_short(char *dst, const char *src, uint32_t a, uint32_t b) {
    uint16_t n = a + b;
    memcpy(dst, src, n);
}
```

如果调用者或协议仍按完整 `a + b` 语义准备数据，截断后的长度可能造成分配/拷贝不一致。

### 场景五：翻转结果作为循环边界

```c
void clear_items(char *dst, uint32_t count) {
    uint32_t limit = count - 1;
    for (uint32_t i = 0; i < limit; i++) {
        dst[i] = 0;
    }
}
```

`count == 0` 时 `limit` 下溢为巨大值，循环可能造成越界写或拒绝服务。

## 反例场景

### 有效下界检查

```c
void safe_sub(char *dst, const char *src, uint32_t packet_len) {
    if (packet_len < 8) return;
    uint32_t body_len = packet_len - 8;
    memcpy(dst, src, body_len);
}
```

### 使用溢出检查 API

```c
void safe_mul(uint32_t count) {
    size_t bytes;
    if (__builtin_mul_overflow(count, sizeof(Item), &bytes)) {
        return;
    }
    void *p = malloc(bytes);
}
```

### 运算结果未进入危险使用点

```c
void log_remaining(uint32_t total, uint32_t used) {
    uint32_t remaining = total - used;
    printf("%u\n", remaining);
}
```

### 纯常量表达式

```c
void fixed_copy(char *dst, const char *src) {
    uint32_t len = 64 - 8;
    memcpy(dst, src, len);
}
```

## 局限性

- Semgrep 不理解完整数据流、宏语义、跨函数值域和协议约束。
- 静态规则会保守召回，真实漏洞必须由 LLM 查看完整函数和必要调用方后确认。
- 入口函数、外部可控性和触发路径不再由静态分析证明。
- 有效 guard 的复杂变体可能仍会被召回，需要在 LLM 阶段判为误报。
