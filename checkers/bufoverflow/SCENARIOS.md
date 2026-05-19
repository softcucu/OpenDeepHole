# 缓冲区越界检测 — 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 代码中由 **结构体强转 + 长度校验缺失** 导致的缓冲区越界读写（CWE-125 / CWE-787），共 6 条规则，覆盖三大类模板：

1. **A 类（cast → 字段解引用）**：把外部缓冲区强转为结构体指针后直接访问字段，但 cast 之前没有 `remaining >= sizeof(*p)` 的最小头部长度校验
2. **B 类（cast → 读长度字段 → 才校验头部）**：cast 之后先读取 `p->len` 作为后续 total length 校验依据，而读取这一步本身就要求 `remaining >= sizeof(*p)`
3. **C 类（变长尾部成员，校验不完整）**：仅校验了 sizeof(header)，但没有校验 `payload_len <= remaining - sizeof(header)` 就对尾部成员做索引 / 拷贝 / 指针运算

---

## 正例场景（工具可检测并确认的越界）

### 场景 1：cast 后直接访问字段，无最小头部校验（A 类）

```c
int parse_msg(const uint8_t *buf, size_t remaining) {
    struct msg_hdr *h = (struct msg_hdr *)buf;
    // ← cast 前没有 if (remaining < sizeof(*h)) return -1;
    if (h->type == MSG_PING) {        // 短包时 h->type 读取本身就越界
        return handle_ping(h);
    }
    return 0;
}
```

**规则**：`struct-cast-field-access-without-min-size-check`
**LLM 分析**：追溯 `buf / remaining` 来源，确认来自外部输入，且整个函数找不到等价的最小长度校验，判定为越界读。

---

### 场景 2：内联 cast 立即解引用（A-inline）

```c
void handle_packet(const uint8_t *pkt, size_t len) {
    if (((struct ctrl_hdr *)pkt)->cmd == CMD_RESET) {
        // ← 没有 if (len < sizeof(struct ctrl_hdr)) 的前置校验
        reset_device();
    }
}
```

**规则**：`inline-struct-cast-field-access`
**说明**：内联 cast 写法很容易完全绕过任何中间长度校验，是 A 类中风险最高的形式。

---

### 场景 3：cast → 读长度字段 → 才校验头部（B 类）

```c
int parse_tlv(const uint8_t *buf, size_t remaining) {
    struct tlv *t = (struct tlv *)buf;
    uint32_t n = t->len;                          // ← 此步要求 remaining >= sizeof(*t)
    if (remaining < sizeof(*t) + n) return -1;    // 校验时机太晚
    memcpy(dst, t->data, n);
    return 0;
}
```

**规则**：`struct-length-field-read-before-header-check`
**LLM 分析**：当 `remaining < sizeof(*t)` 时，`t->len` 的读取本身就越界，攻击者可构造短于 sizeof(tlv) 的包触发越界读，判定为高危。

---

### 场景 4：变长尾部成员被索引，但未做完整 payload 校验（C-1）

```c
int read_field(const uint8_t *buf, size_t remaining, uint32_t idx) {
    if (remaining < sizeof(struct rec)) return -1;     // 只校验了 header
    struct rec *r = (struct rec *)buf;
    return r->payload[idx];                            // ← idx 未与 remaining-sizeof(*r) 比较
}
```

**规则**：`variable-tail-member-index-without-full-bound-check`
**LLM 分析**：仅校验 sizeof(header) 不足以保证 `payload[idx]` 在缓冲区内，需要 `idx < remaining - sizeof(*r)` 类完整校验，判定为越界读。

---

### 场景 5：尾部成员 + 长度字段一起传给拷贝函数，缺少完整校验（C-2）

```c
int copy_payload(const uint8_t *buf, size_t remaining, uint8_t *dst) {
    if (remaining < sizeof(struct frame)) return -1;
    struct frame *f = (struct frame *)buf;
    uint32_t n = f->plen;
    // ← 只校验了 header，没有 if (n > remaining - sizeof(*f)) return -1;
    memcpy(dst, f->data, n);                            // 可越界读
    return 0;
}
```

**规则**：`variable-tail-member-passed-with-length-without-full-check`
**LLM 分析**：`f->plen` 是攻击者写入的 16/32 位字段，可远大于 `remaining - sizeof(*f)`，触发 memcpy 越界读源缓冲区。判定为高危。

---

### 场景 6：尾部指针运算未校验长度字段（C-3）

```c
int next_tlv(const uint8_t *buf, size_t remaining) {
    if (remaining < sizeof(struct tlv)) return -1;
    struct tlv *t = (struct tlv *)buf;
    uint32_t n = t->len;
    struct tlv *next = (struct tlv *)(t->data + n);    // ← 未校验 n <= remaining - sizeof(*t)
    return parse_tlv(next, remaining - sizeof(*t) - n);
}
```

**规则**：`variable-tail-pointer-arithmetic-without-full-check`
**LLM 分析**：`n` 不被校验，`next` 可越过缓冲区尾部；后续 `remaining - sizeof(*t) - n` 还可能发生无符号下溢，进一步放大攻击面。判定为高危。

---

### 场景 7：C++ `reinterpret_cast` 形式（与 C cast 同类）

```cpp
void on_message(const uint8_t *buf, size_t remaining) {
    auto *h = reinterpret_cast<MsgHeader *>(buf);
    if (h->magic != MAGIC) return;                     // ← 缺 remaining >= sizeof(MsgHeader) 校验
    dispatch(h->type, h->payload, h->len);
}
```

**规则**：`struct-cast-field-access-without-min-size-check`
**说明**：A / B / C 各模板均覆盖 `reinterpret_cast<T *>(buf)` 与 `auto *p = reinterpret_cast<T *>(buf)` 写法。

---

### 场景 8：宏内隐藏了长度校验（需 LLM 查看宏定义确认）

```c
#define CAST_HDR(buf, remaining, type, out) \
    do { if ((remaining) < sizeof(type)) return -1; (out) = (type *)(buf); } while (0)

int parse_msg(const uint8_t *buf, size_t remaining) {
    struct hdr *h;
    CAST_HDR(buf, remaining, struct hdr, h);   // 宏内已校验
    return h->type;                            // semgrep 仍报告，因为看不到宏体内的 if
}
```

**LLM 分析**：查看 `CAST_HDR` 宏定义，确认其内部已包含 `remaining < sizeof(type)` 校验，判定为误报。

---

### 场景 9：辅助函数完成校验（需 LLM 查看子函数确认）

```c
static int validate_hdr(const uint8_t *buf, size_t remaining) {
    return remaining >= sizeof(struct hdr) ? 0 : -1;
}

int parse_msg(const uint8_t *buf, size_t remaining) {
    if (validate_hdr(buf, remaining) < 0) return -1;   // semgrep 看不进函数体
    struct hdr *h = (struct hdr *)buf;
    return h->type;
}
```

**LLM 分析**：查看 `validate_hdr` 函数体，确认 cast 前已经完成等价校验，判定为误报。

---

### 场景 10：整数溢出绕过完整校验（隐性越界）

```c
int copy_payload(const uint8_t *buf, size_t remaining) {
    struct frame *f = (struct frame *)buf;
    uint32_t n = f->plen;
    if (sizeof(*f) + n > remaining) return -1;   // ← n 接近 UINT32_MAX 时 sizeof(*f)+n 溢出
    memcpy(dst, f->data, n);
    return 0;
}
```

**LLM 分析**：表面有"完整长度校验"，但 `sizeof(*f) + n` 在 `n` 为攻击者可控 32 位值时可整数溢出回小值，绕过校验导致越界。判定为高危，需要在 description 中明确指出溢出路径。

---

## 反例场景（semgrep 检出但工具正确过滤的误报）

### 反例 1：cast 前已有显式最小长度校验

```c
if (remaining < sizeof(struct hdr)) return -1;
struct hdr *h = (struct hdr *)buf;
return h->type;                  // semgrep 的 pattern-not-inside 排除，不报告
```

### 反例 2：完整变长校验已存在

```c
if (remaining < sizeof(*f) + f->plen) return -1;     // 排除 B 类报告
memcpy(dst, f->data, f->plen);
```

```c
if (n > remaining - sizeof(*f)) return -1;           // 排除 C-2 / C-3 报告
memcpy(dst, f->data, n);
```

### 反例 3：源缓冲区为固定大小数组，且 >= sizeof(T)

```c
uint8_t buf[1024];
fill_buf(buf);
struct small_hdr *h = (struct small_hdr *)buf;       // sizeof(small_hdr) <= 1024，编译期可证
if (h->type == X) ...
```

**LLM 分析**：`buf` 容量在编译期已经决定且足够，不存在外部输入控制，判定为误报。

### 反例 4：长度字段类型本身约束了最大值

```c
struct pkt { uint8_t len; uint8_t data[256]; };       // data 已预分配 256 >= UINT8_MAX
...
struct pkt *p = (struct pkt *)buf;
uint8_t n = p->len;
memcpy(dst, p->data, n);                              // n 最多 255 <= 256，不可越界
```

**LLM 分析**：长度字段宽度 + 预分配容量已足以保证不越界，判定为误报。

### 反例 5：调用链上层网关已统一校验

```c
// 上层入口：
void on_packet(const uint8_t *buf, size_t len) {
    if (len < MIN_VALID_PACKET) return;           // MIN_VALID_PACKET > sizeof(任何子结构)
    dispatch(buf, len);
}
// 当前函数已经在 dispatch 之后被调用，进入时 len 已被保证
```

**LLM 分析**：根据 candidate 描述中的调用链线索追溯到唯一入口，确认上层已做最小长度过滤，判定为误报。

### 反例 6：cast 目标是常量字面量 / 测试数据

```c
// tests/test_parser.c
uint8_t sample[] = { 0x01, 0x02, 0x03, ... };
struct hdr *h = (struct hdr *)sample;
assert(h->type == 1);
```

**LLM 分析**：文件位于 `tests/`，源数据为编译期字面量，判定为误报。

---

## 不支持的场景（超出工具检测范围）

- **非结构体形式的越界**：纯 `arr[i]` / `*(p+n)` 越界而无 cast 行为，本规则不覆盖（应交由其他越界检查器）
- **栈缓冲区固定大小写入越界**：如 `char buf[16]; strcpy(buf, untrusted);` 类经典栈溢出，不属于本规则模板
- **`memcpy(dst, src, n)` 中 dst 端越界**：本规则只看 src 端的 `$P->$PAYLOAD`，dst 端的容量分析需要独立规则
- **多次结构嵌套时的中间层校验缺失**：例如 outer 包含 inner 数组，仅 outer 做了校验但 inner 没有
- **跨翻译单元的长度约束**：长度保证由编译期 `enum` / `static const` 跨文件保证，semgrep 无法关联
- **指针别名导致的"看似有校验，实则失效"**：`p` 与 `q` 是同一缓冲区的别名，但 semgrep 视作不同变量
