# 安全内存函数越界检测 - 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 安全内存函数中的高风险 `dst/dstsz` 误用。规则主动召回成员目标、偏移目标、子数组目标和指针 `sizeof` 等容量明显不匹配场景；普通安全形态本身不会被规则匹配。

覆盖函数包括：

- `memcpy_s`
- `memmove_s`
- `memset_s`
- `strcpy_s`
- `strncpy_s`
- `strcat_s`
- `strncat_s`
- `wcscpy_s`
- `wcsncpy_s`
- `wcscat_s`
- `wcsncat_s`
- `sprintf_s`
- `snprintf_s`
- `vsprintf_s`
- `vsnprintf_s`
- `memcpy_sp`
- `memcpy_safe`
- `VOS_memcpy_safe`
- `VOS_MemCpy_S`
- `VOS_Mem_Copy_Safe`
- `VOS_MemCpy_Safe`

## 正例场景

### 场景 1：成员目标使用父对象大小

```c
typedef struct {
    int type;
    char payload[64];
} Msg;

void parse(Msg *msg, const char *src, size_t len, size_t row) {
    memcpy_s(msg->payload, sizeof(*msg), src, len);
    memcpy_s(msg->chunks[row], sizeof(msg->chunks), src, len);
}
```

`dst` 是 `payload`，真实空间是 `sizeof(msg->payload)`，不是 `sizeof(*msg)`。

### 场景 2：对象成员地址使用完整类型大小

```c
CLASS obj;
memcpy_s(&obj.field, sizeof(CLASS), src, len);
```

`dst` 是成员字段地址，不是完整对象起点。

### 场景 3：偏移目标仍使用完整数组大小

```c
char buf[128];
memcpy_s(buf + off, sizeof(buf), src, len);
memcpy_s(&buf[i], sizeof(buf), src, len);
memcpy_s((char *)(buf + off), sizeof(buf), src, len);
```

真实剩余空间是 `sizeof(buf) - off` 或 `sizeof(buf) - i`。

### 场景 4：成员数组偏移仍使用完整成员大小

```c
memcpy_s(msg.payload + off, sizeof(msg.payload), src, len);
memcpy_s(&msg.payload[i], sizeof(msg.payload), src, len);
```

即使用的是成员本体大小，`dst` 已经偏移，仍需要扣除 offset。

### 场景 5：指针变量使用 `sizeof(ptr)`

```c
char *buf;
memcpy_s(buf, sizeof(buf), src, len);

void copy(char *dst, const char *src, size_t len) {
    memcpy_s(dst, sizeof(dst), src, len);
}
```

`sizeof(buf)` 是指针宽度，不是缓冲区容量。

### 场景 6：`memset_s` 同类误用

```c
memset_s(buf + off, sizeof(buf), 0, len);
memset_s(msg.payload, sizeof(msg), 0, len);
```

`memset_s` 没有源缓冲区，但 `dst/dstsz/count` 的容量关系仍然成立。

### 场景 7：字符串安全函数的同类容量错误

```c
strcpy_s(msg.name, sizeof(msg), src);
strncpy_s(buf + off, sizeof(buf), src, n);
strncat_s(msg.name + off, sizeof(msg.name), src, n);
```

字符串函数同样要求 `dstsz` 描述目标缓冲区容量。对偏移目标、成员目标和子数组目标，也要考虑实际剩余空间以及结尾 `\0` 空间。

### 场景 8：格式化安全函数的同类容量错误

```c
sprintf_s(msg.name, sizeof(msg), "type=%d", msg.type);
snprintf_s(buf + off, sizeof(buf), 32, "%s", src);
vsnprintf_s(msg.name, sizeof(*msg), 16, "%s", args);
```

格式化安全函数同样要求第二个参数描述目标缓冲区容量。规则只覆盖 `dst/dstsz` 明显不匹配，不判断格式字符串本身是否存在格式化漏洞。

## 不作为当前召回重点的场景

以下形态不通过后处理白名单过滤，而是规则本身不主动召回：

```c
char buf[128];
memcpy_s(buf, sizeof(buf), src, len);

CLASS obj;
memcpy_s(&obj, sizeof(obj), src, len);

memcpy_s(obj.field, sizeof(obj.field), src, len);

memcpy_s(buf, sizeof(buf), src, sizeof(buf));
memcpy_s(obj.field, sizeof(obj.field), src, sizeof(obj.field));
memcpy_s(dst, dst_len, src, dst_len);
memcpy_s(buf, src_len, src, src_len);
memcpy_s(obj.field, msg_len, src, msg_len);
strcpy_s(buf, sizeof(buf), src);
strcpy_s(obj.field, sizeof(obj.field), src);
strncpy_s(dst, dst_len, src, dst_len);
sprintf_s(buf, sizeof(buf), "%s", src);
snprintf_s(dst, dst_len, dst_len - 1, "%s", src);
```

## 当前边界

- 不再仅因 `dstsz` 与拷贝长度/源长度使用相同表达式而召回候选；这类场景需要由更具体的成员、偏移、子数组或指针 `sizeof` 规则命中。
- 格式化安全函数只复用 `dst/dstsz` 容量不匹配规则，不覆盖格式字符串内容、参数类型不匹配或格式化注入问题。
- 不使用 tree-sitter 做类型恢复；函数名来自 semgrep 捕获值，捕获不到时为 `unknown`。
- 对项目内部封装函数，LLM 需要确认参数顺序是否确实为 `dst, dstsz, src/value, count`。
