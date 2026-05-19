# 安全内存函数越界检测 - 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 安全内存函数中的高风险 `dst/dstsz` 误用。第一版只召回明显可疑场景，不做 A 类白名单过滤；普通安全形态本身不会被规则匹配。

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

void parse(Msg *msg, const char *src, size_t len) {
    memcpy_s(msg->payload, sizeof(*msg), src, len);
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
```

`sizeof(buf)` 是指针宽度，不是缓冲区容量。

### 场景 6：`memset_s` 同类误用

```c
memset_s(buf + off, sizeof(buf), 0, len);
memset_s(msg.payload, sizeof(msg), 0, len);
```

`memset_s` 没有源缓冲区，但 `dst/dstsz/count` 的容量关系仍然成立。

### 场景 7：`dstsz` 与拷贝长度完全相同

```c
void copy_packet(char *dst, const char *src, size_t packet_len) {
    memcpy_s(dst, packet_len, src, packet_len);
}

void copy_to_array(const char *src, size_t src_len) {
    char buf[64];
    memcpy_s(buf, src_len, src, src_len);
}
```

如果重复使用的长度表达式是源长度、包长或消息长度，它不一定等于目标容量。规则只召回固定数组、成员目标或源语义命名明显的表达式，并排除 `sizeof(dst)`、`sizeof(member)` 等明显安全形态。

### 场景 8：字符串安全函数的同类容量错误

```c
strcpy_s(msg.name, sizeof(msg), src);
strncpy_s(buf + off, sizeof(buf), src, n);
strncat_s(dst, packet_len, src, packet_len);
```

字符串函数同样要求 `dstsz` 描述目标缓冲区容量。对 `strncpy_s` / `strncat_s`，第四个参数是拷贝/拼接长度，不应被当作目标容量；并且还要考虑结尾 `\0` 空间。

## 不作为第一版召回重点的场景

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
strcpy_s(buf, sizeof(buf), src);
strcpy_s(obj.field, sizeof(obj.field), src);
strncpy_s(dst, dst_len, src, dst_len);
```

## 当前边界

- 第一版不覆盖 `strcpy_s`、`strncpy_s`、`strcat_s` 等字符串安全函数。
- `dstsz == count` 场景覆盖拷贝/移动和四参字符串函数，不覆盖 `memset_s` 和三参字符串函数。
- 第一版不覆盖 `sprintf_s`、`snprintf_s`、`vsprintf_s`、`vsnprintf_s` 等格式化函数。
- 不使用 tree-sitter 做类型恢复；函数名来自 semgrep 捕获值，捕获不到时为 `unknown`。
- 对项目内部封装函数，LLM 需要确认参数顺序是否确实为 `dst, dstsz, src/value, count`。
