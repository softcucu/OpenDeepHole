# S1：安全内存函数调用

## 原理描述

安全内存函数（`memcpy_s`、`strcpy_s`、`strncat_s` 等 `_s` 系列，以及 `VOS_MemCpy_Safe`、
`memcpy_sp`、`VOS_StrNCpy` 等内部等价函数）有两种典型漏洞模式：

**写溢出**：向目的缓冲区写入数据时，写入长度校验不严格。常见形式：
- 拷贝长度使用源缓冲区长度，而源缓冲区 > 目的缓冲区；
- 目的缓冲区指针存在加减运算，指针偏移后剩余空间小于写入长度；
- destSize 参数使用了错误的 sizeof（指针 / 整个结构体），大于 dest 实际大小。

**读溢出**：从源缓冲区拷贝数据到目的缓冲区时，读取长度校验不严格：
- 读取长度使用目的缓冲区大小，而目的缓冲区 > 源缓冲区；
- 源缓冲区指针存在加减运算，偏移后访问源缓冲区末端之外；
- 协议报文中的长度字段未与实际接收长度校验。

核心判断：**destSize / 拷贝长度 是否可能超过 dest 实际缓冲区大小，或 读取长度/偏移 是否可能超出源缓冲区。**

---

## 涉及函数清单

### memcpy 类


```c
memcpy(void *dst, void *src, size_t maxlen);                       // maxlen 须 <= dst 分配空间
VOS_MemCpy(void *pvDest, void *pvSrc, size_t n);
VOS_Mem_Copy(void *pvDest, void *pvSrc, size_t n);
bcopy(const void *src, void *dest, int maxlen);
memcpy_s(void *dest, rsize_t destSize, const void *src, rsize_t count);
VOS_MemCpy_S(void *dst, int a1, void *src, size_t a2);             // min(a1, a2) 须 <= dst 分配空间
VOS_Mem_Copy_Safe(void *dst, int a1, void *src, size_t a2);
memcpy_sp / memcpy_safe / VOS_memcpy_safe                          // 华为内部变体
memset(void *dst, int ch, size_t maxlen);                          // maxlen 须 <= dst 分配空间
memmove_s / memset_s
```



### strcpy 类


```c
strcpy(char *dst, char *src);                                      // strlen(src) 须 < dst 分配空间
strncpy(char *dst, char *src, int maxlen);                         // maxlen 须 <= dst 分配空间
VOS_StrCpy / VOS_StrNCpy / VOS_strcpy / VOS_strncpy
strcpy_s / strncpy_s / wcscpy_s / wcsncpy_s
```



**注意：** 字符串拷贝后必须以 `\0` 结尾，因此 dst 需预留一个字节存放终止符，否则后续字符串操作可能越界访问。

### strcat 类


```c
strcat(char *dest, const char *src);                               // strlen(src)+strlen(dest) 须 < dst
strncat(char *dst, char *src, int maxlen);                         // maxlen+strlen(dest) 须 <= dst
VOS_strcat / VOS_StrCat / VOS_strncat / VOS_StrNCat
VOS_StrNCat_Safe(char *dst, a1, char *src, a2);                    // min(a1,a2)+strlen(dest) 须 <= dst
strcat_s / strncat_s / wcscat_s
```



### 字符串搜索类（配合计算长度时危险）


```c
strchr / strrchr / strstr / strnstr / memchr
VOS_StrChr / VOS_StrRChr / VOS_StrStr / VOS_memchr / VOS_strchr
```



---

## 审计流程

### 1. 识别 dest / src 和长度参数

对每个命中点：
- `_s` 系列：第一个参数是 `dest`，第二个参数是 `destSize`，最后一个参数是拷贝长度 `count`。
- 非 `_s` 系列：第一个参数是 `dest`，最后一个参数是拷贝长度 `len`，没有 destSize 保护。

### 2. 确定 dest 的实际缓冲区大小

按 dest 来源分情况：

**A. 局部栈数组** — `char buf[256]` 直接可见。

**B. 结构体成员** — `pObj->field` 或 `stInfo.field`，调用 `view_struct_code(project_id, 结构体类型名)`。
嵌套结构体继续展开。

**C. 全局变量** — 调用 `view_global_variable_definition(project_id, 变量名)`。

**D. 函数参数传入的指针** — 根据 candidate 描述中的调用链线索追踪调用方：
- 有调用方：用 `view_function_code` 追踪实际 buffer。**最多向上 2 层。**
- 无调用方：对外函数，进入"外部输入豁免规则"处理。

**E. 动态分配** — `malloc(expr)` / `new char[expr]`，分析 `expr` 的值（注意级联 S2 整数溢出）。

**F. 无法确定** — 标记信息不足。

### 3. 确定长度参数的值或范围

对 `_s` 系列的 destSize，特别注意以下**高危写法**：

- `sizeof(指针变量)` → 几乎必定 bug，得到 4 或 8 字节
- `sizeof(整个结构体)` 但 dest 只是某个成员 → 大小不匹配
- 硬编码常量 > dest 实际大小
- 来自函数参数的变量（追踪调用方）
- `strlen()` 或算术表达式（可能级联 S2）

对非 `_s` 系列，直接检查拷贝长度参数。

### 4. 检查指针偏移（若 dest 或 src 有加减运算）

当 dest 或 src 形如 `buf + offset` 或 `&buf[offset]`：
- 剩余空间 = `sizeof(buf) - offset`
- 拷贝长度是否 <= 剩余空间？
- `offset` 是否可能被外部控制变大？

### 5. 检查字符串搜索类计算长度的方向

若长度由两个 `strchr`/`strstr` 结果相减得到（如 `pEnd - pBegin`）：
- 正常情况下 pEnd 在 pBegin 之后，结果为正数
- 攻击者可构造 pBegin 在 pEnd 之后的输入（例如 `"aaaa\nbbbbbbb:"` 中 `\n` 在 `:` 前）
- 小数减大数产生无符号下溢，转为巨大长度（级联 S2）

### 6. 检查协议字段校验

若长度来自报文字段（`pMsg->ulMsgLen`、`pHeader->usLen` 等）：
- 该字段是否与 socket 实际接收长度对比？
- 该字段是否与目的缓冲区大小对比？
- 校验的上界是否合理（不能只校验最大值，还要和实际报文长度校验）？

### 7. 外部输入场景的豁免规则

当函数无内部调用方（对外函数）且 destSize / 长度来自外部参数时：

**豁免 1：dest 的分配使用了同一个 len 参数**


```c
void ProcessData(void *pInput, DWORD dwInputLen) {
    char *pBuf = (char*)malloc(dwInputLen);
    memcpy_s(pBuf, dwInputLen, pInput, dwInputLen);   // 安全
}
```



**豁免 2：dest 是结构体指针，destSize 用 sizeof(该结构体)**


```c
void FillInfo(ST_INFO *pInfo, void *pSrc, DWORD dwSrcLen) {
    memcpy_s(pInfo, sizeof(ST_INFO), pSrc, dwSrcLen);   // 安全
}
```



注意：若 dest 是 `pInfo->field` 但 destSize 是 `sizeof(ST_INFO)`，仍然**高危**。

**豁免 3：dest 和 destSize 均来自参数，且 destSize 语义上描述 dest 长度**


```c
void CopyBuffer(void *pDst, DWORD dwDstLen, void *pSrc, DWORD dwSrcLen) {
    memcpy_s(pDst, dwDstLen, pSrc, dwSrcLen);   // 安全（约定由调用方保证）
}
```



判断依据：dest 在外部分配，destSize 是签名中与 dest 配对的长度参数（通常紧跟 dest 之后，
或命名含 `Len`/`Size`/`Buf` 表明关联）。

不满足豁免条件 → `confirmed=true`。

---

## 高危模式速查

1. **`sizeof(指针)` 做 destSize** — 得到 4 或 8，几乎必定是 bug
2. **结构体成员拷贝用整个结构体的 sizeof** — `memcpy_s(obj->buf, sizeof(*obj), ...)`
3. **拷贝长度使用源长度，且源 > 目的** — `memcpy(dst, src, sizeof(src))` 或 `memcpy_sp(mBuf, sizeof(mBuf), pMsg->pBody, pMsg->ulMsgLen)`
4. **协议字段未校验即作长度** — `pMsg->ulMsgLen` 直接作 count
5. **指针偏移 + 长度 >= 缓冲区末端** — `memcpy(buf + off, src, len)` 且 `off + len > sizeof(buf)`
6. **字符串搜索后相减** — 顺序不保证时可能下溢
7. **destSize 来自外部输入且不满足豁免条件**
8. **`strcpy`/`strcat` 无长度保护且 src 来自外部**
9. **字符串拷贝未预留 `\0` 位** — `strncpy(dst, src, sizeof(dst))` 无手动补 `\0`

---

## 判定标准

| 情况 | confirmed |
|------|-----------|
| 能证明 destSize > dest 实际大小 | `true` |
| 拷贝长度 > dest 实际剩余空间 | `true` |
| 读取长度 > 源缓冲区实际大小 | `true` |
| 指针偏移 + 长度超出缓冲区 | `true` |
| 外部长度字段未与实际接收长度/目的缓冲区校验 | `true` |
| 字符串搜索相减顺序不保证且用于无符号长度 | `true` |
| 命中豁免规则 | `false` |
| 所有路径可证明 destSize / 长度 <= dest 实际大小 | `false` |

---

## 案例参考

### 读缓冲区溢出案例

**案例：报文长度字段未与实际接收长度校验**


```c
memcpy_sp(mBuf, sizeof(mBuf), pMsg->pBody, pMsg->ulMsgLen);
```



`pMsg->ulMsgLen` 为报文字段，未与 socket 实际接收长度校验，攻击者可构造非法值导致读越界。

**案例：循环解析，外部长度未与实际报文长度校验**


```c
for (i = 0; i < pstAsnOcts->octetLen; i++) {
    pstBigInt->aVal[i] = pstAsnOcts->octs[i];
}
```



`octetLen` 来自网络报文，未校验实际报文长度时 `octs[i]` 读越界；该值若大于 `aVal` 大小
则还会写越界（级联 S5）。

### 写缓冲区溢出案例

**案例：误用 destSize 参数导致写溢出**


```c
VOS_MemCpy_S(aucBuf,
             pMsg->uwLength + VOS_MSG_HEAD_LENGTH,
             pMsg,
             pMsg->uwLength + VOS_MSG_HEAD_LENGTH);
```



destSize 来自报文长度字段，攻击者构造非法大值时 aucBuf 写溢出。正确做法：destSize 应为 `sizeof(aucBuf)`。

**案例：strncpy 拷贝长度越界**


```c
UCHAR pucLow32Temp[9];
VOS_strncpy(pucHigh32Temp, &pSrcStr[8], (ulStrLen - 8));
```



`ulStrLen` 来自消息，大于 17 时拷贝越界。

**案例：字符串搜索相减下溢**


```c
char source[] = "aaaa\nbbbbbbb:";   // 攻击构造：\n 在 : 前
char *pBegin = strchr(source, ':');
char *pEnd   = strchr(source, '\n');
memcpy(szBuf, pBegin + 1, pEnd - pBegin);   // 负数 → 无符号巨大值
```



---

## ai_analysis 输出模板


```
场景：S1 安全内存函数误用
代码：memcpy_s(stObj.szName, sizeof(stObj), pSrc, dwLen)
关键变量：dest=stObj.szName，类型 char[64]，实际大小 64 字节。
校验情况：destSize 使用了 sizeof(stObj) = 256，与 dest 实际大小不匹配。
判定：destSize(256) > dest 实际大小(64)，存在越界写入风险。
修复建议：将 destSize 改为 sizeof(stObj.szName)。
```




```
场景：S1 安全内存函数误用（协议字段未校验）
代码：memcpy_sp(mBuf, sizeof(mBuf), pMsg->pBody, pMsg->ulMsgLen)
关键变量：拷贝长度 pMsg->ulMsgLen 来自报文字段。
校验情况：未与 socket 实际接收长度、也未与 sizeof(pMsg->pBody) 校验。
判定：攻击者构造 ulMsgLen > 实际 pBody 长度时读越界；ulMsgLen > sizeof(mBuf) 时被 destSize 截断但仍读越界源。
修复建议：读取前校验 pMsg->ulMsgLen <= 实际接收长度 且 <= sizeof(mBuf)。
```
