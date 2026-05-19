# S2：整数溢出/下溢导致越界

## 原理描述

计算机整数分为无符号和有符号。有符号数最高位表示正负（1 负、0 正）。每种类型有固定范围，
运算结果超出范围即整数溢出。整数溢出本身通常不直接改写内存，但会**污染缓冲区大小、拷贝长度、
数组下标**等敏感数值，进而引发栈/堆溢出。

---

## 六种漏洞特征（逐一排查）

### 特征 1：无符号数向上回绕


```c
len = get_len_from_message();
buf = malloc(len + 5);     // len=0xFFFFFFFF 时 len+5=4
read(fd, buf, len);        // 向 4 字节空间写入大量数据 → 溢出
```




```c
unsigned short len3 = 1 + len1 + len2;   // len1=10, len2=0xFFFF → len3=10
if (len3 > 64) return false;             // 绕过检查
malloc(len3);                            // 分配 10 字节
memcpy(buf + len1, s2, len2);            // 写 0xFFFF 字节 → 溢出
```



**检查要点：** 参与内存分配/拷贝长度计算的加法、乘法、左移运算的操作数上界。

### 特征 2：无符号数向下回绕


```c
vos_memcpy(&dst, &src, len - 10);                           // len<10 时巨大
vos_memcpy_safe(&dst, len - 10, &src, len - 10);            // 同上

// strchr / strstr 场景（配合 S1 字符串搜索）
char pStr[] = "aaaa\nbbbbbbb:";                             // 攻击构造
int len = strchr(pStr, '\n') - (strchr(pStr, ':') + 1);     // 负数 → 无符号巨大值
memcpy(&Dst, pStr, len);                                    // 越界
```



**检查要点：** 任何 `A - B` 形式的无符号减法，A < B 时是否可达。

### 特征 3：有符号整数赋值给无符号整数


```c
int copy_something(char *buf, int len) {
    char szBuf[80];
    if (len > sizeof(szBuf)) return -1;   // len=-1 时绕过
    return memcpy(szBuf, buf, len);       // len 隐式转 size_t 巨大值
}
```



**检查要点：** `char`/`short`/`int`/`long` 变量存储外部数据，后续作为数组下标或拷贝长度，
且长度参数为无符号类型。

### 特征 4：大类型赋值给小类型截断


```
加法截断：0xffffffff + 0x00000001 = 0x0000000100000000 (long long) → 0x00000000 (long)
乘法截断：0x00123456 * 0x00654321 = 0x000007336BF94116 (long long) → 0x6BF94116 (long)
```




```c
uint32 ulLen;              // 被攻击者控制
uint8 ucLen = ulLen;       // 截断
char *p = malloc(ucLen);   // 用截断后的小值分配
memcpy(p, &buf, ulLen);    // 用原始大值拷贝 → 溢出
```



**检查要点：** 同一长度语义在代码中是否出现前后类型不一致。

### 特征 5：有符号整数溢出


```c
int i = INT_MAX;  i++;     // → INT_MIN
int i = INT_MIN;  i--;     // → INT_MAX
```



该溢出需结合"有符号赋值给无符号"一起分析。

### 特征 6：有符号整数负负为负


```c
short a = 0x8000;              // -32768
if (a < 0) a = -a;             // a 仍为 -32768
int b = 0x80000000;            // -2147483648
if (b < 0) b = -b;             // b 仍为 -2147483648
```



**检查要点：** `if (x < 0) x = -x;` 模式，x 可达类型最小值则取反失败。

---

## 审计流程

### 1. 识别整数运算点

扫描函数体内参与以下场景的算术表达式：
- `malloc` / `new` / `realloc` 的大小参数
- `memcpy` / `memcpy_s` / `read` / `recv` 等函数的长度参数
- 数组下标 `arr[expr]`
- 循环边界 `for (...; i < expr; ...)`
- 指针偏移 `ptr + expr` / `ptr += expr`

### 2. 分析运算类型和操作数

对每个运算：
- 操作数类型（有符号/无符号、位宽）
- 运算类型（加/减/乘/移位/类型转换/取负）
- 对照六种特征评估溢出/下溢/截断可能性

### 3. 追踪操作数来源

- 来自外部输入（网络报文、文件头、IO、对外函数参数）？
- 函数参数 → 根据 candidate 描述中的调用链线索追踪调用方（最多 2 层）
- 结构体成员 → `view_struct_code`
- 全局变量 → `view_global_variable_definition`

### 4. 检查运算前的校验

- 减法前是否有 `if (A < B) return;`？
- 乘法前是否校验操作数上界？
- 类型转换后是否校验值域？
- 取负前是否排除最小值？

### 5. 评估下游影响

溢出/下溢/截断后的值被用于：
- 分配内存 → 可能分配不足，后续写入时溢出
- 拷贝长度 → 直接越界读写
- 数组下标 → 直接越界访问
- 循环边界 → 循环次数异常 → 越界读写

**在分析中必须标注级联关系**，例如"S2 下溢导致 S1 memcpy_s 越界"。

---

## 判定标准

| 情况 | confirmed |
|------|-----------|
| 算术运算操作数来自外部输入且无范围校验 | `true` |
| 无符号减法无预先比较 | `true` |
| 乘法/左移无上界校验且结果用于分配/拷贝/下标 | `true` |
| 类型截断且截断后值用于内存操作 | `true` |
| 有符号变量作边界检查后作无符号长度使用 | `true` |
| `if (x < 0) x = -x` 且 x 可达类型最小值 | `true` |
| 运算前有完备范围校验 | `false` |

---

## 案例参考

**案例一：**


```c
int handle_control_add_ne(..., unsigned int len) {
    if (len >= PROXY_HEAD_SIZE + SIZE_OF_NE_FIXED_INFO) {
        short sLen = 0;
        memcpy_s(&sLen, sizeof(short), pRecvPos, sizeof(short));
        memcpy_s(&cMOCName[0],
                 (sLen > NAME_LEN ? NAME_LEN : sLen),
                 pRecvPos,
                 (sLen > NAME_LEN ? NAME_LEN : sLen));
    }
}
```



sLen 为有符号 short，来自外部报文。sLen 为负数时三元判断 `sLen > NAME_LEN` 为假，
结果为 sLen 本身，隐式转为 size_t 变巨大值，memcpy_s 越界。

**案例二：**


```c
while (NEXTTHREAD_NOEXIST != ucExtType) {
    ucExtLen = *((UCHAR*)(pucMsg + usLen));
    usLen += (ucExtLen * EXTHEADER_LENGTH_UNIT - 1);
    if (usLen > usMsgLen) return ...;
}
```



ucExtLen 来自外部，连续累加 usLen 可回绕为 0，绕过上界检查进入死循环。

---

## ai_analysis 输出模板


```
场景：S2 整数溢出（无符号下溢）
代码：memcpy_s(pDst, dwDstLen, pSrc + dwOffset, dwTotalLen - dwOffset)
关键变量：dwTotalLen - dwOffset，DWORD 无符号减法。dwOffset、dwTotalLen 均来自外部报文字段。
校验情况：函数内未发现 dwOffset <= dwTotalLen 的校验。
判定：dwOffset > dwTotalLen 时无符号回绕为巨大正数，导致下游 memcpy_s 越界读写（级联 S1）。
修复建议：减法前添加 if (dwOffset > dwTotalLen) return ERROR;
```
