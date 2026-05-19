# S4：IO 类函数缓冲区溢出

## 原理描述

IO 类函数存储数据到目的缓冲区中，如果对数据长度不加限制，可能导致缓冲区越界：

1. IO 函数接收外部输入，数据长度参数 > 接收缓冲区大小 → **写溢出**
2. IO 函数目的缓冲区指针有加减运算，指针偏移后超出 → **写溢出**
3. IO 函数输出数据，数据长度参数 > 源缓冲区大小 → **读越界导致信息泄漏**
4. IO 函数源缓冲区指针有加减运算，超出源缓冲区 → **读越界**

与 `_s` 系列安全函数不同，IO 函数通常不提供 destSize 保护，
**调用者必须自行保证传入的长度参数不超过缓冲区大小**。

---

## 涉及函数清单


```c
ssize_t read(int fd, void *buf, size_t maxlen);           // maxlen 须 <= buf 分配空间
int recv(fd, *buf, int maxlen, int flags);
int recvfrom(fd, *buf, maxlen, flags, addr, addr_len);
char *fgets(char *str, int n, FILE *stream);
char *gets(char *str);                                    // 无边界，永远是漏洞
ssize_t recvmsg(int fd, struct msghdr *msg, int flags);
BOOL ReadFile(HANDLE, LPVOID buf, DWORD nBytes, ...);
size_t fread(void *buf, size_t size, size_t count, FILE *fp);
int scanf(const char *fmt, ...);                          // "%s" 无宽度限定永远是漏洞
```



以及输出类导致**读越界**：`puts`、`printf("%s", ...)`、`fprintf` 等。

---

## 漏洞特征

### 特征 1：长度参数是常量，但大于缓冲区长度


```c
char buf[200];
read(fd, buf, 400);   // 溢出
```



### 特征 2：长度参数是变量，无判断或判断可绕过


```c
if (read(s, (void*)&mlen, 4) != 4) ...
if (read(s, msg, mlen) != mlen || msg[0] != 0) ...   // mlen 来自网络未校验
```



### 特征 3：缓冲区指针参数有加减运算


```c
read(f, s + len, MAX_LEN);    // s+len 可能已接近 s 末端
read(f, &s[len], MAX_LEN);
```



即使 MAX_LEN 本身合理，`s + len` 剩余空间可能不足 MAX_LEN。

### 特征 4：无边界函数输出造成读越界


```c
username = XXXX_GET_MSG_FROM_SERVER(((_XXXX_COORD*)&(p[2]))->username);
puts(username);         // username 无 \0 终止时越界读
```



---

## 审计流程

### 1. 识别 IO 调用

扫描函数体内上述函数的调用。

### 2. 确定目的/源缓冲区大小

第一个参数（buf/dest）或输出函数的源字符串：
- 栈数组 → 声明可见
- 结构体成员 → `view_struct_code`
- 全局变量 → `view_global_variable_definition`
- 参数传入 → 根据 candidate 描述中的调用链线索查看关键调用方（最多 2 层）
- 动态分配 → 追踪分配参数

### 3. 分析长度参数

- 硬编码常量还是变量？
- 变量来源：外部输入？函数参数？计算结果？
- 是否经过与缓冲区大小的比较？

### 4. 分析缓冲区指针是否经过运算

- `buf + offset` / `&buf[offset]` 形式 → 剩余空间 = `sizeof(buf) - offset`
- 长度参数是否 <= 剩余空间？

### 5. 对输出类函数检查源缓冲区终止条件

- `puts(p)` / `printf("%s", p)` 依赖 `\0` 终止
- p 来自外部且可能无终止符 → 越界读

---

## 豁免规则

**豁免 1：读取长度使用了 sizeof(buf) 或 sizeof(buf) - 1**


```c
char buf[1024];
fread(buf, 1, sizeof(buf), fp);           // 安全
fgets(buf, sizeof(buf), fp);              // 安全
```



**豁免 2：读取前有 min()/MIN() 截断或上界比较**


```c
DWORD dwActual = min(dwRequestLen, sizeof(buf));
fread(buf, 1, dwActual, fp);              // 安全
```



或：


```c
if (mlen > sizeof(msg)) return ERROR;
read(s, msg, mlen);                       // 安全
```



**豁免 3：指针偏移场景有剩余空间校验**


```c
if (len + MAX_LEN <= sizeof(s)) {
    read(f, s + len, MAX_LEN);            // 安全
}
```



---

## 判定标准

| 情况 | confirmed |
|------|-----------|
| `gets()` 或无宽度限定的 `scanf("%s")` | **无条件 true** |
| 长度参数来自外部输入且未与缓冲区大小比较 | `true` |
| 长度参数为硬编码但大于缓冲区大小 | `true` |
| 缓冲区指针有偏移，无剩余空间校验 | `true` |
| 输出类函数源字符串来自外部且无 `\0` 保障 | `true` |
| 长度 = sizeof(buf) 或经 min() 截断 | `false` |
| 有上界比较且比较值正确 | `false` |

---

## 与其他场景的级联

- **S4 + S2**：IO 长度来自外部且存在算术运算，既是 IO 溢出又涉及整数溢出。
- **S4 + S3**：循环内重复 IO 读取到累加偏移的缓冲区位置。

---

## 案例参考


```c
void proxyTask(int server_port, uint32 ulSlot) {
    int32 mlen;
    uint8 msg[BUFFER_SIZE];
    while (1) {
        if (read(s, (void*)&mlen, 4) != 4) { ... }
        bigEndianByteSwap((uint8*)&mlen, uint32Layout);
        if (read(s, msg, mlen) != mlen || msg[0] != 0) { ... }  // mlen 未校验
    }
}
```



mlen 从网络报文获取，未与 BUFFER_SIZE 校验。额外：mlen 为 `int32`（有符号），
若为负则转 size_t 后变巨大值（级联 S2）。

---

## ai_analysis 输出模板


```
场景：S4 IO 类函数缓冲区溢出
代码：read(s, msg, mlen)
关键变量：目的缓冲区 msg，类型 uint8[BUFFER_SIZE]；长度 mlen 来自网络报文，类型 int32。
校验情况：函数内未发现 mlen 与 BUFFER_SIZE 的比较，也未校验 mlen >= 0。
判定：mlen 可能 > BUFFER_SIZE 导致写越界；mlen 可能为负数转 size_t 变巨大值（级联 S2）。
修复建议：read 前添加 if (mlen < 0 || mlen > sizeof(msg)) return ERROR;
```
