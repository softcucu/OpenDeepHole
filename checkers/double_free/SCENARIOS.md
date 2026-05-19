# 双重释放检测 — 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 代码中的 CWE-415（双重释放）模式，共 14 条规则，覆盖 7 大类模板：

1. **Template A**：错误路径释放 + 公共 cleanup 标签再次释放同一资源
2. **Template C**：成员释放与 owner cleanup（owner 析构 / free_obj wrapper）重叠
3. **Template D**：所有权转移 API（add / insert / register / attach）之后 caller 再释放
4. **Template E**：refcount get/put 失衡（错误路径 put 一次 + cleanup 再 put 一次）
5. **Template G**：C++ 类持有裸指针，析构释放但缺 Rule of Five（浅拷贝双 delete）
6. **Template H**：多个智能指针包装同一裸指针，或手动 delete 智能指针的 `get()` 结果
7. **Template I**：allocator / deallocator 家族不匹配（new ↔ free、new[] ↔ delete、malloc ↔ delete）

---

## 正例场景（工具可检测并确认的双重释放）

### 场景 1：错误分支释放后未置 NULL，跳到公共 cleanup 再次释放（Template A）

```c
int load_config(const char *path) {
    char *buf = malloc(1024);
    if (read_file(path, buf) < 0) {
        free(buf);           // 第一次释放
        goto cleanup;        // 未 buf = NULL
    }
    parse(buf);
cleanup:
    free(buf);               // ← 第二次释放，双 free
    return 0;
}
```

**规则**：`A.release-before-goto-cleanup-same-resource`
**LLM 分析**：错误分支 `free(buf)` 后未置 NULL，cleanup 路径无 NULL 守卫，可达。判定为真实漏洞。

---

### 场景 2：C++ delete 重复（Template A/C++）

```cpp
int build(Config *cfg) {
    Item *it = new Item();
    if (cfg->bad) {
        delete it;           // 第一次 delete
        goto cleanup;
    }
    cfg->items.push_back(it);
cleanup:
    delete it;               // ← cfg->bad 时 it 已悬空
    return 0;
}
```

**规则**：`A.delete-before-goto-cleanup-same-resource`
**说明**：`delete` 一个非 NULL 已释放指针是 UB，confidence=HIGH。

---

### 场景 3：成员释放与 owner cleanup 重叠（Template C）

```c
struct conn {
    char *url;
    int  fd;
};

int open_conn(struct conn *c, const char *u) {
    c->url = strdup(u);
    if (resolve(c) < 0) {
        free(c->url);            // 释放成员
        goto fail;
    }
    return connect(c);
fail:
    destroy_conn(c);             // ← 如果其内部也 free(c->url)，双 free
    return -1;
}
```

**规则**：`C.member-release-before-owner-cleanup`
**LLM 分析**：用 `view_function_code` 查看 `destroy_conn` 实现，确认其释放 `c->url`，且失败分支未 `c->url = NULL`。判定为真实漏洞。

---

### 场景 4：C++ 成员 delete 与 owner cleanup 重叠（Template C/C++）

```cpp
int parse(Holder *h, const std::string &raw) {
    h->payload = new Payload();
    if (decode(raw, h->payload) < 0) {
        delete h->payload;       // 释放成员
        goto fail;
    }
    return 0;
fail:
    free_holder(h);              // free_holder 内部 delete h->payload
    return -1;
}
```

**规则**：`C.member-delete-before-owner-cleanup`

---

### 场景 5：所有权转移 API 后 caller 再释放（Template D）

```c
int register_handler(Registry *r, Handler *h) {
    if (registry_add(r, h) < 0) {   // registry_add 失败时也接管 h
        free(h);                    // ← 真实双 free
        return -1;
    }
    return 0;
}
```

**规则**：`D.transfer-error-branch-release`
**LLM 分析**：用 `find_function_references` + `view_function_code` 查看 `registry_add` 实现，发现其失败时也调用了 `free(h)`。判定为真实漏洞，severity=high（生产路径常触发）。

---

### 场景 6：refcount get/put 失衡（Template E）

```c
int do_op(Session *s) {
    Object *o = obj_get(s);          // 一次 get
    if (validate(o) < 0) {
        obj_put(o);                  // 第一次 put
        goto cleanup;
    }
    use(o);
cleanup:
    obj_put(o);                      // ← 第二次 put，引用计数下溢
    return 0;
}
```

**规则**：`E.refcount-put-before-goto-cleanup-put`
**LLM 分析**：`obj_get` 只 +1，但代码 put 了两次。引用计数归零后第二次 put 触发释放即双 free。判定为真实漏洞。

---

### 场景 7：C++ Rule of Five 缺失，浅拷贝双 delete（Template G）

```cpp
class Buffer {
public:
    Buffer(size_t n) : data(new uint8_t[n]) {}
    ~Buffer() { delete[] data; }    // ← 浅拷贝时两个对象都会 delete[]
private:
    uint8_t *data;
};

void f() {
    Buffer a(64);
    Buffer b = a;     // 默认拷贝构造：浅拷贝 data 指针，b 析构 + a 析构 = 双 delete
}
```

**规则**：`G.raw-pointer-owner-destructor-rule-of-five`
**LLM 分析**：类未声明 `= delete` 拷贝，且代码中存在按值赋值/容器存储路径，判定为真实漏洞。

---

### 场景 8：两个智能指针包装同一裸指针（Template H）

```cpp
void f() {
    auto *raw = new Item();
    std::shared_ptr<Item> a(raw);
    std::shared_ptr<Item> b(raw);    // ← 两个独立 control block，各自 delete raw
}
```

**规则**：`H.smart-pointer-duplicate-raw-ownership`，severity=ERROR
**说明**：confidence=HIGH，几乎确定为真实漏洞，应使用 `make_shared` 或共享同一个 shared_ptr。

---

### 场景 9：手动 delete 智能指针的 get() 结果（Template H）

```cpp
void f(std::unique_ptr<Item> &up) {
    Item *raw = up.get();
    process(raw);
    delete raw;     // ← unique_ptr 析构时还会再 delete
}
```

**规则**：`H.smart-pointer-get-manual-release`，severity=ERROR
**LLM 分析**：若意图是转移所有权，应使用 `up.release()`；当前写法明确双 delete。判定为真实漏洞。

---

### 场景 10：allocator/deallocator 不匹配（Template I）

```cpp
void f() {
    char *s = strdup("hello");
    delete s;                 // ← strdup 用 malloc 分配，必须 free
}
```

**规则**：`I.malloc-like-pointer-deleted`，severity=ERROR
**说明**：UB；具体崩溃方式因 allocator 实现而异，但属于确定性错误。

```cpp
void f() {
    int *arr = new int[10];
    delete arr;               // ← 应为 delete[]
}
```

**规则**：`I.new-array-deleted-as-scalar`

```cpp
void f() {
    int *x = new int(42);
    delete[] x;               // ← 应为 delete
}
```

**规则**：`I.new-scalar-deleted-as-array`

```cpp
void f() {
    Buffer *b = new Buffer();
    g_free(b);                // ← 应为 delete b
}
```

**规则**：`I.new-pointer-released-by-free-like-function`

---

## 反例场景（semgrep 检出但工具正确过滤的误报）

### 反例 1：第一次释放后已置 NULL

```c
free(buf);
buf = NULL;       // semgrep pattern-not 直接排除，不报告
goto cleanup;
...
cleanup:
    free(buf);    // free(NULL) 安全
```

### 反例 2：宏内置 NULL（需 LLM 看宏定义）

```c
#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)

void f() {
    SAFE_FREE(buf);
    goto cleanup;
cleanup:
    free(buf);          // semgrep 看不见宏内的 buf=NULL，会报告
}
```

**LLM 分析**：查看 `SAFE_FREE` 宏定义，确认包含 `(p) = NULL`，判定为误报。

---

### 反例 3：双指针封装函数内置 NULL

```c
void my_free(void **pp) { free(*pp); *pp = NULL; }

void f() {
    my_free((void **)&buf);
    goto cleanup;
cleanup:
    free(buf);    // buf 已被置 NULL，free(NULL) 安全
}
```

**LLM 分析**：查看 `my_free` 函数体，确认通过双指针置 NULL，判定为误报。

---

### 反例 4：第二次释放前有 NULL 守卫

```c
free(buf);
goto cleanup;
...
cleanup:
    if (buf) free(buf);   // 守卫存在，安全
```

**LLM 分析**：第二次释放被 `if (buf)` 守卫，但因为没有 `buf=NULL` 仍可能进入。需进一步看第一次 free 后 buf 是否仍非 NULL；若 buf 是局部变量且未重新赋值，守卫无效，仍是真实漏洞。**该例需要具体上下文判断。**

---

### 反例 5：release wrapper 容忍 NULL（需 LLM 查看实现）

```c
void my_release(Item *it) {
    if (!it) return;       // 容忍 NULL
    if (--it->refcount > 0) return;
    free(it);
}

void f() {
    my_release(it);
    goto cleanup;
cleanup:
    my_release(it);        // 第二次进入会 free 已释放对象 — 仍是真实漏洞！
}
```

**LLM 分析**：虽然 `my_release` 容忍 NULL，但本例 `it` 没有被置 NULL，第二次调用 `my_release(it)` 进入后 `it->refcount` 已是已释放内存，访问即 UAF + 双 free。判定为**真实漏洞**。

**真正能形成误报的 release wrapper**：必须既容忍 NULL 又**在第一次释放后 caller 已置 NULL**，两者缺一不可。

---

### 反例 6：Template D 中 `$TAKE` 是借用语义（需 LLM 查看实现）

```c
int lookup(Cache *c, const char *key, char *value) {
    // 借用语义：将 value 拷贝到 cache 内部缓冲区，不接管所有权
    strncpy(c->slot[c->n].val, value, MAX_VAL);
    c->n++;
    return 0;
}

void f() {
    char *v = strdup("foo");
    lookup(cache, "k", v);
    free(v);          // 正确：caller 仍持有 v 所有权
}
```

**规则**：`D.possible-ownership-transfer-then-caller-release`（INFO 级别）
**LLM 分析**：`view_function_code` 查看 `lookup`，发现其只读 `value` 字符串拷贝到内部，并未保存指针。caller 释放是正确的。判定为误报。

---

### 反例 7：Template G 类禁止拷贝

```cpp
class Buffer {
public:
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&&) = default;
    ~Buffer() { delete[] data; }
private:
    uint8_t *data;
};
```

**LLM 分析**：类显式 `= delete` 拷贝构造/赋值，编译期阻断浅拷贝路径。判定为误报。

---

### 反例 8：早 return / break 导致第二次释放不可达

```c
if (cond) {
    free(buf);
    return -1;      // 直接 return，不会到 cleanup
}
...
cleanup:
    free(buf);
```

**LLM 分析**：第一次释放路径以 `return` 跳出，并非 `goto cleanup`，所以两次 free 不在同一控制流上。semgrep 若把 `return` 误识别为 `goto` 出现告警，需手动确认控制流。判定为误报。

---

## 不支持的场景（超出工具检测范围）

- **跨函数双重释放**：函数 A free(p) 后返回 p，函数 B 不知情再 free(p)。需要全程序数据流分析
- **跨线程双重释放**：多线程竞态导致两个线程都执行 free，规则不覆盖并发语义
- **回调内的释放**：将 p 注册到 callback list，回调被触发时 free，主路径之后又 free
- **C++ 异常路径双 delete**：异常展开调用析构 + 构造函数中的 cleanup 中又 delete，规则不分析异常控制流
- **跨编译单元的析构合约**：A.cpp 持有 ptr，B.cpp 的析构也释放，规则只看单 TU 内
- **realloc 后旧指针仍被使用**：`p = realloc(p, n)` 失败时旧 p 被释放，但有的写法假设失败 p 仍有效；属于 UAF + 双 free 混合，规则不覆盖
- **通过函数指针的间接释放**：`obj->free_cb(obj)`，free_cb 在不同实例下行为不同，无法静态判断
