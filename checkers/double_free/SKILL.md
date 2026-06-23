---
name: double-free-analysis
description: 验证双重释放候选漏洞（CWE-415），判断同一资源是否会在两条可达路径上被释放两次
---

# 双重释放漏洞验证

你正在核实一处候选双重释放线索（CWE-415）。你的任务是判断这是真实的 bug 还是误报。

## 背景

候选线索通常落在以下 7 大类双重释放模板之一（A: 错误路径释放 + 公共 cleanup 再释放；C: 成员释放与 owner cleanup 重叠；D: 所有权转移 API 后 caller 再释放；E: refcount get/put 失衡；G: C++ 浅拷贝 + 析构释放裸指针；H: 智能指针重复包装裸指针 / 手动释放 get() 结果；I: new/delete/malloc/free 配对错位），即"同一资源 `$P` 或 `$OBJ->$FIELD` 出现在两次释放调用之间，且中间没有 `= NULL` 置空"。

候选描述中已尽量给出 **指针/资源、宿主对象、成员字段、释放调用、所有权 API** 等线索（请据此自行判断属于下文哪种模板）。

候选线索只来自语法层面的初筛，无法感知：跨函数的所有权转移语义、释放包装函数内部是否真的释放、release 后但 goto 之前是否 `p = NULL`、refcount get 实际调用次数、宏内的 NULL 置位、跨编译单元的析构语义。你需要做语义层面的验证。

## 可用工具

- `view_function_code(project_id, function_name)` — 查看函数完整源码（必查；最关键的步骤）
- `view_struct_code(project_id, struct_name)` — 查看结构体/类定义（确认是否存在自定义析构、Rule of Five、所有权字段、是否含有 free callback 函数指针）
- `find_function_references(project_id, function_name)` — 查找释放/所有权 API 的调用位置或定义；用于追溯 `$REL` / `$TAKE` / `$PUT` 的真实语义
- `submit_result(result_id, confirmed, severity, description, ai_analysis)` — 提交分析结论（必须调用）

## 分析步骤

### Step 1 — 读取完整函数体

用 `view_function_code` 获取 candidate 所在函数的完整源码。候选描述只包含少量上下文片段，无法判断两次释放之间是否存在 `= NULL` 置位、是否存在 `return` 跳出、是否存在条件守卫。**必须**先看到整个函数。

### Step 2 — 查看释放函数的语义

候选描述中的"释放调用 / refcount put / 所有权 API"都是按函数名匹配出来的线索（free/destroy/release/unref/put/take/add/register 等命名）。这些名字**不一定**等于"真的释放内存"：

- 用 `find_function_references` 或直接 `view_function_code` 看一下被匹配到的函数实现：
  - 它内部是 `free(p)` / `delete p` / `kfree(p)` 等真实释放吗？
  - 还是仅仅做了 `p->refcount--` 之类的逻辑减引用？是否在 refcount 归零时才真正释放？
  - 是否在内部判断 `if (!p) return;` 已经容忍 NULL 输入？
  - **`$TAKE` 类 API**（add/insert/register/attach）是否真的接管所有权？是 "拷贝一份保存"、"仅保存指针"、还是"失败时调用方仍需释放"？这是 Template D 的关键。

### Step 3 — 根据候选模板聚焦核心验证问题

| 候选模板 | 核心验证问题 |
|---------|------------|
| A. 错误路径释放 + goto cleanup 再释放 | 第一次 `$REL1($P)` 之后 / `goto $LABEL` 之前，`$P` 是否被置 NULL？`$REL2` 是否能容忍 NULL？两次释放是否真的释放同一片内存？ |
| A. 错误路径 delete + goto cleanup 再 delete (C++) | 同上，C++ `delete` 不容忍重复（即便 `delete nullptr` 安全，但 `delete` 一个非 NULL 已释放指针就是 UB） |
| C. 成员释放 + owner cleanup 再释放 | `$OBJ->$FIELD` 被释放后，`$REL2($OBJ)` 内部是否也会释放该成员？该 owner cleanup 是否依赖 `$OBJ->$FIELD == NULL` 才跳过？ |
| C. 成员 delete + owner cleanup 再释放 (C++) | 同上 |
| D. 疑似所有权转移后 caller 再释放 | `$TAKE` 是否真的接管 `$P` 的所有权？是"成功时接管，失败时不接管"还是"无论如何都接管"？后续 `$REL($P)` 是否在 `$TAKE` 成功后执行？ |
| D. 转移失败分支再释放 | `$TAKE` 失败时（`$RC < 0` / `!$RC`），它是否在内部已经释放了 `$P`？常见坑：调用约定模糊导致"调用方也释放" |
| E. refcount put + goto cleanup 再 put | `$GET` 实际增加了几次 refcount？`$PUT1` 之后 refcount 是否仍 > 0？`$PUT2` 是否对应另一次 get？ |
| G. 裸指针 owner 析构 + 缺 Rule of Five | 该类是否定义了拷贝构造 / 拷贝赋值 / 移动构造 / 移动赋值（Rule of Five）？是否声明 `= delete` 禁止拷贝？类对象是否真的会被拷贝（按值传递、放入 STL 容器、赋值）？ |
| H. 智能指针重复包装同一裸指针 | 两个智能指针构造时用的是同一个 `$P`？若都是 `shared_ptr`，会产生两个独立 control block 各自 delete；若是 `unique_ptr`，明确双重所有权 |
| H. 手动释放 smart_ptr get() 结果 | 是否对 `owner.get()` 的返回值做了 delete / free？smart_ptr 析构时是否还会释放一次？是否本意是 `owner.release()`？ |
| I. new 对象用 free 类函数释放 | `new` 出来的对象用 `free()`/wrapper 释放：违反 C/C++ allocator/deallocator 配对；具体运行时是否真的崩溃因 allocator 而异，但属于 UB |
| I. new[] 用 scalar delete | `new T[N]` 必须 `delete[]`，scalar `delete` 是 UB |
| I. new 用 delete[] | `new T` 必须 `delete`，`delete[]` 是 UB |
| I. malloc 类指针用 delete | `malloc/calloc/strdup/kmalloc/...` 必须用对应的 `free/kfree/g_free/...` 释放，不能用 C++ `delete` |

### Step 4 — 验证"看不见的"置空 / 返回 / 守卫

语法初筛只能匹配字面 `$P = NULL`，会漏掉很多形式的"已置空"：

- **宏内置空**：`FREE_AND_NULL(p)` / `SAFE_FREE(p)` / `RELEASE_IF(p)` 等宏在内部展开为 `free(p); p = NULL;`。查看宏定义确认。
- **函数封装内置空**：`my_free(&p)` 通过双重指针在内部置 NULL。查看函数实现。
- **同名条件守卫**：第二次释放前是否有 `if (p) ...` / `if (p != NULL) ...` / `if (obj->field) ...` 守卫？守卫存在时即便重复调用 free 也安全。
- **release 函数自身的 NULL 容忍**：`free(NULL)` 是安全的；`delete nullptr` 是安全的；但很多自定义 release wrapper 不是。需要看其实现。
- **早 return**：第一次释放后是否 `return` 跳出，根本到不了第二次释放？基于 `goto $LABEL` 的初筛理论上能识别 goto，但若实际控制流是 `return` 或 `break` 跳出，告警可能本身就是误报。

### Step 5 — Template D 的所有权语义专项

Template D（possible-ownership-transfer-then-caller-release）误报率最高，需要特别仔细：

1. **`$TAKE` 是"借用"还是"接管"？**
   - 借用语义（e.g. `lookup(key, p)` 拷贝 p 的内容到 map）：caller 仍持有 ownership，后续 `$REL($P)` 正确，**判定误报**。
   - 接管语义（e.g. `container.add(p)` 接管 p）：caller 不应再释放，后续 `$REL($P)` 就是双 free，**判定真实漏洞**。
2. **失败时的所有权归属？**
   - 常见 API（Linux/glib/xml/Qt）：失败时不接管，caller 需要 free → Template D 的"失败分支释放"是**正确**写法，**判定误报**。
   - 反例 API（部分 Kernel API、`av_packet_ref`、`evbuffer_add_reference` 等）：无论成功失败都接管 → 失败分支释放就是**真实漏洞**。
3. **是否依赖具体 API 名**：通过 `find_function_references` 或 `view_function_code` 查看 `$TAKE` 函数体；若是项目内 wrapper，直接读懂；若是第三方库，需要参考其文档语义。

### Step 6 — Template G 的拷贝可达性

Rule of Five 告警的真假取决于：

- 这个类对象**是否真的会被拷贝**？查看类的使用情况：是否按值传入函数？是否放进 `std::vector<T>` / `std::map<K, T>`？是否赋值给另一个对象？
- 类是否声明 `MyClass(const MyClass&) = delete;` 或 `MyClass& operator=(const MyClass&) = delete;`？
- 如果根本没有拷贝路径，告警是潜在风险但当前不可触发，可降级为 low 严重度或视为误报。

## 判定标准

### 判为误报（confirmed=false）的情形

1. **release 之后已置 NULL**（包括宏 / 双指针函数封装）
2. **释放路径之间存在 return / break，第二次释放不可达**
3. **第二次释放前有 NULL 守卫**：`if (p) free(p);` / `if (obj->field) ...`
4. **release wrapper 容忍 NULL 或具有"已释放则 no-op"语义**（需 view_function_code 确认）
5. **Template D：`$TAKE` 是借用语义**（不接管所有权），或失败时确认不接管
6. **Template G：类对象不可拷贝**（`= delete` 或代码中不存在拷贝路径）
7. **Template E：refcount 实际 get 次数 >= put 次数**，没有真正失衡
8. **Template I：`$ALLOC` 实际是 wrapper，内部分配方式与 `delete` 实际匹配**（罕见但存在）
9. **测试 / mock / 模拟代码**：文件路径包含 `test/` `stub/` `mock/` 等

### 判为真实漏洞（confirmed=true）的条件

- 同一资源在两条可达路径上被释放两次，且：
  - 中间没有任何 NULL 置位（含宏 / 包装函数 / 守卫）
  - release wrapper 实际会执行真实释放且不容忍已释放指针
  - 第二次释放路径可达（未被前置 return / break 阻断）
- 对 Template D：`$TAKE` 真正接管所有权且 caller 仍释放
- 对 Template H：两个 smart_ptr 真的来自同一裸指针 / get() 结果被手动 delete
- 对 Template I：allocator / deallocator 家族不匹配，触发 UB

## 严重程度（severity）

- **high**：在常规调用路径上即可触发，资源由攻击者可控或在生产路径上一定走到；或属于 Template H / I 这种确定性 UB
- **medium**：需要特定错误路径或失败分支才触发，但路径在异常输入下可达
- **low**：触发条件极为苛刻（仅在 OOM、罕见 syscall 失败等场景），或资源不受攻击者影响

## 提交结果

分析完成后**必须**调用 `submit_result` 提交结论：

- `result_id`：由分析提示中提供，原样传入
- `confirmed`：true 表示确认漏洞，false 表示误报
- `severity`：`"high"` / `"medium"` / `"low"`
- `description`：一句话摘要，例如 "错误分支 free(buf) 后未置 NULL，cleanup 标签再次 free(buf) 形成双重释放"
- `ai_analysis`：详细推理，需包含：
  1. 两次释放的具体代码位置（行号或片段）
  2. release wrapper 的真实语义（是否真释放、是否容忍 NULL）
  3. 两次释放之间是否存在 NULL 置位 / return / 守卫（如有）
  4. 对 Template D：`$TAKE` 的所有权契约结论；对 Template G：拷贝可达性结论
  5. 调用链可达性：触发该路径的输入条件是否现实
  6. 最终判定理由
