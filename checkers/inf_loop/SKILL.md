---
name: inf-loop-analysis
description: 验证死循环候选漏洞（CWE-835），判断是否为真实可触发的无限循环
---

# 死循环漏洞验证

你正在核实一处候选死循环线索（CWE-835）。你的任务是判断这是真实的 bug 还是误报。

## 背景

候选线索通常落在以下死循环形态之一（while/for/do-while 循环控制变量未更新、C++ 迭代器失效、容器遍历中修改容器、zero-step 步进等），即"某个 continue/迭代路径上，循环控制状态未被推进"。

候选描述中已尽量给出**循环控制变量**等线索（请据此自行判断属于下文哪种形态）。

候选线索只来自语法层面的初筛，无法感知：跨函数的状态更新、指针/引用间接修改、外部信号/flag 退出、以及有意设计的事件循环。你需要做语义层面的验证。

## 可用工具

- `view_function_code(project_id, function_name)` — 查看函数完整源码
- `view_struct_code(project_id, struct_name)` — 查看结构体/类定义
- `submit_result(result_id, confirmed, severity, description, ai_analysis)` — 提交分析结论（必须调用）

## 分析步骤

### Step 1 — 读取完整函数体

用 `view_function_code` 获取 candidate 所在函数的完整源码。注意：候选描述只给了少量上下文，不足以判断，必须看整个函数。

### Step 2 — 判断候选形态，明确验证目标

根据候选涉及的循环形态（自行判断属于下表哪类），确定本次要验证的核心问题：

| 候选形态 | 核心验证问题 |
|---------|------------|
| while + continue 无推进 | continue 分支之前，循环控制变量是否在**所有代码路径**上都有更新？ |
| for 空 increment + continue | for 循环 increment 为空，continue 跳回 condition 而非 increment，变量是否在循环体内每条 continue 前更新？ |
| do-while + continue 无推进 | do-while 的 continue 跳回 condition，该 condition 依赖的状态是否在 continue 前更新？ |
| 步进量可能为 0 | 步进量（`$STEP`）在运行时是否可能为 0？若为 0 则循环不前进 |
| erase 后未回写迭代器 | `container.erase(it)` 的返回值是否被赋回迭代器？否则迭代器失效导致 UB 或死循环 |
| 迭代器循环 continue 无推进 | 迭代器控制的循环，continue 分支前迭代器是否推进？ |
| str.find 位置未递增 | `str.find(x, pos)` 的 pos 是否在循环中递增？否则永远在同一位置搜索 |
| lower_bound key 未推进 | `lower_bound(key)` 的 key 是否在循环中推进？ |
| 迭代器循环中修改容器 | 在迭代器循环中 insert/erase，是否正确更新了迭代器？ |
| range-for 修改同一容器 | range-for 遍历时修改同一容器，是否会导致迭代器失效？ |
| worklist 重复入队未改状态 | 重新入队的元素，其状态是否有改变？否则会被无限反复处理 |

### Step 3 — 验证退出条件与间接更新

检查循环内是否有初筛遗漏的退出或推进机制：

- **显式退出**：`break` / `return` / `throw` / `goto` / `exit()` 是否覆盖了所有可达路径？
- **子函数内的隐式更新**：continue 前调用的子函数是否在内部推进了状态（如 `buf = next_record(buf)`）？用 `view_function_code` 查看可疑的子函数。
- **间接更新**：循环变量是否是指针/引用，通过 `ptr = ptr->next` 或被子函数修改其指向内容？
- **外部 flag**：循环条件是否依赖外部变量（`g_running`、`timeout`），由其他线程/信号更新？

### Step 4 — 向上追溯调用链

根据 candidate 描述中的调用链线索，用 `view_function_code` 查看关键调用方，重点确认：

- **循环控制变量的来源**：若变量是函数参数（规则类型含 `param`），调用方传入的值是什么？是固定值、外部输入还是计算结果？
- **触发问题路径的前提条件**：调用方在什么情况下会让代码走入 continue 分支？这个条件是否现实可达？
- **数据是否来自外部输入**：追溯到最顶层，循环变量或触发条件最终是否来自网络、文件、用户输入等外部可控来源？若是，则为高危 DoS。
- **意图识别**：调用方是否总是以"预期无限运行"的方式调用（如主线程事件循环）？

如果调用方数量很多或调用链较深，优先查看最典型的 1-2 个调用路径，重点判断可达性。

### Step 5 — 意图识别

判断这个循环是否为有意设计的无限循环（若是则为误报）：

- 是否是服务器/守护进程的主循环（`while (g_running)`，等待外部停止信号）？
- 是否是事件驱动的消息泵（`while (true) { event = wait(); process(event); }`）？
- 循环内是否有阻塞等待（`select`、`poll`、`epoll_wait`、`pthread_cond_wait`、`sleep` 等）？
- 代码注释是否说明这是预期行为？

## 判定标准

### 判为误报（confirmed=false）的情形

1. **循环变量实际被更新**：通过指针/引用/子函数间接更新，语法初筛未能识别
2. **有效的隐式退出**：break/return 存在于语法初筛未覆盖的路径上（如宏展开、内联函数）
3. **有意设计的无限循环**：主循环、事件泵、含阻塞等待的服务循环
4. **zero-step 不可达**：步进量在调用约定/类型约束下不可能为 0
5. **迭代器已正确更新**：erase/insert 的返回值被正确赋回
6. **调用链分析表明路径不可达**：触发 continue 分支的条件在正常调用中无法成立
7. **测试/桩代码**：文件路径包含 test/stub/mock 等

### 判为真实漏洞（confirmed=true）的条件

- 循环控制变量/迭代器在 continue 分支前确实没有推进，且没有任何间接更新机制
- 循环内没有其他退出路径可以终止执行
- 调用链分析确认该路径在实际运行中可被到达

## 严重程度（severity）

- **high**：可由外部可控输入直接触发，程序完全挂起（DoS）
- **medium**：需要特定内部状态触发，或触发后仅部分功能受影响
- **low**：触发条件极为苛刻，或影响范围极小

## 提交结果

分析完成后**必须**调用 `submit_result` 提交结论：

- `result_id`：由分析提示中提供，原样传入
- `confirmed`：true 表示确认漏洞，false 表示误报
- `severity`：`"high"` / `"medium"` / `"low"`
- `description`：一句话摘要
- `ai_analysis`：详细推理，需包含：触发路径的具体代码、循环控制变量更新情况、调用链分析结论、判定理由
