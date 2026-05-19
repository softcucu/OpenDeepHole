---
name: mp-npd-analysis
description: 验证多层指针空指针解引用候选漏洞（CWE-476），判断 ctx->session->buf 类多层指针使用前是否真的存在判空缺失
---

# 多层指针空指针解引用验证

你正在验证一个由 semgrep 静态分析发现的候选空指针解引用漏洞（CWE-476），漏洞模式是 **多层指针**（形如 `ctx->session->buf`、`req->msg->hdr->len`）在使用前未完整判空。你的任务是判断这是真实的 bug 还是误报。

## 背景

静态分析器已经完成了以下工作：

- 使用 semgrep 扫描了 3 条规则，覆盖多层指针判空缺失的 3 个典型模式：
  1. **multi-layer-pointer-use-before-null-check**：多层指针 `$ROOT->$F1->$F2` 在使用前未见任何对 `$ROOT` 或 `$ROOT->$F1` 的判空（最宽泛规则）
  2. **multi-layer-pointer-root-checked-child-unchecked**：根指针 `$ROOT` 已在外层 `if` 中判空，但内层使用了 `$ROOT->$F1->$F2`，中间层 `$ROOT->$F1` 未判空（confidence=high）
  3. **multi-layer-pointer-used-as-argument-before-null-check**：多层指针 `$ROOT->$F1->$F2` 作为参数传入函数调用 `$CALL(..., $ROOT->$F1->$F2, ...)`，使用前未完整判空
- candidate 描述中的**规则类型 / 多层指针表达式 / 根指针 / 中间层 / 被调用函数**等元信息已尽量提取

semgrep 是纯语法模式匹配，无法感知：判空发生在调用方、判空通过宏（`CHECK_NULL(ctx)`）或断言（`assert / BUG_ON`）实现、字段在结构体设计上"不可能为空"（构造函数保证）、判空在 inline 函数 / 子函数内完成等场景。多层指针使用本身**误报率高**，必须做语义层面的验证。

## 可用工具

- `view_function_code(project_id, function_name)` — 查看函数完整源码（必查；尤其重点看函数入口处的参数校验、调用前的 if 块、宏调用）
- `view_struct_code(project_id, struct_name)` — 查看结构体定义（确认 `$ROOT`、`$ROOT->$F1` 的类型；判断中间层指针是否在结构体中始终被初始化为非 NULL）
- `find_function_references(project_id, function_name)` — 查找候选函数的所有调用方（核心：判断调用方是否已经保证根指针 / 中间层非空）
- `submit_result(result_id, confirmed, severity, description, ai_analysis)` — 提交分析结论（必须调用)

## 分析步骤

### Step 1 — 读取完整函数体

用 `view_function_code` 获取 candidate 所在函数的完整源码。candidate 描述只给了 semgrep 匹配的几行，**必须**看到完整函数才能判断：

- 函数入口处是否对 `$ROOT` 或 `$ROOT->$F1` 做了校验（包括 `if (!ctx || !ctx->session) return -1;`、`assert(ctx && ctx->session)`、`CHECK_PTR(ctx->session)` 等宏）
- 该使用点上方是否存在被 semgrep 因 pattern 形式不同而漏掉的判空（如 `if (likely(p))`、`if ((p) != ((void *)0))`、`switch` 语句、`?:` 三目表达式）
- 是否在 `if (ctx) { ... if (ctx->session) { ... } }` 这种嵌套但中间夹杂语句的结构里

### Step 2 — 理解"多层指针解引用"的常见判空架构

多层指针访问 `ctx->session->buf` 至少要求：
1. `ctx != NULL`
2. `ctx->session != NULL`

完整判空通常有几种实现方式：

1. **入口集中校验**：函数顶部一次性校验所有参数及其中间层，后续访问无需重复判空。**正常架构，告警通常误报。**
2. **逐层 if 检查**：`if (ctx && ctx->session && ctx->session->buf) { ... }`，semgrep 已识别。
3. **失败提前返回**：`if (!ctx || !ctx->session) return -ERR;`，semgrep 已识别基础形式，但变体（含日志、含计数、`{ log(); return; }` 多语句）可能漏判。
4. **结构体不变量**：根对象通过构造函数 `create_ctx` 保证 `session` 永远非空；语义上是"私有数据，外部碰不到"。**正常架构，告警通常误报。**
5. **真实漏报**：使用前确实未做任何判空，且不变量也不保证非空。**这才是真实漏洞。**

### Step 3 — 根据规则类型聚焦核心验证问题

| 规则类型 | 核心验证问题 |
|---------|------------|
| `multi-layer-pointer-use-before-null-check` | 函数内是否真的没有判空？是否依赖入口校验、宏校验、不变量保证非空？根指针的来源是否可控？ |
| `multi-layer-pointer-root-checked-child-unchecked` | `$ROOT` 已判空，但中间层 `$ROOT->$F1` 是否可能为 NULL？结构体设计上是否允许 `$ROOT->$F1 == NULL`（如可选字段、懒加载、清理过程中暂时为空）？ |
| `multi-layer-pointer-used-as-argument-before-null-check` | 被调用函数 `$CALL` 是否在内部做了 NULL 校验？传入的 `$ROOT->$F1->$F2` 解引用动作发生在调用前还是调用内？ |

### Step 4 — 验证"看不见的"判空路径

semgrep 的 `pattern-not-inside` 限制：

- 只识别字面形式 `if ($ROOT && $ROOT->$F1)` 等少量变体；以下形式会漏判：
  - **宏校验**：`CHECK_NULL_RETURN(ctx, -1); CHECK_NULL_RETURN(ctx->session, -1);`
  - **inline 函数封装**：`validate_ctx(ctx)` 内部 abort/return
  - **switch / 三目运算符 / 短路逻辑链**：`(!ctx || !ctx->session) ? bail() : 0;`
  - **判空发生在更上层 caller**：当前函数仅是 hot path，caller 早已经检查（需 `find_function_references` 确认）
  - **结构体不变量**：根对象类型设计上保证某字段构造后永不为 NULL（例如指向静态全局，或在构造函数中分配）
  - **assert / BUG_ON 之外的防御宏**：`VOS_ASSERT(p)`、`PRINT_ON_FAIL(p)` 等项目自定义防御宏

排查方法：
- 在函数体内全文搜索 `$ROOT` 与 `$F1`（如 `ctx`、`session`），看是否出现在自定义防御宏 / inline 函数 / 短路链中
- 进入嫌疑宏/函数（`view_function_code`）确认是否触发 return/abort 路径
- 用 `find_function_references` 查 caller，判断 caller 是否一定已经检查

### Step 5 — 判断中间层指针的"不变量"

最关键的判定问题：`$ROOT->$F1` 在到达使用点时是否可能为 NULL？

- **结构体定义层面**：`view_struct_code` 查根类型；若 `$F1` 是 `struct session *session;` 且初始化路径不明，则可能为空；若是通过 `create_ctx` 内部 `ctx->session = alloc()` 必填，则正常不为空（但要看是否有失败路径设置为 NULL，或 reset 函数置空）
- **生命周期分析**：在 `init / reset / destroy / detach` 等阶段，`$F1` 可能短暂为 NULL；如果当前函数可能在这些阶段被并发调用（多线程）或在错误路径上被调用，则风险存在
- **caller 上下文**：用 `find_function_references` 查找当前函数的调用方；若全部 caller 都在持有有效 session 时调用（如 `if (s = get_session()) handle(s)`），则误报概率高

### Step 6 — 多层指针作为函数参数的特殊情形

对于规则 3（`used-as-argument-before-null-check`）：

- C/C++ 语义：`func(ctx->session->buf)` 在 `func` 调用前就已经完成了 `ctx->session->buf` 的解引用读取，NULL 解引用发生在调用方而非被调函数。
- 即使 `func` 内部做了 `if (!ptr) return;`，**也来不及** —— 解引用已经发生。
- 因此该规则的误报主要是入口校验、宏校验或不变量保证；不能因为"被调函数有空检查"就判误报。

### Step 7 — 调用链 / 触发可达性

- 触发该函数的路径是常规业务路径还是仅在异常 / 初始化失败 / 销毁中间态进入？
- `$ROOT` 是否来自外部输入（网络协议、用户配置、IPC 消息）？若是，攻击者构造 `$ROOT` 为 NULL 或让中间层 `$F1` 缺失即可触发崩溃 DoS
- 该函数是否运行在敏感上下文（信号处理、中断、内核态）？任何崩溃都可能放大为安全问题

## 判定标准

### 判为误报（confirmed=false）的情形

1. **入口集中校验**：函数顶部已校验 `$ROOT` 与 `$ROOT->$F1`（含通过宏 / inline 函数），semgrep 未识别
2. **caller 已校验**：所有 caller 都在持有有效 `$ROOT->$F1` 时才调用当前函数（通过 `find_function_references` 全量确认）
3. **结构体不变量保证**：`$ROOT->$F1` 在该类型生命周期内不为 NULL（构造函数必填、destroy 之外无置空路径），且当前函数不可能在 destroy 后被调用
4. **宏 / inline 函数完成判空**：semgrep 看不到的防御机制存在
5. **路径不可达**：触发空指针访问的具体上下文在正常运行中不可能成立
6. **测试 / mock / 模拟代码**：路径在 tests/、mock/ 等目录下

### 判为真实漏洞（confirmed=true）的条件

- 多层指针使用点上方确实没有任何判空（包括函数内、调用方、宏、不变量）
- `$ROOT->$F1` 在某些可达状态下确实可能为 NULL（错误路径未分配、reset 路径已置空、并发条件下被其他线程清空、字段为可选）
- 该路径在实际运行中可达（普通业务、可触发的错误场景、可控输入）

### 特别加权（更倾向 confirmed=true）

- 候选位置位于错误处理 / cleanup / fallback 路径上（常见漏检场景）
- `$ROOT` 直接来自外部输入（攻击者可控）
- 候选所在函数为 callback、协议解析、IPC 入口（外部触发频繁）

## 严重程度（severity）

- **high**：外部可控输入 / 攻击者可触发的崩溃（DoS）、或敏感上下文崩溃（驱动 / 内核 / 关键服务）
- **medium**：仅内部状态错误时触发、或仅在特定错误路径上触发但 caller 不会清理
- **low**：触发条件极苛刻、或仅影响一次性启动 / 调试路径

## 提交结果

分析完成后**必须**调用 `submit_result` 提交结论：

- `result_id`：由分析提示中提供，原样传入
- `confirmed`：true 表示确认漏洞，false 表示误报
- `severity`：`"high"` / `"medium"` / `"low"`
- `description`：一句话摘要，例如 "process_request 中访问 ctx->session->buf 前未校验 ctx->session，错误路径下 session 可能为 NULL 导致崩溃"
- `ai_analysis`：详细推理，需包含：
  1. 多层指针表达式与所在函数性质（入口 / 业务 / cleanup / callback）
  2. 函数内 / 函数前是否有判空（具体行号或宏名）
  3. 根指针 `$ROOT` 与中间层 `$ROOT->$F1` 的来源与不变量分析（结构体定义、初始化路径）
  4. caller 端是否承担校验责任（`find_function_references` 结论）
  5. 是否存在通过宏 / inline 函数 / 不变量完成的隐式校验
  6. 最终判定理由
