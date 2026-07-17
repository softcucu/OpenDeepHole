---
name: mp-resouce-leak-analysis
description: 验证多层指针成员资源泄露候选漏洞（CWE-401 / CWE-772），判断 ctx->session->buf 类多层成员持有的资源是否真的存在泄露
---

# 多层指针成员资源泄露验证

你正在核实一处候选资源泄露线索（CWE-401 内存泄露 / CWE-772 资源句柄泄露），问题形态是 **多层指针成员**（形如 `ctx->session->buf`、`obj->child->fd`）持有的资源未被正确释放。你的任务是判断这是真实的 bug 还是误报。

## 背景

候选线索通常落在以下多层指针成员资源管理的 5 个失误形态之一：
  1. **获取后函数内未释放**：多层成员被赋为资源获取函数的返回值，但当前函数内未看到任何对该成员的后续函数调用（可能是释放）
  2. **覆盖前未释放**：多层成员被两次资源赋值覆盖，中间没有释放调用
  3. **置空前未释放**：多层成员被直接置 NULL，置空前未释放原资源
  4. **realloc 结果直接覆盖丢失旧指针**：多层成员直接接收 realloc 类返回值，失败返回 NULL 时旧指针丢失
  5. **临时变量转存成员后未释放**：临时变量持有资源后赋值给多层成员，当前函数内未看到该多层成员被释放

候选描述中已尽量给出**多层成员 / 资源获取函数 / realloc 函数 / 临时变量** 等线索（请据此自行判断属于上述哪种形态）。

候选线索只来自语法层面的初筛，无法感知：所有权是否转移到外部对象（典型场景：把资源挂到 `ctx->session->buf`，由 owner 的析构/销毁函数统一释放）、宏内的释放、跨函数的 cleanup、跨编译单元的析构合约。多层指针成员资源管理本身**所有权链复杂、误报率高**，必须做语义层面的验证。

## 分析步骤

### Step 1 — 读取完整函数体

阅读 candidate 所在函数的完整源码。候选描述只给了少量上下文，**必须**看到完整函数才能判断：

- 函数是否还有其他位置释放了该多层成员（初筛仅以字面包含该字段的调用 `$ANY($FIELD, ...)` 算作释放，会错过 wrapper 调用或宏调用）
- 函数返回前是否调用了 `destroy_ctx(ctx)` / `free_session(ctx->session)` 等 wrapper，统一释放包括该成员在内的所有资源
- 是否存在 `if (err) goto cleanup;` 类错误处理路径

### Step 2 — 理解"多层成员所有权"的常见架构

多层指针成员（`ctx->session->buf`）的释放通常**不在赋值函数**里，而在 owner 链上某一层的销毁函数里：

```
ctx ─owns─► session ─owns─► buf
```

释放时机的几种典型架构：

1. **链式销毁**：`destroy_ctx(ctx)` 内部调用 `destroy_session(ctx->session)`，后者再 free `buf`。**这种是正常架构，告警是误报。**
2. **owner 直接释放成员**：当前函数调用 `free(ctx->session->buf)`。如果初筛已识别就不会报告；如果用了宏或自定义 wrapper，可能误报。
3. **泄露**：当前函数赋值后既没有自己释放，也没有任何 destroy 函数会到达 `ctx->session->buf`。**这才是真实漏洞。**

判断架构需要：
- 查看 `ctx`、`session` 是什么类型
- 查找该函数的调用方，看调用方在错误路径是否调用 destroy
- 在项目里找配套的 `destroy_<type>` / `free_<type>` / `<type>_release` 函数，看它是否级联释放

### Step 3 — 根据候选形态聚焦核心验证问题

| 候选形态 | 核心验证问题 |
|---------|------------|
| 获取后函数内未释放 | 当前函数确实没有释放该成员（包括宏、wrapper、调用 destroy_xxx）？所有权是否转移到 owner 链，由外部 destroy 释放？ |
| 覆盖前未释放 | 两次赋值之间真的没有释放旧值（含宏 / 通过临时变量 / 上锁与解锁内）？第二次赋值是否就是 realloc 语义（旧值已经在内部释放）？ |
| 置空前未释放 | 置 NULL 前没释放：是因为 cleanup 顺序错误（先 NULL 再 free），还是因为该成员本来就是借用的引用、不应释放？ |
| realloc 结果丢失旧指针 | realloc 失败时旧指针确实会丢失？是否项目使用的 realloc wrapper 在失败时已保留旧值？ |
| 临时变量转存成员后未释放 | 临时变量赋值给成员后，所有权是否真的转移给 owner，由 owner 销毁路径释放？或者是否是"暂存指针"语义（caller 仍负责） |

### Step 4 — 验证"看不见的"释放路径

语法初筛的局限：

- `$ANY($FIELD, ...)` 只识别**字面**包含该字段的函数调用。但实际项目里大量使用：
  - **宏释放**：`SAFE_FREE(ctx->session->buf)` / `FREE_AND_NULL(ctx->session->buf)`，宏内调用 free
  - **链式销毁**：`destroy_session(ctx->session)` 内部释放 `ctx->session->buf`
  - **owner 销毁**：`destroy_ctx(ctx)` 内部级联释放
  - **借用语义**：`ctx->session->buf` 实际只是 `g_buffer` 的别名，由全局拥有者释放

排查方法：
- 全函数搜索 `destroy / free / release / cleanup / fini / close / put / drop` 类的调用
- 对每个嫌疑调用，进入其实现，看是否级联释放
- 看根对象类型，是否有配套的 destroy 函数；如果有，候选函数可能依赖 caller 调 destroy

### Step 5 — 判断所有权归属

关键问题：**当前函数对 `ctx->session->buf` 的所有权契约是什么？**

- **当前函数是初始化函数**（`init_xxx`、`create_xxx`、`load_xxx`）：通常分配后所有权转给 caller，由 caller 在 destroy 时释放。当前函数内不释放是**正常**的。但要确认两点：
  1. 错误路径上是否需要回滚（异常路径下 caller 不知道资源已分配，需要当前函数清理）
  2. 是否有错误返回但没回滚的路径（半初始化对象 + 调用方不 destroy = 泄露）
- **当前函数是 destroy/cleanup 函数**：负责释放，置 NULL 前必须先 free
- **当前函数是 reset/重新初始化**：通常需要释放旧资源再赋新值，覆盖类告警高度可疑
- **当前函数是临时操作**（`process_xxx`、`handle_xxx`）：通常不应让 `ctx->session->buf` 在函数返回后还指向新分配但 caller 没记录的资源

### Step 6 — Realloc 类专项

`x = realloc(x, n)` 是经典反模式：失败时 realloc 返回 NULL，但旧 `x` 仍指向有效内存。直接覆盖会丢失旧指针。

- 看项目使用的是标准 `realloc` 还是 wrapper（如 `g_realloc` 失败时 abort；某些 wrapper 失败时保留旧值并返回旧值）
- 如果是 wrapper：查看其失败语义
- 如果是标准 realloc：基本判定为真实漏洞，severity=high（OOM 时确定泄露）

### Step 7 — 调用链 / 触发可达性

- 触发该函数的路径：是常规业务路径，还是仅在 OOM / 内核故障下进入？
- 资源大小是否受外部输入影响（攻击者能否构造请求让该路径反复触发）？
- 该函数运行频率：每次请求触发 vs 每次进程启动触发？高频泄露危害远大于一次性泄露。

## 判定标准

### 判为误报（confirmed=false）的情形

1. **owner 链统一销毁**：根对象 `ctx` 或中间层 `session` 有配套的 destroy 函数，会级联释放该成员，且 caller 在生命周期结束时一定会调用 destroy
2. **释放通过宏 / wrapper 完成**：函数内确实释放了，但因字面匹配限制未被初筛识别（如 `SAFE_FREE(ctx->session->buf)`）
3. **借用语义**：多层成员实际只是其他真实持有者的别名（`ctx->session->buf = g_global_buf`），不应在当前函数释放
4. **realloc wrapper 容忍失败**：项目使用的 realloc 失败时不返回 NULL（如 `g_realloc` 直接 abort），不会真的丢指针
5. **重复赋值之间通过临时变量释放**：第二次赋值前对应资源已转交 caller / 全局缓存
6. **测试 / mock / 模拟代码**

### 判为真实漏洞（confirmed=true）的条件

- 多层成员持有了新分配资源
- 当前函数没有释放，且没有任何 owner 销毁路径会释放它
- 或：覆盖 / 置 NULL / realloc 路径上旧资源指针确实丢失
- 路径可达（在正常业务或合理错误场景下能触发）

## 严重程度（severity）

- **high**：高频路径上稳定泄露（每次请求泄露、外部输入可控）、或确定性 realloc 失败丢指针、或 long-running 服务的连接生命周期内持续累积泄露
- **medium**：仅在错误路径 / 异常路径下泄露、或 caller 已经通过 destroy 部分释放但留下细节缺口
- **low**：仅进程启动 / 一次性路径上的小量泄露，对服务运行影响极小

## 结论内容

分析完成后按以下字段给出结论：

- `confirmed`：true 表示确认漏洞，false 表示误报
- `severity`：`"high"` / `"medium"` / `"low"`
- `description`：一句话摘要，例如 "init_session 错误分支返回前未释放 ctx->session->buf，且 caller 不会再调用 destroy_session 形成泄露"
- `ai_analysis`：详细推理，需包含：
  1. 多层成员的具体表达式与所在函数性质（init / reset / cleanup / 业务）
  2. 资源获取方式（直接 alloc / wrapper / realloc / 临时变量转交）
  3. owner 链销毁函数是否存在、是否级联释放该成员（具体函数名 + 看到的代码）
  4. caller 端的销毁责任（来自调用方分析的结论）
  5. 是否存在通过宏 / wrapper 完成的隐式释放
  6. 最终判定理由
