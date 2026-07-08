---
name: multi_ptr_leak2
description: 验证结构体最外层指针释放时是否遗漏释放其指针成员，判断是否为真实资源泄露
---

# 多层指针外层释放遗漏成员验证

你正在核实一处候选线索：候选位置存在释放函数调用，并且**某一个表达式**已被识别为含指针成员的结构体/类/联合体对象。你的任务是判断释放路径是否只释放了最外层对象，而没有释放结构体内部应由它拥有的指针成员。

## 必读：description 的结构化字段

description 头部固定包含以下字段，**先读它们再读代码片段**，不要从代码反推：

- `所在函数: name (file:line)` —— 候选函数定义位置
- `调用形式: function_call | method_call | delete_expression`
- `释放实参: first_argument | receiver | delete_operand` —— 被识别为"含指针成员结构体"
  的那个表达式，不一定是第一个显式参数。method 调用下可能是 receiver（例如 `obj->destroy()`）
- `receiver: <expr>`（仅 method_call）—— receiver 表达式文本
- `释放调用: <callee>(<arg_text>)`
- `实参类型 / 结构体 / 指针成员 / 调用点上下文`

特别注意 `释放实参`：如果是 `receiver`，意味着候选要审计的对象是
receiver（`obj->destroy()` 中的 `obj`），而**不是**显式参数；如果是
`first_argument`，则按显式参数走。判错对象会直接产生误判。

## 可用工具

- `submit_result(confirmed, severity, description, ai_analysis)` - 提交结论，必须调用

## 必查步骤

1. 先阅读 candidate 所在函数完整源码。不要只根据 candidate 描述中的上下文片段下结论。
2. 查看 candidate 描述中的释放调用，例如 `free(ctx)`、`destroy_ctx(ctx)`、`delete obj`。如果释放函数是项目内 wrapper，继续阅读释放函数实现。
3. 查看候选结构体定义，确认指针成员的语义：是 owned resource、borrowed pointer、缓存别名、嵌套 owner，还是固定外部生命周期对象。
4. 如果释放函数调用了其他 cleanup/destroy/free wrapper，继续查看这些 wrapper 是否级联释放了候选结构体的指针成员。
5. 必要时查看释放函数的调用方，判断该函数是否就是该类型的唯一析构路径，以及 caller 是否额外释放成员。

## 判定重点

真实漏洞通常满足：

- 结构体指针成员由该结构体拥有，例如 `buf`、`data`、`items`、`name`、`child`、`session` 等在初始化路径中分配或获取。
- 释放路径只执行了 `free(obj)`、`delete obj` 或等价 wrapper，没有先释放 owned 指针成员。
- 没有析构函数、cleanup wrapper、引用计数 put、容器 owner 或 caller 侧 cleanup 能覆盖这些成员。
- 该释放路径可达，且泄露会在错误路径、重置路径或常规生命周期结束时发生。

误报通常满足：

- 释放函数内部已经调用了 `free(obj->field)`、`destroy_field(obj->field)`、`SAFE_FREE(obj->field)` 等，只是静态过滤没有理解 wrapper 或宏。
- 指针成员是 borrowed pointer、全局单例、字符串字面量、外部缓存别名，当前结构体不拥有它。
- C++ 析构函数或智能指针成员会自动释放资源。
- 成员由更外层 owner 统一释放，当前释放函数不承担该成员所有权。
- candidate 命中的是测试、mock 或死代码。

## 严重程度

- `high`: 常规请求或循环生命周期中稳定泄露，外部输入可反复触发，或大块内存/句柄泄露。
- `medium`: 错误路径、重置路径或较低频生命周期释放时泄露。
- `low`: 一次性启动/退出路径上的小量泄露，实际影响有限。

## 输出要求

分析完成后必须调用 `submit_result`：

- `confirmed`: true 表示确认漏洞，false 表示误报
- `severity`: `"high"`、`"medium"` 或 `"low"`
- `description`: 一句话说明结论
- `ai_analysis`: 写清楚释放调用、结构体指针成员、释放函数实现、所有权判断、是否存在级联 cleanup，以及最终判定理由
