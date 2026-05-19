---
name: memleak-analysis
description: 验证异常分支内存泄漏候选漏洞
---

# 内存泄漏漏洞验证

你正在验证一个由静态分析发现的候选内存泄漏漏洞。你的任务是判断这是真实的 bug 还是误报。

## 背景

静态分析器已经完成了以下工作：
- 在函数中找到了所有释放资源的调用（free/release/destroy/cleanup/close 等）
- 发现某个退出点（return/goto/continue）之前，有变量在其他路径上被释放，但在当前路径上未被释放
- 已经过滤了判空分支（如 `if (p == NULL) return;`）和返回值所有权转移的情况

## 可用工具

你可以使用以下 MCP 工具来查询代码：

- `view_function_code(project_id, function_name)` — 查看函数的完整源码
- `view_struct_code(project_id, struct_name)` — 查看结构体/类的定义
- `view_global_variable_definition(project_id, var_name)` — 查看全局变量定义
- `submit_result(result_id, confirmed, severity, description, ai_analysis)` — 提交分析结论

## 分析步骤

1. **查看候选函数源码**：理解函数的整体逻辑和资源管理模式
2. **定位资源分配点**：找到疑似泄漏变量的分配位置（malloc/calloc/realloc/new/Get/Query/Init 等）
3. **追踪所有退出路径**：确认正常路径和异常路径的释放行为差异
4. **检查释放函数语义**：如果释放函数不是标准库函数，查看其定义确认是否真正释放资源
5. **排除误报情形**（见下方判定标准）

## 判定标准

### 判为误报 (confirmed=false) 的情形

1. **判空分支退出**：如 `if (p == NULL) return;`，此时变量本就是 NULL，无需释放
2. **资源未分配**：该退出点之前，变量尚未被分配/填充资源（例如函数开头的参数校验 return）
3. **所有权转移**：资源已被存入结构体字段、链表、全局变量，或作为返回值交给调用者
4. **消息发送转移**：变量通过 SendMsg/PostMsg/Enqueue/Dispatch 等接口移交给消息框架
5. **非堆资源**：变量是栈上纯值（如 `int status = {0}`），不持有堆内存
6. **其他释放机制**：通过析构函数、智能指针包装、scope guard 等已确保释放
7. **释放函数实际不释放内存**：查看释放函数定义后发现它只是重置状态，不涉及堆内存
8. **测试/桩代码**：文件路径包含 dt/stub/test 等，属于测试代码

### 判为真实漏洞 (confirmed=true) 的条件

- 变量在当前路径上确实被分配/填充了资源
- 该资源的释放函数确实释放堆内存或外部资源
- 异常路径的退出前没有调用释放函数，也没有通过其他方式转移所有权
- 函数的其他路径上有明确的释放调用作为对照

## 提交结果

分析完成后，**必须**调用 `submit_result` 工具提交结论：

- `result_id`：由分析提示中提供，原样传入
- `confirmed`：true 表示确认漏洞，false 表示误报
- `severity`：严重程度 "high" / "medium" / "low"
  - high: 明确的内存泄漏，在错误处理路径中必定触发
  - medium: 可能的内存泄漏，取决于运行时条件
  - low: 边缘情况的泄漏，影响较小
- `description`：一句话摘要
- `ai_analysis`：详细推理过程，包括资源分配位置、退出路径分析、判断理由
