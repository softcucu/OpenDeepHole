---
name: skill_only_project_audit
description: 管理员测试用项目级 SKILL-only checker，用于验证无 analyzer.py 的 checker 可直接审计代码扫描路径并多次提交结果
---

# SKILL-only 项目级审计测试

你正在执行一个项目级审计测试任务。这个 checker 没有 `analyzer.py`，系统会自动生成一个项目级候选点，然后直接运行本 SKILL。

## 目标

验证你可以在目标代码目录中完成项目级审计，并通过 MCP 工具提交真实结果。

重点不是复核某个静态分析候选点，而是主动阅读代码，寻找可能存在的真实安全问题。发现一个问题就提交一个结果。

## 可用工具

- `view_function_code(project_id, function_name, file_path="")` - 查看指定函数源码
- `view_struct_code(project_id, struct_name)` - 查看结构体、类或联合体定义
- `view_global_variable_definition(project_id, global_variable_name)` - 查看全局变量定义
- `submit_result(result_id, confirmed, severity, description, ai_analysis, file="", line=0, function="")` - 提交审计结果

## 审计要求

1. 先理解代码扫描路径对应的代码范围。提示词中会给出代码扫描路径和 `project_id`。
2. 选择若干关键函数阅读源码，优先关注入口函数、解析函数、认证/权限判断函数、内存拷贝函数、资源释放函数。
3. 如果发现真实问题，每个问题都必须单独调用一次 `submit_result`。
4. 每次提交真实问题时必须填写：
   - `confirmed=true`
   - `severity` 为 `high` / `medium` / `low`
   - `description` 用一句话说明问题
   - `ai_analysis` 写清楚证据、可达路径、触发条件和影响
   - `file` 为真实问题所在文件路径
   - `line` 为真实问题所在行号
   - `function` 为真实问题所在函数名
5. 如果没有发现真实问题，也必须调用一次 `submit_result`，提交：
   - `confirmed=false`
   - `severity="low"`
   - `description` 说明没有发现可确认问题
   - `ai_analysis` 简要说明检查过的函数和未确认漏洞的原因
   - `file`、`line`、`function` 使用提示词中给出的项目级占位值

## 判定标准

确认真实问题需要满足：

- 能指出具体函数和具体行号
- 能说明问题如何被触发
- 能说明现有校验为什么不能阻止问题
- 能说明影响范围

以下情况不要确认：

- 只有代码风格问题，没有安全影响
- 缺少可达路径或触发条件
- 已有边界检查、权限检查或错误处理覆盖该路径
- 位于测试、mock、stub 或不可达代码中

## 输出约束

不要只在文字回复中列出问题。审计完成后必须调用 `submit_result`。如果发现多个问题，必须多次调用 `submit_result`，一次只提交一个问题。
