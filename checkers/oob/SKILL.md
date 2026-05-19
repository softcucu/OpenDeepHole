---
name: oob-audit
description: >
  针对 C/C++ 函数进行越界读写（OOB）漏洞审计的 skill。覆盖六大场景：安全内存函数误用
  （memcpy_s / strcpy_s / _s 系列）、整数溢出/下溢、循环溢出、IO 类函数缓冲区溢出、
  数组越界、格式化字符串。当用户提供函数名并提出以下需求时触发：越界审计、OOB 审计、
  缓冲区溢出审查、内存安全审计、bounds check、代码审计、批量函数排查、漏洞扫描、
  buffer overflow review。即使用户只说"帮我审一下这个函数有没有越界问题"也应触发。
  本 skill 设计为一次审计一个函数，不论是否发现风险，均必须通过 submit_result 保存结果。
---

# 越界读写审计（函数级）

每次对话审计**一个 C/C++ 函数**，识别函数内所有可能导致越界读写的风险点，按六大场景
分类、加载对应 reference 进行深度分析，最后通过 `submit_result` 保存结果。

**核心原则：宁可误报，不可漏报。** 无法证明安全时，标记 `confirmed=true`。

**强制规则：每个函数必须调用一次 `submit_result`。** 即使函数完全无风险，
也要调用一次以保存"已审计"记录。

---

## Quick Start

输入：prompt 中会提供 `function_name`（可能附带 `file_path`）、`project_id` 和 `result_id`。


```
第 1 步  view_function_code(project_id, function_name)         → 获取函数完整代码
第 2 步  按下方"六场景初筛表"扫描函数体，登记所有命中点
第 3 步  对每个命中场景，view references/<场景文件>.md，按其规则深度分析
第 4 步  汇总所有风险点，调用一次 submit_result(...)
第 5 步  结束对话，不要再输出任何文字
```



---

## 六大场景与对应参考文件

| 编号 | 场景 | 参考文件（命中才加载） |
|------|------|----------------------|
| S1 | 安全内存函数误用（`memcpy_s` / `strcpy_s` / `_s` 系列 / VOS_* 等价函数） | `references/safe-mem-func.md` |
| S2 | 整数溢出 / 下溢 / 截断 / 符号转换 | `references/integer-overflow.md` |
| S3 | 循环溢出（循环上界来自外部、循环体内指针/下标累加） | `references/loop-overflow.md` |
| S4 | IO 类函数缓冲区溢出（`read` / `recv` / `fread` / `gets` / 无边界输出） | `references/io-buffer-overflow.md` |
| S5 | 数组越界（`arr[expr]` / `*(ptr+expr)`） | `references/array-oob.md` |
| S6 | 格式化字符串（格式化串非常量 / 参数数不匹配 / snprintf 返回值误用） | `references/format-string.md` |

**只加载初筛命中的参考文件，不要预加载全部六个。**

---

## 可用 MCP 工具

| 工具 | 何时调用 |
|------|---------|
| `view_function_code(project_id, function_name)` | **每次对话第一步必调**，获取函数体 |
| `view_struct_code(project_id, struct_name)` | dest / src / 数组是结构体成员时 |
| `view_global_variable_definition(project_id, global_variable_name)` | 变量是 `g_` 开头或明显是全局变量时 |
| `submit_result(result_id, confirmed, severity, description, ai_analysis)` | **审计完成后必须调用一次** |

**调用链追踪上限：向上 2 层。** 超过则在分析中标记信息不足。

**注意：** `project_id` 和 `result_id` 由 prompt 提供，原样传入即可。

---

## Workflow

### 第 1 步：获取函数代码

调用 `view_function_code(project_id, function_name)`。通读函数体，建立整体理解：参数、局部变量、
涉及的结构体、循环结构、函数内调用了哪些其他函数。

### 第 2 步：六场景初筛（只扫描登记，不深度分析）

按下表关键字遍历函数体，把每一处可疑位置登记为**候选风险点**，并标注所属场景：

| 场景 | 扫描关键字 |
|------|-----------|
| S1 | `memcpy_s`、`memmove_s`、`memset_s`、`strcpy_s`、`strncpy_s`、`strcat_s`、`strncat_s`、`sprintf_s`、`snprintf_s`、`vsprintf_s`、`vsnprintf_s`、`wcscpy_s`、`wcsncpy_s`、`wcscat_s`，以及 `VOS_*` / `_sp` / `_safe` 等含 destSize 参数的内部等价函数 |
| S2 | 参与 `malloc` / `new` / 拷贝长度 / 数组下标 / 循环边界 / 指针偏移计算的**算术表达式**，特别是：减法、乘法、左移、`(unsigned)有符号变量`、`(小类型)大类型`、对有符号变量取负 |
| S3 | `for` / `while` / `do-while` 循环，且循环体内存在缓冲区写入（`memcpy*`、`arr[i] = ...`、`*p = ...`、指针推进 `p += ...`） |
| S4 | `read`、`recv`、`recvfrom`、`recvmsg`、`fread`、`fgets`、`gets`、`ReadFile`、`scanf("%s"/"%[]"...)`，以及无边界输出 `puts(p)`、`printf("%s", p)` |
| S5 | `arr[expr]`、`ptr[expr]`、`*(ptr + expr)`，且 `expr` 不是明显在范围内的常量 |
| S6 | `printf` 系列且**格式化串是变量**，或 `j += snprintf(...)` 形式的返回值累加 |

**初筛无任何命中** → 直接跳到第 4 步以"clean"结论调用 `submit_result`。

### 第 3 步：按需加载参考文件并逐点深度分析

对第 2 步登记的每个不同场景，读取对应的 `references/<场景>.md`。
每个参考文件包含：漏洞原理、审计流程、豁免规则、判定标准、输出模板。

**同一场景命中多个候选点**：参考文件只需加载一次，复用其规则分析所有候选点。

对每个登记的候选点，按对应参考文件的流程执行：

1. **识别关键变量**（dest、destSize、下标、循环上界、格式化串等）
2. **追踪变量来源**（局部 / 结构体成员 / 全局 / 函数参数 / 动态分配 / 外部输入）
3. **确定边界**（缓冲区实际大小、变量取值范围）
4. **检查现有校验**（运算/访问前是否有范围校验？）
5. **应用豁免规则**（参考文件中列出的）
6. **作出判定**——除非能证明安全，否则标记为风险点

按需调用 MCP 工具补充信息。**调用链追踪不超过 2 层**。

### 第 4 步：汇总结果并调用 submit_result

将所有风险点的分析结果汇总，调用一次 `submit_result`：

**参数说明：**

| 参数 | 取值规则 |
|------|---------|
| `result_id` | prompt 中提供的 result_id，原样传入 |
| `confirmed` | 存在任何一个确认或疑似风险点时为 `true`；全部安全时为 `false` |
| `severity` | 按最严重的风险点取值：外部输入可控的越界为 `"high"`，内部逻辑缺陷为 `"medium"`，边界情况为 `"low"` |
| `description` | 一句话摘要，例如 `"函数 XXX 存在 S1 安全内存函数误用和 S2 整数溢出风险"` |
| `ai_analysis` | 所有风险点的结构化分析，格式见下方模板 |

### 第 5 步：结束对话

`submit_result` 之后**不要输出任何文字**。不要总结、不要点评、不要复述。

---

## ai_analysis 输出格式

每个风险点按以下模板输出，多个风险点依次排列，用空行分隔：


```
=== 风险点 1 ===
场景：S<编号> <场景名>
代码：<命中的代码行或表达式>
关键变量：<dest / 下标 / 长度 / 格式化串>，来源：<局部 | 结构体 | 全局 | 参数 | 外部输入>，大小/范围：<具体值或"不可控">
校验情况：<现有校验描述，或"未发现校验">
判定：<具体判定依据，说明为什么越界或为什么安全>
修复建议：<具体修复方式>

=== 风险点 2 ===
...
```



### 判定矩阵

| 情况 | confirmed |
|------|-----------|
| 能证明存在越界路径 | `true` |
| 无法证明安全 | `true` |
| 命中豁免规则 / 所有边界可证明 | `false` |
| 信息不足（追踪 2 层后仍无法确定） | `false`，在 ai_analysis 中说明缺什么 |
| 函数无任何初筛命中 | `false` |

### Clean-function（无风险）ai_analysis 模板


```
场景：N/A
代码：N/A
关键变量：N/A
校验情况：函数经六场景初筛未发现潜在越界读写风险点。
判定：该函数未发现越界读写风险。
修复建议：N/A
```


---

## 跨场景级联

一处代码可能命中多个场景，处理规则：

- **根因级联（S2 → S1/S3/S4/S5）**：整数溢出污染长度或下标，进而被其他场景使用。
  按**根因（S2）**记录，在分析中点出下游被污染的位置。
  例：`"S2 下溢导致 S1 memcpy_s 越界"`。
- **共生场景（S3 + S5）**：循环中的数组下标越界。按 S3 记录，提及下标变量。
- **同一行多个独立根因**：分别记录为不同的风险点。

---

## 关键约束

- **一次对话只审计一个函数**。函数内多个风险点都要覆盖，在 ai_analysis 中逐一列出。
- **不要只阅读提供的函数，如果判断是否越界需要其它函数、变量、调用链信息，通过MCP工具获得所需信息**。
- **每个函数必须调用一次 `submit_result`**。无风险函数也要调用（用 clean 模板）。
- **禁止编造代码或大小**。工具调用失败时如实标注，标记 `confirmed=false` 并说明信息不足。
- **不要预加载参考文件**。只加载初筛命中的场景。
- **`submit_result` 后立即结束对话**，不要追加任何文字。
- 外部输入来源包括：网络报文字段、文件内容、IPC 消息、用户输入、对外函数的参数（调用方不在本代码仓时）。
