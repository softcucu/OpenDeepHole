---
name: safe-mem-oob-analysis
description: 验证安全内存函数 dst/dstsz 不匹配导致的越界写候选漏洞
---

# 安全内存函数越界验证

你正在验证一个由 semgrep 静态规则发现的 C/C++ 安全内存函数候选漏洞。目标是判断 `memcpy_s`、`memmove_s`、`memset_s`、`strcpy_s`、`strncpy_s`、`strcat_s`、`strncat_s` 及项目内等价安全函数中，`dst` 与 `dstsz` 是否明显不匹配，导致安全函数的容量参数大于真实可写空间。

## 背景

静态规则只召回高风险形态，不做白名单后处理。候选通常属于以下场景：

- 成员目标使用父对象大小：`memcpy_s(msg.payload, sizeof(msg), src, len)`
- 成员地址使用完整对象大小：`memcpy_s(&obj.field, sizeof(CLASS), src, len)`
- 偏移目标仍使用完整大小：`memcpy_s(buf + off, sizeof(buf), src, len)`
- 成员偏移仍使用完整成员大小：`memcpy_s(msg.payload + off, sizeof(msg.payload), src, len)`
- 指针变量使用 `sizeof(ptr)`：`memcpy_s(buf, sizeof(buf), src, len)`，其中 `buf` 是指针
- `dstsz` 与拷贝长度完全相同，且该表达式更像源长度或输入长度：`memcpy_s(dst, packet_len, src, packet_len)`
- 字符串安全函数中出现同类容量错误：`strcpy_s(msg.name, sizeof(msg), src)`、`strncpy_s(buf + off, sizeof(buf), src, n)`
- `memset_s` 的 `dst, dstsz, value, count` 中存在同类误用

安全函数在 `count > dstsz` 时通常会失败返回，但如果 `dstsz` 本身大于真实剩余空间，安全函数可能认为容量足够而向 `dst` 后方越界写。你的重点是验证 `dstsz` 是否大于真实可写空间，而不是只看 `count` 是否大于 `dstsz`。

## 可用工具

- `view_function_code(project_id, function_name, file_path)` - 查看函数完整源码。若 candidate 中函数名为 `unknown`，优先根据候选文件和行号定位上下文，或尝试使用文件路径约束查看同文件相关函数。
- `view_struct_code(project_id, struct_name)` - 查看结构体或类定义，确认成员大小和布局。
- `submit_result(result_id, confirmed, severity, description, ai_analysis)` - 提交最终结论，必须调用。

## 分析步骤

### Step 1 - 获取完整上下文

先查看 candidate 所在函数源码。candidate 描述中的匹配行不足以判断真实容量，必须结合局部声明、结构体定义、参数来源和返回值处理。

若函数名是 `unknown`，不要直接放弃；根据 candidate 的文件、行号和匹配代码，在同文件上下文中定位该调用。

### Step 2 - 识别参数语义

对命中调用拆分参数：

- `memcpy_s` / `memmove_s` / `memcpy_sp` / `*_Safe`：通常为 `dst, dstsz, src, count`
- `strcpy_s` / `strcat_s` / `wcscpy_s` / `wcscat_s`：通常为 `dst, dstsz, src`
- `strncpy_s` / `strncat_s` / `wcsncpy_s` / `wcsncat_s`：通常为 `dst, dstsz, src, count`
- `memset_s`：通常为 `dst, dstsz, value, count`

确认本项目封装函数的参数顺序是否一致。如果封装函数参数顺序不同，且无法证明该规则适用，应判为误报。

### Step 3 - 计算真实可写空间

按 `dst` 形态判断真实剩余空间：

- `buf + off` / `&buf[i]`：真实剩余空间是 `sizeof(buf) - off` 或 `sizeof(buf) - i`
- `obj.field` / `ptr->field`：真实空间是该成员本体大小，不是父对象大小
- `obj.field + off` / `&obj.field[i]`：真实剩余空间是 `sizeof(field) - off`
- `(char *)obj + off`：真实剩余空间取决于对象大小和 offset，不能直接相信完整对象大小
- 指针 `p`：`sizeof(p)` 是指针宽度，不是分配容量
- 若 `dstsz == count`，判断这个表达式语义上是源长度、包长、消息长度，还是目标容量。源长度不能直接作为目标容量，除非调用方能证明源和目标容量相等。

必要时调用 `view_struct_code` 查看成员定义，或追踪调用方确认指针实际指向的缓冲区。

### Step 4 - 验证可达性和影响

重点确认：

- `count` 是否可能大于真实剩余空间
- `off` / `i` / `count` 是否来自外部输入、协议字段、文件、网络或用户可控参数
- 调用前是否存在等价校验，例如 `off <= sizeof(buf)` 且 `count <= sizeof(buf) - off`
- 安全函数返回值是否被检查。若 `dstsz` 偏小只会导致失败返回，且返回值被正确处理，通常不是 OOB 写
- 若返回值未检查，失败后继续使用目标缓冲区，可能是逻辑缺陷，但不要误判成越界写，除非 `dstsz` 大于真实空间
- 对 `dstsz == count` 的候选，不要只因两者相等就确认漏洞；必须确认该长度可能超过目标真实容量，或缺少目标容量约束。
- 对字符串函数，额外确认目标缓冲区是否能容纳结尾 `\0`；`strncpy_s` / `strncat_s` 的 `count` 不等同于目标总容量。

### Step 5 - 判定

判为真实漏洞的条件：

- `dst` 不是完整对象或完整缓冲区起点，或 `dst` 是成员/偏移/子数组
- `dstsz` 大于该 `dst` 的真实可写剩余空间
- `count` 在可达路径上可能超过真实剩余空间
- 缺少等价边界校验或校验不覆盖所有路径

判为误报的常见情况：

- 项目封装函数参数顺序与规则假设不一致
- 调用前已经严格保证 `count <= 真实剩余空间`
- `off` 恒为 0，或被严格约束到不会减少剩余空间
- `dstsz` 虽然写法可疑，但实际小于真实空间，只会让安全函数失败且返回值被正确处理
- `dstsz == count` 但该表达式明确是目标容量，例如 `dst_len`，且调用方保证 `count <= dst_len`
- 代码位于测试、mock、stub 或不可达分支

## 严重程度

- `high`：外部输入可控制 `off` / `count` / 长度字段，可导致越界写
- `medium`：需要特定内部状态或配置触发，但真实容量不匹配成立
- `low`：触发条件苛刻，或主要是未检查安全函数失败返回造成的后续逻辑风险

## 提交结果

分析完成后必须调用 `submit_result`：

- `confirmed`: true 表示确认漏洞，false 表示误报
- `severity`: `"high"` / `"medium"` / `"low"`
- `description`: 一句话说明问题
- `ai_analysis`: 写清楚 `dst`、真实可写空间、`dstsz`、`count` 来源、边界校验和最终判定理由
