# OpenCode 公共任务接口

OpenDeepHole 中所有模型任务统一调用 `backend.opencode.run_opencode_task()`。业务组件不直接启动 CLI，不访问任务队列，也不自行创建、查询、取消或删除 OpenCode Session。

> 模型任务只使用 OpenCode/nga serve 与 OpenCode Session，没有 LLM API 降级路径。

## 唯一调用接口

```python
from backend.opencode import OpenCodeTaskType, run_opencode_task


result = await run_opencode_task(
    task_name="候选点审计 NPD",
    task_type=OpenCodeTaskType.CANDIDATE_AUDIT,
    prompt="使用 `npd` 技能审计指定候选点，并输出 JSON。",
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    session_id=None,
)
```

参数只有以下七个：

| 参数 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 逻辑任务名及新 Session 标题 |
| `task_type` | `OpenCodeTaskType` | 必填 | 受控任务类型，用于选择内部策略和看板元数据 |
| `prompt` | `str` | 必填 | 本次发送给模型的提示词 |
| `required_capability` | `"low" \| "high"` | 必填 | 此次任务需要的模型能力；调用值是最终权威值 |
| `output_schema` | `dict \| None` | `None` | 最终普通文本 JSON 必须匹配的 JSON Schema |
| `invalid_json_retry_count` | `int` | `2` | JSON 非法时在原 Session 追加纠正提示的次数 |
| `session_id` | `str \| None` | `None` | 为空时创建 Session；非空时续写已有 Session |

不再接受 `directory`、workspace、timeout、priority、attempt、MCP、SKILL、permission、writable paths、回调、取消句柄或 CLI 配置等参数。它们由 Agent 执行上下文和内部任务策略统一提供。

`task_type` 必须使用 `OpenCodeTaskType` 枚举。当前细分类型包括候选点审计、项目审计、敏感信息清理、报告审计、威胁分析、威胁审计、去误报、漏洞验证、Git 历史、同类变体排查、内存 API 识别和 SKILL 创建。

任务策略页只配置 `low`、`high` 两档。旧配置中的 `any` 自动迁移为 `low`，`medium` 自动迁移为 `high`。模型池中的单个模型仍可标记为 `low`、`medium` 或 `high`，调度器会选择满足任务要求的最低可用能力。

## 返回值

接口只返回以下字段：

| 字段 | 含义 |
| --- | --- |
| `session_id` | 最终实际使用的 Session ID |
| `status` | 仅为 `success`、`failure` 或 `timeout` |
| `text` | 成功时为最终模型文本；失败或超时时为可直接展示的原因 |
| `structured` | 匹配 `output_schema` 的解析值；未传 Schema 或未成功时固定为 `None` |
| `model` | 最终实际响应的 `provider/model` |

```python
if result.status == "success":
    payload = result.structured
else:
    raise RuntimeError(result.text)
```

公共结果中没有 `cancelled`。主动取消会传播 `asyncio.CancelledError`，不会生成一个还需要业务方继续处理的取消结果。

## 目录与权限

Agent 在扫描、去误报、漏洞验证或其它组件的执行边界绑定运行上下文：

- `project_dir`：真实项目目录，只允许 `read`、`list`、`glob`、`grep`。
- `work_dir`：当前任务所属的 `.opendeephole` 隔离工作目录，允许文件编辑工具写入。
- `scan_id`、任务元数据、输出回调和取消事件：由编排层绑定并在异步任务树中自动继承。

没有绑定 `project_dir` 或 `work_dir` 时，调用会立即失败，不会回退到进程当前目录。

每次创建或续写 Session 时，内部服务都会覆盖 Session 权限：

- 允许读取项目目录、当前工作目录和全局 OpenCode workspace。
- 先拒绝所有 `edit`，再只允许当前 `work_dir` 及其子路径。
- 拒绝所有 `bash`，避免通过 shell 绕过项目只读和工作目录写边界。
- 允许加载全局注册的 SKILL；MCP 可见性继续由受管配置决定。

权限是内部实现细节，组件和 validator 不传 `permission`。威胁分析子 Agent 的 `edit` 工具保持启用，以便继承当前 Session 对 `work_dir` 的动态允许规则；其 `bash` 仍禁用。

## JSON 自动纠正和新 Session 重试

只有传入 `output_schema` 时才解析结构化结果。服务不使用 OpenCode 原生 `format=json_schema`，而是把中文 JSON 输出约束和完整 Schema 追加到首次用户 prompt 末尾，再解析普通 assistant 文本；Schema 不再写入 system prompt。任务队列和历史记录保存的也是实际发送的完整用户 prompt 及其长度。

若输出不是符合 Schema 的 JSON，服务会在原 Session 自动追加中文纠正提示，重复 Schema 并要求只输出合法 JSON。最多追加 `invalid_json_retry_count` 次；这些纠正消息复用同一 Session、同一模型 Lease，不重新排队。任务服务自动注入的 JSON、CodeGraph 范围及扫描反馈引导均使用中文，调用方传入的业务 prompt 保持原样。

若同 Session 纠正耗尽，内部服务会按对应任务策略的 `max_retries` 释放 Lease、重新排队并创建全新 Session。普通非超时执行错误也使用相同的新 Session 重试策略。业务方不再传 `attempt`。

超时、主动取消和没有可用模型是终止结果，不创建新的重试 Session：

- 超时返回 `status="timeout"`，原因位于 `text`。
- 最终失败返回 `status="failure"`，原因位于 `text`。
- 主动取消传播 `asyncio.CancelledError`，并停止排队、当前请求、JSON 纠正及后续新 Session 重试。

## Session 续写

将上次返回的 `session_id` 传回同一接口即可续写：

```python
continued = await run_opencode_task(
    task_name="候选点审计补充证据",
    task_type=OpenCodeTaskType.CANDIDATE_AUDIT,
    prompt="基于已有上下文补充证据并重新输出 JSON。",
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    session_id=result.session_id,
)
```

续写约束：

- 同一 Session 的 `project_dir` 和 `work_dir` 都不能改变。
- 同一 Session 的消息在 Agent 进程内串行执行。
- 正常完成后 Session 保留，供后续续写和 OpenCode 历史查看。
- 若续写执行或 JSON 纠正最终需要新 Session 重试，返回值中的 `session_id` 是最后的权威 Session ID。

## 并发调用

独立任务可直接用 `asyncio.gather()` 并发；它们各自创建 Session，并受同一个模型池限制：

```python
code_result, exploit_result = await asyncio.gather(
    run_opencode_task(
        task_name="代码可达性分析",
        task_type=OpenCodeTaskType.VULNERABILITY_VALIDATION,
        prompt=code_prompt,
        required_capability="high",
        output_schema=CODE_SCHEMA,
    ),
    run_opencode_task(
        task_name="利用条件分析",
        task_type=OpenCodeTaskType.VULNERABILITY_VALIDATION,
        prompt=exploit_prompt,
        required_capability="high",
        output_schema=EXPLOIT_SCHEMA,
    ),
)
```

不要并发续写同一个 `session_id`；按顺序 `await`，以保持消息顺序明确。

## Validator 约定

validator 直接导入公共接口；验证运行时已经绑定项目目录、漏洞工作目录、输出回调和取消事件：

```python
from backend.opencode import OpenCodeTaskType, run_opencode_task


result = await run_opencode_task(
    task_name="PoC 设计",
    task_type=OpenCodeTaskType.VULNERABILITY_VALIDATION,
    prompt=kwargs["report_markdown"],
    required_capability=kwargs["required_capability"],
    output_schema=RESULT_SCHEMA,
)
```

validator 不创建 OpenCode workspace、MCP Server 或 CLI 子进程，也不直接执行 `nga`、`opencode`、`hac` 或 `claude`。OpenCode 流只进入 Agent/调试控制台；需要在验证页面展示的内容应显式调用 `await kwargs["emit_stdout"](...)`。

## 内部职责

- `backend/opencode/api.py`：唯一公共调用与精简结果契约。
- `backend/opencode/task_service.py`：内部队列、模型调度、权限、Session、JSON 纠正和重试。
- `backend/opencode/model_pool.py`：模型 Lease、全局并发、能力匹配、时间窗和统计。
- `backend/opencode/serve_client.py`：Serve 生命周期、Session API、事件与消息流。
- `backend/opencode/config.py`：Agent 全局 workspace、SKILL、MCP 与基础拒绝权限。

业务代码只能从 `backend.opencode` 导入公共类型和函数，不应直接依赖 `task_service.py` 中的内部任务记录、句柄或 Session 管理方法。
