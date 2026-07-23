# Task Agent 组件

`task_agent` 是供 OpenDeepHole Agent 使用的、自包含任务管理框架。它负责驱动 OpenCode/nga Serve，并管理延迟初始化的 Serve 单例、任务队列、模型租约、会话续接、权限、重试、事件流和 JSON 结果校验；它本身不实现 OpenCode，也不提供或启动单独的 CLI，模型任务仍通过现有的 `opencode serve` 或 `nga serve` 进程运行。

该目录本身就是顶层 Python 包。在源码项目中可以直接把整个 `task_agent/` 放到项目根目录；也可以从其父目录执行 `python -m pip install ./task_agent`，安装后调用代码放在任何目录都继续使用同一个公开包名。

应用的各个阶段仅使用公开任务 API。`run_opencode_task()` 的所有参数都必须按关键字传入：

```python
import json

from task_agent import run_opencode_task

RESULT_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}
prompt = (
    "审计目标代码并给出结论。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON，不要附加解释：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)
retry_prompt = (
    "上一次回复不符合要求，请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="candidate audit",
    task_type="audit",
    prompt=prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    invalid_json_retry_prompt=retry_prompt,
    session_id=None,
    config_path=None,
    output=None,
    cancel_event=None,
)
```

## 调用参数

| 参数 | 类型 | 必填/默认值 | 说明 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 任务名称，去除首尾空白后不能为空。它会用于队列记录、日志和 Serve 会话标题。 |
| `task_type` | `str` | 必填 | 任务类型，用于选择对应的模型策略、调度优先级和超时配置；仅接受下文列出的值。 |
| `prompt` | `str` | 必填 | 发送给模型的任务提示词，不能是空字符串或只包含空白。组件会原样发送该字符串，不会因 `output_schema` 自动追加或改写内容。 |
| `required_capability` | `Literal["low", "high"]` | 必填 | 模型池所需的能力等级，只接受 `low` 或 `high`。 |
| `output_schema` | `dict[str, Any]` 或 `None` | `None` | 可选的 JSON Schema。传入后，组件会解析并校验模型返回的纯文本 JSON，将结果写入 `result.structured`；它不会修改首次 `prompt`。不传时 `result.structured` 为 `None`。 |
| `invalid_json_retry_count` | `int` | `2` | 首次结果不符合 `output_schema` 时，在同一会话中要求模型修正 JSON 的最大次数，必须大于或等于 `0`。该参数不控制新会话重试次数。 |
| `invalid_json_retry_prompt` | `str` 或 `None` | `None` | JSON 校验失败后的可选纠正提示词。传入非空字符串时，每次纠错都原样重复发送；`None` 使用组件当前包含完整 Schema 的中文默认提示词。 |
| `session_id` | `str` 或 `None` | `None` | 传入已有 Serve 会话 ID 以续接会话；省略、传入 `None` 或空字符串时创建新会话。同一组件生命周期内，续接会话不能切换项目目录或可写工作目录。 |
| `config_path` | `str`、`PathLike[str]` 或 `None` | `None` | 独立运行时使用的 YAML 配置文件路径。未传入时依次读取 `TASK_AGENT_CONFIG` 和当前目录下的 `task-agent.yaml`。宿主配置已注册时不能再传入此参数。 |
| `output` | callable 或 `None` | 使用当前执行上下文 | 可选的本次调用输出覆盖；传 `None` 可关闭 Task Agent 控制台流。 |
| `cancel_event` | 提供 `is_set()` 的对象 | 使用当前执行上下文 | 可选的本次调用取消信号覆盖。 |

返回的 `OpenCodeResult` 包含 `session_id`、`status`、`text`、`structured`、`model` 和可直接 JSON 序列化的 `output_source`。

已有业务实现若提供同步入口，不需要为了接入平台改成异步，也不要在同步代码里感知宿主事件
循环。外层异步门面使用 `await run_sync_component(sync_entry, **kwargs)` 即可；该桥会在独立
线程执行同步入口，并把入口内部对 `run_opencode_task()` 的调用调度回门面所属事件循环。这样
平台公开入口仍统一为 `async`，原实现及其同步任务提交器可以保持不变。

过程门面还可以通过 `opencode_task_context(..., config_path=..., skill_paths=[...])` 绑定独立
配置和过程私有 SKILL 根。绑定值会被内部 `run_opencode_task()` 继承，SKILL 路径仅合并到该
任务的 Serve 配置，不会写入 Agent 全局工作区。

`output_schema` 只定义本地解析和校验规则。需要模型首次就按 Schema 输出时，调用方必须像上例一样把要求和 Schema 明确写入 `prompt`。自定义 `invalid_json_retry_prompt` 也不会被组件追加 Schema、重试序号或其它文字；若省略该参数，组件才会使用当前内置的中文纠错提示词。显式传入空字符串、纯空白或非字符串会在提交任务前报错。

`task_type` 是文档约定的字符串，而不是导出的枚举。支持的值包括 `audit`、`project_audit`、`sensitive_clear`、`report_audit`、`threat_analysis`、`threat_audit`、`fp_review`、`vulnerability_validation`、`git_history`、`variant_hunt`、`memory_api_discovery` 和 `skill_create`；未知值会在提交前被拒绝。

嵌入 OpenDeepHole 时，宿主会在启动期间注册一次 `OpenCodeHostBindings`。注册过程会提供后端配置、共享工作区、解析后的 Serve 进程设置以及可选的 MCP 选择；它不会实例化管理器或启动 Serve。首次调用 `run_opencode_task()` 时，系统会按需创建共享任务服务和 Serve 管理器。在发送提示词之前，该管理器会在 Serve 尚未运行时启动它、复用兼容的进程，或执行既有的重启与恢复逻辑。

未注册宿主时，同一函数会从组件自有的 YAML 文件完成初始化。可以传入 `config_path=...`、设置 `TASK_AGENT_CONFIG`，或将 `task-agent.yaml` 放在当前目录中。请复制 `task-agent.example.yaml` 作为起点。在单例的整个生命周期内，该配置会固定项目、可写工作目录、组件工作区、Serve 进程设置和显式模型池。只有执行 `await shutdown_opencode()` 后才能选择其他配置。

一次 `run_opencode_task()` 返回后不会立即关闭 Serve；只要 Python 宿主进程仍在运行，后续任务就会继续复用这个单例。调用 `await shutdown_opencode()` 会立即终止组件启动的 Serve 进程树。若调用方未显式 shutdown，组件也会在解释器正常退出以及收到 `SIGINT`（Ctrl-C）或 `SIGTERM` 时自动清理，并把信号继续交给宿主原有处理逻辑。`SIGKILL` 和 `os._exit()` 无法执行 Python 清理；这类异常退出由下次启动时的归属标记恢复逻辑处理。

OpenCode 的原生配置放在 `serve.opencode_config` 下，其中 MCP 配置使用 `serve.opencode_config.mcp`。示例文件同时给出了 `type: remote` 的 HTTP MCP 和 `type: local` 的进程 MCP；两项默认关闭，配置好 URL、请求头或启动命令后再将对应的 `enabled` 改为 `true`。MCP 的 `timeout` 单位为毫秒。

独立运行时，组件按 `[<stage>][<session_id>][task|session|step]` 打印结构化进度并立即刷新。`vulnerability_validation` 的 stage 固定为 `validation`，其它任务使用原始 `task_type`；Session 创建前使用 `pending`。`task` 记录排队、模型选择、Serve 和最终状态，`session` 明确标记当前消息执行的 `START`/`STOP`、重试及错误，`step` 记录工具、SKILL 和模型 step。模型 text、reasoning 及工具返回正文不写入控制台，但最终 text 仍正常返回并参与 JSON 解析。一次消息执行结束只打印 `STOP ... retained=true`，不会删除可续写的 Session。宿主模式仍只使用宿主绑定的输出回调，不会额外重复打印。

`serve.timeout` 是一次模型请求的总超时。模型 Provider 无法连接时，OpenCode 自身的 `busy`、`retry` 和 `error` 会出现在上述实时输出中；达到总超时或调用被取消后，组件会 abort 当前 Session 请求并回收请求与事件任务。若模型服务需要代理，请在 `serve.environment` 中同时配置实际环境要求的大小写代理变量和 `NO_PROXY`/`no_proxy`，不要依赖另一个应用进程已经加载的环境。

此目录不会从 OpenDeepHole 的 `deephole_client`、`backend` 或 `mcp_server` 包中导入任何内容。如需提取给其它平台，请复制整个目录并将其放到平台的 Python 导入根目录，或直接安装该目录；依赖会由包元数据安装。随后提供 `task-agent.yaml`，并让所有调用点继续使用上文所示的公开导入方式。已有自身配置系统的应用也可以改为注册 `OpenCodeHostBindings`；宿主绑定的优先级始终高于独立配置文件发现机制。
