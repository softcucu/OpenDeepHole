# Task Agent 组件

`task_agent` 是供 OpenDeepHole Agent 使用的、自包含任务管理框架。它负责驱动 OpenCode/nga Serve，并管理延迟初始化的 Serve 单例、任务队列、模型租约、会话续接、权限、重试、事件流和 JSON 结果校验；它本身不实现 OpenCode，也不提供或启动单独的 CLI，模型任务仍通过现有的 `opencode serve` 或 `nga serve` 进程运行。

该目录本身就是顶层 Python 包。在源码项目中可以直接把整个 `task_agent/` 放到项目根目录；也可以从其父目录执行 `python -m pip install ./task_agent`，安装后调用代码放在任何目录都继续使用同一个公开包名。

应用的各个阶段仅使用公开任务 API。`run_opencode_task()` 的所有参数都必须按关键字传入：

```python
from task_agent import run_opencode_task

result = await run_opencode_task(
    task_name="candidate audit",
    task_type="audit",
    prompt="...",
    required_capability="high",
    output_schema=None,
    invalid_json_retry_count=2,
    session_id=None,
    config_path=None,
)
```

## 调用参数

| 参数 | 类型 | 必填/默认值 | 说明 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 任务名称，去除首尾空白后不能为空。它会用于队列记录、日志和 Serve 会话标题。 |
| `task_type` | `str` | 必填 | 任务类型，用于选择对应的模型策略、调度优先级和超时配置；仅接受下文列出的值。 |
| `prompt` | `str` | 必填 | 发送给模型的任务提示词，不能是空字符串或只包含空白。设置 `output_schema` 后，组件会自动在提示词末尾附加 JSON 输出要求。 |
| `required_capability` | `Literal["low", "high"]` | 必填 | 模型池所需的能力等级，只接受 `low` 或 `high`。 |
| `output_schema` | `dict[str, Any]` 或 `None` | `None` | 可选的 JSON Schema。传入后，组件会解析并校验模型返回的纯文本 JSON，将结果写入 `result.structured`；不传时 `result.structured` 为 `None`。 |
| `invalid_json_retry_count` | `int` | `2` | 首次结果不符合 `output_schema` 时，在同一会话中要求模型修正 JSON 的最大次数，必须大于或等于 `0`。该参数不控制新会话重试次数。 |
| `session_id` | `str` 或 `None` | `None` | 传入已有 Serve 会话 ID 以续接会话；省略、传入 `None` 或空字符串时创建新会话。同一组件生命周期内，续接会话不能切换项目目录或可写工作目录。 |
| `config_path` | `str`、`PathLike[str]` 或 `None` | `None` | 独立运行时使用的 YAML 配置文件路径。未传入时依次读取 `TASK_AGENT_CONFIG` 和当前目录下的 `task-agent.yaml`。宿主配置已注册时不能再传入此参数。 |

`task_type` 是文档约定的字符串，而不是导出的枚举。支持的值包括 `audit`、`project_audit`、`sensitive_clear`、`report_audit`、`threat_analysis`、`threat_audit`、`fp_review`、`vulnerability_validation`、`git_history`、`variant_hunt`、`memory_api_discovery` 和 `skill_create`；未知值会在提交前被拒绝。

嵌入 OpenDeepHole 时，宿主会在启动期间注册一次 `OpenCodeHostBindings`。注册过程会提供后端配置、共享工作区、解析后的 Serve 进程设置以及可选的 MCP 选择；它不会实例化管理器或启动 Serve。首次调用 `run_opencode_task()` 时，系统会按需创建共享任务服务和 Serve 管理器。在发送提示词之前，该管理器会在 Serve 尚未运行时启动它、复用兼容的进程，或执行既有的重启与恢复逻辑。

未注册宿主时，同一函数会从组件自有的 YAML 文件完成初始化。可以传入 `config_path=...`、设置 `TASK_AGENT_CONFIG`，或将 `task-agent.yaml` 放在当前目录中。请复制 `task-agent.example.yaml` 作为起点。在单例的整个生命周期内，该配置会固定项目、可写工作目录、组件工作区、Serve 进程设置和显式模型池。只有执行 `await shutdown_opencode()` 后才能选择其他配置。

OpenCode 的原生配置放在 `serve.opencode_config` 下，其中 MCP 配置使用 `serve.opencode_config.mcp`。示例文件同时给出了 `type: remote` 的 HTTP MCP 和 `type: local` 的进程 MCP；两项默认关闭，配置好 URL、请求头或启动命令后再将对应的 `enabled` 改为 `true`。MCP 的 `timeout` 单位为毫秒。

独立运行时，组件默认将任务排队、模型选择、Serve 启动或复用、Session 状态、工具数量、step、reasoning、文本、JSON 修正和最终状态实时打印到终端并立即刷新。`vulnerability_validation` 使用 `[validation/opencode]` 前缀，其它任务使用 `[<task_type>/opencode]`；宿主模式仍只使用宿主绑定的输出回调，不会额外重复打印。

`serve.timeout` 是一次模型请求的总超时。模型 Provider 无法连接时，OpenCode 自身的 `busy`、`retry` 和 `error` 会出现在上述实时输出中；达到总超时或调用被取消后，组件会 abort 当前 Session 请求并回收请求与事件任务。若模型服务需要代理，请在 `serve.environment` 中同时配置实际环境要求的大小写代理变量和 `NO_PROXY`/`no_proxy`，不要依赖另一个应用进程已经加载的环境。

此目录不会从 OpenDeepHole 的 `agent`、`backend`、`mcp_server` 或 `code_parser` 包中导入任何内容。如需提取给其它平台，请复制整个目录并将其放到平台的 Python 导入根目录，或直接安装该目录；依赖会由包元数据安装。随后提供 `task-agent.yaml`，并让所有调用点继续使用上文所示的公开导入方式。已有自身配置系统的应用也可以改为注册 `OpenCodeHostBindings`；宿主绑定的优先级始终高于独立配置文件发现机制。
