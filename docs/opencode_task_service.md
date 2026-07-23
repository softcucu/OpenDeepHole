# Task Agent 公共任务接口

OpenDeepHole 中所有模型任务统一调用 `task_agent.run_opencode_task()`。业务组件不直接启动 CLI，不访问任务队列，也不自行创建、查询、取消或删除 OpenCode Session。

> 模型任务只使用 OpenCode/nga serve 与 OpenCode Session，没有 LLM API 降级路径。

Agent 启动时只注册一次 OpenDeepHole 的后端配置、workspace 与 MCP/SKILL 适配，不创建 Serve 进程。首次 `run_opencode_task()` 会惰性创建共享任务服务和 Serve 管理单例；组件在真正发送 prompt 前检查 Serve，按现有规则启动、复用兼容进程或恢复异常进程。没有后端宿主绑定时，公共函数改从组件自己的 YAML 配置自举，仍不存在额外的组件 CLI。

## 唯一调用接口

```python
import json

from task_agent import run_opencode_task

prompt = (
    "使用 `npd` 技能审计指定候选点。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)
retry_prompt = (
    "上一次回复不符合要求，请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="候选点审计 NPD",
    task_type="audit",
    prompt=prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    invalid_json_retry_prompt=retry_prompt,
    session_id=None,
    output=None,
    cancel_event=None,
)
```

参数只有以下十一个：

| 参数 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 逻辑任务名及新 Session 标题 |
| `task_type` | `str` | 必填 | 文档约束的任务类型字符串，用于选择内部策略和看板元数据 |
| `prompt` | `str` | 必填 | 本次原样发送给模型的提示词；服务不会根据 Schema 追加或改写内容 |
| `required_capability` | `"low" \| "high"` | 必填 | 此次任务需要的模型能力；调用值是最终权威值 |
| `output_schema` | `dict \| None` | `None` | 最终普通文本 JSON 必须匹配的 JSON Schema；只用于本地解析和校验 |
| `invalid_json_retry_count` | `int` | `2` | JSON 非法时在原 Session 追加纠正提示的次数 |
| `invalid_json_retry_prompt` | `str \| None` | `None` | 自定义 JSON 纠正提示词；非空字符串会原样重复发送，`None` 使用内置中文默认值 |
| `session_id` | `str \| None` | `None` | 为空时创建 Session；非空时续写已有 Session |
| `config_path` | `str \| PathLike \| None` | `None` | 仅独立模式使用的组件 YAML 路径；后端模式禁止覆盖宿主配置 |
| `output` | callable 或 `None` | 当前执行上下文 | 覆盖本次任务的流式输出回调；显式 `None` 表示关闭 |
| `cancel_event` | 提供 `is_set()` 的对象 | 当前执行上下文 | 覆盖本次任务的取消信号 |

不再接受 `directory`、workspace、timeout、priority、attempt、MCP、SKILL、permission、writable paths 或 CLI 配置对象等参数。后端模式由 Agent 执行上下文和内部任务策略统一提供；独立模式由 `config_path` 指向的组件配置统一提供。业务过程可通过 `output` 和 `cancel_event` 对单次调用做局部覆盖。

返回的 `OpenCodeResult.output_source` 是可 JSON 序列化的 dict，用于由客户端协调器原样上报实际模型和 Session 来源。

`task_type` 直接传字符串，不提供枚举。允许值如下；其它值会立即抛出 `ValueError`：

| 字符串 | 用途 |
| --- | --- |
| `audit` | 候选点审计 |
| `project_audit` | 项目级审计 |
| `sensitive_clear` | 敏感信息清理审计 |
| `report_audit` | Markdown 报告审计 |
| `threat_analysis` | 威胁分析 |
| `threat_audit` | 威胁路径审计 |
| `fp_review` | 去误报复核 |
| `vulnerability_validation` | 漏洞验证 |
| `git_history` | Git 历史分析 |
| `variant_hunt` | 同类变体排查 |
| `memory_api_discovery` | 内存 API 识别 |
| `skill_create` | SKILL 创建 |

任务策略页只配置 `low`、`high` 两档。旧配置中的 `any` 自动迁移为 `low`，`medium` 自动迁移为 `high`。模型池中的单个模型仍可标记为 `low`、`medium` 或 `high`，调度器会选择满足任务要求的最低可用能力。

## 独立组件配置

未注册 `OpenCodeHostBindings` 时，配置按以下顺序发现：

1. `run_opencode_task(config_path=...)`；
2. `TASK_AGENT_CONFIG` 环境变量；
3. 当前目录的 `task-agent.yaml`。

格式模板位于 `task_agent/task-agent.example.yaml`。下面的配置包含 Task Agent 自己识别的全部字段；除透传的 `serve.opencode_config` 和由调度器解析的 `time_windows` 项外，顶层、固定分区和模型行都是严格白名单，拼错或加入未知字段会在加载时直接报错：

```yaml
schema_version: 1

context:
  # OpenCode Session 的真实源码目录；该目录必须已经存在。
  project_dir: /absolute/path/to/source
  # 模型文件工具唯一允许写入的任务目录；不存在时自动创建。
  work_dir: /absolute/path/to/task-work
  # Serve 启动、opencode.json 和共享 Skill 所在的稳定组件目录。
  workspace_dir: /absolute/path/to/opencode-workspace

serve:
  # 支持 opencode 或 nga。
  tool: opencode
  # 可执行文件名或路径；省略时使用 tool 的值。
  executable: opencode
  port: 4096
  # 单次模型消息从开始执行到完成的默认超时，单位为秒，不包含排队时间。
  timeout: 1200
  # 普通执行错误或 JSON 纠正耗尽后，创建全新 Session 的重试次数。
  max_retries: 2
  # 传给 Serve 子进程的环境变量。值必须是标量，加载后统一转成字符串。
  environment:
    HTTPS_PROXY: http://127.0.0.1:7890
    NO_PROXY: 127.0.0.1,localhost

  # 这里是原样交给 OpenCode 的原生配置对象，不属于 Task Agent 固定 Schema。
  opencode_config:
    $schema: https://opencode.ai/config.json
    # 推荐将 standalone 共享 Skill 放在 workspace_dir 下，并显式注册绝对路径。
    skills:
      paths:
        - /absolute/path/to/opencode-workspace/.opencode/skills
    mcp:
      remote-example:
        type: remote
        url: http://127.0.0.1:9123/mcp
        enabled: false
        timeout: 30000
        oauth: false
        headers:
          Authorization: "Bearer replace-me"
      local-example:
        type: local
        command:
          - python3
          - -m
          - your_mcp_server
        environment:
          PROJECT_DIR: /absolute/path/to/source
        enabled: false
        timeout: 30000

model_pool:
  # 所有模型合计正在执行的任务数硬上限。
  global_concurrency: 2
  models:
    - id: deepseek-pro
      # OpenCode 使用的 provider/model；use_default_model=false 时必须非空。
      model: deepseek/deepseek-v4-pro
      use_default_model: false
      capability: high
      weight: 1
      max_concurrency: 2
      enabled: true
      # 以下四项均为模型行覆盖；省略时继承 serve 设置。
      tool: opencode
      executable: opencode
      timeout: 1200
      max_retries: 2
      # 使用运行 Task Agent 的机器本地时间；多段时间窗取并集。
      time_windows:
        - weekdays: [1, 2, 3, 4, 5]
          start: "09:00"
          end: "18:00"
```

### 顶层和目录参数

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `schema_version` | 必填，当前只能为 `1` | standalone YAML 的 Schema 版本；缺失或不是 `1` 会拒绝加载。 |
| `context` | 必填 | 固定本次 standalone 组件生命周期使用的目录上下文。 |
| `serve` | 必填 | Serve 进程、默认执行策略和原生 OpenCode 配置。 |
| `model_pool` | 必填 | 显式模型列表及全局调度上限。 |
| `context.project_dir` | 必填，必须是已有目录 | OpenCode Session 的 `directory`，也是真实源码根目录。模型可读取该目录，但 Task Agent 不允许文件编辑工具写入。 |
| `context.work_dir` | 必填，不存在时创建 | 本次独立组件固定的可写任务目录。模型生成的补丁、PoC、报告等任务产物应写在这里。 |
| `context.workspace_dir` | 必填，不存在时创建 | Serve 的稳定启动目录和组件 workspace。运行时会在这里生成 `opencode.json`，也适合保存共享 Skill；不要把每次任务的业务产物写在这里。 |

三个路径都支持 `~`。绝对路径直接使用；相对路径以 `task-agent.yaml` 所在目录为基准，而不是以启动 Python 的当前目录为基准。`project_dir` 必须预先存在；`work_dir` 和 `workspace_dir` 会自动递归创建。创建或续写 Session 后，模型可以读取这三个目录，文件编辑工具只能写 `work_dir`，`bash` 始终禁用。

`workspace_dir` 中生成的 `opencode.json` 包含 `serve.opencode_config` 的实际内容，可能带有 Provider Key、MCP Header 等敏感值；运行时在 POSIX 系统上以 `0600` 权限写入，但该目录仍应只对可信用户开放。

### Serve 参数

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `serve.tool` | 默认 `opencode` | Serve 实现，只能是 `opencode` 或 `nga`。 |
| `serve.executable` | 默认等于 `serve.tool` | 启动 Serve 的可执行文件名或路径。 |
| `serve.port` | 默认 `4096`，范围 `1..65535` | 本机 Serve 监听端口。该值会成为最终的 `OPENCODE_SERVE_PORT`，覆盖 `serve.environment` 中的同名值。 |
| `serve.timeout` | 默认 `1200`，最小 `1` | 默认单次模型消息执行超时，单位为秒；排队等待模型 Lease 的时间不计入。 |
| `serve.max_retries` | 默认 `2`，最小 `0` | 首次 Session 之外最多创建多少个全新 Session 进行重试；不等同于同 Session 的 JSON 纠正次数。 |
| `serve.environment` | 默认 `{}` | 附加或覆盖到 Serve 子进程的环境变量。键转为字符串，值必须是标量并会转为字符串；常用于代理或 Provider 环境变量。 |
| `serve.opencode_config` | 默认 `{}` | 必须是可 JSON 序列化的映射；运行时原样写入 `workspace_dir/opencode.json` 并交给 OpenCode。 |

`serve.opencode_config` 可以包含 OpenCode 当前版本支持的 `$schema`、Provider、Agent、MCP、Skill 等原生配置。Task Agent 不校验这些子字段，也不保证不同 OpenCode 版本的原生字段兼容；Session 的读写和 `bash` 权限仍由 Task Agent 在运行时收紧，不能依赖这里的 `permission` 放宽任务边界。

MCP 直接写在 `serve.opencode_config.mcp` 下。远程 MCP 通常使用 `type: remote`、`url`、`headers` 和 `oauth`；本地 MCP 使用 `type: local`、命令数组 `command` 以及可选的 `environment`。两种 MCP 的 `timeout` 都由 OpenCode 解释，单位为毫秒；这与 `serve.timeout` 的秒不同。

### Skill 放置和注册

单个 Skill 至少使用以下目录结构：

```text
<skill-root>/
└── my-skill/
    ├── SKILL.md
    ├── references/       # 可选
    ├── scripts/          # 可选
    └── assets/           # 可选
```

Skill 有两种常用放置方式：

1. 项目专用 Skill 放在 `<project_dir>/.opencode/skills/<skill-name>/SKILL.md`，由以 `project_dir` 为 Session 目录的 OpenCode 按项目发现。
2. 多个任务共享的 standalone Skill 推荐放在 `<workspace_dir>/.opencode/skills/<skill-name>/SKILL.md`，并将 `<workspace_dir>/.opencode/skills` 的绝对路径写入 `serve.opencode_config.skills.paths`。

standalone 加载器只负责创建 `workspace_dir`，不会自动创建、复制或注册任何 Skill，也不会把 `context.workspace_dir` 变量插值到 `skills.paths`。因此两处路径应手工保持一致，推荐都填写绝对路径。嵌入完整 OpenDeepHole Agent 时则由 `deephole_client/opencode_integration.py` 维护 Agent 全局 workspace、安装内置/checker Skill 并生成 `skills.paths`，不需要业务调用方重复处理。

### 模型池参数

`model_pool.models` 必须是列表，并且至少包含一个已启用且填写了 `model` 的模型，或者一个已启用且显式设置 `use_default_model: true` 的默认模型行。

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `model_pool.global_concurrency` | 默认 `1`，范围 `1..64` | 所有模型合计正在执行的任务数硬上限。 |
| `models[].id` | 默认取 `model`，默认模型行为 `default` | 模型池内部稳定标识，用于 Lease、日志和统计；不同模型行应使用不同 ID。 |
| `models[].model` | 条件必填 | OpenCode 的 `provider/model`。要让该行进入可调度模型池，当 `use_default_model` 为 `false` 时必须非空。 |
| `models[].use_default_model` | 默认 `false` | 为 `true` 时忽略 `model`，让 Serve 使用自己的默认模型。 |
| `models[].capability` | 默认 `high` | 模型能力，可为 `low`、`medium`、`high`。公共任务只请求 `low` 或 `high`；低能力任务优先选择满足条件的较低档模型，高能力任务只使用高档模型。 |
| `models[].weight` | 默认 `1`，最小 `0.01` | 多个可用且能力合适的模型之间的相对调度权重；值越大越容易获得后续 Lease，但不是严格百分比。 |
| `models[].max_concurrency` | 默认 `1`，最小 `1` | 该模型行允许同时持有的 Lease 数量。 |
| `models[].enabled` | 默认 `true` | 是否将该模型加入可调度模型池。 |
| `models[].tool` | 默认继承 `serve.tool` | 仅该模型使用的 Serve 实现，只能为空、`opencode` 或 `nga`。 |
| `models[].executable` | 默认继承 `serve.executable` | 仅该模型使用的可执行文件名或路径。 |
| `models[].timeout` | 默认继承 `serve.timeout`，最小 `1` | 该模型单次消息执行超时，单位为秒。 |
| `models[].max_retries` | 默认继承 `serve.max_retries`，最小 `0` | 该模型在首次获得 Lease 后采用的新 Session 重试次数。 |
| `models[].time_windows` | 默认 `[]` | 模型允许获得新 Lease 的本地时间窗口；空列表表示全天可用。 |

实际并发数同时受全局和模型行限制。对于当前满足能力、已启用且处于可用时间窗内的模型，可近似理解为：

```text
实际并发容量 = min(
    model_pool.global_concurrency,
    所有合格模型的 max_concurrency 之和,
)
```

例如全局并发为 `2`，但唯一高能力模型的 `max_concurrency` 为 `1` 时，两个 `high` 任务会同时进入队列，却仍然只能串行执行。要让它们同时运行，需要把该模型的 `max_concurrency` 提高到 `2`，或者再配置一个当前可用的高能力模型。

每个 `time_windows` 项支持以下字段：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `weekdays` | `[1, 2, 3, 4, 5, 6, 7]` | ISO 星期，`1` 为周一、`7` 为周日。 |
| `start` | 必填 | `HH:MM` 起始时间，包含该分钟。 |
| `end` | 必填 | `HH:MM` 结束时间，不包含该分钟；不能与 `start` 相同。 |

时间窗口使用运行 Task Agent 的机器本地时间，多段取并集。`start < end` 表示同日区间；`start > end` 表示跨夜区间，并按“当前日期的星期”判断。例如周一的 `22:00-06:00` 包含周一 `00:00-06:00` 和 `22:00-24:00`，不会自动把周二凌晨视作周一的延续。时间窗只限制新 Lease，不中断已经运行的任务。

`time_windows` 本身必须是映射列表，但每个窗口中的未知字段不会触发严格 Schema 错误；调度器只读取 `weekdays`、`start`、`end`。时间格式非法、星期为空或超出 `1..7`、起止时间相同的窗口会被忽略。如果一行模型的所有窗口都被忽略，最终等同于没有有效时间窗，该模型会全天可用，因此应特别检查拼写和时间格式。

### 配置校验和生命周期

- 顶层只允许 `schema_version`、`context`、`serve`、`model_pool`；`context`、`serve`、`model_pool.models[]` 也会拒绝未知字段。
- `project_dir` 不存在、模型列表不是数组、没有任何可用模型、端口或数值超出范围、环境变量值不是标量时，首次调用会立即失败。
- 首个独立调用会锁定配置路径，并在同一进程内复用同一个任务服务和 Serve 单例。同一路径可重复传入；若要切换 YAML，必须先执行 `await shutdown_opencode()`。
- 单个任务返回不会停止 Serve；这是同一 Python 进程内跨阶段、跨任务复用的基础。显式调用 `await shutdown_opencode()` 会终止组件实际启动的 Serve 进程树并清除单例。
- 未显式 shutdown 时，组件会登记自己通过 `Popen` 启动的精确 PID，在解释器正常退出、`SIGINT`（Ctrl-C）或 `SIGTERM` 时同步清理该进程树，再恢复或转交宿主原有信号处理器；退出清理不会根据端口终止未知进程，也只会删除 PID 仍匹配的归属标记。
- `SIGKILL` 和 `os._exit()` 不运行 Python 的信号处理器或 `atexit` 回调，无法保证当场清理；下次启动会继续使用既有归属标记和端口恢复逻辑回收残留 Serve。
- 若应用已经注册后端宿主绑定，则完全使用宿主配置，不读取独立 YAML；此时再传 `config_path` 会报冲突。

## 控制台日志

Task Agent 的进度行统一使用下面三个头字段：

```text
[<stage>][<session_id>][task|session|step] <event>
```

- `vulnerability_validation` 映射为 stage `validation`；其它任务直接使用 `task_type`。Session 尚未创建时第二段为 `pending`，创建或续写后改为真实 Session ID。
- 第三段只会是 `task`、`session` 或 `step`：`task` 覆盖排队、模型 Lease、Serve 准备和任务终态；`session` 覆盖当前消息执行的启动、停止、重试、错误及工具发现；`step` 覆盖工具、SKILL 和模型 step 生命周期。
- 每次消息执行都会打印 `session START` 和 `session STOP`。`STOP ... retained=true` 只表示本次消息已结束，Session 本身仍保留并可续写；超时和取消分别标记 `status=timeout`、`status=cancelled`。
- assistant text 和 reasoning 不打印到控制台，仍在内部聚合并作为最终 `text` 返回或用于 JSON 校验。工具调用只打印名称、脱敏参数和结果摘要，工具返回正文不打印；内置 `skill` 调用打印为 `SKILL START`/`SKILL STOP`。

独立模式直接把这些行打印到终端；宿主模式只交给宿主绑定的输出回调。宿主添加本地时间戳时会保留上述三个头字段，不再叠加旧的阶段或模型前缀。

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
- `config_path` 和 `skill_paths`：独立过程可绑定自己的 Task Agent YAML 与私有 SKILL 根；宿主任务未提供时继续使用公共运行配置。

后端模式没有绑定 `project_dir` 或 `work_dir` 时，调用会立即失败，不会回退到进程当前目录。独立模式始终使用 YAML 中固定的两个目录，因此 Session continuation 不会改变权限边界。

每次创建或续写 Session 时，内部服务都会覆盖 Session 权限：

- 允许读取项目目录、当前工作目录和全局 OpenCode workspace。
- 先拒绝所有 `edit`，再只允许当前 `work_dir` 及其子路径。
- 拒绝所有 `bash`，避免通过 shell 绕过项目只读和工作目录写边界。
- 允许加载全局注册的 SKILL，以及当前过程通过 `skill_paths` 绑定的私有 SKILL；MCP 可见性继续由受管配置决定。

权限是内部实现细节，组件和 validator 不传 `permission`。同步过程可以由异步门面通过 `run_sync_component()` 执行；同步实现内部调用 `run_opencode_task()` 时会回到门面所属事件循环，并继续继承同一目录、权限和私有 SKILL 上下文。

## JSON 自动纠正和新 Session 重试

只有传入 `output_schema` 时才解析结构化结果。服务不使用 OpenCode 原生 `format=json_schema`，也不再把 Schema 或任何输出要求追加到首次用户 prompt；调用方传入什么字符串，首次消息和任务队列历史就保存并发送什么字符串，`prompt_length` 也按该原文计算。需要模型首次就输出 JSON 时，调用方必须像上文示例一样显式组装最终 prompt。

若输出不是符合 Schema 的 JSON，服务会在原 Session 最多追加 `invalid_json_retry_count` 次纠正消息；这些消息复用同一 Session、同一模型 Lease，不重新排队。`invalid_json_retry_prompt=None` 时使用当前包含完整 Schema 的中文默认提示词；传入非空字符串时，每次都原样发送该字符串，不追加 Schema、重试序号或其它内容。空字符串、纯空白和非字符串会在提交任务前报错。未传 `output_schema` 或纠错次数为 `0` 时不会发送纠正消息。

若同 Session 纠正耗尽，内部服务会按对应任务策略的 `max_retries` 释放 Lease、重新排队并创建全新 Session。普通非超时执行错误也使用相同的新 Session 重试策略。业务方不再传 `attempt`。

超时、主动取消和没有可用模型是终止结果，不创建新的重试 Session：

- 超时返回 `status="timeout"`，原因位于 `text`。
- 最终失败返回 `status="failure"`，原因位于 `text`。
- 主动取消传播 `asyncio.CancelledError`，并停止排队、当前请求、JSON 纠正及后续新 Session 重试。

## Session 续写

将上次返回的 `session_id` 传回同一接口即可续写：

```python
follow_up_prompt = (
    "基于已有上下文补充证据并重新输出 JSON。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

continued = await run_opencode_task(
    task_name="候选点审计补充证据",
    task_type="audit",
    prompt=follow_up_prompt,
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
code_prompt += (
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(CODE_SCHEMA, ensure_ascii=False, indent=2)
)
exploit_prompt += (
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(EXPLOIT_SCHEMA, ensure_ascii=False, indent=2)
)

code_result, exploit_result = await asyncio.gather(
    run_opencode_task(
        task_name="代码可达性分析",
        task_type="vulnerability_validation",
        prompt=code_prompt,
        required_capability="high",
        output_schema=CODE_SCHEMA,
    ),
    run_opencode_task(
        task_name="利用条件分析",
        task_type="vulnerability_validation",
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
import json

from task_agent import run_opencode_task

prompt = (
    kwargs["report_markdown"]
    + "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="PoC 设计",
    task_type="vulnerability_validation",
    prompt=prompt,
    required_capability=kwargs["required_capability"],
    output_schema=RESULT_SCHEMA,
)
```

validator 不创建 OpenCode workspace、MCP Server 或 CLI 子进程，也不直接执行 `nga`、`opencode`、`hac` 或 `claude`。OpenCode 的结构化任务、Session、工具和 SKILL 进度只进入 Agent 控制台，模型 text/reasoning 不打印；需要在验证页面展示的内容应显式调用 `await kwargs["emit_stdout"](...)`。

## 内部职责

- `task_agent/api.py`：唯一公共调用与精简结果契约。
- `task_agent/task_service.py`：内部队列、模型调度、权限、Session、JSON 纠正和重试。
- `task_agent/model_pool.py`：模型 Lease、全局并发、能力匹配、时间窗和统计。
- `task_agent/serve_client.py`：Serve 生命周期、Session API、事件与消息流。
- `task_agent/host.py`：自包含组件与宿主之间的最小配置回调边界。
- `task_agent/standalone.py`：独立 YAML 的校验、发现、宿主适配和一次性自举。
- `deephole_client/opencode_integration.py`：OpenDeepHole 全局 workspace、SKILL、MCP 与运行配置适配。
- `deephole_client/<process>/`：OpenDeepHole 各业务过程的独立目录；过程只通过公开的 `run_opencode_task()` 调用 Task Agent。

`task_agent/` 内不导入 OpenDeepHole 的 `deephole_client`、`backend` 或 `mcp_server` 模块。单独复制该目录后，可以放到目标项目的 Python 导入根目录，或执行 `python -m pip install ./task_agent`；两种方式都使用 `from task_agent import run_opencode_task`，不因业务代码所在目录变化而改名。组件提供独立配置即可运行，也可由其它应用注册自己的 `OpenCodeHostBindings`。OpenDeepHole 业务阶段只能从 `task_agent` 导入公共类型和函数，不应直接依赖 `task_service.py` 中的内部任务记录、句柄或 Session 管理方法。
