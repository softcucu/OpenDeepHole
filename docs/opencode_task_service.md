# Task Agent 公共任务接口

DeepHole 2.0 中所有模型任务统一调用 `task_agent.run_opencode_task()`。业务组件不直接启动 CLI，不访问任务队列，也不自行创建、查询、取消或删除 OpenCode Session。

> 模型任务只使用 OpenCode 兼容 serve 与 OpenCode Session，没有 LLM API 降级路径。

Agent 启动时只注册一次 DeepHole 2.0 的后端配置、workspace 与 MCP/SKILL 适配，不创建 Serve 进程。首次 `run_opencode_task()` 会惰性创建共享任务服务和 Serve 管理单例；组件在真正发送 prompt 前检查 Serve，按现有规则启动、复用兼容进程或恢复异常进程。没有后端宿主绑定时，公共函数改从组件自己的 YAML 配置自举，仍不存在额外的组件 CLI。

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
    task_name="candidate-audit-npd",
    task_type="vulnerability_mining",
    prompt=prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    invalid_json_retry_prompt=retry_prompt,
    file_write_allowlist=None,
    writable_paths=None,
    readable_paths=None,
    allowed_bash_commands=None,
    required_bash_commands=None,
    bash_command_match_mode="exact",
    required_bash_retry_count=0,
    required_bash_success_markers=None,
    post_session_validator=None,
    post_session_validation_retry_count=0,
    session_id=None,
    config_path=None,
    output=None,
    cancel_event=None,
)
```

调用参数如下：

| 参数 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 逻辑任务名及新 Session 标题；模型看板也使用它识别漏洞挖掘的具体子任务 |
| `task_type` | `str` | 必填 | 文档约束的任务类型字符串，用于选择内部策略和看板元数据 |
| `prompt` | `str` | 必填 | 本次原样发送给模型的提示词；服务不会根据 Schema 追加或改写内容 |
| `required_capability` | `"low" \| "high"` | 必填 | 调用方声明的能力；嵌入 Agent 时，已分类阶段由 Web 阶段策略覆盖 |
| `output_schema` | `dict \| None` | `None` | 最终文本或本次消息所写文件中的 JSON 必须匹配的 JSON Schema；只用于本地解析和校验 |
| `invalid_json_retry_count` | `int` | `2` | JSON 非法时在原 Session 追加纠正提示的次数 |
| `invalid_json_retry_prompt` | `str \| None` | `None` | 自定义 JSON 纠正提示词；非空字符串会原样重复发送，`None` 使用内置中文默认值 |
| `file_write_allowlist` | 单个路径、路径序列或 `None` | `None` | 为本次 Session 额外开放写权限并默认保留的文件或目录；相对路径以 `project_dir` 为基准，绝对路径可位于项目外 |
| `writable_paths` | 单个路径、路径序列或 `None` | `None` | `file_write_allowlist` 的兼容别名；两者会合并为同一组可写和保留路径 |
| `readable_paths` | 单个路径、路径序列或 `None` | `None` | 保留的兼容参数，用于显式声明本次 Session 的只读路径意图；最终全局配置已允许读取全部本地路径，不授予编辑权限，也不改变保留规则 |
| `allowed_bash_commands` | 单个字符串、字符串序列或 `None` | `None` | 精确允许但不要求执行的完整 shell 命令；拒绝空值、换行与通配符，不参与完成审计 |
| `required_bash_commands` | 单个字符串、字符串序列或 `None` | `None` | 精确允许且必须成功执行的完整 shell 命令；拒绝空值、换行与通配符 |
| `bash_command_match_mode` | `"exact"` 或 `"bound_python_script"` | `"exact"` | 默认精确匹配；脚本模式识别 Python 对绑定脚本的直接调用后，将整条命令替换为任务标准命令，覆盖模型提供的参数 |
| `required_bash_retry_count` | `int` | `0` | 必需命令失败后在原 Session 追加诊断并重新校验的次数；耗尽后才进入 fresh Session 重试 |
| `required_bash_success_markers` | `Mapping[str, str] \| None` | `None` | 可选的完整命令到单行成功标记映射；只在 Hook 无法取得退出码时使用，键必须属于必需命令 |
| `post_session_validator` | 无参数 callable 或 `None` | `None` | 每次 Session 消息结束后执行；`None`/空白为通过，非空字符串为失败诊断，awaitable 会被等待 |
| `post_session_validation_retry_count` | `int` | `0` | 宿主校验失败后向原 Session 回传诊断并请求修正的次数；耗尽后才进入 fresh Session 重试 |
| `session_id` | `str \| None` | `None` | 为空时创建 Session；非空时续写已有 Session |
| `config_path` | `str \| PathLike \| None` | `None` | 仅独立模式使用的组件 YAML 路径；后端模式禁止覆盖宿主配置 |
| `output` | callable 或 `None` | 当前执行上下文 | 覆盖本次任务的流式输出回调；显式 `None` 表示关闭 |
| `cancel_event` | 提供 `is_set()` 的对象 | 当前执行上下文 | 覆盖本次任务的取消信号 |

不再接受 `directory`、workspace、timeout、priority、attempt、MCP、SKILL、原生 permission 或 CLI 配置对象等参数。`file_write_allowlist` 是推荐的额外写权限入口，兼容参数 `writable_paths` 使用相同语义；`readable_paths` 只增加读取范围。`allowed_bash_commands` 与 `required_bash_commands` 是仅有的 shell 例外入口：两者都只执行声明的完整命令，前者不要求执行，后者还执行完成审计；`bash_command_match_mode` 控制识别方式，其它 `required_bash_*` 参数只控制必需命令恢复。`post_session_validator` 独立于模型是否执行命令，在每次消息结束后由宿主校验产物并可把诊断回传同一 Session。上述参数都不接受调用方自定义原生权限。后端模式由 Agent 执行上下文和内部任务策略统一提供；独立模式由 `config_path` 指向的组件配置统一提供。业务过程可通过 `output` 和 `cancel_event` 对单次调用做局部覆盖。

返回的 `OpenCodeResult.output_source` 是可 JSON 序列化的 dict，用于由客户端协调器原样上报实际模型和 Session 来源。其中 `serve_session_id` 始终回填为生成该结果的最终 OpenCode `session_id`；问题详情页会把它直接显示在对应输出来源中，历史结果缺少该字段时保持兼容。

`task_type` 直接传字符串，不提供枚举。面向业务调用者的稳定类型如下；其它公共调用值会立即抛出 `ValueError`：

| 字符串 | 用途 |
| --- | --- |
| `vulnerability_mining` | 漏洞挖掘，包括候选点审计、项目级审计和威胁审计 |
| `threat_analysis` | 威胁分析 |
| `fp_review` | 去误报复核 |
| `vulnerability_validation` | 漏洞验证 |

任务优先级由 `task_type` 自动决定，数值越大越先取得模型 Lease：

| `task_type` | 优先级 |
| --- | ---: |
| `vulnerability_validation` | 90 |
| `threat_analysis` | 75 |
| `fp_review` | 60 |
| `vulnerability_mining` | 50 |

Agent 内部辅助任务继续使用各自既有策略，但不属于公共调用指导。同优先级任务按进入队列的先后顺序执行；优先级不会抢占已经取得 Lease 的任务。

漏洞挖掘子任务不再拆分 `task_type`。内置调用分别使用 `candidate-audit-*`、
`project-audit-*`、`threat-audit-*` 和 `threat-pattern-audit-*` 任务名前缀；模型看板以
完整引擎名称作为主标签，并追加候选点审计、项目级审计、威胁审计或攻击模式审计作为
子任务说明，其它任务名回退显示“漏洞挖掘”。

任务策略页只配置 `low`、`high` 两档，v3 默认全部为 `high`。v2 及更早配置中的阶段级 `any`/`low` 会一次性迁移为 `high`，旧默认超时 `1200` 会先迁移为 `3600`；v7 升级到 v8 时，威胁分析策略中的 `3600` 秒再一次性迁移为新的默认值 `7200` 秒，其它阶段及其它自定义超时保持不变。升级到 v8 后仍可手工改回 `low` 或填写任意合法超时。模型行自身的能力标签和显式超时不会迁移。

## 独立组件配置

未注册 `OpenCodeHostBindings` 时，配置按以下顺序发现：

1. `run_opencode_task(config_path=...)`；
2. `TASK_AGENT_CONFIG` 环境变量；
3. 当前目录的 `task-agent.yaml`。

格式模板位于 `task_agent/task-agent.example.yaml`。下面的配置包含 Task Agent 自己识别的全部字段；除透传的 `serve.opencode_config` 和由调度器解析的 `time_windows` 项外，顶层、固定分区和模型行都是严格白名单，拼错或加入未知字段会在加载时直接报错：

```yaml
schema_version: 2

context:
  # OpenCode Session 的真实源码目录；该目录必须已经存在。
  project_dir: /absolute/path/to/source
  # 模型文件工具唯一允许写入的任务目录；不存在时自动创建。
  work_dir: /absolute/path/to/task-work
  # Serve 启动、opencode.json 和共享 Skill 所在的稳定组件目录。
  workspace_dir: /absolute/path/to/opencode-workspace

serve:
  # Task Agent 的实现固定为 OpenCode；这里只能填写 opencode。
  tool: opencode
  # 实际启动文件名或路径，可填写 opencode、nga 或完整路径。
  executable: opencode
  port: 4096
  # 单次模型消息从开始执行到完成的默认超时，单位为秒，不包含排队时间。
  timeout: 3600
  # 超时、普通执行错误或 JSON 纠正耗尽后，创建全新 Session 的重试次数。
  max_retries: 2
  # 传给 Serve 子进程的环境变量。实际代理变量会被清除，只保留绕过列表。
  environment:
    NO_PROXY: 127.0.0.1,localhost
    no_proxy: 127.0.0.1,localhost

  # 这里是优先级高于全局、可执行文件相邻、项目和环境显式配置的
  # OpenCode 原生覆盖对象，不属于 Task Agent 固定 Schema。
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
  # 总并发容量自动汇总已启用模型的 max_concurrency。
  models:
    - id: deepseek-pro
      # OpenCode 使用的 provider/model；use_default_model=false 时必须非空。
      model: deepseek/deepseek-v4-pro
      use_default_model: false
      capability: high
      weight: 1
      max_concurrency: 2
      enabled: true
      # 以下两项均为模型行覆盖；省略时继承 serve 设置。
      timeout: 3600
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
| `schema_version` | 必填，当前为 `2` | standalone YAML 的 Schema 版本。v1 会按下述兼容规则迁移；其它版本拒绝加载。 |
| `context` | 必填 | 固定本次 standalone 组件生命周期使用的目录上下文。 |
| `serve` | 必填 | Serve 进程、默认执行策略和原生 OpenCode 配置。 |
| `model_pool` | 必填 | 显式模型列表及全局调度上限。 |
| `context.project_dir` | 必填，必须是已有目录 | OpenCode Session 的 `directory`，也是真实源码根目录。模型可读取该目录，但 Task Agent 不允许文件编辑工具写入。 |
| `context.work_dir` | 必填，不存在时创建 | 本次独立组件固定的可写任务目录。模型生成的补丁、PoC、报告等任务产物应写在这里。 |
| `context.workspace_dir` | 必填，不存在时创建 | Serve 的稳定启动目录和组件 workspace。运行时会在这里生成 `opencode.json`，也适合保存共享 Skill；不要把每次任务的业务产物写在这里。 |

三个路径都支持 `~`。绝对路径直接使用；相对路径以 `task-agent.yaml` 所在目录为基准，而不是以启动 Python 的当前目录为基准。`project_dir` 必须预先存在；`work_dir` 和 `workspace_dir` 会自动递归创建。standalone 的最终 `workspace_dir/opencode.json` 允许读取运行账户有权访问的全部本地路径；文件编辑工具仍只能写 `work_dir`，`bash` 在未声明精确可选或必需命令时保持禁用。

v1 兼容迁移会把 `serve.tool: nga` 规范为 `tool: opencode`，并在未显式填写 `serve.executable` 时继续使用 `nga`；旧模型行里的 `tool` 和 `executable` 会被忽略。v2 只接受 `serve.tool: opencode`，并拒绝模型行工具或可执行文件覆盖，确保所有模型共用 `serve.executable`。

嵌入完整 Agent 时，Task Agent 在 Serve 启动前把 `read`、`list`、`glob`、`grep` 和 `external_directory` 的全局允许规则写入最终 `opencode.json`，OpenCode 因而可以读取运行账户有权访问的全部本地路径，包括扫描工作区之外的项目、隐藏文件和配置文件。写入边界独立保持收敛：`edit` 先全局拒绝，再为 `~/.opendeephole/scans`、`fp_reviews`、`vulnerability_validation`、`skill_create` 四个稳定根、当前 `work_dir` 及显式动态白名单追加原有允许规则；全局 `bash` 保持拒绝。`OpenCodeHostBindings.readable_roots` 和 `readable_paths` 继续作为只读意图及兼容声明，不授予编辑权限；显式传入 `file_write_allowlist`、兼容参数 `writable_paths`、`allowed_bash_commands` 或 `required_bash_commands` 时，动态权限仍通过 Session 覆盖下发，不进入 Serve 配置哈希。

`workspace_dir` 中生成的 `opencode.json` 包含合并后的实际配置，可能带有 Provider Key、MCP Header 等敏感值；运行时在 POSIX 系统上以 `0600` 权限写入，但该目录仍应只对可信用户开放。Task Agent 还会在该 workspace 的私有目录生成受管文件写入/精确命令 Hook 和知识库项目 Hook，并在最终配置的 `plugin` 列表末尾追加文件 URI；调用方已有的插件条目保持原顺序且不会被覆盖，Hook 源码哈希也参与 Serve 配置重载判断。知识库项目 Hook 通过 Session ID 哈希定位 `0600` 私有绑定文件，在 `tool.execute.before` 原地强制覆盖查询工具的 `project_id`，并拒绝平台专用的项目列表/切换工具；文件写入 Hook 同时按 Session 私有绑定约束父、子 Session 的精确命令，记录执行顺序、完整命令、退出状态及末尾最多 16 KiB 输出。这些诊断通常不写入 Prompt；只有调用方启用必需命令同 Session 纠正且校验失败时，才会追加到同一 Session。绑定和命令审计在每次消息返回后即删除。

完整 Agent 与 standalone 共用配置发现与深度合并规则：用户全局目录 < 可执行文件相邻目录 < 项目目录 < 平台 `opencode.config_paths`（standalone 无此层）< `OPENCODE_CONFIG_PATH` / `OPENCODE_CONFIG` / `OPENCODE_CONFIG_DIR`。standalone 随后再合并 `serve.opencode_config`，所以 YAML 中的映射递归覆盖前述来源，标量和列表整体替换。用户全局目录及显式配置目录兼容旧版 `config.json`；自动发现的可执行文件相邻目录与项目目录只接受 `opencode.json` / `opencode.jsonc`，避免误读安装器、启动器或项目自身的通用 `config.json`。使用 `nga` 可执行文件时还会发现对应的全局 `nga` 配置目录。无效外部 JSON/JSONC 记录警告后忽略，不记录配置值；standalone 的配置快照固定到 `shutdown_opencode()`。

最终的 `workspace_dir/opencode.json` 不参与 standalone 的项目配置发现，避免 `workspace_dir == project_dir` 时回灌上次生成物；仍建议将 `workspace_dir` 与源码目录分开，防止覆盖项目自有的同名文件。Serve 子进程使用 `workspace_dir` 下的独立 `XDG_CONFIG_HOME`，把 `OPENCODE_CONFIG_DIR` 指向该最终配置目录，并清除继承的 `OPENCODE_CONFIG`、`OPENCODE_CONFIG_PATH` 和 `OPENCODE_CONFIG_CONTENT`，避免 OpenCode 再次读取并重复合并用户配置。Task Agent 的文件、Skill 与全局 `bash` 拒绝规则、受管写入和命令 Hook，以及固定的 `compaction.auto: true`、`compaction.prune: true`、`compaction.reserved: 20000` 始终最后生效，不能被外部配置放宽；`compaction` 的其它合法子项继续保留。最终配置中已有的 `provider.*.models.*` 若没有 `limit.context`，Task Agent 会补 `context: 131072`，并在 output 也缺失时补 `output: 32768`；已有 input/output 和显式 context 保持不变，不会根据调度模型池创建配置条目。任务级精确命令只存在于 Session 覆盖和私有绑定中。

### Serve 参数

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `serve.tool` | 默认且只能为 `opencode` | 固定的 OpenCode Serve 实现标识，不用于选择磁盘上的文件。 |
| `serve.executable` | 默认 `opencode` | 实际启动 Serve 的可执行文件名或完整路径；可使用 `opencode`、`nga` 或其它兼容程序。配置哪个就启动哪个，不做名称回退。 |
| `serve.port` | 默认 `4096`，范围 `1..65535` | 本机 Serve 固定监听端口。该值会成为最终的 `OPENCODE_SERVE_PORT`，覆盖 `serve.environment` 中的同名值；standalone 不会自动改号。 |
| `serve.timeout` | 默认 `3600`，最小 `1` | 默认单次模型消息执行超时，单位为秒；排队等待模型 Lease 的时间不计入。 |
| `serve.max_retries` | 默认 `2`，最小 `0` | 首次 Session 之外最多创建多少个全新 Session 进行重试；不等同于同 Session 的 JSON 纠正次数。 |
| `serve.environment` | 默认 `{}` | 附加或覆盖到 Serve 子进程的环境变量。键转为字符串，值必须是标量并会转为字符串；`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及其小写形式会被忽略并从父进程环境清除。`NO_PROXY` 与 `no_proxy` 分别以逗号追加到父进程同名变量，不会覆盖原值。 |
| `serve.opencode_config` | 默认 `{}` | 必须是可 JSON 序列化的映射；作为 standalone 最高优先级用户层与已发现配置合并，再由 Task Agent 写入受管权限并生成 `workspace_dir/opencode.json`。 |

`serve.opencode_config` 可以包含 OpenCode 当前版本支持的 `$schema`、Provider、Agent、MCP、Skill 等原生配置。Task Agent 不校验这些子字段，也不保证不同 OpenCode 版本的原生字段兼容；最终配置中的 `read`、`list`、`glob`、`grep`、`external_directory`、`edit`、`bash` 和 `skill` 会由 Task Agent 覆盖为受管边界，不能依赖这里的 `permission` 放宽任务边界。

MCP 直接写在 `serve.opencode_config.mcp` 下。远程 MCP 通常使用 `type: remote`、`url`、`headers` 和 `oauth`；本地 MCP 使用 `type: local`、命令数组 `command` 以及可选的 `environment`。两种 MCP 的 `timeout` 都由 OpenCode 解释，单位为毫秒；这与 `serve.timeout` 的秒不同。扫描级代码图谱 MCP 对外使用 `code_graph_mcp.timeout_seconds`，运行时乘以 `1000` 写入 OpenCode 配置，例如 `300` 秒生成 `"enabled": true, "timeout": 300000`。

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

standalone 加载器只负责创建 `workspace_dir`，不会自动创建、复制或注册任何 Skill，也不会把 `context.workspace_dir` 变量插值到 `skills.paths`。因此两处路径应手工保持一致，推荐都填写绝对路径；Task Agent 会从最终生效的 `skills.paths` 推导读取权限，使 Skill 内的引用资源一并可读。

完整 DeepHole 2.0 Agent 在首次启动 Serve 前（包括模型列表触发的启动）自动安装全部业务 Skill，固定位置为 `~/.opendeephole/opencode_workspace/.opencode/skills/<name>/`。当前随包提供 28 个：18 个候选审计、4 个去误报、4 个威胁分析、1 个多版本审计和 1 个 Skill 创建功能；数量随业务目录新增自动变化，不读取开发机的历史安装清单。安装按 `SKILL.md` frontmatter 名称组织，保留 `references/`、`agents/`、`assets/`、`scripts/` 等运行资源，并排除各层目录中的 `SCENARIOS.md` 介绍文件；源目录和下发包仍保留该文件用于介绍页。启动或规则同步时会一并清理本次安装 Skill 的旧 `SCENARIOS.md`，保留同步版本和本地续扫的版本选择规则。启动日志中的 `OpenCode Skills ready` 会显示内置数量与绝对目录。

宿主通过 `OpenCodeHostBindings.fixed_skill_root` 绑定固定目录，此时任务上下文中的 `skill_paths` 只检查所需名称已经安装，不向运行配置追加路径。任务之间切换 Skill 不改变 `skills.paths`，不会因此重启 Serve。服务端新下发的规则包在模型任务进入前安装；内容变化时暂停新的 Serve 会话进入，等待已有会话完成，再发布完整目录并让下一次调用重新启动 Serve、发现更新后的 Skill。相同内容不会重复刷新。本地续扫仅补齐缺失 Skill，使用统一目录的当前版本，不将旧扫描快照覆盖回来。

安装清单 `.opendeephole-skills.json` 位于 workspace 根目录，记录来源和内容哈希；暂存与备份不进入 Skill 搜索目录。不同来源的同名 Skill 会明确报错，安装失败会恢复原目录。升级会迁移可识别的旧 checker 目录别名，保留非受管用户文件。需要同步更新后端发布代码和 Agent 并重启 Agent；`deephole-skill-creator` 源文件移到 `deephole_client/builtin_skills/`，随下载包和运行时更新包一起校验、安装，也兼容仍会跳过旧 `system_skills` 目录的 Agent 更新器，无需数据库迁移。

### 模型池参数

`model_pool.models` 必须是列表，并且至少包含一个已启用且填写了 `model` 的模型，或者一个已启用且显式设置 `use_default_model: true` 的默认模型行。

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `models[].id` | 默认取 `model`，默认模型行为 `default` | 模型池内部稳定标识，用于 Lease、日志和统计；不同模型行应使用不同 ID。 |
| `models[].model` | 条件必填 | OpenCode 的 `provider/model`。要让该行进入可调度模型池，当 `use_default_model` 为 `false` 时必须非空。 |
| `models[].use_default_model` | 默认 `false` | 为 `true` 时忽略 `model`，让 Serve 使用自己的默认模型。 |
| `models[].capability` | 默认 `high` | 模型能力，可为 `low`、`medium`、`high`。公共任务只请求 `low` 或 `high`；高能力任务只使用高档模型，低能力任务在当前负载和有效权重相同时优先选择满足条件的较低档模型。 |
| `models[].weight` | 默认 `1`，最小 `0.01` | 多个可用且能力合适的模型之间的基础调度权重；运行时健康降级不会改写该配置值。 |
| `models[].max_concurrency` | 默认 `1`，最小 `1` | 该模型行允许同时持有的 Lease 数量。 |
| `models[].enabled` | 默认 `true` | 是否将该模型加入可调度模型池。 |
| `models[].timeout` | 默认继承 `serve.timeout`，最小 `1` | 该模型单次消息执行超时，单位为秒。 |
| `models[].max_retries` | 默认继承 `serve.max_retries`，最小 `0` | 该模型在超时或其它可重试失败后采用的新 Session 重试次数。 |
| `models[].time_windows` | 默认 `[]` | 模型允许获得新 Lease 的本地时间窗口；空列表表示全天可用。 |

只配置每个模型的 `max_concurrency`，没有独立全局并发闸门。配置总容量汇总已启用且配置有效的模型，时间窗和任务能力决定当前可使用哪些额度：

```text
配置总容量 = 所有已启用且配置有效的模型的 max_concurrency 之和
当前任务可用容量 = 满足能力要求且处于可用时间窗内的模型的 max_concurrency 之和
```

例如两个当前可用的高能力模型分别配置 `4` 和 `5`，充足的 `high` 任务可以同时运行 `9` 个，第 `10` 个等待空位。不同扫描和任务类型共享这些模型额度；总容量也不再受 `8` 或 `64` 截断。单模型并发缺省值仍为 `1`。

旧的 `model_pool.global_concurrency` 和平台顶层 `opencode_concurrency` 已退役，兼容读取但忽略数值；平台保存、导出和下发时不再包含这些字段，独立 Task Agent 也无需修改旧 YAML 才能启动。配置版本保持不变，无需数据库迁移。平台各扫描阶段及内存 API 分析按模型容量创建工作协程，已有阶段不动态扩充工作协程；运行中修改模型额度仍会更新模型租约调度，降低额度不会中断已有请求。

模型池在当前 Agent/Task Agent 进程内为每个实际模型身份维护 `0..4` 级健康惩罚，调度使用的有效权重为：

```text
有效权重 = 基础权重 × max(10%, 0.5 ^ 健康惩罚等级)
```

五个状态的权重系数依次为 `100%`、`50%`、`25%`、`12.5%` 和 `10%`。模型池状态会分别暴露基础权重、有效权重、当前惩罚等级以及最近一次健康故障的时间和类型；配置中的 `models[].weight` 始终保持不变。

只有已经进入模型消息请求后的 Provider/Auth/API 执行失败或总超时才会增加一级惩罚；即使消息接口返回 HTTP 200，assistant `info.error` 中的这类 Provider 执行错误也按真实请求失败处理。`ContextOverflowError`、`MessageOutputLengthError`、`StructuredOutputError` 和非主动取消产生的 `MessageAbortedError` 会让当前任务换模重试，但不会降权。Serve 启动或配置失败、MCP/回调故障、主动取消、没有可用模型，以及返回内容未通过 JSON Schema 校验，也都不属于模型健康故障。一次最终成功会恢复一级；没有新模型消息请求故障满 10 分钟也会恢复一级。JSON 纠错耗尽后仍会进入 fresh Session 换模重试，但该 JSON 失败本身既不降权也不恢复健康；若纠错消息请求本身超时或发生 Provider/Auth/API 执行失败，仍按真实请求故障处理。

assistant 错误可能把 Provider 原始对象包在 `UnknownError`、类型校验文本以及多层 JSON 字符串中。Task Agent 只提取允许公开的错误码、RPM/TPM 类型、身份类别和重试时间；当错误码为 `*.429` 且内容表示请求/Token 配额暂不可用时，按实际模型身份打开临时配额熔断，而不是永久禁用该模型。默认冷却序列为 30、60、120、240、300 秒，Provider 给出的正数 `retry_after` 优先使用并限制到 300 秒，`-1` 或无效值使用默认退避。其它合格身份立即接管；全部合格模型都在冷却时，逻辑任务在既有 fresh Session 重试预算内等待，累计上限为 5 分钟且取消事件会立即生效。冷却到期只允许一个半开请求，成功关闭熔断，重复配额错误重新打开；该状态与健康惩罚一样只存在于当前进程。

健康状态不会写回配置或跨进程持久化，Agent/Task Agent 进程重启后从零惩罚和基础权重重新开始。运行中只修改基础权重、并发数或时间窗时继续沿用同一实际模型身份的健康状态；模型 ID 对应的真实模型、默认模型标记或全局可执行文件变化时视为新身份。

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
- standalone 的 `serve.port` 是显式固定端口，占用时会报告外部监听 PID，无监听却绑定失败时会提示 Windows 排除/保留端口或端点安全软件，不会换号或终止未证明属于本组件的进程。完整 Agent 在未配置端口时才使用自动模式：端口延迟到 Serve 启动边界、完成运行配置准备后即时分配，实际值只保存在 Serve 管理器内，不写回任务运行时或受管配置；其它进程占用候选端口、旧进程已消失但原端口仍处于 Windows 连接回收期，或冷启动健康门持续连接超时时，清理精确归属的失败进程、避开已尝试端口并最多尝试 3 个不同端口。首次只返回无明确原因的 `Error: Unexpected error` 时仍只作一次恢复性换号。当前受管 Serve 仍存活或身份无法安全确认时禁止换号，同一 Agent 进程最多登记一个 Serve。
- 未显式 shutdown 时，组件会登记自己通过 `Popen` 启动的精确 PID 和独立进程组，在解释器正常退出、`SIGINT`（Ctrl-C）或 `SIGTERM` 时同步清理，再恢复或转交宿主原有信号处理器。启动器 PID 退出不再等同于整棵进程树退出：POSIX 会继续检查进程组和已确认归属的监听 PID，发送 `SIGTERM` 5 秒后仍存活则升级为 `SIGKILL`；Windows ownership marker 额外记录进程创建标识，历史 marker 恢复与当前管理器停止共用同一身份分类，只对 `owned` 进程执行 `taskkill /T /F`，`absent`/`foreign` 会清理本方状态且不终止外部 PID，`unknown` 则保留 marker 和管理器状态继续阻断。TCP、监听表和带 `SO_EXCLUSIVEADDRUSE` 的独占绑定分别用于判断端点及端口状态，不再替代进程存活判断：旧进程已消失时删除 marker，端口可用则复用，暂不可绑定则由自动模式避开、固定模式报告。
- Windows `.cmd`/`.bat` shim 的版本查询与 Serve 启动统一使用独立参数 `[COMSPEC, "/d", "/c", "call", executable, *arguments]`。完整路径作为一个参数保留，由 Python 在启动时处理引号；例如 `C:\Program Files\nodejs\opencode.CMD` 可直接使用，不预先通过 `list2cmdline()` 拼接，避免空格路径被二次转义为带字面量 `\"` 的命令。修复同时覆盖模型列表读取和扫描任务；部署后需更新并重启 Agent，再刷新模型列表。
- 启动失败会同时报告固定/自动端口模式、已尝试端口、解析后的可执行文件、版本探测 argv 和版本输出，并附上脱敏后的启动日志尾部。版本探测只是非阻断诊断：旧受管 Serve 安全清理完成后先原子发布最终 `opencode.json`，再以异步子进程执行探测并用普通临时文件承接输出，避免包装器子进程持有管道时在超时后继续等待 EOF；3 秒内未结束时仅终止该探测的进程树、将版本记为未知并继续启动 Serve。探测非零退出也将版本记为未知，并在调试日志保留退出码与错误输出，错误文本不会作为版本号显示。Agent 终端会记录可执行文件解析、旧进程清理、配置发布和版本探测的阶段及耗时。健康失败后的清理若也失败，最终异常会同时保留原始健康错误和清理错误，不再由后者覆盖前者。停止日志会记录重启原因、dirty/restart 标志和当前/目标配置哈希。`OPENCODE_SERVER_PASSWORD is not set` 是 Agent 仅监听 `127.0.0.1` 时的预期警告，日志会明确说明它不是 Serve 退出原因。
- Serve 冷启动和 Web 模型导入都以 `GET /global/health` 的 HTTP `200` 且 JSON `healthy: true` 作为唯一健康成功条件；其它 2xx、无效 JSON 或 `healthy` 非 true 都继续等待或失败。冷启动健康门耗尽会抛出独立的 Serve 启动异常，在自动模式内部完成换端口恢复，最终失败不会作为模型消息超时进入 fresh Session 重试。复用进程但模型导入健康检查失败时，空闲 Serve 只安全重启一次并复查；存在活动 Session 时不强制重启且不会访问 Provider。Agent 终端会按时间打印请求编号、executable 配置与解析路径、版本、启动命令、端口、健康检查、Provider 耗时和已脱敏的 Serve 启动输出。
- `SIGKILL` 和 `os._exit()` 不运行 Python 的信号处理器或 `atexit` 回调，无法保证当场清理；下次启动会继续使用既有归属标记和端口恢复逻辑回收残留 Serve。
- 若应用已经注册后端宿主绑定，则完全使用宿主配置，不读取独立 YAML；此时再传 `config_path` 会报冲突。

## 控制台日志

Task Agent 的进度行统一使用下面三个头字段：

```text
[<stage>][<session_id>][task|session|tool|skill] <event>
```

- `vulnerability_validation` 映射为 stage `validation`；其它任务直接使用 `task_type`。Session 尚未创建时第二段为 `pending`，创建或续写后改为真实 Session ID。
- 第三段只会是 `task`、`session`、`tool` 或 `skill`：`task` 覆盖排队、模型 Lease、Serve 准备和任务终态；`session` 覆盖当前消息执行的启动、停止、Provider 重试、新 Session `RETRY`、独立格式匹配 `JSON_FORMAT_RETRY` / `JSON_FORMAT_RECOVERED` / `JSON_FORMAT_FAILED`、原 Session `JSON_RETRY`、错误及工具发现；`tool`、`skill` 分别表示一次真实工具调用或 SKILL 读取。OpenCode 内部 step 的 START、STOP 和 FAIL 不打印。
- 每次消息执行都会打印 `session START` 和 `session STOP`。Task Agent 发起的消息会在既有三段头部后追加逻辑 `task`、`attempt`，并在响应已形成时追加 `message`，从而把 fresh Session 重试和具体消息关联起来；直接调用底层 Serve 客户端且未传任务关联信息时保持原格式。`STOP status=success retained=true` 同时表示本次消息结束且成功，Session 本身仍保留并可续写；超时和取消分别标记 `status=timeout`、`status=cancelled`。
- assistant text 和 reasoning 不打印到控制台，仍在内部聚合并作为最终 `text` 返回或用于 JSON 校验。Tool/SKILL 调用每次只打印一行：`read` 打印 `path` 及可选 `offset`/`limit`，`write` 打印 `path`/`content_chars`，`edit` 打印 `path`/`old_chars`/`new_chars` 及可选 `replace_all`，`bash`/`shell` 打印完整 `command` 及可选 `workdir`/`timeout`/`description`，`grep`/`glob`/`list` 打印各自的模式与目录；当前扫描实际选中的代码图谱 MCP 打印实际工具名及完整、无截断、无脱敏的单行 `input` JSON，其它未识别的 Tool 和 MCP Tool 仍只打印名称。Bash 命令与代码图谱 MCP 输入使用 JSON 转义保持单行，其中的 Token、密码、请求头或其它敏感值会原样进入日志。成功不追加完成行，调用失败才在同一类别下追加脱敏 `ERROR`；write/edit 正文、其它未列出的调用参数和工具返回正文仍不打印。嵌套 `opencode_task_context(...)` 省略 `output` 时继承宿主回调，只有显式传入 `output=None` 才关闭输出。

独立模式直接把这些行打印到终端；宿主模式只交给宿主绑定的输出回调。宿主添加本地时间戳时会保留上述三个头字段，不再叠加旧的阶段或模型前缀；扫描器转发结构化 Task Agent 行时也不会重复添加进程阶段前缀。

## 返回值

接口只返回以下字段：

| 字段 | 含义 |
| --- | --- |
| `session_id` | 最终实际使用的 Session ID |
| `status` | 仅为 `success`、`failure` 或 `timeout` |
| `text` | 成功时始终为 LLM 最后一次文本输出，即使 `structured` 来自文件也不会替换为文件内容；失败或超时时为可直接展示的原因 |
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
- `file_write_allowlist` / `writable_paths`：调用方显式授权的额外文件或目录；两者合并后同时获得写权限和默认保留语义。相对路径以 `project_dir` 为基准，绝对路径允许位于项目外，但不接受 `*`、`?` 或文件系统根目录。
- `readable_paths`：保留的兼容参数，用于显式声明调用方希望读取的文件或目录；最终全局配置已允许读取全部本地路径，该参数不获得 `edit`，也不参与保留。
- `allowed_bash_commands`：调用方声明的可选精确命令；先拒绝 `*`，再按声明顺序逐条放行。模型可以不执行，执行失败或之后继续写文件也不参与任务完成审计。
- `required_bash_commands`：调用方声明的必需精确命令；与可选命令使用同一条精确绑定路径，但命令必须在最后一次受管文件写入后完成，通常要求退出码 0；若调用方为该命令配置 `required_bash_success_markers`，且 OpenCode Hook 无法读取退出码，则允许以输出中完全匹配的一整行标记成功。
- `bash_command_match_mode`：默认 `exact`。轻量分析显式选择 `bound_python_script`，允许 `python`、`python3`、对应 `.exe` 名称或宿主 Python 绝对路径直接调用绑定脚本；脚本绝对路径按宿主平台规范化匹配，同名其它路径不能命中。前置 Hook 将命令原地替换为当前任务的标准命令，所有产物路径和参考目录均使用宿主已绑定的值，模型遗漏或改写的参数不会参与实际执行；父子 Session 继承同一绑定，并发任务各自独立。同一脚本不能声明多个不同的标准命令，旧绑定默认精确匹配。
- `required_bash_retry_count`：命令校验失败后在原 Session 追加诊断和纠正消息的次数；纠正消息携带失败类型、命令、退出码、超时状态和末尾最多 16 KiB 输出，并要求修复产物后重新运行完全相同的命令。耗尽后才释放 Lease 并进入 fresh Session 重试。
- `post_session_validator` / `post_session_validation_retry_count`：每次完整消息返回后调用宿主校验器；`None` 或空白结果表示通过，非空字符串作为诊断回传原 Session，且明确该内容不是新任务指令、无需模型执行校验命令。预算耗尽后沿用现有 fresh Session 重试；同步回调在当前执行点调用，返回 awaitable 时等待完成。
- `scan_id`、`execution_kind` / `execution_id`、任务元数据、输出回调和取消事件：由编排层绑定并在异步任务树中自动继承。执行身份只用于精确取消一个扫描、去误报或验证作业；共享同一 Serve 的其它任务不会被终止。
- `config_path`：独立过程可绑定自己的 Task Agent YAML；standalone 会合并全局、可执行文件相邻、项目、环境显式配置与 YAML 中的 `serve.opencode_config.skills.paths`，并保留任务路径合并兼容性。
- `skill_paths`：完整 Agent 只用它检查固定目录中是否已安装所需 Skill；独立 Task Agent 未绑定 `fixed_skill_root` 时仍提供任务级路径注册。

后端模式没有绑定 `project_dir` 或 `work_dir` 时，调用会立即失败，不会回退到进程当前目录。独立模式始终使用 YAML 中固定的两个目录，因此 Session continuation 不会改变权限边界。

内部服务会在 Serve 启动前把受管边界写入最终全局 `opencode.json`：

- 全局允许 `read`、`list`、`glob`、`grep` 与 `external_directory`，使 OpenCode 可读取运行账户有权访问的全部本地路径；这包括项目工作目录、其它版本的真实项目路径、全局 workspace、Skill 资源、隐藏文件和配置文件。
- 先拒绝所有 `edit`，再允许宿主声明的稳定可写根。完整 Agent 允许写四个 `.opendeephole` 任务根，standalone 允许写固定 `work_dir`；通用嵌入宿主若没有声明覆盖当前 `work_dir` 的稳定根，Task Agent 会把该目录加入本次最终配置。
- 默认拒绝所有 `bash`；只有当前调用显式声明 `allowed_bash_commands` 或 `required_bash_commands` 时才放行声明的标准命令。默认策略拒绝变形命令；脚本策略允许引号、空格、Python 名称及参数写法差异，并在原生权限检查前还原标准命令，不扩大原生 shell 白名单。受管 Hook 拒绝未绑定脚本、命令拼接、管道、重定向、变量/命令展开及 `python -c/-m`。只有必需命令会把缺失、超时、非零/未知退出及校验后再次写文件视为任务质量失败。Windows 上只对绑定 Session 的 shell 环境临时前置当前 Python 目录；不会授予其它命令权限。
- 允许加载最终配置注册的 SKILL；完整 Agent 的所有业务 Skill 来自统一安装目录，独立过程仍兼容临时路径。注册 Skill 本身不会授予编辑权限，是否可写仍只取决于它是否落在 `work_dir` 或宿主可写根内，MCP 可见性继续由受管配置决定。

原生权限规则仍是内部实现细节，组件和 validator 不能直接传 `permission`。Task Agent 每次都以 `work_dir` 加当前调用显式路径生成 Session 权限；续接已有 Session 时会替换旧覆盖，避免上一次调用的额外写路径残留。新 Session 重试会重新应用相同路径，同 Session JSON 纠正复用当前权限而不重复 PATCH。同步过程可以由异步门面通过 `run_sync_component()` 执行；同步实现内部调用 `run_opencode_task()` 时会回到门面所属事件循环，并继续继承同一目录、权限和私有 SKILL 上下文。

## JSON 自动纠正和新 Session 重试

只有传入 `output_schema` 时才解析结构化结果。服务不使用 OpenCode 原生 `format=json_schema`，也不再把 Schema 或任何输出要求追加到首次用户 prompt；调用方传入什么字符串，首次消息和任务队列历史就保存并发送什么字符串，`prompt_length` 也按该原文计算。需要模型首次就输出 JSON 时，调用方必须像上文示例一样显式组装最终 prompt。

服务先解析 LLM 的最终文本；文本中的 JSON 合法时始终优先采用。若文本不匹配 Schema，服务会检查本轮成功完成的内置 `write`、`edit`、`apply_patch`/`patch` 调用，按实际写入顺序从后向前读取文件，最后一个匹配 Schema 的文件成为 `structured`。受管 OpenCode Hook 在 `tool.execute.after` 为写入结果附加标准化路径、Session、调用 ID 和是否新建等标记；消息完成后，Task Agent 还会基于发送前 assistant 基线重新读取本轮完整消息历史，恢复最终 HTTP 响应未包含的中间 assistant 文件写入。事件流、Hook 标记和 OpenCode 原生 Tool 元数据会合并去重；Hook 异常不会改变工具执行结果。这不会改变 `OpenCodeResult.text`，它仍是 LLM 最后一次文本输出。自定义 MCP 工具的未知文件副作用不在跟踪范围内。

相对写入路径以 OpenCode Session 的 `project_dir` 为基准，只允许从 `project_dir`、`work_dir` 或显式白名单路径读取文件结果。`work_dir` 是隐式白名单，显式路径自身及后代同时可写并默认保留。每次消息结束后，服务会删除本轮确认新建、但位于有效白名单之外的任意位置文件；无论消息成功、失败、取消或即将进入恢复，都会先取得需要的文件快照再清理。若某个本轮新建文件被实际采用为符合 Schema 的 `structured` 来源，则解析后强制删除，即使它位于白名单中；多个合法文件中只有实际采用者使用该例外。已存在但被修改的文件始终不删除或恢复。

若文本和已写文件都没有符合 Schema 的 JSON，且 `invalid_json_retry_count > 0`，服务按以下顺序恢复：

1. 释放原业务模型 Lease，新建一个独立格式匹配 Session。输入优先使用本轮最后写入的非空文件原文，没有可读文件时使用业务 Session 最终文本；新 Session 不连接扫描 MCP、权限覆盖为空、所有已发现工具与内置工具均禁用。
2. 格式匹配以 `required_capability="low"` 严格调度，并优先使用满足要求的最低能力候选，因此配置为低能力的模型可以承担该任务；候选始终只来自已启用且当前时间窗有效的模型，不会使用禁用模型。若没有任何已启用模型，格式匹配失败并回到原 Session。为避免仅有一个模型槽位时死锁，该阶段不会占用原业务 Lease。
3. 格式匹配提示只允许修复 JSON 语法、围栏、引号、转义、逗号及无歧义且不改变语义的组织/字段映射，禁止新增、删除、推断、补全、概括、翻译或改写业务事实。原文缺少 Schema 必需语义、映射有歧义或与 JSON/Schema 完全无关时，模型必须只返回固定非法值 `__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__`，不得强制套用 Schema。
4. 格式匹配输出通过 Schema 后，只把该 JSON 作为 `structured`；公开结果仍返回原业务 `session_id`、原 `text`、原 `model` 和原输出来源。格式匹配失败、返回固定非法值或请求异常时，服务重新取得符合原业务能力要求的已启用模型 Lease，并在原业务 Session 最多追加 `invalid_json_retry_count` 次纠正消息。
5. 原 Session 纠正仍失败后，才按 `serve.max_retries` 重新排队并创建 fresh 业务 Session。格式不合规与固定非法值属于健康中性失败；格式匹配或纠正请求本身发生 Provider/Auth/API 失败或超时时，仍按真实请求结果更新对应模型健康状态。

独立格式匹配和原 Session 纠正会通过模型池上下文的 `task_phase` 标记当前恢复阶段，但任务队列及完成历史中的 `prompt`、`prompt_length` 始终保留调用方首次提交的业务 Prompt 及其长度，不会替换为内部格式匹配/纠正提示或阶段占位符。

原 Session 纠正使用 `invalid_json_retry_prompt`：值为 `None` 时使用当前包含完整 Schema 的中文默认提示词；传入非空字符串时，每次都原样发送该字符串，不追加 Schema、重试序号或其它内容。空字符串、纯空白和非字符串会在提交任务前报错。未传 `output_schema` 时不启用文件 JSON 回退，但仍跟踪并清理非白名单新文件；`invalid_json_retry_count=0` 时同时关闭独立格式匹配与原 Session 纠正，但既有 fresh Session 重试策略保持不变。

若同 Session 纠正耗尽，内部服务会按对应任务策略的 `max_retries` 释放 Lease、重新排队并创建全新 Session。模型消息超时和其它可重试执行错误也使用同一预算；`max_retries=2` 表示首次 Session 之外最多再创建 2 个 Session，即最多执行 3 次。业务方不再传 `attempt`。

模型池完成历史仍以逻辑任务为粒度，只追加一个 `completed_tasks` 项，不把 fresh Session、独立格式匹配、同 Session JSON 纠正或同 Session 命令纠正计为新任务。该项通过 `session_events` 按时间顺序保留 `business`、`json_format`、`json_retry` 和 `validation_retry` 事件，包括 Session ID（创建前失败时为空）、业务尝试/重试序号、模型、结果、时间、耗时和失败原因；校验输出正文只用于当次纠正 Prompt，不进入历史。`serve_session_id` 继续表示最终权威业务 Session。任务最终成功时，之前的超时或输出不合规事件仍会保留。页面在同一任务行的展开详情中展示全部事件，不改变队列计数和分页。

完成记录上报与模型额度释放分开执行：释放时在内存保留待上报记录并唤醒后续任务，后台线程再写入 Agent 的持久 outbox；写入失败保留记录并重试，日志输出 `OpenCode completion report pending`。尚未写入 outbox 的记录仍依赖当前 Agent 进程，正常退出最多等待 10 秒落盘，失败会明确记录。outbox 的入队、领取、确认和重试操作均离开事件循环执行；领取或发送被取消时归还该次领取，迟到清理不能影响后续领取。相同 Lease 的重复或迟到释放不重复计数，也不能释放下一次尝试的额度。Task Service 的收尾异常会记录错误并结束结果与 Session 等待，不留下永远运行的任务。

扫描级模型池发布器由主扫描和各去误报任务共同持有，最后一个持有者结束后才停止。复核入队立即登记 `planned_tasks`，申请模型时进入 `queued_tasks` 并隐藏计划占位，取得额度后消费占位并进入 `active_tasks`；失败、取消及没有实际发起模型调用也会清理占位。每个任务携带 `execution_kind`、`execution_id`、`execution_revision` 和 `agent_session_id`，复核发布器以 `execution_owner={kind: "fp_review", id: review_id, revision: ...}` 校验自身身份。服务端在主扫描完成、出错或续扫时只移除主扫描的运行状态，保留仍有效的独立复核；用户停止整个扫描或 Agent 离线取消复核时同步清除。GET/SSE 顶层仍使用主扫描版本，防止独立复核版本误触发前端的旧轮次过滤。此协议需同步更新后端和 Agent，不需要数据库迁移。

JSON 输出不合规只记录稳定大类：`empty_output`、`no_json`、`invalid_json`、`schema_mismatch`，独立格式匹配判定无法无损转换时另记 `source_unrelated`。诊断不会持久化模型原始回复、目标 Schema 或字段路径；普通终态错误会保存 Task Agent 已规范化且长度受限的安全错误说明。旧模型池历史没有 `session_events` 时继续使用最终 `serve_session_id` 兼容展示，无法反推已丢失的中间 Session。

创建新 Session 或更新续写 Session 的权限返回 HTTP 5xx 时，Task Agent 会把共享 Serve 标记为异常，而不让后续重试继续复用同一个进程。发生并发任务时，下一次 Session 获取会等待所有已获取 Session 释放，在空闲边界停止并重启 Serve、重新生成最终 `opencode.json`；等待中的其它重试随后复用这个新进程，因此同一轮异常只触发一次安全重启。HTTP 4xx 仍按请求或配置错误直接上报，不触发 Serve 重启。

`timeout_seconds` 保持单次调用口径：取得模型 Lease 后，每次调用从 Serve 准备开始使用单调时钟截止时间，覆盖共享 Serve 等待、MCP 准备、Session 创建、消息等待、响应恢复和宿主校验。模型排队不计入，同 Session 的下一次纠正调用及新 Session 重试分别重新计时。Serve 自身的启动故障仍使用 `serve_startup` 分类；准备或校验超时不降低模型健康度，消息超时继续沿用换模和健康惩罚。

超时会输出 `TIMEOUT phase=... task=... attempt=... elapsed=...`。后续 Session 中止、请求/事件回收、MCP 释放及 HTTP 关闭共用最多 10 秒清理预算；取消不合作的操作不会无限阻塞模型 Lease 释放。Session 中止未确认或请求未退出时，标记共享 Serve 在空闲边界恢复，不强制终止其它扫描的活动 Session。关闭旧调用的结果和文件事件回调，迟到回复不能更新新尝试。Session 树 Token 补采最多等待 2 秒，保留已取得的统计并使用现有 `complete=false` 标记不完整；补采失败不替换原始失败原因。

共享 Serve 启动锁内的 MCP 同步和事件订阅清理也共用有界预算；超时后退休旧任务并隔离其进程/事件代次，迟到回调不能恢复旧连接或覆盖新状态。Task Service 对每次业务调用额外限制为调用截止时间加最多 10 秒清理，即使底层请求不响应取消也能返回超时、释放模型额度并继续既有重试。收尾或上报失败不替换已确定的原始超时结果。

模型池在锁内检查状态和登记通知，在锁外等待独立 Event；池内临界区不等待网络、磁盘或其它任务。此约束覆盖模型排队和状态发布，避免 Python 3.10 的 `wait_for(Condition.wait())` 在超时与重复取消时遗留共享锁。排队协程取消后撤销请求；最终上下文通过 `release_model_lease(context_updates=...)` 与额度释放一次完成，重复释放以及旧租约迟到 Token 入账均被租约身份拒绝。释放日志包含 `task`、模型和结果，Session `STOP` 与逻辑任务 `FINISHED` 仍分别表示消息结束和逻辑任务结束。

Token 补采与统计回调共用最多 2 秒预算，成功响应使用调用剩余时间；预算耗尽保留已取得的 Token 并标记 `complete=false`，不将业务成功改成超时，也不降低模型健康度。异常清理仍受上述 10 秒总预算约束。

Agent 重连恢复按主扫描和独立去误报各自的执行身份处理；已领取恢复轮次的主扫描不被复核运行状态阻挡，普通手动续扫仍遵守既有约束。恢复失败按会话和轮次条件落库并通过 SSE 公布具体原因；历史“Agent 进程已重启，正在自动断点恢复”及自动恢复失败记录保留下一次重连的恢复资格，用户主动取消不会自动恢复。部署需更新后端、前端与 Agent 并重启受影响 Agent，无需数据库迁移或强制升级 Python。

OpenCode 轻量威胁分析的宿主产物校验异步启动同一 Python 校验器，最长运行 60 秒，且受本次调用剩余时间约束；主动取消或超时会终止并回收校验进程，Agent 心跳与状态上报继续运行。校验器自身超时作为明确的校验诊断，沿用一次同 Session 纠正及后续新 Session 重试；调用总时限耗尽则直接进入超时重试。恢复扫描时校验已完成产物的同步路径同样限制为 60 秒。校验规则、任务策略默认值、重试次数及轻量分析失败后的一次 DeepHole 回退均保持不变。部署需更新并重启 Agent，然后续扫受影响任务，无需数据库迁移。

OpenCode 同步消息接口若在 HTTP 成功后返回空正文或非 JSON，Task Agent 会查询同一 Session 的消息历史，只接受相对于发送前基线新增且已经完成的 assistant 消息，并将其送回正常的错误、模型、Token、文本和文件写入处理链；恢复成功时控制台输出 `RESPONSE_RECOVERED reason=empty_body|invalid_json source=session_messages`。续写 Session 无法取得发送前基线时不会用历史消息兜底，避免把上一轮结果误认为本轮成功。若没有可确认的新消息，则错误只包含状态码、Content-Type、响应字节数和恢复失败类别，不包含响应正文或模型文本，并作为健康中性失败进入 fresh Session 换模重试，不降低模型权重。

fresh Session 重试会累计本次逻辑任务已经尝试过的实际模型身份。只要还存在满足能力与当前时间窗的未尝试模型，调度器就排除已经尝试的模型；即使未尝试模型的并发容量暂满，也继续排队等待它，而不是立即回到刚失败的模型。只有单模型可用，或所有合格模型都已经尝试后，才重新允许全部候选按当前有效权重竞争 Lease。该换模规则同样适用于 JSON 纠错耗尽，但 JSON 校验失败和纠错耗尽本身不触发健康降权。

Provider 的 RPM/TPM `*.429` 配额错误也使用同一 fresh Session 预算，但在重新排队前会打开上述临时熔断。有替代模型时下一次 Lease 立即选择替代身份；没有替代模型时等待冷却并执行单个半开探测，因此后续 Provider 恢复后同一逻辑任务仍可继续，而不会把一次 `quota=0` 固化成永久不可用。最终耗尽 Session 次数或 5 分钟配额等待上限时才返回明确失败；威胁分析外层仍只保留一次增量恢复加一次 clean fallback，不额外叠加业务层循环。

只有预算耗尽后的超时、主动取消和没有可用模型会成为终止结果：

- 最后一次仍超时时返回 `status="timeout"`，原因位于 `text`，并保留最后创建的 Session ID。
- 最终失败返回 `status="failure"`，原因位于 `text`。
- 主动取消传播 `asyncio.CancelledError`，并停止排队、当前请求、JSON 纠正及后续新 Session 重试。

同步组件通过 `run_sync_component()` 在工作线程中调用公共接口时，桥接层会跟踪其投递到 Agent 主事件循环的精确任务；外层扫描被取消后，桥接任务先取消对应 Task Agent 调用并短暂等待工作线程退栈，不会只丢弃调用方而让 OpenCode Session 在后台继续运行。Agent 的扫描停止命令还会按 `execution_kind="scan"` 与扫描 ID 主动取消所有匹配记录并返回是否仍有活动任务；该路径不会停止共享 Serve。

## Session 续写

将上次返回的 `session_id` 传回同一接口即可续写：

```python
follow_up_prompt = (
    "基于已有上下文补充证据并重新输出 JSON。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

continued = await run_opencode_task(
    task_name="candidate-audit-npd-follow-up",
    task_type="vulnerability_mining",
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
- `task_agent/model_pool.py`：模型 Lease、单模型并发、容量汇总、能力匹配、时间窗和统计。
- `task_agent/serve_client.py`：Serve 生命周期、Session API、事件与消息流。
- `task_agent/host.py`：自包含组件与宿主之间的最小配置回调边界。
- `task_agent/standalone.py`：独立 YAML 的校验、发现、宿主适配和一次性自举。
- `deephole_client/opencode_integration.py`：DeepHole 2.0 全局 workspace、SKILL、MCP 与运行配置适配。
- `deephole_client/<process>/`：DeepHole 2.0 各业务过程的独立目录；过程只通过公开的 `run_opencode_task()` 调用 Task Agent。

`task_agent/` 内不导入 DeepHole 2.0 的 `deephole_client`、`backend` 或 `mcp_server` 模块。单独复制该目录后，可以放到目标项目的 Python 导入根目录，或执行 `python -m pip install ./task_agent`；两种方式都使用 `from task_agent import run_opencode_task`，不因业务代码所在目录变化而改名。组件提供独立配置即可运行，也可由其它应用注册自己的 `OpenCodeHostBindings`。DeepHole 2.0 业务阶段只能从 `task_agent` 导入公共类型和函数，不应直接依赖 `task_service.py` 中的内部任务记录、句柄或 Session 管理方法。
