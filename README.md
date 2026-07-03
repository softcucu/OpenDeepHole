# OpenDeepHole

基于 SKILL 的 C/C++ 源码白盒审计工具。核心漏洞挖掘在用户本地 Agent 上执行，源码不离开本机，结果汇报到 Web 服务器统一展示。

## 整体架构

```
[服务器端]
  FastAPI (port 8000)
  ├── Web UI（React + Tailwind CSS）
  ├── WebSocket /api/agent/ws 接受 Agent 连接
  ├── 通过 WS 下发扫描任务（task / stop / resume）
  ├── 接收 Agent 上报的扫描事件和漏洞结果（HTTP POST）
  ├── 存储扫描历史和误报反馈
  └── 提供 Agent 下载包

[用户本地]
  opendeephole-agent（守护进程，从 Web UI 下载）
  ├── 启动后主动向服务器发起 WebSocket 连接
  ├── 发送 hello 握手，接收 welcome 确认
  ├── 等待服务器通过 WS 推送扫描任务
  ├── 收到任务后：代码索引 → 静态分析 → AI 审计
  └── 实时通过 HTTP POST 将事件和漏洞结果上报服务器
```

**交互流程：**

```
用户在 Web UI 点击「新建扫描」
  → 选择在线 Agent、填写代码路径（Agent 所在机器的路径）、选择检查项
  → 服务器通过 WebSocket 推送任务到 Agent
  → Agent 在本地执行完整扫描流程
  → 进度和结果实时显示在 Web UI
```

**源码不离开本地**：Agent 只上报漏洞分析结论，不上传源码文件。  
**误报反馈闭环**：用户在 Web UI 标记正报或误报后，选中的经验会注入 SKILL 中减少重复误判；也可将问题标为“待分析”作为人工待处理状态，该状态不进入经验库且仍可继续 AI 去误报复核；已标记问题也可以取消标记，取消后会移除该标记生成的经验并重新进入 AI 去误报候选。
**静态候选收敛、同类合并与同模式过滤**：DB 类 checker 会按本次 `code_scan_path` 在 SQL 层收敛函数范围；静态候选进入 AI 前会按 checker `family` 做函数级同类合并，并只向 OpenCode 提供“函数/变量或表达式/问题类型”的最小审计问题。AI 审计确认某个同模式代表点为非问题后，可通过 `pattern_filter` 自动过滤同 `vuln_type + subject + scope` 的后续候选。详细规则见下文“静态候选合并与同模式过滤”。
**git 历史问题挖掘 + 同类变体排查**：创建扫描时（git 仓库且 `git_history.enabled`）会分析 git 提交历史——逐条提交（每条一个 LLM 调用）判定是否为安全修复并提炼「历史问题模式」（根因+缺陷类型+触发条件的抽象描述），再对每条模式派一个 agent 在全仓搜索同类未修复站点，命中的作为新候选（带「同类变体来源」`variant_of`）并入 AI 审计。挖掘出的历史问题模式在扫描详情页「git 历史问题模式」面板展示。相关配置见 `git_history`（`max_commits`/`since`/`paths`/`variant_hunt`）。

**AI 去误报（扫描完成自动触发，历史/校验匹配 + 三阶段辩论，二元定级）**：扫描完成且存在已确认漏洞时**自动发起去误报**，无需手动点击（受 `fp_review.auto_on_complete` 控制，默认开启；仅在该扫描尚无去误报任务时触发，避免重复复核）。扫描详情页顶部「AI去误报」按钮仍保留，可手动重跑或补跑未复核项。FP 复核先运行 `history_match` 阶段——判断候选能否与某条历史问题模式（同根因）或其它函数里把校验做对了的调用站点对应上；**能对应上则直接判定 high 并跳过三阶段对抗辩论**，报告中以「对应修复/校验」字段（`match_type` history/validation + `match_reference`）回溯到对应的历史问题或正面对照。对应不上才进入 `prove-bug`、`prove-fp`、`final-judge` 三阶段辩论（各阶段通过本地 Markdown artifact 文件交接；`prove-bug` 判定非问题时正式早退，记录"可能误报"）。去误报定级简化为二元：命中匹配或论证为外部可触发 → **high**，其余一律 → **low**。阶段结束后页面即可查看论证；阶段未写工件或未提交结论会按配置重试并展示失败原因，复核结束后无最终结论显示"复核失败"。复核按模型池容量并发执行并同时高亮所有进行中的行；Agent 断线重连后复核任务自动重新挂接，不会被误判为已停止。
**漏洞报告导出**：对每一个 AI 判定为「是问题」的扫描项可单独导出 Markdown 报告（含元信息、描述、AI 分析及去误报三阶段论证）；扫描详情页顶部「导出报告」可将本次所有确认为问题的漏洞各自导出为 Markdown 并打包为 zip。对应端点 `GET /api/scan/{id}/vulnerability/{idx}/report`（单项 Markdown）与 `GET /api/scan/{id}/report.zip`（整体 zip）。

### 静态候选合并与同模式过滤

静态扫描阶段的目标是先保留足够召回，再把重复审计成本压到 AI 调用前后两个位置：

- **Checker 内部去重**：各 analyzer 可先按自己的静态命中特征去重，例如同一 semgrep 命中、同一函数变量或同一资源表达式只产出一个 `Candidate`。公共扫描管线不依赖 analyzer 的内部规则，但要求 `Candidate.description` 保持中性、简短，`metadata.subject` 记录被审计的变量、表达式、函数或资源对象，`metadata.problem` 记录问题类型。
- **静态同类合并**：`static_dedup: true` 时，Agent 在所有静态候选和 git 同类变体候选汇总后，按 `(family, file, function)` 分组。`family` 来自 `checker.yaml`，未配置时使用 checker 名称；因此 `npd`、`mp_npd`、`npd_funcret` 等可配置成同一 `family`，在同一文件同一函数里只保留一个代表候选进入 AI。
- **代表点选择**：合并前会先按 checker 候选数量从少到多排序，同一 checker 内保持原有产出顺序；每个分组取排序后的第一个候选作为代表点。被合并候选的 `vuln_type`、`subject`、`file`、`line` 会写入代表点的 `metadata.merged_from`，所有非空 `subject` 会合并回代表点的 `metadata.subject`，并重写为最小化描述。
- **缓存与恢复边界**：合并后的候选会写回本次扫描工作目录的 `candidates.json`，后续函数源码快照、总候选数、断点恢复都以合并后的候选为准；重试未完成候选时不重新做静态同类合并。
- **同模式 key**：`pattern_filter.enabled: true` 时，AI 审计前为每个候选计算模式 key。只有存在 `metadata.subject` 的候选才可传播过滤；key 为 `(vuln_type, subject, scope)`。`scope` 由配置决定：`directory` 表示同目录（默认），`file` 表示同文件，`repo` 表示全仓。
- **代表点排除方式**：进入 AI 审计队列前会按模式 key 做轮转排序，尽量先让每种模式都有代表点被审计。某个候选实际调用 AI 后，只有结果为 `confirmed=false` 且 `ai_verdict == "not_confirmed"`，才把该模式加入已否决集合；超时、无结果、异常或确认存在问题都不会传播排除。
- **后续候选处理**：后续候选开始处理时，如果命中已否决模式，会跳过 LLM 调用，直接上报一条 `confirmed=false`、`ai_verdict="filtered_same_pattern"` 的结果，分析文本标记为“同模式代表点已被 AI 审计否决，自动过滤（未调用 LLM）”，并记录为已处理，保证进度和恢复状态一致。

内置 checker 当前的 `subject` 取值如下。只有“写入 `metadata.subject`”列为“是”的 checker，才会在 AI 否决后触发同模式过滤；其他 checker 即使描述里有类似 subject 的文本，也会被视为不可传播的独立候选。

| Checker | 写入 `metadata.subject` | 当前 subject 取值方式 |
|---------|--------------------------|------------------------|
| `npd` | 是 | 被解引用且缺少判空的变量名 `var_name` |
| `chain_npd` | 是 | 链式指针表达式 `expr_text`，例如 `ctx->a->b` |
| `oob` | 是 | 函数名 `func_name`，这是函数级 OOB 候选 |
| `sensitive_clear` | 是 | 疑似敏感变量名去重后用逗号拼接 |
| `safe_mem_oob` | 否 | 描述中使用 `call_name`，否则 `dst_expr`，否则“安全内存函数调用” |
| `loop_mut_idx_oob` | 否 | 描述中使用循环变化索引 `idx_expr`，否则“循环索引” |
| `bufoverflow` | 否 | 描述中依次取 `idx_expr`、`field_name`、`buf_name`、`ptr_name`、`type_name`，否则“缓冲区访问” |
| `intoverflow` | 否 | 描述中使用可疑整数运算 `arith_expr`，否则危险使用点 `sink_expr`，否则“整数运算” |
| `mp_npd` | 否 | 描述中使用多层指针 `ptr_expr`，否则 `root->field1`/`root`，否则“多层指针” |
| `npd_funcret` | 否 | 描述中使用接收返回值或输出参数赋值的指针 `ptr_name` |
| `memleak` | 否 | 函数级分组候选，描述中列出该函数内多个泄漏位置和变量 |
| `resleak` | 否 | 描述中使用 cppcheck 资源符号 `symbol`，或锁类资源类型 `res_types` |
| `multi_ptr_leak2` | 否 | 描述中使用释放调用点、释放实参、结构体和指针成员列表 |
| `mp_resouce_leak` | 否 | 描述中依次取多层成员 `field_expr`、资源获取 `acq`、根对象 `root`，否则“资源成员” |
| `double_free` | 否 | 描述中依次取 `ptr_name`、`obj_name->field_name`、`field_name`、`obj_name`，否则“指针/资源” |
| `inf_loop` | 否 | 描述中使用循环控制变量 `loop_var`；没有控制变量时只按函数/规则类别描述 |

## 快速开始

### 部署服务器

**Docker（推荐）：**

```bash
docker-compose up --build
```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled[, mode, skill_name]
├── SKILL.md        # opencode 模式必须：opencode skill 定义
├── prompt.txt      # api 模式必须：LLM 系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

访问 `http://localhost:8000`

| Checker | 说明 | 模式 | 静态分析器 |
|---------|------|------|-----------|
| `npd` | 空指针解引用 (NPD) | opencode | 有（tree-sitter AST 分析） |
| `oob` | 数组/缓冲区越界 (OOB) | opencode | 有 |
| `safe_mem_oob` | 安全内存函数越界 (SAFE_MEM_OOB) | opencode | 有（semgrep 高风险规则） |
| `loop_mut_idx_oob` | 循环索引/未校验循环上界越界 (LOOP_MUT_IDX_OOB) | opencode | 有（semgrep 宽召回规则） |
| `memleak` | 异常分支内存泄漏 (MEMLEAK) | opencode | 有（tree-sitter 路径分析） |
| `intoverflow` | 整数翻转/溢出 (INTOVFL) | opencode | 有（多阶段追踪） |
| `sensitive_clear` | 敏感信息未清零 (SENSITIVE_CLEAR) | opencode | 有（启发式敏感变量筛选，函数级审计） |
| `resleak` | 全类型资源泄露 (RESLEAK) | opencode | 有 |

**第 1 步：下载安装包**

打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`，解压到本地目录。

**第 2 步：配置 agent.yaml**

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 显示名称（显示在新建扫描的下拉列表中），留空则使用主机名
agent_name: "my-agent"

# 用户归属 token（下载 Agent 时自动填入，勿手动修改）
owner_token: ""

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"

# CLI 审计工具配置（供 mode: opencode 的检查项使用）
# tool 可选: nga, opencode, hac, claude
opencode:
  tool: "opencode"
  executable: "opencode"
  model: ""       # 兼容字段：未配置 models 时使用；留空则使用 CLI 默认模型
  timeout: 1200
  max_retries: 2
  # 可选：多模型池。配置后由模型池统一决定模型、能力、时间和并发。
  models:
    - id: "fast"
      model: "fast-model"
      use_default_model: false
      capability: "low"      # low | medium | high
      weight: 3              # 权重越高，空闲时越优先分配
      max_concurrency: 2
      enabled: true
      time_windows:          # Agent 本地每日时间；空数组表示全天可用
        - start: "09:00"
          end: "18:00"
    - id: "deep"
      model: "deep-model"
      use_default_model: false
      capability: "high"
      weight: 1
      max_concurrency: 1
      enabled: true
      time_windows: []
    - id: "default"
      model: ""
      use_default_model: true # 不传 --model，使用 CLI 默认模型
      capability: "high"
      weight: 1
      max_concurrency: 1
      enabled: true
      time_windows: []

# OpenCode/兼容 CLI 总并发数：所有模型合计运行数不得超过该值，
# 同时受单模型 max_concurrency 和每日使用时间限制。
opencode_concurrency: 3

# AI 去误报 CLI 配置可选；不配置则继承上面的审计工具和模型
# fp_review_cli:
#   tool: "claude"
#   executable: "claude"
#   model: ""      # 兼容字段：未配置 models 时使用
#   timeout: 1200
#   max_retries: 2
#   models:
#     - id: "judge"
#       model: "high-capability-model"
#       capability: "high"
#       weight: 1
#       max_concurrency: 1
#       enabled: true
```

> 每个检查项的调用方式（`api` 或 `opencode`）在其 `checker.yaml` 中独立配置，无需全局 `mode` 选项。
> 每个检查项可在 `checker.yaml` 中设置 `model_capability: low|medium|high` 指定最低模型能力；未配置时默认为 `any`，AI 去误报默认优先使用高能力模型。
> 模型池的 `time_windows` 使用 Agent 本地每日时间，支持跨午夜窗口；空数组表示全天可用。若存在满足能力要求但当前不在时间窗口内的模型，任务会排队等待，而不会降级使用当前时段的低能力模型。
> 扫描详情页顶部的「模型看板」会展示当前扫描的 OpenCode 模型池统计，包括每个模型累计任务、成功/失败/超时/取消次数、平均耗时、运行中和排队数；页面刷新后会读取最近一次上报快照。
> Agent 启动并连接服务器后，也可以在 Web UI 的「客户端」页面中直接保存或校验 LLM API 配置，并在独立「模型池」页签中配置默认模型、能力、每日使用时间和并发；保存后的配置会写回 `agent.yaml`。

**第 3 步：确认代码索引工具**

代码索引依赖 Universal Ctags。Windows Agent 下载包已内置 `ctags-p6.2.20260517.0-x64/ctags.exe`，`run_agent.bat` 会优先使用包内版本；在 Git Bash/MSYS/Cygwin 中运行 `run_agent.sh` 时也会优先使用包内版本。缺少可用 `ctags` 或 `ctags` 不支持 JSON 输出时 Agent 会停止并提示处理方式，不会回退到旧索引方式。

Linux / macOS 仍需提前用系统包管理器安装 Universal Ctags：

```bash
# Debian / Ubuntu
sudo apt install universal-ctags

# macOS
brew install universal-ctags
```

**第 4 步：启动 Agent 守护进程**

```bash
# Linux / macOS
chmod +x run_agent.sh
./run_agent.sh

# Windows
run_agent.bat
```

启动成功后，终端输出类似：

```
OpenDeepHole Agent
  Name    : my-agent
  Server  : http://your-server:8000

  Connected via WebSocket, agent_id: a1b2c3d4...
```

Agent 通过 WebSocket 保持长连接，等待服务器推送任务。
启动后的 Agent 支持扫描前自动更新运行时代码。服务端更新 `agent/`、`backend/`、`code_parser/`、`mcp_server/`、包内 Windows ctags 目录或 `requirements-agent.txt` 后，旧 Agent 会在下次启动扫描前下载最新 runtime 并重启继续执行该扫描；runtime 更新包会携带快照 manifest，用于校验下载 zip 的文件集合和逐文件 hash；`checkers/` 更新会在创建或恢复扫描时按选中检查项同步到 Agent，不会触发 Agent 重启；如果更新了 `run_agent.sh` 或 `run_agent.bat`，需要重新下载 Agent 包。

**第 4 步：在 Web UI 创建扫描任务**

1. 点击右上角「新建扫描」
2. 从下拉列表选择已在线的 Agent
3. 填写代码路径（Agent 所在机器上的绝对路径，如 `/home/user/myproject`）
4. 选择要运行的检查项，点击「开始扫描」
5. 扫描进度实时显示在当前页面

### Agent 启动参数

```
./run_agent.sh [选项]

选项：
  --server URL        覆盖 agent.yaml 中的 server_url
  --name NAME         覆盖 Agent 显示名称
  --config FILE       指定配置文件路径（默认 ./agent.yaml）
```

### 停止与恢复扫描

- **停止**：在扫描详情页点击「停止扫描」，服务器直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。
- **恢复**：在扫描列表页点击「恢复」，服务器通知 Agent 继续同一扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。
- **配置更新**：运行中的扫描收到新的 Agent 配置后，不会中断当前候选点；从下一个候选点开始使用最新 LLM API、AI CLI 工具和代理配置。

## 误报反馈机制

1. 在 Web UI 的漏洞列表或经验库中提交正报/误报反馈，或在漏洞列表中标记“待分析”
2. 经验库中打勾的反馈会记录到本次扫描的 `feedback_ids`
3. 已选反馈按漏洞类型注入到对应 SKILL 文件的「历史用户经验」章节
4. LLM 在分析同类候选时参考这些经验，校验并减少重复误判
5. “待分析”只保存为漏洞人工状态，不生成经验库反馈、不注入 SKILL，也不会阻止该问题继续进入 AI 去误报或续扫候选
6. 已人工标记的问题可单条或批量取消标记；取消后会删除该标记生成的反馈、从本次扫描的 `feedback_ids` 中移除，并在下次 AI 去误报时重新复核
7. AI 去误报复核在**扫描完成且存在已确认漏洞时自动触发**（无需手动点击，受 `fp_review.auto_on_complete` 控制），也可在扫描详情页手动重跑；复核会依次运行 `prove-bug`、`prove-fp`、`final-judge` 三个阶段；各阶段将 Markdown 写入本次复核的 artifact 目录，后续阶段按文件路径读取，避免把完整论证塞进 prompt
8. **正方早退**：`prove-bug` 提交 `confirmed=false`（非问题）时正式早退，直接以正方理由记录"可能误报"最终结果并推送前端，跳过 `prove-fp` 和 `final-judge`；只有正方判定为真实问题时才进入后两个阶段，此时最终结论采用 `final-judge` 的 `submit_result`
9. 每个阶段结束后，扫描详情页会实时展示对应 Markdown；复核按模型池容量并发执行，所有正在复核的项同时高亮。详情页为**左右主从布局**：左侧为精简问题列表（文件:行 / 函数 / 类型 / 严重级别 + AI、去误报状态徽章及变体/命中标记，顶部带严重级别与类型筛选），右侧为选中问题详情，描述、AI 分析与去误报各阶段输出均以 Markdown 渲染。页面**默认只显示「问题」**——AI 审计未确认或去误报判为误报的候选默认隐藏，顶部「显示全部」开关可查看
10. 阶段产物必须同时包含非空 Markdown artifact 和 `submit_result`；缺失时会按 `fp_review_cli.max_retries` 重试（重试 prompt 会强调即使非问题也必须写工件并提交），仍失败则停止该候选的后续 FP 复核阶段并保留已有有效结论，前端在复核结束后显示"复核失败"而非一直"复核中"；阶段输出会持久化，页面刷新后仍可查看
11. **断线续挂**：Agent WebSocket 重连时会在 hello 中上报仍在运行的 FP 复核任务，后端重新挂接并恢复 running 状态；progress/result/stage-output 上报也会自动把因断连误标为 error 的复核任务恢复为 running

## 插件式 Checker 架构

漏洞类型以插件形式组织在 `checkers/` 目录下，添加新类型无需修改代码：

```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled, mode
├── SKILL.md        # opencode 模式必须；定义 AI 分析技巧
├── prompt.txt      # api 模式可选；自定义系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

**checker.yaml 格式：**

```yaml
name: uaf
label: UAF
description: "Use-After-Free 检测"
enabled: true
visibility: public    # public: 所有用户可见；admin: 仅管理员测试可见
# family: uaf          # 可选，同类 checker 的跨规则去重家族；未配置时使用 name
# mode: opencode       # 可选，默认 opencode；设为 api 则使用 prompt.txt + LLM 直接调用
# skill_name: uaf-audit # 可选，opencode 模式下自定义 skill 名称
# model_capability: high # 可选，any/low/medium/high；未配置默认 any
```

每个 Checker 独立配置 `mode`，同一次扫描中不同 Checker 可使用不同调用方式。
同一 `family` 的候选会在静态阶段按同文件同函数做跨规则合并，只保留一个代表候选进入 AI 审计；代表点和同模式过滤规则见上文“静态候选合并与同模式过滤”。
新增或修改 `checkers/` 下的 checker 后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描目录。测试阶段建议设置 `visibility: admin`，只有管理员能看到并启动该 checker；测试完成后改为 `visibility: public` 即可对所有用户开放。

**内置 Checker：**

| Checker | 说明 |
|---------|------|
| `npd` | 空指针解引用 (Null Pointer Dereference) |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) |
| `safe_mem_oob` | 安全内存函数越界（dst/dstsz 不匹配） |
| `loop_mut_idx_oob` | 循环变化索引或未校验循环上界导致的数组/指针越界 |
| `intoverflow` | 整数翻转/溢出 |
| `memleak` | 内存泄漏 |
| `sensitive_clear` | 敏感信息未清零（启发式筛选敏感变量所在函数，按函数审计生命周期清零状态） |
| `resleak` | 全类型资源泄露（文件/套接字/锁/内存映射等） |

### 在 Web UI 在线创建用户 SKILL

除直接在 `checkers/` 目录开发内置 Checker 外，登录用户也可以在 Web UI 的 **SKILL 市场** 中创建项目级 SKILL。用户创建的 SKILL 会保存到服务端 `storage.user_skills_dir`，所有用户可在新建扫描页选择使用。

创建流程：

1. 打开「SKILL 市场」，点击「在线创建」
2. 填写 **标识**、名称、描述、输入和单次运行超时时间
3. 可选上传 `references/`、`scripts/`、`assets/` 资料
4. 点击「生成草稿」，检查并编辑生成的 `SKILL.md` 和 `SCENARIOS.md`
5. 点击「导入 SKILL 市场」，导入后即可在新建扫描页选择

用户填写的 **标识** 会作为 checker 名称和目录名，不再由系统自动分配 `skill-xx` 编号。标识只能包含字母、数字、下划线，必须以字母或下划线开头，最长 64 个字符，并且不能与现有内置 Checker 或用户 SKILL 重名。

用户创建的 SKILL 采用项目级审计模式：

- 后端会在导入时固定拼接 MCP 工具使用、Markdown 报告保存和写权限约束，用户主要维护审计目标、判断标准和场景说明
- 运行时 Agent 会把 SKILL 和上传资料同步到本次扫描的隔离工作区，项目源码保持只读
- SKILL 只能把 Markdown 报告写入指定 `REPORT_DIR`，扫描完成后报告会同步到服务端，并在扫描详情页的 SKILL 报告入口展示

权限和管理规则：

- SKILL 市场、新建扫描页会展示用户创建 SKILL 的创建者
- 创建者可以删除自己创建的 SKILL
- 管理员可以删除任意用户创建的 SKILL，包括历史上没有创建者字段的旧 SKILL
- 内置 `checkers/` 目录下的 Checker 不能通过 Web UI 删除

### 添加新 Checker

**第 1 步：创建目录和元数据**

```bash
mkdir checkers/mycheck
```

`checkers/mycheck/checker.yaml`：

```yaml
name: mycheck
label: MYCHECK
description: "我的自定义漏洞检测"
enabled: true
mode: "api"
```

**第 2 步（api 模式）：编写 prompt.txt**

```
你是专业的 C/C++ 漏洞审计专家。请分析以下函数是否存在 XXX 漏洞...
```

**第 2 步（opencode 模式）：编写 SKILL.md**

参考 `checkers/npd/SKILL.md`，定义分析步骤和可用 MCP 工具。

**第 3 步（可选）：编写 analyzer.py**

```python
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
from backend.analyzers.base import BaseAnalyzer, Candidate, scoped_functions

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    vuln_type = "mycheck"  # 必须与 checker.yaml 的 name 一致

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []
        candidates = []
        functions = scoped_functions(db, project_path)
        total = len(functions)
        for idx, func in enumerate(functions):
            # 进度回调（可选，用于前端进度条）
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)
            body = func["body"] or ""
            if not body:
                continue
            # ... 分析逻辑 ...
            candidates.append(Candidate(
                file=func["file_path"],
                line=func["start_line"],
                function=func["name"],
                description=f"函数 `{func['name']}` 中变量/表达式 `target` 是否存在 XXX 问题，请审计确认。",
                vuln_type=self.vuln_type,
                metadata={"subject": "target", "problem": "XXX"},
            ))
        return candidates
```

**约定：**

- 类名**必须**是 `Analyzer`
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 字段一致
- `find_candidates()` 接收项目根目录路径，返回 `Iterable[Candidate]`（列表或 generator 均可）
- 可以 `from backend.analyzers.base import BaseAnalyzer, Candidate` 一次性导入所需类
- 使用 DB 的 analyzer 应优先调用 `scoped_functions(db, project_path)`，让 `code_scan_path` 子目录扫描在 SQL 层收敛函数范围；无法判定范围时会自动退回全量。
- `Candidate.description` 应尽量只包含必要审计问题（函数、变量/表达式、问题类型），不要写静态分析规则、命中路径或工具细节；`metadata.subject` 用于跨规则合并和同模式过滤。

**扫描前内存 API 缓存：**

扫描在 checker 静态分析开始前会检查项目根目录中的 `memory_api_pairs.json`。如果文件已存在，会直接复用；如果不存在，会先分析项目中的底层堆内存申请/释放函数和宏，批量调用 opencode 判断候选并生成该 JSON 文件，然后再开始后续扫描。该过程只读取 `code_index.db` 和源码，不修改数据库。

内存类 checker 可读取该文件中的 `allocators`、`deallocators` 和 `pairs` 来识别项目自定义的 malloc/free 薄封装；结构体/对象专用 destroy/free、复杂 cleanup/refcount 生命周期函数和文件/socket/mmap 等非堆资源不会作为底层内存 API 保留。

**第 4 步：本地测试 Checker（无需后端）**

```bash
# 只运行静态分析自测：校验 checker.yaml、Analyzer 加载、代码索引和候选点输出
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --min-candidates 1

# 输出 JSON，便于在脚本或 CI 中断言
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json

# 直接写入格式化 UTF-8 JSON 文件，中文 description 不会被转义成 \uXXXX
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json-output /tmp/mycheck-candidates.json

# 精确断言候选点数量
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --expect-candidates 3

# 可选：对前 1 个候选点运行真实 AI 审计（会使用 agent.yaml 中的 LLM/AI CLI 配置）
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --audit --audit-limit 1 --config agent.yaml
```

本地测试命令不依赖后端、Web UI 或在线 Agent。默认会在被测项目目录下重建 `code_index.db`，与 Agent 扫描时的索引位置一致；如只想把索引写到临时位置，可加 `--index-db /tmp/mycheck-code_index.db`。`--json-output` 会直接生成缩进格式化的 UTF-8 JSON，避免后续 `json.tool` 把中文转义。代码索引同样需要本机已安装 Universal Ctags。

开发阶段即使 `checker.yaml` 中设置了 `enabled: false`，本地测试命令也会临时启用该 checker 进行自测，并输出提示；线上扫描入口仍会遵循 `enabled` 和 `visibility` 配置。`--audit` 会实际调用模型或 opencode，请先确认 `agent.yaml` 配置可用，并用 `--audit-limit` 控制成本。

新增或修改 `checkers/` 下的 checker 后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描目录，创建扫描时也会把选中的 checker 同步到 Agent。

**CodeDatabase API 参考（`code_parser/code_database.py`）：**

当 `db` 参数非 `None` 时，可通过以下方法查询预构建的代码索引。所有查询方法返回 `list[sqlite3.Row]`，通过 `row["field_name"]` 访问字段。

| 方法 | 说明 | 返回字段 |
|------|------|---------|
| `db.get_all_functions()` | 获取所有函数（按文件和行号排序） | function_id, name, signature, return_type, start_line, end_line, is_static, linkage, body, file_path |
| `db.get_functions_by_path_prefix(prefix)` | 获取指定索引相对路径前缀下的函数 | 同上 |
| `db.get_functions_by_name(name)` | 按名称精确匹配函数 | 同上 |
| `db.get_function_body(name)` | 获取第一个匹配函数的函数体 | 返回 `str \| None` |
| `db.get_calls_from_function(function_id)` | 查询指定函数发出的所有调用 | call_id, caller_function_id, callee_name, callee_function_id, line, column, file_path |
| `db.get_call_sites_by_name(callee_name)` | 查询指定函数名的所有被调用点 | 同上 + caller_name |
| `db.get_structs_by_name(name)` | 按名称查询结构体/类定义，短名可匹配 C++ 限定名 | struct_id, name, start_line, end_line, definition, file_path |
| `db.get_global_variables_by_name(name)` | 按名称查询全局变量 | global_var_id, name, start_line, end_line, is_extern, is_static, definition, file_path |
| `db.get_global_variable_reference_by_name(name)` | 查询全局变量的所有引用点 | reference_id, variable_name, function_id, line, column, context, access_type, file_path, function_name |

**tree-sitter 辅助工具（`code_parser/code_utils.py`）：**

如需在 analyzer 中对函数体进行 AST 分析，可结合 tree-sitter 和以下辅助函数：

| 函数 | 说明 |
|------|------|
| `find_nodes_by_type(root_node, node_type, k=0)` | 递归查找所有指定类型的节点（DFS，最大深度 100） |
| `get_child_node_by_type(root_node, node_type: list)` | 返回第一个类型匹配的直接子节点 |
| `get_child_nodes_by_type(root_node, node_type: list)` | 返回所有类型匹配的直接子节点 |
| `get_child_field_text_by_type(root_node, field_name, node_type: list)` | 获取指定字段的文本（仅当字段节点类型匹配时） |
| `get_child_field_text(root_node, field_name)` | 获取指定字段的文本 |

使用示例：

```python
import tree_sitter_cpp
from tree_sitter import Language, Parser
from code_parser.code_utils import find_nodes_by_type

_CPP = Language(tree_sitter_cpp.language())
parser = Parser(_CPP)

tree = parser.parse(func_body.encode())
# 查找所有函数调用节点
for call in find_nodes_by_type(tree.root_node, "call_expression"):
    callee = call.child_by_field_name("function")
    if callee:
        print(callee.text.decode())
```

**常见模式：**

*1. 遍历所有函数并分析*

```python
from backend.analyzers.base import scoped_functions

for func in scoped_functions(db, project_path):
    name = func["name"]
    body = func["body"] or ""
    file_path = func["file_path"]
    start_line = func["start_line"]
    # 对函数体进行模式匹配或 AST 分析...
```

*2. 查询调用关系*

```python
# 查找所有 malloc 调用点
for call in db.get_call_sites_by_name("malloc"):
    print(f"{call['file_path']}:{call['line']} — 调用者: {call['caller_name']}")

# 查找某函数内部调用的所有函数
for call in db.get_calls_from_function(func["function_id"]):
    print(f"  调用了 {call['callee_name']} at line {call['line']}")
```

*3. Generator 模式（流式产出）*

`find_candidates` 可返回 `Iterator[Candidate]`，通过 `yield` 流式产出候选项，让 LLM 提前开始处理：

```python
from collections.abc import Iterator

def find_candidates(self, project_path: Path, db=None) -> Iterator[Candidate]:
    if db is None:
        return
    for func in scoped_functions(db, project_path):
        # ... 分析 ...
        yield Candidate(file=func["file_path"], ...)
```

*4. 进度回调*

```python
functions = scoped_functions(db, project_path)
total = len(functions)
for idx, func in enumerate(functions):
    if self.on_file_progress and idx % 20 == 0:  # 每 20 个函数更新一次
        self.on_file_progress(idx + 1, total)
```

*5. 不依赖 db 的分析*

也可跳过 db，直接遍历文件系统进行自定义解析（如 memleak checker）：

```python
def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
    candidates = []
    for src in project_path.rglob("*.c"):
        source = src.read_bytes()
        tree = self._parser.parse(source)
        # 自定义 AST 分析...
    return candidates
```

**实现建议：**

- 推荐使用 `scoped_functions(db, project_path)` 查询而非直接遍历全量函数或文件系统（性能更好，且与 MCP Server 共享同一索引）
- Generator 模式适合耗时较长的分析器，可让 LLM 提前开始处理已发现的候选项
- `on_file_progress` 回调用于前端进度条显示，建议在循环中定期调用
- `description` 字段会作为初始 prompt 的一部分传递给 AI，应保持中性、简短，只描述需要审计确认的问题
- `mode: api` 的 checker 使用 `prompt.txt` 而非 `SKILL.md`，适用于无需 MCP 工具的场景；需要 MCP 辅助复核的 checker 应使用 `mode: opencode`
- 返回空列表是合法的，表示未找到候选点

### 服务端 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8000

storage:
  projects_dir: "../OpenDeepHoleData/projects"
  scans_dir: "../OpenDeepHoleData/scans"
  user_skills_dir: "../OpenDeepHoleData/user_skills"

logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

`storage` 中的相对路径会按 `config.yaml` 所在目录解析；默认会落到 OpenDeepHole 项目上层的 `OpenDeepHoleData/`。

### Agent agent.yaml

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 显示名称（留空则使用主机名）
agent_name: ""

# 用户归属 token（下载 Agent 时自动填入，勿手动修改）
owner_token: ""

# 代理跳过列表，逗号分隔
no_proxy: "10.0.0.0/8"

# 要运行的检查项，留空则运行全部已启用的检查项
checkers: []

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"
  temperature: 0.1
  timeout: 300
  max_retries: 3
  stream: false

# CLI 审计工具配置（供 mode: opencode 的检查项使用）
# tool 可选: nga, opencode, hac, claude
opencode:
  tool: "opencode"
  executable: "opencode"
  model: ""      # 兼容字段：未配置 models 时使用；留空则使用 CLI 默认模型
  timeout: 1200
  max_retries: 2
  models: []     # 可配置多个模型，字段同上方快速开始示例

# OpenCode/兼容 CLI 总并发数；位置审计、扫描前 API 识别和 AI 去误报都会复用。
# 配置 models 后，该值仍是所有模型合计运行数的硬上限
opencode_concurrency: 1

# 静态候选跨规则去重：同 family、同文件、同函数只保留一个代表候选
static_dedup: true

# AI 审计同模式批量过滤：代表点被 AI 否决后，跳过同 vuln_type/subject/scope 后续候选
pattern_filter:
  enabled: true
  scope: "directory"  # directory | file | repo

# AI 去误报 CLI 配置（可选；不配置则继承上面的审计工具和模型）
# fp_review_cli:
#   tool: "claude"
#   executable: "claude"
#   model: ""      # 兼容字段：未配置 models 时使用
#   timeout: 1200
#   max_retries: 2
#   models: []

# AI 去误报流程配置
fp_review:
  auto_on_complete: true  # 扫描完成且存在已确认漏洞时自动触发去误报（无需手动点击）
```

CLI 工具调用约定：

- `nga` / `opencode`：每个扫描或复核任务使用隔离的 OpenCode 配置目录，并通过 `OPENCODE_CONFIG_CONTENT` 在 serve 启动时注入当前任务的 MCP URL、SKILL 路径和权限配置；API `directory` 始终指向真实项目根目录，不复制源码。
- `nga` / `opencode` 默认通过 serve API 调用，单个 Agent 复用一个固定端口的 serve 进程；默认端口为 `4096`，可用 `OPENCODE_SERVE_PORT` 覆盖。发送 message 时不显式传 `tools`，由 OpenCode 按启动配置和 agent 默认能力暴露内置工具与 MCP 工具；配置内容变化时会等当前 session 结束后重启 serve。
- OpenCode/nga serve 会话会保留在真实项目目录下，便于用 `opencode session list` 查看历史；Agent 只在取消或超时时 abort session，不在正常完成后删除 session。
- `hac`：按 Gemini CLI 兼容方式运行，Agent 会在任务隔离配置目录写入 `.gemini/settings.json` 的 MCP server，并把技能复制到 `.gemini/skills/`。
- `claude`：按 Claude Code 兼容方式运行，Agent 会在任务隔离配置目录写入 `.claude/opendeephole-mcp.json` 并通过 `--mcp-config` 注入 MCP，同时把技能复制到 `.claude/skills/`。

OpenCode 模型池统计：

- 位置审计、扫描前内存 API 识别和 AI 去误报都会通过统一调用入口累计模型池统计。
- 配置模型池后，`opencode_concurrency` 是所有模型合计运行数的硬上限；每个模型还会受自己的 `max_concurrency` 和 `time_windows` 限制。
- 模型行可设置 `use_default_model: true`，表示参与模型池调度但调用 CLI 时不传 `--model`。
- 扫描详情页点击「模型看板」可以查看每个模型的累计任务、成功/失败/超时/取消计数、平均耗时、当前运行数和当前排队数。
- Agent 会在模型池状态变化时上报快照，无变化时只保留低频心跳；服务端会保存到扫描记录中，页面刷新或重新进入扫描详情后会显示最近一次快照。

## 本地开发

```bash
# 后端（含热重载）
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 前端开发服务器（代理到 localhost:8000）
cd frontend
npm install
npm run dev

# 构建前端
npm run build

# 查看日志
tail -f logs/opendeephole.log
```

> **注意：** Agent 需要运行支持 checker 同步的新版本。之后新增或修改 checker 时，只要点击开始扫描，后端会把本次选中的 checker 同步到 Agent，无需重启后端或 Agent，也不会触发 Agent runtime 自更新重启。

## 数据存储位置

Agent 运行时会在以下位置产生数据：

| 位置 | 内容 | 生命周期 |
|------|------|---------|
| `<项目目录>/code_index.db` | tree-sitter 代码索引（函数/结构体/调用关系） | 持久保留，后续扫描复用 |
| `~/.opendeephole/scans/<scan_id>/` | 扫描工作目录（candidates.json、config.yaml、agent.log、隔离 OpenCode 配置目录） | 扫描成功后自动删除；取消/出错时保留用于恢复 |
| `~/.opendeephole/fp_feedback.json` | 本地误报反馈缓存 | 持久保留 |
| `~/.opendeephole/fp_reviews/<review_id>/` | 误报复审临时目录 | 复审完成后自动删除 |

服务端数据：

| 位置 | 内容 |
|------|------|
| `../OpenDeepHoleData/scans/` | 扫描结果 JSON（submit_result 输出）和 `scans.db` |
| `../OpenDeepHoleData/projects/` | 服务端上传扫描的项目缓存 |
| `logs/opendeephole.log` | 服务端日志（滚动，默认 10MB × 5 份） |

> **注意：** `code_index.db` 直接保存在被扫描的代码仓目录下。对于大型代码仓，该文件可能有几十到几百 MB。如需清理，直接删除项目目录下的 `code_index.db` 即可，下次扫描会自动重建。

## 项目结构

```
OpenDeepHole/
├── agent/                 # 本地 Agent Python 包
│   ├── config.py          # agent.yaml 配置加载
│   ├── main.py            # 守护进程入口（WebSocket 连接 + 自动重连）
│   ├── server.py          # WebSocket 命令处理（task/stop/resume）
│   ├── task_manager.py    # 任务生命周期管理（创建/停止/恢复）
│   ├── scanner.py         # 完整扫描流程（索引→静态分析→AI审计→上报）
│   ├── reporter.py        # 向服务器上报进度和结果
│   └── local_mcp.py       # CLI 审计模式：本地启动 MCP Server
├── checkers/              # 插件目录（每种漏洞类型一个子目录）
│   ├── npd/               # checker.yaml + SKILL.md/prompt.txt + analyzer.py
│   ├── oob/
│   ├── safe_mem_oob/
│   ├── memleak/
│   ├── intoverflow/
│   ├── sensitive_clear/
│   └── resleak/
├── code_parser/           # 共享 C/C++ 代码解析器
│   ├── code_database.py   # SQLite 代码索引（函数/结构体/全局变量/调用关系）
│   ├── cpp_analyzer.py    # tree-sitter C++ 解析器
│   ├── code_utils.py      # tree-sitter 节点遍历辅助函数
│   └── code_struct.py     # 解析结果数据类
├── frontend/              # React + TypeScript + Vite + Tailwind CSS
├── backend/
│   ├── api/
│   │   ├── agent.py       # Agent WebSocket 连接、命令下发、结果接收、下载包
│   │   ├── scan.py        # 扫描管理 API（新建/停止/恢复/查询）
│   │   ├── feedback.py    # 误报反馈 CRUD
│   │   ├── checkers.py    # Checker 列表 API
│   │   └── auth.py        # 用户认证与管理 API
│   ├── registry.py        # Checker 自动发现与注册
│   ├── analyzers/base.py  # 静态分析器基类
│   └── opencode/          # AI CLI + LLM API 集成
├── mcp_server/            # MCP Server（Agent CLI 审计模式本地启动）
├── agent.yaml             # Agent 配置模板
├── run_agent.sh           # Agent 守护进程启动脚本（Linux/macOS）
├── run_agent.bat          # Agent 守护进程启动脚本（Windows）
├── requirements-agent.txt # Agent 最小依赖
├── config.yaml            # 服务端全局配置
├── start.sh               # 服务端一键启动脚本
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
