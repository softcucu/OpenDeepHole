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
**git 历史问题挖掘 + 同类变体排查（当前硬禁用）**：默认扫描链路在完成代码索引和工作区准备后，会并行启动威胁分析和静态分析；静态分析完成后立即进入候选点 AI 审计，威胁分析结果生成后独立上报展示，并在扫描最终完成前收尾。git 历史问题挖掘及同类变体排查的实现代码仍保留，但当前版本不会执行该阶段，也不在 Agent 配置页面中暴露开关。

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
| `loop_mut_idx_oob` | 否 | 描述中使用 copy_from_user 重点长度变量 `len_expr`/目标变量 `dst_expr`，或循环变化索引 `idx_expr`，否则“循环索引” |
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
| `loop_mut_idx_oob` | 循环索引/copy_from_user 累加长度越界 (LOOP_MUT_IDX_OOB) | opencode | 有（semgrep 宽召回规则） |
| `memleak` | 异常分支内存泄漏 (MEMLEAK) | opencode | 有（tree-sitter 路径分析） |
| `intoverflow` | 整数翻转/溢出 (INTOVFL) | opencode | 有（多阶段追踪） |
| `sensitive_clear` | 敏感信息未清零 (SENSITIVE_CLEAR) | opencode | 有（启发式敏感变量筛选，函数级审计） |
| `resleak` | 全类型资源泄露 (RESLEAK) | opencode | 有 |

**第 1 步：下载安装包**

打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`，解压到本地目录。

**第 2 步：配置 agent.yaml**

```yaml
server_url: "http://your-server:8000"
agent_name: "my-agent"
owner_token: ""
```

下载包会自动填入 `server_url` 和 `owner_token`。首次启动并连接后，在 Web UI 的 **「Agent 配置」** 页面按机器名与 IP 选择 Agent，统一配置基础工具、显式模型池、完整 OpenCode JSONC、威胁分析、代码图谱 MCP、产品信息 MCP、漏洞挖掘、去误报和各验证环境。服务端会持久化配置并推送给在线 Agent；离线编辑会在重连后生效。

代码图谱和产品信息配置区提供手动 **「检测 MCP」**：检测只在 Agent 上执行 MCP `initialize` 和 `list_tools`，不会调用业务工具，并会展示最近结果、工具列表及 OpenCode 配置加载状态。保存 MCP 后不需要重启 Agent；没有活动 Session 时在下一次模型任务自动加载，有活动 Session 时不会中断当前任务，而是在空闲后的下一次任务加载。检测结果会持久化，Agent 离线时仍可查看带时间戳的历史结果；修改并保存 MCP 配置后，旧结果会标记为需要重新检测。

代码图谱的配置页检测只确认 MCP 服务能够握手并发现工具，不代表某个扫描项目已经生成 `.codegraph/codegraph.db`；项目索引是否就绪仍以对应扫描任务的运行日志和产物为准。

模型池必须至少包含一个已启用且填写明确 `provider/model` 的模型；不再支持“使用 CLI 默认模型”的配置行，没有显式模型时创建和续扫都会被拒绝。阶段级模型能力、模型调用超时和模型重试会覆盖具体模型行的超时/重试；漏洞验证 kwargs 中的 `run_command(..., timeout=...)` 仍只由该命令自己的超时控制，不受模型超时影响，也没有验证函数整体截止时间。

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
启动后的 Agent 支持任务执行前自动更新运行时代码。服务端更新 `agent/`（包含 `agent/product_validators/`）、`backend/`、`code_parser/`、`mcp_server/`、包内 Windows ctags 目录或 `requirements-agent.txt` 后，旧 Agent 会在下次启动扫描、恢复扫描、去误报或漏洞验证任务前下载最新 runtime 并重启后继续执行；runtime 更新包会携带快照 manifest，用于校验下载 zip 的文件集合和逐文件 hash；`checkers/` 更新仍在创建或恢复扫描时按选中检查项同步，不单独触发 runtime 重启；如果更新了 `run_agent.sh` 或 `run_agent.bat`，需要重新下载 Agent 包。

验证方法的 kwargs 契约、可选 `main()`、Agent 配置复用和无后端单独调试方式见 [`docs/vulnerability_validation.md`](docs/vulnerability_validation.md)。

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
- **配置更新**：运行中的扫描收到新的 Agent 配置后，不会中断当前 OpenCode 任务；排队任务会按新模型配置重新调度，后续任务使用最新工具、模型池和代理配置。

## 误报反馈机制

1. 在 Web UI 的漏洞列表或经验库中提交正报/误报反馈，或在漏洞列表中标记“待分析”
2. 经验库中打勾的反馈会记录到本次扫描的 `feedback_ids`
3. 已选反馈按漏洞类型注入到对应 SKILL 文件的「历史用户经验」章节
4. LLM 在分析同类候选时参考这些经验，校验并减少重复误判
5. “待分析”只保存为漏洞人工状态，不生成经验库反馈、不注入 SKILL，也不会阻止该问题继续进入 AI 去误报或续扫候选
6. 已人工标记的问题可单条或批量取消标记；取消后会删除该标记生成的反馈、从本次扫描的 `feedback_ids` 中移除，并在下次 AI 去误报时重新复核
7. AI 去误报复核在**扫描完成且存在已确认漏洞时自动触发**（无需手动点击，受 `fp_review.auto_on_complete` 控制），也可在扫描详情页手动重跑；复核会依次运行 `prove-bug`、`prove-fp`、`final-judge` 三个阶段；各阶段将 Markdown 写入本次复核的 artifact 目录，后续阶段按文件路径读取，避免把完整论证塞进 prompt
8. **正方早退**：`prove-bug` 最终 JSON 返回 `confirmed=false`（非问题）时正式早退，直接以正方理由记录"可能误报"最终结果并推送前端，跳过 `prove-fp` 和 `final-judge`；只有正方判定为真实问题时才进入后两个阶段，此时最终结论采用 `final-judge` 的最终 JSON
9. 每个阶段结束后，扫描详情页会实时展示对应 Markdown；复核按模型池容量并发执行，所有正在复核的项同时高亮。详情页为**左右主从布局**：左侧为精简问题列表（文件:行 / 函数 / 类型 / 严重级别 + AI、去误报状态徽章及变体/命中标记，顶部带严重级别与类型筛选），右侧为选中问题详情，描述、AI 分析与去误报各阶段输出均以 Markdown 渲染。页面**默认只显示「问题」**——AI 审计未确认或去误报判为误报的候选默认隐藏，顶部「显示全部」开关可查看
10. 阶段产物必须同时包含非空 Markdown artifact 和符合 schema 的最终 JSON；缺失时会先在原 Session 纠正输出，仍失败时按 Agent 配置页「去误报」策略创建新 Session 重试，耗尽后停止该候选的后续 FP 复核阶段并保留已有有效结论，前端在复核结束后显示"复核失败"而非一直"复核中"；阶段输出会持久化，页面刷新后仍可查看
11. **断线续挂**：Agent WebSocket 重连时会在 hello 中上报仍在运行的 FP 复核任务，后端重新挂接并恢复 running 状态；progress/result/stage-output 上报也会自动把因断连误标为 error 的复核任务恢复为 running

## 插件式 Checker 架构

漏洞类型以插件形式组织在 `checkers/` 目录下，添加新类型无需修改代码：

```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled, mode
├── SKILL.md        # opencode 模式必须；定义 AI 分析技巧
├── prompt.txt      # 旧 mode: api 的兼容输入，会包装成临时 OpenCode SKILL
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
# mode: opencode       # 可选；旧 api 值仅作 prompt.txt 兼容，不会直调 API
# skill_name: uaf-audit # 可选，自定义 OpenCode skill 名称
# model_capability: high # 可选，any/low/medium/high；未配置默认 any
```

新 Checker 应提供 `SKILL.md` 并使用默认 `mode: opencode`。历史 `mode: api` checker 仍可读取 `prompt.txt`，但运行时会包装成临时 SKILL 后提交 OpenCode session。
同一 `family` 的候选会在静态阶段按同文件同函数做跨规则合并，只保留一个代表候选进入 AI 审计；代表点和同模式过滤规则见上文“静态候选合并与同模式过滤”。
新增或修改 `checkers/` 下的 checker 后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描目录。测试阶段建议设置 `visibility: admin`，只有管理员能看到并启动该 checker；测试完成后改为 `visibility: public` 即可对所有用户开放。

**内置 Checker：**

| Checker | 说明 |
|---------|------|
| `npd` | 空指针解引用 (Null Pointer Dereference) |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) |
| `safe_mem_oob` | 安全内存函数越界（dst/dstsz 不匹配） |
| `loop_mut_idx_oob` | 循环变化索引或 copy_from_user 累加长度导致的数组/指针越界 |
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
mode: "opencode"
```

**第 2 步：编写 SKILL.md**

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

**内存 API 缓存：**

扫描管线已禁用内存 API 预处理，不再在 checker 静态分析前自动检查、生成或复用 `memory_api_pairs.json`。相关模块和配置仍保留，已有产物也仍可被内存类 checker 按需读取。

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

# 可选：对前 1 个候选点运行真实 AI 审计（会使用 agent.yaml 中的 OpenCode 配置）
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
- 新 checker 统一使用 `SKILL.md`；旧 `mode: api` + `prompt.txt` 仅作为迁移兼容，模型调用仍走 OpenCode
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
server_url: "http://your-server:8000"
agent_name: ""
owner_token: ""
checkers: []
schema_version: 2
opencode_config: |
  {}
base:
  tool: "nga"
  executable: "nga"
  no_proxy: "10.0.0.0/8"
model_pool:
  global_concurrency: 4
  models:
    - id: "night-model"
      model: "provider/model"
      capability: "high"
      max_concurrency: 1
      enabled: true
      time_windows:
        - weekdays: [1, 2, 3, 4, 5, 6]  # 周一至周六
          start: "22:00"
          end: "06:00"
```

`server_url`、`agent_name`、`owner_token` 和 `checkers` 是本机启动字段；其余 v2 字段由 Web **「Agent 配置」** 页面管理并写回。`opencode_config` 是完整 JSONC 用户配置层，支持注释和尾随逗号。完整模板见仓库根目录的 `agent.yaml`。配置以 `IP + machine_name` 形成稳定 Agent 身份，Agent 离线或重连后仍使用同一份服务端配置。

模型的 `time_windows` 可配置多段，每段用 ISO 星期 `1..7` 表示周一至周日，并按 Agent 本地时间判断；各段取并集，未配置任何时间段表示全天可用。跨夜时间按当前星期判断，例如周一至周六 `22:00-06:00` 表示这些日期的 `00:00-06:00` 与 `22:00-24:00` 可用，周日不可用。旧配置未填写 `weekdays` 时继续按每天处理。

OpenCode 最终配置按“本机发现及显式指定的配置 < Web `opencode_config` < OpenDeepHole 受管字段”合并。受管字段包括 `$schema`、deephole-code 与已启用的受管 MCP、全局技能路径、运行权限和威胁分析子 Agent；这些值不能从 Web 配置覆盖。API Key、Token 等敏感值会以明文保存在服务端数据库、Agent 的 `agent.yaml` 和运行时文件中，应只在可信环境填写。

配置更新只会刷新独立的受管源并把 OpenCode serve 标记为待重载，不会提前改写正在运行的最终文件。serve 空闲后的下一次启动会原子写入 `~/.opendeephole/opencode_workspace/opencode.json`（POSIX 权限 `0600`），设置 `OPENCODE_CONFIG_DIR` 并显式清除 `OPENCODE_CONFIG_CONTENT`；存在活动 Session 时延迟到空闲边界，因此无需重启 Agent，也不会强制终止正在运行的 Session。

OpenCode 调用约定：

- `nga` / `opencode`：整个 Agent 固定使用 `~/.opendeephole/opencode_workspace`，扫描、复核和验证不再创建各自的配置 workspace，也不再向项目目录镜像运行配置。Agent 根据 Web 管理的基础工具和模型行生成 serve 配置。
- `nga` / `opencode` 只通过 serve API 调用，默认端口为 `4096`，可用 `OPENCODE_SERVE_PORT` 覆盖。组件只调用 `backend.opencode.run_opencode_task()`；真实项目目录和 `.opendeephole` 工作目录由执行上下文提供，不回退到当前目录，也不允许调用方传 permission。
- 每个 Session 可读取 `project_dir`，文件编辑工具只能写当前 `work_dir`，`bash` 全面禁用。所有内置/checker SKILL 注册到全局 skill root，由 OpenCode 按 prompt 名称加载。
- `output_schema` 使用普通文本 JSON 约束，不发送 OpenCode 原生 `format`；中文约束和完整 Schema 自动追加到首次用户 prompt 末尾，不写入 system prompt。JSON 不合规时默认在原 Session 追加 2 次中文纠正；纠正耗尽或普通执行错误后，内部任务策略决定是否重新排队并创建新 Session。
- OpenCode/nga serve 会话会保留在真实项目目录下，便于用 `opencode session list` 查看历史；Agent 只在取消或超时时 abort session，不在正常完成后删除 session。
- Agent 进程内只有一个共享 deephole-code MCP 网关；各扫描用 `project_id` 注册自己的 `code_index.db` 路由，不再为每个扫描启动独立 MCP 服务。
- 漏洞验证方法在 Agent 主进程中异步执行，直接调用同一个公共 OpenCode 接口，复用共享 MCP 网关和项目索引路由；验证方法直接执行 `nga`、`opencode`、`hac` 或 `claude` 会被拒绝。

内部 Python 调用统一使用 `backend.opencode`：

```python
from backend.opencode import OpenCodeTaskType, run_opencode_task

result = await run_opencode_task(
    task_name="candidate audit",
    task_type=OpenCodeTaskType.CANDIDATE_AUDIT,
    prompt="...",
    required_capability="high",
    output_schema={"type": "object", "properties": {}, "additionalProperties": False},
    invalid_json_retry_count=2,
)

continued = await run_opencode_task(
    task_name="candidate follow-up",
    task_type=OpenCodeTaskType.CANDIDATE_AUDIT,
    prompt="...",
    required_capability="high",
    session_id=result.session_id,
)
```

OpenCode 模型池统计：

- 威胁分析、候选点审计、威胁审计、去误报、历史分析、变体排查、SKILL 创建和漏洞验证全部通过唯一公共接口，内部统一创建/续写 Session 并累计模型池统计。
- 模型必须在 `model_pool.models[]` 中填写明确模型名并启用；不再接受默认模型行。没有显式模型时不能创建或恢复扫描。
- `model_pool.global_concurrency` 是所有模型合计运行数的硬上限；每个模型还会受自己的 `max_concurrency` 和 `time_windows` 限制。
- 配置页的每个模型可添加多段使用时间，每段独立选择周一至周日及起止时间；时间窗口只限制新取得的模型 Lease，不会中断已经运行的任务。
- 任务能力只分 `low`、`high`，任务优先级由任务类型自动决定；低能力任务优先用最低足够能力模型并可升级，高能力任务不会降级。模型行本身仍可标记低/中/高能力。
- 任务超时只计算每条模型消息的执行阶段，不包含排队时间。新 Session 重试释放并重新申请模型 Lease；模型池 completed-task 历史只记录一次最终状态。
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

> **注意：** Agent 需要运行支持 checker 同步的新版本。之后新增或修改 checker 时，只要点击开始扫描，后端会把本次选中的 checker 同步到 Agent。新增或修改产品验证方法时，上传到服务端并重启服务端；启动下一个任务时会先强制同步 Agent runtime，再执行验证。

## 数据存储位置

Agent 运行时会在以下位置产生数据：

| 位置 | 内容 | 生命周期 |
|------|------|---------|
| `<项目目录>/code_index.db` | tree-sitter 代码索引（函数/结构体/调用关系） | 持久保留，后续扫描复用 |
| `~/.opendeephole/scans/<scan_id>/` | 扫描工作目录（candidates.json、config.yaml、agent.log 等） | 扫描成功后自动删除；取消/出错时保留用于恢复 |
| `~/.opendeephole/fp_feedback.json` | 本地误报反馈缓存 | 持久保留 |
| `~/.opendeephole/fp_reviews/<review_id>/` | 误报复审临时目录 | 复审完成后自动删除 |

服务端数据：

| 位置 | 内容 |
|------|------|
| `../OpenDeepHoleData/scans/` | 扫描结果、兼容 submit sink 数据和 `scans.db` |
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
│   └── local_mcp.py       # Agent 进程级共享 MCP 网关
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
│   └── opencode/          # OpenCode task/session、模型调度与 serve 集成
├── mcp_server/            # Agent 共享 MCP 网关与源码查询工具
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
