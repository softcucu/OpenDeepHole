# 更新日志

## 2026-07-07

- **修复** 扫描详情页执行流程图中「候选点审计」同时指向「漏洞验证」和「对抗式去误报」；「漏洞挖掘」分组标题改为与流程节点一致的字号和前景色

## 2026-07-06

- **优化** 扫描详情页顶部导航改为执行流程图：仅将威胁分析、静态分析、调用图构建、候选点生成、候选点审计、对抗式去误报和漏洞验证作为流程节点展示，按现有页签层级呈现包含关系，并通过箭头表达阶段跳转顺序
- **新增** 扫描详情页「首页」新增当前扫描的 OpenCode Session 任务队列，展示计划中、排队中和运行中的候选点审计、对抗式去误报、威胁分析等模型调用任务；任务较多时分页显示
- **变更** 扫描详情页「漏洞挖掘」拆分为「候选点审计」和「对抗式去误报」两个页签；去误报流程、复核队列、阶段输出和正报/误报裁决统一移动到「对抗式去误报」页签，历史同类问题挖掘继续归入威胁分析语义
- **变更** 扫描详情页顶层移除「静态分析」页签，并将原静态分析页面作为「漏洞挖掘」下的子页签展示；候选点列表、分页、筛选、详情和日志内容保持不变
- **变更** 漏洞挖掘每确认一个漏洞后，除原有漏洞验证任务外，会同时复用同一扫描的去误报 job 创建单漏洞去误报任务；该任务与候选点审计共享 OpenCode 模型池队列，并在进入真实租约前作为计划任务显示
- **修复** 漏洞挖掘阶段自动触发的漏洞验证改为进入 Agent 独立验证队列，不再绕过队列直接启动验证脚本；同一扫描内多个漏洞继续串行排队，验证脚本等待或运行时不会阻塞 Agent WebSocket 心跳
- **变更** 漏洞验证页中间产出只展示 `ctx.emit_stdout(...)` 和 `ctx.run_command(...)` 子命令输出；验证脚本自身及 helper 的 `print(...)` 仅保留在 Agent 控制台，避免普通脚本日志混入网页展示
- **变更** OpenCode/兼容 CLI 模型池改为全局任务队列调度：漏洞审计、威胁分析等模型调用不再在等待阶段预绑定到某个模型；模型释放真实槽位后再从全局队列选择下一个可运行任务，同时保留 `opencode_concurrency` 和单模型 `max_concurrency` 的并发上限语义
- **新增** 创建扫描时新增「验证环境」下拉选择，默认选项为「仿真UBBPi板环境」；扫描元数据、恢复/续扫命令和漏洞验证上下文都会保留该环境，产品验证器注册支持按 `产品 + 验证环境` 匹配验证方法
- **变更** 漏洞验证详情页不再展示具体验证方法名称，仅保留产品、验证环境和验证结果状态，避免页面暴露方法标签
- **修复** OpenCode/nga 运行时配置发现范围扩展到可执行文件所在目录、`.opencode/config.json`、显式 `opencode.config_paths` 和 `OPENCODE_CONFIG_PATH`，避免便携安装或公司内网非标准配置目录下启动 serve 时丢失 provider/model 配置并回退访问公网 Provider
- **修复** 注入到 `OPENCODE_CONFIG_CONTENT` 的运行时 JSON 会移除顶层 `"$schema"`，避免环境变量携带 schema URL；启动诊断会记录候选配置文件命中情况和最终顶层 key，便于定位配置未合并的问题
- **修复** OpenCode/nga 子进程支持通过 `opencode.proxy_url` 或 `OPENCODE_PROXY_URL` 显式注入 `HTTP_PROXY`/`HTTPS_PROXY` 及小写形式，默认 `NO_PROXY/no_proxy` 使用已验证的内网列表且可由 `opencode.no_proxy` 或 `OPENCODE_NO_PROXY` 覆盖，避免 Agent 进程未继承交互式终端代理环境时 serve 启动阶段访问 Provider 被公司代理拦截；代理变化会触发 serve 重启
- **修复** 重启/续扫任务时若当前 `scan_id` 已保存匹配扫描范围的威胁分析结果，Agent 会直接复用并跳过重新执行威胁分析，避免重复消耗模型调用
- **变更** 威胁分析 `res.json` 恢复写入项目根目录，并继续按 `scan_scope` 判断是否可复用，避免扫描任务目录清理后跨任务无法复用威胁分析结果

## 2026-07-04

- **优化** 扫描详情页「静态分析」拆分为「调用图构建」和「候选点生成」两个子页；调用图构建展示索引文件数、函数数量、调用关系、结构体/类/联合体、全局变量和引用数量，候选点生成保留原候选列表、分页、筛选和状态展示
- **修复** 静态分析/代码索引完成事件不再用 `0/0` 覆盖已有文件进度；刷新扫描详情页也会重新读取索引状态，避免扫描文件数长期显示为 0
- **修复** OpenCode/nga 运行时配置会把用户全局和项目根目录的 provider/model 配置合并进 `OPENCODE_CONFIG_CONTENT`，再覆盖当前任务的 MCP、SKILL 路径和权限配置，避免隔离 `startup_cwd` 下启动 serve 时丢失本机模型配置并回退访问公网 Provider
- **优化** OpenCode/nga serve 启动前会在 Agent 命令行打印完整诊断信息，包括解析后的可执行文件、端口、CWD、marker/startup log 路径、argv、可复现 shell 形式命令、Popen 参数以及脱敏后的 `OPENCODE_CONFIG_CONTENT` 注入内容，便于定位本机 serve 启动失败原因且避免泄露 API Key、token 或认证 header
- **变更** `git_history` 历史提交分析和同类变体排查在扫描管线中硬禁用；实现代码和配置字段继续保留，但即使配置文件里 `git_history.enabled: true` 也不会执行该阶段
- **修复** Agent 远端配置和 Web 配置面板的默认 OpenCode/兼容 CLI 改为与下载包 `agent.yaml` 一致的 `nga`/`nga`、并发 4，避免仅保存 `git_history.enabled: false` 等配置时把本地可用的 `nga serve` 覆盖成默认 `opencode serve`，导致 serve 无法启动
- **变更** `loop_mut_idx_oob` 撤销未校验循环上界直接访问召回，改为召回 `bspkern_copy_from_user`/`copy_from_user` 家族中目标指针按拷贝长度循环累加或递减的候选；候选提示会点名重点长度变量和目标变量，SKILL 复核要求说明真实边界与漏洞触发方式
- **变更** 威胁分析改为在任务工作区准备完成后后台启动，并与静态分析、后续漏洞挖掘并行；扫描最终完成前会等待后台威胁分析收尾，避免提前清理工作区或丢失结果上报
- **变更** 扫描管线硬禁用内存 API 预处理；即使 `memory_api_discovery.enabled: true`，也不会在静态分析前自动生成或复用 `memory_api_pairs.json`，相关模块和配置字段继续保留
- **变更** 漏洞验证默认整体超时调整为 2 小时；产品验证器可在 `registry.register(..., timeout_seconds=7200)` 中覆盖单产品超时，验证上下文会通过 `ctx.timeout_seconds` 和 `get_validation_info()` 暴露最终生效值
- **变更** 漏洞验证 demo 改为在项目目录下保存单漏洞报告，并在代码中显式按 STEP 1-4 串行调用 4 个硬编码 nga skill；每个 STEP 保留独立提示词和 2 次失败重试，进程输出会同步到页面，全部完成后返回需人工介入的验证成功结果
- **变更** 同一扫描的漏洞验证改为 Agent 侧串行排队执行；多个漏洞可连续提交为等待状态，但本地验证脚本同一时刻只会运行一个，停止排队项不会影响队列中的其它漏洞
- **修复** 手动重新点击漏洞验证不再携带或执行 Agent runtime 自动更新，避免修改 demo 后验证按钮触发整包下载或 Agent 重启；产品验证器更新继续通过客户端「同步验证方法」推送到在线 Agent
- **优化** 产品漏洞验证脚本默认在脚本所在目录运行，支持直接读取同目录 `input/input.json` 和导入同目录 helper；脚本及 helper 的 `print()` 输出会实时同步到漏洞验证页中间产物
- **修复** Windows 漏洞验证子命令会合并当前 PATH、注册表用户/系统 PATH 和常见 npm/pnpm/Volta/Scoop/Chocolatey 目录，避免终端可运行 `nga`/`opencode` 但 Agent 验证脚本提示找不到命令
- **修复** Windows Agent 在静态分析完成后进入 git 历史挖掘时，git 子进程输出不再按系统默认 `gbk` 解码，避免非 GBK 字节触发 `UnicodeDecodeError` 并打断后续扫描
- **修复** OpenCode/nga serve 启动失败时不再只返回 `code 1`；Agent 会捕获启动阶段 stdout/stderr 并在健康检查失败或子进程提前退出时带上日志尾部，同时强制子进程使用 UTF-8 友好环境，便于定位 provider、配置或本机 CLI 启动错误
- **修复** OpenCode/nga serve 启动进程改为显式使用受控运行目录作为 CWD，并在该目录内准备最小 git 仓库，避免 Agent 从非 git 目录启动时 OpenCode 自身 VCS 探测报 `fatal: not a git repository`；真实项目目录继续通过 session 请求参数传递，不会污染被扫源码目录
- **修复** OpenCode/nga serve 在已有任务运行时不再因新任务或模型列表请求的运行配置哈希不同而等待当前 session 结束；并发扫描会复用同一个 serve 进程创建独立 session，模型池运行任务同步展示对应 `ses_*` 会话 ID
- **修复** 威胁分析结果改为写入本次扫描任务目录的 `res.json`，避免同一路径并发扫描时争抢项目根目录 `res.json`
- **新增** 漏洞验证函数上下文提供 `get_report_markdown()` 和 `get_validation_info()`，验证结果新增“是否需要人工介入”字段并在漏洞验证页展示；示例产品验证器同步演示读取报告、上下文信息和返回最终结论
- **修复** OpenCode/nga serve 启动时若 `OPENCODE_SERVE_PORT` 被旧子进程残留占用，会自动定位并终止该端口监听进程后重启 serve；覆盖 Windows 停止任务后 `.cmd` 父进程退出但 Node 子进程继续占用 4097 导致普通审计和 FP 复核稳定失败的问题

## 2026-07-03

- **修复** 威胁分析产物继续写入项目根目录 `res.json`，但会标记实际 `code_scan_path` 子目录；新扫描只有在已有产物的扫描范围与本次扫描目录一致时才复用，避免不同子目录扫描误跳过威胁分析
- **修复** Windows 下停止扫描后继续运行时 OpenCode/nga serve 端口可能被旧子进程占用的问题；Agent 关闭或重启本 Agent 标记的 serve 时会清理进程树，避免 `.cmd` 父进程退出但 Node 子进程继续占用 `OPENCODE_SERVE_PORT`
- **修复** OpenCode/nga serve 模式的 `x-opencode-directory` 请求头改为 ASCII 安全编码，避免项目路径包含中文等非 ASCII 字符时 httpx 在创建 `/session` 请求前抛出 `UnicodeEncodeError`
- **优化** `loop_mut_idx_oob` Semgrep 初筛新增未校验循环上界召回：当循环变量由未提前比较校验的上界控制并用于数组下标或指针偏移访问时，会提取候选点，覆盖 `fragInfo[fragId]` 这类访问层级
- **新增** 审计排序优先级：静态候选中若命中函数 `MC_EthBuildPayloadByFrag`，会在漏洞识别阶段优先放到第一个审计位置，不再限制漏洞类型
- **变更** 扫描详情页「发现的问题」列表改为按实际 AI 审计顺序展示，不再按严重程度重新排序
- **优化** MCP 初始提示词和 `deephole-code` 源码查询工具说明会明确要求优先使用 `view_function_code`、`view_struct_code`、`view_global_variable_definition` 阅读源码，索引不可用或需要目录级搜索时再回退内置 `read`/`grep`/`glob`
- **新增** 扫描详情页新增一级「静态分析」页签：展示最终进入 AI 审计队列的所有静态候选点，支持分页、类型/审计状态/验证状态筛选，并在候选详情中展示描述、AI 审计结论和验证状态
- **变更** 扫描详情页顶栏移除「漏洞报告生成」页签；报告型 SKILL 查看、报告 zip 导出和 CSV 下载继续保留在顶部按钮/侧滑面板中
- **新增** Agent 会在静态分析、变体合并和去重完成后上报最终候选点列表；后端持久化候选点并随扫描状态返回，刷新页面后仍可查看静态分析候选点
- **优化** 「发现的问题」页签和页面顶部显示漏洞挖掘发现数与已完成验证数，并支持按验证状态筛选问题列表
- **新增** 漏洞验证支持单条停止：页面可停止正在排队或运行的验证任务，后端立即将该条状态同步为 `cancelled`，并通知 Agent 取消本地验证过程和验证脚本子进程
- **变更** 漏洞验证改为产品注册机制：Agent 会导入 `agent/product_validators/*.py`，由每个文件的 `register(registry)` 为不同产品注册验证函数，并按扫描产品选择验证方法
- **新增** 产品验证函数可直接产生中间 stdout、验证产物、最终结论、验证是否成功和是否确认为问题；验证页移除旧「验证输出」栏，改为实时展示中间产出、产物和最终结论
- **新增** Agent 首次下载包会包含 `agent/product_validators/`；runtime 自动更新继续排除该目录，客户端页面提供「同步验证方法」按钮用于手动把仓库中的验证方法同步到在线 Agent
- **修复** Agent runtime 自动更新改为按受管文件粒度替换，避免点击漏洞验证触发更新时删除本地 `agent/product_validators/`，该目录仅在手动点击「同步验证方法」时覆盖

## 2026-07-02

- **新增** 漏洞验证流程：漏洞挖掘阶段每发现一个 AI 确认问题，Agent 会立即在本机调用验证脚本，验证页实时展示运行标志、中间产出、验证代码和验证输出；默认假脚本位于 `~/.opendeephole/vulnerability_validation/validator.py`，后续可在 Agent 侧替换
- **新增** 已发现问题详情页支持对单个 AI 确认问题手动启动漏洞验证，允许重跑覆盖；后端会将单漏洞 Markdown 报告下发到 Agent 侧验证脚本，并把排队、运行和结果状态实时同步到页面
- **优化** 漏洞验证页改为类似「发现的问题」的左右主从布局，左侧按等待验证、验证中、已验证和异常状态展示问题队列，右侧展示选中问题的摘要、中间产出、验证代码和验证输出
- **优化** Agent runtime 自更新和 checker 同步会忽略本地验证脚本目录，只同步验证调用器和配置字段，避免远端更新覆盖用户在 Agent 机器上维护的真实验证脚本
- **修复** OpenCode/nga serve 模式改为以真实项目目录创建和发送 session，请求同时携带 `directory` 查询参数和 `x-opencode-directory` 头，正常完成后不再删除 session，保证可通过 `opencode session list` 查看历史
- **修复** serve 消息发送前恢复从 `/experimental/tool/ids` 读取当前可用工具并显式传入 `tools`，确保内置源码读取工具和已配置 MCP 工具对 OpenCode/nga 可见；当前任务的 MCP URL、SKILL 路径和权限配置通过 `OPENCODE_CONFIG_CONTENT` 注入 serve 启动环境
- **优化** MCP 工具不再暴露或要求模型填写 `caller_model` 参数，模型/任务归属由 OpenCode 调用侧的模型池租约、session 日志和输出来源元数据记录
- **优化** serve 进程复用身份纳入配置内容哈希，MCP/SKILL 配置变化时会等待活跃 session 结束后重启，避免继续使用旧 MCP 端口或旧运行配置

## 2026-07-01

- **修复** MCP 工具调用日志恢复为 `[MCP ▶]` / `[MCP ◀]` 双向格式并保留调用模型标识，返回日志只输出匹配数量、字符数或保存路径等摘要，避免源码正文和完整报告刷屏
- **修复** OpenCode/nga serve 模式固定使用单 Agent 一个服务端实例；默认端口为 `4096`（可用 `OPENCODE_SERVE_PORT` 覆盖），启动前会清理本 Agent 标记的旧 serve，端口被其它进程占用时明确报错
- **修复** serve API 调用显式保持先创建 `/session`，再使用返回的 session 调用 `/session/{sessionID}/message`，并在 session 创建、工具发现、消息发送和清理时传递一致的 `directory` 参数

- **新增** AI 输出来源追踪：漏洞 AI 分析、报告型 SKILL Markdown、AI 去误报阶段输出和最终结论都会记录 Agent、工具、模型池 ID、实际模型、能力和调用尝试等元数据
- **优化** 扫描详情页、SKILL 报告面板和 Markdown 导出展示输出来源，便于追溯每个结果由哪个 Agent、哪个模型生成；历史数据无来源时保持兼容不显示空占位

- **新增** OpenCode/nga 调用支持 `serve` API 模式并作为默认调用方式；Agent 进程复用一个 `opencode serve`/`nga serve` 服务端，每次审计、去误报或任务调用创建独立 session，保留配置切回原 CLI `run` 模式的能力
- **优化** serve 模式改为按请求使用当前任务的隔离运行配置目录创建 session，同一 Agent 只要已有 serve 进程运行就继续复用；新扫描、不同 checker、模型列表刷新和运行时配置更新不再因为扫描 workspace/MCP/SKILL 配置不同而重启 serve
- **新增** Agent 模型池配置页支持从当前 serve 服务端读取模型列表，勾选后导入审计或去误报模型池；刷新模型列表复用既有 serve 进程
- **修复** serve 模式发送审计消息前会从 `/experimental/tool/ids` 读取当前 OpenCode/nga 实例的全部可用工具并显式传入 message payload，确保 `read`、`grep`、`glob` 以及已配置 MCP 工具在 serve API 调用中可见；工具发现失败时回退到原行为，不影响扫描继续执行
- **修复** serve 模式不再把本地配置目录作为 `workspace` 查询参数传给 OpenCode，避免新版 serve 将其当作 workspace ID 解析导致 `/session` 500；模型提示中会打印真实项目根目录，读取源码时使用该目录下的路径
- **优化** Agent 本地终端输出补齐 LLM/API 与 OpenCode serve 会话的中间文本输出；工具调用统一压缩为单行摘要，MCP/API 工具返回正文不再刷屏，便于并发审计时观察模型进度和实际调用
- **优化** OpenCode/兼容 CLI 默认总并发从 1 调整为 4，新 Agent 和默认配置会并发审计候选；已有远程保存的 Agent 配置仍以用户设置为准

## 2026-06-29

- **变更** 扫描详情页移除原「初始化 / 静态分析 / AI 审计 / 完成」四阶段步骤条，改为可点击的「首页、威胁分析、漏洞挖掘、漏洞验证、漏洞报告生成、发现的问题」页签；详情默认进入首页，展示当前阶段、候选进度、发现问题、历史模式、变体候选、Agent 和模型池概况
- **新增** 威胁分析与漏洞挖掘页签下增加子页签：代码索引、静态分析、Git 历史问题分析、候选点 AI 审计、历史同类问题挖掘分别展示对应任务状态、进度和日志；漏洞验证与报告生成先预留任务页，发现的问题页签继续复用现有问题详情和人工反馈能力

## 2026-06-26

- **修复** Agent 本地 MCP 不再依赖进程级 `AGENT_PROJECT_DIR` 定位代码索引，扫描、AI 去误报和 checker 测试会把索引目录绑定到各自的 MCP 实例，避免多扫描/复核并发时串用项目目录导致“代码索引不可用”
- **修复** MCP 与 LLM API 直调模式的 `code_index.db` 缓存增加文件指纹和健康检查；索引文件被原子替换、删除或连接失效时会清理旧连接并重新打开，减少长时间运行后的索引不可用问题

## 2026-06-25

- **修复** Agent 模型池等待循环不再无条件刷新快照 `updated_at`，避免排队/等待期间状态未变却持续触发 `POST /opencode-pool`，恢复“变化时上报、未变化低频心跳”的节流语义
- **优化** Agent 收到模型池/LLM 配置更新后会立即刷新当前进程内的后端配置和模型池快照，唤醒正在等待模型的扫描调用；下一次 OpenCode 调用会按最新模型、默认模型、总并发和时间窗口选择可用模型，无需重启扫描任务
- **新增** 客户端页面展示 Agent 级 OpenCode 模型使用总览：按模型展示当前任务、运行/排队、成功/失败/超时/取消、平均耗时和可用状态；服务端按 Agent 名称、用户和会话持久化模型使用历史
- **优化** 扫描详情页模型看板同步展示模型可用状态和当前任务上下文，配置变更会通过 Agent 模型池上报链路推动当前扫描看板刷新
- **修复** 扫描详情页 AI 审计进度不再由候选序号推进，避免并发审计时第 N 个候选先开始导致“只完成少量候选却显示 10/xxx”的错误进度；完成数统一由已处理 key 和最终上报决定
- **修复** 模型看板的运行/排队瞬时状态：模型只有真实等待时才计入排队，扫描完成、取消或错误后会清空 running/queued/active task，防止已停止扫描仍显示模型运行中

## 2026-06-24

- **新增** 客户端配置内独立「模型池」页签：OpenCode/兼容 CLI 审计工具不再单独编辑模型字段，模型统一在审计/去误报模型池中配置，并支持默认模型行、模型能力、每日使用时间窗口、单模型并发和工具覆盖
- **变更** 模型池启用后 `opencode_concurrency` 改为所有模型合计运行数的硬上限；调度同时受单模型 `max_concurrency` 与每日 `time_windows` 限制，满足能力但不在当前时间窗口的模型会排队等待而不是降级使用低能力模型
- **优化** checker 静态阶段按 `code_scan_path` 收敛 DB 函数范围：新增 `CodeDatabase.get_functions_by_path_prefix()` 与公共 `scoped_functions()`，`npd`、`chain_npd`、`oob`、`sensitive_clear` 不再先遍历整库函数后事后丢弃范围外候选；`npd`、`chain_npd` 同步补齐静态进度上报
- **新增** 静态候选跨规则去重：`checker.yaml` 支持 `family`，默认开启 `static_dedup`，同 `family + file + function` 只保留一个代表候选进入 AI 审计，并通过 `metadata.merged_from` 记录合并来源
- **优化** OpenCode 初始候选描述改为最小审计问题：只保留函数、变量/表达式和问题类型，静态分析规则、命中路径和工具细节不再写入 `description`
- **新增** AI 审计同模式批量过滤：默认开启 `pattern_filter`，当同模式代表点被 AI 返回 `not_confirmed` 后，后续同 `vuln_type + subject + scope` 候选自动标记为 `filtered_same_pattern`，不再调用 LLM；timeout/no_result 不触发传播
- **文档** README/CLAUDE 补充 DB analyzer 范围收敛、checker family、函数级去重、同模式过滤和配置项说明

## 2026-06-23

- **优化** 清洗所有 checker 送入 AI 的**初始 prompt（候选 description）**，不再体现静态工具痕迹：去掉严重级别/规则名（`[high] xxx`）、规则告警 message、`匹配代码`、`规则策略/复核重点/命中关键字`、`[cppcheck]`/`[锁/线程资源]`/`静态过滤命中` 等表述；各 analyzer 描述统一改为中性问句「函数 X 中变量/表达式 Y 是否存在 Z 问题，请审计确认」，原有变量/表达式/调用线索保留为「相关线索」。涉及 16 个 `checkers/*/analyzer.py`
- **优化** 同步清洗所有 `checkers/*/SKILL.md` 中暴露静态工具的表述（「静态分析器/semgrep/Semgrep/cppcheck/tree-sitter 已 flag/扫描/完成工作」「规则类型」等），统一改为中性的「候选线索 / 语法初筛 / 候选形态」表述，并将引用已移除描述字段的指引（如「根据规则类型」）改为「自行判断候选形态」
- **优化** 空指针解引用 **NPD 家族 SKILL**（`npd`/`chain_npd`/`mp_npd`/`npd_funcret`）新增确认硬性要求：判定为问题（`confirmed=true`）时，`ai_analysis` 必须同时给出【赋值点】（空指针被赋值的确切文件:行号及为何可能为 NULL）、【无判空路径】（赋值点到解引用点每条可达路径均无有效判空的证明）、【调用链/调用过程】（跨函数时给出 `caller → callee` 调用链并标注关键行号），三要素缺一不可
- **优化** 扫描详情页左侧问题列表改为**分页显示**（每页 20 条，底部「上一页/下一页」+ 页码/总数），筛选或切换「显示全部」时回到第一页，避免一次性渲染全部候选
- **新增** 左侧问题列表项展示**人工标记情况**：已标记时显示「人工：确认正报/实为误报/待分析」（沿用对应颜色）及「已提单/单号」，未标记时显示「人工：未标记」

## 2026-06-22

- **变更** 去误报由「手动点击」改为**扫描完成自动触发**：扫描完成（status=complete）且存在已确认漏洞时，后端在 `agent_finish_scan` 末尾自动发起 AI 去误报，无需再点「AI去误报」按钮（按钮仍保留，可手动重跑/补跑未复核项）。仅在该扫描尚无去误报任务时触发，避免 resume/重复 finish 造成重复复核。新增配置 `fp_review.auto_on_complete`（默认 `true`，可关闭）；触发逻辑抽取为 `backend/api/scan.py` 内部函数 `_start_fp_review`，被手动端点与自动触发共用
- **变更** 扫描详情页改为**左右主从布局**：左侧为精简问题列表（文件:行 / 函数 / 类型 / 严重级别 + AI/去误报状态徽章、变体/命中标记），顶部保留严重级别与类型筛选；右侧为选中问题详情，描述、AI 分析与去误报各阶段（历史/校验匹配、正方论证、反方论证、最终裁决）输出均以 Markdown 渲染展示
- **变更** 详情页默认**只显示「问题」**：AI 审计未确认（confirmed=false）或去误报判为 fp 的候选默认隐藏，顶部「显示全部」开关可查看被隐藏的非问题候选

## 2026-06-18

- **新增** git 历史安全问题挖掘 + 同类变体排查（迁移自 SecAnt）：扫描流水线在索引后新增阶段，逐条提交（每条提交一个 LLM 调用）判定是否为安全修复并提炼「历史问题模式」（根因+缺陷类型+触发条件抽象），随后对每条模式派一个 agent 在全仓搜索同类未修复站点，命中的作为带 `variant_of` 的新候选并入审计。新增配置 `git_history`（`enabled`/`max_commits`/`since`/`paths`/`variant_hunt`）、Agent 模块 `agent/git_history.py` 与 `agent/variant_hunter.py`、skill `git_history_mine.md`/`variant_hunt.md`、MCP 工具 `submit_history_pattern`/`submit_variant_finding`、端点 `POST/GET /api/agent/scan/{id}/git_history` 与 `GET /api/scan/{id}/git_history`，扫描详情页新增「git 历史问题模式」面板
- **新增** 去误报「历史/校验匹配」首阶段（`history_match`）：复核每个候选时先判断它能否与某条历史问题模式（同根因）或其它函数里把校验做对了的调用站点对应上；命中则**直接判定 high 并跳过三阶段对抗辩论**，报告中通过 `match_type`（history/validation）+ `match_reference` 字段标明对应的修复/校验，新增 skill `fp_review_match.md` 与 MCP 工具 `submit_match_result`
- **变更** 去误报定级简化为二元 high/low：命中历史/校验匹配或论证为外部可触发 → high，其余（含原 medium、误报）一律 → low；`prove_bug`/`prove_fp`/`final_judge` 三阶段 prompt 与 `_normalize_fp_severity` 同步调整
- **新增** 字段：`Vulnerability.variant_of`（同类变体来源）、`FpReviewResult.match_reference`/`match_type`；报告导出（CSV/单漏洞 Markdown/report.zip）与前端复核结果区均展示这些字段（旧库自动迁移，新增表 `git_history_patterns`）
- **优化** `multi_ptr_leak2`（多层指针外层释放遗漏成员）静态分析器（自 `feat/deep-mining` 分支拣选）：索引函数改为逐函数流式处理，单棵 tree-sitter Tree 用完即弃，常驻内存从「整仓 N 棵 AST」降到「单函数 1 棵」；解析前用 `_RELEASE_HINT_RE` 做廉价文本预筛跳过不含释放语义 token 的函数；新增 `scope_prefix` 将处理范围收敛到本次扫描路径；释放 wrapper 名直接从索引函数名列提取无需解析函数体。行为与召回不变，仅性能/内存优化

## 2026-06-17

- **新增** 漏洞报告 Markdown 导出：对每一个 AI 判定为「是问题」的扫描项，详情页新增「导出 MD」按钮，导出包含元信息、描述、AI 分析以及去误报三阶段（prove_bug / prove_fp / final_judge）报告的 Markdown 文件（`GET /api/scan/{id}/vulnerability/{idx}/report`）
- **新增** 扫描整体报告导出：扫描详情页顶部新增「导出报告」按钮，将本次扫描所有 AI 确认为问题的漏洞各自导出为 Markdown 并打包为 zip（含索引 `README.md`），无确认问题时仍返回带说明的 zip（`GET /api/scan/{id}/report.zip`）；同步提供公开分享场景的对应端点

## 2026-06-11

- **优化** AI 去误报新增正方早退：`prove-bug` 阶段提交 `confirmed=false`（非问题）时直接以正方理由记录"可能误报"最终结果并推送前端，跳过 `prove-fp` 和 `final-judge` 两个阶段；此前该场景下模型常不写 artifact 也不提交结论，导致阶段失败后既无后续阶段也无任何复核结果
- **优化** AI 去误报阶段重试时在 prompt 中强调即使结论为非问题也必须写入 Markdown artifact 并调用 `submit_result`，`prove-bug` SKILL 同步加固该要求
- **修复** AI 去误报并发复核时扫描详情页不高亮正在复核的行：进度上报改为携带完整的进行中索引集合（`active_indices`），后端持久化到 `fp_review_jobs.current_vuln_indices`（旧库自动迁移），前端同时高亮所有正在复核的行并在顶部面板展示并行目标
- **修复** Agent WebSocket 重连后后端误判 AI 去误报已停止：Agent hello 新增 `active_fp_reviews` 上报，后端重新挂接仍在运行的复核任务（更新扫描 agent_id、恢复因断连误标 error 的任务为 running），旧连接的延迟取消不再误杀存活复核；`stage-output` 上报端点补齐与 progress/result 一致的断连自动恢复
- **修复** 页面刷新后无最终结论条目的"复核中"状态和阶段输出消失：`GET /fp_review` 现在会合并 `fp_review_stage_outputs` 中的阶段 Markdown，无最终结论的漏洞以占位条目返回
- **优化** 复核结束后仍无最终结论的条目前端显示"复核失败"徽章，不再永远停留在"复核中"
- **修复** 扫描详情页打开后整页白屏：并发高亮改造引入的 `useMemo` 被放在加载态提前返回之后，违反 React Hooks 顺序规则导致前端崩溃；改为普通表达式计算

## 2026-06-10

- **新增** OpenCode/兼容 CLI 统一模型池调度：Agent 配置支持 `opencode_concurrency` 和 `opencode.models[]`/`fp_review_cli.models[]`，可按模型能力、权重和单模型并发做负载分配；未配置模型池时保持原有单模型行为
- **新增** 扫描详情页「模型看板」：实时展示 OpenCode 模型池每个模型的累计任务、成功/失败/超时/取消计数、平均耗时、运行中和排队数，刷新后可从扫描存储恢复最近快照
- **新增** `checker.yaml` 支持 `model_capability: any|low|medium|high`，位置审计会按 checker 最低能力要求选择模型，AI 去误报和在线创建 SKILL 默认优先高能力模型
- **优化** Agent 模型池快照改为状态变化时上报，无变化时只保留低频心跳，避免 `/opencode-pool` 每秒重复写库和广播 SSE
- **优化** 位置审计、扫描前内存 API 识别和 AI 去误报改为复用统一 OpenCode 调用入口并支持多并发执行；`opencode`/`nga` 每次调用使用独立运行目录，避免并发时覆盖运行时配置
- **优化** `sensitive_clear` 改为启发式筛选敏感变量所在函数后按函数审计；每个函数只启动一次 Agent、只提交一次 `submit_result`，`ai_analysis` 改为人类可读 Markdown 并直接随漏洞条目展示
- **优化** `sensitive_clear` 单次 Agent 分组审计最多包含 5 个函数，降低变量级敏感信息清零分析的单次上下文规模，减少大项目扫描超时

## 2026-06-02

- **优化** Agent 静态分析进度上报增加节流与合并，避免 `sensitive_clear` 等大项目按函数逐次上报导致 `/static-progress` 请求堆积超时；上报失败告警会显示异常类型、状态码和进度上下文
- **修复** 静态分析进度上报乱序或失败时，前端可能不更新进度且完成后仍停留在静态分析阶段的问题；静态完成态改为单调更新，Agent 会等待已投递进度并打印上报失败告警
- **修复** Agent 侧静态分析完成上报丢失或未被当前页面实时接收时，扫描详情可能长期停留在“静态分析 128/128”的问题；后端收到 AI 审计事件会补齐静态完成态，并通过 SSE 推送静态进度字段
- **优化** `sensitive_clear` 改为按函数长度分组审计：每组函数只启动一次 Agent，初始提示词仅包含函数名和变量名，Agent 对组内每个变量分别提交 `submit_result`，完整变量级 JSON 保存为检查项报告，只有确认未清零问题进入漏洞列表
- **新增** 启用 `sensitive_clear` 检查项，敏感信息未清零规则进入扫描选择与运行时 registry
- **修复** AI 去误报三阶段复核在长 prompt 场景下可能把空任务传给 CLI，导致阶段进程结束但未写入指定 Markdown artifact；长 prompt 现在改为文件引用方式传递
- **修复** AI 去误报阶段缺失 Markdown artifact 或 `submit_result` 时不再继续推进后续阶段，会按 `fp_review_cli.max_retries` 重试并在页面展示明确失败原因和 artifact/log 路径
- **修复** Windows Agent 上 OpenCode 写入 FP 复核 artifact 时因 `C:\...` 与 `C:/...` 路径分隔符不一致被权限规则误拒绝的问题
- **修复** 同一扫描完成一次 AI 去误报后再次启动复核时，旧 review 的完成状态可能覆盖新任务运行态，导致页面不显示进度和停止按钮的问题
- **新增** 用户反馈新增“待分析”状态；该状态只保存为漏洞人工处理状态，不进入误报屏蔽规则经验库，也不会阻止 AI 去误报复核或超时/无结果续扫继续处理该问题
- **新增** 扫描前内存申请/释放函数分析：索引完成后先检查项目根目录 `memory_api_pairs.json`，不存在时批量调用 opencode 识别底层堆内存申请/释放函数和宏，合并中间 JSON 后再开始 checker 静态分析；该过程不修改 `code_index.db`
- **优化** 本地 checker 测试命令新增 `--json-output/--output`，可直接生成缩进格式化的 UTF-8 JSON 结果文件，避免中文候选描述被后处理转义成 `\uXXXX`
- **优化** `memleak` checker 改为 opencode 复核，并将静态阶段升级为 tree-sitter 路径分析：`if` then/else 和 `switch/case` 分支单独传播，过滤判空宏、参数/参数成员所有权转移和循环内正常释放后的函数尾部 return 误报，同时召回状态机完成态、循环 `continue` 与初始化待确认的泄漏候选
- **新增** 扫描详情页已人工标记的问题支持单条或批量取消标记；取消后会删除该标记生成的反馈经验、从本次扫描选中经验中移除，并让该问题重新进入 AI 去误报复核候选
- **优化** AI 去误报复核改为 `prove-bug` / `prove-fp` / `final-judge` 三阶段：正反论证通过 Markdown artifact 文件交互，阶段结束后即可在页面按钮中查看对应 Markdown，最终结论由 `final-judge` 提交
- **优化** AI 去误报移除 CVSS 打分规则，最终按外部可触发问题为 high、真实代码问题但外部触发证据不足为 medium、非问题为误报进行归并
- **优化** AI 去误报的问题报告不再仅限 high，最终为真实问题的 high 和 medium 结果都会保留 `vulnerability_report`
- **优化** 扫描详情页 FP 复核后默认展示问题报告，三阶段论证过程改为点击按钮后展开，避免默认占用报告展示区域

## 2026-05-30

- **新增** 扫描完成后支持对 AI 审计超时或无结果的候选点发起续扫，仅重新下发这部分候选并用新结果替换原有未完成记录
- **新增** 用户创建 SKILL 时由用户填写唯一标识，不再自动生成 `skill-xx` 类编号；SKILL 列表、新建扫描页和市场详情展示创建者
- **新增** 用户创建的 SKILL 支持删除，创建者可删除自己的 SKILL，管理员可删除任意用户创建的 SKILL
- **优化** AI 去误报 SKILL 改为从攻击者角度评估漏洞和可利用性，新增 CVSS 3.1 基础评分（AV/AC/PR/UI/S/C/I/A），根据 CVSS 分数判定漏洞等级（high ≥ 7.0、medium 4.0-6.9、low < 4.0）
- **优化** AI 去误报不再以"业务上无法触发"为由降级漏洞，只要外部输入理论上可达就按攻击者视角评估；对于代码缺陷真实存在但触发条件苛刻的情况，在理由中说明触发难度而非直接判为误报
- **优化** AI 去误报 discriminator 阶段改为从攻击者角度验证攻击路径是否真实可行，并逐维度复核 generator 的 CVSS 评分
- **优化** AI 去误报 high 漏洞报告新增 CVSS Score 章节，缺少该章节会自动降级为 medium
- **修复** 页面刷新或后端重启后，Agent 仍在执行 AI 去误报但页面不显示进度和停止按钮的问题：当 Agent 断连后重连继续推送进度时，自动将因断连标记为 error 的去误报任务恢复为 running 状态

## 2026-05-29

- **优化** AI 去误报复核改为 generator-discriminator 双阶段：先按“默认安全”先验证真实代码缺陷和可利用链，再由对抗复核专门寻找不可利用理由；只有可利用链经反驳后仍成立才保留 high
- **优化** AI 去误报 high 结果的 Markdown 漏洞报告固定包含 Summary、Vulnerable Code、Full Call Stack、Root Cause、Why It is Reachable、Impact、Evidence，章节缺失会自动降级为 medium
- **新增** 扫描详情页结果表支持按 AI 去误报复核严重性筛选，可单独过滤 high、medium、low 或无复核结果
- **修复** 启动 AI 去误报复核时会像启动扫描一样下发 Agent runtime update，确保后端代码和 Agent 侧代码先同步再执行复核
- **修复** AI 去误报使用 `opencode`/`nga` 时会将 FP 复核 SKILL 同步到实际运行目录，避免对抗复核阶段偶发报 `fp-review-discriminator` 不存在

## 2026-05-28

- **新增** 用户创建 SKILL 改为服务端模板化生成，不再调用 Agent/opencode 创建草稿；`SKILL.md` 与 `SCENARIOS.md` 可编辑内容由用户维护，MCP 使用、报告保存和写权限约束由后端固定拼接
- **新增** 用户创建 SKILL 支持 `references/`、`scripts/`、`assets/` 资源上传，并支持创建时配置独立运行超时，扫描时不再复用全局 opencode 超时
- **新增** 用户创建 SKILL 支持 Markdown 报告型输出：运行时只开放临时报告目录写权限，Agent 完成后读取 `.md` 报告并同步到服务端，扫描详情页提供独立 SKILL 报告入口和进度提示
- **优化** 新建扫描页将系统内置 checker 与用户新建 SKILL 分成两列展示，便于区分结构化漏洞扫描和报告型用户扫描
- **新增** 外部逆向平台集成扫描接口和 `tools/external_platform_scan.py` 脚本，支持硬编码集成 token 创建扫描、按 Agent 名称下发脚本内置 LLM/opencode 配置、自动运行当前启用且公开的 checker，并返回无需登录的扫描结果链接和进度 API
- **新增** 扫描详情页支持带 `scan_access_token` 的公开访问入口，访问者可像普通用户进入扫描详情一样查看进度、停止扫描、下载报告、确认问题、维护反馈和触发 AI 去误报
- **修复** `opencode`/`nga` 扫描时工具自身生成的 `opencode_result-*.log` 落到目标项目根目录的问题，改为将 CLI 运行目录收敛到项目内 `.opendeephole/opencode/`，同时保留 `--dir` 指向真实项目根目录
- **修复** 长时间扫描后 MCP 和 API 模式报"代码索引不可用"：`llm_api_runner` 每次调用 `_get_db()` 都创建新 SQLite 连接且从不关闭，导致文件描述符泄漏；改为缓存复用连接并在扫描结束时统一清理
- **修复** MCP `_db_cache` 跨扫描未清理，重复扫描同一项目时可能返回指向已替换文件的失效连接；MCP server 停止时自动关闭并清空缓存
- **修复** 扫描清理阶段 `AGENT_PROJECT_DIR` 环境变量在 MCP server 停止之前被移除，可能导致仍在处理的 MCP 请求找不到索引；调整为先停 MCP 再清理环境变量
- **修复** 旧版 Linux Universal Ctags 已编译 `+json` 但不支持 `--list-output-formats` 时被误判为不支持 JSON 输出的问题，改为用真实 `--output-format=json` 探测能力
- **优化** 检查项列表、SKILL 概览、结果看板和新建扫描页区分内置与用户创建的 checker，用户创建项显示在独立分区并带"用户创建"标签，新建扫描默认仅勾选内置检查项
- **优化** 结果看板汇总统计仅计算内置 checker 数据，用户创建 checker 不纳入总览指标
- **优化** 移除 opencode、API 直调和 AI 去误报复核基础提示词中禁止使用子 Agent 的限制

## 2026-05-27

- **新增** SKILL 市场支持在线创建纯 SKILL 项目级检查项，可选择在线 Agent 生成草稿、查看进度、编辑确认后导入市场
- **新增** 用户导入的 SKILL 保存到独立 `user_skills_dir` 目录，导入后作为 public 检查项进入 SKILL 列表和新建扫描选择项，所有登录用户可见可用
- **新增** Agent 支持 `skill_create` 命令，在 Agent 侧调用 opencode 执行 `deephole-skill-creator` 技能生成 `SKILL.md` 与场景说明草稿并回传服务端
- **优化** 新增 SKILL 页面基础信息区域更宽，描述字段改为多行输入，便于填写更完整的检查说明
- **优化** `deephole-skill-creator` 改为服务端系统 SKILL，并在创建 SKILL 任务时随命令下发到 Agent；创建任务会像扫描任务一样先判断并同步 Agent runtime 更新
- **修复** 旧 Agent 不认识 `skill_create` 命令时，创建 SKILL 会先通过扫描任务更新通道完成 Agent 自更新，再继续执行创建任务，避免提示 Unknown command type

## 2026-05-26

- **新增** `skill_only_project_audit` 管理员测试 checker，仅包含 `SKILL.md`，用于验证无 `analysis.py` 的项目级 opencode 审计和多结果提交链路
- **新增** 无 `analysis.py` 的 opencode checker 会自动生成项目级候选并直接运行 `SKILL.md`，支持同一次审计通过 MCP 多次提交真实函数和行号级结果
- **新增** SKILL 元数据支持「认证绕过」和「其他」两个漏洞维度，后续 checker 可通过 `checker.yaml` 的 `category` 字段归类展示
- **优化** AI 去误报复核改为优先处理未产生有效复核结果的报告，再处理已有复核结论的报告；二次复核无结果时不再覆盖旧结论
- **新增** 扫描详情页 AI 去误报复核支持停止按钮，可中断当前复核任务并保留已产生的复核结果
- **新增** `npd_funcret` checker，采用 semgrep 初筛 + tree-sitter 跨函数分析的混合方案，检测函数返回值或参数赋值给指针后未判空即解引用导致的空指针解引用（CWE-476），覆盖返回值直接赋值、带类型强转赋值、声明时赋值和传指针的指针参数赋值等场景
- **新增** `npd_funcret` 支持递归分析被调函数是否可能返回 NULL（最多 3 层），自动过滤不可能返回 NULL 的函数以降低误报
- **新增** `npd_funcret` 集中定义自定义空指针字面量（`VOS_NULL_PTR`、`FCA_NULL`）和自定义判空函数/宏（`CHECK_POINTER_RETURN`、`RET_IF_NULL_PTR` 等 10 个），semgrep 规则层和 analyzer 后处理层两级排除已判空的场景
- **优化** `npd_funcret` 的 LLM 审计提示词改为围绕函数内其他判空、空返回路径到解引用的可达性、以及调用上下文非空保护三点独立复核，避免过度相信静态分析候选结论
- **优化** 统一所有 checker 的 label 为「English Name / 中文名称」格式，便于国际化展示

## 2026-05-25

- **新增** 扫描任务支持配置产品维度，产品候选从 `config.yaml` 维护，新建扫描和历史扫描均可选择产品，未配置扫描显示为“未配置”
- **优化** 扫描历史列表第一列改为产品下拉并移除 Agent 列，结果看板支持按产品或未配置产品筛选统计
- **优化** 扫描历史列表的产品列支持表头筛选，可按具体产品或未配置产品过滤扫描任务
- **新增** SKILL 元数据支持资源泄露、死循环、非法内存使用、读写越界四类维度，并在 SKILL 概览和新建扫描页显示分类与 YAML 维护的最后修改时间，列表按更新时间倒序展示
- **新增** 用户反馈支持标记是否已提单并记录问题单号，扫描结果反馈和误报屏蔽规则面板会同步保存与展示提单状态
- **优化** 结果看板顶部新增扫描次数和已提单数，并在 SKILL 详情中展示对应提单统计
- **优化** 结果看板新增按已提单数计算的提单准确率，顶部总览、SKILL 详情和扫描明细同步展示
- **修复** 结果看板准确率字段在接口缺失或无法计算时统一显示为 `-`，避免出现 `NaN%`

## 2026-05-22

- **优化** `intoverflow` checker 改为 Semgrep 初筛高风险整数溢出/翻转候选并交由 opencode 语义复核，覆盖加减乘、长度减 header、size 乘法和窄化转换等场景，同时移除旧 tree-sitter 调用链追溯实现以降低误报来源
- **修复** Agent 扫描和 AI 去误报复核改为使用每任务隔离的 OpenCode 配置目录，并通过环境配置注入 MCP URL 与 SKILL 路径，避免同一项目多个任务并发时覆盖项目根 `opencode.json` 导致 MCP 端口串用
- **修复** Windows Agent 在 opencode 超时或取消时会终止完整进程树，并限制输出读取线程的退出等待时间，避免锁屏状态下子进程占用管道导致单候选审计卡到超时后很久才结束

## 2026-05-21

- **修复** 扫描详情页刷新后会丢失已存在的 AI 去误报复核列，并在复核运行中显示当前正在复核的漏洞位置
- **修复** `loop_mut_idx_oob` Semgrep 规则因动态 `metavariable-comparison` 和非法派生指针 pattern 导致真实扫描提不出候选的问题，并让 Semgrep runner 将日志和配置写入临时目录以兼容只读 home 环境
- **优化** `loop_mut_idx_oob` Semgrep 初筛改为更宽泛地召回循环中递增/递减索引参与数组、指针和内存函数访问的候选，缺失校验和真实越界交由 opencode 严格复核

## 2026-05-20

- **新增** Agent 配置支持从 `nga`、`opencode`、`hac`、`claude` 固定列表选择 LLM 审计工具，并可为 AI 去误报单独配置工具和模型；未配置时 AI 去误报默认继承 LLM 审计配置
- **优化** Agent 单次扫描选择多个规则时，LLM 审计队列会按各规则候选数量升序排序，优先审计候选更少的规则并在日志中输出实际审计顺序
- **优化** AI 去误报复核新增外部可触发性判断，复核结果会返回严重性标签；外部可触发的高风险漏洞会生成可在扫描详情页查看的 Markdown 漏洞报告
- **优化** 扫描历史和扫描详情页的表头筛选改为按钮式浮层菜单，降低表头高度和边框噪声，激活筛选时显示当前条件
- **优化** 扫描历史页支持在项目名称和创建者表头下拉筛选，扫描详情页结果表支持按文件、类型、严重性、AI 判定、用户反馈和 FP 复核表头筛选，并移除原顶部点击筛选按钮
- **新增** `loop_mut_idx_oob` checker，使用 Semgrep 初筛循环中变化索引参与数组下标、指针偏移和内存函数访问且缺少明显边界约束的潜在越界风险，并由 opencode 复核真实可达性
- **优化** `safe_mem_oob` 的 LLM 审计策略明确 `dstsz` 等于真实缓冲区大小时由安全函数容量校验拦截超长写入，不再继续依据 `count` 确认越界
- **优化** `safe_mem_oob` 删除 `dstsz` 与拷贝长度复用的高噪声检出规则，并扩充偏移目标、指针参数、成员子数组和格式化安全函数等更具体的 `dst/dstsz` 不匹配召回形态
- **优化** `mp_npd` 与 `mp_resouce_leak` 的候选转换优先从 semgrep message 获取函数名，并限制 CodeDB 路径 fallback 次数，避免少量候选在函数名解析阶段长时间停住
- **优化** `mp_npd` 与 `mp_resouce_leak` 在 Agent 控制台输出 semgrep 运行心跳和候选转换进度，便于定位大项目扫描卡在 semgrep 还是 JSON 转候选阶段
- **修复** 多个 semgrep checker 的候选函数定位改为优先按文件和行号查询索引，避免 `mp_resouce_leak`、`mp_npd` 等规则在 semgrep 结束后对每个命中重复全量扫描函数表导致卡住
- **修复** opencode 工作区配置默认允许读取、列举和搜索所有文件路径，并允许访问项目工作目录外的只读路径，避免审计过程中触发 `PermissionRejectedError` 后直接退出无结果
- **修复** semgrep checker 统一改为非交互式启动，关闭 stdin、metrics 和版本检查，并统一读取 `--json-output` 产物，避免 Agent 终端关闭后 semgrep 才继续执行或超时后丢失已产出的扫描结果
- **修复** Agent 扫描详情页索引进度轮询改用 scan_id 查询 Agent 专用接口，避免 Windows 项目路径被拼入 `/api/project/.../index-status` 后因盘符和斜杠触发 404
- **修复** Agent runtime 自更新不再把 `checkers/` 纳入重启判断，并为 runtime 更新包增加快照 manifest 校验，确保下载 zip 的文件集合、逐文件 hash 与服务端发布 hash 来自同一份快照，避免新建扫描时报 `Agent runtime update content hash mismatch`
- **修复** Windows Agent 启动脚本改为先检测 `python3`、再检测 `python`，两者都不可用时明确报错退出，避免缺少 Python 命令时继续执行后续步骤

## 2026-05-19

- **修复** Windows 中文系统（GBK/CP936）下所有 semgrep checker 静态分析因编码不兼容崩溃的问题，为 semgrep 子进程强制设置 UTF-8 环境变量，并在 semgrep 返回错误码但仍有部分扫描结果时继续解析而非直接丢弃
- **新增** Agent 扫描前自更新运行时代码：服务端 Agent 代码变更后，在线 Agent 会在启动扫描前下载最新 runtime 并重启继续执行，无需用户重新下载；`run_agent` 脚本变更仍需重新下载 Agent
- **修复** Agent runtime 更新包改为按创建扫描时的同一份内容快照生成 hash 并下载，避免新建扫描时报 `Agent runtime update content hash mismatch`
- **新增** Agent 配置页支持校验当前表单中的 LLM API 配置，校验请求在 Agent 所在机器上执行，便于确认 API 地址、Key 和模型是否可用
- **优化** 在线修改 Agent 配置会推送到运行中的 Agent，扫描从下一个候选点开始重新加载 LLM API、opencode 和代理配置
- **新增** 新建扫描支持分别配置“项目总路径”和“代码扫描路径”：代码索引与 opencode 使用项目总路径，静态分析仅扫描指定子目录，并统一候选路径以保证 MCP 源码查询可命中全量索引
- **新增** 前端页面 favicon 图标，浏览器标签页可显示 OpenDeepHole 项目标识
- **新增** `safe_mem_oob` checker，使用 semgrep 扫描安全内存/字符串函数中成员目标、偏移目标、指针 `sizeof`、`dstsz` 与拷贝长度复用等高风险 `dst/dstsz` 不匹配场景，并配套 SKILL 与场景文档
- **新增** Agent 初始化完成后输出代码索引统计，包含文件、函数、结构体/类/联合体、全局变量、函数调用关系和全局变量引用数量，便于判断 ctags/tree-sitter 建库是否异常
- **优化** 函数调用关系和 `g_` 全局变量引用改为基于 tree-sitter 遍历 ctags 已提取函数体生成，不再启动 cscope，也不再按全局变量逐个正则扫描全项目源码
- **优化** 代码索引在源码文件读取完成后继续显示 ctags 和 tree-sitter 引用索引进度，避免大型项目在 100% 后看起来卡住
- **调整** 暂停注册函数引用和全局变量引用 MCP 查询工具，底层索引数据仍保留给规则内部使用
- **修复** Agent 离线后后端会将该 Agent 名下仍处于静态分析/AI 审计中的扫描和去误报复核任务收敛为停止/错误状态，避免扫描历史长期显示“审计中”
- **重构** 代码索引迁移为 Universal Ctags + tree-sitter：函数、结构体/类和全局变量定义由 ctags 建索引，函数调用和全局变量引用由 tree-sitter 遍历函数体生成
- **优化** C++ 源码查询继续优先使用完整限定名，并为结构体/类短名查询兼容命名空间或类作用域中的限定名
- **修复** 旧版 `code_index.db` 不再被误判为可复用索引，缺少 Universal Ctags 或 JSON 输出支持时会明确失败并提示安装
- **优化** Agent 下载包和运行时更新包内置 Windows x64 Universal Ctags，`run_agent` 启动脚本优先使用包内 `ctags.exe`，不再通过 MSYS2/winget/pacman 自动安装 ctags
- **修复** Windows Agent 启动脚本会校验当前使用的 `ctags` 支持 JSON 输出，避免索引时报 `output format "json" is not available`
- **修复** ctags 中间文件改为写入源码目录内并使用相对路径调用，避免 Windows 下解析系统临时目录盘符路径失败
- **修复** Windows Agent 代码索引读取 ctags 输出时统一使用 UTF-8 容错解码，避免默认 GBK 解码失败后触发 `NoneType.splitlines` 扫描失败
- **修复** INF_LOOP semgrep 静态扫描超时调整为 15 分钟，并在超时后读取已写出的 JSON 结果继续进入 LLM 分析，避免扫描完成但进程未退出时丢失候选点

## 2026-05-18

- **新增** 本地 checker 测试命令 `tools/checker_test.py`，可在不启动后端的情况下校验 checker 元数据、Analyzer、代码索引和候选点输出，并支持可选 AI 审计
- **修复** Agent WebSocket 增加应用层 heartbeat/watchdog 主动重连，并放宽服务端和 Agent 的 keepalive 超时，降低长任务高负载时误判断联的概率
- **修复** Agent 代码索引改为完整构建后原子替换，避免索引阶段终止留下的半成品 `code_index.db` 被后续扫描复用
- **修复** LLM API 审计提示词在函数名匹配失败时改用代码索引中的文件和行号范围定位函数源码，减少误显示空上下文的问题
- **修复** 扫描详情页 CSV 下载改为携带登录态的 Blob 请求，避免管理员和普通用户点击下载时浏览器提示无法提取文件

## 2026-05-16

- **修复** Agent 最小依赖补充 `semgrep`，并优化 Windows/Linux 启动脚本的依赖检查，避免仅检测 `httpx` 导致 INF_LOOP 所需工具未安装
- **修复** INF_LOOP 静态分析在 semgrep 已识别函数名时仍可能把审计提示词函数名写成 `unknown` 的问题，并兼容 Windows 风格扫描路径
- **修复** Windows GBK/CP936 环境下死循环和资源泄露静态分析读取 semgrep/cppcheck 输出时可能因编码不兼容崩溃的问题
- **优化** 扫描历史页改为显示项目名称，并将漏洞数统一为 LLM 确认减 AI 去误报误报数，同时新增人工确认数量
- **修复** C++ 成员函数源码查询优先按完整限定名匹配，并兼容旧索引中的短名记录，避免多个类存在同名函数时误取源码
- **优化** 误报屏蔽规则注入内容改为用户理由加漏洞函数源码快照，常规扫描和 AI 去误报复核可获得更完整上下文
- **新增** API 模式 checker 在审计前检测 LLM API 可用性，配置不可用或调用失败时自动降级使用 opencode 模式继续扫描
- **修复** `mode: api` 的 checker 不再受旧版 `llm_api.enabled` 全局开关影响，避免 MEMLEAK 在 API 模式配置下误回退到 opencode
- **优化** Agent 控制台审计输出不再统一添加 `[opencode]` 前缀，API 直调日志会按 `[API]` 显示真实执行路径

## 2026-05-15

- **新增** Checker 热更新：后端在刷新列表和创建扫描时重新扫描 `checkers/` 目录，新增 checker 无需重启服务端
- **新增** 扫描下发时自动将选中的 checker 同步到 Agent，Agent 可直接使用新 checker 执行静态分析和 AI 审计
- **新增** `checker.yaml` 支持 `visibility: admin/public`，测试阶段 checker 可仅管理员可见，发布后再切换为所有用户可见
- **优化** 前端将“经验库”入口统一命名为“误报屏蔽规则”，并同步调整相关规则数量文案
- **优化** 顶部导航和对应页面标题改为更直观的中文入口名称，并增加鼠标悬停简介
- **优化** SKILL 概览页为启用中的 SKILL 增加“已启用”标记，便于区分可扫描规则和未启用规则
- **修复** Windows Agent 安装依赖时 `requirements-agent.txt` 在 GBK/CP936 环境下可能触发编码错误的问题
- **修复** 同一条漏洞报告多次提交用户反馈时改为覆盖原反馈，避免 SKILL 历史经验中重复注入同一误报

## 2026-05-14

- **新增** 登录用户可查看 SKILL/checker 介绍页，优先展示各 checker 的 `SCENARIOS.md`，缺失时回退展示 `SKILL.md`
- **优化** SKILL/checker 介绍页改用现成 Markdown 渲染库，支持标题、列表、代码块、引用和表格样式
- **优化** SKILL/checker 介绍页展示全部 checker，不受 `checker.yaml` 中 `enabled` 开关影响
- **优化** Checker Dashboard 左侧 SKILL 列表精简为名称和简介，详细统计保留在右侧详情视图
- **修复** 扫描详情页在 Agent 断开后重新连接时仍显示红色“Agent 断开连接”的旧错误提示，在线状态与断连提示保持一致
- **修复** Agent 连接后的配置页面与本地 `agent.yaml` 不一致的问题，Agent 握手会上报当前配置，页面优先展示真实配置
- **优化** Agent 配置默认值：API 调用超时改为 300 秒，opencode 超时改为 1200 秒，代理跳过列表默认包含 `10.0.0.0/8`
- **新增** Agent 配置页面支持显示和保存 LLM API 流式传输开关、opencode 最大重试次数，并确保保存后立即推送到在线 Agent 且写回 `agent.yaml`
- **调整** NPD、OOB、RESLEAK、SENSITIVE_CLEAR 检查项默认禁用
- **优化** memleak checker 改为按函数合并疑似问题点，同一函数只调用一次 LLM 并在单个 `submit_result` 中汇总所有点位
- **新增** Agent API 直调模式在控制台打印完整初始提示词，包含实际发送给 LLM 的 system 和 user 内容
- **修复** MEMLEAK API 直调模式优先读取 Agent 项目目录下的 `code_index.db`，避免 prompt 的函数源码段误显示“代码索引不可用”
- **修复** Windows Agent 启动脚本在系统缺少 `python3` 命令时无法启动的问题，自动回退使用 `python`

## 2026-05-13

- **修复** 服务端重启后 Agent 仍在扫描时的状态恢复问题，Agent 重连会重新挂回运行中扫描并继续提交进度和结果
- **修复** Agent 恢复/重连后候选点总数和已处理数量统计异常，保留原总数并按 processed checkpoint 同步进度
- **新增** 扫描任务支持按 `feedback_ids` 注入选中的正报/误报经验，Agent 扫描、恢复扫描和 AI 去误报均使用同一组选中经验
- **新增** 经验库新增反馈后自动加入当前扫描的选中经验，并实时刷新普通 SKILL 与 FP REVIEW SKILL 预览
- **优化** 历史经验章节统一为「历史用户经验」，同时包含正报与误报反馈，并按漏洞类型注入到对应 SKILL
- **优化** 运行中修改经验选择会推送到在线 Agent，刷新扫描工作区和 AI 去误报所使用的经验快照
- **修复** AI 去误报结果按扫描聚合最新复核结论，避免多次复核后前端和统计读取到旧结果
- **新增** 管理员 Checker 看板，按 SKILL 汇总扫描项目、静态报告问题数、LLM 判定问题数、FP 复核结果、人工确认数和准确率
- **优化** 管理员 Checker 看板顶部统览指标，新增复核确认、有效问题和人工确认统计，并修复状态列文字换行问题
- **新增** 管理员扫描历史页新增 Dashboard 入口，可点击每个 SKILL 查看对应扫描明细
- **优化** 服务端数据默认保存到项目上层 `OpenDeepHoleData/` 目录，不再写入 `/tmp/opendeephole`
- **优化** Docker 持久化卷同步挂载到 `/OpenDeepHoleData`
- **修复** Agent 模式下 `submit_result` 结果文件保存到扫描根目录的问题，改为保存到当前扫描目录，并增强结果读取路径日志

## 2026-05-12 (5)

- **修复** 去误报 prompt 改为中文单行格式，修复 LLM 找不到 fp-review 技能的问题
- **优化** 去误报仅复核用户未反馈的漏洞，已标记反馈的自动跳过
- **优化** 去误报按钮计数排除已有用户反馈的漏洞

## 2026-05-12 (4)

- **修复** Agent 重启后点击"AI去误报"仍报 Agent 未连接，现在按 agent_name 查找在线 Agent 而非依赖过期的 agent_id
- **修复** 标记漏洞反馈时推送 feedback_update 到 Agent 同样受过期 agent_id 影响，已一并修复
- **修复** 去误报按钮在恢复扫描后无法选择，移除必须扫描完成的限制，只要有 LLM 正报即可触发
- **优化** SKILL 反馈内容仅包含用户描述，不再包含漏洞原始内容
- **优化** 去误报 SKILL (fp_review.md) 翻译为中文，并合并用户反馈（历史误报经验）
- **新增** SKILL 预览面板新增 "FP REVIEW" 标签，可查看去误报 SKILL 及合并的用户反馈
- **新增** 在漏洞列表中标记反馈后，SKILL 预览（含 FP REVIEW）自动同步刷新
- **新增** FP 复核完成后，筛选栏新增 "FP复核:确认" 和 "FP复核:误报" 过滤按钮

## 2026-05-12 (3)

- **新增** LLM API 直调模式支持流式传输（`agent.yaml` 中配置 `llm_api.stream: true`），兼容仅支持流式返回的 API 接口
- **优化** memleak checker 的 prompt 中直接内嵌释放函数源码，LLM 无需调用查询工具即可获得完整上下文
- **新增** Candidate 模型新增 `related_functions` 字段，支持静态分析器将关联函数名传递给 AI 审计阶段

## 2026-05-12 (2)

- **重构** 停止机制：点击停止按钮后立即将扫描标记为已取消，不再依赖 Agent 响应，Agent 保持在线不断开
- **优化** 恢复机制：仅当扫描关联的原始 Agent 在线时才允许恢复，移除回退到任意在线 Agent 的逻辑
- **新增** 扫描列表新增 Agent 列，显示 Agent 名称及在线/离线状态（绿点/灰点）
- **新增** 扫描详情页顶部显示 Agent 名称和在线状态指示器
- **新增** 恢复按钮在 Agent 离线时自动禁用，悬停显示提示

## 2026-05-12

- **优化** 停止/恢复机制：静态分析、代码索引、AI审计各阶段均支持立即中断；被中断的候选不再被标记为已处理，恢复后会重新分析
- **优化** 代码索引和静态分析阶段改为线程池执行，不再阻塞事件循环，停止按钮可即时响应
- **新增** 代码索引和静态分析阶段的进度上报，Agent shell 显示实时进度，前端进度条同步更新
- **修复** 停止按钮无效问题：cancel_event 从 asyncio.Event 改为 threading.Event，解决跨线程信号不可靠的问题

## 2026-05-11

- **修复** Windows 下 opencode 子进程输出 GBK 解码报错，统一使用 UTF-8 编码
- **修复** opencode prompt 命令行长度截断导致 result_id 丢失，改为临时文件传递（Windows 直接传参，Linux 用 `$(cat file)` 命令替换）
- **重构** opencode 进程调用方式，独立线程写 stdin 避免阻塞，使用进程组管理便于 kill
- **新增** Agent 滚动输出中显示 opencode 初始提示词内容
- **修复** 禁止 LLM 使用子 Agent，确保 MCP 工具调用由自身直接执行
- **新增** 代码索引只保存在项目目录（避免重复索引），AI 去误报按钮常驻显示
