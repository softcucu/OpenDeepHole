# 更新日志

## 2026-05-19

- **新增** 前端页面 favicon 图标，浏览器标签页可显示 OpenDeepHole 项目标识
- **新增** `safe_mem_oob` checker，使用 semgrep 扫描安全内存/字符串函数中成员目标、偏移目标、指针 `sizeof`、`dstsz` 与拷贝长度复用等高风险 `dst/dstsz` 不匹配场景，并配套 SKILL 与场景文档
- **新增** Agent 初始化完成后输出代码索引统计，包含文件、函数、结构体/类/联合体、全局变量、函数调用关系和全局变量引用数量，便于判断 ctags/cscope 建库是否异常
- **优化** cscope 函数调用引用查询改为 line-oriented 常驻进程，避免大型项目按函数符号逐次启动 cscope 导致索引过慢
- **优化** 代码索引在源码文件读取完成后继续显示 ctags、cscope 数据库构建、函数符号引用查询和全局变量引用索引进度，避免大型项目在 100% 后看起来卡住
- **修复** Agent 离线后后端会将该 Agent 名下仍处于静态分析/AI 审计中的扫描和去误报复核任务收敛为停止/错误状态，避免扫描历史长期显示“审计中”
- **重构** 代码索引从 tree-sitter 迁移为 Universal Ctags + cscope：函数、结构体/类和全局变量定义由 ctags 建索引，函数调用引用由 cscope 查询
- **优化** C++ 源码查询继续优先使用完整限定名，并为结构体/类短名查询兼容命名空间或类作用域中的限定名
- **修复** 旧版 tree-sitter `code_index.db` 不再被误判为可复用索引，缺少 `ctags` 或 `cscope` 时会明确失败并提示安装
- **修复** Windows Agent 启动脚本改为安装带 JSON 输出支持的 MSYS2 MinGW64 `ctags`，并确保 mingw64 工具路径优先于 usr 路径，避免索引时报 `output format "json" is not available`
- **修复** ctags/cscope 中间文件改为写入源码目录内并使用相对路径调用，避免 Windows 下 cscope 解析系统临时目录盘符路径失败
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
