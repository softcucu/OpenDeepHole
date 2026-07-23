# DeepHole Client

`deephole_client` 是仍以 “Agent” 展示和通信的本地客户端包。后端只下发任务；客户端协调
下面七个可独立运行的业务过程，并把它们的事件和最终结果转换成现有 HTTP/WebSocket 上报。

| 目录 | 唯一公开异步入口 |
|---|---|
| `code_graph_build/` | `run_code_graph_build(**kwargs)` |
| `threat_analysis/` | `run_threat_analysis(**kwargs)` |
| `static_analysis/` | `run_static_analysis(**kwargs)` |
| `candidate_audit/` | `run_candidate_audit(**kwargs)` |
| `threat_audit/` | `run_threat_audit(**kwargs)` |
| `fp_review/` | `run_fp_review(**kwargs)` |
| `vulnerability_validation/` | `run_vulnerability_validation(**kwargs)` |

每个目录自己的 README 是输入契约的权威文档。所有入口均为 `async`，只接受 `**kwargs`，
未知 key 会报错；目录内的 `__main__.py` 使用明确的 CLI 参数，事件 JSON 行写 stderr，最终
JSON 写 stdout。业务过程不导入 `backend`、`reporter`、`server` 或其它业务过程；需要模型时
只调用 `task_agent.run_opencode_task()`。

单独提取时复制目标过程目录即可；需要模型的过程还要让通用 `task_agent` 包可导入，并可通过
`task_agent_config` 指向自己的 `task-agent.yaml`。不调用模型的代码图谱构建和静态规则分析
无需 Task Agent 配置。

接入已有实现时，实现代码放在对应过程目录的内部子目录，外层 `runner.py` 只负责参数校验、
上下文绑定和调用。已有入口是同步函数也不需要修改实现，可由异步门面调用
`task_agent.run_sync_component()`；同步实现内部仍可正常使用
`task_agent.run_opencode_task()`。实现自己的 SKILL 目录通过门面的 `skill_paths` 上下文按任务
合并，不需要安装到 Agent 全局工作区。`threat_analysis/` 就是这一模式的完整样例，其
`threat_analysis_harness/` 与来源实现逐文件一致。

统一事件格式：

```json
{
  "process": "candidate_audit",
  "kind": "log|progress|item|artifact",
  "message": "...",
  "data": {}
}
```

协调器先调用代码图谱构建，再并行启动静态分析与威胁分析；静态分析只读取已有
`code_index.db`，候选点审计只消费静态分析结果。威胁分析保持原生三份 JSON 产物和原生
返回值，协调器只在上报时把文件装入透明 artifact bundle；威胁审计直接读取其中的攻击树和
高风险模块文件，并按每个攻击模式拆分任务。后端不执行这些过程，也不维护实现专属 Schema。
