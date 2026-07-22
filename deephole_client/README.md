# DeepHole Client

`deephole_client` 是仍以 “Agent” 展示和通信的本地客户端包。后端只下发任务；客户端协调
下面六个可独立运行的业务过程，并把它们的事件和最终结果转换成现有 HTTP/WebSocket 上报。

| 目录 | 唯一公开异步入口 |
|---|---|
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

统一事件格式：

```json
{
  "process": "candidate_audit",
  "kind": "log|progress|item|artifact",
  "message": "...",
  "data": {}
}
```

源码索引仍由客户端协调器负责。静态分析接收已有 `code_index.db`，不会自行建立索引。
