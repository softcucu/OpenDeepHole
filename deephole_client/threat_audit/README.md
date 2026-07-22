# 威胁审计过程

公开入口是异步函数 `run_threat_audit(**kwargs)`。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `threat_analysis` | 是 | dict | 威胁分析完整结果 |
| `concurrency` | 否 | int | 并发任务数，默认 1 |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `include_task_ids` | 否 | `list[str]` | 只执行这些派生任务 |
| `exclude_task_ids` | 否 | `list[str]` | 排除这些派生任务 |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

```bash
python -m deephole_client.threat_audit --project-path /src/project \
  --work-dir /tmp/audit --threat-analysis /tmp/threat.json \
  --task-agent-config ./task-agent.yaml
```
