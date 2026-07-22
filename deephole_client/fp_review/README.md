# 去误报过程

公开入口是异步函数 `run_fp_review(**kwargs)`。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `review_id` | 是 | str | 本次复核标识 |
| `vulnerabilities` | 是 | `list[dict]` | 待复核漏洞批次 |
| `feedback_entries` | 否 | `list[dict]` | 人工反馈 |
| `history` | 否 | `list[dict]` | 历史复核信息 |
| `processed_offset` | 否 | int | 已处理数量偏移 |
| `concurrency` | 否 | int | 并发数，默认 1 |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

```bash
python -m deephole_client.fp_review --project-path /src/project \
  --work-dir /tmp/fp --scan-id scan-1 --review-id review-1 \
  --vulnerabilities vulnerabilities.json --task-agent-config ./task-agent.yaml
```
