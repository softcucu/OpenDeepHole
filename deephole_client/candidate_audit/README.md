# 候选点审计过程

公开入口是异步函数 `run_candidate_audit(**kwargs)`，输入和输出都是整批数据。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `candidates` | 是 | `list[dict]` | 静态候选点 |
| `checker_dirs` | 是 | `list[path]` | checker 根目录 |
| `index_db_path` | 是 | path | 代码索引路径 |
| `checker_names` | 否 | `list[str]` | 只审计指定 checker |
| `concurrency` | 否 | int | 并发数，默认 1 |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `pattern_filter_enabled` | 否 | bool | 启用同模式过滤 |
| `pattern_filter_scope` | 否 | str | `function`、`file` 或 `global` |
| `feedback_entries` | 否 | `list[dict]` | 历史人工反馈 |
| `audit_index_offset` | 否 | int | 审计序号偏移 |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

```bash
python -m deephole_client.candidate_audit --project-path /src/project \
  --work-dir /tmp/audit --candidates candidates.json \
  --checker-dir ./checkers --index-db-path code_index.db \
  --task-agent-config ./task-agent.yaml
```
