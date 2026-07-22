# 静态分析过程

公开入口只有异步函数 `run_static_analysis(**kwargs)`。该目录不连接后端；事件通过
`output(event)` 上报，返回值可直接 JSON 序列化。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `index_db_path` | 是 | path | 已存在的 `code_index.db` |
| `checker_dirs` | 是 | `list[path]` | checker 根目录列表 |
| `code_scan_path` | 否 | path | 扫描子目录，默认项目根目录 |
| `checker_names` | 否 | `list[str]` | 只运行指定 checker |
| `deduplicate` | 否 | bool | 是否按位置、函数和类型去重，默认 `true` |
| `output` | 否 | callable | 接收结构化事件，可为同步或异步 callable |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

独立运行：

```bash
python -m deephole_client.static_analysis \
  --project-path /src/project \
  --index-db-path /src/project/code_index.db \
  --checker-dir ./checkers
```

事件写入 stderr，最终 JSON 写入 stdout；可用 `--output-file` 同时保存结果。
