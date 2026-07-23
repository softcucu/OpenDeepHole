# 威胁分析过程

本目录是完整、可独立运行的威胁分析过程。公开入口只有异步函数
`run_threat_analysis(**kwargs)`；平台协调器只负责调用它和上报结果。

`threat_analysis_harness/` 是从
`ThreatAnalysis/src/threat_analysis_harness` 原样嵌入的实现，框架适配全部放在
`runner.py`，不要为了接入平台修改嵌入目录。

## 函数参数

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `code_path` | 是 | path | 待分析代码目录 |
| `output_path` | 是 | path | 原生产物输出目录；不存在时创建 |
| `is_resume` | 否 | bool | 是否复用原生阶段产物，默认 `false` |
| `product_mcp` | 否 | str 或 null | 原生预留参数，原样传入 |
| `attack_modes` | 否 | mapping 或 null | 原生预留参数，原样传入 |
| `task_agent_config` | 否 | path | 脱离平台运行时使用的 Task Agent YAML |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

未知 key 会抛出 `TypeError`。入口始终是异步函数：

```python
from deephole_client.threat_analysis import run_threat_analysis

result = await run_threat_analysis(
    code_path="/src/project",
    output_path="/tmp/threat-analysis",
    is_resume=True,
    task_agent_config="./task-agent.yaml",
)
```

返回值不做平台格式转换，和原生实现完全一致。成功时：

```json
{
  "result": true,
  "value_asset_path": "/tmp/threat-analysis/.../value-assets.json",
  "attack_tree_path": "/tmp/threat-analysis/.../attack_trees.json",
  "high_risk_modules_path": "/tmp/threat-analysis/.../high-risk-module-merge.json"
}
```

失败时：

```json
{"result": false, "reason": "..."}
```

## 独立运行

```bash
python -m deephole_client.threat_analysis \
  --code-path /src/project \
  --output-path /tmp/threat-analysis \
  --task-agent-config ./task-agent.yaml \
  --resume
```

结构化事件按 JSON 行写入 stderr，最终原生返回值写入 stdout。CLI 成功退出码为
`0`，原生结果失败时为 `1`。
