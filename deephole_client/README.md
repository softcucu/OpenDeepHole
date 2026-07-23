# DeepHole Client

`deephole_client` 是仍以 “Agent” 展示和通信的本地客户端包。后端只下发任务；客户端协调
下面七个可独立运行的业务过程，并把它们的事件和最终结果转换成现有 HTTP/WebSocket 上报。

| 过程实现 | 平台异步入口 |
|---|---|
| `code_graph_build/` | `run_code_graph_build(**kwargs)` |
| `threat_analysis/` | `threat_analysis_runner.run_threat_analysis(**kwargs)` |
| `static_analysis/` | `run_static_analysis(**kwargs)` |
| `candidate_audit/` | `run_candidate_audit(**kwargs)` |
| `threat_audit/` | `run_threat_audit(**kwargs)` |
| `fp_review/` | `run_fp_review(**kwargs)` |
| `vulnerability_validation/` | `run_vulnerability_validation(**kwargs)` |

平台入口均为 `async`，只接受 `**kwargs`，未知 key 会报错。框架自有过程通过各目录 README
记录输入契约并可按需提供 `__main__.py`；威胁分析目录是原生实现的逐文件镜像，不向其中加入
平台 README、runner 或 `__main__.py`。业务过程不导入 `backend`、`reporter`、`server` 或
其它业务过程；需要模型时只调用 `task_agent.run_opencode_task()`。

单独提取时复制目标过程目录即可；需要模型的过程还要让通用 `task_agent` 包可导入，并可通过
`task_agent_config` 指向自己的 `task-agent.yaml`。不调用模型的代码图谱构建和静态规则分析
无需 Task Agent 配置。

接入已有实现时，实现可以直接占用对应过程目录，平台适配器放在目录外，只负责参数校验、
上下文绑定和调用。已有入口是同步函数也不需要修改实现，可由异步门面调用
`task_agent.run_sync_component()`；同步实现内部仍可正常使用
`task_agent.run_opencode_task()`。实现自己的 SKILL 目录通过门面的 `skill_paths` 上下文按任务
合并，不需要安装到 Agent 全局工作区。`threat_analysis/` 与来源
`ThreatAnalysis/src/threat_analysis_harness` 逐文件一致；相邻的
`threat_analysis_runner.py` 将它按原包名加载，不修改原生绝对导入。

## 威胁分析入口

```python
from deephole_client.threat_analysis_runner import run_threat_analysis

result = await run_threat_analysis(
    code_path="/src/project",
    output_path="/tmp/threat-analysis",
    is_resume=True,
    task_agent_config="./task-agent.yaml",
)
```

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

返回值不做平台格式转换。成功时包含 `result=true`、`value_asset_path`、
`attack_tree_path` 和 `high_risk_modules_path`；失败时包含 `result=false` 与 `reason`。

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
