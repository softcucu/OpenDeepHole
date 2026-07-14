# Threat Analysis

威胁分析后端代码集中在本目录，扫描流程只依赖 `ThreatAnalysisImplementation` 接口。

## 配置

```yaml
threat_analysis:
  enabled: true
  implementation: "attack_tree"
  attack_path_audit_mode: "after_analysis"
  product_mcp_name: "product-info"
  product_mcp_detection_timeout_seconds: 60
```

`attack_path_audit_mode` 控制威胁分析生成攻击路径后的审计调度：

- `after_analysis`：默认值。先等威胁分析所有阶段完成并归并结果，再统一启动威胁审计。
- `immediate`：每当攻击路径写入并归并到 JSONL 后，立即派发对应威胁审计任务；最终只补跑未被即时派发的路径。

`attack_tree` 是默认实现。运行时会先在 OpenCode 当前配置中检测
`product_mcp_name` 对应的产品信息 MCP：

- 检测到时，基础建模阶段优先使用该 MCP 获取价值资产、高风险外部接口和关联关系，再做代码增量补充。
- 未检测到时，基础建模阶段完全从代码识别资产、接口和关联关系。
- 基础建模阶段由 Harness 按代码索引、顶层目录或语言启动多个
  `threat-asset-interface-agent` 分片协调 Agent。每个协调 Agent 可以在自己的
  scope 内派发 `threat-asset-enumerator`、`threat-attack-goal-enumerator`、
  `threat-code-evidence-mapper` 子 Agent 做交叉分析，再输出完整基础模型片段。
- Harness 最终合并多个分片协调 Agent 的结果，仍输出原有
  `assets`、`high_risk_external_interfaces`、`asset_interface_links`、
  `risks`、`attack_goals` JSON 契约。
- 分片要避免资产 × 接口 × 风险的笛卡尔积爆炸；优先按顶层目录、主要语言、
  外部入口类型、协议/接口族或 MCP 产品模块粗分片。
- 基础建模之后采用攻击树优先调度：拿到一个攻击目标后立即展开该目标下的
  攻击域、攻击面和必要的方法确认，尽快产出这一棵攻击树；不会先把所有攻击目标
  全部分解完再进入下一层。

新流程的事实源是 `runs/<scan_id>/stream/attack_paths.jsonl`。最终
`runs/<scan_id>/res.json` 由 JSONL 归并生成，项目根目录 `res.json` 仅作为旧缓存兼容副本。

默认实现会安装以下内置 Skill 到 OpenCode workspace：

- `threat-asset-interface-agent`
- `threat-asset-enumerator`
- `threat-attack-goal-enumerator`
- `threat-code-evidence-mapper`
- `threat-attack-goal-agent`
- `threat-attack-domain-agent`
- `threat-attack-surface-agent`
- `threat-method-confirm-agent`

## 新增实现

1. 新建实现类，满足 `backend.threat_analysis.base.ThreatAnalysisImplementation`。
2. 在 `backend/threat_analysis/registry.py` 注册实现 ID。
3. 将 `threat_analysis.implementation` 改为新的实现 ID。

## 单独运行

```bash
python -m backend.threat_analysis.cli --project /path/to/project --implementation attack_tree
```
