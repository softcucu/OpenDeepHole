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

- 当前威胁分析代码扫描范围仅限 C/C++ 源文件、头文件和 C/C++ 构建文件；
  Python、TypeScript、Go、Java 等非 C/C++ 文件不会进入代码索引、分片派发或代码证据。
- 检测到时，基础建模阶段优先使用该 MCP 获取价值资产、高风险外部接口和关联关系，再做代码增量补充。
- 未检测到时，基础建模阶段完全从代码识别资产、接口和关联关系。
- 基础建模阶段先启动 1 个 `threat-asset-interface-agent`，一次性识别当前完整
  C/C++ 扫描范围内的价值资产、关键风险、高风险外部接口、资产接口关系和攻击目标。
- 初始识别完成后，Harness 会把当前已识别的价值资产和攻击目标列入输入，
  并行启动 3 个 `threat-base-model-gap-review-agent` 追问是否存在遗漏。
  追问 Agent 只输出遗漏或需要补充的项目，已覆盖项目不重复输出。
- Harness 最终合并初始识别 Agent 和 3 个追问 Agent 的结果，仍输出原有
  `assets`、`high_risk_external_interfaces`、`asset_interface_links`、
  `risks`、`attack_goals` JSON 契约。
- 基础建模合并会先把初始识别和追问补充中的资产、风险、接口和攻击目标 ID 归一，再按人类可读
  名称和语义 key 去重，避免同一价值资产被多个 `ASSET-*` 编号重复保留。
- 基础建模之后采用攻击树深度优先调度：拿到一个攻击目标后，按
  `攻击目标 -> 攻击域 -> 攻击面 -> 必要的方法确认` 逐分支下钻；一个
  攻击面及其方法确认处理完后再处理同域下一个攻击面，一个攻击域处理完后再处理
  同目标下一个攻击域，一个攻击目标处理完后再处理下一个攻击目标。不会先把所有
  攻击目标、攻击域或攻击面同层分解完再进入下一层。

新流程的事实源是当前扫描工作目录下的
`threat_analysis/stream/attack_paths.jsonl`。最终 `threat_analysis/res.json`
由 JSONL 归并生成；项目目录保持只读，旧项目根目录或 `runs/*/res.json`
仅作为历史缓存读取，不再写入。

默认实现会安装以下内置 Skill 到 OpenCode workspace：

- `threat-base-model-shard-planner`
- `threat-asset-interface-agent`
- `threat-base-model-gap-review-agent`
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
python -m deephole_client.threat_analysis_cli --project /path/to/project --implementation attack_tree
```
