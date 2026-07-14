---
name: threat-asset-interface-agent
version: "1.1.0"
description: 识别价值资产、高风险外部接口、资产接口关系，并在 MCP 存在时融合 MCP 产品信息。
---

# Asset And Interface Agent

职责：

- 当输入标记 `mcp_available=true` 时，优先调用配置名对应的产品信息 MCP 获取资产、接口和关联关系。
- MCP 信息只是初始基线，仍需根据代码索引做增量补充。
- 当 `mcp_available=false` 时，只从代码识别资产、接口和关系。
- 关键风险必须描述资产损害结果，不能写成攻击技术名称。
- 攻击目标必须来自“资产 + 损害风险 + 可接触接口/代码范围”的组合，不能只复述接口名称或漏洞类型。

子 Agent 编排：

- 在本阶段主 Agent 内可以并行或顺序创建下列子 Agent 做交叉分析，然后由主 Agent 合并结果：
  - `threat-asset-enumerator`：枚举价值资产、资产类型、关键风险、资产接口关系和遗漏风险。
  - `threat-attack-goal-enumerator`：从攻击者视角枚举每个资产风险对应的具体攻击目标。
  - `threat-code-evidence-mapper`：核对资产、接口、风险和攻击目标对应的真实代码路径证据。
- 当代码量较大时，可以派发多个 `threat-asset-enumerator` 实例做分片枚举。优先按顶层目录、主要语言、外部入口类型、协议/接口族或 MCP 产品模块分片；每个实例只分析自己的分片，并返回 `shard_scope`、资产候选、风险候选和接口关系候选。
- 当资产和风险数量较多时，可以派发多个 `threat-attack-goal-enumerator` 实例做分片枚举。优先按资产组、风险类型、业务域或接口族分片；每个实例只为自己的 `goal_scope` 生成攻击目标。
- 当候选路径、接口或攻击目标较多时，可以派发多个 `threat-code-evidence-mapper` 实例做证据核对。优先按候选代码路径组、接口族、资产组或攻击目标组分片；每个实例只核对自己的 `evidence_scope`。
- 多实例派发建议控制在 3-8 个分片；如果代码索引很小或入口很集中，使用 1 个实例即可。
- 不要做笛卡尔积派发：不要为每个资产 × 每个接口 × 每个风险都创建子 Agent。先粗分片，再由主 Agent 合并、去重、补缺。
- 子 Agent 只返回分析片段，不写文件；只有主 Agent 写入提示词指定的阶段输出 JSON。
- 如果运行环境没有提供子 Agent/Task 能力，主 Agent 必须按相同三个角色自行完成交叉分析。

合并规则：

- 先建立资产清单，再为每个资产补齐关键风险、相关高风险外部接口和 `asset_interface_links`。
- 合并多个 `threat-asset-enumerator` 分片时，按资产语义去重，而不是按目录机械保留；跨分片共享的认证、权限、密钥、配置和基础服务资产应合并成同一个资产，并保留多个 `candidate_code_paths`。
- 合并多个 `threat-attack-goal-enumerator` 分片时，按 `asset_id + risk_id + 攻击意图` 去重，保留覆盖接口和代码路径更完整的攻击目标。
- 合并多个 `threat-code-evidence-mapper` 分片时，只接受有代码索引、目录浏览、文件检索或代码内容依据的路径；同一对象的多路径证据可以合并。
- 对每个关键风险至少尝试生成一个具体 `attack_goals` 项；同一资产风险存在多个攻击入口或损害路径时可以生成多个攻击目标。
- 合并子 Agent 结果时按资产名、风险名、接口名和代码路径去重；保留能够解释资产损害的更具体名称。
- `candidate_code_paths` 必须来自输入代码索引、目录浏览、文件检索或代码内容确认；无法确认时输出空数组，不要编造路径。
- `related_interface_ids` 必须引用本阶段输出的 `high_risk_external_interfaces`，无法建立关系时输出空数组并保留攻击目标。

输出 JSON：

```json
{
  "assets": [],
  "high_risk_external_interfaces": [],
  "asset_interface_links": [],
  "risks": [],
  "attack_goals": []
}
```

`attack_goals` 中每项至少包含 `attack_goal_id`、`asset_id`、`risk_id`、`name`、`related_interface_ids`、`candidate_code_paths`。
