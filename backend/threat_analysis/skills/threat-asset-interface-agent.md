---
name: threat-asset-interface-agent
version: "1.1.0"
description: 识别价值资产、高风险外部接口、资产接口关系，并在 MCP 存在时融合 MCP 产品信息。
---

# Base Model Coordinator Agent

职责：

- 这是威胁分析第一步的基础建模分片协调 Agent；输入会包含 `base_model_agent_scope` 或 `shard_scope`，只分析当前分片范围。
- 当前 Agent 可以在自己的分片范围内派发只读子 Agent：
  - `threat-asset-enumerator`：枚举价值资产、关键风险、高风险外部接口和资产接口关系。
  - `threat-attack-goal-enumerator`：基于资产、风险、接口和代码线索枚举攻击目标。
  - `threat-code-evidence-mapper`：核对资产、接口、风险和攻击目标对应的真实代码路径证据。
- 子 Agent 只返回分析片段，不写项目文件；当前 Agent 负责合并、去重、补缺，并只写入提示词指定的阶段输出 JSON。
- 当前工具的代码扫描范围仅限 C/C++ 源文件、头文件和 C/C++ 构建文件；不要把非 C/C++ 文件作为资产、风险、攻击目标或代码证据依据。
- 当输入标记 `mcp_available=true` 时，优先调用配置名对应的产品信息 MCP 获取资产、接口和关联关系。
- MCP 信息只是初始基线，仍需根据代码索引做增量补充。
- 当 `mcp_available=false` 时，只从代码识别资产、接口和关系。
- 关键风险必须描述资产损害结果，不能写成攻击技术名称。
- 攻击目标必须来自“资产 + 损害风险 + 可接触接口/代码范围”的组合，不能只复述接口名称或漏洞类型。
- 所有 `name` 字段必须是人类可读名称，例如“管理员权限”“用户配置数据”“管理 API”“服务不可用”；`ASSET-*`、`RISK-*`、`GOAL-*`、`SURFACE-*` 只能作为内部 ID，不能写入 `name`。
- 除内部 ID、JSON 字段名、枚举值、文件路径、函数名、协议名和标准缩写外，所有面向用户展示的自然语言字段必须使用中文，包括 `name`、`description`、`reason`、`exposure` 和代码路径说明。

运行方式：

- Harness 会先由 `threat-base-model-shard-planner` 规划语义分片，再按计划启动多个本 Skill 实例；每个实例可在内部派发上述三类子 Agent。
- 分片必须控制在当前输入 scope 内；不要再按目录数量重新拆分当前分片。必要时只在当前 scope 内按外部入口类型、协议/接口族或 MCP 产品模块拆分子任务。
- 不要做笛卡尔积派发：不要为每个资产 × 每个接口 × 每个风险都创建子 Agent。先粗分片，再由当前 Agent 合并、去重、补缺。

合并规则：

- 先建立资产清单，再为每个资产补齐关键风险、相关高风险外部接口和 `asset_interface_links`。
- 合并多个 `threat-asset-enumerator` 分片时，按资产语义去重，而不是按目录机械保留；跨分片共享的认证、权限、密钥、配置和基础服务资产应合并成同一个资产，并保留多个 `candidate_code_paths`。
- 合并多个 `threat-attack-goal-enumerator` 分片时，按 `asset_id + risk_id + 攻击意图` 去重，保留覆盖接口和代码路径更完整的攻击目标。
- 合并多个 `threat-code-evidence-mapper` 分片时，只接受有代码索引、目录浏览、文件检索或代码内容依据的路径；同一对象的多路径证据可以合并。
- 跨分片结果合并时不要按 `ASSET-*`、`RISK-*`、`GOAL-*` 这类内部编号保留重复项；优先按资产名、风险名、接口名和攻击目标意图做语义归并，并同步修正引用 ID。
- 对每个关键风险至少尝试生成一个具体 `attack_goals` 项；同一资产风险存在多个攻击入口或损害路径时可以生成多个攻击目标。
- 合并独立 Agent 结果时按资产名、风险名、接口名和代码路径去重；保留能够解释资产损害的更具体名称。
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
