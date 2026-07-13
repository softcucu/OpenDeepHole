---
name: attack-tree-threat-analysis
version: "1.0.0"
description: 基于源代码和可选产品文档，识别产品关键资产、关键风险，并按攻击目标、攻击域/子系统、攻击面/协议/接口、可能攻击方式构建攻击树，同时为每个攻击面定位一条模块级关键代码路径。该 Skill 只做理论威胁分析和代码关注范围定位，不等同于漏洞审计或漏洞确认。

---

# 基于攻击树的威胁分析

## 运行时流程更新

默认威胁分析组件现在由 Harness 分层编排，不再要求单次调用直接生成最终
`res.json`。运行时以 `runs/<run_id>/stream/attack_paths.jsonl` 为唯一事实源：

```text
产品信息 MCP 检测
  → 资产与高风险外部接口建模
  → 攻击目标 Agent
  → 攻击域 Agent
  → 攻击面 Agent
  → 必要时的方法确认 Agent
  → 标准化与去重写入 attack_paths.jsonl
  → 从 JSONL 归并生成 runs/<run_id>/res.json
```

如果本 Skill 的旧章节仍要求“最终只输出 `res.json`”，以本节和运行时提示词为准。
各 Agent 只能写入运行时提示词指定的阶段输出 JSON，最终 `attack_paths.jsonl`
和 `res.json` 只能由 Harness 校验、标准化、去重和归并后生成。

通过攻击树分析方法对产品进行威胁分析：先识别价值资产及其关键风险，再将每个关键风险对应的具体攻击目标作为攻击树根节点，参考业界渗透测试方法分解攻击域、攻击面和可能的攻击方式。该分析仅用于理论威胁识别和后续渗透测试范围设计，不进行真实漏洞挖掘，也不确认漏洞是否存在。

## 1. 威胁分析3个关键步骤

### a. 价值资产识别

价值资产是系统中一旦被泄露、篡改、破坏、非法控制或停止服务，就会对产品、用户或组织造成明显损失的对象。价值资产通常包括数据、服务、软件、配置、凭据、密钥、权限和设备等。从攻击者视角看，价值资产是希望获取、控制或影响的对象，但价值资产本身不直接作为攻击树节点。需要先识别价值资产及其可能受到的关键风险，常见的价值资产包括但不仅于如下内容（[表1 常见的价值资产列表](https://openx.huawei.com/gitbook/project/5584/llm_training_base_master/_book/威胁分析.html#table62391154101618)）：

**表 1** 常见的价值资产列表

| **资产分类** | **价值资产示例**                                             | **攻击损失**                                                 |
| ------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **数据**     | **个人数据：**与一个身份已被识别或者身份可被识别的自然人（“数据主体”）相关的任何信息；身份可识别的自然人是指其身份可以通过诸如姓名、身份证号、位置数据等识别码或者通过一个或多个与自然人的身体、生理、精神、经济、文化或者社会身份相关的特定因素来直接或者间接地被识别。 | 资产泄露导致个人隐私数据泄露，会导致重大法务风险，会严重损害华为声誉，结合当前政治形势，引发华为面临重大商业风险。 |
|              | **安全类数据：**账号/口令、信任证书、设备证书、密钥、权限信息等 | 资产泄露或被篡改可能导致系统被非法控制或者越权操作，并通过系统任意控制华为设备，从而导致重大网络安全风险。 |
|              | **关键运维数据：**审计日志、配置数据、License数据、元数据信息、AI模型文件等 | 资产泄露或被篡改可能导致网络设备配置异常、功能异常、数据被越权使用、系统审计能力丢失等风险。 |
| **服务**     | **基础监控服务：**告警监控服务、态势感知功能等               | 资产被攻击或者劫持可能导致设备脱管，或者无法进行正常的基本情况监控，网络无法正常维护。 |
|              | **基础运维服务：**业务管理服务、运维服务等                   | 资产被攻击或者劫持可能导致设备脱管，或者无法进行基本的运维操作，网络无法正常管理。 |
|              | **业务服务：**提供正常服务的能力，比如信息服务、网络服务、办公服务、端侧支付业务等 | 资产被攻击可导致设备无法为客户提供正常的服务。               |
| **软件**     | **应用软件：**软件包、补丁包、适配层/组件包、工具等          | 资产被篡改可能导致系统无法正常部署/升级，或者系统工作异常，设备无法连接；或者在系统上运行其他无法应用，攻击者间接获取价值；资产泄露可能通过逆向工程获取软件包中的关键/机密信息，从而降低攻击者攻击网络的难度。 |
|              | **系统软件：**操作系统镜像/设备驱动程序/数据库软件等         | 资产被篡改可能被植入恶意程序，利用系统漏洞获取系统高级权限，可以执行任意程序，从而使攻击者可以任意控制整个系统，甚至控制华为设备。 |
| **硬件**     | 服务器/磁阵/网络设备/机柜/电源等                             | 资产被偷盗可能导致隐私数据泄露；硬件资源被篡改导致恶意攻击。 |

### b. 基于攻击树的威胁分析

本 Skill 使用固定四层结构对威胁进行分类和分解，不表达节点之间的逻辑组合关系，也不表示攻击行为的实际执行顺序。

价值资产不是攻击树节点。一个价值资产可以对应一个或多个关键风险，每个关键风险原则上生成一棵攻击树，关键风险对应的具体攻击目标作为攻击树根节点。整体关系如下：

```text
价值资产
  → 关键风险
    → 攻击目标 goal
      → 攻击域/子系统 domain
        → 攻击面/协议/接口 surface
          → 可能的攻击方式 method
```

各层级含义如下：

* 根节点 `goal`：关键风险对应的具体攻击目标，例如“造成基站服务中断”。
* 中间节点 `domain`：可能导致攻击目标实现的攻击域、功能域或子系统。
* 中间节点 `surface`：攻击者可能接触、输入、调用或影响的协议、接口、服务、端口、文件、配置或消息入口。
* 叶子节点 `method`：针对某个攻击面理论上可能采用的攻击方式。`method` 节点不再向下分解。

攻击树用于描述“哪些攻击域、攻击面和攻击方式可能导致目标风险”，为后续渗透测试确定覆盖范围。所有攻击方式均为理论攻击假设，不表示对应漏洞已经存在或能够成功利用。

对每个识别出的关键风险，根据产品功能、代码结构、外部暴露面和业界常见攻击模式进行攻击树分析。下面是一个完整关系示例：



~~~mermaid
graph TD
    A["关键资产：基站服务"]
    B["关键风险：服务不可用"]
    C["攻击目标：造成基站服务中断"]

    D1["攻击域：基站管理面"]
    D2["攻击域：空口协议栈"]
    D3["攻击域：软件管理"]

    E1["攻击面：管理接口"]
    E2["攻击面：RRC协议"]
    E3["攻击面：PDCP协议"]
    E4["攻击面：软件包升级"]

    F11["可能攻击方式：口令爆破"]
    F12["可能攻击方式：认证绕过"]
    F13["可能攻击方式：接口泛洪"]

    F21["可能攻击方式：畸形RRC消息"]
    F22["可能攻击方式：RRC消息泛洪"]
    F23["可能攻击方式：状态机异常触发"]

    F31["可能攻击方式：畸形PDCP报文"]
    F32["可能攻击方式：重放攻击"]
    F33["可能攻击方式：资源耗尽攻击"]

    F41["可能攻击方式：完整性校验绕过"]
    F42["可能攻击方式：路径穿越"]
    F43["可能攻击方式：恶意冷热补丁"]

    A --> B
    B --> C

    C --> D1
    C --> D2
    C --> D3

    D1 --> E1
    E1 --> F11
    E1 --> F12
    E1 --> F13

    D2 --> E2
    D2 --> E3

    E2 --> F21
    E2 --> F22
    E2 --> F23

    E3 --> F31
    E3 --> F32
    E3 --> F33

    D3 --> E4
    E4 --> F41
    E4 --> F42
    E4 --> F43
```
~~~



### c. 代码路径映射

对每个攻击树，根据每个攻击面查看代码仓，分析其对应的代码路径，可能是一个或多个。代码路径必须通过目录浏览、文件检索、符号检索或代码内容确认真实存在，禁止根据常见工程命名习惯推测或编造路径。无法定位可信代码路径时，仍保留该攻击面的映射记录，并将 `code_paths` 输出为空数组。例如：

| 攻击域/子系统 | 攻击面/协议/接口 | 对应代码路径                                                 |
| ------------- | ---------------- | ------------------------------------------------------------ |
| 基站管理面    | 管理接口         | `/src/management/api/`<br>`/src/management/auth/`<br>`/src/service/control/` |
| 空口协议栈    | RRC协议          | `/src/rrc/transport/`<br>`/src/rrc/codec/`<br>`/src/rrc/state_machine/` |
| 空口协议栈    | PDCP协议         | `/src/pdcp/receive/`<br>`/src/pdcp/security/`<br>`/src/pdcp/delivery/` |
| 软件管理      | 软件包升级       | `/src/upgrade/package/`<br>`/src/upgrade/verify/`<br>`/src/upgrade/install/`<br>`/src/upgrade/patch/` |

## 2. 输出要求

### 2.1 总体结构

LLM 最终只输出一个合法 JSON 对象，保存到当前目录下，文件名为 `res.json`，输出内容要求如下：

```json
{
  "schema_version": "1.0",
  "analysis_id": "ATA-001",
  "sources": {
    "repositories": [],
    "documents": []
  },
  "assets": [],
  "attack_trees": [],
  "code_path_mappings": []
}
```

`sources` 用于记录本次分析实际使用的输入来源：

```json
{
  "repositories": [
    ".",
    "components/gnb"
  ],
  "documents": [
    "docs/product-design.md",
    "docs/interface-specification.pdf"
  ]
}
```

字段说明：

| Key | 填写内容 |
| --- | --- |
| `repositories` | 实际分析的代码仓根目录或代码目录，使用字符串数组；未提供代码时输出空数组 |
| `documents` | 实际分析的产品文档路径，使用字符串数组；未提供文档时输出空数组 |

路径应使用当前分析环境中可识别的相对路径或输入名称，不得填写未实际使用的来源。

三个核心业务对象：

```text
assets
    关键资产及其关键风险

attack_trees
    每个关键风险对应的攻击树

code_path_mappings
    攻击面与模块级代码路径的映射
```

### 2.2  关键资产

```json
{
  "asset_id": "ASSET-001",
  "name": "基站服务",
  "description": "基站向终端提供无线接入、信令处理和数据传输服务",
  "asset_type": "service",
  "criticality": "critical",
  "risks": [
    {
      "risk_id": "RISK-001",
      "name": "服务不可用",
      "security_property": "availability",
      "description": "基站服务被异常停止、阻塞、崩溃或耗尽资源"
    }
  ]
}
```

#### 字段枚举

`asset_type`：

```text
service
data
credential
privilege
software
configuration
key
device
other
```

`criticality`：

```text
critical
high
medium
low
```

`security_property`：

```text
confidentiality
integrity
availability
authenticity
authorization
accountability
```

风险名称必须描述关键资产受到的损害结果，例如：

```text
服务不可用
配置被未授权篡改
用户数据泄露
管理员权限被未授权获取
软件完整性被破坏
```

风险名称不应直接使用攻击技术名称，例如：

```text
SQL注入
路径穿越
缓冲区溢出
口令爆破
```

这些属于攻击方式。

### 2.3  攻击树

每个关键风险原则上对应一棵攻击树。

ID 和引用关系要求：

* `asset_id`、`risk_id`、`tree_id` 和 `node_id` 在整个 `res.json` 中分别保持唯一。
* `attack_tree.asset_id` 必须引用 `assets` 中已存在的资产。
* `attack_tree.risk_id` 必须引用该资产 `risks` 中已存在的风险。
* `root_node_id` 必须引用当前攻击树中 `node_type` 为 `goal` 的根节点。
* `parent_id` 必须引用当前攻击树中已存在的父节点；根节点的 `parent_id` 为 `null`。

```json
{
  "tree_id": "TREE-001",
  "asset_id": "ASSET-001",
  "risk_id": "RISK-001",
  "attack_goal": "造成基站服务中断",
  "root_node_id": "NODE-001",
  "nodes": []
}
```

攻击树使用扁平节点数组，通过 `node_id` 和 `parent_id` 表达层级关系。

```json
{
  "node_id": "NODE-001",
  "parent_id": null,
  "node_type": "goal",
  "name": "造成基站服务中断",
  "order": 1,
  "basis": []
}
```

#### 2.3.1 固定层级

```text
goal
  攻击目标

domain
  攻击域或子系统

surface
  攻击面、协议或接口

method
  可能的攻击方式
```

节点关系必须满足：

```text
goal
  └── domain
        └── surface
              └── method
```

`node_type` 只能使用：

```text
goal
domain
surface
method
```

其中：

* `goal` 是攻击树根节点。
* `domain` 是可能导致攻击目标实现的攻击域或子系统。
* `surface` 是攻击者可能接触或影响的协议、接口、文件、服务或配置入口。
* `method` 是理论上可能采用的具体攻击方式。`method` 节点不得包含子节点。

`surface_type` 仅用于 `surface` 节点，可使用以下枚举值：

```text
protocol
api
interface
service
port
file
message
configuration
command
package
physical
other
```

`method`选择可参考attack-method-reference-catalog.md，不在该文档的也可以根据实际分析情况填写。

`preconditions` 仅用于 `method` 节点，表示该攻击方式成立所需的功能条件、访问条件或环境条件。每个 `method` 节点都应包含该字段；无法识别明确前提时输出空数组。

`order` 表示同一父节点下兄弟节点的展示顺序，从 `1` 开始编号。同一父节点下的 `order` 不应重复，不同父节点下可以重新从 `1` 开始。

#### 2.3.2 攻击树示例

```json
{
  "tree_id": "TREE-001",
  "asset_id": "ASSET-001",
  "risk_id": "RISK-001",
  "attack_goal": "造成基站服务中断",
  "root_node_id": "NODE-001",
  "nodes": [
    {
      "node_id": "NODE-001",
      "parent_id": null,
      "node_type": "goal",
      "name": "造成基站服务中断",
      "order": 1,
      "basis": [
        "基站服务依赖管理面、空口协议栈和软件管理模块"
      ]
    },
    {
      "node_id": "NODE-002",
      "parent_id": "NODE-001",
      "node_type": "domain",
      "name": "基站管理面",
      "order": 1,
      "basis": []
    },
    {
      "node_id": "NODE-003",
      "parent_id": "NODE-002",
      "node_type": "surface",
      "name": "管理接口",
      "surface_type": "interface",
      "order": 1,
      "basis": [
        "代码中存在管理接口、认证和服务控制模块"
      ]
    },
    {
      "node_id": "NODE-004",
      "parent_id": "NODE-003",
      "node_type": "method",
      "name": "口令爆破",
      "order": 1,
      "basis": [],
      "preconditions": [
        "管理接口允许远程登录",
        "系统使用口令认证"
      ]
    },
    {
      "node_id": "NODE-005",
      "parent_id": "NODE-003",
      "node_type": "method",
      "name": "认证绕过",
      "order": 2,
      "basis": [],
      "preconditions": [
        "管理请求经过身份认证处理"
      ]
    },
    {
      "node_id": "NODE-006",
      "parent_id": "NODE-003",
      "node_type": "method",
      "name": "管理接口泛洪",
      "order": 3,
      "basis": [],
      "preconditions": [
        "攻击者能够持续访问管理接口"
      ]
    },
    {
      "node_id": "NODE-007",
      "parent_id": "NODE-001",
      "node_type": "domain",
      "name": "空口协议栈",
      "order": 2,
      "basis": []
    },
    {
      "node_id": "NODE-008",
      "parent_id": "NODE-007",
      "node_type": "surface",
      "name": "RRC协议",
      "surface_type": "protocol",
      "order": 1,
      "basis": [
        "代码中存在RRC消息接收、解码和状态机模块"
      ]
    },
    {
      "node_id": "NODE-009",
      "parent_id": "NODE-008",
      "node_type": "method",
      "name": "畸形RRC消息",
      "order": 1,
      "basis": [],
      "preconditions": [
        "攻击者能够向基站发送RRC消息"
      ]
    },
    {
      "node_id": "NODE-010",
      "parent_id": "NODE-008",
      "node_type": "method",
      "name": "RRC消息泛洪",
      "order": 2,
      "basis": [],
      "preconditions": [
        "攻击者能够持续发起空口信令过程"
      ]
    },
    {
      "node_id": "NODE-011",
      "parent_id": "NODE-001",
      "node_type": "domain",
      "name": "软件管理",
      "order": 3,
      "basis": []
    },
    {
      "node_id": "NODE-012",
      "parent_id": "NODE-011",
      "node_type": "surface",
      "name": "软件包升级",
      "surface_type": "interface",
      "order": 1,
      "basis": [
        "代码中存在软件包接收、校验、安装和补丁处理模块"
      ]
    },
    {
      "node_id": "NODE-013",
      "parent_id": "NODE-012",
      "node_type": "method",
      "name": "完整性或签名校验绕过",
      "order": 1,
      "basis": [],
      "preconditions": [
        "系统支持加载外部升级包"
      ]
    },
    {
      "node_id": "NODE-014",
      "parent_id": "NODE-012",
      "node_type": "method",
      "name": "升级包路径穿越",
      "order": 2,
      "basis": [],
      "preconditions": [
        "系统需要解压或写入升级包文件"
      ]
    },
    {
      "node_id": "NODE-015",
      "parent_id": "NODE-012",
      "node_type": "method",
      "name": "恶意冷热补丁加载",
      "order": 3,
      "basis": [],
      "preconditions": [
        "系统支持冷补丁或热补丁功能"
      ]
    }
  ]
}
```

### 2.4 代码路径映射

代码路径以攻击面 `surface` 为单位，不以具体攻击方式 `method` 为单位。每个 `surface` 节点对应一条代码路径映射记录。代码路径必须在输入代码仓中真实存在；无法定位时输出空数组，不得为了补全结果而生成推测路径。路径相对于 `sources.repositories` 中的代码仓根目录填写；存在多个代码仓时，应在路径中保留能够区分代码仓的目录前缀。

例如攻击树中有：

```text
攻击域：空口协议栈
└── 攻击面：RRC协议
    ├── 畸形RRC消息
    ├── RRC消息泛洪
    └── 状态机异常触发
```

对应代码主要位于：

```text
src/rrc/transport
src/rrc/codec
src/rrc/state_machine
```

映射写法：

```json
{
  "surface_node_id": "NODE-003",
  "code_paths": [
    {
      "path": "src/rrc/transport",
      "description": "RRC消息接收和传输处理"
    },
    {
      "path": "src/rrc/codec",
      "description": "RRC消息编解码和字段解析"
    },
    {
      "path": "src/rrc/state_machine",
      "description": "RRC状态机和流程处理"
    }
  ]
}
```

字段说明：

| Key               | 填写内容 |
| ----------------- | -------- |
| `surface_node_id` | 对应攻击树中的 `surface` 节点 ID |
| `code_paths`      | 该攻击面对应的一个或多个代码路径；无法定位时输出空数组 |
| `path`            | 已确认真实存在的代码目录或文件路径 |
| `description`     | 该路径负责的主要功能，以及它与攻击面的关系 |
