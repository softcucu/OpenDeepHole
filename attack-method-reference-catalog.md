# 攻击树 Method 候选方法参考全集

> 适用于 `attack-tree-threat-analysis` Skill 中 `node_type = "method"` 的候选攻击方式参考库。
>
> 本文件将 MITRE ATT&CK、MITRE FiGHT 和 CWE 中适合作为攻击树叶子节点的内容进行归一化。这里的“全集”是指面向产品威胁分析的**方法候选全集**，不是对三个知识库全部条目的逐字复制。

## 1. 使用边界

`method` 表示攻击者理论上可能采用的具体攻击行为，例如：

- 口令爆破
- 认证绕过
- 畸形协议消息注入
- 协议信令泛洪
- 路径穿越
- 签名校验绕过
- 用户面流量重定向

`method` 不应表示：

| 不应作为 method 的内容 | 示例 | 应放置位置 |
|---|---|---|
| 价值资产 | 用户数据、基站服务、管理员权限 | `asset` |
| 损害结果 | 服务不可用、数据泄露、配置被篡改 | `risk` |
| 攻击目标 | 造成基站服务中断 | `goal` |
| 子系统 | 管理面、空口协议栈、软件管理 | `domain` |
| 攻击入口 | REST API、RRC、升级包接口 | `surface` |
| 代码缺陷结论 | 存在越界写漏洞、存在认证绕过漏洞 | 漏洞审计结果，不属于理论威胁分析 |
| 测试动作 | 执行模糊测试、运行扫描器 | 测试方案，不属于攻击行为 |

所有 method 均表示**攻击假设或攻击方式**，不表示对应漏洞已被确认。

---

## 2. 参考框架与转换原则

### 2.1 ATT&CK

ATT&CK Technique/Sub-technique 通常描述攻击者“如何”实现战术目标，可直接或经对象化后转为 method。

转换示例：

| ATT&CK 表述 | 推荐 method 表述 |
|---|---|
| Brute Force | 口令爆破 |
| Exploit Public-Facing Application | 利用对外应用弱点获取初始访问 |
| Network Sniffing | 网络流量嗅探 |
| Adversary-in-the-Middle | 中间人攻击 |
| Data Manipulation | 业务数据篡改 |
| Network Denial of Service | 网络流量泛洪拒绝服务 |

### 2.2 FiGHT

FiGHT 面向 5G 系统，其 Technique 可优先用于以下攻击面：

- 5G RAN、空口、UE、gNB
- 5G Core、SBA、NF、NRF、NEF、UDM、AMF、UPF、CHF
- 漫游与运营商互联接口
- 网络切片、NFV、SDN、O-RAN
- 用户身份、位置、计费、欺诈

FiGHT 方法优先采用“动作 + 电信对象”的方式命名，例如：

- 伪基站广播欺骗
- 5G 降级攻击
- 核心网信令泛洪
- 恶意网络功能注册
- 用户面流量重定向
- 网络切片资源劫持

### 2.3 CWE

CWE 描述软件或硬件弱点，不能把弱点结论直接写成已经存在的漏洞。应转换成理论攻击方式：

| CWE 弱点 | 推荐 method 表述 |
|---|---|
| CWE-787 越界写 | 通过超长或畸形输入触发越界写 |
| CWE-89 SQL 注入 | SQL 注入 |
| CWE-306 关键功能缺少认证 | 绕过身份认证访问关键功能 |
| CWE-502 不可信数据反序列化 | 恶意序列化对象注入 |
| CWE-770 无限制资源分配 | 大量请求触发资源耗尽 |

除非代码证据已经确认具体弱点，否则 method 不应写成“利用已存在的某漏洞”，而应写成“尝试通过某类输入或行为触发某类弱点”。

---

## 3. Method 命名规范

### 3.1 推荐形式

优先使用以下结构：

```text
动作 + 对象
```

或：

```text
利用/通过 + 条件或弱点 + 实施的动作
```

推荐动词：

```text
探测、枚举、扫描、猜测、伪造、冒充、欺骗、重放、篡改、注入、绕过、
劫持、窃取、泄露、监听、嗅探、重定向、降级、削弱、禁用、植入、执行、
上传、加载、替换、删除、覆盖、泛洪、耗尽、阻塞、干扰、破坏、逃逸
```

### 3.2 粒度要求

过粗：

```text
网络攻击
协议攻击
代码漏洞利用
拒绝服务
```

推荐：

```text
管理接口请求泛洪
畸形 RRC 消息注入
协议状态机异常触发
升级包签名校验绕过
SQL 注入
堆内存越界写触发
```

过细且带漏洞确认：

```text
利用 parse_msg.c 第 132 行长度校验缺失实现堆溢出
```

推荐：

```text
通过畸形长度字段触发堆内存越界写
```

---

# 4. 通用攻击行为方法集

## 4.1 侦察、探测与发现

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 网络地址范围扫描 | 网络边界、管理网、业务网 | ATT&CK Reconnaissance |
| 开放端口扫描 | TCP/UDP 服务 | ATT&CK Network Service Discovery |
| 网络服务版本探测 | SSH、HTTP、数据库、协议服务 | ATT&CK Network Service Discovery |
| 对外接口枚举 | API、Web、RPC、CLI | ATT&CK Active Scanning |
| API 路径与方法枚举 | REST、GraphQL、RPC | ATT&CK Active Scanning |
| 协议能力协商探测 | 通信协议、版本协商接口 | ATT&CK/协议威胁归一化 |
| 软件版本与组件指纹识别 | Web、服务 Banner、软件包 | ATT&CK System Information Discovery |
| 操作系统指纹识别 | 网络服务、主机接口 | ATT&CK System Information Discovery |
| 用户名枚举 | 登录、找回密码、认证 API | ATT&CK Account Discovery |
| 账号与角色枚举 | IAM、管理系统、目录服务 | ATT&CK Account Discovery |
| 权限与访问控制策略枚举 | IAM、RBAC、ACL | ATT&CK Permission Groups Discovery |
| 文件与目录枚举 | 文件系统、文件服务、Web 目录 | ATT&CK File and Directory Discovery |
| 配置文件发现 | 主机、容器、应用目录 | ATT&CK File and Directory Discovery |
| 密钥与凭据文件发现 | 文件系统、镜像、备份 | ATT&CK Unsecured Credentials |
| 进程与服务枚举 | 主机、容器、虚拟机 | ATT&CK Process Discovery / Service Discovery |
| 网络连接与会话枚举 | 主机网络栈、管理面 | ATT&CK System Network Connections Discovery |
| 路由与网络拓扑发现 | 路由器、交换机、SDN | ATT&CK Network Configuration Discovery |
| 远程系统发现 | 内部网络、集群 | ATT&CK Remote System Discovery |
| 安全软件与防护能力探测 | 主机、网关、管理系统 | ATT&CK Security Software Discovery |
| 虚拟化与沙箱环境探测 | 虚拟机、容器、分析环境 | ATT&CK Virtualization/Sandbox Evasion |
| 云资源与租户信息枚举 | 云 API、控制台、元数据服务 | ATT&CK Cloud Infrastructure Discovery |
| 容器与编排资源枚举 | Docker、Kubernetes | ATT&CK Container and Resource Discovery |
| 数据库结构与表名枚举 | 数据库、ORM、API | ATT&CK Database Discovery / CWE 派生 |
| 共享资源枚举 | 文件共享、共享 NF、共享存储 | ATT&CK Network Share Discovery / FiGHT FGT5014 |
| 调试接口与诊断端口探测 | JTAG、UART、Debug API | CWE/硬件威胁归一化 |

## 4.2 初始访问、信任关系与供应链

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 利用对外应用弱点获取初始访问 | Web、API、服务端口 | ATT&CK T1190 |
| 利用半公开合作方接口弱点获取访问 | 漫游、互联、合作方 API | FiGHT FGT5029 |
| 使用有效账号访问系统 | 登录接口、远程服务 | ATT&CK T1078 |
| 使用默认账号口令访问系统 | 设备管理、初始配置接口 | ATT&CK/CWE-798 |
| 使用泄露凭据访问系统 | 登录、VPN、API | ATT&CK T1078 |
| 外部远程服务滥用 | VPN、SSH、RDP、远程运维 | ATT&CK T1133 |
| 信任关系滥用 | 合作方、漫游方、上下游系统 | ATT&CK T1199 / FiGHT |
| 第三方组件供应链投毒 | 依赖包、组件库 | ATT&CK T1195 |
| 软件更新供应链投毒 | 升级服务器、软件仓库 | ATT&CK T1195 |
| 构建流水线投毒 | CI/CD、构建节点 | ATT&CK T1195 |
| 制品仓库投毒 | 软件包仓库、镜像仓库 | ATT&CK T1195 |
| 恶意依赖包引入 | 包管理器、依赖解析 | CWE/供应链威胁归一化 |
| 依赖混淆攻击 | 私有包仓库、公共包仓库 | CWE/供应链威胁归一化 |
| 包名仿冒与拼写欺骗 | 包管理器、插件市场 | CWE/供应链威胁归一化 |
| 恶意插件或扩展安装 | 插件接口、扩展市场 | ATT&CK Software Discovery/Execution 派生 |
| 恶意镜像部署 | 容器镜像、虚拟机镜像 | ATT&CK Deploy Container |
| 恶意外设接入 | USB、PCIe、管理终端 | ATT&CK Hardware Additions |
| 可移动介质传播 | USB、离线升级介质 | ATT&CK Replication Through Removable Media |
| 钓鱼链接或附件诱导执行 | 邮件、消息系统、门户 | ATT&CK T1566 |
| 水坑或浏览器驱动攻击 | Web 门户、浏览器 | ATT&CK T1189 |

## 4.3 身份认证、凭据与会话

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 口令猜测 | 登录接口 | ATT&CK T1110 / CWE-307 |
| 口令爆破 | 登录接口 | ATT&CK T1110 / CWE-307 |
| 密码喷洒 | 统一认证、目录服务 | ATT&CK T1110.003 |
| 凭据填充 | Web、API、VPN | ATT&CK T1110.004 |
| 默认凭据登录 | 设备管理、初始配置 | CWE-798 |
| 空口令或弱口令登录 | 登录接口 | CWE-521 |
| 用户名枚举辅助口令攻击 | 登录、密码找回 | CWE-204/信息差异派生 |
| 认证逻辑绕过 | 登录、鉴权中间件 | CWE-287 |
| 关键功能认证缺失利用 | 管理 API、敏感功能 | CWE-306 |
| 多因素认证绕过 | MFA、二次认证 | ATT&CK T1556 / CWE-308 |
| MFA 疲劳与重复确认诱导 | 推送式 MFA | ATT&CK Multi-Factor Authentication Request Generation |
| 账号找回流程滥用 | 密码重置、验证码接口 | CWE-640 |
| 验证码猜测或重放 | 短信、邮件、OTP | CWE-307/294 |
| 会话固定 | Web、管理门户 | CWE-384 |
| 会话令牌窃取 | Cookie、Token、内存 | ATT&CK Steal Web Session Cookie |
| 会话令牌伪造 | Cookie、JWT、自定义 Token | CWE-345/347 |
| 会话令牌重放 | API、Web、协议会话 | CWE-294 |
| 过期会话继续使用 | Web、API、长连接 | CWE-613 |
| JWT 签名校验绕过 | API、微服务 | CWE-347 |
| JWT 算法降级或混淆 | API、微服务 | CWE-327/347 |
| OAuth 访问令牌伪造 | OAuth、SBA、开放 API | FiGHT FGT5011 / CWE-347 |
| OAuth Scope 越权 | OAuth、SBA | FiGHT FGT5043.001 / CWE-863 |
| OAuth 重定向地址滥用 | OAuth 回调接口 | CWE-601/授权流程归一化 |
| API Key 窃取与滥用 | API、配置文件、日志 | ATT&CK Unsecured Credentials |
| 私钥或证书窃取 | 文件系统、密钥管理 | ATT&CK Steal Authentication Certificate |
| 内存凭据抓取 | 进程内存、认证服务 | ATT&CK Credential Dumping / FiGHT FGT5005 |
| 凭据缓存读取 | 浏览器、系统缓存、配置 | ATT&CK Unsecured Credentials |
| 键盘输入捕获 | 终端、管理主机 | ATT&CK Input Capture |
| 登录表单输入捕获 | Web、浏览器、代理 | ATT&CK Input Capture: Web Forms |
| 强制认证与凭据中继 | SMB、HTTP、目录服务 | ATT&CK Forced Authentication |
| Pass-the-Hash | Windows、SMB、远程服务 | ATT&CK Use Alternate Authentication Material |
| Pass-the-Ticket | Kerberos、域环境 | ATT&CK Use Alternate Authentication Material |
| 认证证书替换或注入 | TLS、客户端证书认证 | ATT&CK Modify Authentication Process |
| 认证流程后门植入 | PAM、SSO、认证中间件 | ATT&CK Modify Authentication Process |

## 4.4 授权、权限提升与隔离绕过

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 未授权访问敏感功能 | 管理 API、业务 API | CWE-862 |
| 错误授权逻辑绕过 | RBAC、ABAC、ACL | CWE-863 |
| 用户可控对象标识越权访问 | API、资源 ID | CWE-639 |
| 水平越权访问 | 多用户业务、租户资源 | CWE-639 |
| 垂直越权访问 | 普通用户到管理员 | CWE-269/863 |
| 角色参数篡改提升权限 | Web、API、Token | CWE-266/863 |
| 权限检查时机绕过 | 文件、对象、事务 | CWE-367/862 |
| ACL 或权限配置篡改 | 文件系统、IAM、网络策略 | ATT&CK File and Directory Permissions Modification |
| 组成员关系篡改 | 目录服务、IAM | ATT&CK Account Manipulation |
| 服务账号滥用 | 微服务、云、编排系统 | ATT&CK Valid Accounts |
| 高权限 Token 窃取 | OS、容器、云 IAM | ATT&CK Access Token Manipulation |
| 访问 Token 冒充 | OS、API、微服务 | ATT&CK Access Token Manipulation |
| 令牌 Scope 扩大 | OAuth、SBA | FiGHT FGT5043.001 |
| 操作系统漏洞权限提升 | 内核、驱动、系统服务 | ATT&CK T1068 |
| SUID/SGID 程序滥用 | Linux、Unix | ATT&CK Abuse Elevation Control Mechanism |
| sudo 配置滥用 | Linux、Unix | ATT&CK Abuse Elevation Control Mechanism |
| 容器特权配置滥用 | 容器、Kubernetes | ATT&CK Escape to Host / CWE-250 |
| 容器逃逸到宿主机 | 容器运行时 | ATT&CK Escape to Host |
| 虚拟机逃逸到宿主机 | Hypervisor、虚拟机 | CWE/虚拟化威胁归一化 |
| 跨租户数据访问 | 云、SaaS、共享平台 | CWE-284/639 |
| 网络分段绕过 | VLAN、VRF、防火墙、SDN | ATT&CK Network Boundary Bridging |
| 网络切片隔离绕过 | 共享 NF、共享基础设施 | FiGHT FGT1599.501/FGT1599.502 |
| 混淆代理权限滥用 | 服务代理、微服务调用链 | CWE-441 |
| 不安全委托关系滥用 | IAM、目录服务、服务间调用 | ATT&CK Additional Cloud Roles / Delegation 派生 |

## 4.5 注入、代码执行与解释器滥用

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| SQL 注入 | 数据库查询接口 | CWE-89 |
| NoSQL 注入 | MongoDB、键值数据库、查询 API | CWE-943 |
| OS 命令注入 | 系统命令调用接口 | CWE-78 |
| 通用命令注入 | 命令解释器、工具封装 | CWE-77 |
| 代码注入 | 动态代码生成、脚本执行 | CWE-94 |
| 脚本注入 | JavaScript、Shell、Python 等 | CWE-94/95 |
| 表达式语言注入 | EL、OGNL、SpEL | CWE-917 |
| 服务端模板注入 | 模板引擎 | CWE-1336 |
| LDAP 注入 | 目录查询接口 | CWE-90 |
| XPath 注入 | XML 查询接口 | CWE-643 |
| XQuery 注入 | XML 数据库 | CWE-652 |
| XML 实体注入 | XML 解析器 | CWE-611 |
| XSLT 注入 | XML/XSLT 转换接口 | CWE-91 |
| HTTP Header 注入 | Web、反向代理 | CWE-113 |
| HTTP 响应拆分 | Web、代理 | CWE-113 |
| CRLF 注入 | HTTP、日志、邮件 | CWE-93 |
| Host Header 注入 | Web、反向代理、链接生成 | CWE-644/346 派生 |
| 邮件头注入 | 邮件发送接口 | CWE-93 |
| 日志注入 | 日志接口、审计系统 | CWE-117 |
| CSV/公式注入 | 报表导出、电子表格 | CWE-1236 |
| 格式化字符串注入 | C/C++ 日志、输出接口 | CWE-134 |
| 参数注入 | 命令行参数、工具封装 | CWE-88 |
| 服务器端包含注入 | SSI、模板服务 | CWE-97 |
| 本地文件包含 | Web、模板、脚本加载 | CWE-98 |
| 远程文件包含 | Web、模板、脚本加载 | CWE-98 |
| 恶意文件上传 | 上传接口、插件接口 | CWE-434 |
| WebShell 上传与执行 | Web 文件上传 | CWE-434 / ATT&CK Server Software Component |
| 动态库或模块注入 | 进程、插件、共享库 | ATT&CK Hijack Execution Flow |
| 进程注入 | 主机进程 | ATT&CK Process Injection |
| DLL 搜索顺序劫持 | Windows、应用目录 | ATT&CK Hijack Execution Flow |
| 共享库加载劫持 | Linux、Unix、应用目录 | ATT&CK Hijack Execution Flow |
| 反序列化对象注入 | RPC、消息队列、缓存、Web | CWE-502 |
| 原生 API 滥用执行 | 操作系统 API | ATT&CK Native API |
| 命令与脚本解释器执行 | Shell、PowerShell、Python 等 | ATT&CK Command and Scripting Interpreter |
| Telecom 协议载荷注入 | 电信防火墙、信令网关、协议栈 | FiGHT FGT5045 |

## 4.6 持久化与执行路径劫持

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 新建后门账号 | 操作系统、应用、IAM | ATT&CK Create Account |
| 修改现有账号认证信息 | 账号系统、目录服务 | ATT&CK Account Manipulation |
| 写入 SSH 授权密钥 | SSH、用户目录 | ATT&CK Account Manipulation |
| 注册恶意系统服务 | Windows/Linux 服务 | ATT&CK System Services |
| 创建计划任务 | Windows、Linux、应用调度 | ATT&CK Scheduled Task/Job |
| 修改启动项 | 操作系统、应用启动配置 | ATT&CK Boot or Logon Autostart Execution |
| 修改 Shell 初始化文件 | Linux、Unix | ATT&CK Unix Shell Configuration Modification |
| Web 服务器组件植入 | WebShell、Filter、Module | ATT&CK Server Software Component |
| 数据库启动过程植入 | 数据库扩展、存储过程 | ATT&CK Event Triggered Execution 派生 |
| 插件或扩展植入 | 插件框架、IDE、浏览器 | ATT&CK Software Extensions |
| 驱动程序植入 | 内核、驱动接口 | ATT&CK Modify Existing Service / Rootkit |
| 内核模块植入 | Linux 内核 | ATT&CK Kernel Modules and Extensions |
| Rootkit 植入 | 操作系统、固件 | ATT&CK T1014 |
| Bootkit 或引导链植入 | Bootloader、UEFI | ATT&CK Pre-OS Boot |
| 固件后门植入 | BIOS、BMC、设备固件 | ATT&CK System Firmware |
| 恶意容器部署 | 容器编排接口 | ATT&CK Deploy Container |
| 恶意虚拟机或镜像部署 | 云、虚拟化平台 | ATT&CK Cloud Infrastructure Modification |
| 恶意网络功能注册 | NRF、5G Core | FiGHT FGT5007 |
| 恶意 VNF 实例化 | NFV、MANO、虚拟化平台 | FiGHT FGT5013 |
| 热补丁或冷补丁植入 | 补丁管理、升级接口 | 供应链/CWE 派生 |
| 软件升级机制持久化利用 | 更新程序、升级代理 | ATT&CK Software Discovery/Modify System Image 派生 |

## 4.7 网络、协议与通信链路

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 网络流量嗅探 | 以太网、无线、镜像口 | ATT&CK T1040 |
| 中间人攻击 | 网络链路、代理、网关 | ATT&CK T1557 |
| ARP 欺骗 | 二层网络 | ATT&CK T1557.002 |
| DHCP 欺骗 | 局域网 | ATT&CK T1557 派生 |
| DNS 缓存投毒 | DNS 服务 | ATT&CK T1584/T1557 派生 |
| DNS 劫持 | DNS、域名配置 | ATT&CK Domain Trust/Traffic Signaling 派生 |
| 路由协议欺骗 | BGP、OSPF、内部路由 | 网络威胁归一化 |
| 路由重定向 | 路由器、SDN、网关 | ATT&CK Network Device CLI/FiGHT 派生 |
| IP 地址伪造 | IP 网络、UDP 服务 | 网络威胁归一化 |
| TCP 序列号预测或注入 | TCP 服务 | CWE-294/网络威胁归一化 |
| TCP Reset 注入 | TCP 长连接、信令链路 | 网络威胁归一化 |
| 协议消息重放 | 任意有状态协议 | CWE-294 |
| 协议消息伪造 | 任意协议接口 | CWE-345 |
| 协议消息篡改 | 任意协议接口 | ATT&CK Data Manipulation |
| 协议字段混淆 | 编解码器、协议解析器 | CWE-436 |
| 协议版本降级 | TLS、通信协议、无线协议 | CWE-757 |
| 加密降级攻击 | TLS、IPsec、无线加密 | ATT&CK Weaken Encryption / FiGHT FGT1600.502 |
| 协议隧道 | 网络边界、C2、代理 | ATT&CK T1572 |
| HTTP/DNS/邮件协议隐蔽通信 | 应用层协议 | ATT&CK T1071 |
| 代理转发隐藏来源 | 网络代理、跳板 | ATT&CK Proxy |
| 端口转发建立访问通道 | SSH、VPN、代理 | ATT&CK Proxy/Protocol Tunneling |
| 网络边界桥接 | 双网卡设备、边界设备 | ATT&CK/FiGHT FGT1599 |
| 防火墙规则绕过或篡改 | 防火墙、ACL、云安全组 | ATT&CK Impair Defenses |
| NAT/端口映射滥用 | NAT、UPnP、网关 | 网络威胁归一化 |
| 分片重组差异绕过 | IP、TCP、应用协议 | CWE-436/协议威胁归一化 |
| 重叠分片注入 | IP、协议网关 | 协议威胁归一化 |
| 请求走私 | HTTP、代理、负载均衡 | CWE-444 |
| HTTP 请求不同步 | HTTP/1、代理链 | CWE-444 |
| WebSocket 跨域连接滥用 | WebSocket | CWE-346/352 派生 |
| 反射放大攻击 | UDP 服务、DNS、NTP 等 | ATT&CK Network DoS / FiGHT FGT1498.002 |
| 用户面流量重定向 | UPF、路由策略 | FiGHT FGT5008 |
| 运营商互联接口滥用 | N32、IPX、N26 等 | FiGHT FGT5016 |

## 4.8 数据收集、窃取与外传

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 文件系统敏感数据收集 | 主机、文件服务 | ATT&CK Data from Local System |
| 网络共享数据收集 | SMB、NFS、共享存储 | ATT&CK Data from Network Shared Drive |
| 数据库数据批量导出 | 数据库、管理接口 | ATT&CK Data from Information Repositories |
| 配置数据窃取 | 配置文件、配置中心 | ATT&CK Data from Local System |
| 审计日志窃取 | 日志系统、SIEM、文件 | ATT&CK Data from Information Repositories |
| 备份数据窃取 | 备份系统、快照、对象存储 | ATT&CK Data from Information Repositories |
| 云对象存储数据窃取 | 云存储、Bucket | ATT&CK Data from Cloud Storage |
| 邮件数据收集 | 邮箱、邮件服务器 | ATT&CK Email Collection |
| 浏览器数据收集 | Cookie、历史、密码 | ATT&CK Credentials from Web Browsers |
| 剪贴板数据收集 | 终端、远程桌面 | ATT&CK Clipboard Data |
| 屏幕截图收集 | 终端、管理主机 | ATT&CK Screen Capture |
| 音频或视频采集 | 终端、摄像头、麦克风 | ATT&CK Audio Capture / Video Capture |
| 输入内容捕获 | 键盘、Web 表单 | ATT&CK Input Capture |
| 进程内存敏感数据抓取 | 认证、业务进程 | FiGHT FGT5005 / ATT&CK Credential Dumping |
| 调试信息与错误信息收集 | Debug API、错误页、日志 | CWE-209/215 |
| 核心转储文件读取 | 文件系统、诊断接口 | CWE-528 |
| 计费记录收集 | CHF、CDR 存储 | FiGHT FGT5017 |
| 用户永久标识获取 | SUPI、IMSI、用户数据库 | FiGHT FGT5019 |
| 用户位置跟踪 | RAN、核心网、漫游接口 | FiGHT FGT5012 |
| 数据压缩后外传 | 文件、归档工具 | ATT&CK Archive Collected Data |
| 数据加密后外传 | 文件、C2 通道 | ATT&CK Archive Collected Data |
| 数据分块外传 | 网络、API、C2 | ATT&CK Data Transfer Size Limits |
| 通过 Web 协议外传 | HTTP/HTTPS | ATT&CK Exfiltration Over Web Service |
| 通过 DNS 隧道外传 | DNS | ATT&CK Exfiltration Over Alternative Protocol |
| 通过云存储外传 | 对象存储、网盘 | ATT&CK Exfiltration to Cloud Storage |
| 通过可移动介质外传 | USB、移动存储 | ATT&CK Exfiltration Over Physical Medium |
| 隐写外传 | 图片、音视频、文档 | ATT&CK Steganography |

## 4.9 防护绕过、隐藏与审计破坏

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 禁用安全软件 | 主机、终端、防护代理 | ATT&CK Impair Defenses |
| 修改安全策略 | 防火墙、EDR、IAM | ATT&CK Impair Defenses |
| 禁用或修改审计日志 | 操作系统、云、应用 | ATT&CK Impair Defenses |
| 清除系统日志 | Windows、Linux、设备 | ATT&CK Indicator Removal |
| 删除攻击文件与痕迹 | 文件系统、临时目录 | ATT&CK Indicator Removal |
| 修改时间戳 | 文件、日志、数据库 | ATT&CK Timestomp |
| 日志伪造 | 日志接口、审计系统 | CWE-117 / ATT&CK 派生 |
| 安全工具界面欺骗 | 管理界面、监控平台 | ATT&CK Modify or Spoof Tool UI |
| 恶意文件或信息混淆 | 文件、脚本、配置 | ATT&CK Obfuscated Files or Information |
| 编码或加密恶意载荷 | 网络、文件、脚本 | ATT&CK Obfuscated Files or Information |
| 协议或服务冒充 | 网络流量、C2 | ATT&CK Protocol or Service Impersonation |
| 文件与目录隐藏 | 文件系统 | ATT&CK Hide Artifacts |
| 进程名称或路径伪装 | 操作系统、容器 | ATT&CK Masquerading |
| 合法签名或证书滥用 | 软件包、脚本、驱动 | ATT&CK Subvert Trust Controls |
| 系统二进制代理执行 | 操作系统工具 | ATT&CK System Binary Proxy Execution |
| 调试器检测与规避 | 应用、恶意载荷 | ATT&CK Debugger Evasion |
| 沙箱或虚拟化环境规避 | 分析环境、终端 | ATT&CK Virtualization/Sandbox Evasion |
| 延迟执行规避检测 | 应用、脚本、任务 | ATT&CK Delay Execution |
| Rootkit 隐藏进程与文件 | 操作系统、内核 | ATT&CK T1014 |
| 关闭完整性校验 | 软件加载、协议、存储 | FiGHT FGT5009 / CWE-353 |
| 关闭或削弱加密 | 网络接口、存储 | ATT&CK T1600 / FiGHT FGT1600.502 |
| 5G 降级以绕过安全能力 | UE、RAN、核心网 | FiGHT FGT1562.501 |

## 4.10 可用性破坏与资源耗尽

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 网络流量泛洪 | 网络接口、网关、服务端口 | ATT&CK Network Denial of Service |
| 应用请求泛洪 | Web、API、RPC | ATT&CK Endpoint Denial of Service |
| 登录接口请求泛洪 | 认证服务 | ATT&CK Endpoint DoS / CWE-770 |
| 协议信令泛洪 | 信令接口、协议栈 | FiGHT FGT1498.501 |
| 连接数耗尽 | TCP、数据库、代理 | CWE-400/770 |
| 线程或工作进程耗尽 | Web、RPC、任务系统 | CWE-400/770 |
| CPU 资源耗尽 | 算法、解析器、加密接口 | CWE-400/407 |
| 内存资源耗尽 | 解析器、缓存、队列 | CWE-400/770 |
| 磁盘空间耗尽 | 日志、上传、缓存、临时文件 | CWE-400/770 |
| 文件描述符耗尽 | 网络服务、文件服务 | CWE-400/770 |
| 数据库连接池耗尽 | 数据库访问接口 | CWE-400/770 |
| 消息队列堆积耗尽 | MQ、事件总线 | CWE-400/770 |
| 缓存污染与容量耗尽 | 缓存、CDN、内存存储 | CWE-400/770 |
| 无限制文件上传耗尽存储 | 上传接口 | CWE-770/434 |
| 大对象或超长消息耗尽资源 | 协议解析器、API | CWE-400/770 |
| 深度嵌套结构耗尽栈或 CPU | JSON、XML、ASN.1、递归解析 | CWE-674/776 |
| 压缩炸弹 | 压缩包、压缩协议 | CWE-409 |
| XML 实体扩展炸弹 | XML 解析器 | CWE-776 |
| 正则表达式拒绝服务 | 正则匹配接口 | CWE-1333 |
| 哈希碰撞拒绝服务 | 哈希表、参数解析 | CWE-407 |
| 算法复杂度攻击 | 排序、解析、匹配接口 | CWE-407 |
| 死循环或无限递归触发 | 状态机、解析器 | CWE-674/835 |
| 死锁或活锁触发 | 并发接口、共享资源 | CWE-833 |
| 崩溃型畸形输入 | 编解码器、协议栈 | CWE-20/476 |
| 重启循环触发 | 服务管理、升级、看门狗 | 可用性威胁归一化 |
| 依赖服务故障放大 | 微服务、级联调用 | 可用性威胁归一化 |
| 账号锁定滥用 | 登录、风控接口 | CWE-307/DoS 派生 |
| 反射放大泛洪 | UDP、DNS、NTP 等 | FiGHT FGT1498.002 |
| 共享切片公共资源耗尽 | 共享 NF、共享控制资源 | FiGHT FGT1498.502 |
| 核心网信令洪泛 | AMF、SMF、UDM、NRF 等 | FiGHT FGT1498.501 |
| 伪造广播消息阻断 UE 接入 | RAN、广播信道 | FiGHT FGT1642.501 |
| 通过 gNB 或 NF 信令拒绝 UE 服务 | gNB、AMF、NSSF 等 | FiGHT FGT1499.503 |
| 触发欺诈告警阻断用户服务 | 风控、注册、计费 | FiGHT FGT1499.502 |
| 无线射频干扰 | RAN、空口 | FiGHT/无线威胁归一化 |
| 注册风暴 | UE 注册、AMF、UDM | FiGHT/5G DoS 归一化 |
| 会话建立风暴 | PDU Session、SMF、UPF | FiGHT/5G DoS 归一化 |
| 寻呼风暴 | Paging、RAN、AMF | FiGHT/5G DoS 归一化 |

## 4.11 数据、配置与业务完整性破坏

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 存储数据篡改 | 数据库、文件、对象存储 | ATT&CK Stored Data Manipulation |
| 传输数据篡改 | 网络、代理、网关 | ATT&CK/FiGHT FGT1565.002 |
| 业务交易数据篡改 | 业务 API、数据库 | ATT&CK Data Manipulation |
| 配置数据篡改 | 配置中心、文件、管理 API | ATT&CK Data Manipulation |
| 用户权限数据篡改 | IAM、数据库、目录服务 | ATT&CK Account Manipulation |
| 审计日志篡改 | 日志系统、文件、数据库 | ATT&CK Indicator Removal |
| 软件包内容篡改 | 软件仓库、升级包 | ATT&CK Supply Chain Compromise |
| 固件内容篡改 | 固件包、烧写接口 | ATT&CK Firmware Corruption |
| 数据库记录批量删除 | 数据库、管理 API | ATT&CK Data Destruction |
| 文件或存储卷擦除 | 文件系统、磁盘 | ATT&CK Disk Wipe/File Deletion |
| 网站或界面内容篡改 | Web、门户、显示系统 | ATT&CK Defacement |
| DNS 记录篡改 | DNS、域名管理 | ATT&CK Domain Trust Discovery/Modify Cloud Compute 派生 |
| 路由或流表规则篡改 | 路由器、SDN 控制器 | FiGHT/SDN 威胁归一化 |
| 服务注册信息投毒 | 注册中心、NRF、服务发现 | FiGHT FGT5007/FGT5003 派生 |
| VNF 配置篡改 | NFV、MANO、VNF | FiGHT FGT5039 |
| 设备数据库篡改 | 设备数据库、UDM、资产数据库 | FiGHT FGT5015 |
| ML 模型篡改 | O-RAN、AI/ML 服务 | FiGHT FGT5037 |
| 用户面转发规则篡改 | UPF、SDN、路由策略 | FiGHT FGT5008 |
| 计费记录篡改 | CHF、CDR、账务系统 | FiGHT Fraud 派生 |
| 互联结算账单伪造 | 漫游、互联计费 | FiGHT FGT5025 |
| 欺诈性 AMF 注册 | AMF、UDM | FiGHT FGT5010 |
| 隧道标识冲突或篡改 | GTP、TEID、用户面隧道 | FiGHT FGT5021 |
| 系统时间或时间源篡改 | NTP、系统时钟、证书校验 | ATT&CK System Time Discovery/Modify System Time 派生 |

## 4.12 云、容器、虚拟化与编排平台

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| 云元数据服务访问 | 云主机、SSRF、容器 | ATT&CK Cloud Instance Metadata API |
| 云 IAM 凭据窃取 | 云 CLI、环境变量、配置 | ATT&CK Unsecured Credentials |
| 云角色权限滥用 | IAM、临时凭据 | ATT&CK Additional Cloud Roles |
| 公共对象存储暴露利用 | Bucket、对象存储 | CWE-284/云威胁归一化 |
| 云快照窃取 | 云磁盘、数据库快照 | ATT&CK Cloud Storage Object Discovery 派生 |
| 云日志禁用或篡改 | 云审计、日志服务 | ATT&CK Impair Defenses |
| 云安全组或网络策略篡改 | 云网络、VPC | ATT&CK Impair Defenses |
| 云函数代码或配置篡改 | Serverless、函数平台 | ATT&CK Cloud Administration Command |
| 容器镜像投毒 | 镜像仓库、构建流水线 | ATT&CK Supply Chain Compromise |
| 恶意容器部署 | Kubernetes、Docker | ATT&CK Deploy Container |
| 特权容器滥用 | 容器编排 | ATT&CK Escape to Host |
| HostPath 或宿主目录挂载滥用 | Kubernetes、容器 | ATT&CK Escape to Host |
| 容器运行时接口滥用 | Docker Socket、CRI | ATT&CK Container Administration Command |
| Kubernetes API 未授权访问 | Kubernetes API | CWE-306/862 |
| Kubernetes ServiceAccount Token 窃取 | Pod、Secret、Token | ATT&CK Unsecured Credentials |
| Kubernetes Secret 窃取 | API、etcd、Pod | ATT&CK Unsecured Credentials |
| Admission Controller 绕过 | Kubernetes 准入控制 | CWE-693/编排威胁归一化 |
| Pod 安全策略绕过 | Kubernetes 安全策略 | CWE-693/编排威胁归一化 |
| 容器逃逸 | 容器运行时、内核 | ATT&CK Escape to Host |
| 虚拟机逃逸 | Hypervisor、虚拟设备 | CWE/虚拟化威胁归一化 |
| 虚拟交换机流量劫持 | vSwitch、SDN | FiGHT Remote System Discovery:vSwitch/虚拟化威胁 |
| 虚拟网络功能配置操纵 | VNF、MANO | FiGHT FGT5039 |
| 恶意 VNF 实例化 | NFV、MANO | FiGHT FGT5013 |

## 4.13 硬件、固件与物理接口

| Method 候选名称 | 典型适用攻击面 | 主要参考 |
|---|---|---|
| JTAG 调试接口未授权访问 | 芯片、设备主板 | CWE Hardware |
| UART/串口控制台未授权访问 | 设备、嵌入式系统 | CWE Hardware |
| Bootloader 解锁或绕过 | 嵌入式设备、终端 | CWE Hardware |
| 安全启动校验绕过 | Boot ROM、UEFI、Bootloader | CWE-1326/硬件弱点归一化 |
| 固件签名校验绕过 | 固件升级接口 | CWE-347/494 |
| 固件回滚攻击 | 固件升级、版本控制 | CWE-1328/版本回退归一化 |
| 固件提取与逆向 | Flash、升级包、调试接口 | ATT&CK Firmware Analysis 派生 |
| 固件篡改与重刷 | Flash、升级接口 | ATT&CK Firmware Corruption |
| 电压毛刺故障注入 | 芯片、电源接口 | CWE Hardware |
| 时钟毛刺故障注入 | 芯片、时钟接口 | CWE Hardware |
| 激光或电磁故障注入 | 芯片、物理封装 | CWE Hardware |
| 功耗侧信道分析 | 加密芯片、终端 | CWE-1300 类硬件弱点 |
| 电磁侧信道分析 | 加密芯片、终端 | CWE Hardware |
| 缓存时间侧信道 | CPU、共享计算平台 | CWE-208/385 派生 |
| Rowhammer 内存扰动 | DRAM、共享主机 | CWE Hardware |
| DMA 未授权内存访问 | PCIe、Thunderbolt、外设 | CWE Hardware |
| 冷启动内存提取 | 物理内存、终端 | 硬件威胁归一化 |
| 总线嗅探 | SPI、I2C、PCIe、内部总线 | CWE Hardware |
| 传感器信号欺骗 | GNSS、射频、工业传感器 | ATT&CK ICS/硬件威胁 |
| 恶意外设植入 | USB、PCIe、网络模块 | ATT&CK Hardware Additions |
| 设备克隆或身份复制 | 安全芯片、设备证书 | CWE Hardware |
| 物理拆解与防拆绕过 | 机箱、芯片封装 | CWE Hardware |
| 网络基础设施物理破坏 | 基站、天线、传输设备 | FiGHT FGT5018.002 等 |

---

# 5. CWE 派生的代码弱点攻击方法集

本章用于源代码分析场景。除非代码已经确认缺陷，否则这些名称均表示“可能尝试触发”的攻击方式。

## 5.1 输入处理、注入与解析

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 通过未校验输入触发异常行为 | CWE-20 | 外部输入进入敏感处理逻辑 |
| SQL 注入 | CWE-89 | 用户输入参与 SQL 构造 |
| OS 命令注入 | CWE-78 | 用户输入进入系统命令 |
| 通用命令注入 | CWE-77 | 输入进入命令解释器 |
| 代码注入 | CWE-94 | 输入参与代码生成或执行 |
| 动态表达式注入 | CWE-917 | 输入进入表达式引擎 |
| 服务端模板注入 | CWE-1336 | 输入参与服务端模板渲染 |
| LDAP 注入 | CWE-90 | 输入参与 LDAP 查询 |
| XPath 注入 | CWE-643 | 输入参与 XPath 查询 |
| XML 外部实体注入 | CWE-611 | 解析不可信 XML |
| XML 实体扩展耗尽 | CWE-776 | XML 允许递归实体扩展 |
| XSS 脚本注入 | CWE-79 | 输入进入浏览器页面输出 |
| HTTP Header 注入 | CWE-113 | 输入进入 HTTP Header |
| CRLF 注入 | CWE-93 | 输入进入按行解析的协议或日志 |
| 日志注入 | CWE-117 | 外部输入直接写入日志 |
| CSV 公式注入 | CWE-1236 | 外部输入导出到表格 |
| 格式化字符串攻击 | CWE-134 | 外部输入作为格式字符串 |
| 参数注入 | CWE-88 | 输入进入命令行参数 |
| 路径穿越 | CWE-22 | 输入参与路径拼接 |
| 相对路径遍历 | CWE-23 | 输入可包含相对路径段 |
| 绝对路径遍历 | CWE-36 | 输入可指定绝对路径 |
| 文件名编码与规范化绕过 | CWE-180/181 | 校验与使用采用不同规范化结果 |
| 不可信数据反序列化 | CWE-502 | 解析外部序列化对象 |
| HTTP 请求走私 | CWE-444 | 前后端对消息边界解析不一致 |
| 协议解释差异攻击 | CWE-436 | 多组件对同一消息解释不同 |
| Unicode 编码混淆绕过 | CWE-176 | 校验前后编码处理不一致 |
| 大小写与等价字符绕过 | CWE-178 | 标识符比较规则不一致 |
| 空字节截断绕过 | CWE-158 | 底层接口使用空字符终止字符串 |
| 恶意正则输入触发 ReDoS | CWE-1333 | 使用高复杂度正则处理外部输入 |

## 5.2 内存安全、数值与类型

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 通过超长输入触发经典缓冲区溢出 | CWE-120 | 固定长度缓冲区复制外部数据 |
| 通过超长输入触发栈缓冲区溢出 | CWE-121 | 栈缓冲区长度控制不足 |
| 通过超长输入触发堆缓冲区溢出 | CWE-122 | 堆缓冲区长度控制不足 |
| 通过畸形索引触发越界写 | CWE-787 | 外部数据控制索引或长度 |
| 通过畸形索引触发越界读 | CWE-125 | 外部数据控制索引或长度 |
| 通过负长度触发缓冲区下溢 | CWE-124 | 长度或偏移可为负数 |
| 通过长度计算错误触发越界访问 | CWE-131 | 分配大小与使用大小不一致 |
| 通过整数溢出影响内存分配 | CWE-190 | 长度计算可能溢出 |
| 通过整数下溢影响边界判断 | CWE-191 | 无符号或有符号减法可能下溢 |
| 通过整数截断绕过长度检查 | CWE-197 | 大整数被转换为较小类型 |
| 通过有符号/无符号转换绕过检查 | CWE-195/196 | 类型转换影响数值范围 |
| 通过错误数值转换触发异常 | CWE-681 | 跨类型转换缺少范围校验 |
| Use-After-Free 触发 | CWE-416 | 对象释放后仍可访问 |
| Double-Free 触发 | CWE-415 | 同一内存可能被重复释放 |
| 非法释放触发 | CWE-590/761 | 释放非堆地址或偏移地址 |
| 空指针解引用触发崩溃 | CWE-476 | 外部输入可使对象为空 |
| 未初始化内存读取 | CWE-457 | 未初始化数据进入输出或控制流 |
| 未初始化指针使用 | CWE-824 | 指针使用前未赋值 |
| 类型混淆触发 | CWE-843 | 对象实际类型与预期类型不一致 |
| 错误对象生命周期触发 | CWE-664 | 创建、使用、释放时序不正确 |
| 内存泄漏耗尽 | CWE-401 | 重复操作导致内存无法释放 |
| 栈耗尽 | CWE-674 | 外部输入控制递归深度 |
| 无限制循环触发 | CWE-835 | 外部输入影响循环终止条件 |
| 竞争条件触发 | CWE-362 | 多线程共享资源缺少同步 |
| TOCTOU 条件竞争 | CWE-367 | 检查与使用之间状态可变化 |
| 信号处理竞争触发 | CWE-364 | 信号处理与主流程共享状态 |

## 5.3 认证、授权与会话弱点

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 绕过身份认证 | CWE-287 | 存在认证判断或认证状态 |
| 利用关键功能缺少认证 | CWE-306 | 关键接口可直接访问 |
| 利用不充分认证 | CWE-308 | 关键操作仅使用弱认证因素 |
| 利用凭据硬编码 | CWE-798 | 二进制、脚本或配置中包含固定凭据 |
| 利用弱密码策略 | CWE-521 | 系统允许低强度密码 |
| 口令爆破绕过尝试限制 | CWE-307 | 登录失败次数未限制 |
| 利用密码恢复弱点接管账号 | CWE-640 | 找回流程身份校验不足 |
| 绕过授权检查 | CWE-862 | 敏感操作缺少授权检查 |
| 利用错误授权逻辑越权 | CWE-863 | 已执行授权但规则不正确 |
| 利用用户可控对象键越权 | CWE-639 | 用户可控制资源标识 |
| 利用不正确访问控制 | CWE-284 | 资源保护策略不完整 |
| 利用不必要高权限执行 | CWE-250 | 服务以高权限运行 |
| 利用权限未及时撤销 | CWE-274 | 权限在任务结束后仍保留 |
| 利用不安全默认权限 | CWE-276 | 新对象默认可被非预期主体访问 |
| 会话固定 | CWE-384 | 登录前后会话标识不更新 |
| 会话过期失效绕过 | CWE-613 | 退出或过期后令牌仍有效 |
| 认证重放 | CWE-294 | 认证消息缺少随机数或时效性 |
| 证书或签名校验绕过 | CWE-295/347 | 信任链或签名验证不完整 |
| 来源验证绕过 | CWE-346 | 请求来源未可信验证 |
| CSRF 跨站请求伪造 | CWE-352 | 浏览器自动携带认证信息 |

## 5.4 文件、目录、资源与配置

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 路径穿越读取任意文件 | CWE-22 | 外部输入参与读取路径 |
| 路径穿越写入任意文件 | CWE-22 | 外部输入参与写入路径 |
| 路径穿越删除任意文件 | CWE-22 | 外部输入参与删除路径 |
| 符号链接跟随攻击 | CWE-59 | 高权限程序跟随不可信链接 |
| 硬链接滥用覆盖文件 | CWE-62 | 高权限程序处理可控硬链接 |
| 临时文件竞争与替换 | CWE-377/378 | 临时文件路径可预测或权限不当 |
| 不安全文件权限利用 | CWE-732 | 文件权限允许非预期访问 |
| 不安全目录权限利用 | CWE-276 | 目录允许非预期写入或读取 |
| 任意文件上传 | CWE-434 | 上传文件类型或内容未限制 |
| 上传文件覆盖现有文件 | CWE-434/73 | 文件名或目标路径可控 |
| 压缩包路径穿越（Zip Slip） | CWE-22 | 解压时未限制目标路径 |
| 压缩炸弹耗尽 | CWE-409 | 系统自动解压外部压缩数据 |
| 备份文件泄露 | CWE-530 | Web 或文件系统暴露备份 |
| 核心转储泄露 | CWE-528 | Core Dump 可被非授权读取 |
| 配置文件泄露 | CWE-552 | 配置目录可被外部访问 |
| 版本控制目录泄露 | CWE-527 | `.git` 等目录对外暴露 |
| 目录列表泄露 | CWE-548 | Web 服务器允许列目录 |
| 资源无限分配耗尽 | CWE-770 | 外部请求可重复申请资源 |
| 资源未释放耗尽 | CWE-772 | 异常路径未释放资源 |
| 文件描述符耗尽 | CWE-775 | 文件或连接未正确关闭 |
| 配额与限流绕过 | CWE-770 | 限流键或配额维度可被绕过 |
| 不安全默认配置利用 | CWE-1188 | 安装后默认暴露高风险能力 |
| 外部可控配置文件加载 | CWE-15 | 外部输入决定关键配置 |

## 5.5 加密、随机数、密钥与信任

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 明文传输敏感数据 | CWE-319 | 敏感数据通过未加密链路传输 |
| 使用弱加密算法实施解密 | CWE-327 | 使用已知弱算法或参数 |
| 加密算法降级 | CWE-757 | 协商允许不安全算法或版本 |
| 硬编码密钥提取 | CWE-321 | 密钥嵌入代码、固件或镜像 |
| 密钥明文存储读取 | CWE-312 | 密钥或敏感数据未加密存储 |
| 私钥保护不足利用 | CWE-320 | 私钥可被非预期读取 |
| 可预测随机数猜测 | CWE-338 | 安全场景使用弱随机数 |
| 可预测令牌猜测 | CWE-330/340 | Token、Nonce、Session ID 可预测 |
| 随机数种子预测 | CWE-337 | PRNG 种子熵不足 |
| Nonce 重用攻击 | CWE-323 | 加密或认证中重复使用 Nonce |
| IV 重用攻击 | CWE-329 | CBC 等模式中 IV 不唯一或可预测 |
| 签名验证绕过 | CWE-347 | 签名未验证或验证逻辑错误 |
| 证书主机名校验绕过 | CWE-297 | TLS 证书名称未正确匹配 |
| 证书链校验绕过 | CWE-295 | 证书信任链未正确验证 |
| 不可信证书接受 | CWE-295 | 系统接受自签或错误证书 |
| 哈希校验绕过 | CWE-328/353 | 使用弱哈希或完整性校验缺失 |
| 下载内容完整性校验绕过 | CWE-494 | 下载代码未验证来源和完整性 |
| 更新包签名校验绕过 | CWE-347/494 | 更新包验证不完整 |
| Padding Oracle 攻击 | CWE-209/327 派生 | 错误响应泄露填充有效性 |
| 时间侧信道推断密钥或凭据 | CWE-208 | 比较或加密耗时与秘密相关 |
| 错误信息侧信道推断 | CWE-209 | 不同错误暴露内部状态 |

## 5.6 状态机、并发与业务流程

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 越过必要流程步骤 | CWE-841 | 业务状态转换未严格限制 |
| 乱序消息触发状态机异常 | CWE-691/841 | 协议或业务流程有固定顺序 |
| 重复提交触发重复执行 | CWE-841 | 操作缺少幂等控制 |
| 事务重放 | CWE-294/841 | 事务缺少唯一性或时效校验 |
| 并发请求绕过额度或库存检查 | CWE-362/367 | 检查和扣减非原子操作 |
| 并发注册或绑定冲突 | CWE-362 | 同一对象可被并发创建或绑定 |
| 状态回滚攻击 | CWE-841 | 旧状态或旧版本可被重新接受 |
| 版本回退攻击 | CWE-757 | 系统允许退回弱安全版本 |
| 事务标识碰撞 | CWE-330/340 | 事务 ID 可预测或重复 |
| 会话标识冲突 | CWE-330/340 | Session ID 唯一性不足 |
| 消息序列号篡改 | CWE-345/294 | 顺序和重放保护依赖序列号 |
| 超时机制绕过 | CWE-613/400 | 长连接或任务缺少合理超时 |
| 异常恢复流程滥用 | CWE-703 | 错误处理进入不安全状态 |
| 失败开放机制利用 | CWE-636 | 安全检查失败时默认允许 |

## 5.7 信息泄露、错误处理与可观测性

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 错误消息泄露内部信息 | CWE-209 | 错误响应包含堆栈、路径、SQL 等 |
| 调试信息泄露 | CWE-215 | 生产环境保留调试输出 |
| 日志泄露凭据或密钥 | CWE-532 | 日志记录敏感信息 |
| 响应中泄露敏感数据 | CWE-200 | 返回数据超出调用者权限 |
| 目录或文件权限导致信息泄露 | CWE-552 | 文件位于外部可访问区域 |
| 内存未清理导致敏感数据残留 | CWE-226 | 释放或复用前未清除敏感数据 |
| 缓存泄露敏感信息 | CWE-524/525 | 敏感响应或数据被缓存 |
| 浏览器历史或缓存泄露 | CWE-525 | 页面允许缓存敏感内容 |
| Referer 或 URL 参数泄露敏感数据 | CWE-598 | 敏感信息出现在 URL |
| 环境变量泄露密钥 | CWE-526 | 环境变量可被非预期读取 |
| 进程列表泄露命令行密钥 | CWE-214 | 密钥出现在命令行参数 |
| 核心转储泄露敏感数据 | CWE-528 | 进程崩溃产生可读 Core Dump |
| 备份副本泄露 | CWE-530 | 备份文件未受保护 |
| 信息差异导致用户名或对象枚举 | CWE-203/204 | 响应内容或时间存在可区分差异 |

## 5.8 Web 与 API 专用方法

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 反射型 XSS | CWE-79 | 输入立即反射到页面 |
| 存储型 XSS | CWE-79 | 输入被存储后渲染 |
| DOM 型 XSS | CWE-79 | 客户端脚本处理不可信数据 |
| CSRF | CWE-352 | 浏览器自动携带认证凭据 |
| Clickjacking | CWE-1021 | 页面可被不可信站点嵌套 |
| CORS 配置绕过 | CWE-942 | 跨域策略过度宽松 |
| 开放重定向 | CWE-601 | 跳转目标由用户控制 |
| SSRF | CWE-918 | 服务端根据外部输入访问 URL |
| 内网服务探测型 SSRF | CWE-918 | SSRF 可访问内部地址 |
| 云元数据窃取型 SSRF | CWE-918 | SSRF 可访问元数据服务 |
| HTTP 请求走私 | CWE-444 | 多级代理解析不一致 |
| HTTP 参数污染 | CWE-235/436 派生 | 多组件对重复参数处理不同 |
| Host Header 欺骗 | CWE-346/644 派生 | 应用信任外部 Host Header |
| Web 缓存投毒 | CWE-444/525 派生 | 缓存键未覆盖影响响应的输入 |
| Web 缓存欺骗 | CWE-525/路径解析派生 | 动态响应被误缓存 |
| Mass Assignment 参数越权 | CWE-915 | 自动绑定外部字段到敏感属性 |
| API 对象级授权绕过 | CWE-639/862 | 对象 ID 可控且缺少授权检查 |
| API 功能级授权绕过 | CWE-862/863 | 普通角色可调用管理功能 |
| API 速率限制绕过 | CWE-770 | 限流键可伪造或分散 |
| GraphQL Introspection 信息枚举 | CWE-200 派生 | 生产接口开放 Schema 查询 |
| GraphQL 批量查询资源耗尽 | CWE-770 | 允许高复杂度嵌套或批量请求 |
| Webhook 事件伪造 | CWE-345/347 | Webhook 缺少签名或来源校验 |
| 回调地址篡改 | CWE-601/918 | 回调 URL 可由外部控制 |
| HTTP Method Override 绕过 | CWE-436/862 | 网关和后端对方法解释不一致 |
| Content-Type 混淆绕过 | CWE-436 | 不同组件按不同格式解析请求 |

## 5.9 软件包、更新、加载与供应链

| Method 候选名称 | CWE 参考 | 推荐前置条件 |
|---|---|---|
| 不可信搜索路径劫持 | CWE-426 | 加载器搜索攻击者可写目录 |
| DLL 预加载攻击 | CWE-427 | 动态库搜索路径不安全 |
| 相对路径加载劫持 | CWE-428 | 可执行文件或库路径未加引号/限定 |
| 下载代码未校验直接执行 | CWE-494 | 下载内容缺少来源和完整性校验 |
| 更新包签名绕过 | CWE-347/494 | 更新包验证流程不完整 |
| 更新源劫持 | CWE-494/346 | 更新地址或 DNS 可被操纵 |
| 软件包依赖混淆 | CWE-829/供应链派生 | 构建从多个信任级别仓库解析依赖 |
| 不可信组件加载 | CWE-829 | 系统加载外部组件或脚本 |
| 恶意插件加载 | CWE-829 | 插件来源或签名未验证 |
| 升级包路径穿越 | CWE-22 | 解包路径未限制 |
| 升级包压缩炸弹 | CWE-409 | 自动解压不可信升级包 |
| 版本回滚到已知弱版本 | CWE-757 | 版本策略允许降级 |
| 制品仓库替换 | CWE-494/供应链派生 | 构建或部署信任可写制品仓库 |
| 镜像标签漂移或替换 | CWE-494/供应链派生 | 部署使用可变标签且不校验摘要 |
| 签名密钥窃取后伪造软件包 | CWE-320/347 | 签名私钥保护不足 |

---

# 6. FiGHT/5G 专用攻击方法集

## 6.1 RAN、空口、UE 与无线接入

| Method 候选名称 | 典型攻击面 | 主要参考 |
|---|---|---|
| 伪基站部署 | 空口、UE、gNB | FiGHT FGT1588.501/无线威胁 |
| 伪基站广播欺骗 | 广播信道、UE | FiGHT FGT1557.501 |
| 空口中间人攻击 | UE 与 gNB 间链路 | FiGHT FGT1557.501 |
| 空口下行消息嗅探 | 无线链路 | FiGHT FGT1040.501 |
| 空口上行消息嗅探 | 无线链路 | FiGHT FGT1040.501 派生 |
| 无线射频干扰 | NR 频段、控制信道 | FiGHT/无线威胁 |
| 5G 降级至低安全制式 | UE、RAN、核心网 | FiGHT FGT1562.501 |
| 伪造系统信息广播 | SIB、广播信道 | FiGHT FGT1557.501/FGT1642.501 |
| 伪造寻呼消息 | Paging、UE | FiGHT FGT5012.007 |
| 静默寻呼定位用户 | Paging、UE | FiGHT FGT5012.007 |
| RRC 畸形消息注入 | RRC 编解码与状态机 | FiGHT/协议载荷归一化 |
| RRC 消息泛洪 | RRC、接入控制 | FiGHT Endpoint/Network DoS |
| RRC 状态机乱序触发 | RRC 状态机 | FiGHT/CWE-841 派生 |
| NAS 畸形消息注入 | NAS 编解码与状态机 | FiGHT/协议载荷归一化 |
| NAS 消息重放 | NAS 安全与状态机 | FiGHT/重放威胁 |
| NGAP 畸形消息注入 | gNB-AMF 接口 | FiGHT FGT5045 派生 |
| NGAP 信令泛洪 | N2、AMF | FiGHT FGT1498.501 派生 |
| UE 注册风暴 | Registration、AMF、UDM | FiGHT FGT1498.501 派生 |
| UE 接入拒绝消息伪造 | RRC/NAS、UE | FiGHT FGT1499.503 |
| 通过欺诈告警阻断 UE | 注册、风控 | FiGHT FGT1499.502 |
| 基站硬件物理破坏 | RAN 设备、天线 | FiGHT FGT5018.002 |

## 6.2 5G Core、SBA 与网络功能

| Method 候选名称 | 典型攻击面 | 主要参考 |
|---|---|---|
| 网络功能服务枚举 | NRF、SCP、SBA | FiGHT FGT5003 |
| 恶意网络功能注册 | NRF、SBA | FiGHT FGT5007 |
| 伪造 NF 身份调用服务 | SBI、mTLS、OAuth | FiGHT/CWE 归一化 |
| NF 访问令牌伪造 | OAuth、SBI | FiGHT FGT5011 |
| NF Token Scope 扩权 | OAuth、SBI | FiGHT FGT5043.001 |
| NEF 未授权访问 | NEF、外部 AF | FiGHT FGT5011 |
| NRF 注册信息投毒 | NRF、服务注册 | FiGHT FGT5007 派生 |
| NRF 服务发现信息窃取 | NRF、SCP | FiGHT FGT5003 |
| SBA HTTP/2 请求泛洪 | SBI、HTTP/2 | FiGHT FGT1498.501 |
| SBA API 请求走私或解析差异 | SBI、代理、SCP | CWE-444/436 派生 |
| SBI 畸形 JSON 或 HTTP 消息注入 | SBI、NF API | FiGHT FGT5045/CWE 派生 |
| 核心网信令泛洪 | AMF、SMF、UDM、AUSF、NRF | FiGHT FGT1498.501 |
| 恶意 VNF 实例化 | NFV、MANO | FiGHT FGT5013 |
| VNF 配置篡改 | VNF、MANO | FiGHT FGT5039 |
| 核心网功能内存敏感数据抓取 | NF 进程、容器 | FiGHT FGT5005 |
| 用户面流量重定向 | UPF、N4、SDN | FiGHT FGT5008 |
| GTP-U 流量嗅探 | N3、N9、UPF | FiGHT Network Sniffing 派生 |
| GTP 隧道标识冲突 | GTP、TEID | FiGHT FGT5021 |
| PFCP 会话规则篡改 | N4、SMF、UPF | FiGHT FGT5008 派生 |
| PDU Session 建立泛洪 | SMF、UPF、AMF | FiGHT FGT1498.501 派生 |
| 欺诈性 AMF 注册到 UDM | AMF、UDM | FiGHT FGT5010 |
| 用户认证密钥强制派生 | AUSF、UDM、漫游认证 | FiGHT FGT5044 |
| 核心网接口完整性削弱 | SBI、N2、N3、N4 等 | FiGHT FGT5009.002 |
| 核心网接口加密削弱 | SBI、非 SBI 接口 | FiGHT FGT1600.502 |

## 6.3 漫游、互联与运营商边界

| Method 候选名称 | 典型攻击面 | 主要参考 |
|---|---|---|
| 漫游信任关系滥用 | 漫游伙伴、SEPP、IPX | FiGHT FGT1199.501 |
| 运营商互联接口滥用 | N32、N26、IPX、GRX | FiGHT FGT5016 |
| 漫游与互联链路中间人攻击 | SEPP、IPX、互联链路 | FiGHT FGT1557.502 |
| 非 SBI 运营商接口中间人攻击 | N2/N3/N4/N6/N9 等 | FiGHT FGT1557.503 |
| 漫游接口畸形信令注入 | N32、N26、IPX | FiGHT FGT5029/FGT5045 |
| 漫游接口信令重放 | SEPP、IPX、漫游网元 | FiGHT/重放威胁 |
| 漫游用户会话信息窃取 | 漫游接口、IPX | FiGHT FGT5016 |
| 漫游用户位置跟踪 | 漫游信令、核心网 | FiGHT FGT5012 |
| 漫游用户标识获取 | SUPI、IMSI、漫游信令 | FiGHT FGT5019 |
| SEPP 安全策略绕过 | N32、SEPP | FiGHT FGT5029 派生 |
| 互联防火墙规则绕过 | 电信防火墙、信令网关 | FiGHT FGT5045 派生 |
| 互联计费账单伪造 | 漫游、互联结算 | FiGHT FGT5025 |
| 漫游认证密钥强制生成 | 漫游认证流程 | FiGHT FGT5044 |
| 互联接口完整性保护削弱 | IPX、SEPP、非 SBI | FiGHT FGT5009.002 |
| 互联接口加密保护削弱 | IPX、SEPP、非 SBI | FiGHT FGT1600.502 |

## 6.4 网络切片、NFV、SDN 与 O-RAN

| Method 候选名称 | 典型攻击面 | 主要参考 |
|---|---|---|
| 网络切片标识枚举 | NSSAI、NSSF、UE 配置 | FiGHT FGT5028 |
| 共享切片资源耗尽 | 共享 NF、公共控制资源 | FiGHT FGT1498.502 |
| 网络切片应用资源劫持 | 切片应用、工作负载 | FiGHT FGT5038 |
| 网络切片基础设施资源劫持 | NFVI、共享基础设施 | FiGHT FGT1599.502 |
| 共享 NF 跨切片信息窃取 | 共享 NF、共享数据库 | FiGHT FGT1599.501/FGT5012.005 |
| 低安全切片跨越到高安全切片 | 网络切片、共享 VNF | FiGHT FGT1599.502 |
| 恶意共租户攻击 NFVI | NFVI、虚拟化平台 | FiGHT FGT1599.501 |
| VNF 配置操纵 | VNF、MANO | FiGHT FGT5039 |
| 恶意 VNF 实例化 | NFV、MANO | FiGHT FGT5013 |
| SDN 控制器未授权访问 | SDN 控制器、北向 API | FiGHT/ATT&CK 派生 |
| SDN 流表规则篡改 | SDN 控制器、交换机 | FiGHT Remote System Discovery:Controller 派生 |
| vSwitch 转发表操纵 | vSwitch、NFVI | FiGHT Remote System Discovery:vSwitch 派生 |
| 虚拟网络边界桥接 | vSwitch、虚拟路由、共享网卡 | FiGHT FGT1599 |
| O-RAN 管理接口滥用 | SMO、O1/O2/A1/E2 接口 | FiGHT/O-RAN 威胁归一化 |
| O-RAN 外部服务请求泛洪 | SMO、开放 API | FiGHT FGT1499 |
| xApp/rApp 恶意应用部署 | Near-RT RIC、Non-RT RIC | FiGHT/O-RAN 威胁归一化 |
| RIC 策略篡改 | A1、E2、RIC | FiGHT/O-RAN 威胁归一化 |
| ML 模型篡改 | O-RAN、AI/ML 模型仓库 | FiGHT FGT5037 |
| 训练数据投毒 | O-RAN、ML 数据管道 | FiGHT FGT5037 派生 |
| 模型推理输入对抗扰动 | O-RAN、ML 推理接口 | FiGHT/AML 威胁归一化 |

## 6.5 用户身份、位置、隐私、计费与欺诈

| Method 候选名称 | 典型攻击面 | 主要参考 |
|---|---|---|
| SUPI/IMSI 获取 | UE、RAN、核心网、漫游 | FiGHT FGT5019 |
| SUCI 关联与用户识别 | 空口、核心网 | FiGHT FGT5019 派生 |
| 通过低制式降级获取用户标识 | UE、伪基站、RAN | FiGHT FGT5019/FGT1562.501 |
| 通过 NF API 获取用户标识 | SBI、核心网 NF | FiGHT FGT5019.003 |
| 通过无线测量定位 UE | RAN、空口 | FiGHT FGT5012 |
| 通过核心网信令定位 UE | AMF、UDM、LMF 等 | FiGHT FGT5012.004 |
| 通过共享 NF 跨切片定位 UE | 共享 NF、网络切片 | FiGHT FGT5012.005 |
| 静默或伪造寻呼定位 UE | Paging、RAN | FiGHT FGT5012.007 |
| 用户位置历史批量收集 | 核心网、数据平台 | FiGHT FGT5012 |
| CDR 计费记录收集 | CHF、计费数据库 | FiGHT FGT5017 |
| CDR 篡改 | CHF、计费链路 | FiGHT Fraud 派生 |
| 互联结算账单伪造 | 漫游计费、合作方结算 | FiGHT FGT5025 |
| 免费或未计费服务滥用 | 计费控制、策略控制 | FiGHT Fraud |
| 用户套餐或计费策略篡改 | PCF、CHF、业务系统 | FiGHT Fraud 派生 |
| 欺诈性 AMF 注册 | AMF、UDM | FiGHT FGT5010 |
| 同一身份多地并发注册欺诈 | 注册、风控 | FiGHT FGT1499.502 派生 |
| 设备或用户身份冒充 | UE、SIM/eSIM、核心网 | FiGHT Credential/Identity 威胁 |
| eSIM 配置文件窃取或替换 | eSIM、SM-DP+、LPA | FiGHT/电信威胁归一化 |

## 6.6 5G 协议通用方法模板

对任一 5G 协议或接口，可按实际功能从下列模板中选择：

| Method 模板 | 示例 |
|---|---|
| 畸形 `<协议>` 消息注入 | 畸形 RRC 消息注入、畸形 NGAP 消息注入 |
| `<协议>` 消息泛洪 | NAS 消息泛洪、SBI 请求泛洪 |
| `<协议>` 消息重放 | NAS 消息重放、N32 信令重放 |
| `<协议>` 消息伪造 | Paging 消息伪造、PFCP 消息伪造 |
| `<协议>` 消息篡改 | GTP-U 数据篡改、N32 信令篡改 |
| `<协议>` 状态机乱序触发 | RRC 状态机乱序触发 |
| `<协议>` 长度字段异常触发 | ASN.1 长度字段异常触发 |
| `<协议>` 未知或重复 IE 注入 | NGAP 重复 IE 注入 |
| `<协议>` 版本协商降级 | TLS/HTTP2/电信协议版本降级 |
| `<协议>` 序列号或事务 ID 操纵 | PFCP Sequence Number 操纵 |
| `<接口>` 认证绕过 | SBI 认证绕过、管理接口认证绕过 |
| `<接口>` 授权绕过 | NEF API 授权绕过 |
| `<接口>` 完整性保护削弱 | N32 完整性保护削弱 |
| `<接口>` 加密保护削弱 | N9 加密保护削弱 |
| `<接口>` 流量嗅探 | 空口流量嗅探、N3 流量嗅探 |
| `<接口>` 中间人攻击 | 空口中间人、漫游链路中间人 |
| `<接口>` 资源耗尽 | AMF 接口资源耗尽、SMO 接口资源耗尽 |

---

# 7. LLM 选择 Method 的规则

## 7.1 选择顺序

对于每个 `surface`，按以下顺序选择候选 method：

1. **FiGHT 精确匹配**：攻击面属于 5G、RAN、Core、漫游、切片、NFV 或 O-RAN 时，优先选择 FiGHT 方法。
2. **ATT&CK 行为匹配**：选择与攻击者行为直接对应的 Technique/Sub-technique。
3. **CWE 弱点利用匹配**：代码中存在相关输入处理、认证、内存、文件、加密或状态机逻辑时，选择对应的理论弱点利用方法。
4. **通用协议模板**：没有精确条目时，使用“畸形消息、伪造、重放、篡改、泛洪、降级、状态机异常”等模板。
5. **领域特定方法**：根据产品文档和代码证据生成更具体的“动作 + 对象”名称。

## 7.2 必须满足的条件

每个 method 应满足：

```text
1. 能够作用于当前 surface；
2. 与当前 risk 和 attack_goal 存在合理因果关系；
3. preconditions 能描述攻击成立的必要条件；
4. 不把理论可能性写成已确认漏洞；
5. 不为了覆盖数量而机械罗列无关 ATT&CK/CWE 条目。
```

## 7.3 数量建议

每个 surface 根据实际情况选择最相关 method，但应避免不经分析把本文件中所有候选方法全部挂到每个攻击面下。

## 7.4 推荐输出示例

```json
{
  "node_id": "NODE-009",
  "parent_id": "NODE-008",
  "node_type": "method",
  "name": "通过畸形RRC长度字段触发越界访问",
  "order": 1,
  "basis": [
    {
      "source_type": "code",
      "location": "src/rrc/codec",
      "description": "该路径负责RRC消息解码和长度字段处理"
    }
  ],
  "preconditions": [
    "攻击者能够向基站发送RRC消息",
    "外部消息长度字段进入解码与内存访问逻辑"
  ]
}
```

---

# 8. 不推荐直接使用的 Method 名称

| 不推荐名称 | 问题 | 推荐改写 |
|---|---|---|
| 漏洞利用 | 过于宽泛 | 利用对外应用弱点获取初始访问 |
| 协议攻击 | 过于宽泛 | 畸形 NGAP 消息注入 |
| 拒绝服务 | 未说明方式和对象 | 核心网信令泛洪 |
| 信息泄露 | 属于风险结果 | 错误消息泄露内部信息 |
| 越权 | 未说明行为和对象 | 用户可控对象标识越权访问 |
| 内存漏洞 | 属于缺陷类别 | 通过超长输入触发堆缓冲区溢出 |
| 认证漏洞 | 属于缺陷类别 | 认证逻辑绕过 |
| SQL 注入漏洞 | 带有漏洞确认含义 | SQL 注入 |
| RRC 存在越界写 | 带有确认结论 | 通过畸形 RRC 长度字段触发越界写 |
| Fuzzing | 属于测试方法 | 畸形协议消息注入 |
| 扫描代码 | 属于分析动作 | 不作为 method 输出 |

---

# 9. 官方参考来源

- MITRE ATT&CK Enterprise Techniques：<https://attack.mitre.org/techniques/enterprise/>
- MITRE ATT&CK Mobile Techniques：<https://attack.mitre.org/techniques/mobile/>
- MITRE ATT&CK ICS Techniques：<https://attack.mitre.org/techniques/ics/>
- MITRE ATT&CK Updates：<https://attack.mitre.org/resources/updates/>
- MITRE FiGHT Techniques：<https://fight.mitre.org/techniques/>
- MITRE FiGHT Matrix：<https://fight.mitre.org/matrix/>
- CWE Current List：<https://cwe.mitre.org/data/index.html>
- 2025 CWE Top 25：<https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>

## 版本基线

本文档整理时采用以下公开版本基线：

```text
MITRE ATT&CK：v19 / v19.1，2026年4月至5月发布
MITRE FiGHT：v3.1.0
CWE：v4.20；同时参考2025 CWE Top 25
```

知识库会持续更新。本文件用于 Skill 的方法候选参考，不替代官方知识库的最新条目和定义。
