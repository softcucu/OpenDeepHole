# OpenDeepHole

基于 SKILL 的 C/C++ 源码白盒审计工具。核心漏洞挖掘在用户本地 Agent 上执行，源码不离开本机，结果汇报到 Web 服务器统一展示。

## 整体架构

```
[服务器端]
  FastAPI (port 8000)
  ├── Web UI（React + Tailwind CSS）
  ├── WebSocket /api/agent/ws 接受 Agent 连接
  ├── 通过 WS 下发扫描任务（task / stop / resume）
  ├── 接收 Agent 上报的扫描事件和漏洞结果（HTTP POST）
  ├── 存储扫描历史和误报反馈
  └── 提供 Agent 下载包

[用户本地]
  opendeephole-agent（守护进程，从 Web UI 下载）
  ├── 启动后主动向服务器发起 WebSocket 连接
  ├── 发送 hello 握手，接收 welcome 确认
  ├── 等待服务器通过 WS 推送扫描任务
  ├── 收到任务后：代码索引 → 静态分析 → AI 审计
  └── 实时通过 HTTP POST 将事件和漏洞结果上报服务器
```

**交互流程：**

```
用户在 Web UI 点击「新建扫描」
  → 选择在线 Agent、填写代码路径（Agent 所在机器的路径）、选择检查项
  → 服务器通过 WebSocket 推送任务到 Agent
  → Agent 在本地执行完整扫描流程
  → 进度和结果实时显示在 Web UI
```

**源码不离开本地**：Agent 只上报漏洞分析结论，不上传源码文件。  
**误报反馈闭环**：用户在 Web UI 标记误报后，Agent 下次扫描前自动拉取这些经验，注入 SKILL 中减少重复误报。

## 快速开始

### 部署服务器

**Docker（推荐）：**

```bash
docker-compose up --build
```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled[, mode, skill_name]
├── SKILL.md        # opencode 模式必须：opencode skill 定义
├── prompt.txt      # api 模式必须：LLM 系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

访问 `http://localhost:8000`

| Checker | 说明 | 模式 | 静态分析器 |
|---------|------|------|-----------|
| `npd` | 空指针解引用 (NPD) | opencode | 有（tree-sitter AST 分析） |
| `oob` | 数组/缓冲区越界 (OOB) | opencode | 有 |
| `memleak` | 异常分支内存泄漏 (MEMLEAK) | api | 有（自定义解析器） |
| `intoverflow` | 整数翻转/溢出 (INTOVFL) | opencode | 有（多阶段追踪） |
| `sensitive_clear` | 敏感信息未清零 (SENSITIVE_CLEAR) | opencode | 有 |
| `resleak` | 全类型资源泄露 (RESLEAK) | opencode | 有 |

**第 1 步：下载安装包**

打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`，解压到本地目录。

**第 2 步：配置 agent.yaml**

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 显示名称（显示在新建扫描的下拉列表中），留空则使用主机名
agent_name: "my-agent"

# 用户归属 token（下载 Agent 时自动填入，勿手动修改）
owner_token: ""

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"

# opencode CLI 配置（供 mode: opencode 的检查项使用）
opencode:
  executable: "opencode"
  timeout: 1200
```

> 每个检查项的调用方式（`api` 或 `opencode`）在其 `checker.yaml` 中独立配置，无需全局 `mode` 选项。

**第 3 步：安装系统代码索引工具**

代码索引依赖 Universal Ctags 和 cscope。缺少任一命令时 Agent 会先尝试通过启动脚本自动安装；安装失败时会停止并提示处理方式，不会回退到旧索引方式。

Windows 推荐使用 MSYS2。`run_agent.bat` 会在缺少工具或 `ctags` 不支持 JSON 输出时优先执行 `winget install -i MSYS2.MSYS2`，然后通过 MSYS2 `pacman` 安装带 JSON 支持的 MinGW64 Universal Ctags 和 cscope，并把 `C:\msys64\mingw64\bin` 放在 `C:\msys64\usr\bin` 前面加入当前启动脚本的 `PATH`。如果需要手动提前安装，可执行：

```powershell
winget install -i MSYS2.MSYS2
```

然后打开 MSYS2 运行：

```bash
pacman -S --needed --noconfirm mingw-w64-x86_64-ctags cscope
```

Linux / macOS 可用系统包管理器安装：

```bash
# Debian / Ubuntu
sudo apt install universal-ctags cscope

# macOS
brew install universal-ctags cscope
```

**第 4 步：启动 Agent 守护进程**

```bash
# Linux / macOS
chmod +x run_agent.sh
./run_agent.sh

# Windows
run_agent.bat
```

启动成功后，终端输出类似：

```
OpenDeepHole Agent
  Name    : my-agent
  Server  : http://your-server:8000

  Connected via WebSocket, agent_id: a1b2c3d4...
```

Agent 通过 WebSocket 保持长连接，等待服务器推送任务。

**第 4 步：在 Web UI 创建扫描任务**

1. 点击右上角「新建扫描」
2. 从下拉列表选择已在线的 Agent
3. 填写代码路径（Agent 所在机器上的绝对路径，如 `/home/user/myproject`）
4. 选择要运行的检查项，点击「开始扫描」
5. 扫描进度实时显示在当前页面

### Agent 启动参数

```
./run_agent.sh [选项]

选项：
  --server URL        覆盖 agent.yaml 中的 server_url
  --name NAME         覆盖 Agent 显示名称
  --config FILE       指定配置文件路径（默认 ./agent.yaml）
```

### 停止与恢复扫描

- **停止**：在扫描详情页点击「停止扫描」，服务器直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。
- **恢复**：在扫描列表页点击「恢复」，服务器通知 Agent 继续同一扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。

## 误报反馈机制

1. 在 Web UI 的漏洞列表或经验库中提交正报/误报反馈
2. 经验库中打勾的反馈会记录到本次扫描的 `feedback_ids`
3. 已选反馈按漏洞类型注入到对应 SKILL 文件的「历史用户经验」章节
4. LLM 在分析同类候选时参考这些经验，校验并减少重复误判

## 插件式 Checker 架构

漏洞类型以插件形式组织在 `checkers/` 目录下，添加新类型无需修改代码：

```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled, mode
├── SKILL.md        # opencode 模式必须；定义 AI 分析技巧
├── prompt.txt      # api 模式可选；自定义系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

**checker.yaml 格式：**

```yaml
name: uaf
label: UAF
description: "Use-After-Free 检测"
enabled: true
visibility: public    # public: 所有用户可见；admin: 仅管理员测试可见
# mode: opencode       # 可选，默认 opencode；设为 api 则使用 prompt.txt + LLM 直接调用
# skill_name: uaf-audit # 可选，opencode 模式下自定义 skill 名称
```

每个 Checker 独立配置 `mode`，同一次扫描中不同 Checker 可使用不同调用方式。
新增或修改 `checkers/` 下的 checker 后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描目录。测试阶段建议设置 `visibility: admin`，只有管理员能看到并启动该 checker；测试完成后改为 `visibility: public` 即可对所有用户开放。

**内置 Checker：**

| Checker | 说明 |
|---------|------|
| `npd` | 空指针解引用 (Null Pointer Dereference) |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) |
| `intoverflow` | 整数翻转/溢出 |
| `memleak` | 内存泄漏 |
| `sensitive_clear` | 敏感信息未清零 |
| `resleak` | 全类型资源泄露（文件/套接字/锁/内存映射等） |

### 添加新 Checker

**第 1 步：创建目录和元数据**

```bash
mkdir checkers/mycheck
```

`checkers/mycheck/checker.yaml`：

```yaml
name: mycheck
label: MYCHECK
description: "我的自定义漏洞检测"
enabled: true
mode: "api"
```

**第 2 步（api 模式）：编写 prompt.txt**

```
你是专业的 C/C++ 漏洞审计专家。请分析以下函数是否存在 XXX 漏洞...
```

**第 2 步（opencode 模式）：编写 SKILL.md**

参考 `checkers/npd/SKILL.md`，定义分析步骤和可用 MCP 工具。

**第 3 步（可选）：编写 analyzer.py**

```python
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    vuln_type = "mycheck"  # 必须与 checker.yaml 的 name 一致

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []
        candidates = []
        functions = db.get_all_functions()
        total = len(functions)
        for idx, func in enumerate(functions):
            # 进度回调（可选，用于前端进度条）
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)
            body = func["body"] or ""
            if not body:
                continue
            # ... 分析逻辑 ...
            candidates.append(Candidate(
                file=func["file_path"],
                line=func["start_line"],
                function=func["name"],
                description="检测到可疑模式...",
                vuln_type=self.vuln_type,
            ))
        return candidates
```

**约定：**

- 类名**必须**是 `Analyzer`
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 字段一致
- `find_candidates()` 接收项目根目录路径，返回 `Iterable[Candidate]`（列表或 generator 均可）
- 可以 `from backend.analyzers.base import BaseAnalyzer, Candidate` 一次性导入所需类

**第 4 步：本地测试 Checker（无需后端）**

```bash
# 只运行静态分析自测：校验 checker.yaml、Analyzer 加载、代码索引和候选点输出
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --min-candidates 1

# 输出 JSON，便于在脚本或 CI 中断言
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json

# 精确断言候选点数量
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --expect-candidates 3

# 可选：对前 1 个候选点运行真实 AI 审计（会使用 agent.yaml 中的 LLM/opencode 配置）
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --audit --audit-limit 1 --config agent.yaml
```

本地测试命令不依赖后端、Web UI 或在线 Agent。默认会在被测项目目录下重建 `code_index.db`，与 Agent 扫描时的索引位置一致；如只想把索引写到临时位置，可加 `--index-db /tmp/mycheck-code_index.db`。代码索引同样需要本机已安装 Universal Ctags 和 cscope。

开发阶段即使 `checker.yaml` 中设置了 `enabled: false`，本地测试命令也会临时启用该 checker 进行自测，并输出提示；线上扫描入口仍会遵循 `enabled` 和 `visibility` 配置。`--audit` 会实际调用模型或 opencode，请先确认 `agent.yaml` 配置可用，并用 `--audit-limit` 控制成本。

新增或修改 `checkers/` 下的 checker 后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描目录，创建扫描时也会把选中的 checker 同步到 Agent。

**CodeDatabase API 参考（`code_parser/code_database.py`）：**

当 `db` 参数非 `None` 时，可通过以下方法查询预构建的代码索引。所有查询方法返回 `list[sqlite3.Row]`，通过 `row["field_name"]` 访问字段。

| 方法 | 说明 | 返回字段 |
|------|------|---------|
| `db.get_all_functions()` | 获取所有函数（按文件和行号排序） | function_id, name, signature, return_type, start_line, end_line, is_static, linkage, body, file_path |
| `db.get_functions_by_name(name)` | 按名称精确匹配函数 | 同上 |
| `db.get_function_body(name)` | 获取第一个匹配函数的函数体 | 返回 `str \| None` |
| `db.get_calls_from_function(function_id)` | 查询指定函数发出的所有调用 | call_id, caller_function_id, callee_name, callee_function_id, line, column, file_path |
| `db.get_call_sites_by_name(callee_name)` | 查询指定函数名的所有被调用点 | 同上 + caller_name |
| `db.get_structs_by_name(name)` | 按名称查询结构体/类定义，短名可匹配 C++ 限定名 | struct_id, name, start_line, end_line, definition, file_path |
| `db.get_global_variables_by_name(name)` | 按名称查询全局变量 | global_var_id, name, start_line, end_line, is_extern, is_static, definition, file_path |
| `db.get_global_variable_reference_by_name(name)` | 查询全局变量的所有引用点 | reference_id, variable_name, function_id, line, column, context, access_type, file_path, function_name |

**tree-sitter 辅助工具（`code_parser/code_utils.py`）：**

如需在 analyzer 中对函数体进行 AST 分析，可结合 tree-sitter 和以下辅助函数：

| 函数 | 说明 |
|------|------|
| `find_nodes_by_type(root_node, node_type, k=0)` | 递归查找所有指定类型的节点（DFS，最大深度 100） |
| `get_child_node_by_type(root_node, node_type: list)` | 返回第一个类型匹配的直接子节点 |
| `get_child_nodes_by_type(root_node, node_type: list)` | 返回所有类型匹配的直接子节点 |
| `get_child_field_text_by_type(root_node, field_name, node_type: list)` | 获取指定字段的文本（仅当字段节点类型匹配时） |
| `get_child_field_text(root_node, field_name)` | 获取指定字段的文本 |

使用示例：

```python
import tree_sitter_cpp
from tree_sitter import Language, Parser
from code_parser.code_utils import find_nodes_by_type

_CPP = Language(tree_sitter_cpp.language())
parser = Parser(_CPP)

tree = parser.parse(func_body.encode())
# 查找所有函数调用节点
for call in find_nodes_by_type(tree.root_node, "call_expression"):
    callee = call.child_by_field_name("function")
    if callee:
        print(callee.text.decode())
```

**常见模式：**

*1. 遍历所有函数并分析*

```python
for func in db.get_all_functions():
    name = func["name"]
    body = func["body"] or ""
    file_path = func["file_path"]
    start_line = func["start_line"]
    # 对函数体进行模式匹配或 AST 分析...
```

*2. 查询调用关系*

```python
# 查找所有 malloc 调用点
for call in db.get_call_sites_by_name("malloc"):
    print(f"{call['file_path']}:{call['line']} — 调用者: {call['caller_name']}")

# 查找某函数内部调用的所有函数
for call in db.get_calls_from_function(func["function_id"]):
    print(f"  调用了 {call['callee_name']} at line {call['line']}")
```

*3. Generator 模式（流式产出）*

`find_candidates` 可返回 `Iterator[Candidate]`，通过 `yield` 流式产出候选项，让 LLM 提前开始处理：

```python
from collections.abc import Iterator

def find_candidates(self, project_path: Path, db=None) -> Iterator[Candidate]:
    if db is None:
        return
    for func in db.get_all_functions():
        # ... 分析 ...
        yield Candidate(file=func["file_path"], ...)
```

*4. 进度回调*

```python
functions = db.get_all_functions()
total = len(functions)
for idx, func in enumerate(functions):
    if self.on_file_progress and idx % 20 == 0:  # 每 20 个函数更新一次
        self.on_file_progress(idx + 1, total)
```

*5. 不依赖 db 的分析*

也可跳过 db，直接遍历文件系统进行自定义解析（如 memleak checker）：

```python
def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
    candidates = []
    for src in project_path.rglob("*.c"):
        source = src.read_bytes()
        tree = self._parser.parse(source)
        # 自定义 AST 分析...
    return candidates
```

**实现建议：**

- 推荐使用 `db` 查询而非直接遍历文件系统（性能更好，且与 MCP Server 共享同一索引）
- Generator 模式适合耗时较长的分析器，可让 LLM 提前开始处理已发现的候选项
- `on_file_progress` 回调用于前端进度条显示，建议在循环中定期调用
- `description` 字段尽可能详细，它会作为 prompt 的一部分传递给 AI
- `mode: api` 的 checker 使用 `prompt.txt` 而非 `SKILL.md`，适用于无需 MCP 工具的场景
- 返回空列表是合法的，表示未找到候选点

### 服务端 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8000

storage:
  projects_dir: "../OpenDeepHoleData/projects"
  scans_dir: "../OpenDeepHoleData/scans"

logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

`storage` 中的相对路径会按 `config.yaml` 所在目录解析；默认会落到 OpenDeepHole 项目上层的 `OpenDeepHoleData/`。

### Agent agent.yaml

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 显示名称（留空则使用主机名）
agent_name: ""

# 用户归属 token（下载 Agent 时自动填入，勿手动修改）
owner_token: ""

# 代理跳过列表，逗号分隔
no_proxy: "10.0.0.0/8"

# 要运行的检查项，留空则运行全部已启用的检查项
checkers: []

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"
  temperature: 0.1
  timeout: 300
  max_retries: 3
  stream: false

# opencode CLI 配置（供 mode: opencode 的检查项使用）
opencode:
  executable: "opencode"
  model: ""      # 留空则使用 opencode 默认模型
  timeout: 1200
  max_retries: 2
```

## 本地开发

```bash
# 后端（含热重载）
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 前端开发服务器（代理到 localhost:8000）
cd frontend
npm install
npm run dev

# 构建前端
npm run build

# 查看日志
tail -f logs/opendeephole.log
```

> **注意：** Agent 需要运行支持 checker 同步的新版本。之后新增 checker 时，只要点击开始扫描，后端会把本次选中的 checker 同步到 Agent，无需重启后端或 Agent。

## 数据存储位置

Agent 运行时会在以下位置产生数据：

| 位置 | 内容 | 生命周期 |
|------|------|---------|
| `<项目目录>/code_index.db` | tree-sitter 代码索引（函数/结构体/调用关系） | 持久保留，后续扫描复用 |
| `~/.opendeephole/scans/<scan_id>/` | 扫描工作目录（candidates.json、config.yaml、agent.log） | 扫描成功后自动删除；取消/出错时保留用于恢复 |
| `~/.opendeephole/fp_feedback.json` | 本地误报反馈缓存 | 持久保留 |
| `~/.opendeephole/fp_reviews/<review_id>/` | 误报复审临时目录 | 复审完成后自动删除 |
| `<项目目录>/opencode.json` + `<项目目录>/.opencode/` | opencode 工作区（SKILL 文件、MCP 配置） | 扫描完成后自动清理 |

服务端数据：

| 位置 | 内容 |
|------|------|
| `../OpenDeepHoleData/scans/` | 扫描结果 JSON（submit_result 输出）和 `scans.db` |
| `../OpenDeepHoleData/projects/` | 服务端上传扫描的项目缓存 |
| `logs/opendeephole.log` | 服务端日志（滚动，默认 10MB × 5 份） |

> **注意：** `code_index.db` 直接保存在被扫描的代码仓目录下。对于大型代码仓，该文件可能有几十到几百 MB。如需清理，直接删除项目目录下的 `code_index.db` 即可，下次扫描会自动重建。

## 项目结构

```
OpenDeepHole/
├── agent/                 # 本地 Agent Python 包
│   ├── config.py          # agent.yaml 配置加载
│   ├── main.py            # 守护进程入口（WebSocket 连接 + 自动重连）
│   ├── server.py          # WebSocket 命令处理（task/stop/resume）
│   ├── task_manager.py    # 任务生命周期管理（创建/停止/恢复）
│   ├── scanner.py         # 完整扫描流程（索引→静态分析→AI审计→上报）
│   ├── reporter.py        # 向服务器上报进度和结果
│   └── local_mcp.py       # opencode 模式：本地启动 MCP Server
├── checkers/              # 插件目录（每种漏洞类型一个子目录）
│   ├── npd/               # checker.yaml + SKILL.md/prompt.txt + analyzer.py
│   ├── oob/
│   ├── memleak/
│   ├── intoverflow/
│   ├── sensitive_clear/
│   └── resleak/
├── code_parser/           # 共享 C/C++ 代码解析器
│   ├── code_database.py   # SQLite 代码索引（函数/结构体/全局变量/调用关系）
│   ├── cpp_analyzer.py    # tree-sitter C++ 解析器
│   ├── code_utils.py      # tree-sitter 节点遍历辅助函数
│   └── code_struct.py     # 解析结果数据类
├── frontend/              # React + TypeScript + Vite + Tailwind CSS
├── backend/
│   ├── api/
│   │   ├── agent.py       # Agent WebSocket 连接、命令下发、结果接收、下载包
│   │   ├── scan.py        # 扫描管理 API（新建/停止/恢复/查询）
│   │   ├── feedback.py    # 误报反馈 CRUD
│   │   ├── checkers.py    # Checker 列表 API
│   │   └── auth.py        # 用户认证与管理 API
│   ├── registry.py        # Checker 自动发现与注册
│   ├── analyzers/base.py  # 静态分析器基类
│   └── opencode/          # opencode CLI + LLM API 集成
├── mcp_server/            # MCP Server（Agent opencode 模式本地启动）
├── agent.yaml             # Agent 配置模板
├── run_agent.sh           # Agent 守护进程启动脚本（Linux/macOS）
├── run_agent.bat          # Agent 守护进程启动脚本（Windows）
├── requirements-agent.txt # Agent 最小依赖
├── config.yaml            # 服务端全局配置
├── start.sh               # 服务端一键启动脚本
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
