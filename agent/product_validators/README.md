# 产品漏洞验证脚本编写指南

`agent/product_validators/` 用于放置 Agent 本地执行的产品漏洞验证方法。每个验证方法必须使用一个独立的一级目录，Agent 会把该目录作为 Python 包导入，并调用目录入口 `__init__.py` 里的 `register(registry)` 注册产品和验证环境。根目录下的单个 `*.py` 文件不会作为验证方法加载。

修改本目录后，需要在客户端页面点击“同步验证方法”并确认，才能推送到在线 Agent。同步会完整替换 Agent 上与服务端同名的方法目录，因此同名目录中的 Agent 本地修改或额外文件会被覆盖或删除；仅存在于 Agent、服务端没有的其它方法目录会保留。重新点击漏洞验证只会执行 Agent 当前已安装的验证器，不会自动下载或覆盖本目录。

## 基本结构

推荐目录结构如下。目录中可以包含任意数量的 Python 模块、子包、JSON、Markdown、提示词和其它运行资源：

```text
agent/product_validators/
├── README.md
└── lte_lab/
    ├── __init__.py
    ├── validator.py
    ├── helpers.py
    └── prompts/
        └── reproduce.md
```

每个方法目录的 `__init__.py` 需要提供 `register(registry)`，并注册一个同步验证函数。验证函数只接收一个参数 `ctx`，返回 `ValidationResult`。包内代码使用相对导入，避免不同方法目录中的同名模块互相冲突：

```python
from .validator import validate_lte


def register(registry) -> None:
    registry.register(
        "LTE",
        validate_lte,
        validation_environment="仿真UBBPi板环境",
        timeout_seconds=7200,
    )
```

`validator.py` 示例：

```python
from pathlib import Path

from agent.vulnerability_validation import ValidationResult
from .helpers import describe_vulnerability


def validate_lte(ctx) -> ValidationResult:
    report = ctx.get_report_markdown()
    info = ctx.get_validation_info()
    vuln = info["vulnerability"]

    ctx.emit_stdout(
        "验证过程",
        describe_vulnerability(vuln),
    )

    artifact_path = Path(ctx.work_dir) / "validation-notes.md"
    artifact_path.write_text(report, encoding="utf-8")
    ctx.publish_artifact("validation-notes.md", path=artifact_path, title="验证报告", kind="report")

    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=False,
        status="verified",
        summary="验证完成，问题可复现。",
    )
```

`helpers.py` 示例：

```python
def describe_vulnerability(vuln: dict) -> str:
    return (
        f"validating {vuln.get('vuln_type')} at "
        f"{vuln.get('file')}:{vuln.get('line')}"
    )
```

`registry.register(product, func, validation_environment="仿真UBBPi板环境", timeout_seconds=None)` 参数说明：

- `product`：扫描任务选择的产品名，必须和扫描元数据里的产品名一致。
- `func`：同步验证函数，不支持 `async def`。
- `validation_environment`：扫描任务选择的验证环境，必须和扫描元数据里的验证环境一致。旧脚本不传该参数时，会按当前扫描的默认验证环境注册。
- `timeout_seconds`：该产品验证器的整体超时，范围是 1 到 86400 秒。未设置时使用 Agent 全局漏洞验证超时。

## ctx 基础字段

验证函数运行时，`ctx` 会提供当前单个漏洞的上下文。

- `ctx.scan_id`：扫描 ID。
- `ctx.vuln_index`：漏洞在扫描结果中的索引。
- `ctx.product`：当前扫描产品。
- `ctx.validation_environment`：当前扫描选择的验证环境。
- `ctx.vulnerability`：当前漏洞对象。需要字典时优先使用 `ctx.get_validation_info()["vulnerability"]`。
- `ctx.report_markdown`：后端下发的单漏洞 Markdown 报告原文，推荐通过 `ctx.get_report_markdown()` 读取。
- `ctx.work_dir`：该漏洞验证任务的工作目录，通常位于扫描目录下的 `validation/vuln-{idx}`。
- `ctx.validator_dir`：当前验证方法包的一级目录。即使验证函数定义在嵌套子模块中，运行时当前目录也固定为这个方法根目录。
- `ctx.report_path`：Agent 已写入的单漏洞 Markdown 报告路径。
- `ctx.project_path`：项目根目录。可能为空，使用前需要判断。
- `ctx.code_scan_path`：本次代码扫描范围。可能为空，使用前需要判断。
- `ctx.timeout_seconds`：本次验证实际生效的整体超时。

## ctx 方法

### `ctx.get_report_markdown()`

返回后端生成的单漏洞 Markdown 报告。这是验证脚本的主输入，内容和页面下载的单漏洞报告保持一致。需要传给外部工具或 OpenCode 任务时，建议先写入一个明确的文件路径。

```python
report_path = Path(ctx.work_dir) / "vulnerability.md"
report_path.write_text(ctx.get_report_markdown(), encoding="utf-8")
ctx.publish_artifact("vulnerability.md", path=report_path, title="输入报告", kind="report")
```

### `ctx.get_validation_info()`

返回当前验证任务的结构化信息，适合读取路径、产品、超时和漏洞字段。

返回字段包括：

- `scan_id`
- `vuln_index`
- `product`
- `validation_environment`
- `work_dir`
- `validator_dir`
- `report_path`
- `project_path`
- `code_scan_path`
- `timeout_seconds`
- `vulnerability`

`vulnerability` 是漏洞对象的字典形式，常用字段包括 `file`、`line`、`function`、`vuln_type`、`severity`、`description`、`ai_analysis`、`confirmed`、`ai_verdict`。

### `ctx.emit_stdout(title, content)` / `ctx.emit_stdout(text)`

把阶段性输出同步到漏洞验证页面。推荐传入标题和内容：同标题的输出会追加到同一个栏位，不存在的标题会自动创建新栏。旧的单参数写法仍兼容，会写入默认的“中间产出”栏。

验证函数执行期间，脚本自身以及运行期导入的同目录 helper 中的 `print(...)` 只会保留在 Agent 控制台输出，不会同步到漏洞验证页面。需要页面展示的进度必须显式调用 `ctx.emit_stdout(...)`，或者通过 `ctx.run_command(...)` 执行外部命令。

```python
ctx.emit_stdout("验证过程", "STEP 1 running poc generation")
ctx.emit_stdout("验证过程", f"artifact will be saved to {artifact_path}")
ctx.emit_stdout("调试信息", "extra diagnostic text")
```

每个输出栏会被截断保留尾部内容，不要依赖它作为唯一持久化结果。需要页面长期展示的文件或代码应使用 `ctx.publish_artifact(...)`。

### `ctx.publish_artifact(name, content=None, *, title="产物", path=None, kind="artifact")`

发布中间产物或最终产物到漏洞验证页面。同 `title` 的产物会在页面和导出报告中归为一栏。

- `title`：页面展示的产物栏标题。
- `name`：页面展示的产物名。
- `content`：直接发布的文本内容。
- `path`：产物文件路径。未传 `content` 时，运行器会尝试读取该文件内容。
- `kind`：产物类型，常用值是 `artifact`、`report`、`code`、`validation_code`。

当 `kind` 为 `code` 或 `validation_code` 时，内容会同步到页面的验证代码展示区。

```python
ctx.publish_artifact("poc.py", "print('poc')", title="PoC", kind="code")
ctx.publish_artifact("step-1.md", path=step_1_artifact, title="阶段产物", kind="artifact")
```

同 `title`、同名且同 `kind` 的产物会被新内容替换。产物内容会被截断保留尾部内容，超大文件应保存摘要或关键片段。

### `ctx.run_command(command, *, cwd=None, timeout=None, output_title=None)`

执行外部命令，并把 stdout 和 stderr 合并同步到 `ctx.emit_stdout(...)`。`output_title` 可指定命令输出进入哪个页面栏，不传时进入默认“中间产出”栏。返回进程退出码。

`run_command` 仅用于编译器、测试程序、PoC 等普通外部命令。不得用它启动 `nga`、`opencode`、`claude` 或 `hac`；这类命令返回 `126`，模型任务必须使用下面的 `ctx.run_opencode_task(...)`。

注意事项：

- `command` 使用参数列表，不要拼接成单个 shell 字符串。
- `cwd` 未传时默认使用 `ctx.validator_dir`，也就是当前验证脚本所在目录。
- `output_title` 未传时会使用默认“中间产出”栏；建议长流程显式传入“命令输出”或阶段名称。
- 运行器会给子进程合并当前 PATH、Windows 用户/系统 PATH 和常见工具目录，例如 `%APPDATA%\npm`、`%LOCALAPPDATA%\pnpm`、`%LOCALAPPDATA%\Volta\bin`、`%USERPROFILE%\scoop\shims`、`%ProgramData%\chocolatey\bin`。
- `timeout` 是单条命令超时。整体验证仍受 `ctx.timeout_seconds` 限制。
- 命令超时时返回 `124`。
- 直接执行 AI CLI 时返回 `126`，并提示改用统一 OpenCode 任务接口。
- 用户停止验证时，运行器会终止正在执行的命令进程树，并返回负数退出码或已结束进程的退出码。

### `ctx.run_opencode_task(...)`

通过 Agent 父进程的统一 OpenCode 队列执行模型任务。验证 worker 不创建 CLI 子进程；模型选择、优先级、执行超时、权限、MCP、SKILL、JSON Schema 和 session 都由公共组件管理。

```python
result = ctx.run_opencode_task(
    task_name="PoC 设计",
    prompt="根据漏洞报告设计验证步骤，最终只返回 JSON。",
    required_capability="high",       # low | medium | high
    directory=ctx.project_path,
    mcp_tools=["view_function_code"],
    skills=["validation-poc"],
    timeout_seconds=ctx.timeout_seconds,
    priority=80,                       # 1..100，数值越大越优先
    output_schema={
        "type": "object",
        "properties": {"content": {"type": "string"}},
        "required": ["content"],
        "additionalProperties": False,
    },
    permissions=[{"permission": "edit", "pattern": "*", "action": "deny"}],
    session_id=None,
)
session_id = result["session_id"]
# structured 是父进程从普通回复文本中本地提取的便利值。
content = result["structured"]["content"]
```

后续阶段把返回的 `session_id` 再传入，即可在同一 OpenCode session 中追加 prompt。session 的运行目录固定不能更换；每次追加仍可独立指定模型能力、MCP 工具、SKILL、权限和输出 Schema。任务超时只从真正获得模型并开始执行时计算，排队时间不计入单次 OpenCode 执行超时，但仍受验证流程的整体超时约束。

验证父进程会按需把当前扫描的 `code_index.db` 注册到共享 MCP 网关，并自动在 prompt 前补充 deephole-code 所需的 `project_id`。按名称选择的 SKILL 会从验证工作区和任务 `directory` 下的 `.opencode/skills`、`.agents/skills` 或 `skills` 目录查找；也可传入 SKILL 目录或 `SKILL.md` 的绝对路径。

### `ctx.cancelled()`

判断用户是否停止了当前漏洞验证。纯 Python 长循环必须周期性检查它，并尽快返回 `status="cancelled"`。

```python
for item in work_items:
    if ctx.cancelled():
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="cancelled",
            summary="validation cancelled",
        )
    run_one_step(item)
```

外部命令优先通过 `ctx.run_command(...)` 执行，因为它已经处理了停止和超时。整体验证运行在独立 worker 进程中；用户点击停止或整体验证超时时，Agent 会在 Linux 上终止 worker 进程组，在 Windows 上通过 `taskkill /T /F` 终止 worker 进程树，覆盖验证函数直接启动的普通子进程。脚本如果主动 daemonize、脱离当前进程树或复用外部既有服务，运行器只做 best-effort，不会按进程名清理可能属于其它任务的无关进程。

## 返回结果

新脚本应优先返回 `ValidationResult`。

```python
ValidationResult(
    validation_success=True,
    is_problem=True,
    summary="验证成功，PoC 能触发目标问题。",
    status="verified",
    requires_human_intervention=False,
    artifacts=[],
    validation_code="",
)
```

字段含义：

- `validation_success`：验证流程是否成功完成。工具缺失、超时、步骤失败时应为 `False`。
- `is_problem`：验证结论是否认为原漏洞是真问题。
- `summary`：最终结论，会展示在验证输出区域。
- `status`：最终状态，常用值是 `verified`、`failed`、`timeout`、`cancelled`。
- `requires_human_intervention`：是否需要人工继续判断或操作。
- `artifacts`：一次性附加的产物列表。长流程中更推荐用 `ctx.publish_artifact(...)` 实时发布。
- `validation_code`：验证代码内容，会展示在验证代码区域。

运行器也兼容字典、元组和带同名属性的对象返回值，但这只是兼容旧脚本。新脚本不要依赖这些兼容形态。

## 路径和产物建议

- 验证函数运行时当前目录是 `ctx.validator_dir`。脚本目录下的 `input/input.json` 可直接用 `open("input/input.json", encoding="utf-8")` 读取。
- 方法目录是独立 Python 包；同目录辅助文件使用 `from . import helper`，子模块使用 `from .helpers import name`，嵌套子包继续使用包内相对导入。
- 普通中间文件优先写入 `ctx.work_dir`，它是当前漏洞验证任务的隔离工作目录。
- OpenCode 任务需要读取项目源码时，可以使用 `ctx.project_path` 作为 `directory`，但必须先判断它是否为空。
- 如果验证只针对本次扫描范围，优先参考 `ctx.code_scan_path`。
- 传给外部工具的漏洞输入建议来自 `ctx.get_report_markdown()`，不要重新拼一个第二格式。
- 每个重要阶段都用 `print(...)` 写 Agent 控制台诊断；需要漏洞验证页面可见的开始、结束、失败和重试信息必须调用 `ctx.emit_stdout("标题", "内容")`。
- 每个需要页面保留的报告、PoC、日志摘要或验证代码都用 `ctx.publish_artifact(..., title="标题")` 发布。

## OpenCode 多阶段验证建议

`demo/__init__.py` 展示了一个四阶段 OpenCode 验证模板：读取漏洞 Markdown，按 STEP 1 到 STEP 4 通过 `ctx.run_opencode_task(...)` 串行执行，并复用同一个 session。模型按 JSON Schema 约束回复普通 JSON 文本，父进程本地提取后由 Python 写入 `.opendeephole/vulnerability_validation/{scan_id}/vuln-{idx}/`，避免依赖模型直接写文件。

多阶段流程建议遵守以下规则：

- 每个 STEP 开始前调用 `ctx.cancelled()`。
- 每个 STEP 开始、失败重试、成功完成都调用 `ctx.emit_stdout("验证过程", ...)`。
- 每个 STEP 产物生成后调用 `ctx.publish_artifact(..., title="阶段产物")`。
- 模型阶段统一用 `ctx.run_opencode_task(...)`；编译、运行 PoC 等非模型命令才使用 `ctx.run_command(...)`。
- 某个必需 STEP 没有产物时，应返回 `validation_success=False`，`requires_human_intervention=True`，并在 `summary` 写清楚缺失的 STEP 和产物路径。
