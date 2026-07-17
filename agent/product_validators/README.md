# 产品漏洞验证方法开发指南

`agent/product_validators/` 是服务端和 Agent 共用的漏洞验证方法目录。每个验证方法占一个一级目录，由 `validator.yaml` 描述适用的产品与验证环境，由 `validator.py` 提供唯一异步入口。

验证方法在 Agent 主进程内执行，不使用验证 worker 子进程，不热加载，也不提供手动同步。开发完成并上传到服务端后，重启服务端刷新产品/环境目录；下次启动扫描、恢复扫描、去误报或漏洞验证任务时，Agent 会先强制同步整个 runtime 并在必要时重启，再执行任务。不要直接修改 Agent 上已安装的副本。

## 1. 目录与 manifest

```text
agent/product_validators/
├── README.md
└── lte_lab/
    ├── validator.yaml
    ├── validator.py
    ├── helpers.py
    └── prompts/
        └── reproduce.md
```

`validator.yaml`：

```yaml
schema_version: 1
product: LTE
validation_environment: 仿真UBBPi板环境
timeout_seconds: 7200
```

- `schema_version`：必填，当前只能为 `1`。
- `product`：必填，后端页面展示的产品名。
- `validation_environment`：必填，只能与本 manifest 的产品成对选择。
- `timeout_seconds`：可选，范围 `1..86400`；不填时使用 Agent 全局验证超时。
- 不接受未知字段。

目录名只能包含字母、数字、点、下划线和连字符。缺文件、manifest 非法，或两个目录声明了相同的产品/环境对时，相关方法会被隔离并从后端目录中排除，不影响其它方法。`validator.py` 导入失败或入口不符合约定时，Agent 会跳过该方法并在控制台记录原因，因此上传前必须完成独立调试。

页面允许产品和验证环境同时留空，表示该扫描不启用漏洞验证；不允许只填写其中一个。服务端启动后读取 manifest，因此新增或修改目录后必须重启服务端。

## 2. 唯一入口与返回值

`validator.py` 必须定义：

```python
async def validate(ctx) -> ValidationResult:
    ...
```

不需要 `__init__.py`、`register(...)` 或注册表调用。不支持同步函数，也不兼容字典、元组等旧返回值。辅助模块应使用相对导入，例如 `from .helpers import build_prompt`。

最小示例：

```python
from agent.vulnerability_validation import ValidationResult


async def validate(ctx) -> ValidationResult:
    await ctx.emit_stdout(
        "验证过程",
        f"从 {ctx.validation_entry_function} 验证到 {ctx.vulnerable_function}",
    )
    return ValidationResult(
        validation_success=True,
        is_problem=True,
        status="verified",
        requires_human_intervention=False,
        summary="验证完成，问题可触发。",
    )
```

`ValidationResult` 字段：

- `validation_success`：流程是否完整执行成功。
- `is_problem`：最终是否认为漏洞真实存在。
- `summary`：页面最终结论。
- `status`：通常为 `verified`、`failed` 或 `cancelled`。
- `requires_human_intervention`：是否仍需人工处理。
- `artifacts`：可选的最终产物列表；实时产物优先用 `ctx.publish_artifact(...)`。
- `validation_code`：可选的验证代码文本。

## 3. `ctx` 输入契约

验证器可以直接读取以下字段：

| 字段 | 含义 |
| --- | --- |
| `ctx.vulnerability_file` | 漏洞源码文件的绝对路径 |
| `ctx.validation_entry_function` | 验证入口函数，即调用链第一个函数 |
| `ctx.vulnerable_function` | 漏洞函数名 |
| `ctx.call_chain` | 从入口到漏洞函数的只读函数名元组 |
| `ctx.vulnerability_type` | 审计过程输出的漏洞类型 |
| `ctx.report_markdown` | 完整 Markdown 漏洞报告 |
| `ctx.project_path` | 项目总目录的绝对路径 |
| `ctx.code_scan_path` | 本次扫描代码路径的绝对路径 |
| `ctx.work_dir` | 当前漏洞的隔离工作目录，OpenCode 文件工具默认可写 |
| `ctx.validator_dir` | 当前验证方法目录 |
| `ctx.report_path` | `report_markdown` 已落盘的路径 |
| `ctx.product` / `ctx.validation_environment` | 当前成对验证目标 |
| `ctx.scan_id` / `ctx.vuln_index` | 扫描与漏洞索引 |
| `ctx.timeout_seconds` | 本次验证整体超时 |
| `ctx.vulnerability` | 完整 `Vulnerability` 模型 |

也可使用：

- `ctx.get_report_markdown()`：返回 Markdown 报告。
- `ctx.get_validation_info()`：返回以上字段及漏洞字典的可序列化快照。
- `ctx.cancelled()`：检查用户是否已经停止验证；纯 Python 长循环必须定期检查。

候选点审计和威胁审计必须输出 `vuln_type`、非空 `call_chain` 和 Markdown `vulnerability_report`。运行时保证调用链至少包含漏洞函数，并把第一个函数作为验证入口。

## 4. OpenCode 调用

验证器与威胁分析、候选点审计使用同一个任务服务，直接调用 `get_opencode_task_service().run_task()`：

```python
from backend.opencode.task_service import OpenCodeTaskSpec, get_opencode_task_service


result = await get_opencode_task_service().run_task(
    OpenCodeTaskSpec(
        task_name="PoC 设计",
        prompt=ctx.report_markdown,
        directory=ctx.project_path,
        required_capability="high",
        timeout_seconds=ctx.timeout_seconds,
        priority=80,
        output_schema=RESULT_SCHEMA,
        writable_paths=[ctx.work_dir],
        on_output=ctx.opencode_output,
        cancel_event=ctx.cancel_event,
    )
)
result.raise_for_status()
payload = result.structured
session_id = result.session_id
```

当前验证执行上下文会自动绑定 `scan_id`、验证元数据、共享 MCP 网关和 `ctx.work_dir` 写权限。验证器不要自行创建 OpenCode workspace、MCP Server 或 CLI 子进程，也不要直接执行 `nga`、`opencode`、`hac` 或 `claude`。

### 同时创建两个任务

两个独立任务使用两个不带 `session_id` 的 `OpenCodeTaskSpec`，通过 `asyncio.gather` 并发提交；实际并发仍受全局模型池和单模型并发限制：

```python
import asyncio

service = get_opencode_task_service()
code_result, exploit_result = await asyncio.gather(
    service.run_task(OpenCodeTaskSpec(
        task_name="代码可达性分析",
        prompt=code_prompt,
        directory=ctx.project_path,
        output_schema=CODE_SCHEMA,
        cancel_event=ctx.cancel_event,
    )),
    service.run_task(OpenCodeTaskSpec(
        task_name="利用条件分析",
        prompt=exploit_prompt,
        directory=ctx.project_path,
        output_schema=EXPLOIT_SCHEMA,
        cancel_event=ctx.cancel_event,
    )),
)
code_result.raise_for_status()
exploit_result.raise_for_status()
```

同一个 `session_id` 表示续写同一会话。不要并发续写同一 session；应按顺序 `await`，因为会话消息具有严格先后关系：

```python
first = (await service.run_task(first_spec)).raise_for_status()
second = await service.run_task(OpenCodeTaskSpec(
    task_name="生成 PoC",
    prompt="根据上一轮结论生成 PoC。",
    directory=ctx.project_path,
    session_id=first.session_id,
    cancel_event=ctx.cancel_event,
))
```

`ctx.opencode_output` 只把模型流打印到 Agent/调试控制台，不进入后端漏洞验证页面。需要页面展示时，由验证器提取阶段性结论后显式调用 `await ctx.emit_stdout(...)`。

## 5. 页面输出、产物和命令

后端页面布局不变，只有以下内容进入中间输出：

- `await ctx.emit_stdout(title, content)` 或单参数形式；
- `await ctx.run_command(...)` 的 stdout/stderr。

普通 `print(...)` 和 OpenCode 输出只进入 Agent 控制台；独立调试时也会显示在当前终端。

发布产物：

```python
artifact_path = ctx.work_dir / "poc.py"
artifact_path.write_text(poc, encoding="utf-8")
await ctx.publish_artifact(
    "poc.py",
    path=artifact_path,
    title="PoC",
    kind="code",
)
```

执行编译器、测试程序或 PoC：

```python
exit_code = await ctx.run_command(
    ["python3", str(artifact_path)],
    cwd=ctx.work_dir,
    timeout=60,
    output_title="PoC 输出",
)
```

`run_command` 不经过 shell，返回退出码；命令超时返回 `124`。用户取消或验证整体结束时会终止该命令的进程树。验证器自行创建的后台进程不受可靠托管，因此不要 daemonize，也不要绕过 `ctx.run_command(...)`。

## 6. 无后端独立调试

独立调试不需要启动 Web 后端，但需要可用的 Agent 配置、OpenCode serve 依赖以及目标项目源码：

```bash
python -m agent.validation_debug \
  --validator agent/product_validators/demo \
  --case agent/product_validators/debug-case.example.json \
  --config agent.yaml
```

调试 case：

```json
{
  "project_path": "/absolute/path/to/project",
  "code_scan_path": "/absolute/path/to/project/src",
  "vulnerability": {
    "file": "src/parser.c",
    "line": 120,
    "function": "parse_payload",
    "call_chain": ["handle_packet", "parse_message", "parse_payload"],
    "vuln_type": "oob",
    "severity": "high",
    "description": "长度字段可导致越界读取",
    "ai_analysis": "完整分析",
    "vulnerability_report": "# 漏洞报告\n\n验证该越界路径。",
    "confirmed": true,
    "ai_verdict": "confirmed"
  },
  "report_markdown": "# 漏洞报告\n\n可选；不填时由漏洞对象生成。"
}
```

默认运行目录为 `~/.opendeephole/vulnerability_validation/debug/<validator>/<run-id>/`。终端显示 `print(...)`、OpenCode 输出、显式中间输出和产物通知，最终结果写入 `validation/vuln-0/result.json`。进程退出码 `0` 表示验证流程成功，`1` 表示流程失败。`Ctrl-C` 会设置与线上相同的取消信号。

## 7. 提交前检查

1. `validator.yaml` 的产品/环境对唯一且字段合法。
2. `validator.py` 只暴露异步 `validate(ctx)`，返回严格 `ValidationResult`。
3. 所有临时文件写入 `ctx.work_dir`，方法自带只读资源放在 `ctx.validator_dir`。
4. 模型调用直接使用共享 `OpenCodeTaskService`；并发独立任务用 `asyncio.gather`，同 session 串行。
5. 页面进度显式 `await ctx.emit_stdout(...)`，产物显式 `await ctx.publish_artifact(...)`。
6. 外部进程只通过 `await ctx.run_command(...)`。
7. 本地 debug case 能完整跑通停止、失败和成功路径。
8. 上传服务端、重启服务端，然后从页面启动任务；Agent runtime 会在任务执行前强制同步。
