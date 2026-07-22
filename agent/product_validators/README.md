# 产品漏洞验证方法

每个验证方法占一个一级目录，并包含：

```text
<method>/
├── validator.yaml
└── validator.py
```

平台入口固定为：

```python
async def validate(**kwargs) -> ValidationResult:
    ...
```

平台只调用 `validate(**kwargs)`。验证方法需要模型时直接调用 `task_agent.run_opencode_task()`；平台会提前绑定后端配置、项目目录、漏洞工作目录、MCP、输出回调和取消信号。

demo 额外提供一个轻量 `main()`：它手工构造示例实际使用的 kwargs，并由 `run_opencode_task()` 从组件独立 YAML 自举 OpenCode。该入口不依赖已删除的 `agent.validation_debug`，也不会加载完整 manifest 或模拟平台队列。

完整的 manifest、kwargs、返回值和 OpenCode 调用约定见 [漏洞验证方法](../../docs/vulnerability_validation.md)。
