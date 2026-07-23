# 接入结构

```text
调用方
  └─ await run_threat_analysis(**kwargs)
       └─ runner.py
            ├─ 绑定代码目录、输出目录、Task Agent 配置和本目录 SKILL
            ├─ 在线程中调用同步原生入口
            └─ threat_analysis_harness/run_threat_analysis(...)
```

`runner.py` 是唯一适配层。它动态把嵌入目录加载为原实现期望的顶级包名
`threat_analysis_harness`，并通过 `task_agent.run_sync_component()` 让同步流水线中的
`run_opencode_task()` 安全回到平台所属的异步事件循环。

这条边界保证：

- `threat_analysis_harness/` 可以与上游目录逐文件比较，不含平台补丁；
- 过程返回原生三份 JSON 产物，不依赖后端模型；
- 独立 CLI 与平台调用走同一个异步入口；
- 将来接入其它阶段时，只需复制该阶段实现并在其目录外层提供一个薄异步门面。

平台侧的 `process_artifacts.collect_json_artifacts()` 只在上报时读取 `*_path` 指向的
JSON 并生成透明产物包；它不是威胁分析过程的一部分，也不改变入口返回值。
