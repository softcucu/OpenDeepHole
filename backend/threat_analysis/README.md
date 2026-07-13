# Threat Analysis

威胁分析后端代码集中在本目录，扫描流程只依赖 `ThreatAnalysisImplementation` 接口。

## 配置

```yaml
threat_analysis:
  enabled: true
  implementation: "attack_tree"
```

`attack_tree` 是默认实现，沿用内置 `attack-tree-threat-analysis.md` 和 `res.json` 输出格式。

## 新增实现

1. 新建实现类，满足 `backend.threat_analysis.base.ThreatAnalysisImplementation`。
2. 在 `backend/threat_analysis/registry.py` 注册实现 ID。
3. 将 `threat_analysis.implementation` 改为新的实现 ID。

## 单独运行

```bash
python -m backend.threat_analysis.cli --project /path/to/project --implementation attack_tree
```
