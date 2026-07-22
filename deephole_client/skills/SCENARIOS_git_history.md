# git 历史问题挖掘 + 同类变体排查 + 历史/校验匹配 — 可扫描场景

本文档描述迁移自 SecAnt 的三项能力（`deephole_client/git_history.py`、`deephole_client/variant_hunter.py`、
去误报 `history_match` 阶段）所针对的典型场景，便于评估召回与误报边界。

## 1. git 历史问题挖掘（git_history_mine.md）

逐条提交判定「是否安全修复」，并把安全修复抽象成可复用的「问题模式」。

### 命中（security_related=true）

- 修复内存破坏 / 整型溢出 / 越界读写 / UAF / double-free 的提交，例如：
  ```diff
  - memcpy(dst, src, len);
  + if (len > sizeof(dst)) return -EINVAL;
  + memcpy(dst, src, len);
  ```
  → 提炼模式：「外部可控 len 未夹紧上界即用于 memcpy，构造超长 len 触发越界写」（lens=memory）。
- 修复竞态 / TOCTOU、认证绕过 / 降级、注入、加密误用、DoS、信息泄露的提交。

### 不命中（security_related=false）

- 纯功能新增、重构、格式化、文档、构建/CI、依赖升级等无安全语义的提交。
- 仅提交标题含 fix/security 但代码改动与安全无关者（以**改动代码**为准）。

## 2. 同类变体排查（variant_hunt.md）

理解一条历史问题模式的根因后，在全仓搜索**同类但可能未修复**的站点。

### 命中（产出新候选）

- 同一危险原语 / 被调函数在另一处调用，**缺少**历史修复所加的校验/夹紧/判空：
  ```c
  // 历史已修：caller A 在调用前夹紧 len
  // 本站点 caller B 未夹紧即调用同一 helper → 命中
  copy_into(buf, user_len);   // 缺少 user_len <= sizeof(buf) 校验
  ```

### 不命中（不产出）

- 已正确校验 / 已修复 / 不满足相似条件的站点（避免误报淹没结果）。

## 3. 去误报「历史/校验匹配」（fp_review_match.md）

复核候选时优先判断能否对应上历史问题或其它函数的正确校验。

- **match_type=history**：候选与某条历史问题模式同根因 → 直接判 high。
- **match_type=validation**：全仓存在对同一原语把校验做对了的站点，而本候选缺失 → 直接判 high。
- 两类匹配均**跳过三阶段对抗辩论**，并在报告 `match_reference` 中标明对应的修复/校验。
- 无法对应上 → 转入三阶段辩论，论证是否外部可触发：可触发 → high，否则 → low。
