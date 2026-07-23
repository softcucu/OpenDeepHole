# Threat Analysis Feature

威胁分析前端代码集中在本目录：

- `api.ts`：威胁分析结果请求，复用全局鉴权和公开扫描访问逻辑。
- `ThreatAnalysisPanel.tsx`：独立面板组件，只通过 props 接收数据。
- `index.ts`：feature 对外出口。

面板直接读取后端保存的原生 artifact bundle，不再依赖旧版归一化
`ThreatAnalysis` Schema，也不在 `ScanStatus.tsx` 中复制实现专属字段。

独立使用：

```tsx
import { ThreatAnalysisPanel, getScanThreatAnalysis } from "../features/threatAnalysis";
```

扫描页只负责加载数据和处理 SSE，攻击树展示细节不再放在 `ScanStatus.tsx`。
