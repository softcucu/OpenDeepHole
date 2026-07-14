import { useEffect, useMemo, useState } from "react";
import type {
  ScanEvent,
  ThreatAnalysis,
  ThreatAsset,
  ThreatAttackTree,
  ThreatAttackTreeNode,
  ThreatAuditTask,
  ThreatCodePathMapping,
  ThreatRisk,
} from "../../types";

interface ThreatAnalysisPanelProps {
  analysis: ThreatAnalysis | null;
  threatAuditTasks: ThreatAuditTask[];
  events: ScanEvent[];
  loading: boolean;
  isDone: boolean;
}

export function ThreatAnalysisPanel({
  analysis,
  threatAuditTasks,
  events,
  loading,
  isDone,
}: ThreatAnalysisPanelProps) {
  const surfaceCount = analysis?.attack_trees.reduce(
    (count, tree) => count + tree.nodes.filter((node) => node.node_type === "surface").length,
    0,
  ) ?? 0;
  const methodCount = analysis?.attack_trees.reduce(
    (count, tree) => count + tree.nodes.filter((node) => node.node_type === "method").length,
    0,
  ) ?? 0;
  const externalInterfaceCount = analysis?.high_risk_external_interfaces?.length ?? 0;
  const attackPathCount = analysis?.attack_paths?.length ?? 0;
  const mappingBySurface = useMemo(() => {
    const out = new Map<string, ThreatCodePathMapping>();
    for (const mapping of analysis?.code_path_mappings ?? []) {
      if (mapping.surface_node_id) out.set(mapping.surface_node_id, mapping);
    }
    return out;
  }, [analysis]);

  if (!analysis) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-slate-700 bg-slate-900/70 p-6">
          <div className="flex items-center gap-3">
            {loading && <div className="h-4 w-4 rounded-full border-2 border-emerald-400/30 border-t-emerald-300 animate-spin" />}
            <div>
              <h2 className="text-base font-semibold text-white">
                {loading ? "威胁分析运行中" : isDone ? "未生成威胁分析结果" : "等待威胁分析结果"}
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                {isDone ? "当前扫描没有可展示的 res.json 结果。" : "攻击路径写入后会实时显示关键资产、攻击目标和攻击树。"}
              </p>
            </div>
          </div>
        </div>
        <ThreatAuditTaskList tasks={threatAuditTasks} />
        <ThreatEventList events={events} />
      </div>
    );
  }

  if (analysis.assets.length === 0) {
    return (
      <div className="space-y-4">
        <ThreatSummaryStrip
          analysis={analysis}
          surfaceCount={surfaceCount}
          methodCount={methodCount}
          externalInterfaceCount={externalInterfaceCount}
          attackPathCount={attackPathCount}
        />
        <ThreatAuditTaskList tasks={threatAuditTasks} />
        <EmptyState text="res.json 中未包含关键资产。" />
        <ThreatEventList events={events} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <ThreatSummaryStrip
        analysis={analysis}
        surfaceCount={surfaceCount}
        methodCount={methodCount}
        externalInterfaceCount={externalInterfaceCount}
        attackPathCount={attackPathCount}
      />
      <ThreatAuditTaskList tasks={threatAuditTasks} />
      <div className="space-y-4">
        {analysis.assets.map((asset, index) => (
          <ThreatAssetCard
            key={asset.asset_id || `${asset.name}-${index}`}
            asset={asset}
            trees={analysis.attack_trees.filter((tree) => tree.asset_id === asset.asset_id)}
            mappingBySurface={mappingBySurface}
          />
        ))}
      </div>
      <ThreatEventList events={events} />
    </div>
  );
}

function threatAuditStatusLabel(status: string): string {
  if (status === "pending") return "待创建";
  if (status === "queued") return "排队中";
  if (status === "running") return "运行中";
  if (status === "completed") return "已完成";
  if (status === "timeout") return "超时";
  if (status === "no_result") return "无结果";
  if (status === "cancelled") return "已取消";
  if (status === "failed") return "失败";
  return status || "未知";
}

function threatAuditStatusClass(status: string): string {
  if (status === "completed") return pillClass("success");
  if (status === "running") return pillClass("running");
  if (status === "queued" || status === "pending") return pillClass("queued");
  if (status === "failed" || status === "timeout" || status === "no_result" || status === "cancelled") return pillClass("failure");
  return pillClass("");
}

function pillClass(status: string): string {
  const base = "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium";
  if (status === "success") return `${base} border-emerald-500/40 bg-emerald-500/10 text-emerald-200`;
  if (status === "running") return `${base} border-cyan-500/40 bg-cyan-500/10 text-cyan-200`;
  if (status === "queued") return `${base} border-amber-500/40 bg-amber-500/10 text-amber-200`;
  if (status === "failure") return `${base} border-red-500/40 bg-red-500/10 text-red-200`;
  return `${base} border-slate-700 bg-slate-800 text-slate-300`;
}

function ThreatAuditTaskList({ tasks }: { tasks: ThreatAuditTask[] }) {
  if (tasks.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm font-semibold text-white">威胁审计任务</div>
        <div className="mt-1 text-sm text-slate-500">威胁分析生成攻击面、攻击方式和代码路径后会创建独立审计任务。</div>
      </div>
    );
  }
  const completed = tasks.filter((task) => task.status === "completed").length;
  const running = tasks.filter((task) => task.status === "running").length;
  const queued = tasks.filter((task) => task.status === "queued" || task.status === "pending").length;
  const failed = tasks.length - completed - running - queued;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-white">威胁审计任务</div>
          <div className="mt-1 text-xs text-slate-500">
            {tasks.length} 个任务 · 已完成 {completed} · 运行中 {running} · 排队 {queued} · 异常 {failed}
          </div>
        </div>
      </div>
      <div className="mt-3 max-h-72 overflow-auto divide-y divide-slate-800">
        {tasks.map((task) => (
          <div key={task.task_id} className="py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className={threatAuditStatusClass(task.status)}>{threatAuditStatusLabel(task.status)}</span>
              <span className="text-sm font-medium text-slate-100">{task.surface_name || task.surface_node_id || "未标记攻击面"}</span>
              <span className="text-xs text-slate-500">/</span>
              <span className="text-sm text-slate-300">{task.method_name || task.method_node_id || "未标记攻击方式"}</span>
            </div>
            <div className="mt-1 font-mono text-xs text-slate-400 truncate">{task.code_path}</div>
            {(task.code_paths?.length ?? 0) > 1 && (
              <div className="mt-1 text-xs text-slate-500">关联路径：{task.code_paths?.length} 个</div>
            )}
            {task.code_path_description && (
              <div className="mt-1 text-xs text-slate-500 line-clamp-2">{task.code_path_description}</div>
            )}
            {(task.result_vuln_indexes?.length ?? 0) > 0 && (
              <div className="mt-1 text-xs text-cyan-300">结果：{task.result_vuln_indexes?.map((idx) => `#${idx}`).join(", ")}</div>
            )}
            {task.failure_reason && task.status !== "completed" && (
              <div className="mt-1 text-xs text-red-300 line-clamp-2">{task.failure_reason}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatSummaryStrip({
  analysis,
  surfaceCount,
  methodCount,
  externalInterfaceCount,
  attackPathCount,
}: {
  analysis: ThreatAnalysis;
  surfaceCount: number;
  methodCount: number;
  externalInterfaceCount: number;
  attackPathCount: number;
}) {
  const sourceCount = analysis.sources.repositories.length + analysis.sources.documents.length;
  const isStreaming = analysis.analysis_id.startsWith("STREAMING-ATA-");
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      {isStreaming && (
        <div className="mb-3 inline-flex items-center gap-2 rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-xs font-medium text-cyan-200">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-300" />
          实时攻击树
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <ThreatSummaryItem label="关键资产" value={analysis.assets.length} />
        <ThreatSummaryItem label="攻击目标" value={analysis.attack_trees.length} />
        <ThreatSummaryItem label="高风险接口" value={externalInterfaceCount} />
        <ThreatSummaryItem label="攻击路径" value={attackPathCount} />
        <ThreatSummaryItem label="攻击面" value={surfaceCount} />
        <ThreatSummaryItem label="攻击方式" value={methodCount} />
      </div>
      {(analysis.analysis_id || analysis.updated_at || analysis.sources.product_mcp_name) && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500">
          {analysis.analysis_id && <span>分析 ID：{analysis.analysis_id}</span>}
          {analysis.updated_at && <span>更新时间：{new Date(analysis.updated_at).toLocaleString()}</span>}
          <span>输入来源：{sourceCount}</span>
          {analysis.sources.product_mcp_name && (
            <span>
              产品 MCP：{analysis.sources.product_mcp_name}
              {analysis.sources.mcp_available ? "（可用）" : "（未检测到）"}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatSummaryItem({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-950/70 px-3 py-2">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-slate-100">{value}</div>
    </div>
  );
}

function ThreatAssetCard({
  asset,
  trees,
  mappingBySurface,
}: {
  asset: ThreatAsset;
  trees: ThreatAttackTree[];
  mappingBySurface: Map<string, ThreatCodePathMapping>;
}) {
  const [expandedTreeId, setExpandedTreeId] = useState<string | null>(trees[0]?.tree_id ?? null);
  const riskById = useMemo(() => new Map(asset.risks.map((risk) => [risk.risk_id, risk])), [asset.risks]);
  const treeIdsKey = trees.map((tree) => tree.tree_id).join("\u0000");
  useEffect(() => {
    setExpandedTreeId((current) => {
      if (current && trees.some((tree) => tree.tree_id === current)) return current;
      return trees[0]?.tree_id ?? null;
    });
  }, [treeIdsKey]);
  const expandedTree = trees.find((tree) => tree.tree_id === expandedTreeId) ?? null;

  return (
    <section className="rounded-lg border border-slate-700 bg-slate-900/60">
      <div className="border-b border-slate-800 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <h2 className="break-words text-lg font-semibold text-white">{asset.name || asset.asset_id || "未命名资产"}</h2>
              <span className={`rounded border px-2 py-0.5 text-xs ${criticalityClass(asset.criticality)}`}>
                {criticalityLabel(asset.criticality)}
              </span>
              <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
                {assetTypeLabel(asset.asset_type)}
              </span>
            </div>
            {asset.description && <p className="max-w-4xl text-sm leading-6 text-slate-400">{asset.description}</p>}
          </div>
          <div className="rounded border border-slate-800 bg-slate-950/80 px-3 py-2 text-right">
            <div className="text-xs text-slate-500">风险</div>
            <div className="text-base font-semibold text-slate-100">{asset.risks.length}</div>
          </div>
        </div>
      </div>

      <div className="space-y-3 p-4">
        {asset.risks.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {asset.risks.map((risk, index) => (
              <RiskPill key={risk.risk_id || `${risk.name}-${index}`} risk={risk} />
            ))}
          </div>
        )}

        {trees.length === 0 ? (
          <EmptyState text="该资产暂无攻击目标。" />
        ) : (
          <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
            {trees.map((tree) => {
              const active = tree.tree_id === expandedTreeId;
              const risk = riskById.get(tree.risk_id);
              return (
                <button
                  key={tree.tree_id || tree.attack_goal}
                  type="button"
                  onClick={() => setExpandedTreeId(active ? null : tree.tree_id)}
                  className={`rounded-lg border p-3 text-left transition-colors ${
                    active
                      ? "border-emerald-500/50 bg-emerald-500/10"
                      : "border-slate-800 bg-slate-950/70 hover:border-slate-600 hover:bg-slate-800/70"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="mb-1 text-xs font-medium text-slate-500">攻击目标</div>
                      <div className="break-words text-sm font-semibold text-slate-100">
                        {tree.attack_goal || rootGoalName(tree) || tree.tree_id || "未命名攻击目标"}
                      </div>
                      {risk && <div className="mt-1 text-xs text-slate-400">关联风险：{risk.name || risk.risk_id}</div>}
                    </div>
                    <svg
                      className={`mt-0.5 h-4 w-4 shrink-0 text-slate-400 transition-transform ${active ? "rotate-90" : ""}`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </button>
              );
            })}
          </div>
        )}

        {expandedTree && (
          <AttackTreeGraph
            tree={expandedTree}
            risk={riskById.get(expandedTree.risk_id) ?? null}
            mappingBySurface={mappingBySurface}
          />
        )}
      </div>
    </section>
  );
}

function RiskPill({ risk }: { risk: ThreatRisk }) {
  return (
    <span className="inline-flex max-w-full items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs text-amber-100">
      <span className="shrink-0 text-amber-300">{securityPropertyLabel(risk.security_property)}</span>
      <span className="truncate text-slate-200">{risk.name || risk.risk_id || "未命名风险"}</span>
    </span>
  );
}

function AttackTreeGraph({
  tree,
  risk,
  mappingBySurface,
}: {
  tree: ThreatAttackTree;
  risk: ThreatRisk | null;
  mappingBySurface: Map<string, ThreatCodePathMapping>;
}) {
  const nodeMap = useMemo(() => new Map(tree.nodes.map((node) => [node.node_id, node])), [tree.nodes]);
  const childMap = useMemo(() => {
    const out = new Map<string, ThreatAttackTreeNode[]>();
    for (const node of tree.nodes) {
      if (!node.parent_id) continue;
      const list = out.get(node.parent_id) ?? [];
      list.push(node);
      out.set(node.parent_id, list);
    }
    for (const list of out.values()) list.sort(compareThreatNodeOrder);
    return out;
  }, [tree.nodes]);
  const root = nodeMap.get(tree.root_node_id)
    ?? tree.nodes.find((node) => node.node_type === "goal" && !node.parent_id)
    ?? tree.nodes.find((node) => node.node_type === "goal")
    ?? null;
  const domains = root
    ? (childMap.get(root.node_id) ?? []).filter((node) => node.node_type === "domain")
    : tree.nodes.filter((node) => node.node_type === "domain").sort(compareThreatNodeOrder);

  return (
    <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-4">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-200">
          {tree.tree_id || "攻击树"}
        </span>
        {risk && (
          <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-xs text-slate-300">
            {risk.name || risk.risk_id}
          </span>
        )}
      </div>
      <div className="overflow-x-auto pb-1">
        <div className="min-w-[980px]">
          <div className="grid grid-cols-[230px_1fr] gap-4">
            <ThreatNodeBox node={root} fallback={tree.attack_goal || "攻击目标"} />
            <div className="space-y-4 border-l border-emerald-500/20 pl-4">
              {domains.length === 0 ? (
                <EmptyState text="攻击树中暂无攻击域节点。" />
              ) : (
                domains.map((domain) => (
                  <DomainBranch
                    key={domain.node_id}
                    domain={domain}
                    childMap={childMap}
                    mappingBySurface={mappingBySurface}
                  />
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function DomainBranch({
  domain,
  childMap,
  mappingBySurface,
}: {
  domain: ThreatAttackTreeNode;
  childMap: Map<string, ThreatAttackTreeNode[]>;
  mappingBySurface: Map<string, ThreatCodePathMapping>;
}) {
  const surfaces = (childMap.get(domain.node_id) ?? []).filter((node) => node.node_type === "surface");
  return (
    <div className="grid grid-cols-[220px_1fr] gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <ThreatNodeBox node={domain} fallback="攻击域" />
      <div className="space-y-3 border-l border-slate-800 pl-3">
        {surfaces.length === 0 ? (
          <EmptyState text="暂无攻击面。" />
        ) : (
          surfaces.map((surface) => (
            <SurfaceBranch
              key={surface.node_id}
              surface={surface}
              methods={(childMap.get(surface.node_id) ?? []).filter((node) => node.node_type === "method")}
              mapping={mappingBySurface.get(surface.node_id) ?? null}
            />
          ))
        )}
      </div>
    </div>
  );
}

function SurfaceBranch({
  surface,
  methods,
  mapping,
}: {
  surface: ThreatAttackTreeNode;
  methods: ThreatAttackTreeNode[];
  mapping: ThreatCodePathMapping | null;
}) {
  return (
    <div className="grid grid-cols-[250px_1fr] gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div>
        <ThreatNodeBox node={surface} fallback="攻击面" />
        {(mapping?.code_paths.length ?? 0) > 0 && (
          <div className="mt-2 space-y-1">
            {mapping!.code_paths.map((item, index) => (
              <div key={`${item.path}-${index}`} className="rounded border border-slate-800 bg-slate-950 px-2 py-1">
                <div className="break-all font-mono text-xs text-cyan-200">{item.path}</div>
                {item.description && <div className="mt-0.5 text-xs text-slate-500">{item.description}</div>}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="grid grid-cols-1 gap-2 2xl:grid-cols-2">
        {methods.length === 0 ? (
          <EmptyState text="暂无攻击方式。" />
        ) : (
          methods.sort(compareThreatNodeOrder).map((method) => (
            <ThreatMethodCard key={method.node_id} method={method} />
          ))
        )}
      </div>
    </div>
  );
}

function ThreatNodeBox({ node, fallback }: { node: ThreatAttackTreeNode | null; fallback: string }) {
  const type = node?.node_type || "goal";
  return (
    <div className={`rounded-lg border px-3 py-2 ${threatNodeClass(type)}`}>
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium opacity-80">{threatNodeLabel(type)}</span>
        {type === "surface" && node?.surface_type && (
          <span className="rounded border border-current px-1.5 py-0.5 text-[11px] opacity-80">
            {surfaceTypeLabel(node.surface_type)}
          </span>
        )}
      </div>
      <div className="break-words text-sm font-semibold">{node?.name || fallback}</div>
      {(node?.basis.length ?? 0) > 0 && (
        <div className="mt-2 space-y-1 text-xs opacity-80">
          {node!.basis.slice(0, 3).map((item, index) => (
            <div key={`${item}-${index}`} className="break-words">{item}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function ThreatMethodCard({ method }: { method: ThreatAttackTreeNode }) {
  return (
    <div className="rounded-lg border border-rose-500/25 bg-rose-500/10 px-3 py-2 text-rose-50">
      <div className="mb-1 text-xs font-medium text-rose-200">攻击方式</div>
      <div className="break-words text-sm font-semibold">{method.name || method.node_id || "未命名攻击方式"}</div>
      {(method.preconditions?.length ?? 0) > 0 && (
        <div className="mt-2 space-y-1 text-xs text-rose-100/80">
          {method.preconditions!.slice(0, 3).map((item, index) => (
            <div key={`${item}-${index}`} className="break-words">{item}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function ThreatEventList({ events }: { events: ScanEvent[] }) {
  if (events.length === 0) {
    return <EmptyState text="暂无威胁分析日志" />;
  }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <div className="mb-3 text-sm font-semibold text-white">威胁分析日志</div>
      <div className="max-h-80 space-y-2 overflow-auto">
        {events.map((event, index) => (
          <div key={`${event.timestamp}-${index}`} className="rounded border border-slate-800 bg-slate-950/70 px-3 py-2">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : ""}</span>
              <span>{event.phase}</span>
            </div>
            <div className="mt-1 whitespace-pre-wrap break-words text-sm text-slate-300">{event.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6 text-center text-sm text-slate-500">
      {text}
    </div>
  );
}

function compareThreatNodeOrder(a: ThreatAttackTreeNode, b: ThreatAttackTreeNode): number {
  const orderDelta = (a.order || 0) - (b.order || 0);
  if (orderDelta !== 0) return orderDelta;
  return (a.name || a.node_id).localeCompare(b.name || b.node_id);
}

function rootGoalName(tree: ThreatAttackTree): string {
  return tree.nodes.find((node) => node.node_id === tree.root_node_id)?.name
    || tree.nodes.find((node) => node.node_type === "goal")?.name
    || "";
}

function criticalityLabel(value: string): string {
  return {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  }[value] ?? (value || "Medium");
}

function criticalityClass(value: string): string {
  return {
    critical: "border-red-500/40 bg-red-500/10 text-red-200",
    high: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    medium: "border-cyan-500/40 bg-cyan-500/10 text-cyan-200",
    low: "border-slate-600 bg-slate-800 text-slate-300",
  }[value] ?? "border-slate-600 bg-slate-800 text-slate-300";
}

function assetTypeLabel(value: string): string {
  return {
    service: "服务",
    data: "数据",
    credential: "凭据",
    privilege: "权限",
    software: "软件",
    configuration: "配置",
    key: "密钥",
    device: "设备",
    other: "其他",
  }[value] ?? (value || "其他");
}

function securityPropertyLabel(value: string): string {
  return {
    confidentiality: "机密性",
    integrity: "完整性",
    availability: "可用性",
    authenticity: "真实性",
    authorization: "授权",
    accountability: "可审计",
  }[value] ?? (value || "风险");
}

function surfaceTypeLabel(value: string): string {
  return {
    protocol: "协议",
    api: "API",
    interface: "接口",
    service: "服务",
    port: "端口",
    file: "文件",
    message: "消息",
    configuration: "配置",
    command: "命令",
    package: "软件包",
    physical: "物理",
    other: "其他",
  }[value] ?? (value || "其他");
}

function threatNodeLabel(value: string): string {
  return {
    goal: "攻击目标",
    domain: "攻击域",
    surface: "攻击面",
    method: "攻击方式",
  }[value] ?? (value || "节点");
}

function threatNodeClass(value: string): string {
  return {
    goal: "border-emerald-500/40 bg-emerald-500/10 text-emerald-50",
    domain: "border-blue-500/35 bg-blue-500/10 text-blue-50",
    surface: "border-cyan-500/35 bg-cyan-500/10 text-cyan-50",
    method: "border-rose-500/35 bg-rose-500/10 text-rose-50",
  }[value] ?? "border-slate-700 bg-slate-900 text-slate-100";
}
