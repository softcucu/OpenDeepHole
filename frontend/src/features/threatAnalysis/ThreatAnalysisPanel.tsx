import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type {
  NativeThreatAttackTree,
  NativeThreatHighRiskModule,
  NativeThreatTreeNode,
  NativeThreatValueAsset,
  ScanEvent,
  ThreatAnalysis,
  ThreatAuditTask,
} from "../../types";

interface ThreatAnalysisPanelProps {
  analysis: ThreatAnalysis | null;
  threatAuditTasks: ThreatAuditTask[];
  events: ScanEvent[];
  loading: boolean;
  isDone: boolean;
}

type Tab = "assets" | "modules" | "nodes" | "trees";

export function ThreatAnalysisPanel({
  analysis,
  threatAuditTasks,
  events,
  loading,
  isDone,
}: ThreatAnalysisPanelProps) {
  const [tab, setTab] = useState<Tab>("assets");
  const assets = artifactContent<NativeThreatValueAsset[]>(
    analysis,
    "value_asset_path",
    [],
  );
  const modules = artifactContent<NativeThreatHighRiskModule[]>(
    analysis,
    "high_risk_modules_path",
    [],
  );
  const treeDocument = artifactContent<{ attack_trees: NativeThreatAttackTree[] }>(
    analysis,
    "attack_tree_path",
    { attack_trees: [] },
  );
  const trees = Array.isArray(treeDocument.attack_trees)
    ? treeDocument.attack_trees
    : [];
  const internalNodes = useMemo(
    () => trees.flatMap((tree) => tree.nodes ?? []).filter(
      (node) => node.node_type === "内部节点",
    ),
    [trees],
  );
  const attackPathCount = trees.reduce(
    (total, tree) => total + (tree.attack_paths?.length ?? 0),
    0,
  );

  if (!analysis) {
    return (
      <div className="space-y-4">
        <EmptyState
          text={
            loading
              ? "威胁分析运行中，完成后会展示原生产物。"
              : isDone
                ? "当前扫描未生成威胁分析产物。"
                : "等待威胁分析结果。"
          }
        />
        <ThreatAuditTaskList tasks={threatAuditTasks} />
        <ThreatEventList events={events} />
      </div>
    );
  }

  if (
    !analysis.entrypoint_result
    || analysis.entrypoint_result.result !== true
    || !analysis.artifacts
  ) {
    return (
      <div className="space-y-4">
        <EmptyState text="该扫描使用旧版威胁分析格式，当前版本不再提供兼容展示。" />
        <ThreatAuditTaskList tasks={threatAuditTasks} />
        <ThreatEventList events={events} />
      </div>
    );
  }

  const tabs: Array<{ key: Tab; label: string; count: number }> = [
    { key: "assets", label: "价值资产", count: assets.length },
    { key: "modules", label: "高风险模块", count: modules.length },
    { key: "nodes", label: "内部节点", count: internalNodes.length },
    { key: "trees", label: "攻击树", count: trees.length },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryItem label="价值资产" value={assets.length} />
        <SummaryItem label="高风险模块" value={modules.length} />
        <SummaryItem label="攻击树" value={trees.length} />
        <SummaryItem label="攻击路径" value={attackPathCount} />
      </div>

      <ThreatAuditTaskList tasks={threatAuditTasks} />

      <section className="overflow-hidden rounded-lg border border-slate-700 bg-slate-900/60">
        <div className="flex flex-wrap gap-2 border-b border-slate-800 p-3">
          {tabs.map((item) => (
            <button
              key={item.key}
              type="button"
              onClick={() => setTab(item.key)}
              className={`rounded px-3 py-1.5 text-sm ${
                tab === item.key
                  ? "bg-emerald-500/20 text-emerald-200"
                  : "bg-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              {item.label} · {item.count}
            </button>
          ))}
        </div>
        <div className="p-4">
          {tab === "assets" && <ValueAssets assets={assets} />}
          {tab === "modules" && <HighRiskModules modules={modules} />}
          {tab === "nodes" && <InternalNodes nodes={internalNodes} />}
          {tab === "trees" && <AttackTrees trees={trees} />}
        </div>
      </section>

      <ArtifactPaths analysis={analysis} />
      <ThreatEventList events={events} />
    </div>
  );
}

function artifactContent<T>(
  analysis: ThreatAnalysis | null,
  key: string,
  fallback: T,
): T {
  const artifact = analysis?.artifacts?.[key];
  return artifact && "content" in artifact ? artifact.content as T : fallback;
}

function ValueAssets({ assets }: { assets: NativeThreatValueAsset[] }) {
  if (assets.length === 0) return <EmptyState text="未识别到价值资产。" />;
  return (
    <div className="space-y-3">
      {assets.map((asset, index) => (
        <article
          key={`${asset["资产名"]}-${index}`}
          className="rounded border border-slate-800 bg-slate-950/60 p-4"
        >
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold text-white">{asset["资产名"]}</h3>
            <Pill>{asset["资产类别"]}</Pill>
          </div>
          <p className="mt-2 text-sm text-slate-300">{asset["资产描述"]}</p>
          <Detail label="攻击损失" value={asset["攻击损失"]} />
          <Detail label="判定原因" value={asset["判断为价值资产的原因"]} />
        </article>
      ))}
    </div>
  );
}

function HighRiskModules({ modules }: { modules: NativeThreatHighRiskModule[] }) {
  if (modules.length === 0) return <EmptyState text="未识别到高风险模块。" />;
  return (
    <div className="space-y-3">
      {modules.map((module, index) => {
        const paths = Array.isArray(module["代码目录"])
          ? module["代码目录"]
          : [module["代码目录"]];
        return (
          <article
            key={`${module["模块名称"]}-${index}`}
            className="rounded border border-slate-800 bg-slate-950/60 p-4"
          >
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-semibold text-white">{module["模块名称"]}</h3>
              <Pill>{module["是否外部暴露面"] === "是" ? "外部暴露" : "内部模块"}</Pill>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {paths.filter(Boolean).map((path) => (
                <code key={path} className="rounded bg-slate-800 px-2 py-1 text-xs text-cyan-200">
                  {path}
                </code>
              ))}
            </div>
            <Detail label="面临威胁" value={module["面临威胁"]} />
            <Detail label="判定原因" value={module["判断为高风险模块的原因"]} />
          </article>
        );
      })}
    </div>
  );
}

function InternalNodes({ nodes }: { nodes: NativeThreatTreeNode[] }) {
  if (nodes.length === 0) return <EmptyState text="攻击树中没有内部节点。" />;
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {nodes.map((node, index) => (
        <article
          key={`${node.node_id}-${index}`}
          className="rounded border border-slate-800 bg-slate-950/60 p-4"
        >
          <div className="font-medium text-white">{node.node_name}</div>
          <div className="mt-1 font-mono text-xs text-slate-500">{node.node_id}</div>
          <p className="mt-2 text-sm text-slate-300">{node.description}</p>
          {node.module_name && <Detail label="模块" value={node.module_name} />}
        </article>
      ))}
    </div>
  );
}

function AttackTrees({ trees }: { trees: NativeThreatAttackTree[] }) {
  if (trees.length === 0) return <EmptyState text="未生成攻击树。" />;
  return (
    <div className="space-y-4">
      {trees.map((tree) => (
        <article
          key={tree.tree_id}
          className="rounded border border-slate-800 bg-slate-950/60 p-4"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="font-semibold text-white">{tree.value_asset?.asset_name || "未命名资产"}</h3>
              <div className="mt-1 font-mono text-xs text-slate-500">{tree.tree_id}</div>
            </div>
            <Pill>{tree.value_asset?.asset_category || "未分类"}</Pill>
          </div>
          <p className="mt-2 text-sm text-slate-300">{tree.value_asset?.asset_description}</p>
          <div className="mt-4 space-y-3">
            {(tree.attack_paths ?? []).map((path) => (
              <div key={path.path_id} className="rounded border border-slate-800 p-3">
                <div className="font-medium text-emerald-200">{path.path_name}</div>
                <p className="mt-1 text-sm text-slate-400">{path.path_description}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(path.related_high_risk_modules ?? []).map((module) => (
                    <Pill key={`${path.path_id}-${module.node_id}`}>
                      {module.module_name} · {module.path_role}
                    </Pill>
                  ))}
                </div>
                <div className="mt-3 space-y-2">
                  {(path.attack_patterns ?? []).map((pattern) => (
                    <div key={`${path.path_id}-${pattern.pattern_id}`} className="rounded bg-slate-900 p-3">
                      <div className="text-sm font-medium text-rose-200">
                        {pattern.pattern_id ? `${pattern.pattern_id} · ` : ""}
                        {pattern.pattern_name}
                      </div>
                      <p className="mt-1 text-xs leading-5 text-slate-400">
                        {pattern.association_description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </article>
      ))}
    </div>
  );
}

function ArtifactPaths({ analysis }: { analysis: ThreatAnalysis }) {
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        原生产物
      </summary>
      <div className="space-y-2 border-t border-slate-800 p-4">
        {Object.entries(analysis.artifacts).map(([key, artifact]) => (
          artifact && (
            <div key={key} className="flex flex-wrap gap-2 text-xs">
              <span className="text-slate-500">{key}</span>
              <code className="text-cyan-200">{artifact.path}</code>
            </div>
          )
        ))}
      </div>
    </details>
  );
}

function ThreatAuditTaskList({ tasks }: { tasks: ThreatAuditTask[] }) {
  if (tasks.length === 0) {
    return <EmptyState text="尚未创建按攻击模式拆分的威胁审计任务。" />;
  }
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <h3 className="text-sm font-semibold text-white">威胁审计任务 · {tasks.length}</h3>
      <div className="mt-3 max-h-72 divide-y divide-slate-800 overflow-auto">
        {tasks.map((task) => (
          <div key={task.task_id} className="py-3">
            <div className="flex flex-wrap items-center gap-2">
              <Pill>{auditStatus(task.status)}</Pill>
              <span className="text-sm text-slate-200">{task.method_name || "未命名攻击模式"}</span>
              <span className="text-xs text-slate-500">·</span>
              <span className="text-sm text-slate-400">{task.surface_name || "未命名模块"}</span>
            </div>
            {task.code_path && (
              <div className="mt-1 font-mono text-xs text-cyan-200">{task.code_path}</div>
            )}
            {task.failure_reason && <div className="mt-1 text-xs text-red-300">{task.failure_reason}</div>}
          </div>
        ))}
      </div>
    </section>
  );
}

function ThreatEventList({ events }: { events: ScanEvent[] }) {
  if (events.length === 0) return null;
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        运行日志 · {events.length}
      </summary>
      <div className="max-h-64 divide-y divide-slate-800 overflow-auto border-t border-slate-800 px-4">
        {events.map((event, index) => (
          <div key={`${event.timestamp}-${index}`} className="py-2 text-xs">
            <span className="mr-2 text-slate-600">{event.timestamp}</span>
            <span className="mr-2 text-cyan-300">{event.phase}</span>
            <span className="text-slate-300">{event.message}</span>
          </div>
        ))}
      </div>
    </details>
  );
}

function SummaryItem({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-950/70 px-3 py-2">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-slate-100">{value}</div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="mt-2 text-sm">
      <span className="text-slate-500">{label}：</span>
      <span className="text-slate-300">{value}</span>
    </div>
  );
}

function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
      {children}
    </span>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-5 text-sm text-slate-400">
      {text}
    </div>
  );
}

function auditStatus(value: string): string {
  const labels: Record<string, string> = {
    pending: "待执行",
    queued: "排队中",
    running: "运行中",
    completed: "已完成",
    failed: "失败",
    timeout: "超时",
    no_result: "无结果",
    cancelled: "已取消",
  };
  return labels[value] ?? value;
}
