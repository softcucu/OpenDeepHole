import { useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { createSkill, getAgents, getCheckerCatalog, getSkillCreateJob, importSkill } from "../api/client";
import type { AgentInfo, CheckerCatalogItem, SkillCreateJob } from "../types";

interface Props {
  onBack: () => void;
}

export default function CheckerCatalogPage({ onBack }: Props) {
  const [mode, setMode] = useState<"catalog" | "create">("catalog");
  const [items, setItems] = useState<CheckerCatalogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeChecker, setActiveChecker] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      const next = await getCheckerCatalog();
      setItems(next);
      setActiveChecker((current) => current ?? next[0]?.name ?? null);
    } catch (err: any) {
      setError(err.response?.data?.detail || "加载 SKILL 列表失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const selected = useMemo(() => {
    if (!activeChecker) return null;
    return items.find((item) => item.name === activeChecker) ?? null;
  }, [items, activeChecker]);

  const handleImported = async (name: string) => {
    setMode("catalog");
    setActiveChecker(name);
    await refresh();
  };

  if (mode === "create") {
    return (
      <SkillCreatePage
        onBack={() => setMode("catalog")}
        onImported={handleImported}
      />
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <div className="bg-slate-900/90 border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              &larr; 返回
            </button>
            <div>
              <h1 className="text-lg font-bold text-white">SKILL市场</h1>
              <p className="text-sm text-slate-400 mt-0.5">
                查看当前可用 SKILL 的检测范围和使用说明
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMode("create")}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg border border-blue-500/60 transition-colors"
            >
              在线创建
            </button>
            <button
              onClick={refresh}
              className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
            >
              刷新
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 px-6 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-6 h-6 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="border border-red-500/30 bg-red-500/10 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        ) : (
          <div className="max-w-7xl mx-auto grid grid-cols-1 xl:grid-cols-[24rem_1fr] gap-5">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  SKILL 列表
                </h2>
                <span className="text-xs text-slate-500">共 {items.length} 个</span>
              </div>
              <div className="space-y-2">
                {items.filter(item => !item.user_created).map((item) => (
                  <CheckerListItem
                    key={item.name}
                    item={item}
                    active={item.name === activeChecker}
                    onClick={() => setActiveChecker(item.name)}
                  />
                ))}
                {items.some(item => item.user_created) && (
                  <>
                    <div className="flex items-center gap-3 py-2">
                      <div className="flex-1 border-t border-slate-700" />
                      <span className="text-xs font-semibold text-slate-500 whitespace-nowrap">用户创建</span>
                      <div className="flex-1 border-t border-slate-700" />
                    </div>
                    {items.filter(item => item.user_created).map((item) => (
                      <CheckerListItem
                        key={item.name}
                        item={item}
                        active={item.name === activeChecker}
                        onClick={() => setActiveChecker(item.name)}
                      />
                    ))}
                  </>
                )}
              </div>
            </div>

            <div className="min-w-0">
              {selected ? (
                <CheckerIntro item={selected} />
              ) : (
                <div className="border border-slate-800 rounded-lg p-8 text-center text-slate-500">
                  暂无可展示的 SKILL
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SkillCreatePage({
  onBack,
  onImported,
}: {
  onBack: () => void;
  onImported: (name: string) => Promise<void>;
}) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [agentId, setAgentId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [input, setInput] = useState("");
  const [job, setJob] = useState<SkillCreateJob | null>(null);
  const [skillMd, setSkillMd] = useState("");
  const [scenariosMd, setScenariosMd] = useState("");
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState("");

  const dirty = !!(name || description || input || skillMd || scenariosMd || job);
  const creating = job?.status === "pending" || job?.status === "running";

  useEffect(() => {
    let alive = true;
    getAgents()
      .then((list) => {
        if (!alive) return;
        setAgents(list);
        const online = list.find((agent) => agent.online);
        if (online) setAgentId(online.agent_id);
      })
      .catch(() => {
        if (alive) setError("加载 Agent 列表失败");
      })
      .finally(() => {
        if (alive) setLoadingAgents(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (!job || (job.status !== "pending" && job.status !== "running")) return;
    const timer = window.setInterval(async () => {
      try {
        const next = await getSkillCreateJob(job.job_id);
        setJob(next);
        if (next.draft) {
          setSkillMd((current) => current || next.draft?.skill_md || "");
          setScenariosMd((current) => current || next.draft?.scenarios_md || "");
        }
      } catch (err: any) {
        setError(err.response?.data?.detail || "刷新创建进度失败");
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [job?.job_id, job?.status]);

  const handleBack = () => {
    if (dirty && !window.confirm("输入将被清空，是否确认返回？")) return;
    onBack();
  };

  const handleReset = () => {
    setName("");
    setDescription("");
    setInput("");
    setJob(null);
    setSkillMd("");
    setScenariosMd("");
    setError("");
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (!agentId) {
      setError("请选择 Agent");
      return;
    }
    if (!name.trim() || !description.trim() || !input.trim()) {
      setError("名称、描述和输入不能为空");
      return;
    }

    setSubmitting(true);
    try {
      const next = await createSkill({
        agent_id: agentId,
        name: name.trim(),
        description: description.trim(),
        input: input.trim(),
      });
      setJob(next);
      if (next.draft) {
        setSkillMd(next.draft.skill_md || "");
        setScenariosMd(next.draft.scenarios_md || "");
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "创建 SKILL 失败");
    } finally {
      setSubmitting(false);
    }
  };

  const handleImport = async () => {
    if (!job) return;
    setImporting(true);
    setError("");
    try {
      const result = await importSkill(job.job_id, {
        skill_md: skillMd,
        scenarios_md: scenariosMd,
      });
      await onImported(result.name);
    } catch (err: any) {
      setError(err.response?.data?.detail || "导入 SKILL 市场失败");
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <div className="bg-slate-900/90 border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={handleBack}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              &larr; 返回
            </button>
            <div>
              <h1 className="text-lg font-bold text-white">新增SKILL</h1>
              <p className="text-sm text-slate-400 mt-0.5">
                选择 Agent 在线生成纯 SKILL 项目级检查项
              </p>
            </div>
          </div>
          <StatusPill status={job?.status || "idle"} />
        </div>
      </div>

      <div className="flex-1 px-6 py-6">
        <div className="max-w-7xl mx-auto grid grid-cols-1 xl:grid-cols-[34rem_1fr] gap-5">
          <form onSubmit={handleSubmit} className="space-y-4">
            <Panel title="基础信息">
              <label className="block text-sm font-medium text-slate-300 mb-2">名称</label>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={creating}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="例如：认证绕过配置审计"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">描述</label>
              <textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                disabled={creating}
                rows={3}
                className="w-full resize-y bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm leading-6 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="说明这个 SKILL 要检查什么、适用对象和主要价值"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">输入</label>
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                disabled={creating}
                rows={8}
                className="w-full resize-y bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm leading-6 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="写清楚适用场景、判断标准、误报排除条件、期望输出等"
              />
            </Panel>

            <Panel title="Agent">
              {loadingAgents ? (
                <div className="text-sm text-slate-500">加载中...</div>
              ) : agents.length === 0 ? (
                <div className="text-sm text-slate-500">暂无 Agent 连接</div>
              ) : (
                <div className="space-y-2">
                  {agents.map((agent) => (
                    <label
                      key={agent.agent_id}
                      className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                        agentId === agent.agent_id
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-slate-700 hover:border-slate-600"
                      }`}
                    >
                      <input
                        type="radio"
                        name="skill-agent"
                        className="sr-only"
                        checked={agentId === agent.agent_id}
                        disabled={creating}
                        onChange={() => setAgentId(agent.agent_id)}
                      />
                      <span className={`w-2 h-2 rounded-full ${agent.online ? "bg-green-400" : "bg-slate-500"}`} />
                      <span className="min-w-0 flex-1 text-sm text-white truncate">{agent.name}</span>
                      <span className="text-xs text-slate-500">{agent.online ? "在线" : "离线"}</span>
                    </label>
                  ))}
                </div>
              )}
            </Panel>

            {error && (
              <div className="border border-red-500/30 bg-red-500/10 text-red-300 rounded-lg px-4 py-3 text-sm">
                {error}
              </div>
            )}

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={submitting || creating}
                className="flex-1 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {submitting || creating ? "进行中..." : "确定"}
              </button>
              <button
                type="button"
                onClick={handleReset}
                disabled={creating}
                className="px-6 py-2.5 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-lg border border-slate-700 transition-colors"
              >
                重置
              </button>
            </div>
          </form>

          <div className="min-w-0 space-y-4">
            <Panel title="创建进度">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-medium text-white">{statusText(job?.status || "idle")}</div>
                  <div className="text-xs text-slate-500 mt-1">
                    {job?.error_message || job?.draft?.summary || "提交后会显示 Agent 创建进度"}
                  </div>
                </div>
                {creating && (
                  <div className="w-5 h-5 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
                )}
              </div>
            </Panel>

            {job?.status === "completed" && (
              <Panel title="生成草稿">
                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                  SKILL.md
                </label>
                <textarea
                  value={skillMd}
                  onChange={(event) => setSkillMd(event.target.value)}
                  rows={18}
                  className="w-full resize-y font-mono bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs leading-5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mt-4 mb-2">
                  SCENARIOS.md
                </label>
                <textarea
                  value={scenariosMd}
                  onChange={(event) => setScenariosMd(event.target.value)}
                  rows={7}
                  className="w-full resize-y font-mono bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs leading-5 text-slate-200 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="button"
                  onClick={handleImport}
                  disabled={importing || !skillMd.trim()}
                  className="mt-4 w-full py-2.5 text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
                >
                  {importing ? "导入中..." : "导入SKILL市场"}
                </button>
              </Panel>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border border-slate-800 bg-slate-900/70 rounded-lg p-5">
      <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4">{title}</h2>
      {children}
    </section>
  );
}

function StatusPill({ status }: { status: string }) {
  const cls = status === "completed"
    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
    : status === "error"
      ? "border-red-500/30 bg-red-500/10 text-red-300"
      : status === "running" || status === "pending"
        ? "border-blue-500/30 bg-blue-500/10 text-blue-300"
        : "border-slate-700 bg-slate-800 text-slate-400";
  return (
    <span className={`text-xs font-semibold rounded px-2 py-1 border ${cls}`}>
      {statusText(status)}
    </span>
  );
}

function statusText(status: string): string {
  if (status === "pending") return "等待中";
  if (status === "running") return "进行中";
  if (status === "completed") return "已完成";
  if (status === "error") return "失败";
  return "未开始";
}

function CheckerListItem({
  item,
  active,
  onClick,
}: {
  item: CheckerCatalogItem;
  active: boolean;
  onClick: () => void;
}) {
  const activeCls = active
    ? "border-blue-500/60 bg-blue-500/10"
    : "border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-slate-700";

  return (
    <button
      onClick={onClick}
      className={`w-full rounded-lg border px-4 py-3 text-left transition-colors ${activeCls}`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="min-w-0 text-sm font-semibold text-white truncate">{item.label}</span>
        <span className="shrink-0 text-[11px] font-semibold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
          {item.name.toUpperCase()}
        </span>
        {item.enabled && (
          <span className="shrink-0 text-[11px] font-semibold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded px-1.5 py-0.5">
            已启用
          </span>
        )}
        {item.visibility === "admin" && (
          <span className="shrink-0 text-[11px] font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5">
            管理员测试
          </span>
        )}
        {item.user_created && (
          <span className="shrink-0 text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-1.5 py-0.5">
            用户创建
          </span>
        )}
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="font-semibold text-cyan-200 bg-cyan-500/10 border border-cyan-500/30 rounded px-1.5 py-0.5">
          {item.category_label || "非法内存使用"}
        </span>
        <span className="text-slate-500">
          最后修改：{formatModifiedAt(item.modified_at)}
        </span>
      </div>
      <p className="text-xs text-slate-500 line-clamp-2 min-h-8">
        {item.description || "暂无描述"}
      </p>
    </button>
  );
}

function CheckerIntro({ item }: { item: CheckerCatalogItem }) {
  return (
    <div className="border border-slate-800 bg-slate-900/70 rounded-lg overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-lg font-semibold text-white truncate">{item.label}</h2>
              <span className="text-xs font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {item.name.toUpperCase()}
              </span>
              {item.enabled && (
                <span className="text-xs font-semibold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded px-2 py-0.5">
                  已启用
                </span>
              )}
              {item.visibility === "admin" && (
                <span className="text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-2 py-0.5">
                  管理员测试
                </span>
              )}
              {item.user_created && (
                <span className="text-xs font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-2 py-0.5">
                  用户创建
                </span>
              )}
              <span className="text-xs font-semibold text-cyan-200 bg-cyan-500/10 border border-cyan-500/30 rounded px-2 py-0.5">
                {item.category_label || "非法内存使用"}
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-3xl">{item.description || "暂无描述"}</p>
          </div>
          <div className="flex flex-col items-start sm:items-end gap-2 text-xs text-slate-400">
            <span className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
              最后修改：{formatModifiedAt(item.modified_at)}
            </span>
            <span className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
              {item.introduction_source || "checker.yaml"}
            </span>
          </div>
        </div>
      </div>
      <div className="p-5">
        <MarkdownContent content={item.introduction || item.description || "暂无介绍"} />
      </div>
    </div>
  );
}

function formatModifiedAt(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function MarkdownContent({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mt-1 mb-5 text-2xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-8 mb-3 text-lg font-semibold text-white">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-6 mb-2 text-base font-semibold text-slate-100">{children}</h3>,
        h4: ({ children }) => <h4 className="mt-5 mb-2 text-sm font-semibold text-slate-200">{children}</h4>,
        p: ({ children }) => <p className="my-3 text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-3 space-y-1.5 pl-5 text-sm leading-relaxed text-slate-300 list-disc marker:text-blue-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-3 space-y-1.5 pl-5 text-sm leading-relaxed text-slate-300 list-decimal marker:text-blue-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        blockquote: ({ children }) => (
          <blockquote className="my-4 border-l-2 border-blue-500/70 bg-blue-500/5 px-4 py-3 text-sm leading-relaxed text-slate-300">
            {children}
          </blockquote>
        ),
        hr: () => <hr className="my-6 border-slate-800" />,
        table: ({ children }) => (
          <div className="my-4 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-950/70">{children}</thead>,
        th: ({ children }) => (
          <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">
            {children}
          </th>
        ),
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-4 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
            {children}
          </pre>
        ),
        code: ({ className, children }) => (
          <code className={`${className ?? ""} rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[0.85em] text-blue-200`}>
            {children}
          </code>
        ),
        strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}
