import { useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { createSkill, deleteSkill, getCheckerCatalog, importSkill } from "../api/client";
import type { CheckerCatalogItem, SkillCreateJob, SkillImportFile } from "../types";

interface Props {
  onBack: () => void;
}

export default function CheckerCatalogPage({ onBack }: Props) {
  const [mode, setMode] = useState<"catalog" | "create">("catalog");
  const [items, setItems] = useState<CheckerCatalogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeChecker, setActiveChecker] = useState<string | null>(null);
  const [deletingSkill, setDeletingSkill] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      const next = await getCheckerCatalog();
      setItems(next);
      setActiveChecker((current) => (
        current && next.some((item) => item.name === current)
          ? current
          : next[0]?.name ?? null
      ));
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

  const handleDelete = async (item: CheckerCatalogItem) => {
    if (!item.can_delete) return;
    if (!window.confirm(`确定删除 SKILL「${item.label}」吗？此操作无法撤销。`)) return;
    setDeletingSkill(item.name);
    setError("");
    try {
      await deleteSkill(item.name);
      setActiveChecker(null);
      await refresh();
    } catch (err: any) {
      setError(err.response?.data?.detail || "删除 SKILL 失败");
    } finally {
      setDeletingSkill(null);
    }
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
                <CheckerIntro
                  item={selected}
                  deleting={deletingSkill === selected.name}
                  onDelete={() => handleDelete(selected)}
                />
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
  const [name, setName] = useState("");
  const [skillId, setSkillId] = useState("");
  const [description, setDescription] = useState("");
  const [input, setInput] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(1200);
  const [job, setJob] = useState<SkillCreateJob | null>(null);
  const [skillMd, setSkillMd] = useState("");
  const [scenariosMd, setScenariosMd] = useState("");
  const [uploadDir, setUploadDir] = useState<"references" | "scripts" | "assets">("references");
  const [files, setFiles] = useState<SkillImportFile[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState("");

  const dirty = !!(skillId || name || description || input || skillMd || scenariosMd || job || files.length);

  const handleBack = () => {
    if (dirty && !window.confirm("输入将被清空，是否确认返回？")) return;
    onBack();
  };

  const handleReset = () => {
    setName("");
    setSkillId("");
    setDescription("");
    setInput("");
    setTimeoutSeconds(1200);
    setJob(null);
    setSkillMd("");
    setScenariosMd("");
    setFiles([]);
    setError("");
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (!skillId.trim() || !name.trim() || !description.trim() || !input.trim()) {
      setError("标识、名称、描述和输入不能为空");
      return;
    }

    setSubmitting(true);
    try {
      const next = await createSkill({
        skill_id: skillId.trim(),
        name: name.trim(),
        description: description.trim(),
        input: input.trim(),
        timeout_seconds: timeoutSeconds,
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

  const handleFiles = async (selected: FileList | null) => {
    if (!selected || selected.length === 0) return;
    const nextFiles: SkillImportFile[] = [];
    for (const file of Array.from(selected)) {
      const content_b64 = await fileToBase64(file);
      nextFiles.push({ path: `${uploadDir}/${file.name}`, content_b64 });
    }
    setFiles((current) => [...current, ...nextFiles]);
  };

  const handleImport = async () => {
    if (!job) return;
    setImporting(true);
    setError("");
    try {
      const result = await importSkill(job.job_id, {
        skill_md: skillMd,
        scenarios_md: scenariosMd,
        timeout_seconds: timeoutSeconds,
        files,
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
                直接生成可编辑模板，系统固定运行规则会在导入时强制拼接
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
              <label className="block text-sm font-medium text-slate-300 mb-2">标识</label>
              <input
                value={skillId}
                onChange={(event) => setSkillId(event.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 font-mono text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="例如：auth_bypass_audit"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">名称</label>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="例如：认证绕过配置审计"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">描述</label>
              <textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                rows={3}
                className="w-full resize-y bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm leading-6 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="说明这个 SKILL 要检查什么、适用对象和主要价值"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">输入</label>
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                rows={8}
                className="w-full resize-y bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm leading-6 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                placeholder="写清楚适用场景、判断标准、误报排除条件、期望输出等"
              />

              <label className="block text-sm font-medium text-slate-300 mt-4 mb-2">单次运行超时（秒）</label>
              <input
                type="number"
                min={60}
                max={86400}
                value={timeoutSeconds}
                onChange={(event) => setTimeoutSeconds(Number(event.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </Panel>

            <Panel title="上传资料">
              <div className="flex flex-wrap items-center gap-3">
                <select
                  value={uploadDir}
                  onChange={(event) => setUploadDir(event.target.value as "references" | "scripts" | "assets")}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="references">references/</option>
                  <option value="scripts">scripts/</option>
                  <option value="assets">assets/</option>
                </select>
                <input
                  type="file"
                  multiple
                  onChange={(event) => {
                    handleFiles(event.target.files);
                    event.currentTarget.value = "";
                  }}
                  className="block text-sm text-slate-400 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-sm file:font-medium file:text-slate-200 hover:file:bg-slate-700"
                />
              </div>
              {files.length > 0 && (
                <div className="mt-3 space-y-1">
                  {files.map((file, index) => (
                    <div key={`${file.path}-${index}`} className="flex items-center justify-between gap-3 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
                      <span className="min-w-0 truncate font-mono">{file.path}</span>
                      <button
                        type="button"
                        onClick={() => setFiles((current) => current.filter((_, i) => i !== index))}
                        className="shrink-0 text-slate-500 hover:text-red-300"
                      >
                        移除
                      </button>
                    </div>
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
                disabled={submitting}
                className="flex-1 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {submitting ? "生成中..." : "生成草稿"}
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="px-6 py-2.5 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-lg border border-slate-700 transition-colors"
              >
                重置
              </button>
            </div>
          </form>

          <div className="min-w-0 space-y-4">
            <Panel title="系统固定规则">
              <FixedSkillRules />
            </Panel>

            <Panel title="创建状态">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-medium text-white">{statusText(job?.status || "idle")}</div>
                  <div className="text-xs text-slate-500 mt-1">
                    {job?.error_message || job?.draft?.summary || "生成草稿后可继续编辑再导入市场"}
                  </div>
                </div>
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

function FixedSkillRules() {
  return (
    <div className="space-y-3 text-sm leading-6 text-slate-300">
      <p>MCP 工具使用、Markdown 报告保存方式、写权限约束会由后端固定拼接到最终 SKILL.md。</p>
      <ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">
        <li>可调用 view_function_code、view_struct_code、view_global_variable_definition。</li>
        <li>运行提示词会提供 REPORT_DIR，报告只能写入该目录。</li>
        <li>项目代码和上传资料保持只读，仅临时报告目录可写。</li>
      </ul>
    </div>
  );
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      resolve(result.includes(",") ? result.split(",", 2)[1] : result);
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
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
        {item.user_created && (
          <span className="text-slate-500">
            创建者：{item.creator_username || "-"}
          </span>
        )}
      </div>
      <p className="text-xs text-slate-500 line-clamp-2 min-h-8">
        {item.description || "暂无描述"}
      </p>
    </button>
  );
}

function CheckerIntro({
  item,
  deleting,
  onDelete,
}: {
  item: CheckerCatalogItem;
  deleting: boolean;
  onDelete: () => void;
}) {
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
            {item.user_created && (
              <span className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
                创建者：{item.creator_username || "-"}
              </span>
            )}
            <span className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
              最后修改：{formatModifiedAt(item.modified_at)}
            </span>
            <span className="bg-slate-800 border border-slate-700 rounded px-2 py-1">
              {item.introduction_source || "checker.yaml"}
            </span>
            {item.can_delete && (
              <button
                onClick={onDelete}
                disabled={deleting}
                className="rounded border border-red-500/40 px-3 py-1.5 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {deleting ? "删除中..." : "删除"}
              </button>
            )}
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
