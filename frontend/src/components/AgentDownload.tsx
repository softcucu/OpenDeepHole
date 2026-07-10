import { useEffect, useState } from "react";
import { getAgentOpenCodeModels, getAgentOpenCodePool, getAgents, getAgentConfig, syncProductValidators, testAgentConfig, updateAgentConfig } from "../api/client";
import type {
  AgentGitHistoryConfig,
  AgentInfo,
  AgentOpenCodeModelListItem,
  AgentOpenCodePoolStatus,
  AgentOpenCodeConfig,
  AgentOpenCodeModelConfig,
  OpenCodePoolModelStats,
  AgentPatternFilterConfig,
  AgentRemoteConfig,
} from "../types";

interface Props {
  onBack: () => void;
}

const DEFAULT_PATTERN_FILTER: AgentPatternFilterConfig = {
  enabled: true,
  scope: "directory",
};

const DEFAULT_GIT_HISTORY: AgentGitHistoryConfig = {
  enabled: false,
  max_commits: 200,
  since: "",
  paths: "",
  variant_hunt: true,
};

const DEFAULT_VULNERABILITY_VALIDATION = {
  enabled: true,
  script_path: "",
  command: "",
  timeout_seconds: 7200,
};

const DEFAULT_CONFIG: AgentRemoteConfig = {
  no_proxy: "10.0.0.0/8",
  opencode_concurrency: 4,
  llm_api: {
    base_url: "https://api.anthropic.com",
    api_key: "",
    model: "claude-sonnet-4-6",
    temperature: 0.1,
    timeout: 300,
    max_retries: 3,
    stream: false,
  },
  opencode: {
    tool: "nga",
    executable: "nga",
    invocation_mode: "serve",
    model: "",
    timeout: 1200,
    max_retries: 2,
    models: [],
    config_paths: [],
    proxy_url: "",
    no_proxy: "",
  },
  fp_review_cli: null,
  memory_api_discovery: {
    enabled: true,
    batch_size: 8,
    timeout_seconds: 300,
    max_candidates: 200,
  },
  git_history: DEFAULT_GIT_HISTORY,
  static_dedup: true,
  pattern_filter: DEFAULT_PATTERN_FILTER,
  vulnerability_validation: DEFAULT_VULNERABILITY_VALIDATION,
};

const DEFAULT_MODEL: AgentOpenCodeModelConfig = {
  id: "",
  model: "",
  use_default_model: false,
  capability: "high",
  weight: 1,
  max_concurrency: 1,
  enabled: true,
  tool: "",
  executable: "",
  timeout: null,
  max_retries: null,
  time_windows: [],
};

const TOOL_OPTIONS = [
  { value: "nga", label: "nga" },
  { value: "opencode", label: "opencode" },
  { value: "hac", label: "hac" },
  { value: "claude", label: "claude" },
];

const DEFAULT_EXECUTABLE_BY_TOOL: Record<string, string> = {
  nga: "nga",
  opencode: "opencode",
  hac: "hac",
  claude: "claude",
};

function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

function normalizeConfig(config: AgentRemoteConfig): AgentRemoteConfig {
  const base = deepClone(DEFAULT_CONFIG);
  const opencode = { ...base.opencode, ...config.opencode };
  opencode.models = normalizeModels(config.opencode?.models);
  opencode.config_paths = normalizeConfigPaths(config.opencode?.config_paths);
  opencode.proxy_url = String(config.opencode?.proxy_url || "").trim();
  opencode.no_proxy = String(config.opencode?.no_proxy || "").trim();
  const fpReviewCli = config.fp_review_cli
    ? {
        ...opencode,
        ...config.fp_review_cli,
        models: normalizeModels(config.fp_review_cli.models),
        config_paths: normalizeConfigPaths(config.fp_review_cli.config_paths ?? opencode.config_paths),
        proxy_url: String(config.fp_review_cli.proxy_url ?? opencode.proxy_url ?? "").trim(),
        no_proxy: String(config.fp_review_cli.no_proxy ?? opencode.no_proxy ?? "").trim(),
      }
    : null;
  return {
    ...base,
    ...config,
    opencode_concurrency: config.opencode_concurrency || 1,
    opencode,
    fp_review_cli: fpReviewCli,
    memory_api_discovery: { ...base.memory_api_discovery, ...config.memory_api_discovery },
    git_history: { ...DEFAULT_GIT_HISTORY, ...config.git_history },
    static_dedup: config.static_dedup ?? base.static_dedup,
    pattern_filter: { ...DEFAULT_PATTERN_FILTER, ...config.pattern_filter },
    vulnerability_validation: {
      ...DEFAULT_VULNERABILITY_VALIDATION,
      ...config.vulnerability_validation,
    },
    llm_api: { ...base.llm_api, ...config.llm_api },
  };
}

function normalizeModels(models?: AgentOpenCodeModelConfig[]): AgentOpenCodeModelConfig[] {
  return Array.isArray(models)
    ? models.map((model) => ({
        ...DEFAULT_MODEL,
        ...model,
        time_windows: Array.isArray(model.time_windows) ? model.time_windows : [],
      }))
    : [];
}

function normalizeConfigPaths(paths?: string[]): string[] {
  return Array.isArray(paths)
    ? paths.map((path) => String(path || "").trim()).filter(Boolean)
    : [];
}

function configPathsText(paths?: string[]): string {
  return normalizeConfigPaths(paths).join("\n");
}

function parseConfigPaths(text: string): string[] {
  return text.split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
}

function validateTime(value: string): boolean {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
}

function validateModelPool(title: string, models: AgentOpenCodeModelConfig[]): string | null {
  const seen = new Set<string>();
  for (const [index, model] of models.entries()) {
    const row = `${title} 第 ${index + 1} 行`;
    const id = model.id.trim();
    if (!id) return `${row} 缺少 ID`;
    if (seen.has(id)) return `${title} 存在重复 ID：${id}`;
    seen.add(id);
    if (!model.use_default_model && !model.model.trim()) return `${row} 缺少模型名`;
    for (const window of model.time_windows || []) {
      if (!validateTime(window.start) || !validateTime(window.end) || window.start === window.end) {
        return `${row} 的使用时间必须是有效的 HH:MM-HH:MM，且起止不能相同`;
      }
    }
  }
  return null;
}

function formatDurationSeconds(value: number): string {
  if (!value || value < 0) return "—";
  if (value < 60) return `${Math.round(value)}s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function compactTaskTypeLabel(value: unknown): string {
  const type = String(value || "audit");
  if (type === "audit") return "候选点审计";
  if (type === "fp_review") return "对抗式去误报";
  if (type === "threat_analysis") return "威胁分析";
  if (type === "threat_audit") return "威胁审计";
  if (type === "validation") return "漏洞验证";
  return type;
}

function compactTaskLabel(task: Record<string, unknown> | undefined): string {
  if (!task) return "—";
  const taskType = compactTaskTypeLabel(task.task_type);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const target = file ? `${file}${line}` : checker;
  const session = task.serve_session_id ? String(task.serve_session_id) : "";
  return [taskType + stage, target, session].filter(Boolean).join(" ");
}

function ActiveTaskList({ tasks }: { tasks?: Record<string, unknown>[] }) {
  const activeTasks = tasks || [];
  if (activeTasks.length === 0) return <>—</>;
  return (
    <div className="space-y-1">
      {activeTasks.map((task, index) => (
        <div key={String(task.task_id || index)} className="truncate">
          {compactTaskLabel(task)}
        </div>
      ))}
    </div>
  );
}

interface AgentConfigPanelProps {
  agent: AgentInfo;
}

const PRODUCT_VALIDATOR_SYNC_WARNING =
  "警告：同步会使用服务端内容完整替换 Agent 上的同名验证方法目录；同名目录内的本地文件可能被覆盖或删除，Agent 独有目录会保留。";

function AgentConfigPanel({ agent }: AgentConfigPanelProps) {
  const [open, setOpen] = useState(false);
  const [pool, setPool] = useState<AgentOpenCodePoolStatus | null>(null);
  const [activeTab, setActiveTab] = useState<"base" | "models">("base");
  const [cfg, setCfg] = useState<AgentRemoteConfig>(deepClone(DEFAULT_CONFIG));
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncingValidators, setSyncingValidators] = useState(false);
  const [validatorSyncConfirmOpen, setValidatorSyncConfirmOpen] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [validatorSyncResult, setValidatorSyncResult] = useState<{ ok: boolean; message: string; installed: string[] } | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modelPicker, setModelPicker] = useState<{
    section: "opencode" | "fp_review_cli";
    title: string;
    loading: boolean;
    error: string | null;
    models: AgentOpenCodeModelListItem[];
    selected: string[];
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const data = await getAgentOpenCodePool(agent.agent_id);
        if (!cancelled) setPool(data);
      } catch {
        if (!cancelled) setPool(null);
      }
    };
    refresh();
    const id = setInterval(() => {
      if (document.visibilityState === "hidden") return;
      refresh();
    }, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [agent.agent_id]);

  const handleOpen = async () => {
    setOpen(true);
    setLoading(true);
    setError(null);
    try {
      const data = await getAgentConfig(agent.agent_id);
      setCfg(normalizeConfig(data));
    } catch {
      setError("加载配置失败");
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const validationError =
        validateModelPool("审计模型池", cfg.opencode.models || [])
        || validateModelPool("去误报模型池", cfg.fp_review_cli?.models || []);
      if (validationError) {
        setError(validationError);
        return;
      }
      await updateAgentConfig(agent.agent_id, cfg);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setError("保存失败，请重试");
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const result = await testAgentConfig(agent.agent_id, cfg);
      setTestResult(result);
    } catch {
      setError("API 校验失败，请确认 Agent 在线并重试");
    } finally {
      setTesting(false);
    }
  };

  const handleSyncValidators = () => {
    if (!agent.online || syncingValidators) return;
    setValidatorSyncConfirmOpen(true);
  };

  const handleConfirmSyncValidators = async () => {
    if (!agent.online || syncingValidators) {
      setValidatorSyncConfirmOpen(false);
      return;
    }
    setValidatorSyncConfirmOpen(false);
    setSyncingValidators(true);
    setError(null);
    setValidatorSyncResult(null);
    try {
      const result = await syncProductValidators(agent.agent_id);
      setValidatorSyncResult(result);
    } catch {
      setError("验证方法同步失败，请确认 Agent 在线并重试");
    } finally {
      setSyncingValidators(false);
    }
  };

  const setLLM = (key: keyof AgentRemoteConfig["llm_api"], value: string | number | boolean) => {
    setCfg((prev) => ({ ...prev, llm_api: { ...prev.llm_api, [key]: value } }));
  };

  const setOC = (key: keyof AgentRemoteConfig["opencode"], value: string | number | string[]) => {
    setCfg((prev) => ({ ...prev, opencode: { ...prev.opencode, [key]: value } }));
  };

  const setAuditTool = (tool: string) => {
    setCfg((prev) => ({
      ...prev,
      opencode: {
        ...prev.opencode,
        tool,
        executable: DEFAULT_EXECUTABLE_BY_TOOL[tool] ?? tool,
      },
    }));
  };

  const setFpCli = (key: keyof AgentRemoteConfig["opencode"], value: string | number | string[]) => {
    setCfg((prev) => {
      const base = prev.fp_review_cli ?? { ...prev.opencode };
      return { ...prev, fp_review_cli: { ...base, [key]: value } };
    });
  };

  const setConcurrency = (value: number) => {
    setCfg((prev) => ({ ...prev, opencode_concurrency: Math.max(1, Math.min(8, value || 1)) }));
  };

  const updateModelPool = (
    section: "opencode" | "fp_review_cli",
    updater: (models: AgentOpenCodeModelConfig[]) => AgentOpenCodeModelConfig[],
  ) => {
    setCfg((prev) => {
      const current: AgentOpenCodeConfig = section === "opencode"
        ? prev.opencode
        : (prev.fp_review_cli ?? { ...prev.opencode, models: [] });
      const next = { ...current, models: updater(current.models || []) };
      return section === "opencode"
        ? { ...prev, opencode: next }
        : { ...prev, fp_review_cli: next };
    });
  };

  const setFpInherit = (inherit: boolean) => {
    setCfg((prev) => ({
      ...prev,
      fp_review_cli: inherit
        ? null
        : {
            ...prev.opencode,
            model: "",
            models: normalizeModels(prev.opencode.models).filter((model) => model.capability === "high"),
          },
    }));
  };

  const setFpTool = (tool: string) => {
    setCfg((prev) => {
      const base = prev.fp_review_cli ?? { ...prev.opencode };
      return {
        ...prev,
        fp_review_cli: {
          ...base,
          tool,
          executable: DEFAULT_EXECUTABLE_BY_TOOL[tool] ?? tool,
        },
      };
    });
  };

  const openModelPicker = async (section: "opencode" | "fp_review_cli", title: string, refresh = false) => {
    setModelPicker({
      section,
      title,
      loading: true,
      error: null,
      models: [],
      selected: [],
    });
    try {
      const result = await getAgentOpenCodeModels(agent.agent_id, refresh);
      if (!result.ok) {
        throw new Error(result.message || "读取模型失败");
      }
      setModelPicker({
        section,
        title,
        loading: false,
        error: null,
        models: result.models,
        selected: [],
      });
    } catch (exc) {
      setModelPicker((prev) => prev && {
        ...prev,
        loading: false,
        error: exc instanceof Error ? exc.message : "读取模型失败",
      });
    }
  };

  const refreshModelPicker = () => {
    if (!modelPicker) return;
    void openModelPicker(modelPicker.section, modelPicker.title, true);
  };

  const togglePickedModel = (id: string) => {
    setModelPicker((prev) => {
      if (!prev) return prev;
      const selected = prev.selected.includes(id)
        ? prev.selected.filter((item) => item !== id)
        : [...prev.selected, id];
      return { ...prev, selected };
    });
  };

  const importPickedModels = () => {
    if (!modelPicker) return;
    const picked = modelPicker.models.filter((model) => modelPicker.selected.includes(model.id));
    updateModelPool(modelPicker.section, (current) => {
      const existing = new Set(current.map((model) => model.id));
      const additions = picked
        .filter((model) => !existing.has(model.id))
        .map((model) => ({
          ...DEFAULT_MODEL,
          id: model.id,
          model: model.model || model.id,
        }));
      return [...current, ...additions];
    });
    setModelPicker(null);
  };

  return (
    <>
      {validatorSyncConfirmOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby={`validator-sync-confirm-${agent.agent_id}`}
        >
          <div className="w-full max-w-md rounded-xl border border-red-500/30 bg-slate-800 p-6 shadow-2xl">
            <h3
              id={`validator-sync-confirm-${agent.agent_id}`}
              className="mb-2 text-base font-semibold text-white"
            >
              确认同步验证方法
            </h3>
            <p className="text-sm leading-6 text-slate-300">
              即将同步 Agent <span className="font-medium text-white">{agent.name}</span>。
              {PRODUCT_VALIDATOR_SYNC_WARNING}
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setValidatorSyncConfirmOpen(false)}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white"
              >
                取消
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmSyncValidators()}
                disabled={!agent.online || syncingValidators}
                className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-red-500 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-500"
              >
                确认同步
              </button>
            </div>
          </div>
        </div>
      )}
      <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
      {/* Agent row */}
      <div className="flex items-center gap-3 px-4 py-3">
        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${agent.online ? "bg-green-400" : "bg-slate-500"}`} />
        <div className="flex-1 min-w-0">
          <span className="text-sm font-medium text-white">{agent.name}</span>
          <span className="ml-2 text-xs text-slate-400">{agent.ip}</span>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded border mr-2 ${
          agent.online
            ? "bg-green-500/20 text-green-400 border-green-500/30"
            : "bg-slate-700 text-slate-500 border-slate-600"
        }`}>
          {agent.online ? "在线" : "离线"}
        </span>
        <button
          onClick={open ? () => setOpen(false) : handleOpen}
          className="px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center gap-1"
        >
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          配置
        </button>
        <span className="inline-flex" title={PRODUCT_VALIDATOR_SYNC_WARNING}>
          <button
            type="button"
            onClick={handleSyncValidators}
            disabled={!agent.online || syncingValidators}
            className="px-3 py-1.5 text-xs font-medium bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-slate-100 rounded-lg transition-colors"
          >
            {syncingValidators ? "同步中" : "同步验证方法"}
          </button>
        </span>
      </div>

      {validatorSyncResult && (
        <div className={`border-t px-4 py-2 text-xs ${
          validatorSyncResult.ok
            ? "border-green-500/20 bg-green-500/10 text-green-300"
            : "border-red-500/20 bg-red-500/10 text-red-300"
        }`}>
          {validatorSyncResult.message || (validatorSyncResult.ok ? "验证方法已同步" : "验证方法同步失败")}
          {validatorSyncResult.installed.length > 0 && (
            <span className="ml-2 text-slate-400">{validatorSyncResult.installed.join(", ")}</span>
          )}
        </div>
      )}

      <AgentModelUsage pool={pool} />

      {/* Config form */}
      {open && (
        <div className="border-t border-slate-700 px-4 py-4">
          {loading ? (
            <div className="flex justify-center py-6">
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            </div>
          ) : (
            <div className="space-y-5">
              <div className="flex gap-2 border-b border-slate-700 pb-2">
                <button
                  type="button"
                  onClick={() => setActiveTab("base")}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                    activeTab === "base"
                      ? "bg-blue-600 text-white"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-700"
                  }`}
                >
                  基础配置
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("models")}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                    activeTab === "models"
                      ? "bg-blue-600 text-white"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-700"
                  }`}
                >
                  模型池
                </button>
              </div>

              {activeTab === "base" && (
                <>
              {/* LLM API */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">LLM API 配置</h3>
                <div className="grid grid-cols-1 gap-3">
                  <Field label="API 地址" hint="OpenAI 兼容接口">
                    <input type="text" value={cfg.llm_api.base_url}
                      onChange={(e) => setLLM("base_url", e.target.value)}
                      className={inputCls} placeholder="https://api.anthropic.com" />
                  </Field>
                  <Field label="API Key">
                    <input type="password" value={cfg.llm_api.api_key}
                      onChange={(e) => setLLM("api_key", e.target.value)}
                      className={inputCls} placeholder="sk-..." />
                  </Field>
                  <Field label="模型">
                    <input type="text" value={cfg.llm_api.model}
                      onChange={(e) => setLLM("model", e.target.value)}
                      className={inputCls} placeholder="claude-sonnet-4-6" />
                  </Field>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <Field label="超时（秒）">
                      <input type="number" value={cfg.llm_api.timeout}
                        onChange={(e) => setLLM("timeout", Number(e.target.value))}
                        className={inputCls} min={10} />
                    </Field>
                    <Field label="最大重试">
                      <input type="number" value={cfg.llm_api.max_retries}
                        onChange={(e) => setLLM("max_retries", Number(e.target.value))}
                        className={inputCls} min={0} max={10} />
                    </Field>
                    <Field label="Temperature">
                      <input type="number" value={cfg.llm_api.temperature}
                        onChange={(e) => setLLM("temperature", Number(e.target.value))}
                        className={inputCls} min={0} max={2} step={0.1} />
                    </Field>
                  </div>
                  <label className="flex items-center gap-2 text-sm text-slate-300">
                    <input
                      type="checkbox"
                      checked={cfg.llm_api.stream}
                      onChange={(e) => setLLM("stream", e.target.checked)}
                      className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                    />
                    使用流式传输
                  </label>
                </div>
              </div>

              {/* CLI audit */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">LLM 审计工具</h3>
                <div className="grid grid-cols-1 gap-3">
                  <Field label="工具">
                    <select value={cfg.opencode.tool || "opencode"}
                      onChange={(e) => setAuditTool(e.target.value)}
                      className={inputCls}>
                      {TOOL_OPTIONS.map((item) => (
                        <option key={item.value} value={item.value}>{item.label}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="调用方式">
                    <select value={cfg.opencode.invocation_mode || "serve"}
                      onChange={(e) => setOC("invocation_mode", e.target.value)}
                      className={inputCls}>
                      <option value="serve">serve API（默认）</option>
                      <option value="cli">CLI run</option>
                    </select>
                  </Field>
                  <Field label="可执行文件" hint="CLI 名称或完整路径">
                    <input type="text" value={cfg.opencode.executable}
                      onChange={(e) => setOC("executable", e.target.value)}
                      className={inputCls} placeholder={DEFAULT_EXECUTABLE_BY_TOOL[cfg.opencode.tool] ?? "opencode"} />
                  </Field>
                  <Field label="代理地址" hint="可选，如 http://127.0.0.1:3131">
                    <input type="text" value={cfg.opencode.proxy_url || ""}
                      onChange={(e) => setOC("proxy_url", e.target.value)}
                      className={inputCls} placeholder="http://127.0.0.1:3131" />
                  </Field>
                  <Field label="代理跳过列表" hint="可选；留空则使用全局 no_proxy">
                    <textarea
                      value={cfg.opencode.no_proxy || ""}
                      onChange={(e) => setOC("no_proxy", e.target.value)}
                      className={`${inputCls} min-h-[72px] resize-y`}
                      placeholder="mirrors.tools.huawei.com,.huawei.com,127.0.0.1,localhost"
                    />
                  </Field>
                  <Field label="OpenCode 配置文件" hint="一行一个文件路径">
                    <textarea
                      value={configPathsText(cfg.opencode.config_paths)}
                      onChange={(e) => setOC("config_paths", parseConfigPaths(e.target.value))}
                      className={`${inputCls} min-h-[72px] resize-y`}
                      placeholder="/path/to/opencode.json"
                    />
                  </Field>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <Field label="超时（秒）">
                      <input type="number" value={cfg.opencode.timeout}
                        onChange={(e) => setOC("timeout", Number(e.target.value))}
                        className={inputCls} min={30} />
                    </Field>
                    <Field label="最大重试">
                      <input type="number" value={cfg.opencode.max_retries}
                        onChange={(e) => setOC("max_retries", Number(e.target.value))}
                        className={inputCls} min={0} max={10} />
                    </Field>
                  </div>
                </div>
              </div>

              {/* FP review CLI */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">AI 去误报工具</h3>
                <label className="flex items-center gap-2 text-sm text-slate-300 mb-3">
                  <input
                    type="checkbox"
                    checked={!cfg.fp_review_cli}
                    onChange={(e) => setFpInherit(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                  />
                  继承 LLM 审计工具和模型
                </label>
                {cfg.fp_review_cli && (
                  <div className="grid grid-cols-1 gap-3">
                    <Field label="工具">
                      <select value={cfg.fp_review_cli.tool || "opencode"}
                        onChange={(e) => setFpTool(e.target.value)}
                        className={inputCls}>
                        {TOOL_OPTIONS.map((item) => (
                          <option key={item.value} value={item.value}>{item.label}</option>
                        ))}
                      </select>
                    </Field>
                    <Field label="调用方式">
                      <select value={cfg.fp_review_cli.invocation_mode || "serve"}
                        onChange={(e) => setFpCli("invocation_mode", e.target.value)}
                        className={inputCls}>
                        <option value="serve">serve API（默认）</option>
                        <option value="cli">CLI run</option>
                      </select>
                    </Field>
                    <Field label="可执行文件" hint="CLI 名称或完整路径">
                      <input type="text" value={cfg.fp_review_cli.executable}
                        onChange={(e) => setFpCli("executable", e.target.value)}
                        className={inputCls} placeholder={DEFAULT_EXECUTABLE_BY_TOOL[cfg.fp_review_cli.tool] ?? "opencode"} />
                    </Field>
                    <Field label="代理地址" hint="可选，如 http://127.0.0.1:3131">
                      <input type="text" value={cfg.fp_review_cli.proxy_url || ""}
                        onChange={(e) => setFpCli("proxy_url", e.target.value)}
                        className={inputCls} placeholder="http://127.0.0.1:3131" />
                    </Field>
                    <Field label="代理跳过列表" hint="可选；留空则继承审计工具">
                      <textarea
                        value={cfg.fp_review_cli.no_proxy || ""}
                        onChange={(e) => setFpCli("no_proxy", e.target.value)}
                        className={`${inputCls} min-h-[72px] resize-y`}
                        placeholder="mirrors.tools.huawei.com,.huawei.com,127.0.0.1,localhost"
                      />
                    </Field>
                    <Field label="OpenCode 配置文件" hint="一行一个文件路径">
                      <textarea
                        value={configPathsText(cfg.fp_review_cli.config_paths)}
                        onChange={(e) => setFpCli("config_paths", parseConfigPaths(e.target.value))}
                        className={`${inputCls} min-h-[72px] resize-y`}
                        placeholder="/path/to/opencode.json"
                      />
                    </Field>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <Field label="超时（秒）">
                        <input type="number" value={cfg.fp_review_cli.timeout}
                          onChange={(e) => setFpCli("timeout", Number(e.target.value))}
                          className={inputCls} min={30} />
                      </Field>
                      <Field label="最大重试">
                        <input type="number" value={cfg.fp_review_cli.max_retries}
                          onChange={(e) => setFpCli("max_retries", Number(e.target.value))}
                          className={inputCls} min={0} max={10} />
                      </Field>
                    </div>
                  </div>
                )}
              </div>

              {/* no_proxy */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">网络</h3>
                <Field label="代理跳过列表" hint="逗号分隔，如 localhost,10.0.0.0/8">
                  <input type="text" value={cfg.no_proxy}
                    onChange={(e) => setCfg((prev) => ({ ...prev, no_proxy: e.target.value }))}
                    className={inputCls} placeholder="localhost,127.0.0.1" />
                </Field>
              </div>
                </>
              )}

              {activeTab === "models" && (
                <div className="space-y-5">
                  <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">总并发</h3>
                    <Field label="OpenCode 并发数" hint="所有模型合计同时运行的 CLI 任务上限">
                      <input type="number" value={cfg.opencode_concurrency}
                        onChange={(e) => setConcurrency(Number(e.target.value))}
                        className={inputCls} min={1} max={8} />
                    </Field>
                  </div>
                  <ModelPoolEditor
                    title="审计模型池"
                    models={cfg.opencode.models || []}
                    onChange={(models) => updateModelPool("opencode", () => models)}
                    onImport={() => openModelPicker("opencode", "审计模型池")}
                  />
                  <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">AI 去误报模型池</h3>
                    <label className="flex items-center gap-2 text-sm text-slate-300 mb-3">
                      <input
                        type="checkbox"
                        checked={!cfg.fp_review_cli}
                        onChange={(e) => setFpInherit(e.target.checked)}
                        className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                      />
                      继承审计模型池
                    </label>
                    {cfg.fp_review_cli && (
                      <ModelPoolEditor
                        title="去误报模型池"
                        models={cfg.fp_review_cli.models || []}
                        onChange={(models) => updateModelPool("fp_review_cli", () => models)}
                        onImport={() => openModelPicker("fp_review_cli", "去误报模型池")}
                      />
                    )}
                  </div>
                </div>
              )}

              {error && (
                <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                  {error}
                </p>
              )}

              {testResult && (
                <p className={`text-sm rounded-lg px-3 py-2 border ${
                  testResult.ok
                    ? "text-green-300 bg-green-500/10 border-green-500/20"
                    : "text-red-300 bg-red-500/10 border-red-500/20"
                }`}>
                  {testResult.message || (testResult.ok ? "API 配置可用" : "API 配置不可用")}
                </p>
              )}

              <div className="flex flex-wrap justify-end gap-2 pt-1">
                <button onClick={() => setOpen(false)}
                  className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
                  关闭
                </button>
                <button onClick={handleTest} disabled={testing || !agent.online}
                  className="px-4 py-1.5 text-sm font-medium text-slate-100 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-lg transition-colors">
                  {testing ? "校验中…" : "校验 API"}
                </button>
                <button onClick={handleSave} disabled={saving}
                  className="px-4 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors">
                  {saving ? "保存中…" : saved ? "已保存 ✓" : "保存配置"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
      {modelPicker && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-xl">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">从 serve 导入到{modelPicker.title}</h3>
              <button
                type="button"
                onClick={() => setModelPicker(null)}
                className="px-2 py-1 text-xs text-slate-300 hover:text-white"
              >
                关闭
              </button>
            </div>
            <div className="max-h-[24rem] overflow-y-auto rounded-md border border-slate-700">
              {modelPicker.loading ? (
                <div className="px-3 py-6 text-center text-sm text-slate-400">读取中…</div>
              ) : modelPicker.error ? (
                <div className="px-3 py-6 text-center text-sm text-red-300">{modelPicker.error}</div>
              ) : modelPicker.models.length === 0 ? (
                <div className="px-3 py-6 text-center text-sm text-slate-400">serve 未返回可用模型</div>
              ) : (
                <div className="divide-y divide-slate-700">
                  {modelPicker.models.map((model) => (
                    <label key={model.id} className="flex items-center gap-3 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800">
                      <input
                        type="checkbox"
                        checked={modelPicker.selected.includes(model.id)}
                        onChange={() => togglePickedModel(model.id)}
                        className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-xs text-slate-100">{model.id}</span>
                        {model.name && <span className="block truncate text-xs text-slate-500">{model.name}</span>}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs text-slate-500">已选择 {modelPicker.selected.length} 个模型</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={refreshModelPicker}
                  disabled={modelPicker.loading}
                  className="px-3 py-1.5 text-xs text-slate-100 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-md transition-colors"
                >
                  刷新
                </button>
                <button
                  type="button"
                  onClick={importPickedModels}
                  disabled={modelPicker.loading || modelPicker.selected.length === 0}
                  className="px-3 py-1.5 text-xs text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors"
                >
                  导入
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      </div>
    </>
  );
}

function AgentModelUsage({ pool }: { pool: AgentOpenCodePoolStatus | null }) {
  const models = pool?.models ?? [];
  const queuedTasks = pool?.queued_tasks ?? [];
  if (!pool || models.length === 0) {
    return (
      <div className="border-t border-slate-700/60 px-4 py-3 text-xs text-slate-500">
        暂无模型使用数据
      </div>
    );
  }
  const total = models.reduce((sum, model) => sum + model.total, 0);
  const success = models.reduce((sum, model) => sum + model.success, 0);
  return (
    <div className="border-t border-slate-700/60 px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
        <span>运行中 <b className="text-cyan-300">{pool.global_running}</b></span>
        <span>排队 <b className="text-amber-300">{pool.global_queued}</b></span>
        <span>成功 <b className="text-green-300">{success}</b> / {total}</span>
      </div>
      {queuedTasks.length > 0 && (
        <div className="mb-2 grid grid-cols-1 gap-1 sm:grid-cols-2">
          {queuedTasks.map((task, index) => (
            <div
              key={String(task.request_id || index)}
              className="truncate rounded border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-xs text-amber-100"
            >
              {compactTaskLabel(task)}
            </div>
          ))}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[52rem] text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="px-2 py-1 font-medium">模型</th>
              <th className="px-2 py-1 font-medium">能力</th>
              <th className="px-2 py-1 font-medium">可用</th>
              <th className="px-2 py-1 font-medium">运行/上限</th>
              <th className="px-2 py-1 font-medium">成功</th>
              <th className="px-2 py-1 font-medium">失败/超时</th>
              <th className="px-2 py-1 font-medium">平均时间</th>
              <th className="px-2 py-1 font-medium">当前任务</th>
            </tr>
          </thead>
          <tbody>
            {models.map((model) => (
              <AgentModelUsageRow key={model.id} model={model} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AgentModelUsageRow({ model }: { model: OpenCodePoolModelStats }) {
  return (
    <tr className="border-t border-slate-700/50 text-slate-300">
      <td className="px-2 py-1.5">
        <div className="font-medium text-slate-100">{model.id}</div>
        <div className="max-w-40 truncate font-mono text-[11px] text-slate-500">
          {model.model || "(默认模型)"}
        </div>
      </td>
      <td className="px-2 py-1.5">{model.capability || "—"}</td>
      <td className="px-2 py-1.5">
        <span className={model.enabled && model.available ? "text-green-300" : "text-slate-500"}>
          {model.enabled ? (model.available ? "可用" : "时间窗外") : "禁用"}
        </span>
      </td>
      <td className="px-2 py-1.5">{model.running}/{model.max_concurrency}</td>
      <td className="px-2 py-1.5 text-green-300">{model.success}</td>
      <td className="px-2 py-1.5 text-amber-300">{model.failure + model.timeout}</td>
      <td className="px-2 py-1.5">{formatDurationSeconds(model.avg_duration_seconds)}</td>
      <td className="px-2 py-1.5 max-w-64 truncate text-slate-400">
        <ActiveTaskList tasks={model.active_tasks} />
      </td>
    </tr>
  );
}

const inputCls =
  "w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors";

function ModelPoolEditor({
  title,
  models,
  onChange,
  onImport,
}: {
  title: string;
  models: AgentOpenCodeModelConfig[];
  onChange: (models: AgentOpenCodeModelConfig[]) => void;
  onImport?: () => void;
}) {
  const updateAt = (index: number, patch: Partial<AgentOpenCodeModelConfig>) => {
    onChange(models.map((model, i) => (i === index ? { ...model, ...patch } : model)));
  };
  const addModel = () => {
    onChange([...models, { ...DEFAULT_MODEL, id: `model-${models.length + 1}` }]);
  };
  const addDefaultModel = () => {
    onChange([...models, { ...DEFAULT_MODEL, id: "default", use_default_model: true, model: "" }]);
  };
  const removeAt = (index: number) => {
    onChange(models.filter((_, i) => i !== index));
  };
  const addWindow = (index: number) => {
    const current = models[index].time_windows || [];
    updateAt(index, { time_windows: [...current, { start: "09:00", end: "18:00" }] });
  };
  const updateWindow = (modelIndex: number, windowIndex: number, patch: { start?: string; end?: string }) => {
    const current = models[modelIndex].time_windows || [];
    updateAt(modelIndex, {
      time_windows: current.map((window, i) => (i === windowIndex ? { ...window, ...patch } : window)),
    });
  };
  const removeWindow = (modelIndex: number, windowIndex: number) => {
    updateAt(modelIndex, {
      time_windows: (models[modelIndex].time_windows || []).filter((_, i) => i !== windowIndex),
    });
  };

  return (
    <div className="border border-slate-700 rounded-lg p-3 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold text-slate-300">{title}</span>
        <div className="flex gap-2">
          {onImport && (
            <button
              type="button"
              onClick={onImport}
              className="px-2.5 py-1 text-xs text-slate-100 bg-slate-700 hover:bg-slate-600 rounded-md transition-colors"
            >
              从 serve 读取
            </button>
          )}
          <button
            type="button"
            onClick={addDefaultModel}
            className="px-2.5 py-1 text-xs text-slate-100 bg-slate-700 hover:bg-slate-600 rounded-md transition-colors"
          >
            添加默认模型
          </button>
          <button
            type="button"
            onClick={addModel}
            className="px-2.5 py-1 text-xs text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors"
          >
            添加模型
          </button>
        </div>
      </div>
      {models.length === 0 ? (
        <p className="text-xs text-slate-500">未配置模型池时使用兼容的单模型配置；配置后由这里的模型、时间和总并发统一调度。</p>
      ) : (
        <div className="space-y-3">
          {models.map((model, index) => (
            <div key={index} className="grid grid-cols-1 md:grid-cols-12 gap-2 border border-slate-700 rounded-lg p-2">
              <label className="md:col-span-1 flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={model.enabled}
                  onChange={(e) => updateAt(index, { enabled: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                />
                启用
              </label>
              <input
                type="text"
                value={model.id}
                onChange={(e) => updateAt(index, { id: e.target.value })}
                className={`${inputCls} md:col-span-2`}
                placeholder="ID"
              />
              <input
                type="text"
                value={model.model}
                onChange={(e) => updateAt(index, { model: e.target.value, use_default_model: false })}
                disabled={!!model.use_default_model}
                className={`${inputCls} md:col-span-3 disabled:opacity-50`}
                placeholder="模型名"
              />
              <select
                value={model.capability || "high"}
                onChange={(e) => updateAt(index, { capability: e.target.value })}
                className={`${inputCls} md:col-span-2`}
              >
                <option value="low">低能力</option>
                <option value="medium">中能力</option>
                <option value="high">高能力</option>
              </select>
              <input
                type="number"
                value={model.weight}
                onChange={(e) => updateAt(index, { weight: Number(e.target.value) })}
                className={`${inputCls} md:col-span-1`}
                min={0.1}
                step={0.1}
                title="权重"
              />
              <input
                type="number"
                value={model.max_concurrency}
                onChange={(e) => updateAt(index, { max_concurrency: Number(e.target.value) })}
                className={`${inputCls} md:col-span-1`}
                min={1}
                title="单模型并发"
              />
              <button
                type="button"
                onClick={() => removeAt(index)}
                className="md:col-span-2 px-2.5 py-1 text-xs text-red-200 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-md transition-colors"
              >
                删除
              </button>
              <label className="md:col-span-12 flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={!!model.use_default_model}
                  onChange={(e) => updateAt(index, { use_default_model: e.target.checked, model: e.target.checked ? "" : model.model })}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                />
                使用 CLI 默认模型（不传 --model）
              </label>
              <div className="md:col-span-12 grid grid-cols-1 sm:grid-cols-4 gap-2">
                <select
                  value={model.tool || ""}
                  onChange={(e) => updateAt(index, { tool: e.target.value })}
                  className={inputCls}
                >
                  <option value="">继承工具</option>
                  {TOOL_OPTIONS.map((item) => (
                    <option key={item.value} value={item.value}>{item.label}</option>
                  ))}
                </select>
                <input
                  type="text"
                  value={model.executable || ""}
                  onChange={(e) => updateAt(index, { executable: e.target.value })}
                  className={inputCls}
                  placeholder="可执行文件覆盖（可选）"
                />
                <input
                  type="number"
                  value={model.timeout ?? ""}
                  onChange={(e) => updateAt(index, { timeout: e.target.value === "" ? null : Number(e.target.value) })}
                  className={inputCls}
                  min={30}
                  placeholder="超时覆盖"
                />
                <input
                  type="number"
                  value={model.max_retries ?? ""}
                  onChange={(e) => updateAt(index, { max_retries: e.target.value === "" ? null : Number(e.target.value) })}
                  className={inputCls}
                  min={0}
                  max={10}
                  placeholder="重试覆盖"
                />
              </div>
              <div className="md:col-span-12 space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-slate-400">每日使用时间</span>
                  <button
                    type="button"
                    onClick={() => addWindow(index)}
                    className="px-2 py-1 text-xs text-slate-200 bg-slate-700 hover:bg-slate-600 rounded-md transition-colors"
                  >
                    添加时间段
                  </button>
                </div>
                {(model.time_windows || []).length === 0 ? (
                  <p className="text-xs text-slate-500">全天可用</p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {(model.time_windows || []).map((window, windowIndex) => (
                      <div key={windowIndex} className="flex items-center gap-2">
                        <input
                          type="time"
                          value={window.start}
                          onChange={(e) => updateWindow(index, windowIndex, { start: e.target.value })}
                          className={inputCls}
                        />
                        <span className="text-xs text-slate-500">至</span>
                        <input
                          type="time"
                          value={window.end}
                          onChange={(e) => updateWindow(index, windowIndex, { end: e.target.value })}
                          className={inputCls}
                        />
                        <button
                          type="button"
                          onClick={() => removeWindow(index, windowIndex)}
                          className="px-2 py-1 text-xs text-red-200 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-md transition-colors"
                        >
                          删除
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-300 mb-1">
        {label}
        {hint && <span className="ml-1 text-slate-500 font-normal">— {hint}</span>}
      </label>
      {children}
    </div>
  );
}

export default function AgentDownload({ onBack }: Props) {
  const [downloading, setDownloading] = useState(false);
  const [agents, setAgents] = useState<AgentInfo[]>([]);

  useEffect(() => {
    const refresh = () => getAgents().then(setAgents).catch(() => {});
    refresh();
    // 页面不可见时跳过轮询，重新可见时立即刷新
    const id = setInterval(() => {
      if (document.visibilityState === "hidden") return;
      refresh();
    }, 10000);
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") refresh();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const token = localStorage.getItem("auth_token");
      const resp = await fetch("/api/agent/download", {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "opendeephole-agent.zip";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(`下载失败：${e}`);
    } finally {
      setDownloading(false);
    }
  };

  const origin = window.location.origin;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-gray-100">
      <div className="max-w-5xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={onBack}
            className="text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1 text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            返回
          </button>
          <h1 className="text-xl font-bold text-white">客户端</h1>
        </div>

        {/* 已连接 Agent */}
        <div className="mb-6">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">已连接 Agent</h2>
          {agents.length === 0 ? (
            <div className="bg-slate-800/40 border border-slate-700 rounded-xl px-5 py-4 text-sm text-slate-500">
              暂无 Agent 连接到本服务器。下载并启动 Agent 后，它将自动出现在这里。
            </div>
          ) : (
            <div className="space-y-2">
              {agents.map((a) => (
                <AgentConfigPanel key={a.agent_id} agent={a} />
              ))}
            </div>
          )}
        </div>

        {/* 简介 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <p className="text-slate-300 text-sm leading-relaxed">
            Agent 是运行在你本地机器上的常驻服务程序。启动后向本服务器注册，由 Web 端「新建扫描」下发任务，在本地执行代码索引、静态分析和 AI 审计，仅将漏洞结果回传到服务端展示。<span className="text-slate-400">源代码始终不离开本机。</span>
          </p>
        </div>

        {/* 第一步：下载 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">1</span>
            下载安装包
          </h2>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm"
          >
            {downloading ? "正在下载..." : "下载 opendeephole-agent.zip"}
          </button>
          <p className="text-slate-500 text-xs mt-3">
            解压后即可使用，无需编译。需要 Python 3.10+。下载包中 <code className="text-blue-400">agent.yaml</code> 已自动填入本服务器地址 <code className="text-blue-400">{origin}</code>。
          </p>
        </div>

        {/* 第二步：启动 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">2</span>
            启动 Agent 守护进程
          </h2>

          <div className="mb-4">
            <p className="text-slate-400 text-xs mb-2 font-medium uppercase tracking-wide">Linux / macOS</p>
            <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-green-400 overflow-x-auto">{`chmod +x run_agent.sh
./run_agent.sh`}</pre>
          </div>

          <div className="mb-5">
            <p className="text-slate-400 text-xs mb-2 font-medium uppercase tracking-wide">Windows</p>
            <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-green-400 overflow-x-auto">{`run_agent.bat`}</pre>
          </div>

          <p className="text-slate-400 text-sm mb-2">启动成功后，Agent 自动注册到本服务器，终端输出类似：</p>
          <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-400 overflow-x-auto">{`OpenDeepHole Agent Daemon
  Name    : my-agent
  Server  : ${origin}

Connecting to ws://.../api/agent/ws ...
  Connected. Agent ID: a1b2c3d4...`}</pre>

          <p className="text-slate-400 text-xs mt-3">
            可选：在 <code className="text-blue-400">agent.yaml</code> 中修改 <code className="text-blue-400">agent_name</code>（显示名称）。LLM API 等其他配置可在此页面直接配置，无需手动编辑文件。
          </p>
        </div>

        {/* 第三步：配置 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">3</span>
            在此页面配置 Agent
          </h2>
          <p className="text-slate-300 text-sm mb-2">
            Agent 启动并连接后，会在顶部「已连接 Agent」列表中出现。点击对应 Agent 的「配置」按钮，填写 LLM API Key 等信息并保存。
          </p>
          <p className="text-slate-400 text-sm">
            保存后会立即推送到在线 Agent 并写回 agent.yaml。正在运行的扫描会从下一个候选点开始使用新配置。
          </p>
        </div>

        {/* 第四步：新建扫描 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">4</span>
            在 Web 端创建扫描任务
          </h2>
          <ol className="text-slate-300 text-sm space-y-2 list-none">
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">①</span>点击右上角「新建扫描」</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">②</span>从下拉列表选择已在线的 Agent</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">③</span>填写代码路径（Agent 所在机器上的绝对路径，如 <code className="text-blue-400 text-xs">/home/user/myproject</code>）</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">④</span>选择要运行的检查项，点击「开始扫描」</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">⑤</span>扫描进度实时显示在当前页面</li>
          </ol>
        </div>

        {/* 停止与续扫 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-3">停止与续扫</h2>
          <div className="space-y-3 text-sm">
            <div className="flex gap-3">
              <span className="text-red-400 font-medium shrink-0">停止</span>
              <span className="text-slate-300">扫描列表页或详情页点击「停止」，Server 直接通知 Agent 停止，已处理的结果和任务记录会保留。</span>
            </div>
            <div className="flex gap-3">
              <span className="text-amber-400 font-medium shrink-0">续扫</span>
              <span className="text-slate-300">扫描列表页或详情页点击「续扫」，会同时继续未扫描任务并重试静态候选、威胁审计中的失败任务。</span>
            </div>
          </div>
        </div>

        {/* 误报反馈 */}
        <div className="bg-blue-950/30 border border-blue-800/40 rounded-xl p-4">
          <p className="text-blue-300 text-sm leading-relaxed">
            <span className="font-semibold">误报反馈同步：</span>在 Web 端将某个漏洞标记为「误报」后，Agent 下次扫描时会自动拉取这些经验数据，合并到分析技能中，从而减少相同误报的出现。
          </p>
        </div>
      </div>
    </div>
  );
}
