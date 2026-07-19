import { useEffect, useMemo, useRef, useState } from "react";
import {
  getAgentConfig,
  getAgentMcpStatus,
  getAgentOpenCodeModels,
  getAgentOpenCodePool,
  getAgents,
  getAgentValidatorCatalog,
  probeAgentMcp,
  reloadAgentMcp,
  updateAgentConfig,
} from "../api/client";
import type {
  AgentInfo,
  AgentMcpConfig,
  AgentMcpStatusResponse,
  AgentMcpTarget,
  AgentMcpTargetStatus,
  AgentModelTimeWindow,
  AgentModelTaskPolicy,
  AgentOpenCodeModelConfig,
  AgentOpenCodeModelListItem,
  AgentOpenCodePoolStatus,
  AgentRemoteConfig,
  AgentValidationEnvironmentConfig,
  AgentValidatorCatalog,
  AgentValidatorField,
} from "../types";

interface Props { onBack: () => void }
type Section = "base" | "models" | "threat" | "codegraph" | "product" | "mining" | "fp" | "validation";

const sections: { id: Section; label: string }[] = [
  { id: "base", label: "基础配置" },
  { id: "models", label: "模型配置" },
  { id: "threat", label: "威胁分析" },
  { id: "codegraph", label: "代码图谱" },
  { id: "product", label: "产品信息" },
  { id: "mining", label: "漏洞挖掘" },
  { id: "fp", label: "去误报" },
  { id: "validation", label: "漏洞验证" },
];

const policy = (required_capability = "high", max_retries = 2): AgentModelTaskPolicy => ({
  required_capability, timeout_seconds: 1200, max_retries,
});
const mcp = (name: string): AgentMcpConfig => ({
  enabled: false, name, transport: "local", timeout_seconds: 300,
  local: { executable: name, args: [], environment: {} },
  remote: { url: "", headers: {} },
});
const emptyMcpRuntime = () => ({
  state: "unknown", config_fingerprint: "", updated_at: "", error: "",
  loaded_directories: 0, total_directories: 0,
});
const defaultConfig = (): AgentRemoteConfig => ({
  schema_version: 2,
  base: { tool: "nga", executable: "nga", no_proxy: "10.0.0.0/8" },
  model_pool: { global_concurrency: 4, models: [] },
  threat_analysis: { enabled: true, attack_path_audit_mode: "after_analysis", model_policy: policy("high", 3) },
  code_graph: {
    ...mcp("codegraph"),
    local: {
      executable: "codegraph", args: ["serve", "--mcp"],
      environment: { CODEGRAPH_MCP_TOOLS: "explore,node,search,callers,callees,impact,files,status" },
    },
  },
  product_info: mcp("product-info"),
  vulnerability_mining: policy("any"),
  false_positive: policy("high"),
  vulnerability_validation: { environments: {} },
});

const input = "w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";
const parsePairs = (text: string) => Object.fromEntries(text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
  const index = line.indexOf("=");
  return index < 0 ? [line, ""] : [line.slice(0, index).trim(), line.slice(index + 1).trim()];
}));
const pairsText = (value: Record<string, string>) => Object.entries(value).map(([key, item]) => `${key}=${item}`).join("\n");
const weekdays = [
  { value: 1, label: "周一" },
  { value: 2, label: "周二" },
  { value: 3, label: "周三" },
  { value: 4, label: "周四" },
  { value: 5, label: "周五" },
  { value: 6, label: "周六" },
  { value: 7, label: "周日" },
];
const allWeekdays = weekdays.map((item) => item.value);
const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;

function configuredWeekdays(window: AgentModelTimeWindow): number[] {
  return Array.isArray(window.weekdays) ? window.weekdays : allWeekdays;
}

function validateModelTimeWindows(config: AgentRemoteConfig): string {
  for (const model of config.model_pool.models) {
    for (const window of model.time_windows || []) {
      if (configuredWeekdays(window).length === 0) return `模型 ${model.id || "未命名"} 的每个使用时间段至少要选择一天`;
      if (!timePattern.test(window.start) || !timePattern.test(window.end)) return `模型 ${model.id || "未命名"} 的使用时间必须为 HH:MM-HH:MM`;
      if (window.start === window.end) return `模型 ${model.id || "未命名"} 的使用时间起止不能相同`;
    }
  }
  return "";
}

function PolicyEditor({ value, onChange }: { value: AgentModelTaskPolicy; onChange: (value: AgentModelTaskPolicy) => void }) {
  return <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
    <Field label="需要的模型能力"><select className={input} value={value.required_capability} onChange={(e) => onChange({ ...value, required_capability: e.target.value })}>
      <option value="any">任意能力</option><option value="low">低能力</option><option value="medium">中能力</option><option value="high">高能力</option>
    </select></Field>
    <Field label="模型调用超时（秒）"><input className={input} type="number" min={1} value={value.timeout_seconds} onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="模型调用重试次数"><input className={input} type="number" min={0} value={value.max_retries} onChange={(e) => onChange({ ...value, max_retries: Number(e.target.value) })} /></Field>
  </div>;
}

function StatusBadge({ label, tone = "slate" }: { label: string; tone?: "slate" | "green" | "red" | "amber" | "blue" }) {
  const colors = {
    slate: "border-slate-600 bg-slate-700/40 text-slate-200",
    green: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    red: "border-red-500/40 bg-red-500/10 text-red-200",
    amber: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    blue: "border-blue-500/40 bg-blue-500/10 text-blue-200",
  };
  return <span className={`rounded-full border px-2.5 py-1 text-xs ${colors[tone]}`}>{label}</span>;
}

interface HeaderRow { id: number; name: string; value: string }
let headerRowId = 0;
const newHeaderRow = (name = "", value = ""): HeaderRow => ({ id: ++headerRowId, name, value });
const sensitiveHeader = (name: string) => /(authorization|token|secret|api[-_]?key|cookie)/i.test(name);

function HeaderEditor({ value, onChange }: { value: Record<string, string>; onChange: (value: Record<string, string>) => void }) {
  const [rows, setRows] = useState<HeaderRow[]>(() => Object.entries(value).map(([name, item]) => newHeaderRow(name, item)));
  const [revealed, setRevealed] = useState<Set<number>>(new Set());
  const committed = useRef(JSON.stringify(value));
  const serialized = JSON.stringify(value);

  useEffect(() => {
    if (serialized === committed.current) return;
    committed.current = serialized;
    setRows(Object.entries(value).map(([name, item]) => newHeaderRow(name, item)));
    setRevealed(new Set());
  }, [serialized, value]);

  const commit = (next: HeaderRow[]) => {
    setRows(next);
    const headers: Record<string, string> = {};
    const canonicalNames = new Map<string, string>();
    for (const row of next) {
      const name = row.name.trim();
      if (!name) continue;
      const lowered = name.toLowerCase();
      const previous = canonicalNames.get(lowered);
      if (previous) delete headers[previous];
      headers[name] = row.value;
      canonicalNames.set(lowered, name);
    }
    committed.current = JSON.stringify(headers);
    onChange(headers);
  };
  const normalizedNames = rows.map((row) => row.name.trim().toLowerCase()).filter(Boolean);
  const hasDuplicates = new Set(normalizedNames).size !== normalizedNames.length;

  return <div className="space-y-3">
    {rows.map((row) => {
      const hidden = sensitiveHeader(row.name) && !revealed.has(row.id);
      return <div key={row.id} className="grid gap-2 sm:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)_auto_auto]">
        <input
          className={input}
          placeholder="Authorization"
          value={row.name}
          onChange={(e) => commit(rows.map((item) => item.id === row.id ? { ...item, name: e.target.value } : item))}
        />
        <input
          className={input}
          type={hidden ? "password" : "text"}
          placeholder={row.name.toLowerCase() === "authorization" ? "Bearer test-secret-123" : "请求头值"}
          value={row.value}
          onChange={(e) => commit(rows.map((item) => item.id === row.id ? { ...item, value: e.target.value } : item))}
        />
        {sensitiveHeader(row.name) && <button
          type="button"
          className="rounded-lg border border-slate-600 px-3 py-2 text-xs text-slate-300"
          onClick={() => setRevealed((current) => {
            const next = new Set(current);
            if (next.has(row.id)) next.delete(row.id); else next.add(row.id);
            return next;
          })}
        >{hidden ? "显示" : "隐藏"}</button>}
        <button
          type="button"
          className="rounded-lg border border-red-500/40 px-3 py-2 text-xs text-red-300"
          onClick={() => commit(rows.filter((item) => item.id !== row.id))}
        >删除</button>
      </div>;
    })}
    <button type="button" className="rounded-lg border border-slate-600 px-3 py-2 text-xs text-slate-300" onClick={() => setRows([...rows, newHeaderRow()])}>添加请求头</button>
    {hasDuplicates && <p className="text-xs text-red-300">请求头名称重复（不区分大小写）；保存时同名项只会保留最后一个，请删除或改名。</p>}
    <p className="text-xs text-slate-500">目前支持静态请求头认证。例如：名称填写 Authorization，值填写 Bearer test-secret-123。敏感值默认隐藏。</p>
  </div>;
}

function probeTime(value: string): string {
  if (!value) return "";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function McpEditor({
  value, onChange, status, online, unsaved, probing, reloading, busy, onProbe, onReload,
}: {
  value: AgentMcpConfig;
  onChange: (value: AgentMcpConfig) => void;
  status: AgentMcpTargetStatus | null;
  online: boolean;
  unsaved: boolean;
  probing: boolean;
  reloading: boolean;
  busy: boolean;
  onProbe: () => void;
  onReload: () => void;
}) {
  const lastProbe = status?.last_probe;
  const connectivity = probing
    ? { label: "检测中", tone: "blue" as const }
    : !lastProbe
      ? { label: "未检测", tone: "slate" as const }
      : status?.stale
        ? { label: "已过期", tone: "amber" as const }
        : lastProbe.success
          ? { label: "可用", tone: "green" as const }
          : { label: "不可用", tone: "red" as const };
  const runtime = status?.runtime;
  const runtimeDisplay: Record<string, { label: string; tone: "slate" | "green" | "red" | "amber" | "blue" }> = {
    connected: { label: "OpenCode 已连接", tone: "green" },
    applying: { label: "正在热加载", tone: "blue" },
    failed: { label: "热加载失败", tone: "red" },
    needs_auth: { label: "需要认证", tone: "red" },
    needs_client_registration: { label: "需要 OAuth 客户端", tone: "red" },
    disabled: { label: "OpenCode 已停用", tone: "slate" },
    next_session: { label: "下个 Session 加载", tone: "amber" },
    offline: { label: "Agent 离线", tone: "amber" },
    unknown: { label: "运行状态未知", tone: "slate" },
  };
  const runtimeBadge = runtimeDisplay[runtime?.state || "unknown"] || runtimeDisplay.unknown;
  const disabledReason = !online
    ? "Agent 离线"
    : !value.enabled
      ? "请先启用并保存 MCP"
      : unsaved
        ? "当前 MCP 配置有未保存修改"
        : busy
          ? "正在处理 MCP"
          : "";
  return <div className="space-y-5">
    <div className="space-y-4 rounded-xl border border-slate-700 bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge label={value.enabled ? "配置已启用" : "配置已禁用"} tone={value.enabled ? "green" : "slate"} />
        <StatusBadge label={connectivity.label} tone={connectivity.tone} />
        <StatusBadge label={online ? "Agent 在线" : "Agent 离线"} tone={online ? "green" : "amber"} />
        <StatusBadge label={runtimeBadge.label} tone={runtimeBadge.tone} />
        {!online && lastProbe && <StatusBadge label="历史结果" tone="amber" />}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1 text-xs text-slate-400">
          <p>检测只执行 MCP 握手和工具发现，不会调用业务工具。</p>
          {lastProbe && <p>最近检测：{probeTime(lastProbe.checked_at)} · {lastProbe.duration_ms} ms{lastProbe.protocol ? ` · ${lastProbe.protocol}` : ""}</p>}
          {(runtime?.total_directories || 0) > 0 && <p>已在 {runtime?.loaded_directories || 0}/{runtime?.total_directories || 0} 个 OpenCode 工作目录加载。</p>}
          {runtime?.state === "next_session" && <p>当前没有可更新的运行目录；下一次新建或续用 Session 会在工具发现前加载。</p>}
          {unsaved && <p className="text-amber-300">当前 MCP 表单有未保存修改，请先保存再检测。</p>}
          {!unsaved && status?.stale && <p className="text-amber-300">已保存的 MCP 配置已变更，上次结果仅供参考，请重新检测。</p>}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onProbe}
            disabled={Boolean(disabledReason)}
            title={disabledReason}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >{probing ? "检测中…" : lastProbe ? "重新检测" : "检测连接"}</button>
          <button
            type="button"
            onClick={onReload}
            disabled={Boolean(disabledReason)}
            title={disabledReason}
            className="rounded-lg border border-blue-500/50 px-4 py-2 text-sm font-medium text-blue-200 disabled:cursor-not-allowed disabled:border-slate-700 disabled:text-slate-500"
          >{reloading ? "重载中…" : "重新加载"}</button>
        </div>
      </div>
      {lastProbe && lastProbe.tool_count > 0 && <div className="text-xs text-slate-300">
        <span className="font-medium text-slate-200">发现 {lastProbe.tool_count} 个工具：</span>
        <span className="break-words">{lastProbe.tool_names.join("、")}</span>
      </div>}
      {lastProbe?.error && <div className="break-words rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">{lastProbe.error}</div>}
      {runtime?.error && <div className="break-words rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">OpenCode：{runtime.error}</div>}
    </div>
    <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={value.enabled} onChange={(e) => onChange({ ...value, enabled: e.target.checked })} />启用 MCP</label>
    <div className="grid gap-4 md:grid-cols-3">
      <Field label="MCP 名称"><input className={input} value={value.name} onChange={(e) => onChange({ ...value, name: e.target.value })} /></Field>
      <Field label="连接方式"><select className={input} value={value.transport} onChange={(e) => onChange({ ...value, transport: e.target.value })}><option value="local">本地进程</option><option value="remote">远端服务</option></select></Field>
      <Field label="连接超时（秒）"><input className={input} type="number" min={1} value={value.timeout_seconds} onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    </div>
    {value.transport === "local" ? <div className="grid gap-4 md:grid-cols-2">
      <Field label="可执行文件"><input className={input} value={value.local.executable} onChange={(e) => onChange({ ...value, local: { ...value.local, executable: e.target.value } })} /></Field>
      <Field label="启动参数（每行一个）"><textarea className={input} rows={4} value={value.local.args.join("\n")} onChange={(e) => onChange({ ...value, local: { ...value.local, args: e.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) } })} /></Field>
      <Field label="环境变量（KEY=VALUE）"><textarea className={input} rows={5} value={pairsText(value.local.environment)} onChange={(e) => onChange({ ...value, local: { ...value.local, environment: parsePairs(e.target.value) } })} /></Field>
    </div> : <div className="grid gap-4 md:grid-cols-2">
      <Field label="远端 URL（支持 IP/主机名）"><input className={input} value={value.remote.url} placeholder="http://10.0.0.8:9000/mcp" onChange={(e) => onChange({ ...value, remote: { ...value.remote, url: e.target.value } })} /></Field>
      <Field label="请求头与认证"><HeaderEditor value={value.remote.headers} onChange={(headers) => onChange({ ...value, remote: { ...value.remote, headers } })} /></Field>
    </div>}
  </div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-300">{label}{hint && <span className="ml-1 font-normal text-slate-500">— {hint}</span>}</span>{children}</label>;
}

function DynamicField({ schema, value, onChange }: { schema: AgentValidatorField; value: unknown; onChange: (value: unknown) => void }) {
  if (schema.type === "boolean") return <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />{schema.label}</label>;
  if (schema.type === "select") return <Field label={schema.label} hint={schema.help}><select className={input} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>{!schema.required && <option value="">未配置</option>}{schema.options.map((option) => <option key={String(option)} value={String(option)}>{String(option)}</option>)}</select></Field>;
  const type = schema.type === "integer" || schema.type === "number" ? "number" : schema.type === "secret" ? "password" : "text";
  return <Field label={`${schema.label}${schema.required ? " *" : ""}`} hint={schema.help}><input className={input} type={type} min={schema.min ?? undefined} max={schema.max ?? undefined} step={schema.type === "number" ? "any" : undefined} placeholder={schema.placeholder} value={String(value ?? "")} onChange={(e) => onChange(type === "number" && e.target.value !== "" ? Number(e.target.value) : e.target.value)} /></Field>;
}

export default function AgentConfigPage({ onBack }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [agentKey, setAgentKey] = useState("");
  const [section, setSection] = useState<Section>("base");
  const [config, setConfig] = useState<AgentRemoteConfig>(defaultConfig);
  const [savedConfig, setSavedConfig] = useState<AgentRemoteConfig>(defaultConfig);
  const [catalog, setCatalog] = useState<AgentValidatorCatalog>({ registrations: [], errors: [], updated_at: "" });
  const [pool, setPool] = useState<AgentOpenCodePoolStatus | null>(null);
  const [mcpStatus, setMcpStatus] = useState<AgentMcpStatusResponse | null>(null);
  const [probingTarget, setProbingTarget] = useState<AgentMcpTarget | null>(null);
  const [reloadingTarget, setReloadingTarget] = useState<AgentMcpTarget | null>(null);
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [modelPicker, setModelPicker] = useState<{
    agentId: string;
    loading: boolean;
    error: string | null;
    message: string | null;
    models: AgentOpenCodeModelListItem[];
    selected: string[];
  } | null>(null);

  const selectedAgent = agents.find((agent) => agent.agent_key === agentKey);
  const setCfg = (next: AgentRemoteConfig) => { setConfig(next); setDirty(true); setMessage(""); };

  useEffect(() => {
    getAgents().then((items) => {
      setAgents(items);
      const first = items.find((item) => item.online) || items[0];
      if (first) setAgentKey(first.agent_key);
      else setLoading(false);
    }).catch(() => { setMessage("加载 Agent 列表失败"); setLoading(false); });
  }, []);

  useEffect(() => {
    if (!agentKey) return;
    setLoading(true);
    setMcpStatus(null);
    Promise.all([getAgentConfig(agentKey), getAgentValidatorCatalog(agentKey), getAgentMcpStatus(agentKey)]).then(([next, nextCatalog, nextMcpStatus]) => {
      setConfig(next); setSavedConfig(next); setCatalog(nextCatalog); setMcpStatus(nextMcpStatus); setDirty(false); setMessage("");
      const live = agents.find((item) => item.agent_key === agentKey && item.online);
      if (live) getAgentOpenCodePool(live.agent_id).then(setPool).catch(() => setPool(null)); else setPool(null);
    }).catch(() => setMessage("加载 Agent 配置失败")).finally(() => setLoading(false));
  }, [agentKey, agents]);

  useEffect(() => {
    if (!agentKey || !selectedAgent?.online || !["codegraph", "product"].includes(section)) return;
    let disposed = false;
    let timer = 0;
    const refresh = async () => {
      try {
        const next = await getAgentMcpStatus(agentKey);
        if (!disposed) setMcpStatus(next);
      }
      catch { /* Keep the last observable state during a transient disconnect. */ }
      if (!disposed) timer = window.setTimeout(refresh, 3000);
    };
    timer = window.setTimeout(refresh, 3000);
    return () => { disposed = true; window.clearTimeout(timer); };
  }, [agentKey, section, selectedAgent?.online]);

  const switchAgent = (next: string) => {
    if (dirty && !window.confirm("当前 Agent 的修改尚未保存，确定切换吗？")) return;
    setAgentKey(next);
  };
  const save = async () => {
    if (!agentKey) return;
    const timeWindowError = validateModelTimeWindows(config);
    if (timeWindowError) { setMessage(timeWindowError); return; }
    setSaving(true); setMessage("");
    try {
      const mcpChanged = JSON.stringify(config.code_graph) !== JSON.stringify(savedConfig.code_graph)
        || JSON.stringify(config.product_info) !== JSON.stringify(savedConfig.product_info);
      await updateAgentConfig(agentKey, config);
      setSavedConfig(config); setDirty(false);
      getAgentMcpStatus(agentKey).then(setMcpStatus).catch(() => undefined);
      setMessage(selectedAgent?.online
        ? (mcpChanged ? "配置已保存，Agent 正在热加载 MCP" : "配置已保存并推送到 Agent")
        : "配置已保存，将在 Agent 重连后生效");
    }
    catch (error: any) { setMessage(error?.response?.data?.detail || "保存失败"); }
    finally { setSaving(false); }
  };

  const probeMcp = async (target: AgentMcpTarget) => {
    if (!agentKey || probingTarget) return;
    setProbingTarget(target); setMessage("");
    try {
      const result = await probeAgentMcp(agentKey, target);
      setMcpStatus((current): AgentMcpStatusResponse => {
        const base = current || {
          agent_key: agentKey,
          online: true,
          code_graph: { enabled: savedConfig.code_graph.enabled, stale: false, last_probe: null, runtime: emptyMcpRuntime() },
          product_info: { enabled: savedConfig.product_info.enabled, stale: false, last_probe: null, runtime: emptyMcpRuntime() },
        };
        const existing = target === "code_graph" ? base.code_graph : base.product_info;
        const targetStatus = { enabled: target === "code_graph" ? savedConfig.code_graph.enabled : savedConfig.product_info.enabled, stale: false, last_probe: result, runtime: existing.runtime };
        return target === "code_graph"
          ? { ...base, online: true, code_graph: targetStatus }
          : { ...base, online: true, product_info: targetStatus };
      });
      setMessage(result.success ? `MCP 检测成功，发现 ${result.tool_count} 个工具` : `MCP 检测失败：${result.error}`);
    } catch (error: any) {
      setMessage(error?.response?.data?.detail || "MCP 检测请求失败");
    } finally {
      setProbingTarget(null);
    }
  };

  const reloadMcp = async (target: AgentMcpTarget) => {
    if (!agentKey || probingTarget || reloadingTarget) return;
    setReloadingTarget(target); setMessage("");
    try {
      await reloadAgentMcp(agentKey, target);
      setMessage("已提交 MCP 重新加载请求");
      window.setTimeout(() => getAgentMcpStatus(agentKey).then(setMcpStatus).catch(() => undefined), 500);
    } catch (error: any) {
      setMessage(error?.response?.data?.detail || "MCP 重新加载失败");
    } finally {
      setReloadingTarget(null);
    }
  };

  const openModelPicker = async (refresh = false) => {
    if (!selectedAgent?.online) return;
    const agentId = selectedAgent.agent_id;
    setModelPicker({
      agentId,
      loading: true,
      error: null,
      message: null,
      models: [],
      selected: [],
    });
    try {
      const result = await getAgentOpenCodeModels(agentId, refresh);
      if (!result.ok) throw new Error(result.message || "读取模型失败");
      setModelPicker((current) => current?.agentId === agentId ? {
        ...current,
        loading: false,
        message: result.message.trim() || null,
        models: result.models,
        selected: [],
      } : current);
    } catch (error) {
      setModelPicker((current) => current?.agentId === agentId ? {
        ...current,
        loading: false,
        error: error instanceof Error ? error.message : "读取模型失败",
      } : current);
    }
  };

  const togglePickedModel = (id: string) => {
    setModelPicker((current) => {
      if (!current) return current;
      return {
        ...current,
        selected: current.selected.includes(id)
          ? current.selected.filter((item) => item !== id)
          : [...current.selected, id],
      };
    });
  };

  const importPickedModels = () => {
    if (!modelPicker) return;
    const selected = new Set(modelPicker.selected);
    const existing = new Set(config.model_pool.models.map((item) => item.model));
    const ids = new Set(config.model_pool.models.map((item) => item.id));
    const added: AgentOpenCodeModelConfig[] = [];
    for (const item of modelPicker.models) {
      if (!selected.has(item.id)) continue;
      const model = item.model || item.id;
      if (!model || existing.has(model)) continue;
      const base = item.id || `serve-${config.model_pool.models.length + added.length + 1}`;
      let id = base;
      let suffix = 2;
      while (ids.has(id)) {
        id = `${base}-${suffix}`;
        suffix += 1;
      }
      existing.add(model);
      ids.add(id);
      added.push({
        id, model, capability: "high", weight: 1,
        max_concurrency: 1, enabled: true, tool: "", executable: "",
        timeout: null, max_retries: null, time_windows: [],
      });
    }
    setCfg({ ...config, model_pool: { ...config.model_pool, models: [...config.model_pool.models, ...added] } });
    setMessage(`从 serve 添加了 ${added.length} 个模型`);
    setModelPicker(null);
  };

  const environments = useMemo(() => Array.from(new Set([
    ...catalog.registrations.map((item) => item.environment),
    ...Object.keys(config.vulnerability_validation.environments),
  ])).sort(), [catalog, config.vulnerability_validation.environments]);
  const envConfig = (name: string): AgentValidationEnvironmentConfig => config.vulnerability_validation.environments[name] || {
    supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0,
    model_policy: policy("high"), methods: {},
  };
  const updateEnvironment = (name: string, value: AgentValidationEnvironmentConfig) => setCfg({
    ...config, vulnerability_validation: { environments: { ...config.vulnerability_validation.environments, [name]: value } },
  });

  return <div className="min-h-screen bg-slate-900 text-white">
    <header className="border-b border-slate-700 bg-slate-800/90 px-6 py-4">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4">
        <button onClick={onBack} className="text-sm text-slate-400 hover:text-white">← 返回</button>
        <h1 className="text-lg font-bold">Agent 配置</h1>
        <select disabled={probingTarget !== null || reloadingTarget !== null} className={`${input} ml-auto max-w-md disabled:cursor-not-allowed disabled:opacity-60`} value={agentKey} onChange={(e) => switchAgent(e.target.value)}>
          {!agents.length && <option value="">暂无 Agent</option>}
          {agents.map((agent) => <option key={agent.agent_key} value={agent.agent_key}>{agent.machine_name || agent.name} / {agent.ip} / {agent.online ? "在线" : "离线"}</option>)}
        </select>
        <button disabled={!dirty || saving || probingTarget !== null || reloadingTarget !== null} onClick={save} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium disabled:bg-slate-700">{saving ? "保存中…" : "保存配置"}</button>
      </div>
      {message && <p className="mx-auto mt-3 max-w-7xl text-sm text-amber-300">{message}</p>}
    </header>
    <main className="mx-auto flex max-w-7xl gap-6 px-6 py-6">
      <nav className="w-44 shrink-0 space-y-1">{sections.map((item) => <button key={item.id} onClick={() => setSection(item.id)} className={`w-full rounded-lg px-4 py-2.5 text-left text-sm ${section === item.id ? "bg-blue-600 text-white" : "text-slate-300 hover:bg-slate-800"}`}>{item.label}</button>)}</nav>
      <section className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-800/60 p-6">
        {loading ? <p className="text-slate-400">加载中…</p> : !agentKey ? <p className="text-slate-400">请先启动或注册 Agent。</p> : <>
          <h2 className="mb-6 text-lg font-semibold">{sections.find((item) => item.id === section)?.label}</h2>
          {section === "base" && <div className="grid gap-5 md:grid-cols-2">
            <Field label="工具"><select className={input} value={config.base.tool} onChange={(e) => setCfg({ ...config, base: { ...config.base, tool: e.target.value } })}><option value="nga">nga</option><option value="opencode">opencode</option></select></Field>
            <Field label="工具可执行文件名或完整路径"><input className={input} value={config.base.executable} onChange={(e) => setCfg({ ...config, base: { ...config.base, executable: e.target.value } })} /></Field>
            <Field label="代理跳过列表" hint="逗号分隔"><textarea className={input} rows={4} value={config.base.no_proxy} onChange={(e) => setCfg({ ...config, base: { ...config.base, no_proxy: e.target.value } })} /></Field>
          </div>}
          {section === "models" && <ModelEditor config={config} setCfg={setCfg} online={Boolean(selectedAgent?.online)} onImport={() => void openModelPicker()} pool={pool} />}
          {section === "threat" && <div className="space-y-5"><label className="flex gap-2 text-sm"><input type="checkbox" checked={config.threat_analysis.enabled} onChange={(e) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, enabled: e.target.checked } })} />启用威胁分析</label><Field label="攻击路径审计模式"><select className={input} value={config.threat_analysis.attack_path_audit_mode} onChange={(e) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, attack_path_audit_mode: e.target.value } })}><option value="after_analysis">分析完成后审计</option><option value="immediate">生成后立即审计</option></select></Field><PolicyEditor value={config.threat_analysis.model_policy} onChange={(value) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, model_policy: value } })} /></div>}
          {section === "codegraph" && <McpEditor value={config.code_graph} onChange={(value) => setCfg({ ...config, code_graph: value })} status={mcpStatus?.code_graph || null} online={Boolean(mcpStatus?.online)} unsaved={JSON.stringify(config.code_graph) !== JSON.stringify(savedConfig.code_graph)} probing={probingTarget === "code_graph"} reloading={reloadingTarget === "code_graph"} busy={probingTarget !== null || reloadingTarget !== null} onProbe={() => probeMcp("code_graph")} onReload={() => reloadMcp("code_graph")} />}
          {section === "product" && <McpEditor value={config.product_info} onChange={(value) => setCfg({ ...config, product_info: value })} status={mcpStatus?.product_info || null} online={Boolean(mcpStatus?.online)} unsaved={JSON.stringify(config.product_info) !== JSON.stringify(savedConfig.product_info)} probing={probingTarget === "product_info"} reloading={reloadingTarget === "product_info"} busy={probingTarget !== null || reloadingTarget !== null} onProbe={() => probeMcp("product_info")} onReload={() => reloadMcp("product_info")} />}
          {section === "mining" && <PolicyEditor value={config.vulnerability_mining} onChange={(value) => setCfg({ ...config, vulnerability_mining: value })} />}
          {section === "fp" && <PolicyEditor value={config.false_positive} onChange={(value) => setCfg({ ...config, false_positive: value })} />}
          {section === "validation" && <div className="space-y-6">{catalog.errors.length > 0 && <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{catalog.errors.join("；")}</div>}{environments.length === 0 ? <p className="text-sm text-slate-400">该 Agent 未安装有效的 validator.yaml。</p> : environments.map((name) => {
            const value = envConfig(name); const registrations = catalog.registrations.filter((item) => item.environment === name);
            return <div key={name} className="space-y-5 rounded-xl border border-slate-700 p-5"><h3 className="font-semibold text-blue-300">{name}</h3><div className="grid gap-4 md:grid-cols-3"><Field label="支持的漏洞类型" hint="逗号分隔，* 表示全部"><input className={input} value={value.supported_vulnerability_types.join(", ")} onChange={(e) => updateEnvironment(name, { ...value, supported_vulnerability_types: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></Field><Field label="同时验证数量"><input className={input} type="number" min={1} value={value.concurrency} onChange={(e) => updateEnvironment(name, { ...value, concurrency: Number(e.target.value) })} /></Field><Field label="整体验证重试次数"><input className={input} type="number" min={0} value={value.validation_max_retries} onChange={(e) => updateEnvironment(name, { ...value, validation_max_retries: Number(e.target.value) })} /></Field></div><PolicyEditor value={value.model_policy} onChange={(next) => updateEnvironment(name, { ...value, model_policy: next })} />{registrations.map((registration) => <div key={registration.registration_key} className="rounded-lg bg-slate-900/70 p-4"><h4 className="mb-4 text-sm font-medium">{registration.method_label} · {registration.product}</h4><div className="grid gap-4 md:grid-cols-2">{registration.fields.map((field) => <DynamicField key={field.key} schema={field} value={value.methods[registration.registration_key]?.[field.key] ?? field.default} onChange={(next) => updateEnvironment(name, { ...value, methods: { ...value.methods, [registration.registration_key]: { ...(value.methods[registration.registration_key] || {}), [field.key]: next } } })} />)}</div></div>)}</div>;
          })}</div>}
        </>}
      </section>
    </main>
    {modelPicker && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-xl">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-white">从 serve 导入模型</h3>
          <button type="button" onClick={() => setModelPicker(null)} className="px-2 py-1 text-xs text-slate-300 hover:text-white">关闭</button>
        </div>
        {modelPicker.message && <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">{modelPicker.message}</div>}
        <div className="max-h-[24rem] overflow-y-auto rounded-md border border-slate-700">
          {modelPicker.loading ? <div className="px-3 py-6 text-center text-sm text-slate-400">读取中…</div>
            : modelPicker.error ? <div className="px-3 py-6 text-center text-sm text-red-300">{modelPicker.error}</div>
              : modelPicker.models.length === 0 ? <div className="px-3 py-6 text-center text-sm text-slate-400">serve 未返回可用模型</div>
                : <div className="divide-y divide-slate-700">{modelPicker.models.map((model) => <label key={model.id} className="flex items-center gap-3 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800">
                  <input type="checkbox" checked={modelPicker.selected.includes(model.id)} onChange={() => togglePickedModel(model.id)} className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-xs text-slate-100">{model.id}</span>
                    {model.name && <span className="block truncate text-xs text-slate-500">{model.name}</span>}
                  </span>
                </label>)}</div>}
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-slate-500">已选择 {modelPicker.selected.length} 个模型</span>
          <div className="flex gap-2">
            <button type="button" onClick={() => void openModelPicker(true)} disabled={modelPicker.loading} className="rounded-md bg-slate-700 px-3 py-1.5 text-xs text-slate-100 transition-colors hover:bg-slate-600 disabled:opacity-50">刷新</button>
            <button type="button" onClick={importPickedModels} disabled={modelPicker.loading || modelPicker.selected.length === 0} className="rounded-md bg-blue-600 px-3 py-1.5 text-xs text-white transition-colors hover:bg-blue-500 disabled:opacity-50">导入</button>
          </div>
        </div>
      </div>
    </div>}
  </div>;
}

function ModelEditor({ config, setCfg, online, onImport, pool }: { config: AgentRemoteConfig; setCfg: (value: AgentRemoteConfig) => void; online: boolean; onImport: () => void; pool: AgentOpenCodePoolStatus | null }) {
  const models = config.model_pool.models;
  const update = (index: number, patch: Partial<AgentOpenCodeModelConfig>) => setCfg({ ...config, model_pool: { ...config.model_pool, models: models.map((item, current) => current === index ? { ...item, ...patch } : item) } });
  const add = () => setCfg({ ...config, model_pool: { ...config.model_pool, models: [...models, { id: `model-${models.length + 1}`, model: "", capability: "high", weight: 1, max_concurrency: 1, enabled: true, tool: "", executable: "", timeout: null, max_retries: null, time_windows: [] }] } });
  const addWindow = (modelIndex: number) => update(modelIndex, {
    time_windows: [...(models[modelIndex].time_windows || []), { weekdays: [...allWeekdays], start: "09:00", end: "18:00" }],
  });
  const updateWindow = (modelIndex: number, windowIndex: number, next: AgentModelTimeWindow) => update(modelIndex, {
    time_windows: (models[modelIndex].time_windows || []).map((window, current) => current === windowIndex ? next : window),
  });
  const removeWindow = (modelIndex: number, windowIndex: number) => update(modelIndex, {
    time_windows: (models[modelIndex].time_windows || []).filter((_, current) => current !== windowIndex),
  });
  const ready = models.some((item) => item.enabled && item.model.trim());
  return <div className="space-y-5">
    <div className="flex flex-wrap items-end gap-3">
      <Field label="模型池总并发"><input className={`${input} w-32`} type="number" min={1} value={config.model_pool.global_concurrency} onChange={(e) => setCfg({ ...config, model_pool: { ...config.model_pool, global_concurrency: Number(e.target.value) } })} /></Field>
      <button onClick={onImport} disabled={!online} className="rounded bg-slate-700 px-3 py-2 text-sm disabled:opacity-40">从 serve 读取</button>
      <button onClick={add} className="rounded bg-blue-600 px-3 py-2 text-sm">添加模型</button>
      {pool && <span className="pb-2 text-xs text-slate-400">运行 {pool.global_running} / 排队 {pool.global_queued}</span>}
    </div>
    {!ready && <div className="rounded border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">必须手动配置并启用至少一个有明确模型名的模型，才能启动或恢复扫描。</div>}
    <div className="space-y-4">{models.map((model, index) => <div key={index} className="rounded-xl border border-slate-700 p-4">
      <div className="grid gap-3 md:grid-cols-6">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={model.enabled} onChange={(e) => update(index, { enabled: e.target.checked })} />启用</label>
        <input className={input} value={model.id} placeholder="唯一 ID" onChange={(e) => update(index, { id: e.target.value })} />
        <input className={`${input} md:col-span-2`} value={model.model} placeholder="provider/model" onChange={(e) => update(index, { model: e.target.value })} />
        <select className={input} value={model.capability} onChange={(e) => update(index, { capability: e.target.value })}><option value="low">低能力</option><option value="medium">中能力</option><option value="high">高能力</option></select>
        <button onClick={() => setCfg({ ...config, model_pool: { ...config.model_pool, models: models.filter((_, current) => current !== index) } })} className="rounded border border-red-500/30 text-sm text-red-300">删除</button>
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-6">
        <input className={input} type="number" min={0.1} step={0.1} value={model.weight} title="权重" onChange={(e) => update(index, { weight: Number(e.target.value) })} />
        <input className={input} type="number" min={1} value={model.max_concurrency} title="单模型并发" onChange={(e) => update(index, { max_concurrency: Number(e.target.value) })} />
        <select className={input} value={model.tool || ""} onChange={(e) => update(index, { tool: e.target.value })}><option value="">继承工具</option><option value="nga">nga</option><option value="opencode">opencode</option></select>
        <input className={input} value={model.executable || ""} placeholder="可执行文件覆盖" onChange={(e) => update(index, { executable: e.target.value })} />
        <input className={input} type="number" min={1} value={model.timeout ?? ""} placeholder="超时覆盖" onChange={(e) => update(index, { timeout: e.target.value ? Number(e.target.value) : null })} />
        <input className={input} type="number" min={0} value={model.max_retries ?? ""} placeholder="重试覆盖" onChange={(e) => update(index, { max_retries: e.target.value ? Number(e.target.value) : null })} />
      </div>
      <div className="mt-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-medium text-slate-300">使用时间</p>
            <p className="mt-1 text-xs text-slate-500">按 Agent 本地时间；跨夜时间按当前星期判断</p>
          </div>
          <button type="button" onClick={() => addWindow(index)} className="rounded-md bg-slate-700 px-2.5 py-1.5 text-xs text-slate-100 hover:bg-slate-600">添加时间段</button>
        </div>
        {(model.time_windows || []).length === 0 ? <p className="text-xs text-slate-500">全天可用</p> : <div className="space-y-3">
          {(model.time_windows || []).map((window, windowIndex) => {
            const selectedWeekdays = configuredWeekdays(window);
            return <div key={windowIndex} className="space-y-3 rounded-lg border border-slate-700 bg-slate-900/50 p-3">
              <div className="flex flex-wrap gap-2">{weekdays.map((day) => {
                const selected = selectedWeekdays.includes(day.value);
                return <button
                  key={day.value}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => updateWindow(index, windowIndex, {
                    ...window,
                    weekdays: selected
                      ? selectedWeekdays.filter((value) => value !== day.value)
                      : [...selectedWeekdays, day.value].sort((left, right) => left - right),
                  })}
                  className={`rounded-md border px-2.5 py-1.5 text-xs transition-colors ${selected ? "border-blue-500 bg-blue-600 text-white" : "border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700"}`}
                >{day.label}</button>;
              })}</div>
              {selectedWeekdays.length === 0 && <p className="text-xs text-red-300">请至少选择一天，或删除该时间段。</p>}
              <div className="flex flex-wrap items-center gap-2">
                <input type="time" className={`${input} w-auto min-w-36`} value={window.start} onChange={(e) => updateWindow(index, windowIndex, { ...window, weekdays: selectedWeekdays, start: e.target.value })} />
                <span className="text-xs text-slate-500">至</span>
                <input type="time" className={`${input} w-auto min-w-36`} value={window.end} onChange={(e) => updateWindow(index, windowIndex, { ...window, weekdays: selectedWeekdays, end: e.target.value })} />
                <button type="button" onClick={() => removeWindow(index, windowIndex)} className="rounded-md border border-red-500/30 bg-red-500/10 px-2.5 py-2 text-xs text-red-200 hover:bg-red-500/20">删除</button>
              </div>
            </div>;
          })}
        </div>}
      </div>
    </div>)}</div>
  </div>;
}
