import { useEffect, useState } from "react";
import { getAgents, getAgentConfig, testAgentConfig, updateAgentConfig } from "../api/client";
import type { AgentInfo, AgentRemoteConfig } from "../types";

interface Props {
  onBack: () => void;
}

const DEFAULT_CONFIG: AgentRemoteConfig = {
  no_proxy: "10.0.0.0/8",
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
    executable: "opencode",
    model: "",
    timeout: 1200,
    max_retries: 2,
  },
};

function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

interface AgentConfigPanelProps {
  agent: AgentInfo;
}

function AgentConfigPanel({ agent }: AgentConfigPanelProps) {
  const [open, setOpen] = useState(false);
  const [cfg, setCfg] = useState<AgentRemoteConfig>(deepClone(DEFAULT_CONFIG));
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleOpen = async () => {
    setOpen(true);
    setLoading(true);
    setError(null);
    try {
      const data = await getAgentConfig(agent.agent_id);
      setCfg(data);
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

  const setLLM = (key: keyof AgentRemoteConfig["llm_api"], value: string | number | boolean) => {
    setCfg((prev) => ({ ...prev, llm_api: { ...prev.llm_api, [key]: value } }));
  };

  const setOC = (key: keyof AgentRemoteConfig["opencode"], value: string | number) => {
    setCfg((prev) => ({ ...prev, opencode: { ...prev.opencode, [key]: value } }));
  };

  return (
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
      </div>

      {/* Config form */}
      {open && (
        <div className="border-t border-slate-700 px-4 py-4">
          {loading ? (
            <div className="flex justify-center py-6">
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            </div>
          ) : (
            <div className="space-y-5">
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

              {/* opencode */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">opencode 配置</h3>
                <div className="grid grid-cols-1 gap-3">
                  <Field label="可执行文件" hint="CLI 名称或完整路径">
                    <input type="text" value={cfg.opencode.executable}
                      onChange={(e) => setOC("executable", e.target.value)}
                      className={inputCls} placeholder="opencode" />
                  </Field>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <Field label="模型" hint="留空使用默认">
                      <input type="text" value={cfg.opencode.model}
                        onChange={(e) => setOC("model", e.target.value)}
                        className={inputCls} placeholder="（默认）" />
                    </Field>
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

              {/* no_proxy */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">网络</h3>
                <Field label="代理跳过列表" hint="逗号分隔，如 localhost,10.0.0.0/8">
                  <input type="text" value={cfg.no_proxy}
                    onChange={(e) => setCfg((prev) => ({ ...prev, no_proxy: e.target.value }))}
                    className={inputCls} placeholder="localhost,127.0.0.1" />
                </Field>
              </div>

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
    </div>
  );
}

const inputCls =
  "w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors";

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
    getAgents().then(setAgents).catch(() => {});
    const id = setInterval(() => getAgents().then(setAgents).catch(() => {}), 10000);
    return () => clearInterval(id);
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
      <div className="max-w-3xl mx-auto px-6 py-8">
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

        {/* 停止与恢复 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-3">停止与恢复</h2>
          <div className="space-y-3 text-sm">
            <div className="flex gap-3">
              <span className="text-red-400 font-medium shrink-0">停止</span>
              <span className="text-slate-300">扫描详情页点击「停止扫描」，Server 直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。</span>
            </div>
            <div className="flex gap-3">
              <span className="text-amber-400 font-medium shrink-0">恢复</span>
              <span className="text-slate-300">扫描列表页点击「恢复」，Server 通知 Agent 继续同一个扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。</span>
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
