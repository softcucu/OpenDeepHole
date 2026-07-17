import { useEffect, useState } from "react";
import { getAgents, getCheckers, getValidationTargets, createScan } from "../api/client";
import type { AgentInfo, CheckerInfo, ValidationTarget } from "../types";

interface Props {
  onScanStarted: (scanId: string) => void;
  onBack: () => void;
}

const SCAN_MODE_FULL = "full";
const SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only";

export default function NewScanForm({ onScanStarted, onBack }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [validationTargets, setValidationTargets] = useState<ValidationTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [projectPath, setProjectPath] = useState<string>("");
  const [codeScanPath, setCodeScanPath] = useState<string>("");
  const [scanName, setScanName] = useState<string>("");
  const [selectedScanMode, setSelectedScanMode] = useState<string>(SCAN_MODE_FULL);
  const [selectedProduct, setSelectedProduct] = useState<string>("");
  const [selectedValidationEnvironment, setSelectedValidationEnvironment] = useState<string>("");
  const [selectedCheckers, setSelectedCheckers] = useState<Set<string>>(new Set());
  const builtinCheckers = checkers.filter((checker) => !checker.user_created);
  const userCheckers = checkers.filter((checker) => checker.user_created);
  const threatAnalysisOnly = selectedScanMode === SCAN_MODE_THREAT_ANALYSIS_ONLY;
  const products = Array.from(new Set(validationTargets.map((target) => target.product))).sort();
  const validationEnvironments = validationTargets
    .filter((target) => target.product === selectedProduct)
    .map((target) => target.validation_environment);

  useEffect(() => {
    const load = async () => {
      try {
        const [agentList, checkerList, targets] = await Promise.all([
          getAgents(),
          getCheckers(),
          getValidationTargets(),
        ]);
        setAgents(agentList);
        setCheckers(checkerList);
        setValidationTargets(targets);
        // Pre-select all checkers
        setSelectedCheckers(new Set(checkerList.filter((c) => !c.user_created).map((c) => c.name)));
        // Pre-select first online agent
        const onlineAgent = agentList.find((a) => a.online);
        if (onlineAgent) setSelectedAgent(onlineAgent.agent_id);
      } catch (e) {
        setError("加载数据失败，请重试");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const toggleChecker = (name: string) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const selectAllInGroup = (group: CheckerInfo[]) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      group.forEach((c) => next.add(c.name));
      return next;
    });
  };

  const deselectAllInGroup = (group: CheckerInfo[]) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      group.forEach((c) => next.delete(c.name));
      return next;
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedAgent) {
      setError("请选择一个 Agent");
      return;
    }
    if (!projectPath.trim()) {
      setError("请输入项目路径");
      return;
    }
    if (!threatAnalysisOnly && selectedCheckers.size === 0) {
      setError("请至少选择一个检查项");
      return;
    }

    setSubmitting(true);
    try {
      const resp = await createScan({
        agent_id: selectedAgent,
        project_path: projectPath.trim(),
        code_scan_path: codeScanPath.trim(),
        scan_name: scanName.trim(),
        scan_mode: selectedScanMode,
        product: selectedProduct,
        validation_environment: selectedValidationEnvironment,
        checkers: threatAnalysisOnly ? [] : Array.from(selectedCheckers),
      });
      onScanStarted(resp.scan_id);
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        "创建扫描失败，请检查 Agent 是否在线";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white">新建扫描</h1>
            <p className="text-sm text-slate-400 mt-0.5">选择客户端、项目路径、代码扫描范围、产品、验证环境和检测项，创建扫描任务</p>
          </div>
          <button
            onClick={onBack}
            className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
          >
            返回
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 py-6 max-w-5xl mx-auto w-full">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6">
          扫描配置
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Agent selection */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                选择 Agent
              </label>
              {agents.length === 0 ? (
                <p className="text-sm text-slate-500">暂无在线 Agent。请先运行 ./run_agent.sh</p>
              ) : (
                <div className="space-y-2">
                  {agents.map((agent) => (
                    <label
                      key={agent.agent_id}
                      className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                        selectedAgent === agent.agent_id
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-slate-600 hover:border-slate-500"
                      }`}
                    >
                      <input
                        type="radio"
                        name="agent"
                        value={agent.agent_id}
                        checked={selectedAgent === agent.agent_id}
                        onChange={() => setSelectedAgent(agent.agent_id)}
                        className="sr-only"
                      />
                      <span
                        className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          agent.online ? "bg-green-400" : "bg-slate-500"
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium text-white">{agent.name}</span>
                        <span className="ml-2 text-xs text-slate-400">
                          {agent.ip}:{agent.port}
                        </span>
                      </div>
                      <span
                        className={`text-xs px-2 py-0.5 rounded border ${
                          agent.online
                            ? "bg-green-500/20 text-green-400 border-green-500/30"
                            : "bg-slate-700 text-slate-500 border-slate-600"
                        }`}
                      >
                        {agent.online ? "在线" : "离线"}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Scan mode */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                扫描模式
              </label>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <label
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                    selectedScanMode === SCAN_MODE_FULL
                      ? "border-blue-500 bg-blue-500/10"
                      : "border-slate-600 hover:border-slate-500"
                  }`}
                >
                  <input
                    type="radio"
                    name="scan_mode"
                    value={SCAN_MODE_FULL}
                    checked={selectedScanMode === SCAN_MODE_FULL}
                    onChange={() => setSelectedScanMode(SCAN_MODE_FULL)}
                    className="mt-0.5 h-4 w-4 border-slate-500 bg-slate-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">完整扫描</div>
                    <div className="mt-1 text-xs text-slate-500">代码索引、威胁分析、静态分析和候选点审计</div>
                  </div>
                </label>
                <label
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                    selectedScanMode === SCAN_MODE_THREAT_ANALYSIS_ONLY
                      ? "border-emerald-500 bg-emerald-500/10"
                      : "border-slate-600 hover:border-slate-500"
                  }`}
                >
                  <input
                    type="radio"
                    name="scan_mode"
                    value={SCAN_MODE_THREAT_ANALYSIS_ONLY}
                    checked={selectedScanMode === SCAN_MODE_THREAT_ANALYSIS_ONLY}
                    onChange={() => setSelectedScanMode(SCAN_MODE_THREAT_ANALYSIS_ONLY)}
                    className="mt-0.5 h-4 w-4 border-slate-500 bg-slate-700 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-0"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">仅威胁分析</div>
                    <div className="mt-1 text-xs text-slate-500">用于单独执行和调试威胁分析 Agent</div>
                  </div>
                </label>
              </div>
            </div>

            {/* Project path */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                项目总路径
              </label>
              <input
                type="text"
                value={projectPath}
                onChange={(e) => setProjectPath(e.target.value)}
                placeholder="/path/to/your/project"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-slate-500 mt-2">
                Agent 所在机器上的项目根目录，用于代码索引和 opencode 工作区
              </p>
            </div>

            {/* Code scan path */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                代码扫描路径 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <input
                type="text"
                value={codeScanPath}
                onChange={(e) => setCodeScanPath(e.target.value)}
                placeholder="留空则扫描项目总路径，可填写子目录或绝对路径"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-slate-500 mt-2">
                静态分析只扫描该目录；必须位于项目总路径内
              </p>
            </div>

            {/* Scan name */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                扫描名称 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <input
                type="text"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="留空则使用目录名"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>

            {/* Product */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                产品 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <select
                value={selectedProduct}
                onChange={(e) => {
                  const product = e.target.value;
                  setSelectedProduct(product);
                  setSelectedValidationEnvironment(
                    validationTargets.find((target) => target.product === product)?.validation_environment || "",
                  );
                }}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
              >
                <option value="">未配置</option>
                {products.map((product) => (
                  <option key={product} value={product}>
                    {product}
                  </option>
                ))}
              </select>
            </div>

            {/* Validation environment */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                验证环境
              </label>
              <select
                value={selectedValidationEnvironment}
                onChange={(e) => setSelectedValidationEnvironment(e.target.value)}
                disabled={!selectedProduct}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
              >
                {!selectedProduct || validationEnvironments.length === 0 ? (
                  <option value="">未配置</option>
                ) : (
                  validationEnvironments.map((environment) => (
                    <option key={environment} value={environment}>
                      {environment}
                    </option>
                  ))
                )}
              </select>
              <p className="text-xs text-slate-500 mt-2">
                漏洞验证会按产品和验证环境选择对应的 Agent 本地验证方法
              </p>
            </div>

            {/* Checker selection */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                检查项
              </label>
              {threatAnalysisOnly ? (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-4 text-sm text-emerald-200">
                  仅威胁分析模式不需要选择检查项。
                </div>
              ) : checkers.length === 0 ? (
                <p className="text-sm text-slate-500">无可用检查项</p>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">系统内置</div>
                      <button
                        type="button"
                        className="text-xs text-blue-400 hover:text-blue-300"
                        onClick={() => {
                          builtinCheckers.every((c) => selectedCheckers.has(c.name))
                            ? deselectAllInGroup(builtinCheckers)
                            : selectAllInGroup(builtinCheckers);
                        }}
                      >
                        {builtinCheckers.every((c) => selectedCheckers.has(c.name)) ? "全不选" : "全选"}
                      </button>
                    </div>
                    {builtinCheckers.map((checker) => (
                      <CheckerOption key={checker.name} checker={checker} selected={selectedCheckers.has(checker.name)} onToggle={() => toggleChecker(checker.name)} />
                    ))}
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">用户新建</div>
                      {userCheckers.length > 0 && (
                        <button
                          type="button"
                          className="text-xs text-blue-400 hover:text-blue-300"
                          onClick={() => {
                            userCheckers.every((c) => selectedCheckers.has(c.name))
                              ? deselectAllInGroup(userCheckers)
                              : selectAllInGroup(userCheckers);
                          }}
                        >
                          {userCheckers.every((c) => selectedCheckers.has(c.name)) ? "全不选" : "全选"}
                        </button>
                      )}
                    </div>
                    {userCheckers.length === 0 ? (
                      <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-6 text-center text-sm text-slate-500">
                        暂无用户新建 SKILL
                      </div>
                    ) : (
                      userCheckers.map((checker) => (
                        <CheckerOption key={checker.name} checker={checker} selected={selectedCheckers.has(checker.name)} onToggle={() => toggleChecker(checker.name)} />
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Error */}
            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Submit */}
            <div className="flex gap-3">
              <button
                type="submit"
                disabled={submitting || agents.length === 0}
                className="flex-1 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {submitting ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    创建中...
                  </span>
                ) : (
                  "开始扫描"
                )}
              </button>
              <button
                type="button"
                onClick={onBack}
                className="px-6 py-2.5 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                取消
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function CheckerOption({ checker, selected, onToggle }: { checker: CheckerInfo; selected: boolean; onToggle: () => void }) {
  return (
    <label
      className="flex items-start gap-3 p-3 rounded-lg border border-slate-600 hover:border-slate-500 cursor-pointer transition-colors"
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        className="mt-0.5 w-4 h-4 rounded border-slate-500 bg-slate-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
      />
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-white">{checker.label}</span>
          {checker.visibility === "admin" && (
            <span className="text-[11px] font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5">
              管理员测试
            </span>
          )}
          {checker.user_created && (
            <span className="text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-1.5 py-0.5">
              用户创建
            </span>
          )}
          <span className="text-[11px] font-semibold text-cyan-200 bg-cyan-500/10 border border-cyan-500/30 rounded px-1.5 py-0.5">
            {checker.category_label || "非法内存使用"}
          </span>
        </div>
        <div className="text-[11px] text-slate-500 mt-1">
          最后修改：{formatModifiedAt(checker.modified_at)}
          {checker.user_created && (
            <span className="ml-2">
              创建者：{checker.creator_username || "-"}
            </span>
          )}
        </div>
        <p className="text-xs text-slate-400 mt-0.5">{checker.description}</p>
      </div>
    </label>
  );
}

function formatModifiedAt(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
