import { useEffect, useMemo, useRef, useState } from "react";
import { getValidationTargets, getScans, resumeScan, stopScan, deleteScan, updateScanValidationTarget } from "../api/client";
import type { ScanSummary, ScanItemStatus, User, ValidationTarget } from "../types";

interface Props {
  onViewScan: (scanId: string) => void;
  onDownloadAgent: () => void;
  onNewScan: () => void;
  user: User;
  onLogout: () => void;
  onManageUsers: () => void;
  onCheckerDashboard: () => void;
  onCheckerCatalog: () => void;
}

const STATUS_STYLES: Record<ScanItemStatus, { label: string; cls: string }> = {
  pending: { label: "等待中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  analyzing: { label: "分析中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  auditing: { label: "审计中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  complete: { label: "已完成", cls: "bg-green-500/20 text-green-400 border-green-500/30" },
  error: { label: "错误", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  cancelled: { label: "已取消", cls: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

function isRunning(status: ScanItemStatus) {
  return status === "pending" || status === "analyzing" || status === "auditing";
}

type NavButtonVariant = "default" | "primary";

const NAV_BUTTON_STYLES: Record<NavButtonVariant, string> = {
  default: "text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600",
  primary: "text-white bg-blue-600 hover:bg-blue-700",
};

const ALL_FILTER = "__all__";
const UNCONFIGURED_PRODUCT_FILTER = "__unconfigured__";

function projectName(scan: ScanSummary) {
  return scan.scan_name || scan.project_id || scan.scan_id.slice(0, 8);
}

function productFilterValue(scan: ScanSummary) {
  return scan.product || UNCONFIGURED_PRODUCT_FILTER;
}

function productFilterLabel(value: string) {
  return value === UNCONFIGURED_PRODUCT_FILTER ? "未配置" : value;
}

function validationTargetValue(product: string, environment: string) {
  return product && environment ? JSON.stringify([product, environment]) : "";
}

function isThreatAnalysisOnlyScan(scan: ScanSummary) {
  return scan.scan_mode === "threat_analysis_only";
}

function uniqueOptions(values: string[]) {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

interface HeaderFilterOption {
  value: string;
  label: string;
}

function FilterIcon({ active }: { active: boolean }) {
  return (
    <svg
      className={`h-3.5 w-3.5 ${active ? "text-blue-300" : "text-slate-500"}`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M3 5h18M6 12h12M10 19h4"
      />
    </svg>
  );
}

function HeaderFilter({
  id,
  label,
  value,
  options,
  open,
  onOpenChange,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  options: HeaderFilterOption[];
  open: boolean;
  onOpenChange: (id: string | null) => void;
  onChange: (value: string) => void;
}) {
  const active = value !== ALL_FILTER;
  const activeOption = options.find((option) => option.value === value);
  const displayValue = activeOption?.label ?? value;

  return (
    <div
      className="relative inline-flex min-w-[7.5rem] max-w-[14rem] flex-col items-start gap-1 normal-case tracking-normal"
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
          onOpenChange(null);
        }
      }}
    >
      <button
        type="button"
        onClick={() => onOpenChange(open ? null : id)}
        className={`inline-flex max-w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-xs font-semibold transition-colors ${
          active
            ? "bg-blue-500/10 text-blue-300 hover:bg-blue-500/15"
            : "text-slate-400 hover:bg-slate-700/60 hover:text-slate-200"
        }`}
        aria-label={`${label}筛选`}
        aria-expanded={open}
      >
        <span className="truncate uppercase tracking-wider">{label}</span>
        <FilterIcon active={active} />
      </button>
      {active && (
        <span className="max-w-full truncate text-[11px] font-medium text-blue-300/80" title={displayValue}>
          {displayValue}
        </span>
      )}
      {open && (
        <div className="absolute left-0 top-full z-40 mt-2 w-56 overflow-hidden rounded-lg border border-slate-600 bg-slate-900 shadow-xl shadow-black/30">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => {
              onChange(ALL_FILTER);
              onOpenChange(null);
            }}
            className={`flex w-full items-center justify-between px-3 py-2 text-left text-xs transition-colors ${
              value === ALL_FILTER ? "bg-blue-500/15 text-blue-200" : "text-slate-300 hover:bg-slate-800"
            }`}
          >
            <span>全部</span>
            {value === ALL_FILTER && <span className="text-blue-300">✓</span>}
          </button>
          <div className="max-h-64 overflow-y-auto border-t border-slate-700/70 py-1">
            {options.map((option) => (
              <button
                key={option.value}
                type="button"
                title={option.label}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  onChange(option.value);
                  onOpenChange(null);
                }}
                className={`flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-xs transition-colors ${
                  value === option.value ? "bg-blue-500/15 text-blue-200" : "text-slate-300 hover:bg-slate-800"
                }`}
              >
                <span className="min-w-0 truncate">{option.label}</span>
                {value === option.value && <span className="shrink-0 text-blue-300">✓</span>}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function NavButton({
  label,
  description,
  onClick,
  variant = "default",
}: {
  label: string;
  description: string;
  onClick: () => void;
  variant?: NavButtonVariant;
}) {
  return (
    <div className="relative group">
      <button
        onClick={onClick}
        aria-label={`${label}：${description}`}
        className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${NAV_BUTTON_STYLES[variant]}`}
      >
        {label}
      </button>
      <div
        role="tooltip"
        className="pointer-events-none absolute right-0 top-full z-30 mt-2 w-64 translate-y-1 rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-xs leading-relaxed text-slate-200 shadow-xl opacity-0 transition-all duration-150 group-hover:translate-y-0 group-hover:opacity-100 group-focus-within:translate-y-0 group-focus-within:opacity-100"
      >
        <div className="mb-0.5 font-semibold text-white">{label}</div>
        {description}
      </div>
    </div>
  );
}

export default function ScanHistory({ onViewScan, onDownloadAgent, onNewScan, user, onLogout, onManageUsers, onCheckerDashboard, onCheckerCatalog }: Props) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [validationTargets, setValidationTargets] = useState<ValidationTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [productSavingId, setProductSavingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState(ALL_FILTER);
  const [projectFilter, setProjectFilter] = useState(ALL_FILTER);
  const [creatorFilter, setCreatorFilter] = useState(ALL_FILTER);
  const [openFilter, setOpenFilter] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      const data = await getScans();
      setScans(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  };

  // 自适应轮询：有运行中扫描时 5s，全部空闲时降为 30s；页面不可见时暂停，
  // 重新可见时立即刷新一次。
  const hasRunningScans = scans.some((s) => isRunning(s.status));
  const hasRunningRef = useRef(hasRunningScans);
  hasRunningRef.current = hasRunningScans;

  useEffect(() => {
    fetchScans();
    getValidationTargets().then(setValidationTargets).catch(() => {});

    let lastFetch = Date.now();
    const timer = setInterval(() => {
      if (document.visibilityState === "hidden") return;
      const interval = hasRunningRef.current ? 5000 : 30000;
      if (Date.now() - lastFetch < interval) return;
      lastFetch = Date.now();
      fetchScans();
    }, 5000);

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        lastFetch = Date.now();
        fetchScans();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const handleContinue = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await resumeScan(scanId);
      onViewScan(scanId);
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const handleStop = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await stopScan(scanId);
      await fetchScans();
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteConfirmId) return;
    const scanId = deleteConfirmId;
    setDeleteConfirmId(null);
    setActionLoading(scanId);
    try {
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const handleValidationTargetChange = async (scanId: string, value: string) => {
    const [product, validationEnvironment] = value
      ? (JSON.parse(value) as [string, string])
      : ["", ""];
    setProductSavingId(scanId);
    try {
      await updateScanValidationTarget(scanId, product, validationEnvironment);
      setScans((prev) => prev.map((scan) => (
        scan.scan_id === scanId
          ? { ...scan, product, validation_environment: validationEnvironment }
          : scan
      )));
    } catch {
      // silently fail
    } finally {
      setProductSavingId(null);
    }
  };

  const formatTime = (iso: string) => {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  };

  const deleteTarget = deleteConfirmId
    ? scans.find((scan) => scan.scan_id === deleteConfirmId)
    : null;
  const deleteTargetName = deleteTarget
    ? projectName(deleteTarget)
    : deleteConfirmId?.slice(0, 8);

  const projectOptions = useMemo(
    () => uniqueOptions(scans.map(projectName)).map((value) => ({ value, label: value })),
    [scans],
  );

  const productOptions = useMemo(
    () => uniqueOptions(scans.map(productFilterValue)).map((value) => ({
      value,
      label: productFilterLabel(value),
    })),
    [scans],
  );

  const creatorOptions = useMemo(
    () => uniqueOptions(scans.map((scan) => scan.username || "-")).map((value) => ({ value, label: value })),
    [scans],
  );

  const filteredScans = useMemo(
    () =>
      scans.filter((scan) => {
        if (productFilter !== ALL_FILTER && productFilterValue(scan) !== productFilter) {
          return false;
        }
        if (projectFilter !== ALL_FILTER && projectName(scan) !== projectFilter) {
          return false;
        }
        if (creatorFilter !== ALL_FILTER && (scan.username || "-") !== creatorFilter) {
          return false;
        }
        return true;
      }),
    [creatorFilter, productFilter, projectFilter, scans],
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-6 w-80">
            <h3 className="text-base font-semibold text-white mb-2">确认删除</h3>
            <p className="text-sm text-slate-400 mb-5">
              确定要删除扫描任务 <span className="font-medium text-slate-300">{deleteTargetName}</span> 吗？此操作无法撤销。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={handleDeleteConfirm}
                className="px-4 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white">OpenDeepHole</h1>
            <p className="text-sm text-slate-400 mt-0.5">C/C++ Source Code Audit Tool</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-slate-400">
              {user.username}
              {user.role === "admin" && (
                <span className="ml-1.5 text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  Admin
                </span>
              )}
            </span>
            {user.role === "admin" && (
              <>
                <NavButton
                  label="结果看板"
                  description="按 SKILL 汇总扫描结果、问题数量和确认情况"
                  onClick={onCheckerDashboard}
                />
                <NavButton
                  label="用户管理"
                  description="管理系统用户账号和权限"
                  onClick={onManageUsers}
                />
              </>
            )}
            <NavButton
              label="SKILL市场"
              description="查看各类 SKILL 的检测范围和使用说明"
              onClick={onCheckerCatalog}
            />
            <NavButton
              label="客户端"
              description="查看已连接客户端，并配置扫描执行参数"
              onClick={onDownloadAgent}
            />
            <NavButton
              label="新建扫描"
              description="选择客户端、代码路径和检测项，创建扫描任务"
              onClick={onNewScan}
              variant="primary"
            />
            <button
              onClick={onLogout}
              className="px-3 py-2 text-sm font-medium text-slate-400 hover:text-red-400 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 py-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          扫描历史
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <p className="text-lg font-medium">暂无扫描记录</p>
            <p className="text-sm mt-1">点击右上角「新建扫描」开始</p>
          </div>
        ) : (
          <div className="border border-slate-700 rounded-xl">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-800 border-b border-slate-700">
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <HeaderFilter
                      id="product"
                      label="产品"
                      value={productFilter}
                      options={productOptions}
                      open={openFilter === "product"}
                      onOpenChange={setOpenFilter}
                      onChange={setProductFilter}
                    />
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <HeaderFilter
                      id="project"
                      label="项目名称"
                      value={projectFilter}
                      options={projectOptions}
                      open={openFilter === "project"}
                      onOpenChange={setOpenFilter}
                      onChange={setProjectFilter}
                    />
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">状态</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">任务进度</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">漏洞数</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">人工确认</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">检查项</th>
                  {user.role === "admin" && (
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      <HeaderFilter
                        id="creator"
                        label="创建者"
                        value={creatorFilter}
                        options={creatorOptions}
                        open={openFilter === "creator"}
                        onOpenChange={setOpenFilter}
                        onChange={setCreatorFilter}
                      />
                    </th>
                  )}
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">创建时间</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => {
                  const st = STATUS_STYLES[scan.status];
                  const running = isRunning(scan.status);
                  const canContinue = !running && !!scan.can_continue;
                  const totalTasks = scan.total_task_count ?? 0;
                  const completedTasks = scan.completed_task_count ?? 0;
                  const taskPct = totalTasks > 0 ? Math.min(100, Math.round((completedTasks / totalTasks) * 100)) : 0;
                  const canDelete = !running;
                  const isLoading = actionLoading === scan.scan_id;
                  const isProductSaving = productSavingId === scan.scan_id;
                  const displayProjectName = projectName(scan);

                  return (
                    <tr
                      key={scan.scan_id}
                      className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <select
                          value={validationTargetValue(scan.product || "", scan.validation_environment || "")}
                          onChange={(e) => handleValidationTargetChange(scan.scan_id, e.target.value)}
                          disabled={isProductSaving}
                          className="max-w-[9rem] bg-slate-900 border border-slate-600 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-60"
                        >
                          <option value="">未配置</option>
                          {validationTargets.map((target) => (
                            <option
                              key={target.validator_id}
                              value={validationTargetValue(target.product, target.validation_environment)}
                            >
                              {target.product} / {target.validation_environment}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-slate-200 max-w-[14rem] truncate" title={displayProjectName}>
                        {displayProjectName}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${st.cls}`}>
                          {st.label}
                        </span>
                        {running && (
                          <span className="ml-2 inline-block w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${running ? "bg-blue-500" : "bg-green-500"}`}
                              style={{ width: `${taskPct}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-400">
                            {completedTasks}/{totalTasks}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-300">
                        {scan.vulnerability_count}
                      </td>
                      <td className="px-4 py-3 text-sm text-emerald-300">
                        {scan.human_confirmed_count}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {isThreatAnalysisOnlyScan(scan) ? (
                            <span className="text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 rounded">
                              仅威胁分析
                            </span>
                          ) : (
                            scan.scan_items.map((item) => (
                              <span
                                key={item}
                                className="text-xs bg-slate-700/50 text-slate-400 px-1.5 py-0.5 rounded"
                              >
                                {item}
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                      {user.role === "admin" && (
                        <td className="px-4 py-3 text-xs text-slate-300">
                          {scan.username || "-"}
                        </td>
                      )}
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {formatTime(scan.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onViewScan(scan.scan_id)}
                            className="text-xs px-2 py-1 rounded text-blue-400 hover:bg-blue-500/10 transition-colors"
                          >
                            查看
                          </button>
                          {running && (
                            <button
                              onClick={() => handleStop(scan.scan_id)}
                              disabled={isLoading}
                              className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
                            >
                              {isLoading ? "..." : "停止"}
                            </button>
                          )}
                          {canContinue && (
                            <button
                              onClick={() => handleContinue(scan.scan_id)}
                              disabled={isLoading || !scan.agent_online}
                              title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${scan.continuable_task_count ?? 0} 个任务`}
                              className="text-xs px-2 py-1 rounded text-amber-300 hover:bg-amber-500/10 disabled:opacity-50 transition-colors"
                            >
                              {isLoading ? "..." : "续扫"}
                            </button>
                          )}
                          {canDelete && (
                            <button
                              onClick={() => setDeleteConfirmId(scan.scan_id)}
                              disabled={isLoading}
                              className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
                            >
                              {isLoading ? "..." : "删除"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {filteredScans.length === 0 && (
                  <tr>
                    <td
                      colSpan={user.role === "admin" ? 10 : 9}
                      className="px-4 py-8 text-center text-sm text-slate-500"
                    >
                      当前筛选条件下无扫描记录
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
