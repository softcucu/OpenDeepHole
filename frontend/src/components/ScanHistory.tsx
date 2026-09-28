import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getScansPage, resumeScan, stopScan, deleteScan } from "../api/client";
import type { ScanSummary, ScanItemStatus, User } from "../types";
import AnnouncementBoard from "./AnnouncementBoard";
import { ThemeToggle } from "./ThemeToggle";
import ScanShareButton from "./ScanShareButton";

interface Props {
  onViewScan: (scanId: string) => void;
  onDownloadAgent: () => void;
  onAgentConfig: () => void;
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
const ANNOUNCEMENT_LAST_SEEN_STORAGE_PREFIX = "opendeephole.announcements.lastSeen";

function announcementLastSeenStorageKey(userId: string) {
  return `${ANNOUNCEMENT_LAST_SEEN_STORAGE_PREFIX}.${userId}`;
}

function normalizeAnnouncementVersion(value: string | null) {
  if (!value || Number.isNaN(Date.parse(value))) return "";
  return value;
}

function readLastSeenAnnouncementVersion(userId: string) {
  if (typeof window === "undefined") return "";
  try {
    return normalizeAnnouncementVersion(
      window.localStorage.getItem(announcementLastSeenStorageKey(userId)),
    );
  } catch {
    return "";
  }
}

function isNewerAnnouncementVersion(candidate: string, baseline: string) {
  if (!candidate) return false;
  if (!baseline) return true;

  const candidateTime = Date.parse(candidate);
  const baselineTime = Date.parse(baseline);
  if (candidateTime !== baselineTime) return candidateTime > baselineTime;

  // Preserve Python ISO timestamps' sub-millisecond precision.
  return candidate > baseline;
}

function projectName(scan: ScanSummary) {
  return scan.scan_name || scan.project_id || scan.scan_id.slice(0, 8);
}

function productFilterValue(scan: ScanSummary) {
  return scan.product || UNCONFIGURED_PRODUCT_FILTER;
}

function productFilterLabel(value: string) {
  return value === UNCONFIGURED_PRODUCT_FILTER ? "未配置" : value;
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
  unread = false,
}: {
  label: string;
  description: string;
  onClick: () => void;
  variant?: NavButtonVariant;
  unread?: boolean;
}) {
  return (
    <div className="relative group">
      <button
        onClick={onClick}
        aria-label={`${label}：${description}${unread ? "，有未读更新" : ""}`}
        className={`relative px-3 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${NAV_BUTTON_STYLES[variant]}`}
      >
        {label}
        {unread && (
          <span
            aria-hidden="true"
            className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-red-500"
          />
        )}
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

export default function ScanHistory({ onViewScan, onDownloadAgent, onAgentConfig, onNewScan, user, onLogout, onManageUsers, onCheckerDashboard, onCheckerCatalog }: Props) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const loadedOlderPagesRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState(ALL_FILTER);
  const [projectFilter, setProjectFilter] = useState(ALL_FILTER);
  const [creatorFilter, setCreatorFilter] = useState(ALL_FILTER);
  const [openFilter, setOpenFilter] = useState<string | null>(null);
  const [announcementOpen, setAnnouncementOpen] = useState(false);
  const [announcementRefreshKey, setAnnouncementRefreshKey] = useState(0);
  const [announcementVersion, setAnnouncementVersion] = useState("");
  const [lastSeenAnnouncementVersion, setLastSeenAnnouncementVersion] = useState(
    () => readLastSeenAnnouncementVersion(user.user_id),
  );

  const rememberAnnouncementVersion = useCallback((version: string) => {
    if (!version) return;
    setLastSeenAnnouncementVersion((previous) => {
      const stored = readLastSeenAnnouncementVersion(user.user_id);
      const baseline = isNewerAnnouncementVersion(stored, previous) ? stored : previous;
      if (!isNewerAnnouncementVersion(version, baseline)) return baseline;
      try {
        window.localStorage.setItem(
          announcementLastSeenStorageKey(user.user_id),
          version,
        );
      } catch {
        // Keep the read marker in memory when browser storage is unavailable.
      }
      return version;
    });
  }, [user.user_id]);

  useEffect(() => {
    const storageKey = announcementLastSeenStorageKey(user.user_id);
    setAnnouncementVersion("");
    setLastSeenAnnouncementVersion(readLastSeenAnnouncementVersion(user.user_id));

    const handleStorage = (event: StorageEvent) => {
      if (event.key !== storageKey) return;
      const incoming = normalizeAnnouncementVersion(event.newValue);
      setLastSeenAnnouncementVersion((previous) => (
        isNewerAnnouncementVersion(incoming, previous) ? incoming : previous
      ));
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, [user.user_id]);

  useEffect(() => {
    if (
      announcementOpen
      && isNewerAnnouncementVersion(announcementVersion, lastSeenAnnouncementVersion)
    ) {
      rememberAnnouncementVersion(announcementVersion);
    }
  }, [
    announcementOpen,
    announcementVersion,
    lastSeenAnnouncementVersion,
    rememberAnnouncementVersion,
  ]);

  const hasUnreadAnnouncement = isNewerAnnouncementVersion(
    announcementVersion,
    lastSeenAnnouncementVersion,
  );

  const openAnnouncements = () => {
    rememberAnnouncementVersion(announcementVersion);
    setAnnouncementOpen(true);
    setAnnouncementRefreshKey((current) => current + 1);
  };

  const fetchScans = async (initial = false) => {
    try {
      const data = await getScansPage(50);
      setScans((previous) => {
        if (initial || !loadedOlderPagesRef.current) return data.items;
        const refreshedIds = new Set(data.items.map((item) => item.scan_id));
        return [
          ...data.items,
          ...previous.filter((item) => !refreshedIds.has(item.scan_id)),
        ];
      });
      if (initial || !loadedOlderPagesRef.current) {
        setNextCursor(data.next_cursor);
      }
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  };

  // 自适应轮询：有运行中扫描时 5s，全部空闲时降为 30s；页面不可见时暂停，
  // 重新可见时立即刷新一次。
  const hasRunningScans = scans.some((s) => isRunning(s.status) || s.fp_review_running);
  const hasRunningRef = useRef(hasRunningScans);
  hasRunningRef.current = hasRunningScans;

  useEffect(() => {
    fetchScans(true);
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
        setAnnouncementRefreshKey((current) => current + 1);
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const handleLoadMore = async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const data = await getScansPage(50, nextCursor);
      setScans((previous) => {
        const existing = new Set(previous.map((item) => item.scan_id));
        return [
          ...previous,
          ...data.items.filter((item) => !existing.has(item.scan_id)),
        ];
      });
      loadedOlderPagesRef.current = true;
      setNextCursor(data.next_cursor);
    } catch {
      // Keep the current page; the operator can retry.
    } finally {
      setLoadingMore(false);
    }
  };

  const handleContinue = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await resumeScan(scanId);
      onViewScan(scanId);
    } catch (err: unknown) {
      const message = err && typeof err === "object" && "response" in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      alert(`续扫失败：${message || "未知错误，请稍后重试"}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleStop = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      const result = await stopScan(scanId);
      if (result.agent_stop_state === "pending") {
        alert("已记录停止请求，但 Agent 暂未确认；重连后将继续停止。");
      }
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-scan-title"
            className="w-full max-w-sm bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-5 sm:p-6"
          >
            <h3 id="delete-scan-title" className="text-base font-semibold text-white mb-2">确认删除</h3>
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
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-4 py-4 sm:px-6">
        <div className="mx-auto flex max-w-[100rem] flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="shrink-0">
            <h1 className="text-lg font-bold text-white">DeepHole 2.0</h1>
            <p className="text-sm text-slate-400 mt-0.5">C/C++ Source Code Audit Tool</p>
          </div>
          <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">
            <span className="mr-auto text-sm text-slate-400 xl:mr-1">
              {user.username}
              {user.role === "admin" && (
                <span className="ml-1.5 text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  Admin
                </span>
              )}
            </span>
            <NavButton
              label="结果看板"
              description={user.role === "admin"
                ? "汇总全部扫描结果和 Token 用量"
                : "汇总我创建的扫描结果和 Token 用量"}
              onClick={onCheckerDashboard}
            />
            {user.role === "admin" && (
              <>
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
              description="下载并启动 Agent 客户端"
              onClick={onDownloadAgent}
            />
            <NavButton
              label="客户端配置"
              description="按机器名和 IP 配置客户端扫描能力"
              onClick={onAgentConfig}
            />
            <NavButton
              label="新建扫描"
              description="选择客户端、代码路径和检测项，创建扫描任务"
              onClick={onNewScan}
              variant="primary"
            />
            <NavButton
              label="公告"
              description="查看最近发布的平台更新公告"
              onClick={openAnnouncements}
              unread={hasUnreadAnnouncement}
            />
            <ThemeToggle />
            <button
              onClick={onLogout}
              className="px-3 py-2 text-sm font-medium text-slate-400 hover:text-red-400 transition-colors whitespace-nowrap"
            >
              退出登录
            </button>
          </div>
        </div>
      </div>

      <AnnouncementBoard
        user={user}
        open={announcementOpen}
        onClose={() => setAnnouncementOpen(false)}
        refreshKey={announcementRefreshKey}
        onPublishedVersionChange={setAnnouncementVersion}
      />

      {/* Content */}
      <div className="mx-auto w-full max-w-[100rem] flex-1 px-4 py-6 sm:px-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          扫描历史
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div role="status" aria-label="加载扫描历史" className="page-spinner w-5 h-5 border-2 rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <p className="text-lg font-medium">暂无扫描记录</p>
            <p className="text-sm mt-1">点击右上角「新建扫描」开始</p>
          </div>
        ) : (
          <div>
            <div className="overflow-x-auto rounded-xl border border-slate-700">
              <table className="w-full min-w-[62rem] text-sm">
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
                      label="扫描名称"
                      value={projectFilter}
                      options={projectOptions}
                      open={openFilter === "project"}
                      onOpenChange={setOpenFilter}
                      onChange={setProjectFilter}
                    />
                  </th>
                  <th className="min-w-[6.5rem] whitespace-nowrap px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">状态</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">疑似问题</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">确认问题</th>
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
                  const coreRunning = isRunning(scan.status);
                  const running = coreRunning || scan.fp_review_running;
                  const st = scan.status === "complete" && scan.fp_review_running
                    ? { ...STATUS_STYLES.pending, label: "进行中" }
                    : STATUS_STYLES[scan.status];
                  const canContinue = !running && !!scan.can_continue;
                  const canDelete = !running;
                  const isLoading = actionLoading === scan.scan_id;
                  const displayProjectName = projectName(scan);

                  return (
                    <tr
                      key={scan.scan_id}
                      className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-200">{scan.product || "未配置"}</span>
                        {scan.vulnerability_validation_enabled && (
                          <span className="mt-1 block max-w-[10rem] truncate text-xs text-blue-300" title={scan.validation_method_label || scan.validation_method_id}>
                            验证：{scan.validation_method_label || scan.validation_method_id}
                          </span>
                        )}
                        {!scan.vulnerability_validation_enabled && scan.validation_environment && (
                          <span className="mt-1 block max-w-[10rem] truncate text-xs text-slate-400" title={scan.validation_environment}>
                            旧验证环境：{scan.validation_environment}
                          </span>
                        )}
                        {scan.knowledge_base_enabled && <span className="mt-1 block text-xs text-emerald-300">已启用知识库</span>}
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-slate-200 max-w-[14rem] truncate" title={displayProjectName}>
                        {displayProjectName}
                      </td>
                      <td className="min-w-[6.5rem] whitespace-nowrap px-4 py-3">
                        <span className="inline-flex items-center gap-2 whitespace-nowrap">
                          <span className={`inline-flex items-center whitespace-nowrap rounded border px-2 py-0.5 text-xs font-semibold ${st.cls}`}>
                            {st.label}
                          </span>
                          {running && (
                            <span className="inline-flex items-center gap-1 text-xs text-blue-300" title={scan.fp_review_running ? "去误报进行中" : "主扫描进行中"}>
                              <span className="inline-block h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                              {!coreRunning && scan.fp_review_running && "去误报进行中"}
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-300">
                        {scan.suspected_issue_count}
                      </td>
                      <td className="px-4 py-3 text-sm text-emerald-300">
                        {scan.confirmed_vulnerability_count}
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
                          <ScanShareButton scanId={scan.scan_id} compact />
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
                      colSpan={user.role === "admin" ? 8 : 7}
                      className="px-4 py-8 text-center text-sm text-slate-500"
                    >
                      当前筛选条件下无扫描记录
                    </td>
                  </tr>
                )}
              </tbody>
              </table>
            </div>
            {nextCursor && (
              <div className="mt-4 flex justify-center">
                <button
                  type="button"
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                  className="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:opacity-50"
                >
                  {loadingMore ? "加载中..." : "加载更多"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
