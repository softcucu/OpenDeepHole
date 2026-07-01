import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { getScanStatus, stopScan, downloadScanReport, downloadScanReportZip, getCheckers, updateScanFeedback, getSkillContent, triggerFpReview, stopFpReview, getFpReview, getFpReviewSkill, getScanGitHistory, getSkillReports, retryIncompleteScan } from "../api/client";
import type { Candidate, FpReviewJob, HistoryPattern, IndexStatus, ScanItemStatus, ScanStatus as ScanStatusType, ScanEvent, CheckerInfo, SkillReport, OpenCodePoolStatus, Vulnerability, OutputSource } from "../types";
import { useScanSSE } from "../hooks/useScanSSE";
import type { ScanSSEHandlers, SSEStateSetters } from "../hooks/useScanSSE";
import VulnerabilityList from "./VulnerabilityList";
import FeedbackManager from "./FeedbackManager";

const MAX_LOG_LINES = 500;
const AGENT_DISCONNECT_ERROR = "Agent 断开连接";
const FINAL_USER_VERDICTS = new Set(["confirmed", "false_positive"]);

type MainTab = "overview" | "threat" | "mining" | "validation" | "reports" | "issues";
type ThreatTab = "index" | "static" | "git_history";
type MiningTab = "candidate_audit" | "variant_hunt";
type TaskTone = "slate" | "cyan" | "amber" | "green" | "red" | "purple" | "blue";

const MAIN_TABS: { key: MainTab; label: string }[] = [
  { key: "overview", label: "首页" },
  { key: "threat", label: "威胁分析" },
  { key: "mining", label: "漏洞挖掘" },
  { key: "validation", label: "漏洞验证" },
  { key: "reports", label: "漏洞报告生成" },
  { key: "issues", label: "发现的问题" },
];

const THREAT_TABS: { key: ThreatTab; label: string }[] = [
  { key: "index", label: "代码索引" },
  { key: "static", label: "静态分析" },
  { key: "git_history", label: "Git 历史问题分析" },
];

const MINING_TABS: { key: MiningTab; label: string }[] = [
  { key: "candidate_audit", label: "候选点 AI 审计" },
  { key: "variant_hunt", label: "历史同类问题挖掘" },
];

function hasOutputSource(source?: OutputSource | null): boolean {
  return Boolean(source && (source.agent_name || source.agent_id || source.model || source.model_id || source.tool));
}

function formatOutputSource(source?: OutputSource | null): string {
  if (!hasOutputSource(source)) return "";
  const agent = source?.agent_name || source?.agent_id || "未知 Agent";
  const tool = source?.tool || source?.backend || "AI";
  const model = source?.use_default_model
    ? "CLI 默认模型"
    : (source?.model || source?.model_id || "默认模型");
  const modelId = source?.model_id && source.model_id !== model ? `${source.model_id} / ${model}` : model;
  return `${agent} · ${tool} · ${modelId}`;
}

function isAgentDisconnectError(message: string | null | undefined): boolean {
  return !!message && message.includes(AGENT_DISCONNECT_ERROR);
}

function hasFinalUserVerdict(vuln: { user_verdict?: string | null }): boolean {
  return FINAL_USER_VERDICTS.has(vuln.user_verdict || "");
}

function percent(current: number, total: number): number {
  if (!total || total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
}

function scanEventMatches(event: ScanEvent, phases: string[]): boolean {
  return phases.includes(event.phase);
}

function filterEvents(events: ScanEvent[], phases: string[]): ScanEvent[] {
  return events.filter((event) => scanEventMatches(event, phases));
}

function hasEvent(events: ScanEvent[], phases: string[]): boolean {
  return events.some((event) => scanEventMatches(event, phases));
}

function isAiConfirmed(vuln: { ai_verdict?: string; confirmed?: boolean }): boolean {
  return vuln.ai_verdict === "confirmed" || (!vuln.ai_verdict && !!vuln.confirmed);
}

function effectiveIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  const fpMap = new Map((fpReview?.results ?? []).map((result) => [result.vuln_index, result]));
  return scan.vulnerabilities.filter((vuln, index) => {
    if (!isAiConfirmed(vuln)) return false;
    if (fpMap.get(index)?.verdict === "fp") return false;
    return true;
  }).length;
}

function currentStageLabel(scan: ScanStatusType, events: ScanEvent[]): string {
  if (scan.status === "error") return "异常中断";
  if (scan.status === "cancelled") return "已取消";
  if (scan.status === "complete") return "完成";
  const latest = [...events].reverse().find((event) => event.phase !== "opencode_output");
  if (latest?.phase === "variant_hunt") return "漏洞挖掘 / 历史同类问题挖掘";
  if (latest?.phase === "git_history") return "威胁分析 / Git 历史问题分析";
  if (latest?.phase === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (latest?.phase === "static_analysis") return "威胁分析 / 静态分析";
  if (latest?.phase === "mcp_ready" || latest?.phase === "init") return "威胁分析 / 代码索引";
  if (scan.status === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (scan.status === "analyzing") return "威胁分析 / 静态分析";
  return "等待启动";
}

function taskStateLabel(done: boolean, running: boolean, failed = false): string {
  if (failed) return "异常";
  if (done) return "完成";
  if (running) return "进行中";
  return "等待";
}

function formatIndexProgress(indexStatus: IndexStatus | null, scan: ScanStatusType): { current: number; total: number; done: boolean; running: boolean; failed: boolean } {
  const current = indexStatus?.parsed_files ?? scan.static_scanned_files ?? 0;
  const total = indexStatus?.total_files ?? scan.static_total_files ?? 0;
  const failed = indexStatus?.status === "error";
  const running = indexStatus?.status === "parsing";
  const done = !running && (indexStatus?.status === "done" || scan.static_analysis_done || (indexStatus == null && scan.static_total_files > 0));
  return { current, total, done, running, failed };
}

interface Props {
  scanId: string;
  onBack: () => void;
}

export default function ScanStatus({ scanId, onBack }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [activeTab, setActiveTab] = useState<MainTab>("overview");
  const [activeThreatTab, setActiveThreatTab] = useState<ThreatTab>("index");
  const [activeMiningTab, setActiveMiningTab] = useState<MiningTab>("candidate_audit");
  const [stopping, setStopping] = useState(false);
  const [retryingIncomplete, setRetryingIncomplete] = useState(false);
  const [downloadingReport, setDownloadingReport] = useState(false);
  const [exportingZip, setExportingZip] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [modelPoolOpen, setModelPoolOpen] = useState(false);
  const [lastSeenEvents, setLastSeenEvents] = useState(0);
  const logRef = useRef<HTMLDivElement>(null);

  // Feedback panel state
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [selectedFeedbackIds, setSelectedFeedbackIds] = useState<Set<string> | null>(null);

  // SKILL preview state
  const [skillOpen, setSkillOpen] = useState(false);
  const [skillType, setSkillType] = useState<string | null>(null);
  const [skillContent, setSkillContent] = useState("");
  const [skillLoading, setSkillLoading] = useState(false);

  // Markdown reports generated by user-created SKILLs
  const [reportsOpen, setReportsOpen] = useState(false);
  const [reports, setReports] = useState<SkillReport[]>([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [activeReportIndex, setActiveReportIndex] = useState(0);

  // FP review state
  const [fpReview, setFpReview] = useState<FpReviewJob | null>(null);
  const [fpReviewLoading, setFpReviewLoading] = useState(false);
  const [fpReviewStopping, setFpReviewStopping] = useState(false);

  // Code indexing progress
  const [indexStatus, setIndexStatus] = useState<IndexStatus | null>(null);

  // Git history mined patterns
  const [gitHistory, setGitHistory] = useState<HistoryPattern[]>([]);

  const isRunning = scan && (scan.status === "pending" || scan.status === "analyzing" || scan.status === "auditing");
  const isDone = scan && (scan.status === "complete" || scan.status === "error" || scan.status === "cancelled");

  useEffect(() => {
    getCheckers().then(setCheckers).catch(() => {});
  }, []);

  // Initial full-state hydration on mount
  useEffect(() => {
    getScanStatus(scanId)
      .then((data) => {
        setScan(data);
        if (selectedFeedbackIds === null && data.feedback_ids) {
          setSelectedFeedbackIds(new Set(data.feedback_ids));
        }
      })
      .catch(() => {});
    getFpReview(scanId)
      .then(setFpReview)
      .catch(() => {});
    getScanGitHistory(scanId)
      .then(setGitHistory)
      .catch(() => {});
  }, [scanId]);

  // SSE event handlers — update state incrementally
  const sseHandlers = useMemo<ScanSSEHandlers>(() => ({
    onScanStatus: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const patch: Partial<ScanStatusType> = {};
        if (data.status != null) patch.status = data.status as ScanItemStatus;
        if (data.progress != null) patch.progress = data.progress;
        if (data.total_candidates != null) patch.total_candidates = data.total_candidates;
        if (data.processed_candidates != null) patch.processed_candidates = data.processed_candidates;
        if (data.static_total_files != null) patch.static_total_files = data.static_total_files;
        if (data.static_scanned_files != null) patch.static_scanned_files = data.static_scanned_files;
        if (data.static_analysis_done != null) patch.static_analysis_done = data.static_analysis_done;
        if (data.opencode_pool !== undefined) patch.opencode_pool = data.opencode_pool;
        return { ...prev, ...patch };
      });
    },
    onScanVulnerability: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const vulns = [...prev.vulnerabilities];
        vulns[data.index] = data.vulnerability;
        return { ...prev, vulnerabilities: vulns };
      });
    },
    onScanEvent: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const events = [...prev.events, data.event].slice(-MAX_LOG_LINES);
        return { ...prev, events };
      });
    },
    onScanFinish: (data) => {
      setScan((prev) =>
        prev ? { ...prev, status: data.status as ScanItemStatus, error_message: data.error_message } : prev,
      );
    },
    onFpReviewStarted: (data) => {
      setFpReview({
        review_id: data.review_id,
        scan_id: scanId,
        status: data.status,
        total: data.total,
        processed: 0,
        current_vuln_index: null,
        results: [],
        error_message: null,
        created_at: new Date().toISOString(),
      });
    },
    onFpReviewProgress: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return {
          ...prev,
          status: "running",
          processed: data.processed,
          current_vuln_index: data.vuln_index,
          current_vuln_indices: data.active_indices ?? [data.vuln_index],
          total: data.total,
        };
      });
    },
    onFpReviewStageOutput: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const results = [...prev.results];
        const existingIndex = results.findIndex((result) => result.vuln_index === data.vuln_index);
        if (existingIndex >= 0) {
          const existing = results[existingIndex];
          results[existingIndex] = {
            ...existing,
            stage_outputs: {
              ...(existing.stage_outputs ?? {}),
              [data.stage]: data.markdown,
            },
            stage_output_sources: {
              ...(existing.stage_output_sources ?? {}),
              [data.stage]: data.output_source ?? {},
            },
          };
        } else {
          results.push({
            vuln_index: data.vuln_index,
            verdict: "tp",
            severity: "low",
            reason: "",
            vulnerability_report: "",
            stage_outputs: { [data.stage]: data.markdown },
            stage_output_sources: { [data.stage]: data.output_source ?? {} },
            created_at: new Date().toISOString(),
          });
        }
        return { ...prev, status: "running", results };
      });
    },
    onFpReviewResult: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const existing = prev.results.find((result) => result.vuln_index === data.vuln_index);
        const newResult = {
          vuln_index: data.vuln_index,
          verdict: data.verdict,
          severity: data.severity,
          reason: data.reason,
          vulnerability_report: data.vulnerability_report ?? "",
          stage_outputs: {
            ...(existing?.stage_outputs ?? {}),
            ...(data.stage_outputs ?? {}),
          },
          match_reference: data.match_reference ?? existing?.match_reference ?? "",
          match_type: data.match_type ?? existing?.match_type ?? "",
          stage_output_sources: {
            ...(existing?.stage_output_sources ?? {}),
            ...(data.stage_output_sources ?? {}),
          },
          output_source: data.output_source ?? existing?.output_source,
          created_at: new Date().toISOString(),
        };
        return {
          ...prev,
          status: "running",
          results: [
            ...prev.results.filter((result) => result.vuln_index !== data.vuln_index),
            newResult,
          ],
        };
      });
    },
    onFpReviewFinish: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return { ...prev, status: data.status, error_message: data.error_message, current_vuln_index: null };
      });
    },
    onIndexStatus: (data) => {
      setIndexStatus(data);
    },
  }), [scanId]);

  const sseStateSetters = useMemo<SSEStateSetters>(() => ({
    setScan,
    setFpReview,
    setIndexStatus,
  }), []);

  useScanSSE(scanId, sseHandlers, sseStateSetters);

  const handleFpReview = async () => {
    setFpReviewLoading(true);
    try {
      const started = await triggerFpReview(scanId);
      setFpReview({
        review_id: started.review_id,
        scan_id: scanId,
        status: started.status ?? "running",
        total: started.total ?? 0,
        processed: started.processed ?? 0,
        current_vuln_index: null,
        results: [],
        error_message: null,
        created_at: new Date().toISOString(),
      });
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "触发失败";
      alert(`AI去误报失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewLoading(false);
    }
  };

  const handleStopFpReview = async () => {
    setFpReviewStopping(true);
    try {
      await stopFpReview(scanId);
      const job = await getFpReview(scanId);
      setFpReview(job);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "停止失败";
      alert(`停止AI复核失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewStopping(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopScan(scanId);
    } catch {
      setStopping(false);
    }
  };

  const handleRetryIncomplete = async () => {
    setRetryingIncomplete(true);
    try {
      await retryIncompleteScan(scanId);
      const next = await getScanStatus(scanId);
      setScan(next);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "续扫失败";
      alert(`续扫未完成候选失败：${msg || "未知错误"}`);
    } finally {
      setRetryingIncomplete(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!scan) return;
    setDownloadingReport(true);
    try {
      const blob = await downloadScanReport(scan.scan_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report-${scan.scan_id}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "未知错误";
      alert(`下载 CSV 失败：${msg}`);
    } finally {
      setDownloadingReport(false);
    }
  };

  const handleExportZip = async () => {
    if (!scan) return;
    setExportingZip(true);
    try {
      const blob = await downloadScanReportZip(scan.scan_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan-${scan.scan_id}-report.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "未知错误";
      alert(`导出报告失败：${msg}`);
    } finally {
      setExportingZip(false);
    }
  };

  // Handle feedback selection change — update backend and refresh skills
  const handleFeedbackChange = async (ids: Set<string>) => {
    setSelectedFeedbackIds(ids);
    setScan((prev) => prev ? { ...prev, feedback_ids: [...ids] } : prev);
    try {
      await updateScanFeedback(scanId, [...ids]);
      // Refresh SKILL preview if it's currently open
      if (skillOpen && skillType) {
        const content = skillType === "__fp_review__"
          ? await getFpReviewSkill(scanId)
          : await getSkillContent(scanId, skillType);
        setSkillContent(content);
      }
    } catch {
      // ignore
    }
  };

  const addSelectedFeedbackIds = async (feedbackIds: string[]) => {
    if (feedbackIds.length === 0) return;
    const next = new Set(selectedFeedbackIds ?? scan?.feedback_ids ?? []);
    for (const id of feedbackIds) next.add(id);
    await handleFeedbackChange(next);
  };

  const removeSelectedFeedbackIds = async (feedbackIds: string[]) => {
    if (feedbackIds.length === 0) return;
    const next = new Set(selectedFeedbackIds ?? scan?.feedback_ids ?? []);
    for (const id of feedbackIds) next.delete(id);
    setSelectedFeedbackIds(next);
    setScan((prev) => prev ? { ...prev, feedback_ids: [...next] } : prev);
  };

  const loadSkill = async (vulnType: string) => {
    setSkillType(vulnType);
    setSkillLoading(true);
    try {
      const content = await getSkillContent(scanId, vulnType);
      setSkillContent(content);
    } catch {
      setSkillContent("加载失败");
    } finally {
      setSkillLoading(false);
    }
  };

  const loadFpReviewSkill = async () => {
    setSkillType("__fp_review__");
    setSkillLoading(true);
    try {
      const content = await getFpReviewSkill(scanId);
      setSkillContent(content);
    } catch {
      setSkillContent("加载失败");
    } finally {
      setSkillLoading(false);
    }
  };

  const loadSkillReports = async () => {
    setReportsOpen(true);
    setReportsLoading(true);
    try {
      const next = await getSkillReports(scanId);
      setReports(next);
      setActiveReportIndex(0);
    } catch {
      setReports([]);
    } finally {
      setReportsLoading(false);
    }
  };

  // Compute log event count for scroll/unseen tracking
  const logEventCount = scan?.events.length ?? 0;

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current && logOpen) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logEventCount, logOpen]);

  // Track unseen events
  useEffect(() => {
    if (logOpen) {
      setLastSeenEvents(logEventCount);
    }
  }, [logOpen, logEventCount]);

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  const pct = Math.round(scan.progress * 100);
  const allLogEvents = scan.events;
  const truncated = allLogEvents.length > MAX_LOG_LINES;
  const logEvents = truncated ? allLogEvents.slice(-MAX_LOG_LINES) : allLogEvents;
  const unseenCount = allLogEvents.length - lastSeenEvents;
  const feedbackCount = selectedFeedbackIds?.size ?? scan.feedback_ids?.length ?? 0;
  const agentDisconnectError = isAgentDisconnectError(scan.error_message);
  const staleAgentDisconnectError = scan.status === "cancelled" && agentDisconnectError && !!scan.agent_online;
  const visibleErrorMessage = staleAgentDisconnectError ? null : scan.error_message;
  const isFpReviewing = fpReview?.status === "running" || fpReview?.status === "pending";
  const fpIndicesSource = !isFpReviewing
    ? []
    : fpReview?.current_vuln_indices?.length
    ? fpReview.current_vuln_indices
    : fpReview?.current_vuln_index != null
    ? [fpReview.current_vuln_index]
    : [];
  const currentFpReviewIndices = new Set(fpIndicesSource.filter((i) => i >= 0));
  const currentFpReviewTargets = [...currentFpReviewIndices]
    .sort((a, b) => a - b)
    .map((i) => scan.vulnerabilities[i])
    .filter(Boolean);
  const reportCheckers = checkers.filter(
    (checker) => scan.scan_items.includes(checker.name) && checker.result_mode === "markdown_reports",
  );
  const hasReportModeSkill = reportCheckers.length > 0 || (scan.skill_reports?.length ?? 0) > 0;
  const displayedReports = reports.length > 0 ? reports : (scan.skill_reports ?? []);
  const activeReport = displayedReports[activeReportIndex] ?? displayedReports[0];
  const retryableCount = scan.vulnerabilities.filter(
    (v) => !hasFinalUserVerdict(v) && (v.ai_verdict === "timeout" || v.ai_verdict === "no_result" || v.ai_verdict === "failed"),
  ).length || scan.retryable_candidates_count || 0;
  const issueCount = effectiveIssueCount(scan, fpReview);
  const variantIssueCount = scan.vulnerabilities.filter((v) => v.variant_of).length;
  const indexProgress = formatIndexProgress(indexStatus, scan);
  const threatEvents = filterEvents(scan.events, ["init", "mcp_ready", "static_analysis", "git_history"]);
  const miningEvents = filterEvents(scan.events, ["variant_hunt", "auditing", "opencode_output"]);
  const validationEvents = filterEvents(scan.events, ["fp_review"]);
  const issuesView = scan.vulnerabilities.length === 0 && isDone ? (
    <div className="flex items-center justify-center h-64 text-slate-400">
      <div className="text-center">
        <p className="text-lg font-medium">未发现漏洞</p>
        <p className="text-sm mt-1 text-slate-500">当前扫描没有可展示的问题</p>
      </div>
    </div>
  ) : (
    <VulnerabilityList
      scanId={scanId}
      vulnerabilities={scan.vulnerabilities}
      events={scan.events}
      isScanning={!!isRunning}
      currentCandidate={scan.current_candidate}
      totalCandidates={scan.total_candidates}
      processedCandidates={scan.processed_candidates}
      fpReview={fpReview}
      currentFpReviewIndices={currentFpReviewIndices}
      fpReviewRunning={isFpReviewing}
      onFeedbackCreated={addSelectedFeedbackIds}
      onFeedbackRemoved={removeSelectedFeedbackIds}
      onVulnMarked={() => {
        if (skillOpen && skillType) {
          if (skillType === "__fp_review__") {
            getFpReviewSkill(scanId).then(setSkillContent).catch(() => {});
          } else {
            getSkillContent(scanId, skillType).then(setSkillContent).catch(() => {});
          }
        }
      }}
    />
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Top bar */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              返回
            </button>
            <h1 className="text-lg font-bold text-white">OpenDeepHole</h1>
            <span className="text-sm text-slate-400">
              {scan.status === "cancelled"
                ? (agentDisconnectError ? (scan.agent_online ? "扫描已中断" : "Agent 断开，已中断") : "已取消")
                : isDone ? "扫描完成" : "扫描中..."}
            </span>
            {scan.agent_name && (
              <span className="flex items-center gap-1.5 text-sm text-slate-400 border-l border-slate-600 pl-4">
                <span
                  className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    scan.agent_online ? "bg-green-400" : "bg-slate-500"
                  }`}
                />
                Agent: {scan.agent_name}
                {!scan.agent_online && (
                  <span className="text-xs text-slate-500">(离线)</span>
                )}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            {/* Feedback button with count badge */}
            <button
              onClick={() => setFeedbackOpen(true)}
              className="px-3 py-1.5 text-sm font-medium text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              误报屏蔽规则
              {feedbackCount > 0 && (
                <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
                  {feedbackCount}
                </span>
              )}
            </button>
            <button
              onClick={() => {
                setSkillOpen(true);
                if (!skillType && scan.scan_items.length > 0) {
                  loadSkill(scan.scan_items[0]);
                }
              }}
              className="px-3 py-1.5 text-sm font-medium text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              SKILL 预览
            </button>
            <button
              onClick={() => setModelPoolOpen(true)}
              className="px-3 py-1.5 text-sm font-medium text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/10 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 19V5m0 14h16M8 15V9m4 6V7m4 8v-4" />
              </svg>
              模型看板
              {(scan.opencode_pool?.global_running ?? 0) > 0 && (
                <span className="text-xs text-cyan-100">{scan.opencode_pool?.global_running}</span>
              )}
            </button>
            {hasReportModeSkill && (
              <button
                onClick={loadSkillReports}
                className="px-3 py-1.5 text-sm font-medium text-purple-300 border border-purple-500/40 rounded-lg hover:bg-purple-500/10 transition-colors flex items-center gap-1.5"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                SKILL 报告
                {(scan.skill_reports?.length ?? 0) > 0 && (
                  <span className="text-xs text-purple-200">{scan.skill_reports.length}</span>
                )}
              </button>
            )}
            {(() => {
              const confirmedVulns = scan.vulnerabilities.filter(
                (v) => (v.ai_verdict === "confirmed" || (!v.ai_verdict && v.confirmed)) && !hasFinalUserVerdict(v)
              ).length;
              const canTrigger = confirmedVulns > 0;
              const isReviewing = fpReview?.status === "running" || fpReview?.status === "pending";
              return (
                <>
                  <button
                    onClick={handleFpReview}
                    disabled={!canTrigger || fpReviewLoading || !!isReviewing}
                    className="px-3 py-1.5 text-sm font-medium text-amber-400 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
                    title={!canTrigger ? "需要存在 LLM 正报才可使用" : "使用 AI 对已确认漏洞逐条进行误报复核"}
                  >
                    {isReviewing ? (
                      <>
                        <div className="w-3 h-3 border border-amber-500/30 border-t-amber-400 rounded-full animate-spin" />
                        复核中 {fpReview!.processed}/{fpReview!.total}
                      </>
                    ) : fpReviewLoading ? (
                      <>
                        <div className="w-3 h-3 border border-amber-500/30 border-t-amber-400 rounded-full animate-spin" />
                        启动中...
                      </>
                    ) : (
                      <>
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        AI去误报
                        {fpReview?.status === "complete" && (
                          <span className="text-xs text-green-400 ml-0.5">✓</span>
                        )}
                        {fpReview?.status === "cancelled" && (
                          <span className="text-xs text-amber-300 ml-0.5">已停止</span>
                        )}
                      </>
                    )}
                  </button>
                  {isReviewing && (
                    <button
                      onClick={handleStopFpReview}
                      disabled={fpReviewStopping}
                      className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      title="停止当前AI去误报复核"
                    >
                      {fpReviewStopping ? "停止中..." : "停止复核"}
                    </button>
                  )}
                </>
              );
            })()}
            {isDone && (
              <>
                {retryableCount > 0 && (
                  <button
                    onClick={handleRetryIncomplete}
                    disabled={retryingIncomplete || !scan.agent_online}
                    title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${retryableCount} 个未完成候选`}
                    className="px-3 py-1.5 text-sm font-medium text-amber-300 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {retryingIncomplete ? "启动中..." : `续扫未完成 ${retryableCount}`}
                  </button>
                )}
              </>
            )}
            {isDone && (
              <button
                onClick={handleExportZip}
                disabled={exportingZip}
                className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {exportingZip ? "导出中..." : "导出报告"}
              </button>
            )}
            {isDone && (
              <button
                onClick={handleDownloadReport}
                disabled={downloadingReport}
                className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {downloadingReport ? "下载中..." : "下载 CSV"}
              </button>
            )}
            {isRunning && (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {stopping ? "停止中..." : "停止扫描"}
              </button>
            )}
          </div>
        </div>

        {/* Page tabs */}
        <div className="flex flex-wrap items-center gap-2 border-t border-slate-700/60 pt-3">
          {MAIN_TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActiveTab(tab.key)}
              className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
                activeTab === tab.key
                  ? "border-blue-500/50 bg-blue-500/15 text-blue-100"
                  : "border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-700"
              }`}
            >
              {tab.label}
              {tab.key === "issues" && (
                <span className="ml-1.5 text-xs text-red-300">{issueCount}</span>
              )}
            </button>
          ))}
        </div>

        {/* Error */}
        {visibleErrorMessage && (
          <div className="mt-3 p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {visibleErrorMessage}
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-auto px-6 py-4">
        {activeTab === "overview" && (
          <ScanOverview
            scan={scan}
            issueCount={issueCount}
            retryableCount={retryableCount}
            variantIssueCount={variantIssueCount}
            gitHistoryCount={gitHistory.length}
            currentStage={currentStageLabel(scan, scan.events)}
            indexProgress={indexProgress}
            pct={pct}
            isRunning={!!isRunning}
            isDone={!!isDone}
            fpReview={fpReview}
            isFpReviewing={isFpReviewing}
            currentFpReviewTargets={currentFpReviewTargets}
            hasReportModeSkill={hasReportModeSkill}
            onNavigate={setActiveTab}
          />
        )}
        {activeTab === "threat" && (
          <TabbedPanel
            tabs={THREAT_TABS}
            active={activeThreatTab}
            onChange={setActiveThreatTab}
          >
            {activeThreatTab === "index" && (
              <IndexTaskPanel progress={indexProgress} indexStatus={indexStatus} events={threatEvents} />
            )}
            {activeThreatTab === "static" && (
              <StaticTaskPanel scan={scan} events={filterEvents(scan.events, ["static_analysis"])} />
            )}
            {activeThreatTab === "git_history" && (
              <GitHistoryPanel patterns={gitHistory} events={filterEvents(scan.events, ["git_history"])} />
            )}
          </TabbedPanel>
        )}
        {activeTab === "mining" && (
          <TabbedPanel
            tabs={MINING_TABS}
            active={activeMiningTab}
            onChange={setActiveMiningTab}
          >
            {activeMiningTab === "candidate_audit" && (
              <AuditTaskPanel
                scan={scan}
                pct={pct}
                currentCandidate={scan.current_candidate}
                events={filterEvents(miningEvents, ["auditing", "opencode_output"])}
                pool={scan.opencode_pool ?? null}
              />
            )}
            {activeMiningTab === "variant_hunt" && (
              <VariantHuntPanel
                variantIssueCount={variantIssueCount}
                vulnerabilities={scan.vulnerabilities}
                events={filterEvents(scan.events, ["variant_hunt"])}
              />
            )}
          </TabbedPanel>
        )}
        {activeTab === "validation" && (
          <PlaceholderPanel
            title="漏洞验证"
            description="漏洞验证任务入口已预留。当前可在顶部继续使用 AI 去误报复核，并在发现的问题页签查看复核结果。"
            events={validationEvents}
          />
        )}
        {activeTab === "reports" && (
          <ReportGenerationPanel
            scan={scan}
            displayedReports={displayedReports}
            hasReportModeSkill={hasReportModeSkill}
            isRunning={!!isRunning}
            onOpenReports={loadSkillReports}
            onExportZip={handleExportZip}
            onDownloadCsv={handleDownloadReport}
            exportingZip={exportingZip}
            downloadingReport={downloadingReport}
          />
        )}
        {activeTab === "issues" && issuesView}
      </div>

      {/* Log floating button */}
      <button
        onClick={() => { setLogOpen(true); setLastSeenEvents(logEvents.length); }}
        className="fixed bottom-6 right-6 px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-medium rounded-full shadow-lg border border-slate-600 transition-colors z-40 flex items-center gap-2"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        日志
        {unseenCount > 0 && (
          <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
            {unseenCount > 99 ? "99+" : unseenCount}
          </span>
        )}
      </button>

      {/* Log slide-over panel */}
      {logOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setLogOpen(false)}
          />
          {/* Panel */}
          <div className="fixed right-0 top-0 bottom-0 w-[32rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                处理日志
              </h3>
              <button
                onClick={() => setLogOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-3 space-y-1 font-mono text-xs"
            >
              {logEvents.length === 0 ? (
                <p className="text-slate-500">等待事件...</p>
              ) : (
                <>
                  {truncated && (
                    <p className="text-slate-600 text-center py-1 border-b border-slate-700/50 mb-1">
                      ... 已省略 {allLogEvents.length - MAX_LOG_LINES} 条早期日志 ...
                    </p>
                  )}
                  {logEvents.map((event, i) => (
                    <EventLine key={i} event={event} />
                  ))}
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* Feedback Manager Panel */}
      {feedbackOpen && scan.project_id && (
        <FeedbackManager
          checkers={checkers.filter((c) => scan.scan_items.includes(c.name))}
          initialTypes={scan.scan_items}
          scanId={scanId}
          projectId={scan.project_id}
          selectedIds={selectedFeedbackIds ?? new Set(scan.feedback_ids)}
          onSelectionChange={handleFeedbackChange}
          onFeedbackCreated={addSelectedFeedbackIds}
          onClose={() => setFeedbackOpen(false)}
        />
      )}

      {/* OpenCode model pool dashboard */}
      {modelPoolOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setModelPoolOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[60rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                  OpenCode 模型看板
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  {scan.opencode_pool?.updated_at
                    ? `最后更新：${formatDateTime(scan.opencode_pool.updated_at)}`
                    : "当前扫描尚未产生 OpenCode 模型池统计"}
                </p>
              </div>
              <button
                onClick={() => setModelPoolOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <ModelPoolDashboard pool={scan.opencode_pool ?? null} />
          </div>
        </>
      )}

      {/* SKILL Preview Panel */}
      {skillOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setSkillOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[40rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                SKILL 预览
              </h3>
              <button
                onClick={() => setSkillOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {/* Type tabs */}
            <div className="flex gap-1.5 px-4 py-2.5 border-b border-slate-700/50 overflow-x-auto">
              {scan.scan_items.map((item) => (
                <button
                  key={item}
                  onClick={() => loadSkill(item)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
                    skillType === item
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                      : "text-slate-400 border-slate-700 hover:bg-slate-800"
                  }`}
                >
                  {item.toUpperCase()}
                </button>
              ))}
              <button
                onClick={() => loadFpReviewSkill()}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
                  skillType === "__fp_review__"
                    ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                    : "text-slate-400 border-slate-700 hover:bg-slate-800"
                }`}
              >
                FP REVIEW
              </button>
            </div>
            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4">
              {skillLoading ? (
                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <div className="w-3 h-3 border border-slate-600 border-t-blue-400 rounded-full animate-spin" />
                  加载中...
                </div>
              ) : (
                <pre className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed font-mono">
                  {skillContent}
                </pre>
              )}
            </div>
          </div>
        </>
      )}

      {/* Markdown report panel */}
      {reportsOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setReportsOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[52rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                  SKILL 报告
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  {isRunning ? "报告型 SKILL 正在运行或等待同步" : `已同步 ${displayedReports.length} 个 Markdown 报告`}
                </p>
              </div>
              <button
                onClick={() => setReportsOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="flex min-h-0 flex-1">
              <div className="w-64 shrink-0 border-r border-slate-800 p-3 overflow-y-auto">
                {reportsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <div className="w-3 h-3 border border-slate-600 border-t-purple-400 rounded-full animate-spin" />
                    加载中...
                  </div>
                ) : displayedReports.length === 0 ? (
                  <div className="rounded border border-slate-800 bg-slate-950 px-3 py-4 text-xs text-slate-500">
                    暂无报告
                  </div>
                ) : (
                  <div className="space-y-2">
                    {displayedReports.map((report, index) => (
                      <button
                        key={`${report.checker_name}-${report.filename}-${index}`}
                        onClick={() => setActiveReportIndex(index)}
                        className={`w-full rounded-lg border px-3 py-2 text-left transition-colors ${
                          index === activeReportIndex
                            ? "border-purple-500/50 bg-purple-500/10"
                            : "border-slate-800 bg-slate-950 hover:border-slate-700"
                        }`}
                      >
                        <div className="text-xs font-semibold text-slate-200 truncate">{report.title || report.filename}</div>
                        <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">{report.checker_name}/{report.filename}</div>
                        {hasOutputSource(report.output_source) && (
                          <div className="mt-1 text-[11px] text-cyan-300 truncate">{formatOutputSource(report.output_source)}</div>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="min-w-0 flex-1 overflow-y-auto p-5">
                {activeReport ? (
                  <>
                    {hasOutputSource(activeReport.output_source) && (
                      <div
                        className="mb-3 rounded border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs text-cyan-200"
                        title={[
                          activeReport.output_source?.agent_id ? `Agent ID: ${activeReport.output_source.agent_id}` : "",
                          activeReport.output_source?.agent_session_id ? `Session: ${activeReport.output_source.agent_session_id}` : "",
                          activeReport.output_source?.task_id ? `Task: ${activeReport.output_source.task_id}` : "",
                        ].filter(Boolean).join("\n")}
                      >
                        输出来源：{formatOutputSource(activeReport.output_source)}
                      </div>
                    )}
                    <MarkdownContent content={activeReport.content} />
                  </>
                ) : (
                  <div className="text-sm text-slate-500">选择左侧报告查看内容</div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function ScanOverview({
  scan,
  issueCount,
  retryableCount,
  variantIssueCount,
  gitHistoryCount,
  currentStage,
  indexProgress,
  pct,
  isRunning,
  isDone,
  fpReview,
  isFpReviewing,
  currentFpReviewTargets,
  hasReportModeSkill,
  onNavigate,
}: {
  scan: ScanStatusType;
  issueCount: number;
  retryableCount: number;
  variantIssueCount: number;
  gitHistoryCount: number;
  currentStage: string;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  pct: number;
  isRunning: boolean;
  isDone: boolean;
  fpReview: FpReviewJob | null;
  isFpReviewing: boolean;
  currentFpReviewTargets: Vulnerability[];
  hasReportModeSkill: boolean;
  onNavigate: (tab: MainTab) => void;
}) {
  const staticSeen = scan.static_analysis_done || scan.status === "analyzing" || scan.status === "auditing" || hasEvent(scan.events, ["static_analysis"]);
  const staticScannedFiles = staticSeen ? scan.static_scanned_files : 0;
  const staticTotalFiles = staticSeen ? scan.static_total_files : 0;
  const staticPct = percent(staticScannedFiles, staticTotalFiles);
  const auditRunning = scan.status === "auditing";
  const staticRunning = scan.status === "analyzing" && !scan.static_analysis_done;
  const target = scan.current_candidate;
  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">当前扫描</div>
            <h2 className="mt-1 text-xl font-semibold text-white">{currentStage}</h2>
            <p className="mt-1 text-sm text-slate-400">
              {scan.product || scan.project_id || scan.scan_id}
              {scan.agent_name && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  Agent: <span className={scan.agent_online ? "text-green-300" : "text-slate-500"}>{scan.agent_name}</span>
                </span>
              )}
            </p>
          </div>
          <StatusPill
            label={scan.status === "complete" ? "已完成" : scan.status === "error" ? "异常" : scan.status === "cancelled" ? "已取消" : isRunning ? "运行中" : "等待"}
            tone={scan.status === "error" ? "red" : scan.status === "cancelled" ? "amber" : isDone ? "green" : "blue"}
          />
        </div>
      </section>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <OverviewMetric icon="target" label="候选点" value={scan.total_candidates || scan.vulnerabilities.length} detail={`${scan.processed_candidates} 已审计`} tone="blue" />
        <OverviewMetric icon="alert" label="发现的问题" value={issueCount} detail={`${scan.vulnerabilities.length} 条结果`} tone="red" onClick={() => onNavigate("issues")} />
        <OverviewMetric icon="history" label="历史模式" value={gitHistoryCount} detail={`${variantIssueCount} 个变体候选`} tone="purple" onClick={() => onNavigate("threat")} />
        <OverviewMetric icon="queue" label="未完成候选" value={retryableCount} detail={retryableCount > 0 ? "可续扫" : "无待处理项"} tone="amber" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_22rem]">
        <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">任务进展</h3>
            <span className="text-xs text-slate-500">扫描 ID: {scan.scan_id}</span>
          </div>
          <div className="space-y-3">
            <TaskSummaryRow
              label="代码索引"
              status={taskStateLabel(indexProgress.done, indexProgress.running, indexProgress.failed)}
              tone={indexProgress.failed ? "red" : indexProgress.done ? "green" : indexProgress.running ? "amber" : "slate"}
              progress={indexProgress.total ? percent(indexProgress.current, indexProgress.total) : undefined}
              detail={indexProgress.total ? `${indexProgress.current}/${indexProgress.total} 文件` : "等待索引状态"}
            />
            <TaskSummaryRow
              label="静态分析"
              status={taskStateLabel(scan.static_analysis_done, staticRunning, scan.status === "error")}
              tone={scan.status === "error" ? "red" : scan.static_analysis_done ? "green" : staticRunning ? "cyan" : "slate"}
              progress={staticTotalFiles ? staticPct : undefined}
              detail={staticTotalFiles ? `${staticScannedFiles}/${staticTotalFiles} 文件` : "等待静态分析"}
            />
            <TaskSummaryRow
              label="Git 历史问题分析"
              status={taskStateLabel(gitHistoryCount > 0 || hasEvent(scan.events, ["git_history"]), hasEvent(scan.events, ["git_history"]) && !auditRunning && !isDone)}
              tone={gitHistoryCount > 0 ? "purple" : hasEvent(scan.events, ["git_history"]) ? "amber" : "slate"}
              detail={gitHistoryCount > 0 ? `${gitHistoryCount} 条历史问题模式` : "暂无历史模式"}
            />
            <TaskSummaryRow
              label="候选点 AI 审计"
              status={taskStateLabel(isDone || (scan.total_candidates > 0 && scan.processed_candidates >= scan.total_candidates), auditRunning)}
              tone={auditRunning ? "blue" : isDone ? "green" : "slate"}
              progress={scan.static_analysis_done ? pct : undefined}
              detail={scan.total_candidates ? `${scan.processed_candidates}/${scan.total_candidates} 候选点` : "等待候选点"}
            />
            <TaskSummaryRow
              label="漏洞验证"
              status={fpReview ? taskStateLabel(fpReview.status === "complete", isFpReviewing, fpReview.status === "error") : "预留"}
              tone={isFpReviewing ? "amber" : fpReview?.status === "complete" ? "green" : fpReview?.status === "error" ? "red" : "slate"}
              progress={fpReview?.total ? percent(fpReview.processed, fpReview.total) : undefined}
              detail={fpReview ? `${fpReview.processed}/${fpReview.total} 已复核` : "后续接入验证任务"}
            />
            <TaskSummaryRow
              label="漏洞报告生成"
              status={hasReportModeSkill ? (isRunning ? "同步中" : "可查看") : "预留"}
              tone={hasReportModeSkill ? "purple" : "slate"}
              detail={hasReportModeSkill ? `${scan.skill_reports?.length ?? 0} 个 SKILL 报告` : "后续接入报告生成任务"}
            />
          </div>
        </section>

        <aside className="space-y-4">
          <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
            <h3 className="text-sm font-semibold text-slate-200">当前目标</h3>
            {target ? (
              <div className="mt-3 rounded-lg border border-blue-500/30 bg-blue-500/10 p-3">
                <div className="font-mono text-xs text-blue-100">{target.file}:{target.line}</div>
                <div className="mt-1 truncate font-mono text-xs text-slate-400">{target.function}</div>
                <div className="mt-2 text-xs text-slate-300">{target.vuln_type.toUpperCase()}</div>
              </div>
            ) : currentFpReviewTargets.length > 0 ? (
              <div className="mt-3 space-y-2">
                {currentFpReviewTargets.map((item) => (
                  <div key={`${item.file}:${item.line}:${item.function}`} className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
                    <div className="font-mono text-xs text-amber-100">{item.file}:{item.line}</div>
                    <div className="mt-1 truncate font-mono text-xs text-slate-400">{item.function}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-slate-500">当前没有正在处理的候选。</p>
            )}
          </section>
          <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
            <h3 className="text-sm font-semibold text-slate-200">模型池</h3>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <MiniMetric label="运行中" value={scan.opencode_pool?.global_running ?? 0} tone="cyan" />
              <MiniMetric label="排队中" value={scan.opencode_pool?.global_queued ?? 0} tone="amber" />
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function OverviewMetric({
  icon,
  label,
  value,
  detail,
  tone,
  onClick,
}: {
  icon: "target" | "alert" | "history" | "queue";
  label: string;
  value: number;
  detail: string;
  tone: TaskTone;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
        <PanelIcon name={icon} />
      </div>
      <div className="min-w-0">
        <div className="text-xs text-slate-500">{label}</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`text-2xl font-semibold ${toneText(tone)}`}>{value}</span>
          <span className="truncate text-xs text-slate-500">{detail}</span>
        </div>
      </div>
    </>
  );
  const cls = "flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-left";
  if (onClick) {
    return <button type="button" onClick={onClick} className={`${cls} transition-colors hover:border-slate-600 hover:bg-slate-800/70`}>{content}</button>;
  }
  return <div className={cls}>{content}</div>;
}

function TabbedPanel<T extends string>({
  tabs,
  active,
  onChange,
  children,
}: {
  tabs: { key: T; label: string }[];
  active: T;
  onChange: (value: T) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => onChange(tab.key)}
            className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
              active === tab.key
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-100"
                : "border-slate-700 bg-slate-900/70 text-slate-300 hover:bg-slate-800"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {children}
    </div>
  );
}

function IndexTaskPanel({
  progress,
  indexStatus,
  events,
}: {
  progress: ReturnType<typeof formatIndexProgress>;
  indexStatus: IndexStatus | null;
  events: ScanEvent[];
}) {
  return (
    <TaskPanel
      title="代码索引构建"
      status={taskStateLabel(progress.done, progress.running, progress.failed)}
      tone={progress.failed ? "red" : progress.done ? "green" : progress.running ? "amber" : "slate"}
      summary={indexStatus?.error || "构建代码索引，用于后续函数、调用关系和上下文检索。"}
    >
      <ProgressBlock
        label="索引文件"
        current={progress.current}
        total={progress.total}
        fallback={indexStatus?.status === "not_started" ? "尚未收到索引进度" : "等待索引文件总数"}
      />
      <EventList events={events} empty="暂无威胁分析日志" />
    </TaskPanel>
  );
}

function StaticTaskPanel({ scan, events }: { scan: ScanStatusType; events: ScanEvent[] }) {
  const running = scan.status === "analyzing" && !scan.static_analysis_done;
  const seen = scan.static_analysis_done || running || scan.status === "auditing" || events.length > 0;
  const scannedFiles = seen ? scan.static_scanned_files : 0;
  const totalFiles = seen ? scan.static_total_files : 0;
  return (
    <TaskPanel
      title="静态分析过程"
      status={taskStateLabel(scan.static_analysis_done, running, scan.status === "error")}
      tone={scan.static_analysis_done ? "green" : running ? "cyan" : scan.status === "error" ? "red" : "slate"}
      summary="运行已选择的静态规则，产出候选点并进入后续 AI 审计。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="扫描文件" value={scannedFiles} tone="cyan" />
        <MiniMetric label="总文件" value={totalFiles} />
        <MiniMetric label="候选点" value={scan.total_candidates} tone="blue" />
      </div>
      <ProgressBlock label="静态分析" current={scannedFiles} total={totalFiles} fallback="等待静态分析进度" />
      <EventList events={events} empty="暂无静态分析日志" />
    </TaskPanel>
  );
}

function GitHistoryPanel({ patterns, events }: { patterns: HistoryPattern[]; events: ScanEvent[] }) {
  return (
    <TaskPanel
      title="Git 历史问题分析"
      status={patterns.length > 0 ? "已提炼" : events.length > 0 ? "已运行" : "等待"}
      tone={patterns.length > 0 ? "purple" : events.length > 0 ? "amber" : "slate"}
      summary="分析历史提交中的安全修复，提炼可用于同类问题挖掘的问题模式。"
    >
      {patterns.length === 0 ? (
        <EmptyState text="暂无历史问题模式。目标不是 Git 仓库、未启用该能力或尚未运行到此步骤时会显示为空。" />
      ) : (
        <div className="space-y-2">
          {patterns.map((pattern, index) => (
            <div key={`${pattern.source}-${index}`} className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-3">
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-purple-200">{pattern.source || "unknown"}</span>
                {pattern.lens_hint && (
                  <span className="rounded border border-slate-600 px-1.5 py-0.5 text-xs text-slate-300">{pattern.lens_hint}</span>
                )}
              </div>
              <p className="text-sm text-slate-200">{pattern.pattern}</p>
              {pattern.files.length > 0 && <p className="mt-1 text-xs text-slate-500">涉及文件：{pattern.files.join(", ")}</p>}
              {pattern.rationale && <p className="mt-1 text-xs text-slate-400">{pattern.rationale}</p>}
            </div>
          ))}
        </div>
      )}
      <EventList events={events} empty="暂无 Git 历史分析日志" />
    </TaskPanel>
  );
}

function AuditTaskPanel({
  scan,
  pct,
  currentCandidate,
  events,
  pool,
}: {
  scan: ScanStatusType;
  pct: number;
  currentCandidate: Candidate | null;
  events: ScanEvent[];
  pool: OpenCodePoolStatus | null;
}) {
  return (
    <TaskPanel
      title="候选点 AI 审计"
      status={scan.status === "auditing" ? "进行中" : scan.status === "complete" ? "完成" : scan.status === "error" ? "异常" : "等待"}
      tone={scan.status === "auditing" ? "blue" : scan.status === "complete" ? "green" : scan.status === "error" ? "red" : "slate"}
      summary="对静态分析和历史同类问题挖掘产生的候选点逐条审计，确认是否为真实问题。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <MiniMetric label="已审计" value={scan.processed_candidates} tone="blue" />
        <MiniMetric label="总候选" value={scan.total_candidates} />
        <MiniMetric label="运行中" value={pool?.global_running ?? 0} tone="cyan" />
        <MiniMetric label="排队中" value={pool?.global_queued ?? 0} tone="amber" />
      </div>
      <ProgressBlock label="AI 审计" current={scan.processed_candidates} total={scan.total_candidates} percentOverride={scan.static_analysis_done ? pct : undefined} fallback="等待审计候选点" />
      {currentCandidate && (
        <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3">
          <div className="text-xs font-semibold uppercase text-blue-200">正在审计</div>
          <div className="mt-1 font-mono text-xs text-slate-200">{currentCandidate.file}:{currentCandidate.line}</div>
          <div className="mt-1 truncate font-mono text-xs text-slate-500">{currentCandidate.function}</div>
        </div>
      )}
      <EventList events={events} empty="暂无 AI 审计日志" />
    </TaskPanel>
  );
}

function VariantHuntPanel({
  variantIssueCount,
  vulnerabilities,
  events,
}: {
  variantIssueCount: number;
  vulnerabilities: Vulnerability[];
  events: ScanEvent[];
}) {
  const variants = vulnerabilities.filter((vuln) => vuln.variant_of);
  return (
    <TaskPanel
      title="历史同类问题挖掘"
      status={events.length > 0 ? "已运行" : "等待"}
      tone={variantIssueCount > 0 ? "purple" : events.length > 0 ? "amber" : "slate"}
      summary="基于 Git 历史提炼的问题模式，在当前代码中搜索同类变体候选。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <MiniMetric label="变体候选" value={variantIssueCount} tone="purple" />
        <MiniMetric label="变体来源结果" value={variants.length} />
      </div>
      {variants.length > 0 ? (
        <div className="space-y-2">
          {variants.slice(0, 12).map((vuln, index) => (
            <div key={`${vuln.file}:${vuln.line}:${index}`} className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
              <div className="font-mono text-xs text-slate-200">{vuln.file}:{vuln.line}</div>
              <div className="mt-1 text-xs text-purple-200">{vuln.variant_of}</div>
            </div>
          ))}
          {variants.length > 12 && <div className="text-xs text-slate-500">仅展示前 12 条，完整列表见“发现的问题”。</div>}
        </div>
      ) : (
        <EmptyState text="暂未产生历史同类变体候选。" />
      )}
      <EventList events={events} empty="暂无历史同类问题挖掘日志" />
    </TaskPanel>
  );
}

function PlaceholderPanel({ title, description, events }: { title: string; description: string; events: ScanEvent[] }) {
  return (
    <TaskPanel title={title} status="预留" tone="slate" summary={description}>
      <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-8 text-center text-sm text-slate-500">
        该页签已预留，后续任务接入后会在这里展示执行状态、当前目标和结果。
      </div>
      <EventList events={events} empty="暂无验证任务日志" />
    </TaskPanel>
  );
}

function ReportGenerationPanel({
  scan,
  displayedReports,
  hasReportModeSkill,
  isRunning,
  onOpenReports,
  onExportZip,
  onDownloadCsv,
  exportingZip,
  downloadingReport,
}: {
  scan: ScanStatusType;
  displayedReports: SkillReport[];
  hasReportModeSkill: boolean;
  isRunning: boolean;
  onOpenReports: () => void;
  onExportZip: () => void;
  onDownloadCsv: () => void;
  exportingZip: boolean;
  downloadingReport: boolean;
}) {
  return (
    <TaskPanel
      title="漏洞报告生成"
      status={hasReportModeSkill ? (isRunning ? "同步中" : "可查看") : "预留"}
      tone={hasReportModeSkill ? "purple" : "slate"}
      summary="报告生成页签已预留；当前保留现有导出能力和报告型 SKILL 的 Markdown 查看入口。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="Markdown 报告" value={displayedReports.length} tone="purple" />
        <MiniMetric label="确认问题" value={scan.vulnerabilities.filter((v) => isAiConfirmed(v)).length} tone="red" />
        <MiniMetric label="扫描结果" value={scan.vulnerabilities.length} />
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onExportZip}
          disabled={exportingZip}
          className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-blue-800"
        >
          {exportingZip ? "导出中..." : "导出报告"}
        </button>
        <button
          type="button"
          onClick={onDownloadCsv}
          disabled={downloadingReport}
          className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-blue-800"
        >
          {downloadingReport ? "下载中..." : "下载 CSV"}
        </button>
        {hasReportModeSkill && (
          <button
            type="button"
            onClick={onOpenReports}
            className="rounded-lg border border-purple-500/40 px-3 py-1.5 text-sm font-medium text-purple-200 transition-colors hover:bg-purple-500/10"
          >
            查看 SKILL 报告
          </button>
        )}
      </div>
      {!hasReportModeSkill && <EmptyState text="当前扫描没有报告型 SKILL 输出；后续报告生成任务会在此接入。" />}
    </TaskPanel>
  );
}

function TaskPanel({
  title,
  status,
  tone,
  summary,
  children,
}: {
  title: string;
  status: string;
  tone: TaskTone;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-white">{title}</h2>
          <p className="mt-1 text-sm text-slate-400">{summary}</p>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {children}
    </section>
  );
}

function TaskSummaryRow({
  label,
  status,
  tone,
  detail,
  progress,
}: {
  label: string;
  status: string;
  tone: TaskTone;
  detail: string;
  progress?: number;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-slate-200">{label}</div>
          <div className="mt-0.5 text-xs text-slate-500">{detail}</div>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {progress !== undefined && <ProgressBar value={progress} tone={tone} className="mt-3" />}
    </div>
  );
}

function ProgressBlock({
  label,
  current,
  total,
  fallback,
  percentOverride,
}: {
  label: string;
  current: number;
  total: number;
  fallback: string;
  percentOverride?: number;
}) {
  const value = percentOverride ?? percent(current, total);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
        <span>{total > 0 ? `${label}: ${current}/${total}` : fallback}</span>
        {total > 0 || percentOverride !== undefined ? <span>{value}%</span> : null}
      </div>
      <ProgressBar value={total > 0 || percentOverride !== undefined ? value : 0} tone="blue" />
    </div>
  );
}

function ProgressBar({ value, tone, className = "" }: { value: number; tone: TaskTone; className?: string }) {
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-slate-800 ${className}`}>
      <div className={`h-full rounded-full transition-all duration-500 ${toneFill(tone)}`} style={{ width: `${value}%` }} />
    </div>
  );
}

function EventList({ events, empty }: { events: ScanEvent[]; empty: string }) {
  const visible = events.slice(-80);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-500">任务日志</div>
      <div className="max-h-80 overflow-y-auto p-3 font-mono text-xs">
        {visible.length === 0 ? (
          <p className="text-slate-600">{empty}</p>
        ) : (
          <div className="space-y-1">
            {visible.map((event, index) => <EventLine key={`${event.timestamp}-${index}`} event={event} />)}
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">{text}</div>;
}

function MiniMetric({ label, value, tone = "slate" }: { label: string; value: number; tone?: TaskTone }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${toneText(tone)}`}>{value}</div>
    </div>
  );
}

function StatusPill({ label, tone }: { label: string; tone: TaskTone }) {
  return (
    <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
      {label}
    </span>
  );
}

function PanelIcon({ name }: { name: "target" | "alert" | "history" | "queue" }) {
  if (name === "alert") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      </svg>
    );
  }
  if (name === "history") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12a9 9 0 1 0 3-6.7M3 4v6h6m3-2v5l4 2" />
      </svg>
    );
  }
  if (name === "queue") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7h16M4 12h16M4 17h10" />
      </svg>
    );
  }
  return (
    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6l4 2m5-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
    </svg>
  );
}

function toneText(tone: TaskTone): string {
  return {
    slate: "text-slate-300",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
    purple: "text-purple-300",
    blue: "text-blue-300",
  }[tone];
}

function toneBorder(tone: TaskTone): string {
  return {
    slate: "border-slate-700",
    cyan: "border-cyan-500/30",
    amber: "border-amber-500/30",
    green: "border-green-500/30",
    red: "border-red-500/30",
    purple: "border-purple-500/30",
    blue: "border-blue-500/30",
  }[tone];
}

function toneBg(tone: TaskTone): string {
  return {
    slate: "bg-slate-800",
    cyan: "bg-cyan-500/10",
    amber: "bg-amber-500/10",
    green: "bg-green-500/10",
    red: "bg-red-500/10",
    purple: "bg-purple-500/10",
    blue: "bg-blue-500/10",
  }[tone];
}

function toneFill(tone: TaskTone): string {
  return {
    slate: "bg-slate-500",
    cyan: "bg-cyan-400",
    amber: "bg-amber-400",
    green: "bg-green-500",
    red: "bg-red-500",
    purple: "bg-purple-500",
    blue: "bg-blue-500",
  }[tone];
}

function EventLine({ event }: { event: ScanEvent }) {
  const time = new Date(event.timestamp).toLocaleTimeString();

  const phaseColor: Record<string, string> = {
    init: "text-yellow-400",
    mcp_ready: "text-green-400",
    static_analysis: "text-cyan-400",
    git_history: "text-purple-300",
    variant_hunt: "text-purple-400",
    auditing: "text-blue-400",
    opencode_output: "text-slate-500",
    fp_review: "text-amber-300",
    complete: "text-green-400",
    error: "text-red-400",
  };

  return (
    <div className="flex gap-2 leading-5">
      <span className="text-slate-600 shrink-0">{time}</span>
      <span className={`shrink-0 ${phaseColor[event.phase] ?? "text-slate-400"}`}>
        [{event.phase}]
      </span>
      <span className="text-slate-400 break-all">{event.message}</span>
    </div>
  );
}

function ModelPoolDashboard({ pool }: { pool: OpenCodePoolStatus | null }) {
  const models = pool?.models ?? [];
  const total = models.reduce((sum, item) => sum + item.total, 0);
  const success = models.reduce((sum, item) => sum + item.success, 0);
  const failure = models.reduce((sum, item) => sum + item.failure, 0);
  const timeout = models.reduce((sum, item) => sum + item.timeout, 0);
  const cancelled = models.reduce((sum, item) => sum + item.cancelled, 0);

  if (!pool || models.length === 0) {
    return (
      <div className="flex-1 overflow-y-auto p-5">
        <div className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-5 text-sm text-slate-500">
          当前扫描尚未产生 OpenCode 模型池统计。开始运行审计、扫描前内存 API 识别或 AI 去误报后，这里会显示模型分配情况。
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <MetricBox label="运行中" value={pool.global_running} tone="cyan" />
        <MetricBox label="排队中" value={pool.global_queued} tone="amber" />
        <MetricBox label="累计任务" value={total} />
        <MetricBox label="成功" value={success} tone="green" />
        <MetricBox label="失败" value={failure} tone="red" />
        <MetricBox label="超时/取消" value={timeout + cancelled} tone="amber" />
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full min-w-[68rem] text-sm">
          <thead className="bg-slate-950">
            <tr>
              <th className={thCls}>模型</th>
              <th className={thCls}>能力</th>
              <th className={thCls}>可用</th>
              <th className={thCls}>权重</th>
              <th className={thCls}>运行/上限</th>
              <th className={thCls}>排队</th>
              <th className={thCls}>累计</th>
              <th className={thCls}>成功</th>
              <th className={thCls}>失败</th>
              <th className={thCls}>超时</th>
              <th className={thCls}>取消</th>
              <th className={thCls}>平均耗时</th>
              <th className={thCls}>当前任务</th>
              <th className={thCls}>最近状态</th>
            </tr>
          </thead>
          <tbody>
            {models.map((model) => (
              <tr key={model.id} className="border-t border-slate-800/70">
                <td className={tdCls}>
                  <div className="font-semibold text-slate-100">{model.id}</div>
                  <div className="mt-1 max-w-48 truncate font-mono text-[11px] text-slate-500">
                    {model.model || "(默认模型)"}
                  </div>
                </td>
                <td className={tdCls}>{capabilityLabel(model.capability)}</td>
                <td className={tdCls}>
                  <span className={model.enabled && model.available ? "text-green-300" : "text-slate-500"}>
                    {model.enabled ? (model.available ? "可用" : "时间窗外") : "禁用"}
                  </span>
                </td>
                <td className={tdCls}>{model.weight}</td>
                <td className={tdCls}>{model.running}/{model.max_concurrency}</td>
                <td className={tdCls}>{model.queued}</td>
                <td className={tdCls}>{model.total}</td>
                <td className={`${tdCls} text-green-300`}>{model.success}</td>
                <td className={`${tdCls} text-red-300`}>{model.failure}</td>
                <td className={`${tdCls} text-amber-300`}>{model.timeout}</td>
                <td className={`${tdCls} text-slate-300`}>{model.cancelled}</td>
                <td className={tdCls}>{formatDuration(model.avg_duration_seconds)}</td>
                <td className={`${tdCls} max-w-64 truncate text-slate-400`}>
                  {modelTaskLabel(model.active_tasks?.[0])}
                </td>
                <td className={tdCls}>
                  <div className={statusClass(model.last_status)}>
                    {statusLabel(model.last_status)}
                  </div>
                  <div className="mt-1 text-[11px] text-slate-600">
                    {formatDateTime(model.last_finished_at || model.last_started_at)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const thCls = "px-3 py-2 text-left text-xs font-semibold text-slate-400";
const tdCls = "px-3 py-3 text-slate-300 align-top";

function MetricBox({
  label,
  value,
  tone = "slate",
}: {
  label: string;
  value: number;
  tone?: "slate" | "cyan" | "amber" | "green" | "red";
}) {
  const color = {
    slate: "text-slate-100",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
  }[tone];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

function capabilityLabel(value: string): string {
  if (value === "high") return "高";
  if (value === "medium") return "中";
  if (value === "low") return "低";
  return value || "-";
}

function statusLabel(value: string): string {
  if (value === "queued") return "排队";
  if (value === "running") return "运行中";
  if (value === "success") return "成功";
  if (value === "failure") return "失败";
  if (value === "timeout") return "超时";
  if (value === "cancelled") return "取消";
  return value || "-";
}

function statusClass(value: string): string {
  const base = "inline-flex rounded border px-2 py-0.5 text-xs";
  if (value === "running") return `${base} border-cyan-500/30 bg-cyan-500/10 text-cyan-300`;
  if (value === "success") return `${base} border-green-500/30 bg-green-500/10 text-green-300`;
  if (value === "failure") return `${base} border-red-500/30 bg-red-500/10 text-red-300`;
  if (value === "timeout" || value === "queued") return `${base} border-amber-500/30 bg-amber-500/10 text-amber-300`;
  return `${base} border-slate-700 bg-slate-800 text-slate-400`;
}

function modelTaskLabel(task: Record<string, unknown> | undefined): string {
  if (!task) return "-";
  const taskType = String(task.task_type || "audit");
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const target = file ? `${file}${line}` : checker;
  return [taskType + stage, target].filter(Boolean).join(" ");
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return "-";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

function formatDateTime(value: string): string {
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
        h1: ({ children }) => <h1 className="mb-4 text-xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-6 mb-2 text-base font-semibold text-purple-100">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-4 mb-2 text-sm font-semibold text-slate-100">{children}</h3>,
        p: ({ children }) => <p className="my-2 text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        table: ({ children }) => (
          <div className="my-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-950">{children}</thead>,
        th: ({ children }) => <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">{children}</th>,
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-3 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
            {children}
          </pre>
        ),
        code: ({ className, children }) => (
          <code className={`${className ?? ""} rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[0.85em] text-purple-200`}>
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
