import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { getScanStatus, stopScan, resumeScan, downloadScanReport, downloadScanReportZip, getCheckers, updateScanFeedback, getSkillContent, triggerFpReview, stopFpReview, getFpReview, getFpReviewSkill, getScanGitHistory, getSkillReports, getAgentIndexStatus, triggerVulnerabilityValidation, stopVulnerabilityValidation } from "../api/client";
import { getScanThreatAnalysis, ThreatAnalysisPanel } from "../features/threatAnalysis";
import type { Candidate, CodeIndexStats, FpReviewJob, HistoryPattern, IndexStatus, ScanItemStatus, ScanStatus as ScanStatusType, ScanEvent, CheckerInfo, SkillReport, OpenCodePoolStatus, ScanCandidate, Vulnerability, OutputSource, VulnerabilityValidation } from "../types";
import { useScanSSE } from "../hooks/useScanSSE";
import type { ScanSSEHandlers, SSEStateSetters } from "../hooks/useScanSSE";
import VulnerabilityList from "./VulnerabilityList";
import FeedbackManager from "./FeedbackManager";

const MAX_LOG_LINES = 500;
const STATIC_CANDIDATE_PAGE_SIZE = 20;
const SCAN_QUEUE_PAGE_SIZE = 12;
const AGENT_DISCONNECT_ERROR = "Agent 断开连接";
const FINAL_USER_VERDICTS = new Set(["confirmed", "false_positive"]);

type MainTab = "overview" | "threat" | "mining" | "validation" | "issues";
type MiningTab = "static_analysis" | "candidate_audit" | "fp_review";
type StaticTab = "call_graph" | "candidate_generation";
type TaskTone = "slate" | "cyan" | "amber" | "green" | "red" | "purple" | "blue";
type ScanQueueTaskStatus = "planned" | "queued" | "running" | "success" | "failure" | "timeout" | "cancelled" | "unknown";
type FlowNodeId = "threat" | "static_analysis" | "call_graph" | "candidate_generation" | "candidate_audit" | "fp_review" | "validation";
type FlowNodeStatus = "pending" | "running" | "done";

interface ScanQueueTask {
  id: string;
  status: ScanQueueTaskStatus;
  modelId: string;
  scopeId: string;
  task: Record<string, unknown>;
  timestamp: string;
}

const MINING_TABS: { key: MiningTab; label: string }[] = [
  { key: "static_analysis", label: "静态分析" },
  { key: "candidate_audit", label: "候选点审计" },
  { key: "fp_review", label: "对抗式去误报" },
];

const STATIC_TABS: { key: StaticTab; label: string }[] = [
  { key: "call_graph", label: "调用图构建" },
  { key: "candidate_generation", label: "候选点生成" },
];

function hasOutputSource(source?: OutputSource | null): boolean {
  return Boolean(source && (source.agent_name || source.agent_id || source.model || source.model_id || source.tool));
}

function formatOutputSource(source?: OutputSource | null): string {
  if (!hasOutputSource(source)) return "";
  const agent = source?.agent_name || source?.agent_id || "未知 Agent";
  const tool = source?.tool || source?.backend || "AI";
  const model = source?.model
    || (source?.use_default_model ? "CLI 默认模型" : (source?.model_id || "默认模型"));
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

function isStaticCandidateVulnerability(vuln: Vulnerability): boolean {
  return (vuln.analysis_source || "static_candidate") === "static_candidate"
    && vuln.vuln_type.toLowerCase() !== "threat_audit";
}

function isStaticCandidate(item: Candidate): boolean {
  return item.vuln_type.toLowerCase() !== "threat_audit"
    && String(item.metadata?.source || "").toLowerCase() !== "threat_analysis";
}

function effectiveIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  const fpMap = new Map((fpReview?.results ?? []).map((result) => [result.vuln_index, result]));
  return scan.vulnerabilities.filter((vuln, index) => {
    if (!isAiConfirmed(vuln)) return false;
    if (fpMap.get(index)?.verdict === "fp") return false;
    return true;
  }).length;
}

function issueItems(scan: ScanStatusType, fpReview: FpReviewJob | null): { vuln: Vulnerability; index: number }[] {
  const fpMap = new Map((fpReview?.results ?? []).map((result) => [result.vuln_index, result]));
  return scan.vulnerabilities
    .map((vuln, index) => ({ vuln, index }))
    .filter(({ vuln, index }) => isAiConfirmed(vuln) && fpMap.get(index)?.verdict !== "fp");
}

function isValidationTerminalStatus(status: string): boolean {
  return ["verified", "success", "failed", "error", "timeout", "cancelled", "skipped"].includes(status);
}

function validatedIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  const validationMap = new Map((scan.validations ?? []).map((item) => [item.vuln_index, item]));
  return issueItems(scan, fpReview).filter(({ index }) => {
    const validation = validationMap.get(index);
    return Boolean(validation && !validation.running && isValidationTerminalStatus(validation.status));
  }).length;
}

function candidateKey(item: Pick<Candidate, "file" | "line" | "function" | "vuln_type">): string {
  return `${item.file}\u0000${item.line}\u0000${item.function}\u0000${item.vuln_type}`;
}

function currentStageLabel(scan: ScanStatusType, events: ScanEvent[]): string {
  if (scan.status === "error") return "异常中断";
  if (scan.status === "cancelled") return "已取消";
  if (scan.status === "complete") return "完成";
  const latest = [...events].reverse().find((event) => event.phase !== "opencode_output");
  if (latest?.phase === "fp_review") return "漏洞挖掘 / 对抗式去误报";
  if (latest?.phase === "variant_hunt") return "威胁分析 / 历史同类问题挖掘";
  if (latest?.phase === "threat_analysis") return "威胁分析 / 攻击树分析";
  if (latest?.phase === "threat_audit") return "威胁分析 / 威胁审计";
  if (latest?.phase === "git_history") return "威胁分析 / Git 历史问题分析";
  if (latest?.phase === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (latest?.phase === "static_analysis") return "漏洞挖掘 / 静态分析";
  if (latest?.phase === "mcp_ready" || latest?.phase === "init") return "威胁分析 / 代码索引";
  if (scan.status === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (scan.status === "analyzing") return "漏洞挖掘 / 静态分析";
  return "等待启动";
}

function taskStateLabel(done: boolean, running: boolean, failed = false): string {
  if (failed) return "异常";
  if (done) return "完成";
  if (running) return "进行中";
  return "等待";
}

function formatIndexProgress(indexStatus: IndexStatus | null, scan: ScanStatusType): {
  current: number;
  total: number;
  done: boolean;
  running: boolean;
  failed: boolean;
  stage: string;
  stageCurrent: number;
  stageTotal: number;
  stats?: CodeIndexStats;
} {
  const status = indexStatus?.status ?? "unknown";
  const statsFiles = indexStatus?.stats?.files ?? 0;
  const total = indexStatus?.total_files || statsFiles || scan.static_total_files || 0;
  let current = indexStatus?.parsed_files ?? scan.static_scanned_files ?? 0;
  const failed = status === "error";
  const running = status === "parsing";
  const done = !running && (status === "done" || scan.static_analysis_done || (indexStatus == null && scan.static_total_files > 0));
  if (done && total > 0 && current === 0) current = total;
  return {
    current,
    total,
    done,
    running,
    failed,
    stage: indexStatus?.stage ?? "",
    stageCurrent: indexStatus?.stage_current ?? 0,
    stageTotal: indexStatus?.stage_total ?? 0,
    stats: indexStatus?.stats,
  };
}

interface Props {
  scanId: string;
  onBack: () => void;
}

export default function ScanStatus({ scanId, onBack }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [activeTab, setActiveTab] = useState<MainTab>("overview");
  const [activeMiningTab, setActiveMiningTab] = useState<MiningTab>("static_analysis");
  const [activeStaticTab, setActiveStaticTab] = useState<StaticTab>("call_graph");
  const [stopping, setStopping] = useState(false);
  const [continuing, setContinuing] = useState(false);
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
  const [launchingValidations, setLaunchingValidations] = useState<Set<number>>(new Set());
  const [stoppingValidations, setStoppingValidations] = useState<Set<number>>(new Set());

  // Code indexing progress
  const [indexStatus, setIndexStatus] = useState<IndexStatus | null>(null);

  // Git history mined patterns
  const [gitHistory, setGitHistory] = useState<HistoryPattern[]>([]);
  const [threatAnalysisLoading, setThreatAnalysisLoading] = useState(false);

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
    getAgentIndexStatus(scanId)
      .then(setIndexStatus)
      .catch(() => {});
    getScanGitHistory(scanId)
      .then(setGitHistory)
      .catch(() => {});
    setThreatAnalysisLoading(true);
    getScanThreatAnalysis(scanId)
      .then((analysis) => {
        setScan((prev) => prev ? { ...prev, threat_analysis: analysis } : prev);
      })
      .catch(() => {})
      .finally(() => setThreatAnalysisLoading(false));
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
    onScanCandidates: (data) => {
      setScan((prev) => prev ? { ...prev, candidates: data.candidates, total_candidates: data.candidates.length } : prev);
    },
    onScanVulnerability: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const vulns = [...prev.vulnerabilities];
        vulns[data.index] = data.vulnerability;
        return { ...prev, vulnerabilities: vulns };
      });
    },
    onVulnerabilityValidation: (data) => {
      setLaunchingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setStoppingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setScan((prev) => {
        if (!prev) return prev;
        const validations = [...(prev.validations ?? [])];
        const existingIndex = validations.findIndex((item) => item.vuln_index === data.validation.vuln_index);
        if (existingIndex >= 0) {
          validations[existingIndex] = data.validation;
        } else {
          validations.push(data.validation);
          validations.sort((a, b) => a.vuln_index - b.vuln_index);
        }
        return { ...prev, validations };
      });
    },
    onThreatAnalysis: (data) => {
      setThreatAnalysisLoading(false);
      setScan((prev) => prev ? { ...prev, threat_analysis: data.analysis } : prev);
    },
    onThreatAuditTask: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const tasks = [...(prev.threat_audit_tasks ?? [])];
        const existing = tasks.findIndex((task) => task.task_id === data.task.task_id);
        if (existing >= 0) {
          tasks[existing] = data.task;
        } else {
          tasks.push(data.task);
        }
        tasks.sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")) || a.task_id.localeCompare(b.task_id));
        return { ...prev, threat_audit_tasks: tasks };
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
        processed: data.processed ?? 0,
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
      const totalFiles = data.total_files || data.stats?.files || 0;
      const parsedFiles = data.status === "done" && (data.parsed_files ?? 0) === 0
        ? totalFiles
        : data.parsed_files;
      if (totalFiles > 0 && parsedFiles != null) {
        setScan((prev) => prev ? {
          ...prev,
          static_total_files: totalFiles,
          static_scanned_files: parsedFiles,
        } : prev);
      }
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

  const handleTriggerValidation = async (index: number) => {
    setLaunchingValidations((prev) => new Set(prev).add(index));
    try {
      await triggerVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string } } }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`启动漏洞验证失败：${msg}`);
      setLaunchingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
    }
  };

  const handleStopValidation = async (index: number) => {
    setStoppingValidations((prev) => new Set(prev).add(index));
    try {
      await stopVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string } } }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`停止漏洞验证失败：${msg}`);
      setStoppingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
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
      const next = await getScanStatus(scanId);
      setScan(next);
    } catch {
      // The next poll can still reconcile an Agent-side stop.
    } finally {
      setStopping(false);
    }
  };

  const handleContinue = async () => {
    setContinuing(true);
    try {
      await resumeScan(scanId);
      const next = await getScanStatus(scanId);
      setScan(next);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "续扫失败";
      alert(`续扫失败：${msg || "未知错误"}`);
    } finally {
      setContinuing(false);
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

  const handleFlowNodeClick = (node: FlowNodeId) => {
    if (node === "threat") {
      setActiveTab("threat");
      return;
    }
    if (node === "validation") {
      setActiveTab("validation");
      return;
    }
    setActiveTab("mining");
    if (node === "candidate_audit") {
      setActiveMiningTab("candidate_audit");
      return;
    }
    if (node === "fp_review") {
      setActiveMiningTab("fp_review");
      return;
    }
    setActiveMiningTab("static_analysis");
    if (node === "call_graph" || node === "candidate_generation") {
      setActiveStaticTab(node);
    }
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
  const continuableCount = scan.continuable_task_count || 0;
  const issueCount = effectiveIssueCount(scan, fpReview);
  const verifiedIssueCount = validatedIssueCount(scan, fpReview);
  const variantIssueCount = scan.vulnerabilities.filter((v) => v.variant_of).length;
  const showGitHistoryStages = gitHistory.length > 0
    || variantIssueCount > 0
    || hasEvent(scan.events, ["git_history", "variant_hunt"]);
  const indexProgress = formatIndexProgress(indexStatus, scan);
  const threatAnalysisEvents = filterEvents(scan.events, ["threat_analysis", "threat_audit"]);
  const miningEvents = filterEvents(scan.events, ["auditing", "fp_review", "opencode_output"]);
  const validationEvents = filterEvents(scan.events, ["validation"]);
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
      totalCandidates={scan.total_candidates}
      processedCandidates={scan.processed_candidates}
      fpReview={fpReview}
      currentFpReviewIndices={currentFpReviewIndices}
      fpReviewRunning={isFpReviewing}
      validations={scan.validations ?? []}
      validatingIndices={launchingValidations}
      stoppingValidationIndices={stoppingValidations}
      agentOnline={!!scan.agent_online}
      onTriggerValidation={handleTriggerValidation}
      onStopValidation={handleStopValidation}
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
                {scan.can_continue && (
                  <button
                    onClick={handleContinue}
                    disabled={continuing || !scan.agent_online}
                    title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${continuableCount} 个任务`}
                    className="px-3 py-1.5 text-sm font-medium text-amber-300 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {continuing ? "启动中..." : "续扫"}
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

        <ProcessFlowNav
          scan={scan}
          indexProgress={indexProgress}
          fpReview={fpReview}
          activeTab={activeTab}
          activeMiningTab={activeMiningTab}
          activeStaticTab={activeStaticTab}
          issueCount={issueCount}
          verifiedIssueCount={verifiedIssueCount}
          threatAnalysisLoading={threatAnalysisLoading}
          isDone={!!isDone}
          isFpReviewing={isFpReviewing}
          onNodeClick={handleFlowNodeClick}
          onHome={() => setActiveTab("overview")}
          onIssues={() => setActiveTab("issues")}
        />

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
            continuableCount={continuableCount}
            variantIssueCount={variantIssueCount}
            gitHistoryCount={gitHistory.length}
            showGitHistoryStages={showGitHistoryStages}
            currentStage={currentStageLabel(scan, scan.events)}
            indexProgress={indexProgress}
            pct={pct}
            isRunning={!!isRunning}
            isDone={!!isDone}
            fpReview={fpReview}
            isFpReviewing={isFpReviewing}
            currentFpReviewTargets={currentFpReviewTargets}
            hasReportModeSkill={hasReportModeSkill}
            verifiedIssueCount={verifiedIssueCount}
            onNavigate={setActiveTab}
          />
        )}
        {activeTab === "threat" && (
          <ThreatAnalysisPanel
            analysis={scan.threat_analysis ?? null}
            threatAuditTasks={scan.threat_audit_tasks ?? []}
            events={threatAnalysisEvents}
            loading={threatAnalysisLoading && !scan.threat_analysis}
            isDone={!!isDone}
          />
        )}
        {activeTab === "mining" && (
          <TabbedPanel
            tabs={MINING_TABS}
            active={activeMiningTab}
            onChange={setActiveMiningTab}
          >
            {activeMiningTab === "static_analysis" && (
              <StaticTaskPanel
                scan={scan}
                indexStatus={indexStatus}
                indexProgress={indexProgress}
                candidates={scan.candidates ?? []}
                vulnerabilities={scan.vulnerabilities}
                validations={scan.validations ?? []}
                currentCandidate={scan.current_candidate}
                processedCandidates={scan.processed_candidates}
                events={filterEvents(scan.events, ["static_analysis"])}
                indexEvents={filterEvents(scan.events, ["init"])}
                activeStaticTab={activeStaticTab}
                onStaticTabChange={setActiveStaticTab}
              />
            )}
            {activeMiningTab === "candidate_audit" && (
              <AuditTaskPanel
                scan={scan}
                pct={pct}
                currentCandidate={scan.current_candidate}
                events={filterEvents(miningEvents, ["auditing", "opencode_output"])}
                pool={scan.opencode_pool ?? null}
              />
            )}
            {activeMiningTab === "fp_review" && (
              <FpReviewPanel
                vulnerabilities={scan.vulnerabilities}
                fpReview={fpReview}
                isFpReviewing={isFpReviewing}
                loading={fpReviewLoading}
                stopping={fpReviewStopping}
                events={filterEvents(miningEvents, ["fp_review", "opencode_output"])}
                onTrigger={handleFpReview}
                onStop={handleStopFpReview}
              />
            )}
          </TabbedPanel>
        )}
        {activeTab === "validation" && (
          <ValidationPanel
            vulnerabilities={scan.vulnerabilities}
            validations={scan.validations ?? []}
            stoppingValidationIndices={stoppingValidations}
            events={validationEvents}
            onStopValidation={handleStopValidation}
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

interface FlowNodeView {
  id: FlowNodeId;
  label: string;
  detail: string;
  status: FlowNodeStatus;
  active: boolean;
  tone: TaskTone;
}

function ProcessFlowNav({
  scan,
  indexProgress,
  fpReview,
  activeTab,
  activeMiningTab,
  activeStaticTab,
  issueCount,
  verifiedIssueCount,
  threatAnalysisLoading,
  isDone,
  isFpReviewing,
  onNodeClick,
  onHome,
  onIssues,
}: {
  scan: ScanStatusType;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  fpReview: FpReviewJob | null;
  activeTab: MainTab;
  activeMiningTab: MiningTab;
  activeStaticTab: StaticTab;
  issueCount: number;
  verifiedIssueCount: number;
  threatAnalysisLoading: boolean;
  isDone: boolean;
  isFpReviewing: boolean;
  onNodeClick: (node: FlowNodeId) => void;
  onHome: () => void;
  onIssues: () => void;
}) {
  const candidates = scan.candidates ?? [];
  const candidateCount = candidates.length || scan.total_candidates || scan.vulnerabilities.length;
  const staticRunning = scan.status === "analyzing" && !scan.static_analysis_done;
  const staticDone = scan.static_analysis_done || candidateCount > 0 || scan.status === "auditing" || scan.status === "complete";
  const threatRunning = (threatAnalysisLoading && !scan.threat_analysis)
    || (!isDone && hasEvent(scan.events, ["threat_analysis"]) && !scan.threat_analysis);
  const auditRunning = scan.status === "auditing" || Boolean(scan.current_candidate);
  const auditDone = scan.status === "complete"
    || (scan.total_candidates > 0 && scan.processed_candidates >= scan.total_candidates);
  const validations = scan.validations ?? [];
  const confirmedCount = scan.vulnerabilities.filter((vuln) => isAiConfirmed(vuln)).length;
  const validationRunningCount = validations.filter((item) =>
    item.running || item.status === "queued" || item.status === "running" || item.status === "pending",
  ).length;
  const validationDoneCount = validations.filter((item) => !item.running && isValidationTerminalStatus(item.status)).length;
  const validationDone = validationDoneCount > 0 || (confirmedCount > 0 && validationDoneCount >= confirmedCount);
  const fpReviewDone = fpReview?.status === "complete";
  const fpReviewProcessed = fpReview?.processed ?? 0;
  const fpReviewTotal = fpReview?.total ?? 0;

  const staticDetail = candidateCount > 0
    ? `${candidateCount} 个候选点`
    : indexProgress.total > 0
      ? `${indexProgress.current}/${indexProgress.total} 文件`
      : "等待静态结果";
  const validationDetail = confirmedCount > 0
    ? `${validationRunningCount} 运行 · ${validationDoneCount}/${confirmedCount} 完成`
    : "等待确认问题";

  const nodes: Record<FlowNodeId, FlowNodeView> = {
    threat: {
      id: "threat",
      label: "威胁分析",
      detail: scan.threat_analysis
        ? `${scan.threat_analysis.assets.length} 资产 · ${scan.threat_analysis.attack_trees.length} 攻击树`
        : "攻击树分析",
      status: flowStatus(Boolean(scan.threat_analysis), threatRunning),
      active: activeTab === "threat",
      tone: "green",
    },
    static_analysis: {
      id: "static_analysis",
      label: "静态分析",
      detail: staticDetail,
      status: flowStatus(staticDone, staticRunning),
      active: activeTab === "mining" && activeMiningTab === "static_analysis",
      tone: "cyan",
    },
    call_graph: {
      id: "call_graph",
      label: "调用图构建",
      detail: indexProgress.total > 0
        ? `${indexProgress.current}/${indexProgress.total} 文件`
        : "代码索引",
      status: flowStatus(indexProgress.done, indexProgress.running),
      active: activeTab === "mining" && activeMiningTab === "static_analysis" && activeStaticTab === "call_graph",
      tone: "blue",
    },
    candidate_generation: {
      id: "candidate_generation",
      label: "候选点生成",
      detail: candidateCount > 0 ? `${candidateCount} 个候选点` : "静态规则产出",
      status: flowStatus(staticDone, staticRunning),
      active: activeTab === "mining" && activeMiningTab === "static_analysis" && activeStaticTab === "candidate_generation",
      tone: "cyan",
    },
    candidate_audit: {
      id: "candidate_audit",
      label: "候选点审计",
      detail: scan.total_candidates > 0
        ? `${scan.processed_candidates}/${scan.total_candidates} 已审计`
        : "等待候选点",
      status: flowStatus(auditDone, auditRunning),
      active: activeTab === "mining" && activeMiningTab === "candidate_audit",
      tone: "blue",
    },
    fp_review: {
      id: "fp_review",
      label: "对抗式去误报",
      detail: fpReviewTotal > 0 ? `${fpReviewProcessed}/${fpReviewTotal} 已复核` : "等待正报复核",
      status: flowStatus(fpReviewDone, isFpReviewing),
      active: activeTab === "mining" && activeMiningTab === "fp_review",
      tone: "amber",
    },
    validation: {
      id: "validation",
      label: "漏洞验证",
      detail: validationDetail,
      status: flowStatus(validationDone, validationRunningCount > 0),
      active: activeTab === "validation",
      tone: "purple",
    },
  };

  return (
    <section className="border-t border-slate-700/60 pt-3">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">执行流程</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <FlowUtilityButton active={activeTab === "overview"} onClick={onHome}>
            首页
          </FlowUtilityButton>
          <FlowUtilityButton active={activeTab === "issues"} onClick={onIssues}>
            发现的问题
            <span className="ml-1.5 text-xs text-red-300">发现 {issueCount} · 已验证 {verifiedIssueCount}</span>
          </FlowUtilityButton>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-700/50 bg-slate-900/35 p-2.5 shadow-inner">
        <div className="mx-auto flex w-max items-stretch gap-3">
          <div className="flex items-center">
            <FlowNodeButton node={nodes.threat} onClick={onNodeClick} />
          </div>
          <FlowArrow label="进入" />
          <div className="flex-none rounded-xl border border-cyan-500/25 bg-gradient-to-br from-slate-950/80 via-slate-900/60 to-cyan-950/20 p-3 shadow-sm">
            <div className="mb-3 flex items-center justify-center">
              <div className="text-sm font-semibold text-slate-100">漏洞挖掘</div>
            </div>
            <div className="flex min-h-[11rem] items-center justify-center gap-3">
              <div className="w-[400px] rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-2.5 shadow-sm">
                <FlowNodeButton node={nodes.static_analysis} onClick={onNodeClick} wide />
                <div className="mt-2.5 flex items-center gap-1.5">
                  <FlowNodeButton node={nodes.call_graph} onClick={onNodeClick} compact />
                  <FlowArrow compact />
                  <FlowNodeButton node={nodes.candidate_generation} onClick={onNodeClick} compact />
                </div>
              </div>
              <FlowArrow />
              <FlowAuditBranch
                auditNode={nodes.candidate_audit}
                fpReviewNode={nodes.fp_review}
                onNodeClick={onNodeClick}
              />
            </div>
          </div>
          <FlowArrow label="正报验证" />
          <div className="flex items-center">
            <FlowNodeButton node={nodes.validation} onClick={onNodeClick} />
          </div>
        </div>
      </div>
    </section>
  );
}

function flowStatus(done: boolean, running: boolean): FlowNodeStatus {
  if (running) return "running";
  if (done) return "done";
  return "pending";
}

function FlowUtilityButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
        active
          ? "border-blue-500/50 bg-blue-500/15 text-blue-100"
          : "border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-700"
      }`}
    >
      {children}
    </button>
  );
}

function FlowNodeButton({
  node,
  onClick,
  compact = false,
  wide = false,
}: {
  node: FlowNodeView;
  onClick: (node: FlowNodeId) => void;
  compact?: boolean;
  wide?: boolean;
}) {
  const statusTone = flowStatusTone(node.status, node.tone);
  const sizeClass = compact
    ? "min-h-[5rem] w-[10.5rem]"
    : wide
      ? "min-h-[5.25rem] w-full"
      : "min-h-[5.75rem] w-[11.5rem]";
  return (
    <button
      type="button"
      onClick={() => onClick(node.id)}
      className={`${sizeClass} rounded-lg border px-3 py-2 text-left transition-colors ${
        node.active
          ? `${toneBorder(node.tone)} ${toneBg(node.tone)} ring-1 ring-current/20`
          : "border-slate-700 bg-slate-900/70 hover:border-slate-600 hover:bg-slate-800/80"
      }`}
      title={`${node.label} · ${flowStatusLabel(node.status)} · ${node.detail}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className={`break-words text-sm font-semibold ${node.active ? toneText(node.tone) : "text-slate-100"}`}>
          {node.label}
        </span>
        {node.status === "running" && (
          <span className="mt-0.5 h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <StatusPill label={flowStatusLabel(node.status)} tone={statusTone} />
      </div>
      <div className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">
        {node.detail}
      </div>
    </button>
  );
}

function FlowArrow({ label, compact = false }: { label?: string; compact?: boolean }) {
  return (
    <div className={`flex shrink-0 items-center ${compact ? "w-6" : "w-8"}`}>
      <div className="h-px flex-1 bg-slate-600" />
      <svg className="h-4 w-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
      {label && !compact && <span className="sr-only">{label}</span>}
    </div>
  );
}

function FlowAuditBranch({
  auditNode,
  fpReviewNode,
  onNodeClick,
}: {
  auditNode: FlowNodeView;
  fpReviewNode: FlowNodeView;
  onNodeClick: (node: FlowNodeId) => void;
}) {
  return (
    <div className="grid grid-cols-[11.5rem_1.5rem_10.5rem] grid-rows-[minmax(0,1fr)_auto] items-center gap-x-1.5 gap-y-2.5">
      <div className="row-span-2 flex items-center">
        <FlowNodeButton node={auditNode} onClick={onNodeClick} />
      </div>
      <div className="flex h-full items-center">
        <FlowArrow compact />
      </div>
      <div />
      <div className="flex items-center">
        <FlowArrow compact />
      </div>
      <FlowNodeButton node={fpReviewNode} onClick={onNodeClick} compact />
    </div>
  );
}

function flowStatusLabel(status: FlowNodeStatus): string {
  if (status === "running") return "正在执行";
  if (status === "done") return "执行完毕";
  return "待执行";
}

function flowStatusTone(status: FlowNodeStatus, doneTone: TaskTone): TaskTone {
  if (status === "running") return "blue";
  if (status === "done") return doneTone;
  return "slate";
}

function ScanOverview({
  scan,
  issueCount,
  continuableCount,
  variantIssueCount,
  gitHistoryCount,
  showGitHistoryStages,
  currentStage,
  indexProgress,
  pct,
  isRunning,
  isDone,
  fpReview,
  isFpReviewing,
  currentFpReviewTargets,
  hasReportModeSkill,
  verifiedIssueCount,
  onNavigate,
}: {
  scan: ScanStatusType;
  issueCount: number;
  continuableCount: number;
  variantIssueCount: number;
  gitHistoryCount: number;
  showGitHistoryStages: boolean;
  currentStage: string;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  pct: number;
  isRunning: boolean;
  isDone: boolean;
  fpReview: FpReviewJob | null;
  isFpReviewing: boolean;
  currentFpReviewTargets: Vulnerability[];
  hasReportModeSkill: boolean;
  verifiedIssueCount: number;
  onNavigate: (tab: MainTab) => void;
}) {
  const staticSeen = scan.static_analysis_done || scan.status === "analyzing" || scan.status === "auditing" || hasEvent(scan.events, ["static_analysis"]);
  const staticScannedFiles = staticSeen ? (scan.static_scanned_files || indexProgress.current) : 0;
  const staticTotalFiles = staticSeen ? (scan.static_total_files || indexProgress.total) : 0;
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
              {scan.validation_environment && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  验证环境：<span className="text-slate-300">{scan.validation_environment}</span>
                </span>
              )}
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
        <OverviewMetric icon="alert" label="发现的问题" value={issueCount} detail={`${verifiedIssueCount} 已验证`} tone="red" onClick={() => onNavigate("issues")} />
        {showGitHistoryStages && (
          <OverviewMetric icon="history" label="历史模式" value={gitHistoryCount} detail={`${variantIssueCount} 个变体候选`} tone="purple" onClick={() => onNavigate("threat")} />
        )}
        <OverviewMetric
          icon="queue"
          label="任务总数"
          value={scan.opencode_pool?.total_tasks ?? scan.total_task_count}
          detail={`${scan.opencode_pool?.completed_task_count ?? scan.completed_task_count} 已执行`}
          tone="blue"
        />
        <OverviewMetric icon="queue" label="可续扫任务" value={continuableCount} detail={continuableCount > 0 ? "可续扫" : "无待处理项"} tone="amber" />
      </div>

      <ScanTaskQueuePanel pool={scan.opencode_pool ?? null} />

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
            {showGitHistoryStages && (
              <TaskSummaryRow
                label="Git 历史问题分析"
                status={taskStateLabel(gitHistoryCount > 0 || hasEvent(scan.events, ["git_history"]), hasEvent(scan.events, ["git_history"]) && !auditRunning && !isDone)}
                tone={gitHistoryCount > 0 ? "purple" : hasEvent(scan.events, ["git_history"]) ? "amber" : "slate"}
                detail={gitHistoryCount > 0 ? `${gitHistoryCount} 条历史问题模式` : "暂无历史模式"}
              />
            )}
            <TaskSummaryRow
              label="候选点 AI 审计"
              status={taskStateLabel(isDone || (scan.total_candidates > 0 && scan.processed_candidates >= scan.total_candidates), auditRunning)}
              tone={auditRunning ? "blue" : isDone ? "green" : "slate"}
              progress={scan.static_analysis_done ? pct : undefined}
              detail={scan.total_candidates ? `${scan.processed_candidates}/${scan.total_candidates} 候选点` : "等待候选点"}
            />
            <TaskSummaryRow
              label="对抗式去误报"
              status={fpReview ? taskStateLabel(fpReview.status === "complete", isFpReviewing, fpReview.status === "error") : "预留"}
              tone={isFpReviewing ? "amber" : fpReview?.status === "complete" ? "green" : fpReview?.status === "error" ? "red" : "slate"}
              progress={fpReview?.total ? percent(fpReview.processed, fpReview.total) : undefined}
              detail={fpReview ? `${fpReview.processed}/${fpReview.total} 已复核` : "等待确认漏洞"}
            />
            <TaskSummaryRow
              label="报告导出"
              status={hasReportModeSkill ? (isRunning ? "同步中" : "可查看") : "预留"}
              tone={hasReportModeSkill ? "purple" : "slate"}
              detail={hasReportModeSkill ? `${scan.skill_reports?.length ?? 0} 个 SKILL 报告` : "可使用顶部导出按钮"}
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

function ScanTaskQueuePanel({ pool }: { pool: OpenCodePoolStatus | null }) {
  const [page, setPage] = useState(1);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const tasks = useMemo(() => collectScanQueueTasks(pool), [pool]);
  const runningCount = tasks.filter((task) => task.status === "running").length;
  const queuedCount = tasks.filter((task) => task.status === "queued").length;
  const plannedCount = tasks.filter((task) => task.status === "planned").length;
  const completedCount = tasks.filter((task) => !["planned", "queued", "running"].includes(task.status)).length;
  const unsuccessfulCount = tasks.filter((task) => ["failure", "timeout", "cancelled", "unknown"].includes(task.status)).length;
  const totalPages = Math.max(1, Math.ceil(tasks.length / SCAN_QUEUE_PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedTasks = tasks.slice((safePage - 1) * SCAN_QUEUE_PAGE_SIZE, safePage * SCAN_QUEUE_PAGE_SIZE);
  const toggleTask = (taskId: string) => {
    setExpandedTaskId((current) => (current === taskId ? null : taskId));
  };

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  useEffect(() => {
    if (expandedTaskId && !tasks.some((task) => scanQueueTaskKey(task) === expandedTaskId)) {
      setExpandedTaskId(null);
    }
  }, [expandedTaskId, tasks]);

  return (
    <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">任务队列</h3>
          <p className="mt-1 text-xs text-slate-500">
            当前扫描的 OpenCode Session 计划、排队、运行和历史任务
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill label={`计划中 ${plannedCount}`} tone="slate" />
          <StatusPill label={`排队中 ${queuedCount}`} tone="amber" />
          <StatusPill label={`运行中 ${runningCount}`} tone="cyan" />
          <StatusPill label={`已执行 ${completedCount}`} tone="green" />
          {unsuccessfulCount > 0 && <StatusPill label={`未成功 ${unsuccessfulCount}`} tone="red" />}
        </div>
      </div>

      {tasks.length === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">
          当前扫描还没有 OpenCode 任务记录
        </div>
      ) : (
        <div className="mt-4 overflow-hidden rounded-lg border border-slate-800">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[52rem] text-sm">
              <thead className="bg-slate-950/70">
                <tr>
                  <th className={thCls}>状态</th>
                  <th className={thCls}>任务</th>
                  <th className={thCls}>目标</th>
                  <th className={thCls}>模型</th>
                  <th className={thCls}>时间</th>
                </tr>
              </thead>
              <tbody>
                {pagedTasks.map((task) => {
                  const taskKey = scanQueueTaskKey(task);
                  const isExpanded = expandedTaskId === taskKey;
                  const prompt = scanQueueTaskPrompt(task.task);
                  const promptLength = scanQueueTaskPromptLength(task.task, prompt);
                  const failureReason = typeof task.task.failure_reason === "string"
                    ? task.task.failure_reason.trim()
                    : "";
                  return (
                    <Fragment key={taskKey}>
                      <tr
                        className="cursor-pointer border-t border-slate-800/70 transition-colors hover:bg-slate-800/40 focus-within:bg-slate-800/40"
                        onClick={() => toggleTask(taskKey)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            toggleTask(taskKey);
                          }
                        }}
                        tabIndex={0}
                        aria-expanded={isExpanded}
                      >
                        <td className="px-3 py-3 align-top">
                          <StatusPill label={scanQueueStatusLabel(task.status)} tone={scanQueueStatusTone(task.status)} />
                        </td>
                        <td className="px-3 py-3 align-top">
                          <div className="flex items-start gap-2">
                            <span
                              className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded border border-slate-700 text-slate-400 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                              aria-hidden="true"
                            >
                              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="m9 5 7 7-7 7" />
                              </svg>
                            </span>
                            <div className="min-w-0">
                              <div className="font-medium text-slate-200">{scanQueueTaskTitle(task.task)}</div>
                              {task.scopeId && (
                                <div className="mt-1 font-mono text-[11px] text-slate-600">{task.scopeId}</div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="max-w-[28rem] px-3 py-3 align-top">
                          <div className="truncate font-mono text-xs text-slate-400" title={scanQueueTaskTarget(task.task)}>
                            {scanQueueTaskTarget(task.task) || "-"}
                          </div>
                        </td>
                        <td className="px-3 py-3 align-top text-xs text-slate-400">
                          {task.modelId || "-"}
                        </td>
                        <td className="px-3 py-3 align-top text-xs text-slate-500">
                          {formatDateTime(task.timestamp)}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-t border-slate-800/70 bg-slate-950/60">
                          <td colSpan={5} className="px-3 pb-4 pt-0">
                            <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-950 p-3">
                              {failureReason && (
                                <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2">
                                  <div className="text-xs font-semibold text-red-200">失败原因</div>
                                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">
                                    {failureReason}
                                  </div>
                                </div>
                              )}
                              <div>
                                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-xs font-semibold text-slate-300">Prompt</span>
                                  {prompt && (
                                    <span className="font-mono text-[11px] text-slate-600">
                                      {promptLength} chars
                                    </span>
                                  )}
                                </div>
                                {prompt ? (
                                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-800 bg-slate-900/80 p-3 font-mono text-xs leading-relaxed text-slate-300">
                                    {prompt}
                                  </pre>
                                ) : !["planned", "queued", "running"].includes(task.status) ? (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    该历史任务未保存完整 Prompt{promptLength > 0 ? `，仅记录长度 ${promptLength} chars` : ""}。
                                  </div>
                                ) : (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    完整 prompt 尚未生成，进入排队或运行后显示。
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          {tasks.length > SCAN_QUEUE_PAGE_SIZE && (
            <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
              <button
                type="button"
                disabled={safePage === 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                上一页
              </button>
              <span className="text-xs text-slate-500">
                第 {safePage}/{totalPages} 页 · 共 {tasks.length} 条
              </span>
              <button
                type="button"
                disabled={safePage === totalPages}
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                下一页
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function collectScanQueueTasks(pool: OpenCodePoolStatus | null): ScanQueueTask[] {
  if (!pool) return [];
  const out: ScanQueueTask[] = [];
  for (const [index, task] of (pool.planned_tasks ?? []).entries()) {
    out.push({
      id: String(task.planned_task_id || `planned-${index}`),
      status: "planned",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.planned_at || ""),
    });
  }
  for (const [index, task] of (pool.queued_tasks ?? []).entries()) {
    out.push({
      id: String(task.request_id || `queued-${index}`),
      status: "queued",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.queued_at || ""),
    });
  }
  for (const model of pool.models ?? []) {
    for (const [index, task] of (model.active_tasks ?? []).entries()) {
      out.push({
        id: String(task.task_id || `${model.id}-running-${index}`),
        status: "running",
        modelId: model.id,
        scopeId: String(task.scope_id || pool.scope_id || ""),
        task,
        timestamp: String(task.started_at || ""),
      });
    }
  }
  for (const [index, task] of (pool.completed_tasks ?? []).entries()) {
    const outcome = normalizeCompletedTaskOutcome(task.outcome);
    out.push({
      id: String(task.task_id || `completed-${index}`),
      status: outcome,
      modelId: String(task.model_id || task.model || ""),
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.finished_at || task.started_at || ""),
    });
  }
  return out.sort((a, b) => {
    const rank = scanQueueStatusRank(a.status) - scanQueueStatusRank(b.status);
    if (rank !== 0) return rank;
    if (scanQueueStatusRank(a.status) >= 3) return compareScanQueueTime(b.timestamp, a.timestamp);
    return compareScanQueueTime(a.timestamp, b.timestamp);
  });
}

function normalizeCompletedTaskOutcome(value: unknown): ScanQueueTaskStatus {
  const outcome = String(value || "unknown");
  if (["success", "failure", "timeout", "cancelled"].includes(outcome)) {
    return outcome as ScanQueueTaskStatus;
  }
  return "unknown";
}

function scanQueueTaskKey(task: ScanQueueTask): string {
  return `${task.status}-${task.id}`;
}

function scanQueueStatusRank(status: ScanQueueTaskStatus): number {
  if (status === "running") return 0;
  if (status === "queued") return 1;
  if (status === "planned") return 2;
  return 3;
}

function compareScanQueueTime(a: string, b: string): number {
  const at = Date.parse(a);
  const bt = Date.parse(b);
  if (Number.isNaN(at) && Number.isNaN(bt)) return 0;
  if (Number.isNaN(at)) return 1;
  if (Number.isNaN(bt)) return -1;
  return at - bt;
}

function scanQueueTaskTypeLabel(value: unknown): string {
  const type = String(value || "audit");
  if (type === "audit") return "候选点审计";
  if (type === "fp_review") return "对抗式去误报";
  if (type === "threat_analysis") return "威胁分析";
  if (type === "threat_audit") return "威胁审计";
  if (type === "validation") return "漏洞验证";
  return type;
}

function scanQueueTaskTitle(task: Record<string, unknown>): string {
  const type = scanQueueTaskTypeLabel(task.task_type);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const vulnType = task.vuln_type ? String(task.vuln_type) : "";
  return [type + stage, checker || vulnType].filter(Boolean).join(" · ");
}

function scanQueueTaskTarget(task: Record<string, unknown>): string {
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const fn = task.function ? String(task.function) : "";
  const auditIndex = task.audit_index != null ? `#${String(task.audit_index)}` : "";
  const vulnIndex = task.vuln_index != null ? `漏洞 #${String(task.vuln_index)}` : "";
  return [auditIndex || vulnIndex, file ? `${file}${line}` : "", fn].filter(Boolean).join(" ");
}

function scanQueueTaskPrompt(task: Record<string, unknown>): string {
  return typeof task.prompt === "string" ? task.prompt : "";
}

function scanQueueTaskPromptLength(task: Record<string, unknown>, prompt: string): number {
  if (typeof task.prompt_length === "number" && Number.isFinite(task.prompt_length)) {
    return task.prompt_length;
  }
  const parsed = Number(task.prompt_length);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : prompt.length;
}

function scanQueueStatusLabel(status: ScanQueueTaskStatus): string {
  if (status === "running") return "运行中";
  if (status === "queued") return "排队中";
  if (status === "planned") return "计划中";
  if (status === "success") return "成功";
  if (status === "failure") return "失败";
  if (status === "timeout") return "超时";
  if (status === "cancelled") return "已停止";
  return "未知";
}

function scanQueueStatusTone(status: ScanQueueTaskStatus): TaskTone {
  if (status === "running") return "cyan";
  if (status === "queued") return "amber";
  if (status === "planned") return "slate";
  if (status === "success") return "green";
  if (status === "cancelled" || status === "timeout") return "amber";
  return "red";
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

function StaticTaskPanel({
  scan,
  indexStatus,
  indexProgress,
  candidates,
  vulnerabilities,
  validations,
  currentCandidate,
  processedCandidates,
  events,
  indexEvents,
  activeStaticTab,
  onStaticTabChange,
}: {
  scan: ScanStatusType;
  indexStatus: IndexStatus | null;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  candidates: ScanCandidate[];
  vulnerabilities: Vulnerability[];
  validations: VulnerabilityValidation[];
  currentCandidate: Candidate | null;
  processedCandidates: number;
  events: ScanEvent[];
  indexEvents: ScanEvent[];
  activeStaticTab: StaticTab;
  onStaticTabChange: (value: StaticTab) => void;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [typeFilter, setTypeFilter] = useState(ALL_STATIC_FILTER);
  const [auditFilter, setAuditFilter] = useState(ALL_STATIC_FILTER);
  const [validationFilter, setValidationFilter] = useState(ALL_STATIC_FILTER);
  const [currentPage, setCurrentPage] = useState(1);
  const running = scan.status === "analyzing" && !scan.static_analysis_done;
  const seen = scan.static_analysis_done || running || scan.status === "auditing" || events.length > 0;
  const scannedFiles = seen ? (scan.static_scanned_files || indexProgress.current) : 0;
  const totalFiles = seen ? (scan.static_total_files || indexProgress.total) : 0;
  const displayedCandidates = useMemo<ScanCandidate[]>(() => {
    if (candidates.length > 0) return candidates.filter(isStaticCandidate);
    return vulnerabilities
      .filter(isStaticCandidateVulnerability)
      .map((vuln, index) => ({
        idx: index,
        file: vuln.file,
        line: vuln.line,
        function: vuln.function,
        description: vuln.description,
        vuln_type: vuln.vuln_type,
        related_functions: [],
        metadata: {},
      }));
  }, [candidates, vulnerabilities]);
  const vulnerabilityByKey = useMemo(() => {
    const out = new Map<string, { vuln: Vulnerability; index: number }>();
    vulnerabilities.forEach((vuln, index) => {
      out.set(candidateKey(vuln), { vuln, index });
    });
    return out;
  }, [vulnerabilities]);
  const validationByIndex = useMemo(
    () => new Map(validations.map((validation) => [validation.vuln_index, validation])),
    [validations],
  );
  const currentKey = currentCandidate ? candidateKey(currentCandidate) : "";
  const annotated = useMemo(
    () =>
      displayedCandidates.map((candidate) => {
        const vulnEntry = vulnerabilityByKey.get(candidateKey(candidate));
        const validation = vulnEntry ? validationByIndex.get(vulnEntry.index) : undefined;
        const auditStatus = currentKey && candidateKey(candidate) === currentKey
          ? "running"
          : vulnEntry
            ? "done"
            : "pending";
        const validationStatus = !vulnEntry || !isAiConfirmed(vulnEntry.vuln)
          ? "not_applicable"
          : validation?.running || validation?.status === "running" || validation?.status === "queued"
            ? "running"
            : validation && isValidationTerminalStatus(validation.status)
              ? isValidationFailed(validation.status) || validation.status === "failed"
                ? "failed"
                : "verified"
              : "unverified";
        return {
          candidate,
          vulnerability: vulnEntry?.vuln,
          vulnerabilityIndex: vulnEntry?.index,
          validation,
          auditStatus,
          validationStatus,
        };
      }),
    [currentKey, displayedCandidates, validationByIndex, vulnerabilityByKey],
  );
  const typeOptions = useMemo(
    () => valueOptions(displayedCandidates.map((candidate) => candidate.vuln_type), (value) => value.toUpperCase()),
    [displayedCandidates],
  );
  const auditOptions = useMemo(() => countStaticOptions(annotated.map((item) => item.auditStatus), AUDIT_FILTER_LABELS), [annotated]);
  const validationOptions = useMemo(
    () => countStaticOptions(annotated.map((item) => item.validationStatus), VALIDATION_FILTER_LABELS),
    [annotated],
  );
  const visible = useMemo(() => {
    let list = annotated;
    if (typeFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.candidate.vuln_type === typeFilter);
    if (auditFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.auditStatus === auditFilter);
    if (validationFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.validationStatus === validationFilter);
    return list;
  }, [annotated, auditFilter, typeFilter, validationFilter]);
  const totalPages = Math.max(1, Math.ceil(visible.length / STATIC_CANDIDATE_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paged = visible.slice((safePage - 1) * STATIC_CANDIDATE_PAGE_SIZE, safePage * STATIC_CANDIDATE_PAGE_SIZE);
  const selected = selectedIndex === null
    ? null
    : annotated.find((item) => item.candidate.idx === selectedIndex) ?? null;
  const verifiedCount = annotated.filter((item) => item.validationStatus === "verified" || item.validationStatus === "failed").length;
  const runningValidationCount = annotated.filter((item) => item.validationStatus === "running").length;

  useEffect(() => {
    setCurrentPage(1);
  }, [auditFilter, typeFilter, validationFilter]);

  useEffect(() => {
    if (visible.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !visible.some((item) => item.candidate.idx === selectedIndex)) {
      setSelectedIndex(visible[0].candidate.idx);
    }
  }, [selectedIndex, visible]);

  return (
    <TaskPanel
      title="静态分析"
      status={taskStateLabel(scan.static_analysis_done, running, scan.status === "error")}
      tone={scan.static_analysis_done ? "green" : running ? "cyan" : scan.status === "error" ? "red" : "slate"}
      summary="构建代码索引和调用关系后，运行静态规则产出后续 AI 审计候选点。"
    >
      <TabbedPanel tabs={STATIC_TABS} active={activeStaticTab} onChange={onStaticTabChange}>
        {activeStaticTab === "call_graph" ? (
          <CallGraphBuildPanel
            indexStatus={indexStatus}
            indexProgress={indexProgress}
            events={indexEvents}
          />
        ) : (
          <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="扫描文件" value={scannedFiles} tone="cyan" />
        <MiniMetric label="总文件" value={totalFiles} />
        <MiniMetric label="候选点" value={displayedCandidates.length || scan.total_candidates} tone="blue" />
      </div>
      <ProgressBlock label="候选点生成" current={scannedFiles} total={totalFiles} fallback="等待静态分析进度" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="已审计" value={processedCandidates} tone="blue" />
        <MiniMetric label="验证中" value={runningValidationCount} tone="cyan" />
        <MiniMetric label="已验证" value={verifiedCount} tone="green" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StaticFilterSelect label="类型" value={typeFilter} options={typeOptions} onChange={setTypeFilter} />
        <StaticFilterSelect label="审计" value={auditFilter} options={auditOptions} onChange={setAuditFilter} />
        <StaticFilterSelect label="验证" value={validationFilter} options={validationOptions} onChange={setValidationFilter} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,24rem)_1fr]">
        <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
          <div className="max-h-[70vh] flex-1 overflow-y-auto">
            {visible.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-slate-500">
                {displayedCandidates.length === 0 ? "暂无静态分析候选点" : "当前筛选条件下无候选点"}
              </div>
            ) : (
              <ul className="divide-y divide-slate-800">
                {paged.map((item) => (
                  <StaticCandidateListItem
                    key={item.candidate.idx}
                    item={item}
                    active={selectedIndex === item.candidate.idx}
                    onClick={() => setSelectedIndex(item.candidate.idx)}
                  />
                ))}
              </ul>
            )}
          </div>
          {visible.length > STATIC_CANDIDATE_PAGE_SIZE && (
            <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
              <button
                type="button"
                disabled={safePage === 1}
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                上一页
              </button>
              <span className="text-xs text-slate-500">
                第 {safePage}/{totalPages} 页 · 共 {visible.length} 条
              </span>
              <button
                type="button"
                disabled={safePage === totalPages}
                onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                下一页
              </button>
            </div>
          )}
        </div>
        <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
          {selected ? (
            <StaticCandidateDetail item={selected} />
          ) : (
            <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
              从左侧选择一个候选点查看详情
            </div>
          )}
        </div>
      </div>
      <EventList events={events} empty="暂无静态分析日志" />
          </>
        )}
      </TabbedPanel>
    </TaskPanel>
  );
}

function CallGraphBuildPanel({
  indexStatus,
  indexProgress,
  events,
}: {
  indexStatus: IndexStatus | null;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  events: ScanEvent[];
}) {
  const stats = indexProgress.stats;
  const files = stats?.files ?? indexProgress.total;
  const functions = stats?.functions ?? 0;
  const structs = stats?.structs ?? 0;
  const globals = stats?.global_variables ?? 0;
  const calls = stats?.function_calls ?? 0;
  const globalRefs = stats?.global_variable_references ?? 0;
  const statusText = indexProgress.failed
    ? (indexStatus?.error || "索引构建失败")
    : indexProgress.done
      ? "索引已完成"
      : indexProgress.running
        ? "索引构建中"
        : "等待索引状态";

  return (
    <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MiniMetric label="文件数" value={files} tone="cyan" />
        <MiniMetric label="函数数量" value={functions} tone="blue" />
        <MiniMetric label="调用关系" value={calls} tone="purple" />
        <MiniMetric label="结构体/类/联合体" value={structs} />
        <MiniMetric label="全局变量" value={globals} />
        <MiniMetric label="全局变量引用" value={globalRefs} />
      </div>
      <ProgressBlock label="文件解析" current={indexProgress.current} total={indexProgress.total} fallback="等待索引文件进度" />
      {indexProgress.stage && (
        <ProgressBlock
          label={`索引阶段：${indexProgress.stage}`}
          current={indexProgress.stageCurrent}
          total={indexProgress.stageTotal}
          fallback="等待阶段进度"
        />
      )}
      <div className="rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-3 text-sm text-slate-300">
        {statusText}
      </div>
      <EventList events={events} empty="暂无调用图构建日志" />
    </>
  );
}

const ALL_STATIC_FILTER = "__all__";

const AUDIT_FILTER_LABELS: Record<string, string> = {
  pending: "待审计",
  running: "审计中",
  done: "已审计",
};

const VALIDATION_FILTER_LABELS: Record<string, string> = {
  unverified: "未验证",
  running: "验证中",
  verified: "已验证",
  failed: "验证异常",
  not_applicable: "无验证目标",
};

interface StaticFilterOption {
  value: string;
  label: string;
  count: number;
}

interface StaticCandidateItem {
  candidate: ScanCandidate;
  vulnerability?: Vulnerability;
  vulnerabilityIndex?: number;
  validation?: VulnerabilityValidation;
  auditStatus: string;
  validationStatus: string;
}

function valueOptions(
  values: string[],
  formatLabel: (value: string) => string = (value) => value,
): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries())
    .sort(([a], [b]) => formatLabel(a).localeCompare(formatLabel(b)))
    .map(([value, count]) => ({ value, label: formatLabel(value), count }));
}

function countStaticOptions(values: string[], labels: Record<string, string>): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Object.entries(labels).map(([value, label]) => ({
    value,
    label,
    count: counts.get(value) ?? 0,
  }));
}

function StaticFilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: StaticFilterOption[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
      >
        <option value={ALL_STATIC_FILTER}>全部</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label} ({option.count})
          </option>
        ))}
      </select>
    </label>
  );
}

function StaticCandidateListItem({
  item,
  active,
  onClick,
}: {
  item: StaticCandidateItem;
  active: boolean;
  onClick: () => void;
}) {
  const fileName = item.candidate.file.split("/").pop() || item.candidate.file;
  const auditTone: TaskTone = item.auditStatus === "running" ? "blue" : item.auditStatus === "done" ? "green" : "slate";
  const validationToneValue: TaskTone =
    item.validationStatus === "running"
      ? "blue"
      : item.validationStatus === "verified"
        ? "green"
        : item.validationStatus === "failed"
          ? "red"
          : "slate";
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        className={`w-full px-3 py-2.5 text-left transition-colors ${
          active ? "bg-blue-500/15" : item.auditStatus === "running" ? "bg-blue-500/10 hover:bg-blue-500/15" : "hover:bg-slate-800/60"
        }`}
      >
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[11px] text-slate-500">#{item.candidate.idx}</span>
          <span className="truncate font-mono text-xs text-slate-200" title={`${item.candidate.file}:${item.candidate.line}`}>
            {fileName}:{item.candidate.line}
          </span>
          {item.auditStatus === "running" && (
            <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />
          )}
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
            {item.candidate.vuln_type}
          </span>
          <StatusPill label={AUDIT_FILTER_LABELS[item.auditStatus] ?? item.auditStatus} tone={auditTone} />
          <StatusPill label={VALIDATION_FILTER_LABELS[item.validationStatus] ?? item.validationStatus} tone={validationToneValue} />
        </div>
        {item.candidate.function && (
          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={item.candidate.function}>
            {item.candidate.function}
          </div>
        )}
      </button>
    </li>
  );
}

function StaticCandidateDetail({ item }: { item: StaticCandidateItem }) {
  const metadata = item.candidate.metadata && Object.keys(item.candidate.metadata).length > 0
    ? JSON.stringify(item.candidate.metadata, null, 2)
    : "";
  const related = item.candidate.related_functions ?? [];
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{item.candidate.idx}</span>
              <span className="text-sm font-semibold text-slate-100">{item.candidate.vuln_type}</span>
              {item.vulnerabilityIndex !== undefined && (
                <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-xs text-red-300">
                  结果 #{item.vulnerabilityIndex}
                </span>
              )}
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{item.candidate.file}:{item.candidate.line}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{item.candidate.function}</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <StatusPill label={AUDIT_FILTER_LABELS[item.auditStatus] ?? item.auditStatus} tone={item.auditStatus === "done" ? "green" : item.auditStatus === "running" ? "blue" : "slate"} />
            <StatusPill label={VALIDATION_FILTER_LABELS[item.validationStatus] ?? item.validationStatus} tone={item.validationStatus === "verified" ? "green" : item.validationStatus === "running" ? "blue" : item.validationStatus === "failed" ? "red" : "slate"} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">候选描述</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={item.candidate.description || "（无描述）"} />
          </div>
        </section>
        {item.vulnerability && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">AI 审计结论</h4>
            <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
              <MarkdownContent content={item.vulnerability.ai_analysis || "（无分析）"} />
            </div>
          </section>
        )}
        {item.validation && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞验证状态</h4>
            <div className="flex flex-wrap gap-2">
              <StatusPill label={validationStatusLabel(item.validation.status)} tone={validationTone(item.validation)} />
              <StatusPill label={`验证成功：${formatNullableBool(item.validation.validation_success)}`} tone={nullableBoolTone(item.validation.validation_success)} />
              <StatusPill label={`是否问题：${formatNullableBool(item.validation.is_problem)}`} tone={nullableBoolTone(item.validation.is_problem)} />
              <StatusPill label={`人工介入：${formatNullableBool(item.validation.requires_human_intervention)}`} tone={humanInterventionTone(item.validation.requires_human_intervention)} />
            </div>
          </section>
        )}
        {related.length > 0 && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">相关函数</h4>
            <div className="rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300">
              {related.join(", ")}
            </div>
          </section>
        )}
        {metadata && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">候选元数据</h4>
            <pre className="max-h-72 overflow-auto rounded border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs leading-5 text-slate-300">
              {metadata}
            </pre>
          </section>
        )}
      </div>
    </div>
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
  const runningAudits = (pool?.models ?? []).reduce(
    (count, model) => count + model.active_tasks.filter(
      (task) => String(task.task_type || "audit") === "audit",
    ).length,
    0,
  );
  const queuedAudits = (pool?.queued_tasks ?? []).filter(
    (task) => String(task.task_type || "audit") === "audit",
  ).length;
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
        <MiniMetric label="运行中" value={runningAudits} tone="cyan" />
        <MiniMetric label="排队中" value={queuedAudits} tone="amber" />
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

const FP_REVIEW_STAGE_LABELS: Record<string, string> = {
  history_match: "历史匹配",
  prove_bug: "正报论证",
  prove_fp: "误报论证",
  final_judge: "最终裁决",
};

function FpReviewPanel({
  vulnerabilities,
  fpReview,
  isFpReviewing,
  loading,
  stopping,
  events,
  onTrigger,
  onStop,
}: {
  vulnerabilities: Vulnerability[];
  fpReview: FpReviewJob | null;
  isFpReviewing: boolean;
  loading: boolean;
  stopping: boolean;
  events: ScanEvent[];
  onTrigger: () => void | Promise<void>;
  onStop: () => void | Promise<void>;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const confirmed = useMemo(
    () => vulnerabilities.map((vuln, index) => ({ vuln, index })).filter(({ vuln }) => isAiConfirmed(vuln)),
    [vulnerabilities],
  );
  const resultByIndex = useMemo(
    () => new Map((fpReview?.results ?? []).map((result) => [result.vuln_index, result])),
    [fpReview],
  );
  const currentIndices = useMemo(() => {
    if (!isFpReviewing) return new Set<number>();
    const values = fpReview?.current_vuln_indices?.length
      ? fpReview.current_vuln_indices
      : fpReview?.current_vuln_index != null
        ? [fpReview.current_vuln_index]
        : [];
    return new Set(values.filter((index) => index >= 0));
  }, [fpReview, isFpReviewing]);
  const items = useMemo(
    () =>
      confirmed
        .map(({ vuln, index }) => ({
          vuln,
          index,
          result: resultByIndex.get(index),
          running: currentIndices.has(index),
        }))
        .sort((a, b) => fpReviewSortRank(a.result, a.running) - fpReviewSortRank(b.result, b.running) || a.index - b.index),
    [confirmed, currentIndices, resultByIndex],
  );
  const waitingCount = items.filter((item) => !item.result && !item.running).length;
  const tpCount = items.filter((item) => item.result?.verdict === "tp").length;
  const fpCount = items.filter((item) => item.result?.verdict === "fp").length;
  const status = isFpReviewing
    ? "复核中"
    : fpReview?.status === "complete"
      ? "已完成"
      : fpReview?.status === "error"
        ? "异常"
        : fpReview?.status === "cancelled"
          ? "已停止"
          : confirmed.length > 0
            ? "等待"
            : "无目标";
  const tone: TaskTone = isFpReviewing
    ? "amber"
    : fpReview?.status === "complete"
      ? "green"
      : fpReview?.status === "error"
        ? "red"
        : fpReview?.status === "cancelled"
          ? "amber"
          : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;
  const canTrigger = confirmed.length > 0 && !isFpReviewing && !loading;

  useEffect(() => {
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex]);

  return (
    <TaskPanel
      title="对抗式去误报"
      status={status}
      tone={tone}
      summary="对漏洞挖掘阶段确认的问题逐条复核，输出正报或误报裁决。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={confirmed.length} tone="red" />
        <MiniMetric label="等待复核" value={waitingCount} />
        <MiniMetric label="复核中" value={currentIndices.size} tone="amber" />
        <MiniMetric label="保留正报" value={tpCount} tone="red" />
        <MiniMetric label="判定误报" value={fpCount} tone="green" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onTrigger}
          disabled={!canTrigger}
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-sm font-medium text-amber-200 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "启动中..." : "启动去误报"}
        </button>
        {isFpReviewing && (
          <button
            type="button"
            onClick={onStop}
            disabled={stopping}
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {stopping ? "停止中..." : "停止复核"}
          </button>
        )}
        {fpReview?.error_message && (
          <span className="text-xs text-red-300">{fpReview.error_message}</span>
        )}
      </div>
      {confirmed.length === 0 ? (
        <EmptyState text="当前还没有漏洞挖掘阶段确认的问题。" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[70vh] flex-1 overflow-y-auto">
              <ul className="divide-y divide-slate-800">
                {items.map(({ vuln, index, result, running }) => {
                  const active = selectedIndex === index;
                  const fileName = vuln.file.split("/").pop() || vuln.file;
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        onClick={() => setSelectedIndex(index)}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${
                          active ? "bg-amber-500/15" : running ? "bg-amber-500/10 hover:bg-amber-500/15" : "hover:bg-slate-800/60"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11px] text-slate-500">#{index}</span>
                          <span className="truncate font-mono text-xs text-slate-200" title={`${vuln.file}:${vuln.line}`}>
                            {fileName}:{vuln.line}
                          </span>
                          {running && <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-amber-500/30 border-t-amber-300 animate-spin" />}
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
                            {vuln.vuln_type}
                          </span>
                          <StatusPill label={fpReviewItemLabel(result, running)} tone={fpReviewItemTone(result, running)} />
                        </div>
                        {vuln.function && (
                          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vuln.function}>
                            {vuln.function}
                          </div>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <FpReviewDetail
                index={selected.index}
                vulnerability={selected.vuln}
                result={selected.result}
                running={selected.running}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个问题查看复核详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无去误报任务日志" />
    </TaskPanel>
  );
}

function FpReviewDetail({
  index,
  vulnerability,
  result,
  running,
}: {
  index: number;
  vulnerability: Vulnerability;
  result?: FpReviewJob["results"][number];
  running: boolean;
}) {
  const stageEntries = Object.entries(result?.stage_outputs ?? {})
    .filter(([, content]) => Boolean(content))
    .sort(([a], [b]) => fpStageOrder(a) - fpStageOrder(b));
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerability.vuln_type}</span>
              <span className="text-xs text-slate-500">{vulnerability.severity}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerability.file}:{vulnerability.line}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerability.function}</div>
          </div>
          <div className="flex items-center gap-2">
            {running && <span className="h-3 w-3 rounded-full border border-amber-500/30 border-t-amber-300 animate-spin" />}
            <StatusPill label={fpReviewItemLabel(result, running)} tone={fpReviewItemTone(result, running)} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </section>
        {result ? (
          <>
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">复核结论</h4>
              <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
                <div className="mb-2 flex flex-wrap gap-2">
                  <StatusPill label={result.verdict === "fp" ? "误报" : "正报"} tone={result.verdict === "fp" ? "green" : "red"} />
                  <StatusPill label={`严重性：${result.severity || "-"}`} tone="slate" />
                  {result.match_type && <StatusPill label={`依据：${result.match_type}`} tone="purple" />}
                </div>
                <MarkdownContent content={result.reason || "（无结论说明）"} />
                {result.match_reference && (
                  <div className="mt-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
                    {result.match_reference}
                  </div>
                )}
              </div>
            </section>
            {result.vulnerability_report && (
              <section>
                <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞报告</h4>
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
                  <MarkdownContent content={result.vulnerability_report} />
                </div>
              </section>
            )}
            {stageEntries.length > 0 && (
              <section className="space-y-3">
                <h4 className="text-xs font-semibold uppercase text-slate-500">阶段输出</h4>
                {stageEntries.map(([stage, content]) => (
                  <div key={stage} className="rounded-lg border border-slate-800 bg-slate-950/40">
                    <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-400">
                      {FP_REVIEW_STAGE_LABELS[stage] ?? stage}
                    </div>
                    <div className="px-4 py-2">
                      <MarkdownContent content={content} />
                    </div>
                  </div>
                ))}
              </section>
            )}
          </>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-500">
            {running ? "当前问题正在复核中" : "等待去误报任务处理"}
          </div>
        )}
      </div>
    </div>
  );
}

function fpStageOrder(stage: string): number {
  const order = ["history_match", "prove_bug", "prove_fp", "final_judge"];
  const index = order.indexOf(stage);
  return index >= 0 ? index : order.length;
}

function fpReviewSortRank(result: FpReviewJob["results"][number] | undefined, running: boolean): number {
  if (running) return 0;
  if (!result) return 1;
  return 2;
}

function fpReviewItemLabel(result: FpReviewJob["results"][number] | undefined, running: boolean): string {
  if (running) return "复核中";
  if (!result) return "等待复核";
  return result.verdict === "fp" ? "误报" : "正报";
}

function fpReviewItemTone(result: FpReviewJob["results"][number] | undefined, running: boolean): TaskTone {
  if (running) return "amber";
  if (!result) return "slate";
  return result.verdict === "fp" ? "green" : "red";
}

function ValidationPanel({
  vulnerabilities,
  validations,
  stoppingValidationIndices,
  events,
  onStopValidation,
}: {
  vulnerabilities: Vulnerability[];
  validations: VulnerabilityValidation[];
  stoppingValidationIndices?: Set<number>;
  events: ScanEvent[];
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const confirmed = vulnerabilities
    .map((vuln, index) => ({ vuln, index }))
    .filter(({ vuln }) => isAiConfirmed(vuln));
  const validationByIndex = new Map(validations.map((item) => [item.vuln_index, item]));
  const items = confirmed
    .map(({ vuln, index }) => ({ vuln, index, validation: validationByIndex.get(index) }))
    .sort((a, b) => {
      const aRank = validationSortRank(a.validation);
      const bRank = validationSortRank(b.validation);
      if (aRank !== bRank) return aRank - bRank;
      return a.index - b.index;
    });
  const itemValidations = items.map((item) => item.validation).filter((item): item is VulnerabilityValidation => Boolean(item));
  const waitingCount = items.filter((item) => !item.validation || item.validation.status === "queued" || item.validation.status === "pending").length;
  const runningCount = itemValidations.filter((item) => item.running || item.status === "running").length;
  const completedCount = itemValidations.filter((item) => isValidationComplete(item.status)).length;
  const failedCount = itemValidations.filter((item) => isValidationFailed(item.status)).length;
  const status = runningCount > 0 ? "验证中" : completedCount > 0 ? "已验证" : confirmed.length > 0 ? "等待" : "无目标";
  const tone: TaskTone = runningCount > 0 ? "blue" : failedCount > 0 ? "red" : completedCount > 0 ? "green" : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;

  useEffect(() => {
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex]);

  return (
    <TaskPanel
      title="漏洞验证"
      status={status}
      tone={tone}
      summary="对漏洞挖掘阶段确认的问题调用 Agent 本地验证脚本，展示验证过程和脚本返回结果。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={confirmed.length} tone="red" />
        <MiniMetric label="等待验证" value={waitingCount} />
        <MiniMetric label="验证中" value={runningCount} tone="blue" />
        <MiniMetric label="已完成" value={completedCount} tone="green" />
        <MiniMetric label="异常/超时" value={failedCount} tone="amber" />
      </div>
      {confirmed.length === 0 ? (
        <EmptyState text="当前还没有漏洞挖掘阶段确认的问题。" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[70vh] flex-1 overflow-y-auto">
              <ul className="divide-y divide-slate-800">
                {items.map(({ vuln, index, validation }) => {
                  const active = selectedIndex === index;
                  const statusText = validation?.status || "pending";
                  const itemTone = validationTone(validation);
                  const fileName = vuln.file.split("/").pop() || vuln.file;
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        onClick={() => setSelectedIndex(index)}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${
                          active ? "bg-blue-500/15" : "hover:bg-slate-800/60"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="truncate font-mono text-xs text-slate-200" title={`${vuln.file}:${vuln.line}`}>
                            {fileName}:{vuln.line}
                          </span>
                          {validation?.running && <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-semibold uppercase text-slate-400 bg-slate-700/50 px-1.5 py-0.5 rounded">
                            {vuln.vuln_type}
                          </span>
                          <StatusPill label={validationStatusLabel(statusText)} tone={itemTone} />
                        </div>
                        {vuln.function && (
                          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vuln.function}>
                            {vuln.function}
                          </div>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <ValidationDetail
                index={selected.index}
                vulnerability={selected.vuln}
                validation={selected.validation}
                stopping={stoppingValidationIndices?.has(selected.index) ?? false}
                onStopValidation={onStopValidation}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个问题查看验证详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无验证任务日志" />
    </TaskPanel>
  );
}

function ValidationDetail({
  index,
  vulnerability,
  validation,
  stopping = false,
  onStopValidation,
}: {
  index: number;
  vulnerability: Vulnerability;
  validation?: VulnerabilityValidation;
  stopping?: boolean;
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const status = validation?.status || "pending";
  const tone = validationTone(validation);
  const canStop = Boolean(onStopValidation && (stopping || validation?.running || status === "queued" || status === "running"));
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerability.vuln_type}</span>
              <span className="text-xs text-slate-500">{vulnerability.severity}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerability.file}:{vulnerability.line}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerability.function}</div>
          </div>
          <div className="flex items-center gap-2">
            {canStop && (
              <button
                type="button"
                onClick={() => onStopValidation?.(index)}
                disabled={stopping}
                className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {stopping ? "停止中..." : "停止验证"}
              </button>
            )}
            {validation?.running && <span className="h-3 w-3 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
            <StatusPill label={validationStatusLabel(status)} tone={tone} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <div className="min-w-0">
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </div>
        {validation ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <StatusPill
                label={`验证成功：${formatNullableBool(validation.validation_success)}`}
                tone={nullableBoolTone(validation.validation_success)}
              />
              <StatusPill
                label={`是否问题：${formatNullableBool(validation.is_problem)}`}
                tone={nullableBoolTone(validation.is_problem)}
              />
              <StatusPill
                label={`人工介入：${formatNullableBool(validation.requires_human_intervention)}`}
                tone={humanInterventionTone(validation.requires_human_intervention)}
              />
              {validation.product && <StatusPill label={`产品：${validation.product}`} tone="slate" />}
              {validation.validation_environment && <StatusPill label={`环境：${validation.validation_environment}`} tone="slate" />}
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                <div className="space-y-3">
                  <ValidationOutputSections validation={validation} />
                </div>
                <div className="space-y-3">
                  <ValidationArtifacts validation={validation} />
                </div>
              </div>
              <ValidationBlock title="最终结论" content={validation.final_output || validation.validation_output} />
            </div>
          </div>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-500">等待验证脚本启动</div>
        )}
      </div>
    </div>
  );
}

function ValidationOutputSections({ validation }: { validation: VulnerabilityValidation }) {
  const sections = validationOutputSections(validation);
  if (sections.length === 0) return null;
  return (
    <>
      {sections.map((section, idx) => (
        <ValidationBlock
          key={`${section.title}-${idx}`}
          title={section.title || "中间产出"}
          content={section.content || ""}
        />
      ))}
    </>
  );
}

function ValidationArtifacts({ validation }: { validation: VulnerabilityValidation }) {
  const artifacts = validation.artifacts && validation.artifacts.length > 0
    ? validation.artifacts
    : validation.validation_code
      ? [{ title: "产物", name: "validation.py", kind: "code", content: validation.validation_code }]
      : [];
  const groups = groupedValidationArtifacts(artifacts);
  if (groups.length === 0) return null;
  return (
    <>
      {groups.map(([title, items]) => (
        <div key={title} className="min-w-0 rounded border border-slate-800 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
        <div className="max-h-72 overflow-auto">
          {items.map((artifact, idx) => (
            <div key={`${artifact.name}-${idx}`} className="border-b border-slate-900 last:border-b-0">
              <div className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
                <span className="font-mono text-slate-200">{artifact.name}</span>
                {artifact.kind && <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">{artifact.kind}</span>}
                {artifact.path && <span className="break-all font-mono text-[11px] text-slate-500">{artifact.path}</span>}
              </div>
              {artifact.content && (
                <pre className="whitespace-pre-wrap break-words px-3 pb-2 font-mono text-xs leading-5 text-slate-300">
                  {artifact.content}
                </pre>
              )}
            </div>
          ))}
        </div>
        </div>
      ))}
    </>
  );
}

function validationOutputSections(validation: VulnerabilityValidation) {
  const sections = (validation.output_sections ?? [])
    .filter((section) => section && (section.title || section.content))
    .map((section) => ({
      title: section.title || "中间产出",
      content: section.content || "",
      updated_at: section.updated_at || "",
    }));
  if (sections.length > 0) return sections;
  if (validation.intermediate_output) {
    return [{ title: "中间产出", content: validation.intermediate_output, updated_at: validation.updated_at }];
  }
  return [];
}

function groupedValidationArtifacts(artifacts: NonNullable<VulnerabilityValidation["artifacts"]>) {
  const groups = new Map<string, typeof artifacts>();
  for (const artifact of artifacts) {
    const title = artifact.title?.trim() || "产物";
    const items = groups.get(title) ?? [];
    items.push(artifact);
    groups.set(title, items);
  }
  return Array.from(groups.entries());
}

function ValidationBlock({ title, content }: { title: string; content: string }) {
  return (
    <div className="min-w-0 rounded border border-slate-800 bg-slate-950">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words px-3 py-2 font-mono text-xs leading-5 text-slate-300">
        {content || "（暂无）"}
      </pre>
    </div>
  );
}

function validationStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "等待",
    queued: "等待",
    running: "验证中",
    verified: "已验证",
    success: "已验证",
    failed: "未通过",
    error: "异常",
    timeout: "超时",
    cancelled: "已取消",
    skipped: "跳过",
  };
  return labels[status] ?? status;
}

function formatNullableBool(value?: boolean | null): string {
  if (value === true) return "是";
  if (value === false) return "否";
  return "未知";
}

function nullableBoolTone(value?: boolean | null): TaskTone {
  if (value === true) return "green";
  if (value === false) return "amber";
  return "slate";
}

function humanInterventionTone(value?: boolean | null): TaskTone {
  if (value === true) return "amber";
  if (value === false) return "green";
  return "slate";
}

function validationTone(validation?: VulnerabilityValidation): TaskTone {
  const status = validation?.status || "pending";
  if (validation?.running || status === "queued" || status === "running") return "blue";
  if (isValidationFailed(status)) return "red";
  if (isValidationComplete(status)) return "green";
  return "slate";
}

function validationSortRank(validation?: VulnerabilityValidation): number {
  if (!validation) return 1;
  if (validation.running || validation.status === "running") return 0;
  if (validation.status === "queued" || validation.status === "pending") return 1;
  if (isValidationFailed(validation.status)) return 2;
  if (isValidationComplete(validation.status)) return 3;
  return 4;
}

function isValidationComplete(status: string): boolean {
  return ["verified", "success", "failed"].includes(status);
}

function isValidationFailed(status: string): boolean {
  return ["error", "timeout", "cancelled"].includes(status);
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
    threat_analysis: "text-emerald-300",
    threat_audit: "text-cyan-300",
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
  const plannedTasks = pool?.planned_tasks ?? [];
  const queuedTasks = pool?.queued_tasks ?? [];
  const completedTasks = pool?.completed_tasks ?? [];
  const failedTasks = completedTasks.filter((task) => {
    const outcome = String(task.outcome || "unknown");
    return outcome !== "success";
  });
  const recentFailedTasks = failedTasks.slice(-10).reverse();
  const unassignedCompletedTasks = completedTasks.filter(
    (task) => !String(task.model_id || task.model || "").trim(),
  );
  const hasEnabledModel = models.some((model) => model.enabled);
  const total = models.reduce((sum, item) => sum + item.total, 0) + unassignedCompletedTasks.length;
  const success = models.reduce((sum, item) => sum + item.success, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "success").length;
  const failure = models.reduce((sum, item) => sum + item.failure, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "failure").length;
  const timeout = models.reduce((sum, item) => sum + item.timeout, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "timeout").length;
  const cancelled = models.reduce((sum, item) => sum + item.cancelled, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "cancelled").length;

  if (!pool) {
    return (
      <div className="flex-1 overflow-y-auto p-5">
        <div className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-5 text-sm text-slate-500">
          当前扫描尚未收到 OpenCode 模型池状态。
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-4">
      {!hasEnabledModel && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm leading-6 text-amber-200">
          当前没有启用的模型，新的 LLM 任务会立即失败。如需使用 CLI 默认模型，必须在 Agent 模型池中显式添加并启用“默认模型”。
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
        <MetricBox label="计划中" value={plannedTasks.length} tone="amber" />
        <MetricBox label="运行中" value={pool.global_running} tone="cyan" />
        <MetricBox label="排队中" value={pool.global_queued} tone="amber" />
        <MetricBox label="累计任务" value={total} />
        <MetricBox label="成功" value={success} tone="green" />
        <MetricBox label="失败" value={failure} tone="red" />
        <MetricBox label="超时/取消" value={timeout + cancelled} tone="amber" />
      </div>

      {plannedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">计划中任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {plannedTasks.map((task, index) => (
              <div
                key={String(task.planned_task_id || index)}
                className="truncate rounded border border-slate-500/20 bg-slate-800/70 px-2 py-1.5 text-xs text-slate-200"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {queuedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">全局排队任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {queuedTasks.map((task, index) => (
              <div
                key={String(task.request_id || index)}
                className="truncate rounded border border-amber-500/20 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-100"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {failedTasks.length > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
          <div className="mb-2 text-xs font-semibold text-red-200">
            任务失败 {failedTasks.length} 个{failedTasks.length > recentFailedTasks.length ? `（显示最近 ${recentFailedTasks.length} 个）` : ""}
          </div>
          <div className="space-y-2">
            {recentFailedTasks.map((task, index) => {
              const reason = typeof task.failure_reason === "string" && task.failure_reason.trim()
                ? task.failure_reason.trim()
                : "未记录失败原因";
              return (
                <div key={String(task.task_id || index)} className="rounded border border-red-500/20 bg-slate-950/50 px-3 py-2">
                  <div className="text-xs font-medium text-red-100">{modelTaskLabel(task)}</div>
                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">{reason}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {models.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[64rem] text-sm">
          <thead className="bg-slate-950">
            <tr>
              <th className={thCls}>模型</th>
              <th className={thCls}>能力</th>
              <th className={thCls}>可用</th>
              <th className={thCls}>权重</th>
              <th className={thCls}>运行/上限</th>
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
                    {model.use_default_model ? "(CLI 默认模型)" : (model.model || "(模型名为空)")}
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
                <td className={tdCls}>{model.total}</td>
                <td className={`${tdCls} text-green-300`}>{model.success}</td>
                <td className={`${tdCls} text-red-300`}>{model.failure}</td>
                <td className={`${tdCls} text-amber-300`}>{model.timeout}</td>
                <td className={`${tdCls} text-slate-300`}>{model.cancelled}</td>
                <td className={tdCls}>{formatDuration(model.avg_duration_seconds)}</td>
                <td className={`${tdCls} max-w-72 text-slate-400`}>
                  <ModelTaskList tasks={model.active_tasks} />
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
      )}
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
  const taskType = scanQueueTaskTypeLabel(task.task_type);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const target = file ? `${file}${line}` : checker;
  const session = task.serve_session_id ? String(task.serve_session_id) : "";
  return [taskType + stage, target, session].filter(Boolean).join(" ");
}

function ModelTaskList({ tasks }: { tasks?: Record<string, unknown>[] }) {
  const activeTasks = tasks || [];
  if (activeTasks.length === 0) return <>-</>;
  return (
    <div className="space-y-1">
      {activeTasks.map((task, index) => (
        <div key={String(task.task_id || index)} className="truncate">
          {modelTaskLabel(task)}
        </div>
      ))}
    </div>
  );
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
