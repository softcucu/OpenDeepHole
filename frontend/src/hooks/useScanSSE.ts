import { useEffect, useRef, useState, useCallback } from "react";
import { scanSSEUrl, getScanStatus, getFpReview } from "../api/client";
import type {
  FpReviewJob,
  FpReviewStatus,
  IndexStatus,
  ScanEvent,
  ScanStatus,
  Vulnerability,
} from "../types";

/* ------------------------------------------------------------------ */
/*  SSE event payload types (mirror backend publish() shapes)          */
/* ------------------------------------------------------------------ */

interface ScanStatusEvent {
  status: string | null;
  progress: number | null;
  total_candidates: number | null;
  processed_candidates: number | null;
  static_total_files?: number | null;
  static_scanned_files?: number | null;
  static_analysis_done?: boolean | null;
  opencode_pool?: ScanStatus["opencode_pool"];
}

interface ScanVulnerabilityEvent {
  index: number;
  vulnerability: Vulnerability;
}

interface ScanEventPayload {
  event: ScanEvent;
}

interface ScanFinishEvent {
  status: string;
  error_message: string | null;
}

interface FpReviewStartedEvent {
  review_id: string;
  status: FpReviewStatus;
  total: number;
}

interface FpReviewProgressEvent {
  review_id: string;
  vuln_index: number;
  processed: number;
  total: number;
}

interface FpReviewResultEvent {
  review_id: string;
  vuln_index: number;
  verdict: "tp" | "fp";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report?: string;
  stage_outputs?: Record<string, string>;
}

interface FpReviewStageOutputEvent {
  review_id: string;
  vuln_index: number;
  stage: string;
  markdown: string;
}

interface FpReviewFinishEvent {
  review_id: string;
  status: FpReviewStatus;
  error_message: string | null;
}

/* ------------------------------------------------------------------ */
/*  Handler map                                                        */
/* ------------------------------------------------------------------ */

export interface ScanSSEHandlers {
  onScanStatus?: (data: ScanStatusEvent) => void;
  onScanVulnerability?: (data: ScanVulnerabilityEvent) => void;
  onScanEvent?: (data: ScanEventPayload) => void;
  onScanFinish?: (data: ScanFinishEvent) => void;
  onFpReviewStarted?: (data: FpReviewStartedEvent) => void;
  onFpReviewProgress?: (data: FpReviewProgressEvent) => void;
  onFpReviewStageOutput?: (data: FpReviewStageOutputEvent) => void;
  onFpReviewResult?: (data: FpReviewResultEvent) => void;
  onFpReviewFinish?: (data: FpReviewFinishEvent) => void;
  onIndexStatus?: (data: IndexStatus) => void;
}

/* ------------------------------------------------------------------ */
/*  Full-state refresh helpers (used on connect and reconnect)         */
/* ------------------------------------------------------------------ */

export interface SSEStateSetters {
  setScan: React.Dispatch<React.SetStateAction<ScanStatus | null>>;
  setFpReview: React.Dispatch<React.SetStateAction<FpReviewJob | null>>;
  setIndexStatus: React.Dispatch<React.SetStateAction<IndexStatus | null>>;
}

async function refreshFullState(
  scanId: string,
  { setScan, setFpReview }: SSEStateSetters,
) {
  try {
    const data = await getScanStatus(scanId);
    setScan(data);
  } catch {
    // transient — SSE will keep pushing
  }
  try {
    const job = await getFpReview(scanId);
    // Merge with existing state to preserve in-progress stage_outputs
    // that arrived via SSE but are not yet part of a completed result.
    setFpReview((prev) => {
      if (!prev) return job;
      if (prev.review_id !== job.review_id) return job;
      const mergedResults = job.results.map((r) => {
        const existing = prev.results.find((p) => p.vuln_index === r.vuln_index);
        if (existing) {
          return {
            ...r,
            stage_outputs: { ...(existing.stage_outputs ?? {}), ...(r.stage_outputs ?? {}) },
          };
        }
        return r;
      });
      // Keep entries that only exist locally (in-progress, not yet in DB).
      const inProgressOnly = prev.results.filter(
        (p) =>
          !job.results.some((r) => r.vuln_index === p.vuln_index) &&
          Object.keys(p.stage_outputs ?? {}).length > 0,
      );
      return { ...job, results: [...mergedResults, ...inProgressOnly] };
    });
  } catch {
    // 404 = no review yet
  }
}

/* ------------------------------------------------------------------ */
/*  Hook                                                               */
/* ------------------------------------------------------------------ */

export function useScanSSE(
  scanId: string,
  handlers: ScanSSEHandlers,
  stateSetters: SSEStateSetters,
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  // Use a ref so the EventSource listeners always see the latest handlers
  // without re-creating the connection on every render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  const stateSettersRef = useRef(stateSetters);
  stateSettersRef.current = stateSetters;

  const refreshState = useCallback(() => {
    refreshFullState(scanId, stateSettersRef.current);
  }, [scanId]);

  useEffect(() => {
    const url = scanSSEUrl(scanId);
    const es = new EventSource(url);

    function handle<T>(eventType: string, handler: ((data: T) => void) | undefined) {
      es.addEventListener(eventType, ((e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data) as T;
          handler?.(data);
        } catch {
          // malformed JSON — ignore
        }
      }) as EventListener);
    }

    es.addEventListener("connected", () => {
      setConnected(true);
    });

    // Register typed event listeners
    handle<ScanStatusEvent>("scan_status", (d) => handlersRef.current.onScanStatus?.(d));
    handle<ScanVulnerabilityEvent>("scan_vulnerability", (d) => handlersRef.current.onScanVulnerability?.(d));
    handle<ScanEventPayload>("scan_event", (d) => handlersRef.current.onScanEvent?.(d));
    handle<ScanFinishEvent>("scan_finish", (d) => handlersRef.current.onScanFinish?.(d));
    handle<FpReviewStartedEvent>("fp_review_started", (d) => handlersRef.current.onFpReviewStarted?.(d));
    handle<FpReviewProgressEvent>("fp_review_progress", (d) => handlersRef.current.onFpReviewProgress?.(d));
    handle<FpReviewStageOutputEvent>("fp_review_stage_output", (d) => handlersRef.current.onFpReviewStageOutput?.(d));
    handle<FpReviewResultEvent>("fp_review_result", (d) => handlersRef.current.onFpReviewResult?.(d));
    handle<FpReviewFinishEvent>("fp_review_finish", (d) => handlersRef.current.onFpReviewFinish?.(d));
    handle<IndexStatus>("index_status", (d) => handlersRef.current.onIndexStatus?.(d));

    es.onopen = () => {
      setConnected(true);
    };

    es.onerror = () => {
      setConnected(false);
      // EventSource auto-reconnects. On reconnect (next onopen) we do a full
      // state refresh to catch events missed during the gap.
      const origOnOpen = es.onopen;
      es.onopen = (evt) => {
        setConnected(true);
        refreshState();
        es.onopen = origOnOpen;
        origOnOpen?.call(es, evt);
      };
    };

    // Fallback poll every 30s as safety net
    const fallbackTimer = setInterval(refreshState, 30_000);

    return () => {
      es.close();
      clearInterval(fallbackTimer);
      setConnected(false);
    };
  }, [scanId, refreshState]);

  return { connected };
}
