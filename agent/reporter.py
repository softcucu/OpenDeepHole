"""HTTP client for pushing scan progress and results to the web server."""

from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4
from typing import Optional

import httpx

from backend.models import (
    Candidate,
    FeedbackEntry,
    HistoryPattern,
    OutputSource,
    ScanEvent,
    ThreatAnalysis,
    ThreatAuditTask,
    Vulnerability,
    VulnerabilityValidation,
)


OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS = 15.0


def _snapshot_signature(snapshot: dict) -> str:
    """Return a stable signature for deciding whether a pool snapshot changed."""
    return json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Reporter:
    """Sends scan events and final results to the web server via HTTP."""

    def __init__(self, server_url: str, dry_run: bool = False) -> None:
        self.server_url = server_url.rstrip("/")
        self.dry_run = dry_run
        self.agent_id = ""
        self.agent_name = ""
        self.agent_session_id = uuid4().hex
        self._client = httpx.AsyncClient(timeout=30.0)
        self._static_progress_warning_at: dict[str, float] = {}

    def set_agent_id(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def set_agent_name(self, agent_name: str) -> None:
        self.agent_name = agent_name

    def _with_agent_source(self, source: OutputSource | None) -> OutputSource:
        next_source = source.model_copy() if source is not None else OutputSource()
        if self.agent_id and not next_source.agent_id:
            next_source.agent_id = self.agent_id
        if self.agent_name and not next_source.agent_name:
            next_source.agent_name = self.agent_name
        if self.agent_session_id and not next_source.agent_session_id:
            next_source.agent_session_id = self.agent_session_id
        return next_source

    # ---------------------------------------------------------------------------
    # Config fetch (used before each scan to get latest server-managed settings)
    # ---------------------------------------------------------------------------

    async def fetch_config(self, agent_id: str) -> dict | None:
        """Fetch the latest server-managed config for this agent."""
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/{agent_id}/config",
                timeout=5.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    # ---------------------------------------------------------------------------
    # Scan events / results
    # ---------------------------------------------------------------------------

    async def report_candidates(self, scan_id: str, candidates: list[Candidate]) -> None:
        """Push the final static-analysis candidate list for the scan."""
        if self.dry_run:
            print(f"  [CANDIDATES] {len(candidates)} static candidate(s)")
            return
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/candidates",
                json={"candidates": [candidate.model_dump() for candidate in candidates]},
                timeout=30.0,
            )
            resp.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to upload static candidates: {e}")

    async def report_vulnerability(self, scan_id: str, vuln: Vulnerability) -> dict | None:
        """Push a single vulnerability result immediately after it is audited."""
        if self.dry_run:
            marker = "[VULN]" if vuln.confirmed else "[  FP]"
            print(f"  {marker} {vuln.vuln_type.upper()} {vuln.file}:{vuln.line} ({vuln.function})")
            return None
        vuln.output_source = self._with_agent_source(vuln.output_source)
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                json=vuln.model_dump(),
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"Warning: failed to upload vulnerability result: {e}")
            return None

    async def report_vulnerability_validation(
        self,
        scan_id: str,
        validation: VulnerabilityValidation,
    ) -> None:
        """Push local validation script progress/results."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/validation",
                json=validation.model_dump(exclude={"scan_id"}),
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload vulnerability validation: {e}")

    async def replace_skill_reports(self, scan_id: str, checker_name: str, reports: list[dict]) -> None:
        """Replace Markdown reports generated by one report-mode SKILL."""
        if self.dry_run:
            print(f"  [REPORT] {checker_name}: {len(reports)} markdown report(s)")
            return
        try:
            payload_reports = []
            for report in reports:
                item = dict(report)
                raw_source = item.get("output_source")
                source = raw_source if isinstance(raw_source, OutputSource) else OutputSource(**raw_source) if isinstance(raw_source, dict) else OutputSource()
                item["output_source"] = self._with_agent_source(source).model_dump()
                payload_reports.append(item)
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/skill-report",
                json={"checker_name": checker_name, "reports": payload_reports},
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload skill reports: {e}")

    async def push_threat_analysis(self, scan_id: str, analysis: dict) -> None:
        """Upload attack-tree threat-analysis JSON generated by the local agent."""
        if self.dry_run:
            assets = analysis.get("assets") if isinstance(analysis, dict) else []
            print(f"  [THREAT] {len(assets) if isinstance(assets, list) else 0} asset(s)")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-analysis",
                json=analysis,
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload threat analysis: {e}")

    async def get_threat_analysis(self, scan_id: str) -> ThreatAnalysis | None:
        """Fetch an already stored threat-analysis result for scan resume."""
        if self.dry_run:
            return None
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-analysis",
                timeout=10.0,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return ThreatAnalysis(**resp.json())
        except Exception:
            return None

    async def push_threat_audit_task(self, scan_id: str, task: ThreatAuditTask) -> ThreatAuditTask | None:
        """Create or update one threat-analysis-derived audit task."""
        if self.dry_run:
            print(f"  [THREAT_AUDIT] {task.status} {task.code_path} {task.method_name}")
            return task
        task.output_source = self._with_agent_source(task.output_source)
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-audit-task",
                json=task.model_dump(),
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
            payload = data.get("task") if isinstance(data, dict) else None
            if isinstance(payload, dict):
                return ThreatAuditTask(**payload)
        except Exception as e:
            print(f"Warning: failed to upload threat audit task: {e}")
        return None

    async def get_threat_audit_tasks(self, scan_id: str) -> list[ThreatAuditTask]:
        """Fetch threat-analysis-derived audit tasks for scan resume."""
        if self.dry_run:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-audit-tasks",
                timeout=10.0,
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return [ThreatAuditTask(**item) for item in data if isinstance(item, dict)]
        except Exception:
            return []
        return []

    async def send_event(self, scan_id: str, event: ScanEvent) -> None:
        """Push a progress event to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/event",
                json=event.model_dump(),
                timeout=10.0,
            )
        except Exception:
            pass

    async def finish_scan(
        self,
        scan_id: str,
        vulnerabilities: list[Vulnerability],
        status: str,
        total_candidates: int,
        processed_candidates: int,
        error_message: Optional[str] = None,
    ) -> None:
        """Push final scan results. Retries up to 3 times on failure."""
        if self.dry_run:
            confirmed = sum(1 for v in vulnerabilities if v.confirmed)
            print(f"\n--- Dry-run results: {confirmed}/{len(vulnerabilities)} confirmed ---")
            for v in vulnerabilities:
                marker = "[VULN]" if v.confirmed else "[  FP]"
                print(f"  {marker} {v.vuln_type.upper()} {v.file}:{v.line} ({v.function})")
                if v.confirmed:
                    print(f"         {v.description}")
            return

        payload = {
            "vulnerabilities": [v.model_dump() for v in vulnerabilities],
            "status": status,
            "total_candidates": total_candidates,
            "processed_candidates": processed_candidates,
            "error_message": error_message,
        }
        for attempt in range(3):
            try:
                resp = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/finish",
                    json=payload,
                    timeout=60.0,
                )
                resp.raise_for_status()
                return
            except Exception as e:
                if attempt == 2:
                    print(f"Warning: failed to deliver results to server after 3 attempts: {e}")
                    return
                await asyncio.sleep(2**attempt)

    async def send_index_status(
        self,
        scan_id: str,
        status: str,
        parsed_files: int = 0,
        total_files: int = 0,
        *,
        stage: str = "",
        stage_current: int = 0,
        stage_total: int = 0,
        stats: dict[str, int] | None = None,
    ) -> None:
        """Push code-indexing progress to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        payload = {
            "status": status,
            "parsed_files": parsed_files,
            "total_files": total_files,
        }
        if stage:
            payload.update({
                "stage": stage,
                "stage_current": stage_current,
                "stage_total": stage_total,
            })
        if stats is not None:
            payload["stats"] = stats
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/index-status",
                json=payload,
                timeout=5.0,
            )
        except Exception:
            pass

    async def send_static_progress(
        self,
        scan_id: str,
        scanned: int,
        total: int,
        done: bool = False,
    ) -> None:
        """Push static analysis progress to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/static-progress",
                json={"scanned": scanned, "total": total, "done": done},
                timeout=5.0,
            )
            resp.raise_for_status()
        except Exception as e:
            self._warn_static_progress_failure(scan_id, scanned, total, done, e)

    def _warn_static_progress_failure(
        self,
        scan_id: str,
        scanned: int,
        total: int,
        done: bool,
        error: Exception,
    ) -> None:
        status = ""
        response_text = ""
        if isinstance(error, httpx.HTTPStatusError):
            status = f" status={error.response.status_code}"
            response_text = (error.response.text or "").strip()
            if response_text:
                response_text = f" response={response_text[:200]!r}"
        key = f"{type(error).__name__}:{status}"
        now = time.monotonic()
        last = self._static_progress_warning_at.get(key, 0.0)
        if now - last < 30.0:
            return
        self._static_progress_warning_at[key] = now
        print(
            "Warning: failed to push static analysis progress "
            f"scan_id={scan_id} progress={scanned}/{total} done={done} "
            f"error_type={type(error).__name__}{status} error={error!r}{response_text}",
            flush=True,
        )

    async def report_processed_key(
        self, scan_id: str, file: str, line: int, function: str, vuln_type: str
    ) -> None:
        """Report a successfully processed candidate key (fire-and-forget)."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                json={"file": file, "line": line, "function": function, "vuln_type": vuln_type},
                timeout=5.0,
            )
        except Exception:
            pass

    async def push_opencode_pool_status(self, scan_id: str, snapshot: dict) -> bool:
        """Push the latest OpenCode model-pool status snapshot."""
        if self.dry_run:
            return True
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/opencode-pool",
                json=snapshot,
                timeout=5.0,
            )
            return True
        except Exception:
            return False

    async def publish_opencode_pool_until(
        self,
        scan_id: str,
        stop_event: asyncio.Event,
        interval_seconds: float = 1.0,
        unchanged_heartbeat_seconds: float = OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS,
    ) -> None:
        """Publish model-pool stats until *stop_event* is set.

        The model pool is polled frequently so running/queued transitions are
        reflected quickly, but identical snapshots are not posted every poll.
        """
        from backend.opencode.model_pool import model_pool_snapshot

        last_signature: str | None = None
        last_sent_at = 0.0

        async def publish_if_needed(*, force: bool = False) -> None:
            nonlocal last_signature, last_sent_at
            snapshot = model_pool_snapshot(scan_id)
            signature = _snapshot_signature(snapshot)
            now = time.monotonic()
            if (
                not force
                and signature == last_signature
                and now - last_sent_at < unchanged_heartbeat_seconds
            ):
                return
            if await self.push_opencode_pool_status(scan_id, snapshot):
                last_signature = signature
                last_sent_at = now

        try:
            while not stop_event.is_set():
                await publish_if_needed()
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                except asyncio.TimeoutError:
                    pass
        finally:
            await publish_if_needed(force=True)

    async def push_agent_opencode_pool_status(self, snapshot: dict) -> bool:
        """Push the latest Agent-wide OpenCode model-pool status snapshot."""
        if self.dry_run or not self.agent_id:
            return True
        payload = dict(snapshot)
        payload["agent_session_id"] = self.agent_session_id
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/{self.agent_id}/opencode-pool",
                json=payload,
                timeout=5.0,
            )
            return True
        except Exception:
            return False

    async def publish_agent_opencode_pool_until(
        self,
        stop_event: asyncio.Event,
        interval_seconds: float = 1.0,
        unchanged_heartbeat_seconds: float = OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS,
    ) -> None:
        """Publish Agent-wide model-pool stats until *stop_event* is set."""
        from backend.opencode.model_pool import model_pool_snapshot

        last_signature: str | None = None
        last_sent_at = 0.0

        async def publish_if_needed(*, force: bool = False) -> None:
            nonlocal last_signature, last_sent_at
            snapshot = model_pool_snapshot()
            signature = _snapshot_signature(snapshot)
            now = time.monotonic()
            if (
                not force
                and signature == last_signature
                and now - last_sent_at < unchanged_heartbeat_seconds
            ):
                return
            if await self.push_agent_opencode_pool_status(snapshot):
                last_signature = signature
                last_sent_at = now

        try:
            while not stop_event.is_set():
                await publish_if_needed()
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                except asyncio.TimeoutError:
                    pass
        finally:
            await publish_if_needed(force=True)

    async def get_processed_keys(self, scan_id: str) -> set[tuple[str, int, str, str]]:
        """Fetch already-processed candidate keys for resume (skip these on restart)."""
        if self.dry_run:
            return set()
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                timeout=10.0,
            )
            resp.raise_for_status()
            return {
                (item["file"], int(item["line"]), item["function"], item["vuln_type"])
                for item in resp.json()
            }
        except Exception:
            return set()

    async def push_git_history(self, scan_id: str, patterns: list[HistoryPattern]) -> None:
        """Upload the mined git-history security patterns for a scan."""
        if self.dry_run:
            print(f"  [git_history] {len(patterns)} pattern(s) mined")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/git_history",
                json={"patterns": [p.model_dump() for p in patterns]},
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload git history patterns: {e}")

    async def get_git_history(self, scan_id: str) -> list[HistoryPattern]:
        """Fetch the mined git-history security patterns for a scan (FP review use)."""
        if self.dry_run:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/git_history",
                timeout=10.0,
            )
            resp.raise_for_status()
            return [HistoryPattern(**item) for item in resp.json()]
        except Exception:
            return []

    async def get_feedback(self, vuln_types: list[str]) -> list[FeedbackEntry]:
        """Fetch feedback entries from the server for SKILL enrichment."""
        if self.dry_run or not vuln_types:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/feedback",
                params={"vuln_types": ",".join(vuln_types)},
                timeout=10.0,
            )
            resp.raise_for_status()
            return [FeedbackEntry(**item) for item in resp.json()]
        except Exception:
            return []

    async def push_fp_result(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        verdict: str,
        severity: str,
        reason: str,
        vulnerability_report: str = "",
        stage_outputs: dict[str, str] | None = None,
        match_reference: str = "",
        match_type: str = "",
        stage_output_sources: dict[str, OutputSource] | None = None,
        output_source: OutputSource | None = None,
    ) -> None:
        """Push a single FP review result to the server."""
        if self.dry_run:
            marker = "FP" if verdict == "fp" else "TP"
            print(f"  [fp_review] [{marker}/{severity}] vuln[{vuln_index}]: {reason[:80]}")
            return
        result_source = self._with_agent_source(output_source)
        result_stage_sources = {
            key: self._with_agent_source(value).model_dump()
            for key, value in (stage_output_sources or {}).items()
        }
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/result",
                json={
                    "review_id": review_id,
                    "vuln_index": vuln_index,
                    "verdict": verdict,
                    "severity": severity,
                    "reason": reason,
                    "vulnerability_report": vulnerability_report,
                    "stage_outputs": stage_outputs or {},
                    "match_reference": match_reference,
                    "match_type": match_type,
                    "stage_output_sources": result_stage_sources,
                    "output_source": result_source.model_dump(),
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to push FP review result: {e}")

    async def push_fp_stage_output(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        stage: str,
        markdown: str,
        output_source: OutputSource | None = None,
    ) -> None:
        """Push one FP review stage Markdown output to the server."""
        if self.dry_run:
            print(f"  [fp_review] [{stage}] vuln[{vuln_index}] markdown ready ({len(markdown)} chars)")
            return
        source = self._with_agent_source(output_source)
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/stage-output",
                json={
                    "review_id": review_id,
                    "vuln_index": vuln_index,
                    "stage": stage,
                    "markdown": markdown,
                    "output_source": source.model_dump(),
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to push FP review stage output: {e}")

    async def push_fp_progress(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        processed: int | None = None,
        active_indices: list[int] | None = None,
    ) -> None:
        """Report the vulnerability currently being reviewed."""
        if self.dry_run:
            print(f"  [fp_review] Reviewing vuln[{vuln_index}]")
            return
        try:
            payload = {
                "review_id": review_id,
                "vuln_index": vuln_index,
            }
            if processed is not None:
                payload["processed"] = processed
            if active_indices is not None:
                payload["active_indices"] = active_indices
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/progress",
                json=payload,
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to push FP review progress: {e}")

    async def finish_fp_review(
        self,
        scan_id: str,
        review_id: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Signal to the server that the FP review job is complete."""
        if self.dry_run:
            print(f"  [fp_review] Finished with status: {status}")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/finish",
                json={
                    "review_id": review_id,
                    "status": status,
                    "error_message": error_message,
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to signal FP review finish: {e}")

    async def close(self) -> None:
        await self._client.aclose()
