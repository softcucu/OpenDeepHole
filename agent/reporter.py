"""HTTP client for pushing scan progress and results to the web server."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from backend.models import FeedbackEntry, ScanEvent, Vulnerability


class Reporter:
    """Sends scan events and final results to the web server via HTTP."""

    def __init__(self, server_url: str, dry_run: bool = False) -> None:
        self.server_url = server_url.rstrip("/")
        self.dry_run = dry_run
        self._client = httpx.AsyncClient(timeout=30.0)

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

    async def report_vulnerability(self, scan_id: str, vuln: Vulnerability) -> None:
        """Push a single vulnerability result immediately after it is audited."""
        if self.dry_run:
            marker = "[VULN]" if vuln.confirmed else "[  FP]"
            print(f"  {marker} {vuln.vuln_type.upper()} {vuln.file}:{vuln.line} ({vuln.function})")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                json=vuln.model_dump(),
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload vulnerability result: {e}")

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
    ) -> None:
        """Push code-indexing progress to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/index-status",
                json={"status": status, "parsed_files": parsed_files, "total_files": total_files},
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
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/static-progress",
                json={"scanned": scanned, "total": total, "done": done},
                timeout=5.0,
            )
        except Exception:
            pass

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
    ) -> None:
        """Push a single FP review result to the server."""
        if self.dry_run:
            marker = "FP" if verdict == "fp" else "TP"
            print(f"  [fp_review] [{marker}/{severity}] vuln[{vuln_index}]: {reason[:80]}")
            return
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
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to push FP review result: {e}")

    async def push_fp_progress(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        processed: int | None = None,
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
