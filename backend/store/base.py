"""Abstract interface for scan data persistence.

Implementations handle serialization/deserialization internally.
To switch databases, create a new implementation class and update the
factory function in ``__init__.py`` — no changes needed in API code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.scan_metrics import VulnStat
from backend.models import (
    CandidateAuditTaskResult,
    VulnerabilityAuditSource,
    Candidate,
    FeedbackEntry,
    FpReviewJob,
    FpReviewResult,
    FpReviewStageOutput,
    HistoryPattern,
    OpenCodePoolStatus,
    OpenCodeTokenUsage,
    MiningEngineRunStatus,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanCandidate,
    ScanStatus,
    ScanSummary,
    SkillReport,
    ThreatAuditTask,
    ThreatAuditTaskResult,
    ThreatAnalysisRunStatus,
    UserInDB,
    Vulnerability,
    VulnerabilityValidation,
)


class DuplicateScanNameError(ValueError):
    """Raised when a user already owns a scan with the requested name."""


class ScanStoreBase(ABC):
    """Scan data storage abstract interface."""

    def get_scan_share(self, scan_id: str) -> dict | None:
        """Return the active share and its scan owner; exclude deleted scans."""
        raise NotImplementedError

    def get_or_create_scan_share(self, scan_id: str) -> dict | None:
        """Atomically return a stable share, or None for an unavailable scan."""
        raise NotImplementedError

    def revoke_scan_share(self, scan_id: str) -> None:
        """Revoke the current share without changing scan execution."""
        raise NotImplementedError

    # -- Scan lifecycle --

    @abstractmethod
    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        """Create or fully overwrite a scan record (metadata + status)."""

    @abstractmethod
    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        """Load a single scan's full state. Returns *None* if not found."""

    def load_scan_overview(
        self,
        scan_id: str,
    ) -> tuple[ScanStatus, ScanMeta, dict[str, int]] | None:
        """Load scan state without large detail collections plus their counts."""
        raise NotImplementedError

    @abstractmethod
    def get_scan_meta(self, scan_id: str) -> ScanMeta | None:
        """Load only a scan's metadata (no vulnerabilities/reports/events)."""

    @abstractmethod
    def update_scan_validation_target(
        self,
        scan_id: str,
        product: str,
        validation_environment: str,
    ) -> None:
        """Update the complete product/environment validation target for a scan."""

    @abstractmethod
    def update_opencode_pool_status(self, scan_id: str, status: OpenCodePoolStatus) -> None:
        """Persist the latest OpenCode model-pool status snapshot for a scan."""

    def update_mining_engine_run(
        self,
        scan_id: str,
        run: MiningEngineRunStatus,
    ) -> list[MiningEngineRunStatus]:
        """Create or replace one mining-engine lifecycle row."""
        raise NotImplementedError

    def update_threat_analysis_run(
        self,
        scan_id: str,
        run: ThreatAnalysisRunStatus,
    ) -> ThreatAnalysisRunStatus | None:
        """Replace the standalone threat-analysis lifecycle state."""
        raise NotImplementedError

    def replace_scan_stage_runs(
        self,
        scan_id: str,
        threat_analysis_run: ThreatAnalysisRunStatus | None,
        mining_engine_runs: list[MiningEngineRunStatus],
    ) -> bool:
        """Atomically replace continuation-visible process lifecycle states."""
        raise NotImplementedError

    @abstractmethod
    def upsert_scan_opencode_token_usage(
        self,
        *,
        scan_id: str,
        agent_session_id: str,
        status: OpenCodePoolStatus,
    ) -> None:
        """Replace one Agent-process snapshot of scan token usage."""

    @abstractmethod
    def get_scan_opencode_token_usage(self, scan_id: str) -> OpenCodeTokenUsage | None:
        """Return cumulative token usage for a scan."""

    def upsert_opencode_task_report(self, **kwargs) -> bool:
        """Persist one immutable terminal OpenCode task report."""
        raise NotImplementedError

    def list_opencode_task_reports(self, scan_id: str) -> list[dict]:
        """Return terminal OpenCode task reports in arrival order."""
        raise NotImplementedError

    def get_vulnerability_indexes_by_source_task(
        self,
        scan_id: str,
        task_id: str,
    ) -> list[int]:
        """Return finding indexes produced by one logical audit task."""
        raise NotImplementedError

    def link_threat_audit_task_vulnerability(
        self,
        scan_id: str,
        task_id: str,
        vulnerability_idx: int,
    ) -> bool:
        """Idempotently link one finding to an already stored threat-audit task."""
        raise NotImplementedError

    @abstractmethod
    def list_scans(self) -> list[ScanSummary]:
        """List all scans as summaries, ordered by *created_at* descending."""

    def list_scans_page(
        self,
        *,
        limit: int,
        user_id: str | None = None,
        before_created_at: str | None = None,
        before_scan_id: str | None = None,
    ) -> list[ScanSummary]:
        """Return a stable page ordered by ``(created_at, scan_id)`` descending."""
        raise NotImplementedError

    @abstractmethod
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record. Returns whether the record existed."""

    @abstractmethod
    def count_scans_for_project(self, project_id: str) -> int:
        """Return the number of scans referencing the given project_id."""

    # -- Progress updates (called frequently during a running scan) --

    @abstractmethod
    def update_scan_progress(
        self,
        scan_id: str,
        *,
        status: ScanItemStatus | None = None,
        progress: float | None = None,
        total_candidates: int | None = None,
        processed_candidates: int | None = None,
        current_candidate: Candidate | None = None,
        clear_current_candidate: bool = False,
        error_message: str | None = None,
        static_total_files: int | None = None,
        static_scanned_files: int | None = None,
        static_analysis_done: bool | None = None,
    ) -> None:
        """Incrementally update progress fields on the scans row.

        Use *clear_current_candidate=True* to set current_candidate to NULL.
        """

    @abstractmethod
    def claim_scan_for_resume(
        self,
        scan_id: str,
        *,
        processed_candidates: int,
        progress: float,
        expected_revision: int | None = None,
        agent_id: str | None = None,
        agent_session_id: str | None = None,
        claimed_revision: int | None = None,
    ) -> int | None:
        """Atomically claim a terminal scan and bind its execution identity.

        Return the new revision, or None if the state/revision changed. Recovery
        can retain its already reserved revision using ``claimed_revision``.
        """

    # -- Static-analysis candidates --

    @abstractmethod
    def replace_scan_candidates(
        self,
        scan_id: str,
        candidates: list[Candidate | ScanCandidate],
    ) -> list[ScanCandidate]:
        """Replace the final static-analysis candidate list for a scan."""

    def upsert_scan_candidates_batch(
        self,
        scan_id: str,
        *,
        offset: int,
        candidates: list[Candidate],
        reset: bool,
        final: bool,
        total: int | None,
    ) -> list[ScanCandidate]:
        raise NotImplementedError

    @abstractmethod
    def list_scan_candidates(self, scan_id: str) -> list[ScanCandidate]:
        """Return persisted static-analysis candidates for a scan, ordered by index."""

    def list_scan_candidates_page(
        self,
        scan_id: str,
        *,
        after_index: int,
        limit: int,
    ) -> list[ScanCandidate]:
        raise NotImplementedError

    def update_scan_candidate_audit(
        self,
        scan_id: str,
        candidate_idx: int,
        *,
        state: str,
        result: Vulnerability | None,
        vulnerability_idx: int | None,
        dedup_decision: dict,
    ) -> ScanCandidate | None:
        """Replace the one authoritative result owned by a candidate index."""
        raise NotImplementedError

    def get_processed_candidate_indexes(self, scan_id: str) -> set[int]:
        """Return candidate indexes that have a terminal audit result."""
        raise NotImplementedError

    def count_terminal_candidate_audits(self, scan_id: str) -> int:
        raise NotImplementedError

    def reset_scan_candidate_audits(
        self,
        scan_id: str,
        candidate_indexes: list[int],
    ) -> None:
        """Clear authoritative results for an explicit candidate retry set."""
        raise NotImplementedError

    # -- Vulnerabilities --

    @abstractmethod
    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Append a vulnerability result. Returns the assigned index."""

    @abstractmethod
    def upsert_incomplete_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Replace a matching timeout/no-result vulnerability, or append a new result."""

    def add_provisional_vulnerability(
        self,
        scan_id: str,
        report_batch_id: str,
        vuln: Vulnerability,
    ) -> int:
        """Append or replay one provisional vulnerability for an engine run."""
        raise NotImplementedError

    def reconcile_provisional_vulnerabilities(
        self,
        scan_id: str,
        report_batch_ids: list[str],
        vulnerabilities: list[Vulnerability],
    ) -> list[tuple[int, Vulnerability]]:
        """Atomically replace provisional batches with authoritative results."""
        raise NotImplementedError

    def promote_provisional_vulnerabilities(self, scan_id: str) -> int:
        """Make interrupted provisional results durable partial results."""
        raise NotImplementedError

    def promote_provisional_vulnerability_indexes(self, scan_id: str) -> list[int]:
        """Promote provisional results and return their stable indexes."""
        raise NotImplementedError

    def list_provisional_scan_ids_for_agent(self, agent_key: str) -> list[str]:
        """Return scans owned by one stable Agent that retain provisional results."""
        raise NotImplementedError

    @abstractmethod
    def update_vulnerability(
        self,
        scan_id: str,
        index: int,
        verdict: str,
        reason: str,
        ticket_submitted: bool = False,
        ticket_id: str = "",
    ) -> None:
        """Update user verdict on a vulnerability."""

    @abstractmethod
    def clear_vulnerability_user_verdict(self, scan_id: str, index: int) -> list[str]:
        """Clear user verdict and delete same-source feedback. Returns removed feedback IDs."""

    @abstractmethod
    def get_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        """Return all vulnerabilities for a scan, ordered by index."""

    def get_vulnerabilities_page(
        self,
        scan_id: str,
        *,
        after_index: int,
        limit: int,
    ) -> list[tuple[int, Vulnerability]]:
        raise NotImplementedError

    @abstractmethod
    def upsert_vulnerability_validation(
        self,
        scan_id: str,
        validation: VulnerabilityValidation,
    ) -> VulnerabilityValidation:
        """Create or update validation status for one vulnerability."""

    @abstractmethod
    def list_vulnerability_validations(self, scan_id: str) -> list[VulnerabilityValidation]:
        """Return validation statuses for a scan, ordered by vulnerability index."""

    def get_vulnerability_validation_states(
        self,
        scan_id: str,
    ) -> dict[int, tuple[str, bool]]:
        """Return lightweight validation status/running values keyed by vulnerability index."""
        raise NotImplementedError

    @abstractmethod
    def get_vuln_stats_by_scans(self, scan_ids: list[str]) -> dict[str, list[VulnStat]]:
        """Return lightweight per-vulnerability stats grouped by scan, ordered by index."""

    # -- Skill reports --

    @abstractmethod
    def replace_skill_reports(self, scan_id: str, checker_name: str, reports: list[SkillReport]) -> None:
        """Replace Markdown reports for one checker in one scan."""

    @abstractmethod
    def list_skill_reports(self, scan_id: str, checker_name: str | None = None) -> list[SkillReport]:
        """Return Markdown reports for a scan, optionally filtered by checker."""

    # -- Threat analysis --

    @abstractmethod
    def replace_threat_analysis(self, scan_id: str, analysis: dict) -> dict:
        """Replace the opaque threat-analysis artifact bundle for a scan."""

    @abstractmethod
    def get_threat_analysis(self, scan_id: str) -> dict | None:
        """Return the opaque threat-analysis artifact bundle if present."""

    @abstractmethod
    def upsert_threat_audit_task(self, scan_id: str, task: ThreatAuditTask) -> ThreatAuditTask:
        """Create or update one threat-analysis-derived audit task."""

    @abstractmethod
    def list_threat_audit_tasks(self, scan_id: str) -> list[ThreatAuditTask]:
        """Return threat-analysis-derived audit tasks for a scan."""

    def get_threat_audit_task_results(
        self, scan_id: str, task_ids: list[str],
    ) -> list[ThreatAuditTaskResult]:
        """Read linked findings and effective conclusions for a bounded task batch."""
        raise NotImplementedError

    def get_candidate_audit_results(
        self, scan_id: str, candidate_indexes: list[int],
    ) -> list[CandidateAuditTaskResult]:
        """Read final issue summaries for a bounded candidate batch."""
        raise NotImplementedError

    def get_vulnerability_audit_source(
        self, scan_id: str, vuln_index: int,
    ) -> VulnerabilityAuditSource:
        """Read one finding's uniquely linked audit task, if it still exists."""
        raise NotImplementedError

    @abstractmethod
    def get_incomplete_threat_audit_counts(self, scan_ids: list[str]) -> dict[str, int]:
        """Return non-terminal threat-audit task counts grouped by scan."""

    # -- Events --

    @abstractmethod
    def add_event(self, scan_id: str, event: ScanEvent) -> bool:
        """Append a scan event when its parent scan still exists."""

    def add_events_batch(self, scan_id: str, events: list[ScanEvent]) -> int:
        """Append scan events and return the number actually persisted."""
        raise NotImplementedError

    @abstractmethod
    def get_events(self, scan_id: str) -> list[ScanEvent]:
        """Return all events for a scan, ordered chronologically."""

    def get_events_page(
        self,
        scan_id: str,
        *,
        before_id: int | None,
        limit: int,
    ) -> list[tuple[int, ScanEvent]]:
        """Return newest events first so callers can page backward by id."""
        raise NotImplementedError

    # -- Processed keys (for resume) --

    @abstractmethod
    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        """Record a processed candidate key ``(file, line, function, vuln_type)``."""

    def add_processed_keys_batch(
        self,
        scan_id: str,
        keys: list[tuple[str, int, str, str]],
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        """Return the set of already-processed candidate keys."""

    def count_processed_keys(self, scan_id: str) -> int:
        raise NotImplementedError

    @abstractmethod
    def remove_processed_keys(
        self, scan_id: str, keys: list[tuple[str, int, str, str]]
    ) -> None:
        """Remove processed candidate keys so a retry can process them again."""

    # -- Feedback entries --

    @abstractmethod
    def add_feedback(self, entry: FeedbackEntry) -> None:
        """Create a new feedback entry."""

    @abstractmethod
    def upsert_feedback_for_report(self, entry: FeedbackEntry) -> FeedbackEntry:
        """Create or replace feedback for the same source vulnerability report."""

    @abstractmethod
    def update_feedback(
        self,
        feedback_id: str,
        verdict: str | None,
        reason: str | None,
        ticket_submitted: bool | None = None,
        ticket_id: str | None = None,
    ) -> bool:
        """Update mutable feedback fields. Returns False if not found."""

    @abstractmethod
    def delete_feedback(self, feedback_id: str) -> bool:
        """Delete a feedback entry. Returns False if not found."""

    @abstractmethod
    def list_feedback(self, vuln_type: str | None = None, project_id: str | None = None) -> list[FeedbackEntry]:
        """List feedback entries, optionally filtered by vuln_type and/or project_id."""

    @abstractmethod
    def get_feedback_by_ids(self, ids: list[str]) -> list[FeedbackEntry]:
        """Return feedback entries matching the given IDs."""

    @abstractmethod
    def list_feedback_by_scan(self, scan_id: str) -> list[FeedbackEntry]:
        """Return feedback entries created from a specific scan."""

    # -- Bulk status update (crash recovery) --

    @abstractmethod
    def mark_running_as_error(self) -> int:
        """Mark non-agent scans with running status as *error*.

        Agent-owned scans may still be running locally while the server restarts,
        so they are recovered through the agent reconnect handshake instead.
        Returns the number of scans affected.
        """

    def begin_scan_execution(
        self,
        scan_id: str,
        *,
        agent_id: str,
        agent_session_id: str,
    ) -> int:
        """Bind a new Agent-process execution and return its monotonic revision."""
        raise NotImplementedError

    def begin_fp_review_execution(
        self,
        review_id: str,
        *,
        agent_session_id: str,
    ) -> int:
        raise NotImplementedError

    def acquire_fp_review_execution(
        self,
        review_id: str,
        *,
        agent_session_id: str,
        force_new: bool = False,
    ) -> int:
        """Bind an FP-review execution, reusing the active process revision.

        Repeated automatic dispatches to the same Agent process must share one
        revision.  Explicit reruns can request a fresh revision via
        ``force_new``.
        """
        raise NotImplementedError

    def begin_validation_execution(
        self,
        scan_id: str,
        vuln_index: int,
        *,
        agent_session_id: str,
    ) -> int:
        raise NotImplementedError

    def list_agent_inflight_executions(
        self,
        agent_key: str,
        agent_id: str,
    ) -> dict[str, list[dict]]:
        """Return bounded identities for non-terminal Agent-owned work."""
        raise NotImplementedError

    def adopt_active_execution(
        self,
        kind: str,
        work_id: str,
        sub_id: int | None,
        *,
        previous_session_id: str,
        agent_session_id: str,
        execution_revision: int | None = None,
    ) -> bool:
        """Rebind an Agent-reported active execution without changing revision."""
        raise NotImplementedError

    def fail_scan_execution(
        self, scan_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        """Fail only the matching pending execution without replacing results."""
        raise NotImplementedError

    def claim_scan_for_agent_recovery(
        self,
        scan_id: str,
        *,
        previous_session_id: str,
        agent_id: str,
        agent_session_id: str,
        error_message: str,
        expected_revision: int | None = None,
    ) -> int | None:
        raise NotImplementedError

    def fail_scan_recovery(
        self, scan_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        raise NotImplementedError

    def fail_fp_review_recovery(
        self, review_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        raise NotImplementedError

    def claim_fp_review_for_agent_recovery(
        self,
        review_id: str,
        *,
        previous_session_id: str,
        agent_session_id: str,
    ) -> int | None:
        raise NotImplementedError

    def claim_validation_for_agent_recovery(
        self,
        scan_id: str,
        vuln_index: int,
        *,
        previous_session_id: str,
        agent_session_id: str,
    ) -> int | None:
        raise NotImplementedError

    def execution_matches(
        self,
        kind: str,
        work_id: str,
        sub_id: int | None,
        *,
        agent_session_id: str,
        execution_revision: int,
    ) -> bool:
        """Return whether an Agent report belongs to the current execution."""
        raise NotImplementedError

    @abstractmethod
    def mark_agent_scans_cancelled(self, agent_id: str, error_message: str) -> list[str]:
        """Mark running scans owned by *agent_id* as cancelled.

        Returns the affected scan IDs.
        """

    @abstractmethod
    def mark_fp_reviews_for_agent_error(self, agent_id: str, error_message: str) -> int:
        """Mark pending/running FP review jobs for scans owned by *agent_id* as error."""

    @abstractmethod
    def mark_fp_reviews_for_scan_error(self, scan_id: str, error_message: str) -> int:
        """Mark pending/running FP review jobs for a scan as error."""

    @abstractmethod
    def list_fp_review_states_by_scans(
        self,
        scan_ids: list[str],
    ) -> dict[str, list[tuple[str, str]]]:
        """Return FP-review ``(review_id, status)`` rows grouped by scan."""

    @abstractmethod
    def cancel_active_fp_reviews_for_scan(
        self,
        scan_id: str,
        error_message: str,
    ) -> list[str]:
        """Cancel every pending/running FP review and return its review IDs."""

    # -- FP Review jobs --

    @abstractmethod
    def create_fp_review_job(
        self,
        review_id: str,
        scan_id: str,
        total: int,
        created_at: str,
        method: str = "adversarial",
    ) -> None:
        """Create a new FP review job record."""

    @abstractmethod
    def get_fp_review_job(self, review_id: str) -> FpReviewJob | None:
        """Return the FP review job, including its results. None if not found."""

    @abstractmethod
    def get_fp_review_by_scan(self, scan_id: str) -> FpReviewJob | None:
        """Return the latest FP review job for a scan (most recently created)."""

    @abstractmethod
    def list_fp_review_results_by_scan(self, scan_id: str) -> list[FpReviewResult]:
        """Return all FP review results for a scan, oldest first."""

    @abstractmethod
    def list_fp_review_verdicts_by_scans(self, scan_ids: list[str]) -> dict[str, list[FpReviewResult]]:
        """Return FP review results grouped by scan, oldest first, without heavy report fields."""

    @abstractmethod
    def upsert_fp_review_stage_output(
        self,
        review_id: str,
        vuln_index: int,
        stage: str,
        markdown: str,
        timestamp: str,
        output_source=None,
    ) -> None:
        """Create or replace one FP review stage Markdown output."""

    @abstractmethod
    def list_fp_review_stage_outputs_by_review(self, review_id: str) -> list[FpReviewStageOutput]:
        """Return all stage outputs for an FP review job."""

    @abstractmethod
    def update_fp_review_job(
        self,
        review_id: str,
        *,
        status: str | None = None,
        total: int | None = None,
        processed: int | None = None,
        current_vuln_index: int | None = None,
        current_vuln_indices: list[int] | None = None,
        clear_current_vuln_index: bool = False,
        error_message: str | None = None,
    ) -> None:
        """Update status/progress on an FP review job."""

    @abstractmethod
    def add_fp_review_result(self, review_id: str, result: FpReviewResult) -> None:
        """Append a single vulnerability FP review result to a job."""

    # -- Git history patterns --

    @abstractmethod
    def replace_git_history_patterns(self, scan_id: str, patterns: list[HistoryPattern]) -> None:
        """Replace the mined git-history security patterns for a scan."""

    @abstractmethod
    def get_git_history_patterns(self, scan_id: str) -> list[HistoryPattern]:
        """Return the mined git-history security patterns for a scan, in order."""

    # -- Users --

    @abstractmethod
    def create_user(
        self, user_id: str, username: str, password_hash: str, role: str, agent_token: str
    ) -> None:
        """Create a new user."""

    @abstractmethod
    def get_user_by_id(self, user_id: str) -> UserInDB | None:
        """Return a user by ID, or None."""

    @abstractmethod
    def get_user_by_username(self, username: str) -> UserInDB | None:
        """Return a user by username, or None."""

    @abstractmethod
    def get_user_by_agent_token(self, agent_token: str) -> UserInDB | None:
        """Return a user by agent_token, or None."""

    @abstractmethod
    def list_users(self) -> list[UserInDB]:
        """Return all users."""

    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """Delete a user. Returns False if not found."""

    @abstractmethod
    def update_user_password(self, user_id: str, password_hash: str) -> bool:
        """Update a user's password hash. Returns False if not found."""

    @abstractmethod
    def count_users(self) -> int:
        """Return the total number of users."""

    # -- Announcements --

    def list_announcements(
        self,
        *,
        published_only: bool = False,
        limit: int | None = None,
    ):
        raise NotImplementedError

    def get_announcement(self, announcement_id: str):
        raise NotImplementedError

    def create_announcement(self, announcement) -> None:
        raise NotImplementedError

    def update_announcement(self, announcement) -> bool:
        raise NotImplementedError

    def delete_announcement(self, announcement_id: str) -> bool:
        raise NotImplementedError

    # -- Scans filtered by user --

    @abstractmethod
    def list_scans_by_user(self, user_id: str) -> list[ScanSummary]:
        """List scans owned by a specific user."""

    # -- Persistent Agent catalog/config --

    def find_agent_record(self, user_id: str, ip: str, machine_name: str) -> dict | None:
        raise NotImplementedError

    def get_agent_record(self, agent_key: str) -> dict | None:
        raise NotImplementedError

    def list_agent_records(self, user_id: str | None = None) -> list[dict]:
        raise NotImplementedError

    def upsert_agent_record(self, **kwargs) -> dict:
        raise NotImplementedError

    def update_agent_config_record(self, agent_key: str, config_json: str) -> bool:
        raise NotImplementedError

    def update_agent_catalog_record(self, agent_key: str, catalog_json: str) -> bool:
        raise NotImplementedError

    def update_agent_mcp_probe_record(self, agent_key: str, mcp_probe_json: str) -> bool:
        raise NotImplementedError

    def touch_agent_record(self, agent_key: str, agent_id: str, last_seen: str) -> bool:
        raise NotImplementedError

    def set_agent_runtime_update_record(
        self,
        agent_key: str,
        *,
        status: str,
        target_hash: str = "",
        server_url: str = "",
        requested_at: str = "",
        started_at: str = "",
        error: str = "",
    ) -> bool:
        raise NotImplementedError

    # -- User + client scoped scan-form memory --

    def get_scan_config_memory(self, user_id: str, agent_key: str) -> dict | None:
        raise NotImplementedError

    def upsert_scan_config_memory(
        self,
        user_id: str,
        agent_key: str,
        config: dict,
    ) -> None:
        raise NotImplementedError

    # -- Cleanup --

    @abstractmethod
    def close(self) -> None:
        """Release resources (database connections, etc.)."""
