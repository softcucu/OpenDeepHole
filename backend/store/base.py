"""Abstract interface for scan data persistence.

Implementations handle serialization/deserialization internally.
To switch databases, create a new implementation class and update the
factory function in ``__init__.py`` — no changes needed in API code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.scan_metrics import VulnStat
from backend.models import (
    Candidate,
    FeedbackEntry,
    FpReviewJob,
    FpReviewResult,
    FpReviewStageOutput,
    HistoryPattern,
    OpenCodePoolStatus,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanCandidate,
    ScanStatus,
    ScanSummary,
    SkillReport,
    ThreatAnalysis,
    UserInDB,
    Vulnerability,
    VulnerabilityValidation,
)


class ScanStoreBase(ABC):
    """Scan data storage abstract interface."""

    # -- Scan lifecycle --

    @abstractmethod
    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        """Create or fully overwrite a scan record (metadata + status)."""

    @abstractmethod
    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        """Load a single scan's full state. Returns *None* if not found."""

    @abstractmethod
    def get_scan_meta(self, scan_id: str) -> ScanMeta | None:
        """Load only a scan's metadata (no vulnerabilities/reports/events)."""

    @abstractmethod
    def update_scan_product(self, scan_id: str, product: str) -> None:
        """Update the product associated with a scan."""

    @abstractmethod
    def update_opencode_pool_status(self, scan_id: str, status: OpenCodePoolStatus) -> None:
        """Persist the latest OpenCode model-pool status snapshot for a scan."""

    @abstractmethod
    def list_scans(self) -> list[ScanSummary]:
        """List all scans as summaries, ordered by *created_at* descending."""

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

    # -- Static-analysis candidates --

    @abstractmethod
    def replace_scan_candidates(
        self,
        scan_id: str,
        candidates: list[Candidate | ScanCandidate],
    ) -> list[ScanCandidate]:
        """Replace the final static-analysis candidate list for a scan."""

    @abstractmethod
    def list_scan_candidates(self, scan_id: str) -> list[ScanCandidate]:
        """Return persisted static-analysis candidates for a scan, ordered by index."""

    # -- Vulnerabilities --

    @abstractmethod
    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Append a vulnerability result. Returns the assigned index."""

    @abstractmethod
    def upsert_incomplete_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Replace a matching timeout/no-result vulnerability, or append a new result."""

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
    def replace_threat_analysis(self, scan_id: str, analysis: ThreatAnalysis) -> ThreatAnalysis:
        """Replace the attack-tree threat analysis result for a scan."""

    @abstractmethod
    def get_threat_analysis(self, scan_id: str) -> ThreatAnalysis | None:
        """Return the attack-tree threat analysis result for a scan if present."""

    # -- Events --

    @abstractmethod
    def add_event(self, scan_id: str, event: ScanEvent) -> None:
        """Append a scan event."""

    @abstractmethod
    def get_events(self, scan_id: str) -> list[ScanEvent]:
        """Return all events for a scan, ordered chronologically."""

    # -- Processed keys (for resume) --

    @abstractmethod
    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        """Record a processed candidate key ``(file, line, function, vuln_type)``."""

    @abstractmethod
    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        """Return the set of already-processed candidate keys."""

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

    # -- FP Review jobs --

    @abstractmethod
    def create_fp_review_job(self, review_id: str, scan_id: str, total: int, created_at: str) -> None:
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
        processed: int | None = None,
        current_vuln_index: int | None = None,
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

    # -- Scans filtered by user --

    @abstractmethod
    def list_scans_by_user(self, user_id: str) -> list[ScanSummary]:
        """List scans owned by a specific user."""

    # -- Cleanup --

    @abstractmethod
    def close(self) -> None:
        """Release resources (database connections, etc.)."""
