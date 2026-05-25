"""Pydantic models for API requests, responses, and internal data."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel


class ScanItemStatus(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"   # static analysis running
    AUDITING = "auditing"     # opencode AI analysis running
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


# --- User / Auth models ---

class User(BaseModel):
    user_id: str
    username: str
    role: str  # "admin" | "user"
    agent_token: str = ""
    created_at: str = ""


class UserInDB(User):
    password_hash: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user: User


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class RegisterRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# --- Internal models ---

class Candidate(BaseModel):
    """A candidate vulnerability location found by static analysis."""
    file: str
    line: int
    function: str
    description: str
    vuln_type: str
    related_functions: list[str] = []


class Vulnerability(BaseModel):
    """A confirmed or assessed vulnerability after AI analysis."""
    file: str
    line: int
    function: str
    vuln_type: str
    severity: str        # "high", "medium", "low"
    description: str
    ai_analysis: str
    confirmed: bool
    ai_verdict: str = ""                     # "confirmed" | "not_confirmed" | "timeout" | "no_result"
    user_verdict: str | None = None          # "confirmed" | "false_positive" | None
    user_verdict_reason: str | None = None   # 用户填写的理由
    ticket_submitted: bool = False           # 是否已提问题单
    ticket_id: str = ""                      # 问题单号
    function_source: str = ""
    function_start_line: int | None = None


# --- API request/response models ---

class CheckerInfo(BaseModel):
    """Info about an available checker, returned by GET /api/checkers."""
    name: str
    label: str
    description: str
    visibility: str = "public"


class CheckerCatalogItem(BaseModel):
    """Detailed checker/SKILL introduction for the checker catalog page."""
    name: str
    label: str
    description: str
    enabled: bool = True
    visibility: str = "public"
    introduction: str = ""
    introduction_source: str = ""


class UploadResponse(BaseModel):
    project_id: str


class ScanRequest(BaseModel):
    project_id: str
    scan_items: list[str]
    feedback_ids: list[str] = []


class ScanStartResponse(BaseModel):
    scan_id: str


class ScanEvent(BaseModel):
    """A timestamped event during the scan process."""
    timestamp: str
    phase: str            # "init", "mcp_ready", "static_analysis", "auditing", "complete", "error"
    message: str
    candidate_index: int | None = None

    @staticmethod
    def create(phase: str, message: str, candidate_index: int | None = None) -> "ScanEvent":
        return ScanEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            message=message,
            candidate_index=candidate_index,
        )


class MarkRequest(BaseModel):
    """Request to mark a vulnerability as confirmed or false positive."""
    index: int
    verdict: str        # "confirmed" | "false_positive"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkItem(BaseModel):
    """Single item in a batch mark request."""
    index: int
    verdict: str        # "confirmed" | "false_positive"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkRequest(BaseModel):
    """Request to batch-mark multiple vulnerabilities."""
    items: list[BatchMarkItem]

class SaveFalsePositiveRequest(BaseModel):
    """Request to save a false positive experience to the project SKILL."""
    index: int


# --- Feedback models ---

class FeedbackEntry(BaseModel):
    """A user feedback entry stored in the experience database."""
    id: str
    project_id: str
    vuln_type: str
    verdict: str          # "confirmed" | "false_positive"
    file: str
    line: int
    function: str
    description: str
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""
    function_source: str = ""
    function_start_line: int | None = None
    source_scan_id: str | None = None
    created_at: str
    updated_at: str


class FeedbackCreateRequest(BaseModel):
    """Request to create a new feedback entry."""
    project_id: str
    vuln_type: str
    verdict: str          # "confirmed" | "false_positive"
    file: str
    line: int
    function: str
    description: str
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""
    function_source: str = ""
    function_start_line: int | None = None
    source_scan_id: str | None = None


class FeedbackUpdateRequest(BaseModel):
    """Request to update an existing feedback entry."""
    verdict: str | None = None
    reason: str | None = None
    ticket_submitted: bool | None = None
    ticket_id: str | None = None


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    scan_items: list[str] = []
    created_at: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    vulnerabilities: list[Vulnerability]
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
    feedback_ids: list[str] = []

    # 静态分析进度（按文件计）
    static_total_files: int = 0
    static_scanned_files: int = 0
    static_analysis_done: bool = False

    # Agent 信息
    agent_name: str = ""
    agent_online: bool = False


# --- Agent API models ---

class AgentScanRegister(BaseModel):
    """Sent by the agent to register a new scan and receive a scan_id."""
    project_name: str
    scan_items: list[str]
    agent_version: str = ""


class AgentScanFinish(BaseModel):
    """Sent by the agent when the scan completes (success or error)."""
    vulnerabilities: list[Vulnerability]
    status: str                    # "complete" | "error"
    total_candidates: int
    processed_candidates: int
    error_message: str | None = None


class AgentInfo(BaseModel):
    """Info about a registered agent."""
    agent_id: str
    name: str
    ip: str
    port: int = 0
    last_seen: str
    user_id: str = ""


class AgentLLMApiConfig(BaseModel):
    base_url: str = "https://api.anthropic.com"
    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.1
    timeout: int = 300
    max_retries: int = 3
    stream: bool = False


class AgentOpenCodeConfig(BaseModel):
    tool: str = "opencode"
    executable: str = "opencode"
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2


class AgentRemoteConfig(BaseModel):
    """Agent configuration managed from the server Web UI."""
    no_proxy: str = "10.0.0.0/8"
    llm_api: AgentLLMApiConfig = AgentLLMApiConfig()
    opencode: AgentOpenCodeConfig = AgentOpenCodeConfig()
    fp_review_cli: AgentOpenCodeConfig | None = None


class CreateScanRequest(BaseModel):
    """Request to create a new scan via a registered agent."""
    agent_id: str
    project_path: str
    code_scan_path: str = ""
    scan_name: str = ""
    checkers: list[str]
    feedback_ids: list[str] = []


class ScanMeta(BaseModel):
    """扫描元数据，记录扫描配置信息。"""
    scan_items: list[str]
    created_at: str
    feedback_ids: list[str] = []
    agent_id: str = ""
    agent_name: str = ""
    project_path: str = ""
    code_scan_path: str = ""
    scan_name: str = ""
    user_id: str = ""


class ScanSummary(BaseModel):
    """扫描列表的摘要信息。"""
    scan_id: str
    project_id: str
    scan_name: str = ""
    status: ScanItemStatus
    created_at: str
    progress: float
    total_candidates: int
    processed_candidates: int
    vulnerability_count: int
    human_confirmed_count: int = 0
    scan_items: list[str]
    user_id: str = ""
    username: str = ""
    agent_name: str = ""
    agent_online: bool = False


# --- Admin dashboard models ---

class CheckerScanDashboardStats(BaseModel):
    """Per-checker stats for one scan shown in the admin checker dashboard."""
    scan_id: str
    project_id: str
    scan_name: str = ""
    project_path: str = ""
    status: ScanItemStatus
    created_at: str
    username: str = ""
    agent_name: str = ""
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None


class CheckerDashboardStats(BaseModel):
    """Aggregated stats for a checker/SKILL."""
    checker: str
    label: str
    description: str = ""
    scan_count: int = 0
    project_count: int = 0
    projects: list[str] = []
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None
    scans: list[CheckerScanDashboardStats] = []


class CheckerDashboardSummary(BaseModel):
    """Top-level summary for the admin checker dashboard."""
    checker_count: int = 0
    scan_count: int = 0
    project_count: int = 0
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    total_issue_count: int = 0
    human_confirmed_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None


class CheckerDashboardResponse(BaseModel):
    """Admin checker dashboard response."""
    summary: CheckerDashboardSummary
    checkers: list[CheckerDashboardStats]


# --- FP Review models ---

class FpReviewStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"


class FpReviewResult(BaseModel):
    """Per-vulnerability false-positive review result."""
    vuln_index: int           # index in the parent scan's vulnerability list
    verdict: str              # "tp" (true positive) | "fp" (false positive)
    severity: str = "low"     # "high" | "medium" | "low"
    reason: str               # AI reasoning
    vulnerability_report: str = ""  # Markdown report for externally triggerable issues
    created_at: str


class FpReviewJob(BaseModel):
    """A false-positive review job for a scan."""
    review_id: str
    scan_id: str
    status: FpReviewStatus
    created_at: str
    total: int = 0
    processed: int = 0
    current_vuln_index: int | None = None
    results: list[FpReviewResult] = []
    error_message: str | None = None


class FpReviewTriggerRequest(BaseModel):
    """Request body for POST /api/scan/{scan_id}/fp_review."""
    pass  # no extra fields needed for now


class AgentFpReviewResult(BaseModel):
    """Sent by the agent to push a single FP review result."""
    review_id: str
    vuln_index: int
    verdict: str       # "tp" | "fp"
    severity: str = "low"
    reason: str
    vulnerability_report: str = ""


class AgentFpReviewProgress(BaseModel):
    """Sent by the agent when it starts reviewing a vulnerability."""
    review_id: str
    vuln_index: int


class AgentFpReviewFinish(BaseModel):
    """Sent by the agent when the FP review job is complete."""
    review_id: str
    status: str        # "complete" | "error"
    error_message: str | None = None
