"""Pydantic models for API requests, responses, and internal data."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


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
    metadata: dict = Field(default_factory=dict)


class ScanCandidate(Candidate):
    """A persisted static-analysis candidate for one scan."""
    idx: int


class OutputSource(BaseModel):
    """Metadata describing which runtime produced an AI-visible output."""
    agent_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    backend: str = ""              # "cli" | "api" | "system"
    tool: str = ""
    model_id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    required_capability: str = ""
    task_id: str = ""
    attempt: int = 0
    started_at: str = ""


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
    ai_verdict: str = ""                     # "confirmed" | "not_confirmed" | "timeout" | "no_result" | "failed" | "filtered_same_pattern"
    failure_reason: str = ""                 # OpenCode/runner output for retryable failures
    user_verdict: str | None = None          # "confirmed" | "false_positive" | "pending_analysis" | None
    user_verdict_reason: str | None = None   # 用户填写的理由
    ticket_submitted: bool = False           # 是否已提问题单
    ticket_id: str = ""                      # 问题单号
    function_source: str = ""
    function_start_line: int | None = None
    variant_of: str = ""                     # 同类变体排查命中时，来源历史问题模式（根因摘要+出处提交/文件）
    output_source: OutputSource = Field(default_factory=OutputSource)


# --- API request/response models ---

class CheckerInfo(BaseModel):
    """Info about an available checker, returned by GET /api/checkers."""
    name: str
    label: str
    description: str
    visibility: str = "public"
    category: str = "illegal_memory_use"
    category_label: str = "非法内存使用"
    modified_at: str = ""
    user_created: bool = False
    created_by_user_id: str = ""
    creator_username: str = ""
    can_delete: bool = False
    result_mode: str = "vulnerabilities"
    timeout_seconds: int | None = None
    model_capability: str = "any"


class CheckerCatalogItem(BaseModel):
    """Detailed checker/SKILL introduction for the checker catalog page."""
    name: str
    label: str
    description: str
    enabled: bool = True
    visibility: str = "public"
    category: str = "illegal_memory_use"
    category_label: str = "非法内存使用"
    modified_at: str = ""
    introduction: str = ""
    introduction_source: str = ""
    user_created: bool = False
    created_by_user_id: str = ""
    creator_username: str = ""
    can_delete: bool = False
    result_mode: str = "vulnerabilities"
    timeout_seconds: int | None = None
    model_capability: str = "any"


class SkillDraft(BaseModel):
    skill_md: str = ""
    scenarios_md: str = ""
    summary: str = ""


class SkillCreateRequest(BaseModel):
    agent_id: str = ""
    skill_id: str
    name: str
    description: str
    input: str
    timeout_seconds: int = 1200


class SkillCreateJob(BaseModel):
    job_id: str
    status: str
    skill_id: str = ""
    name: str
    description: str
    input: str = ""
    agent_id: str = ""
    agent_name: str = ""
    user_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    error_message: str = ""
    draft: SkillDraft | None = None


class SkillImportFile(BaseModel):
    path: str
    content_b64: str


class SkillImportRequest(BaseModel):
    skill_md: str
    scenarios_md: str = ""
    timeout_seconds: int = 1200
    files: list[SkillImportFile] = []


class SkillImportResponse(BaseModel):
    ok: bool = True
    name: str


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
    """Request to mark a vulnerability with manual triage feedback."""
    index: int
    verdict: str        # "confirmed" | "false_positive" | "pending_analysis"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkItem(BaseModel):
    """Single item in a batch mark request."""
    index: int
    verdict: str        # "confirmed" | "false_positive" | "pending_analysis"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkRequest(BaseModel):
    """Request to batch-mark multiple vulnerabilities."""
    items: list[BatchMarkItem]

class UnmarkRequest(BaseModel):
    """Request to clear a vulnerability's manual verdict."""
    index: int

class BatchUnmarkRequest(BaseModel):
    """Request to clear manual verdicts for multiple vulnerabilities."""
    indices: list[int]

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


class SkillReport(BaseModel):
    id: int | None = None
    scan_id: str = ""
    checker_name: str
    filename: str
    title: str = ""
    content: str
    created_at: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)


class ThreatAnalysisSources(BaseModel):
    """Input sources actually used by the attack-tree threat analysis."""
    repositories: list[str] = []
    documents: list[str] = []


class ThreatRisk(BaseModel):
    risk_id: str = ""
    name: str = ""
    security_property: str = ""
    description: str = ""


class ThreatAsset(BaseModel):
    asset_id: str = ""
    name: str = ""
    description: str = ""
    asset_type: str = "other"
    criticality: str = "medium"
    risks: list[ThreatRisk] = []


class ThreatAttackTreeNode(BaseModel):
    node_id: str = ""
    parent_id: str | None = None
    node_type: str = ""
    name: str = ""
    order: int = 0
    basis: list[str] = []
    surface_type: str = ""
    preconditions: list[str] = []


class ThreatAttackTree(BaseModel):
    tree_id: str = ""
    asset_id: str = ""
    risk_id: str = ""
    attack_goal: str = ""
    root_node_id: str = ""
    nodes: list[ThreatAttackTreeNode] = []


class ThreatCodePath(BaseModel):
    path: str = ""
    description: str = ""


class ThreatCodePathMapping(BaseModel):
    surface_node_id: str = ""
    code_paths: list[ThreatCodePath] = []


class ThreatAnalysis(BaseModel):
    schema_version: str = "1.0"
    analysis_id: str = ""
    sources: ThreatAnalysisSources = Field(default_factory=ThreatAnalysisSources)
    assets: list[ThreatAsset] = []
    attack_trees: list[ThreatAttackTree] = []
    code_path_mappings: list[ThreatCodePathMapping] = []
    updated_at: str = ""


class VulnerabilityValidation(BaseModel):
    """Runtime validation status and artifacts for one vulnerability."""
    scan_id: str = ""
    vuln_index: int
    status: str = "pending"              # pending | running | verified | failed | error | timeout | skipped
    running: bool = False
    product: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class OpenCodePoolModelStats(BaseModel):
    id: str
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    available: bool = True
    time_windows: list[dict[str, str]] = []
    queued: int = 0
    running: int = 0
    total: int = 0
    success: int = 0
    failure: int = 0
    timeout: int = 0
    cancelled: int = 0
    avg_duration_seconds: float = 0.0
    last_status: str = ""
    last_started_at: str = ""
    last_finished_at: str = ""
    active_tasks: list[dict] = []


class OpenCodePoolStatus(BaseModel):
    scope_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    global_running: int = 0
    global_queued: int = 0
    models: list[OpenCodePoolModelStats] = []
    updated_at: str = ""


class AgentOpenCodePoolStatus(OpenCodePoolStatus):
    agent_id: str = ""
    online: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    product: str = ""
    scan_items: list[str] = []
    created_at: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    candidates: list[ScanCandidate] = []
    vulnerabilities: list[Vulnerability]
    skill_reports: list[SkillReport] = []
    threat_analysis: ThreatAnalysis | None = None
    validations: list[VulnerabilityValidation] = []
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
    feedback_ids: list[str] = []
    retryable_candidates_count: int = 0
    opencode_pool: OpenCodePoolStatus | None = None

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


class AgentScanCandidates(BaseModel):
    """Sent by the agent after the final static candidate list is ready."""
    candidates: list[Candidate] = []


class AgentVulnerabilityValidationUpdate(BaseModel):
    """Sent by the agent while a local vulnerability validation script runs."""
    vuln_index: int
    status: str = "pending"
    running: bool = False
    product: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class AgentInfo(BaseModel):
    """Info about a registered agent."""
    agent_id: str
    name: str
    ip: str
    port: int = 0
    last_seen: str
    user_id: str = ""
    runtime_hash: str = ""
    agent_session_id: str = ""


class AgentLLMApiConfig(BaseModel):
    base_url: str = "https://api.anthropic.com"
    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.1
    timeout: int = 300
    max_retries: int = 3
    stream: bool = False


class AgentOpenCodeModelConfig(BaseModel):
    id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = "high"
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: list[dict[str, str]] = []


class AgentOpenCodeConfig(BaseModel):
    tool: str = "opencode"
    executable: str = "opencode"
    invocation_mode: str = "serve"
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2
    models: list[AgentOpenCodeModelConfig] = []


class AgentMemoryApiDiscoveryConfig(BaseModel):
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 300
    max_candidates: int = 200


class AgentGitHistoryConfig(BaseModel):
    enabled: bool = True
    max_commits: int = 200
    since: str = ""
    paths: str = ""
    variant_hunt: bool = True


class AgentPatternFilterConfig(BaseModel):
    enabled: bool = True
    scope: str = "directory"


class AgentVulnerabilityValidationConfig(BaseModel):
    enabled: bool = True
    script_path: str = ""
    command: str = ""
    timeout_seconds: int = 300


class AgentRemoteConfig(BaseModel):
    """Agent configuration managed from the server Web UI."""
    no_proxy: str = "10.0.0.0/8"
    opencode_concurrency: int = 1
    llm_api: AgentLLMApiConfig = AgentLLMApiConfig()
    opencode: AgentOpenCodeConfig = AgentOpenCodeConfig()
    fp_review_cli: AgentOpenCodeConfig | None = None
    memory_api_discovery: AgentMemoryApiDiscoveryConfig = AgentMemoryApiDiscoveryConfig()
    git_history: AgentGitHistoryConfig = AgentGitHistoryConfig()
    static_dedup: bool = True
    pattern_filter: AgentPatternFilterConfig = AgentPatternFilterConfig()
    vulnerability_validation: AgentVulnerabilityValidationConfig = AgentVulnerabilityValidationConfig()


class CreateScanRequest(BaseModel):
    """Request to create a new scan via a registered agent."""
    agent_id: str
    project_path: str
    code_scan_path: str = ""
    scan_name: str = ""
    product: str = ""
    checkers: list[str]
    feedback_ids: list[str] = []


class ScanProductList(BaseModel):
    products: list[str]


class UpdateScanProductRequest(BaseModel):
    product: str = ""


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
    product: str = ""
    user_id: str = ""
    public_access_token: str = ""


class ScanSummary(BaseModel):
    """扫描列表的摘要信息。"""
    scan_id: str
    project_id: str
    scan_name: str = ""
    product: str = ""
    status: ScanItemStatus
    created_at: str
    progress: float
    total_candidates: int
    processed_candidates: int
    vulnerability_count: int
    human_confirmed_count: int = 0
    retryable_candidates_count: int = 0
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
    product: str = ""
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
    ticket_accuracy: float | None = None


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
    ticket_accuracy: float | None = None
    scans: list[CheckerScanDashboardStats] = []
    user_created: bool = False


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
    ticket_accuracy: float | None = None


class CheckerDashboardResponse(BaseModel):
    """Admin checker dashboard response."""
    summary: CheckerDashboardSummary
    checkers: list[CheckerDashboardStats]


# --- Git history mining models ---

class HistoryPattern(BaseModel):
    """从 git 历史中挖掘出的一条「历史安全问题模式」。"""
    pattern: str                  # 根因 + 缺陷类型 + 触发条件的抽象描述
    source: str = ""              # 出处：提交短 hash + 标题
    lens_hint: str = ""           # memory | integer | race | injection | authn | crypto | dos | infoleak
    files: list[str] = []         # 涉及/出现的文件
    rationale: str = ""           # 判定理由 + 改动要点摘要


class AgentGitHistory(BaseModel):
    """Agent 上报某次扫描挖掘出的历史问题模式批次。"""
    patterns: list[HistoryPattern] = []


# --- FP Review models ---

class FpReviewStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


class FpReviewResult(BaseModel):
    """Per-vulnerability false-positive review result."""
    vuln_index: int           # index in the parent scan's vulnerability list
    verdict: str              # "tp" (true positive) | "fp" (false positive)
    severity: str = "low"     # "high" | "low"
    reason: str               # AI reasoning
    vulnerability_report: str = ""  # Markdown report for confirmed issues
    stage_outputs: dict[str, str] = {}
    match_reference: str = ""  # 命中历史问题模式或其它函数校验时，对应的修复/校验描述
    match_type: str = ""       # "history" | "validation" | ""（命中类型）
    stage_output_sources: dict[str, OutputSource] = Field(default_factory=dict)
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str


class FpReviewStageOutput(BaseModel):
    """Markdown output produced by one FP review stage."""
    review_id: str
    vuln_index: int
    stage: str
    markdown: str
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str
    updated_at: str


class FpReviewJob(BaseModel):
    """A false-positive review job for a scan."""
    review_id: str
    scan_id: str
    status: FpReviewStatus
    created_at: str
    total: int = 0
    processed: int = 0
    current_vuln_index: int | None = None
    current_vuln_indices: list[int] = []
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
    stage_outputs: dict[str, str] = {}
    match_reference: str = ""
    match_type: str = ""
    stage_output_sources: dict[str, OutputSource] = Field(default_factory=dict)
    output_source: OutputSource = Field(default_factory=OutputSource)


class AgentFpReviewStageOutput(BaseModel):
    """Sent by the agent when a stage Markdown output is ready."""
    review_id: str
    vuln_index: int
    stage: str
    markdown: str
    output_source: OutputSource = Field(default_factory=OutputSource)


class AgentFpReviewProgress(BaseModel):
    """Sent by the agent when it starts reviewing a vulnerability."""
    review_id: str
    vuln_index: int
    processed: int | None = None
    active_indices: list[int] | None = None  # all vuln indices being reviewed concurrently


class AgentFpReviewFinish(BaseModel):
    """Sent by the agent when the FP review job is complete."""
    review_id: str
    status: str        # "complete" | "error" | "cancelled"
    error_message: str | None = None
