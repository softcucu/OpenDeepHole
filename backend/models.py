"""Pydantic models for API requests, responses, and internal data."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


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
    serve_session_id: str = ""


class Vulnerability(BaseModel):
    """A confirmed or assessed vulnerability after AI analysis."""
    file: str
    line: int
    function: str
    call_chain: list[str] = []
    vuln_type: str
    severity: str        # "high", "medium", "low"
    description: str
    ai_analysis: str
    vulnerability_report: str = ""            # Markdown report emitted by the audit
    confirmed: bool
    ai_verdict: str = ""                     # "confirmed" | "not_confirmed" | "timeout" | "no_result" | "failed" | "filtered_same_pattern"
    failure_reason: str = ""                 # OpenCode/runner output for retryable failures
    user_verdict: str | None = None          # "confirmed" | "false_positive" | "pending_analysis" | None
    user_verdict_reason: str | None = None   # 用户填写的理由
    ticket_submitted: bool = False           # 是否已提问题单
    ticket_id: str = ""                      # 问题单号
    function_source: str = ""
    function_start_line: int | None = None
    audit_index: int | None = None           # Static candidate audit order; DB idx remains the API handle.
    variant_of: str = ""                     # 同类变体排查命中时，来源历史问题模式（根因摘要+出处提交/文件）
    analysis_source: str = "static_candidate"  # "static_candidate" | "threat_audit"
    source_task_id: str = ""
    threat_surface_node_id: str = ""
    threat_method_node_id: str = ""
    threat_code_path: str = ""
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


class ThreatCodePath(BaseModel):
    path: str = ""
    description: str = ""


class ThreatAuditTask(BaseModel):
    """One audit task derived from an attack-tree threat-analysis result."""
    task_id: str
    scan_id: str = ""
    status: str = "pending"  # pending | queued | running | completed | failed | timeout | no_result | cancelled
    surface_node_id: str = ""
    surface_name: str = ""
    method_node_id: str = ""
    method_name: str = ""
    attack_goal: str = ""
    risk_id: str = ""
    risk_name: str = ""
    asset_id: str = ""
    asset_name: str = ""
    code_path: str = ""
    code_path_description: str = ""
    code_paths: list[ThreatCodePath] = []
    attack_path_id: str = ""
    attack_path_fingerprint: str = ""
    description: str = ""
    result_vuln_indexes: list[int] = []
    failure_reason: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class VulnerabilityValidation(BaseModel):
    """Runtime validation status and artifacts for one vulnerability."""
    scan_id: str = ""
    vuln_index: int
    status: str = "pending"              # pending | queued | running | verified | failed | error | timeout | skipped | cancelled
    running: bool = False
    product: str = ""
    validation_environment: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    requires_human_intervention: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    output_sections: list[dict] = []
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class AgentModelTimeWindow(BaseModel):
    """One model availability window in the Agent's local timezone."""

    weekdays: list[int] = Field(default_factory=lambda: list(range(1, 8)))
    start: str = ""
    end: str = ""


class OpenCodePoolModelStats(BaseModel):
    id: str
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    available: bool = True
    time_windows: list[dict[str, object]] = []
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
    total_tasks: int = 0
    completed_task_count: int = 0
    queued_tasks: list[dict] = []
    planned_tasks: list[dict] = []
    completed_tasks: list[dict] = []
    models: list[OpenCodePoolModelStats] = []
    updated_at: str = ""


class AgentOpenCodePoolStatus(OpenCodePoolStatus):
    agent_id: str = ""
    online: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    scan_mode: str = "full"
    product: str = ""
    validation_environment: str = ""
    scan_items: list[str] = []
    created_at: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    candidates: list[ScanCandidate] = []
    vulnerabilities: list[Vulnerability]
    skill_reports: list[SkillReport] = []
    threat_analysis: dict[str, Any] | None = None
    threat_audit_tasks: list[ThreatAuditTask] = []
    validations: list[VulnerabilityValidation] = []
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
    feedback_ids: list[str] = []
    retryable_candidates_count: int = 0
    continuable_task_count: int = 0
    can_continue: bool = False
    total_task_count: int = 0
    completed_task_count: int = 0
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
    validation_environment: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    requires_human_intervention: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    output_sections: list[dict] = []
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class AgentInfo(BaseModel):
    """Info about a registered agent."""
    agent_id: str
    agent_key: str = ""
    name: str
    machine_name: str = ""
    ip: str
    port: int = 0
    last_seen: str
    user_id: str = ""
    runtime_hash: str = ""
    agent_session_id: str = ""


class AgentOpenCodeModelConfig(BaseModel):
    id: str = ""
    model: str = ""
    # Read-only compatibility for old agent.yaml files.  It is deliberately
    # omitted from the managed v2 config and never satisfies scan readiness.
    use_default_model: bool = Field(default=False, exclude=True)
    capability: str = "high"
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: list[AgentModelTimeWindow] = []


class AgentOpenCodeConfig(BaseModel):
    tool: str = "nga"
    executable: str = "nga"
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2
    models: list[AgentOpenCodeModelConfig] = []
    config_paths: list[str] = []
    proxy_url: str = ""
    no_proxy: str = ""
    config_jsonc: str = "{}"


class AgentBaseConfig(BaseModel):
    tool: str = "nga"
    executable: str = "nga"
    no_proxy: str = "10.0.0.0/8"


class AgentModelPoolConfig(BaseModel):
    global_concurrency: int = 4
    models: list[AgentOpenCodeModelConfig] = []


class AgentModelTaskPolicy(BaseModel):
    required_capability: str = "high"
    timeout_seconds: int = 1200
    max_retries: int = 2

    @field_validator("required_capability", mode="before")
    @classmethod
    def _normalize_required_capability(cls, value: object) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"medium", "high"}:
            return "high"
        if normalized in {"", "any", "low"}:
            return "low"
        raise ValueError("required_capability must be low or high")


class AgentMcpLocalConfig(BaseModel):
    executable: str = ""
    args: list[str] = []
    environment: dict[str, str] = {}


class AgentMcpRemoteConfig(BaseModel):
    url: str = ""
    headers: dict[str, str] = {}


class AgentMcpConfig(BaseModel):
    enabled: bool = False
    name: str = ""
    transport: str = "local"
    timeout_seconds: int = 300
    local: AgentMcpLocalConfig = AgentMcpLocalConfig()
    remote: AgentMcpRemoteConfig = AgentMcpRemoteConfig()


class AgentMcpProbeResult(BaseModel):
    target: str
    config_fingerprint: str = ""
    success: bool = False
    checked_at: str = ""
    transport: str = ""
    protocol: str = ""
    tool_names: list[str] = []
    tool_count: int = 0
    duration_ms: int = 0
    error: str = ""
    runtime_state: str = "next_task"
    active_sessions: int = 0


class AgentMcpRuntimeStatus(BaseModel):
    state: str = "unknown"
    config_fingerprint: str = ""
    updated_at: str = ""
    error: str = ""
    loaded_directories: int = 0
    total_directories: int = 0


class AgentMcpTargetStatus(BaseModel):
    enabled: bool = False
    stale: bool = False
    last_probe: AgentMcpProbeResult | None = None
    runtime: AgentMcpRuntimeStatus = AgentMcpRuntimeStatus()


class AgentMcpStatusResponse(BaseModel):
    agent_key: str
    online: bool = False
    code_graph: AgentMcpTargetStatus = AgentMcpTargetStatus()
    product_info: AgentMcpTargetStatus = AgentMcpTargetStatus()


class AgentOpenCodeRuntimeConfigResponse(BaseModel):
    agent_key: str
    online: bool = False
    exists: bool = False
    source: str = "none"
    content: str = ""
    redacted: bool = True
    path: str = ""
    captured_at: str = ""
    modified_at: str = ""
    sha256: str = ""
    size_bytes: int = 0
    runtime_state: str = "next_task"
    active_sessions: int = 0
    warning: str = ""


class AgentValidationEnvironmentConfig(BaseModel):
    supported_vulnerability_types: list[str] = ["*"]
    concurrency: int = 1
    validation_max_retries: int = 0
    model_policy: AgentModelTaskPolicy = AgentModelTaskPolicy()
    # Values are keyed by the stable validator registration key.
    methods: dict[str, dict[str, object]] = {}


class AgentValidatorField(BaseModel):
    key: str
    label: str = ""
    type: str = "string"
    required: bool = False
    default: object | None = None
    options: list[object] = []
    min: float | None = None
    max: float | None = None
    help: str = ""
    placeholder: str = ""


class AgentValidatorRegistration(BaseModel):
    registration_key: str
    method_id: str
    method_label: str = ""
    product: str
    environment: str
    fields: list[AgentValidatorField] = []
    timeout_seconds: int | None = None
    legacy: bool = False


class AgentValidatorCatalog(BaseModel):
    registrations: list[AgentValidatorRegistration] = []
    errors: list[str] = []
    updated_at: str = ""


def _safe_policy_int(value: object, default: int, *, minimum: int) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


class AgentMemoryApiDiscoveryConfig(BaseModel):
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 300
    max_candidates: int = 200


class AgentGitHistoryConfig(BaseModel):
    enabled: bool = False
    max_commits: int = 200
    since: str = ""
    paths: str = ""
    variant_hunt: bool = True


class AgentThreatAnalysisConfig(BaseModel):
    enabled: bool = True


class AgentPatternFilterConfig(BaseModel):
    enabled: bool = True
    scope: str = "directory"


class AgentVulnerabilityValidationConfig(BaseModel):
    environments: dict[str, AgentValidationEnvironmentConfig] = {}


class AgentRemoteConfig(BaseModel):
    """Agent configuration managed from the server Web UI."""
    schema_version: int = 2
    opencode_config: str = "{}"
    base: AgentBaseConfig = AgentBaseConfig()
    model_pool: AgentModelPoolConfig = AgentModelPoolConfig()
    threat_analysis: AgentThreatAnalysisConfig = AgentThreatAnalysisConfig()
    code_graph: AgentMcpConfig = AgentMcpConfig(
        name="codegraph",
        local=AgentMcpLocalConfig(
            executable="codegraph",
            args=["serve", "--mcp"],
            environment={
                "CODEGRAPH_MCP_TOOLS": "explore,node,search,callers,callees,impact,files,status",
            },
        ),
    )
    product_info: AgentMcpConfig = AgentMcpConfig(name="product-info")
    vulnerability_mining: AgentModelTaskPolicy = AgentModelTaskPolicy(
        required_capability="low",
    )
    false_positive: AgentModelTaskPolicy = AgentModelTaskPolicy(
        required_capability="high",
    )
    vulnerability_validation: AgentVulnerabilityValidationConfig = AgentVulnerabilityValidationConfig()

    @model_validator(mode="before")
    @classmethod
    def _upgrade_legacy(cls, value):
        """Accept pre-v2 Agent payloads while emitting only the v2 contract."""
        if not isinstance(value, dict) or value.get("schema_version") == 2 or "base" in value:
            return value
        legacy = dict(value)
        opencode = legacy.get("opencode") if isinstance(legacy.get("opencode"), dict) else {}
        fp_cli = legacy.get("fp_review_cli") if isinstance(legacy.get("fp_review_cli"), dict) else {}
        threat = legacy.get("threat_analysis") if isinstance(legacy.get("threat_analysis"), dict) else {}
        models = []
        for raw_model in opencode.get("models") or []:
            if not isinstance(raw_model, dict):
                continue
            migrated_model = dict(raw_model)
            if migrated_model.pop("use_default_model", False):
                migrated_model["model"] = ""
                migrated_model["enabled"] = False
            models.append(migrated_model)
        seen_ids = {str(item.get("id") or "") for item in models if isinstance(item, dict)}
        for item in fp_cli.get("models") or []:
            if not isinstance(item, dict):
                continue
            migrated = dict(item)
            if migrated.pop("use_default_model", False):
                migrated["model"] = ""
                migrated["enabled"] = False
            model_id = str(migrated.get("id") or "model")
            if model_id in seen_ids:
                model_id = f"fp-{model_id}"
            migrated["id"] = model_id
            if not any(
                isinstance(existing, dict)
                and str(existing.get("model") or "") == str(migrated.get("model") or "")
                and str(existing.get("tool") or "") == str(migrated.get("tool") or "")
                for existing in models
            ):
                models.append(migrated)
                seen_ids.add(model_id)
        timeout = _safe_policy_int(opencode.get("timeout"), 1200, minimum=1)
        retries = _safe_policy_int(opencode.get("max_retries"), 2, minimum=0)
        fp_timeout = _safe_policy_int(fp_cli.get("timeout"), timeout, minimum=1)
        fp_retries = _safe_policy_int(fp_cli.get("max_retries"), retries, minimum=0)
        return {
            "schema_version": 2,
            "opencode_config": str(
                legacy.get("opencode_config") or opencode.get("config_jsonc") or "{}"
            ),
            "base": {
                "tool": opencode.get("tool", "nga"),
                "executable": opencode.get("executable", "nga"),
                "no_proxy": legacy.get("no_proxy") or opencode.get("no_proxy") or "10.0.0.0/8",
            },
            "model_pool": {
                "global_concurrency": legacy.get("opencode_concurrency", 4),
                "models": models,
            },
            "threat_analysis": {
                "enabled": threat.get("enabled", True),
            },
            "product_info": {
                "enabled": False,
                "name": "product-info",
            },
            "vulnerability_mining": {
                "required_capability": "low",
                "timeout_seconds": timeout,
                "max_retries": retries,
            },
            "false_positive": {
                "required_capability": "high",
                "timeout_seconds": fp_timeout,
                "max_retries": fp_retries,
            },
            "vulnerability_validation": {"environments": {}},
        }

    @property
    def no_proxy(self) -> str:
        return self.base.no_proxy

    @property
    def opencode_concurrency(self) -> int:
        return self.model_pool.global_concurrency

    @property
    def opencode(self) -> AgentOpenCodeConfig:
        return AgentOpenCodeConfig(
            tool=self.base.tool,
            executable=self.base.executable,
            timeout=self.vulnerability_mining.timeout_seconds,
            max_retries=self.vulnerability_mining.max_retries,
            models=self.model_pool.models,
            no_proxy=self.base.no_proxy,
            config_jsonc=self.opencode_config,
        )


class CreateScanRequest(BaseModel):
    """Request to create a new scan via a registered agent."""
    agent_key: str = ""
    agent_id: str = ""  # compatibility for older callers
    project_path: str
    code_scan_path: str = ""
    scan_name: str = ""
    scan_mode: str = "full"
    product: str = ""
    validation_environment: str = ""
    checkers: list[str]
    feedback_ids: list[str] = []


class ValidationTarget(BaseModel):
    validator_id: str
    product: str
    validation_environment: str
    timeout_seconds: int | None = None


class ScanValidationTargetList(BaseModel):
    targets: list[ValidationTarget]


class UpdateScanValidationTargetRequest(BaseModel):
    product: str = ""
    validation_environment: str = ""


class ScanMeta(BaseModel):
    """扫描元数据，记录扫描配置信息。"""
    scan_items: list[str]
    created_at: str
    scan_mode: str = "full"
    feedback_ids: list[str] = []
    agent_id: str = ""
    agent_key: str = ""
    agent_name: str = ""
    project_path: str = ""
    code_scan_path: str = ""
    scan_name: str = ""
    product: str = ""
    validation_environment: str = ""
    user_id: str = ""
    public_access_token: str = ""


class ScanSummary(BaseModel):
    """扫描列表的摘要信息。"""
    scan_id: str
    project_id: str
    scan_mode: str = "full"
    scan_name: str = ""
    product: str = ""
    validation_environment: str = ""
    status: ScanItemStatus
    created_at: str
    progress: float
    total_candidates: int
    processed_candidates: int
    vulnerability_count: int
    human_confirmed_count: int = 0
    retryable_candidates_count: int = 0
    continuable_task_count: int = 0
    can_continue: bool = False
    total_task_count: int = 0
    completed_task_count: int = 0
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
