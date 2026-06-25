// --- Auth ---

export interface User {
  user_id: string;
  username: string;
  role: "admin" | "user";
  agent_token: string;
  created_at: string;
}

export interface TokenResponse {
  token: string;
  user: User;
}

// --- Scan ---

export type ScanItemStatus =
  | "pending"
  | "analyzing"
  | "auditing"
  | "complete"
  | "error"
  | "cancelled";

export interface CheckerInfo {
  name: string;
  label: string;
  description: string;
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface CheckerCatalogItem {
  name: string;
  label: string;
  description: string;
  enabled: boolean;
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  introduction: string;
  introduction_source: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface SkillDraft {
  skill_md: string;
  scenarios_md: string;
  summary: string;
}

export interface SkillCreateJob {
  job_id: string;
  status: "pending" | "running" | "completed" | "error";
  skill_id: string;
  name: string;
  description: string;
  input: string;
  agent_id: string;
  agent_name: string;
  user_id: string;
  created_at: string;
  updated_at: string;
  error_message: string;
  draft: SkillDraft | null;
}

export interface SkillImportFile {
  path: string;
  content_b64: string;
}

export interface UploadResponse {
  project_id: string;
}

export interface ScanStartResponse {
  scan_id: string;
}

export type UserFeedbackVerdict = "confirmed" | "false_positive" | "pending_analysis";
export type FeedbackEntryVerdict = "confirmed" | "false_positive";

export interface Vulnerability {
  file: string;
  line: number;
  function: string;
  vuln_type: string;
  severity: string;
  description: string;
  ai_analysis: string;
  confirmed: boolean;
  ai_verdict?: "confirmed" | "not_confirmed" | "timeout" | "no_result" | "";
  user_verdict?: UserFeedbackVerdict | null;
  user_verdict_reason?: string | null;
  ticket_submitted?: boolean;
  ticket_id?: string;
  function_source?: string;
  function_start_line?: number | null;
  variant_of?: string;
}

export interface HistoryPattern {
  pattern: string;
  source: string;
  lens_hint: string;
  files: string[];
  rationale: string;
}

export interface SkillReport {
  id?: number | null;
  scan_id: string;
  checker_name: string;
  filename: string;
  title: string;
  content: string;
  created_at: string;
}

export interface Candidate {
  file: string;
  line: number;
  function: string;
  description: string;
  vuln_type: string;
}

export interface ScanEvent {
  timestamp: string;
  phase: string;
  message: string;
  candidate_index: number | null;
}

export interface OpenCodePoolModelStats {
  id: string;
  model: string;
  use_default_model: boolean;
  capability: string;
  weight: number;
  max_concurrency: number;
  enabled: boolean;
  available: boolean;
  time_windows: { start: string; end: string }[];
  queued: number;
  running: number;
  total: number;
  success: number;
  failure: number;
  timeout: number;
  cancelled: number;
  avg_duration_seconds: number;
  last_status: string;
  last_started_at: string;
  last_finished_at: string;
  active_tasks: Record<string, unknown>[];
}

export interface OpenCodePoolStatus {
  scope_id: string;
  agent_name?: string;
  agent_session_id?: string;
  global_running: number;
  global_queued: number;
  models: OpenCodePoolModelStats[];
  updated_at: string;
}

export interface AgentOpenCodePoolStatus extends OpenCodePoolStatus {
  agent_id: string;
  online: boolean;
}

export interface ScanStatus {
  scan_id: string;
  project_id: string;
  product: string;
  scan_items: string[];
  created_at: string;
  status: ScanItemStatus;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerabilities: Vulnerability[];
  skill_reports: SkillReport[];
  events: ScanEvent[];
  current_candidate: Candidate | null;
  error_message: string | null;
  feedback_ids: string[];
  retryable_candidates_count: number;
  opencode_pool?: OpenCodePoolStatus | null;

  // 静态分析进度
  static_total_files: number;
  static_scanned_files: number;
  static_analysis_done: boolean;

  // Agent 信息
  agent_name?: string;
  agent_online?: boolean;
}

export interface FeedbackEntry {
  id: string;
  project_id: string;
  vuln_type: string;
  verdict: FeedbackEntryVerdict;
  file: string;
  line: number;
  function: string;
  description: string;
  reason: string;
  ticket_submitted: boolean;
  ticket_id: string;
  function_source: string;
  function_start_line: number | null;
  source_scan_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IndexStatus {
  status: "not_started" | "parsing" | "done" | "error" | "unknown";
  parsed_files?: number;
  total_files?: number;
  error?: string;
}

export interface ScanSummary {
  scan_id: string;
  project_id: string;
  scan_name: string;
  product: string;
  status: ScanItemStatus;
  created_at: string;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerability_count: number;
  human_confirmed_count: number;
  retryable_candidates_count: number;
  scan_items: string[];
  user_id?: string;
  username?: string;
  agent_name?: string;
  agent_online?: boolean;
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  ip: string;
  port?: number;
  last_seen: string;
  online: boolean;
  agent_session_id?: string;
}

export interface AgentLLMApiConfig {
  base_url: string;
  api_key: string;
  model: string;
  temperature: number;
  timeout: number;
  max_retries: number;
  stream: boolean;
}

export interface AgentOpenCodeConfig {
  tool: "nga" | "opencode" | "hac" | "claude" | string;
  executable: string;
  model: string;
  timeout: number;
  max_retries: number;
  models: AgentOpenCodeModelConfig[];
}

export interface AgentOpenCodeModelConfig {
  id: string;
  model: string;
  use_default_model?: boolean;
  capability: "low" | "medium" | "high" | string;
  weight: number;
  max_concurrency: number;
  enabled: boolean;
  tool?: "nga" | "opencode" | "hac" | "claude" | string;
  executable?: string;
  timeout?: number | null;
  max_retries?: number | null;
  time_windows?: { start: string; end: string }[];
}

export interface AgentMemoryApiDiscoveryConfig {
  enabled: boolean;
  batch_size: number;
  timeout_seconds: number;
  max_candidates: number;
}

export interface AgentGitHistoryConfig {
  enabled: boolean;
  max_commits: number;
  since: string;
  paths: string;
  variant_hunt: boolean;
}

export interface AgentPatternFilterConfig {
  enabled: boolean;
  scope: "directory" | "file" | "repo" | string;
}

export interface AgentRemoteConfig {
  no_proxy: string;
  opencode_concurrency: number;
  llm_api: AgentLLMApiConfig;
  opencode: AgentOpenCodeConfig;
  fp_review_cli?: AgentOpenCodeConfig | null;
  memory_api_discovery: AgentMemoryApiDiscoveryConfig;
  git_history?: AgentGitHistoryConfig;
  static_dedup?: boolean;
  pattern_filter?: AgentPatternFilterConfig;
}

export interface AgentConfigTestResult {
  ok: boolean;
  message: string;
}

export type FpReviewStatus = "pending" | "running" | "complete" | "error" | "cancelled";

export interface FpReviewResult {
  vuln_index: number;
  verdict: "tp" | "fp";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report: string;
  stage_outputs?: Record<string, string>;
  match_reference?: string;
  match_type?: "history" | "validation" | "" | string;
  created_at: string;
}

export interface FpReviewJob {
  review_id: string;
  scan_id: string;
  status: FpReviewStatus;
  created_at: string;
  total: number;
  processed: number;
  current_vuln_index: number | null;
  current_vuln_indices?: number[];
  results: FpReviewResult[];
  error_message: string | null;
}

// --- Admin dashboard ---

export interface CheckerScanDashboardStats {
  scan_id: string;
  project_id: string;
  scan_name: string;
  project_path: string;
  product: string;
  status: ScanItemStatus;
  created_at: string;
  username: string;
  agent_name: string;
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  human_confirmed_count: number;
  human_false_positive_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
}

export interface CheckerDashboardStats {
  checker: string;
  label: string;
  description: string;
  scan_count: number;
  project_count: number;
  projects: string[];
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  human_confirmed_count: number;
  human_false_positive_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
  scans: CheckerScanDashboardStats[];
  user_created: boolean;
}

export interface CheckerDashboardSummary {
  checker_count: number;
  scan_count: number;
  project_count: number;
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  total_issue_count: number;
  human_confirmed_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
}

export interface CheckerDashboardResponse {
  summary: CheckerDashboardSummary;
  checkers: CheckerDashboardStats[];
}
