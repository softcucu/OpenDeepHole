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
}

export interface UploadResponse {
  project_id: string;
}

export interface ScanStartResponse {
  scan_id: string;
}

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
  user_verdict?: "confirmed" | "false_positive" | null;
  user_verdict_reason?: string | null;
  ticket_submitted?: boolean;
  ticket_id?: string;
  function_source?: string;
  function_start_line?: number | null;
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
  events: ScanEvent[];
  current_candidate: Candidate | null;
  error_message: string | null;
  feedback_ids: string[];

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
  verdict: "confirmed" | "false_positive";
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
}

export interface AgentRemoteConfig {
  no_proxy: string;
  llm_api: AgentLLMApiConfig;
  opencode: AgentOpenCodeConfig;
  fp_review_cli?: AgentOpenCodeConfig | null;
}

export interface AgentConfigTestResult {
  ok: boolean;
  message: string;
}

export type FpReviewStatus = "pending" | "running" | "complete" | "error";

export interface FpReviewResult {
  vuln_index: number;
  verdict: "tp" | "fp";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report: string;
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
  scans: CheckerScanDashboardStats[];
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
}

export interface CheckerDashboardResponse {
  summary: CheckerDashboardSummary;
  checkers: CheckerDashboardStats[];
}
