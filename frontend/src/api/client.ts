import axios from "axios";
import type { AgentConfigTestResult, AgentInfo, AgentRemoteConfig, CheckerCatalogItem, CheckerDashboardResponse, CheckerInfo, FeedbackEntry, FpReviewJob, IndexStatus, ScanStatus, ScanStartResponse, ScanSummary, SkillCreateJob, SkillImportFile, SkillReport, TokenResponse, User, UserFeedbackVerdict } from "../types";

const api = axios.create({ baseURL: "/" });

let publicScanAccess: { scanId: string; token: string } | null = null;

export function setPublicScanAccess(access: { scanId: string; token: string } | null): void {
  publicScanAccess = access;
}

function isPublicScan(scanId: string): boolean {
  return !!publicScanAccess && publicScanAccess.scanId === scanId && !!publicScanAccess.token;
}

function publicParams(): { token: string } | undefined {
  return publicScanAccess ? { token: publicScanAccess.token } : undefined;
}

function publicScanPath(path: string): string {
  if (!publicScanAccess) return path;
  return `/api/public/scans/${publicScanAccess.scanId}${path}`;
}

// Attach JWT token to all requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear token so the UI can redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_user");
      window.dispatchEvent(new Event("auth_expired"));
    }
    return Promise.reject(error);
  },
);

// --- Auth ---

export async function login(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/login", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export async function register(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/register", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_user");
}

export function getStoredUser(): User | null {
  const raw = localStorage.getItem("auth_user");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("auth_token");
}

export async function getCurrentUser(): Promise<User> {
  const { data } = await api.get<User>("/api/auth/me");
  return data;
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  await api.put("/api/auth/password", { old_password: oldPassword, new_password: newPassword });
}

export async function listUsers(): Promise<User[]> {
  const { data } = await api.get<User[]>("/api/auth/users");
  return data;
}

export async function createUser(username: string, password: string, role: string): Promise<User> {
  const { data } = await api.post<User>("/api/auth/users", { username, password, role });
  return data;
}

export async function deleteUser(userId: string): Promise<void> {
  await api.delete(`/api/auth/users/${userId}`);
}

export async function getCheckers(): Promise<CheckerInfo[]> {
  if (publicScanAccess) {
    const { data } = await api.get<CheckerInfo[]>(
      publicScanPath("/checkers"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function getCheckerCatalog(): Promise<CheckerCatalogItem[]> {
  const { data } = await api.get<CheckerCatalogItem[]>("/api/checkers/catalog");
  return data;
}

export async function createSkill(body: {
  agent_id?: string;
  skill_id: string;
  name: string;
  description: string;
  input: string;
  timeout_seconds: number;
}): Promise<SkillCreateJob> {
  const { data } = await api.post<SkillCreateJob>("/api/skills/create", body);
  return data;
}

export async function deleteSkill(skillId: string): Promise<void> {
  await api.delete(`/api/skills/${skillId}`);
}

export async function getSkillCreateJob(jobId: string): Promise<SkillCreateJob> {
  const { data } = await api.get<SkillCreateJob>(`/api/skills/create/${jobId}`);
  return data;
}

export async function importSkill(jobId: string, body: {
  skill_md: string;
  scenarios_md?: string;
  timeout_seconds: number;
  files?: SkillImportFile[];
}): Promise<{ ok: boolean; name: string }> {
  const { data } = await api.post<{ ok: boolean; name: string }>(
    `/api/skills/create/${jobId}/import`,
    body,
  );
  return data;
}

export async function getSkillReports(
  scanId: string,
  checkerName?: string,
): Promise<SkillReport[]> {
  const params = checkerName ? { checker_name: checkerName } : undefined;
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ reports: SkillReport[] }>(
      publicScanPath("/skill-reports"),
      { params: { ...publicParams(), ...(params ?? {}) } },
    );
    return data.reports;
  }
  const { data } = await api.get<{ reports: SkillReport[] }>(
    `/api/scan/${scanId}/skill-reports`,
    { params },
  );
  return data.reports;
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await api.get<AgentInfo[]>("/api/agents");
  return data;
}

export async function getIndexStatus(projectId: string): Promise<IndexStatus> {
  const { data } = await api.get<IndexStatus>(`/api/project/${projectId}/index-status`);
  return data;
}

export async function getAgentIndexStatus(scanId: string): Promise<IndexStatus> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<IndexStatus>(
      publicScanPath("/index-status"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<IndexStatus>(`/api/agent/scan/${scanId}/index-status`);
  return data;
}

export async function startScan(
  projectId: string,
  scanItems: string[],
  feedbackIds: string[] = [],
): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", {
    project_id: projectId,
    scan_items: scanItems,
    feedback_ids: feedbackIds,
  });
  return data;
}

export async function createScan(body: {
  agent_id: string;
  project_path: string;
  code_scan_path?: string;
  scan_name: string;
  product?: string;
  checkers: string[];
  feedback_ids?: string[];
}): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", body);
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<ScanStatus>(
      publicScanPath(""),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<ScanStatus>(`/api/scan/${scanId}`);
  return data;
}

export async function getScanProducts(): Promise<string[]> {
  const { data } = await api.get<{ products: string[] }>("/api/scan/products");
  return data.products;
}

export async function updateScanProduct(scanId: string, product: string): Promise<void> {
  await api.put(`/api/scan/${scanId}/product`, { product });
}

export async function stopScan(scanId: string): Promise<void> {
  if (isPublicScan(scanId)) {
    await api.post(publicScanPath("/stop"), null, { params: publicParams() });
    return;
  }
  await api.post(`/api/scan/${scanId}/stop`);
}

export async function downloadScanReport(scanId: string): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report"),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report`, { responseType: "blob" });
  return data;
}

export async function downloadVulnerabilityReport(scanId: string, idx: number): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath(`/vulnerability/${idx}/report`),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(
    `/api/scan/${scanId}/vulnerability/${idx}/report`,
    { responseType: "blob" },
  );
  return data;
}

export async function downloadScanReportZip(scanId: string): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report.zip"),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report.zip`, { responseType: "blob" });
  return data;
}

export async function markVulnerability(
  scanId: string,
  index: number,
  verdict: UserFeedbackVerdict,
  reason: string,
  ticketSubmitted = false,
  ticketId = "",
): Promise<{ ok: boolean; feedback_id: string | null; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/mark"),
      {
        index,
        verdict,
        reason,
        ticket_submitted: ticketSubmitted,
        ticket_id: ticketSubmitted ? ticketId : "",
      },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/mark`, {
    index,
    verdict,
    reason,
    ticket_submitted: ticketSubmitted,
    ticket_id: ticketSubmitted ? ticketId : "",
  });
  return data;
}

export async function unmarkVulnerability(
  scanId: string,
  index: number,
): Promise<{ ok: boolean; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/unmark"),
      { index },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/unmark`, { index });
  return data;
}

export async function batchMarkVulnerabilities(
  scanId: string,
  items: Array<{ index: number; verdict: UserFeedbackVerdict; reason: string }>,
): Promise<{ ok: boolean; feedback_ids: string[]; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/batch-mark"),
      { items },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/batch-mark`, { items });
  return data;
}

export async function batchUnmarkVulnerabilities(
  scanId: string,
  indices: number[],
): Promise<{ ok: boolean; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/batch-unmark"),
      { indices },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/batch-unmark`, { indices });
  return data;
}

export async function saveFalsePositive(
  scanId: string,
  index: number,
): Promise<void> {
  await api.post(`/api/scan/${scanId}/save-fp`, { index });
}

// --- Feedback CRUD ---

export async function listFeedback(
  vulnType?: string,
  projectId?: string,
): Promise<FeedbackEntry[]> {
  const params: Record<string, string> = {};
  if (vulnType) params.vuln_type = vulnType;
  if (projectId) params.project_id = projectId;
  if (publicScanAccess) {
    params.token = publicScanAccess.token;
    const { data } = await api.get<FeedbackEntry[]>(
      publicScanPath("/feedback"),
      { params },
    );
    return data;
  }
  const { data } = await api.get<FeedbackEntry[]>("/api/feedback", { params });
  return data;
}

export async function createFeedback(body: {
  project_id: string;
  vuln_type: string;
  verdict: string;
  file: string;
  line: number;
  function: string;
  description: string;
  reason?: string;
  ticket_submitted?: boolean;
  ticket_id?: string;
  function_source?: string;
  function_start_line?: number | null;
  source_scan_id?: string;
}): Promise<FeedbackEntry> {
  if (publicScanAccess) {
    const { data } = await api.post<FeedbackEntry>(
      publicScanPath("/feedback"),
      body,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post<FeedbackEntry>("/api/feedback", body);
  return data;
}

export async function updateFeedback(
  feedbackId: string,
  body: { verdict?: string; reason?: string; ticket_submitted?: boolean; ticket_id?: string },
): Promise<FeedbackEntry> {
  if (publicScanAccess) {
    const { data } = await api.put<FeedbackEntry>(
      publicScanPath(`/feedback/${feedbackId}`),
      body,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.put<FeedbackEntry>(`/api/feedback/${feedbackId}`, body);
  return data;
}

export async function deleteFeedback(feedbackId: string): Promise<void> {
  if (publicScanAccess) {
    await api.delete(publicScanPath(`/feedback/${feedbackId}`), { params: publicParams() });
    return;
  }
  await api.delete(`/api/feedback/${feedbackId}`);
}

export async function updateScanFeedback(
  scanId: string,
  feedbackIds: string[],
): Promise<void> {
  if (isPublicScan(scanId)) {
    await api.put(
      publicScanPath("/feedback"),
      { feedback_ids: feedbackIds },
      { params: publicParams() },
    );
    return;
  }
  await api.put(`/api/scan/${scanId}/feedback`, { feedback_ids: feedbackIds });
}

export async function getSkillContent(
  scanId: string,
  vulnType: string,
): Promise<string> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ vuln_type: string; content: string }>(
      publicScanPath(`/skill/${vulnType}`),
      { params: publicParams() },
    );
    return data.content;
  }
  const { data } = await api.get<{ vuln_type: string; content: string }>(
    `/api/scan/${scanId}/skill/${vulnType}`,
  );
  return data.content;
}

export async function getScans(): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>("/api/scans");
  return data;
}

export async function resumeScan(scanId: string): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>(`/api/scan/${scanId}/resume`);
  return data;
}

export async function retryIncompleteScan(scanId: string): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>(`/api/scan/${scanId}/retry-incomplete`);
  return data;
}

export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/api/scan/${scanId}`);
}

export async function getCheckerDashboard(product?: string): Promise<CheckerDashboardResponse> {
  const params = product ? { product } : undefined;
  const { data } = await api.get<CheckerDashboardResponse>("/api/admin/checker-dashboard", { params });
  return data;
}

// --- Agent config ---

export async function getAgentConfig(agentId: string): Promise<AgentRemoteConfig> {
  const { data } = await api.get<AgentRemoteConfig>(`/api/agent/${agentId}/config`);
  return data;
}

export async function updateAgentConfig(agentId: string, config: AgentRemoteConfig): Promise<void> {
  await api.put(`/api/agent/${agentId}/config`, config);
}

export async function testAgentConfig(agentId: string, config: AgentRemoteConfig): Promise<AgentConfigTestResult> {
  const { data } = await api.post<AgentConfigTestResult>(`/api/agent/${agentId}/config/test`, config);
  return data;
}

// --- FP Review ---

export function scanSSEUrl(scanId: string): string {
  const base = window.location.origin;
  if (isPublicScan(scanId) && publicScanAccess) {
    return `${base}/api/public/scans/${scanId}/events?token=${encodeURIComponent(publicScanAccess.token)}`;
  }
  const token = localStorage.getItem("auth_token") || "";
  return `${base}/api/scan/${scanId}/events?token=${encodeURIComponent(token)}`;
}

export async function triggerFpReview(scanId: string): Promise<{
  ok: boolean;
  review_id: string;
  status?: FpReviewJob["status"];
  total?: number;
  processed?: number;
}> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(publicScanPath("/fp_review"), null, { params: publicParams() });
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function stopFpReview(scanId: string): Promise<{ ok: boolean; review_id: string }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(publicScanPath("/fp_review/stop"), null, { params: publicParams() });
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/fp_review/stop`);
  return data;
}

export async function getFpReview(scanId: string): Promise<FpReviewJob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<FpReviewJob>(
      publicScanPath("/fp_review"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<FpReviewJob>(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function getFpReviewSkill(scanId: string): Promise<string> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ content: string }>(
      publicScanPath("/fp-review/skill"),
      { params: publicParams() },
    );
    return data.content;
  }
  const { data } = await api.get<{ content: string }>(`/api/scan/${scanId}/fp-review/skill`);
  return data.content;
}
