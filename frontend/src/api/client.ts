import axios from "axios";
import type { AgentConfigTestResult, AgentInfo, AgentRemoteConfig, CheckerCatalogItem, CheckerDashboardResponse, CheckerInfo, FeedbackEntry, FpReviewJob, IndexStatus, ScanStatus, ScanStartResponse, ScanSummary, TokenResponse, User } from "../types";

const api = axios.create({ baseURL: "/" });

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
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function getCheckerCatalog(): Promise<CheckerCatalogItem[]> {
  const { data } = await api.get<CheckerCatalogItem[]>("/api/checkers/catalog");
  return data;
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
  checkers: string[];
  feedback_ids?: string[];
}): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", body);
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  const { data } = await api.get<ScanStatus>(`/api/scan/${scanId}`);
  return data;
}

export async function stopScan(scanId: string): Promise<void> {
  await api.post(`/api/scan/${scanId}/stop`);
}

export async function downloadScanReport(scanId: string): Promise<Blob> {
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report`, { responseType: "blob" });
  return data;
}

export async function markVulnerability(
  scanId: string,
  index: number,
  verdict: string,
  reason: string,
  ticketSubmitted = false,
  ticketId = "",
): Promise<{ ok: boolean; feedback_id: string }> {
  const { data } = await api.post(`/api/scan/${scanId}/mark`, {
    index,
    verdict,
    reason,
    ticket_submitted: ticketSubmitted,
    ticket_id: ticketSubmitted ? ticketId : "",
  });
  return data;
}

export async function batchMarkVulnerabilities(
  scanId: string,
  items: Array<{ index: number; verdict: string; reason: string }>,
): Promise<{ ok: boolean; feedback_ids: string[] }> {
  const { data } = await api.post(`/api/scan/${scanId}/batch-mark`, { items });
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
  const { data } = await api.post<FeedbackEntry>("/api/feedback", body);
  return data;
}

export async function updateFeedback(
  feedbackId: string,
  body: { verdict?: string; reason?: string; ticket_submitted?: boolean; ticket_id?: string },
): Promise<FeedbackEntry> {
  const { data } = await api.put<FeedbackEntry>(`/api/feedback/${feedbackId}`, body);
  return data;
}

export async function deleteFeedback(feedbackId: string): Promise<void> {
  await api.delete(`/api/feedback/${feedbackId}`);
}

export async function updateScanFeedback(
  scanId: string,
  feedbackIds: string[],
): Promise<void> {
  await api.put(`/api/scan/${scanId}/feedback`, { feedback_ids: feedbackIds });
}

export async function getSkillContent(
  scanId: string,
  vulnType: string,
): Promise<string> {
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

export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/api/scan/${scanId}`);
}

export async function getCheckerDashboard(): Promise<CheckerDashboardResponse> {
  const { data } = await api.get<CheckerDashboardResponse>("/api/admin/checker-dashboard");
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

export async function triggerFpReview(scanId: string): Promise<{ ok: boolean; review_id: string }> {
  const { data } = await api.post(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function getFpReview(scanId: string): Promise<FpReviewJob> {
  const { data } = await api.get<FpReviewJob>(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function getFpReviewSkill(scanId: string): Promise<string> {
  const { data } = await api.get<{ content: string }>(`/api/scan/${scanId}/fp-review/skill`);
  return data.content;
}
