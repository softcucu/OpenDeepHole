import { api, isPublicScan, publicParams, publicScanPath } from "../../api/client";
import type { ThreatAnalysis } from "../../types";

export async function getScanThreatAnalysis(scanId: string): Promise<ThreatAnalysis> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<ThreatAnalysis>(
      publicScanPath("/threat-analysis"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<ThreatAnalysis>(`/api/scan/${scanId}/threat-analysis`);
  return data;
}
