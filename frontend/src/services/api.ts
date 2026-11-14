
const API_BASE_URL = "http://localhost:8000";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  agent_id: string;
  tool_name: string;
  operation: string;
  resource: string | null;
  decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  reason: string;
  executed: boolean;
  previous_hash: string | null;
  event_hash: string | null;
}

export interface SecurityEventsResponse {
  total: number;
  events: SecurityEvent[];
}

export interface IntegrityReport {
  valid: boolean;
  checked_events: number;
  legacy_events: number;
  legacy_events_verified: boolean;
  failed_event_id: string | null;
  reason: string;
}

export interface Anomaly {
  agent_id: string;
  anomaly_type: string;
  severity: string;
  count: number;
  threshold: number;
  event_ids: string[];
  explanation: string;
}

export interface AnomalyReport {
  monitoring_window_seconds: number;
  events_analyzed: number;
  agents_analyzed: number;
  total_anomalies: number;
  anomalies: Anomaly[];
}

async function apiRequest<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`);

  if (!response.ok) {
    throw new Error(
      `API request failed: ${response.status} ${response.statusText}`
    );
  }

  return response.json() as Promise<T>;
}

export const api = {
  getHealth: () =>
    apiRequest<{ status: string; service: string; timestamp: string }>("/health"),

  getEvents: (limit = 100) =>
    apiRequest<SecurityEventsResponse>(`/security/events?limit=${limit}`),

  getIntegrity: () =>
    apiRequest<IntegrityReport>("/security/verify"),

  getAnomalies: () =>
    apiRequest<AnomalyReport>("/security/anomalies"),
};
