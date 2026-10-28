import {
  DashboardSummary,
  AlertListResponse,
  AlertDetailResponse,
  SensorStatusItem
} from "../types";

const API_BASE = "";

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const res = await fetch(`${API_BASE}/api/v1/dashboard/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch dashboard summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlerts(
  page: number = 1,
  pageSize: number = 20,
  severity?: string,
  status?: string,
  sensorId?: string
): Promise<AlertListResponse> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize)
  });
  if (severity) params.append("severity", severity);
  if (status) params.append("status", status);
  if (sensorId) params.append("sensor_id", sensorId);

  const res = await fetch(`${API_BASE}/api/v1/alerts?${params.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertDetail(alertId: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert detail for ${alertId}: ${res.statusText}`);
  }
  return res.json();
}

export async function updateAlertStatus(
  alertId: string,
  status: string,
  note?: string,
  analystEmail: string = "analyst@sentinelnids.local"
): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, note, analyst_email: analystEmail })
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to update alert: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSensors(): Promise<SensorStatusItem[]> {
  const res = await fetch(`${API_BASE}/api/v1/sensors`);
  if (!res.ok) {
    throw new Error(`Failed to fetch sensors: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchModelInfo(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/model`);
  if (!res.ok) {
    throw new Error(`Failed to fetch model info: ${res.statusText}`);
  }
  return res.json();
}

export async function checkReadiness(): Promise<{ ready: boolean; checks: any }> {
  try {
    const res = await fetch(`${API_BASE}/health/ready`);
    const data = await res.json();
    return { ready: res.ok, checks: data.checks };
  } catch (e) {
    return { ready: false, checks: { error: String(e) } };
  }
}

