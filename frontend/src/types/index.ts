export interface AlertItem {
  alert_id: string;
  dedup_key: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "new" | "investigating" | "true_positive" | "false_positive" | "resolved";
  decision: string;
  summary: string;
  reason: string;
  matched_rules: string[];
  model_score: number | null;
  model_version: string | null;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
}

export interface AlertListResponse {
  total: number;
  page: number;
  page_size: number;
  items: AlertItem[];
}

export interface FlowEvidence {
  id: number;
  sensor_id: string;
  event_id: string;
  observed_at: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  duration_ms: number;
  packets_out: number;
  packets_in: number;
  bytes_out: number;
  bytes_in: number;
}

export interface FeedbackItem {
  id: number;
  analyst_email: string;
  disposition: string;
  note: string | null;
  created_at: string;
}

export interface AlertDetailResponse extends AlertItem {
  created_at: string;
  updated_at: string;
  feedbacks: FeedbackItem[];
  sample_flows: FlowEvidence[];
}

export interface SeverityDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface StatusDistribution {
  new: number;
  investigating: number;
  true_positive: number;
  false_positive: number;
  resolved: number;
}

export interface SensorStatusItem {
  sensor_id: string;
  name: string;
  enabled: boolean;
  last_seen_at: string;
  is_online: boolean;
  flow_count: number;
}

export interface ModelStatusInfo {
  model_version: string;
  algorithm: string;
  optimal_threshold: number;
  test_accuracy: number;
  test_f1: number;
  test_precision: number;
  test_recall: number;
  false_positive_rate: number;
  throughput_flows_per_sec: number;
  status: string;
}

export interface DashboardSummary {
  total_flows: number;
  total_alerts: number;
  active_alerts: number;
  resolved_alerts: number;
  severity_distribution: SeverityDistribution;
  status_distribution: StatusDistribution;
  active_sensors_count: number;
  sensors: SensorStatusItem[];
  model_info: ModelStatusInfo;
  last_ingestion_time: string | null;
}
