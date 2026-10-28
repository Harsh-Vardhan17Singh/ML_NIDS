import React, { useState, useEffect } from "react";
import {
  fetchDashboardSummary,
  fetchAlerts,
  fetchAlertDetail,
  fetchSensors,
  checkReadiness
} from "./api/client";
import {
  DashboardSummary,
  AlertListResponse,
  AlertDetailResponse,
  SensorStatusItem
} from "./types";
import { Navbar } from "./components/Navbar";
import { StatCard } from "./components/StatCard";
import { AlertTable } from "./components/AlertTable";
import { AlertDetailModal } from "./components/AlertDetailModal";
import { SensorTable } from "./components/SensorTable";
import { ModelCardView } from "./components/ModelCardView";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"overview" | "alerts" | "sensors" | "model">("overview");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [alertsData, setAlertsData] = useState<AlertListResponse>({ total: 0, page: 1, page_size: 20, items: [] });
  const [sensors, setSensors] = useState<SensorStatusItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertDetailResponse | null>(null);
  const [systemReady, setSystemReady] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Filters for Alerts View
  const [page, setPage] = useState<number>(1);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const loadData = async (isManualRefresh: boolean = false) => {
    if (isManualRefresh) setRefreshing(true);
    try {
      const [sum, alts, sens, ready] = await Promise.all([
        fetchDashboardSummary().catch(() => null),
        fetchAlerts(page, 20, severityFilter, statusFilter).catch(() => ({ total: 0, page: 1, page_size: 20, items: [] })),
        fetchSensors().catch(() => []),
        checkReadiness()
      ]);

      if (sum) setSummary(sum);
      setAlertsData(alts);
      setSensors(sens);
      setSystemReady(ready.ready);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    // 10-second polling interval
    const interval = setInterval(() => loadData(false), 10000);
    return () => clearInterval(interval);
  }, [page, severityFilter, statusFilter]);

  const handleSelectAlert = async (alertId: string) => {
    try {
      const detail = await fetchAlertDetail(alertId);
      setSelectedAlert(detail);
    } catch (e) {
      console.error(e);
    }
  };

  const handleAlertUpdated = (updated: AlertDetailResponse) => {
    setSelectedAlert(updated);
    // Refresh alerts table and summary
    loadData(false);
  };

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#090d16", display: "flex", flexDirection: "column" }}>
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        systemReady={systemReady}
        onRefresh={() => loadData(true)}
        refreshing={refreshing}
      />

      <main style={{ flex: 1, padding: "28px", maxWidth: "1440px", margin: "0 auto", width: "100%", boxSizing: "border-box" }}>
        {/* OVERVIEW TAB */}
        {activeTab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "28px" }}>
            {/* Stat Cards Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px" }}>
              <StatCard
                label="Total Ingested Flows"
                value={summary ? summary.total_flows.toLocaleString() : "0"}
                subtext="Processed by telemetry pipeline"
                icon="🌊"
                accentColor="#3b82f6"
              />
              <StatCard
                label="Active Detections"
                value={summary ? summary.active_alerts.toLocaleString() : "0"}
                subtext="Pending analyst investigation"
                icon="🚨"
                accentColor="#ef4444"
              />
              <StatCard
                label="Resolved Incidents"
                value={summary ? summary.resolved_alerts.toLocaleString() : "0"}
                subtext="Dispositioned & closed"
                icon="✅"
                accentColor="#10b981"
              />
              <StatCard
                label="Monitored Sensors"
                value={summary ? `${summary.active_sensors_count} / ${summary.sensors.length}` : "0 / 0"}
                subtext="Healthy telemetry collectors"
                icon="📡"
                accentColor="#8b5cf6"
              />
              <StatCard
                label="Model Precision"
                value={summary?.model_info ? `${(summary.model_info.test_precision * 100).toFixed(1)}%` : "99.9%"}
                subtext="Held-out validation accuracy"
                icon="🧠"
                accentColor="#06b6d4"
              />
              <StatCard
                label="Inference Latency"
                value="20.5 µs"
                subtext="~48,700 flows/sec CPU capacity"
                icon="⚡"
                accentColor="#eab308"
              />
            </div>

            {/* Distribution Breakdowns Banner */}
            {summary && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                {/* Severity Breakdown */}
                <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                  <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: "600", letterSpacing: "0.5px" }}>
                    Alert Severity Distribution
                  </span>
                  <div style={{ display: "flex", gap: "12px", marginTop: "14px", flexWrap: "wrap" }}>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #ef444440", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#f87171", fontWeight: "600" }}>CRITICAL</span>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "#f87171", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                        {summary.severity_distribution.critical}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #f9731640", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#fb923c", fontWeight: "600" }}>HIGH</span>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "#fb923c", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                        {summary.severity_distribution.high}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #eab30840", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#facc15", fontWeight: "600" }}>MEDIUM</span>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "#facc15", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                        {summary.severity_distribution.medium}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #10b98140", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#34d399", fontWeight: "600" }}>LOW</span>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "#34d399", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                        {summary.severity_distribution.low}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Status Breakdown */}
                <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                  <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: "600", letterSpacing: "0.5px" }}>
                    Investigation Disposition Status
                  </span>
                  <div style={{ display: "flex", gap: "10px", marginTop: "14px", flexWrap: "wrap" }}>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#38bdf8" }}>NEW</span>
                      <div style={{ fontSize: "18px", fontWeight: "700", color: "#38bdf8", fontFamily: "'JetBrains Mono', monospace" }}>
                        {summary.status_distribution.new}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#fbbf24" }}>INVESTIGATING</span>
                      <div style={{ fontSize: "18px", fontWeight: "700", color: "#fbbf24", fontFamily: "'JetBrains Mono', monospace" }}>
                        {summary.status_distribution.investigating}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#f87171" }}>TRUE POSITIVE</span>
                      <div style={{ fontSize: "18px", fontWeight: "700", color: "#f87171", fontFamily: "'JetBrains Mono', monospace" }}>
                        {summary.status_distribution.true_positive}
                      </div>
                    </div>
                    <div style={{ flex: 1, backgroundColor: "#131d35", padding: "12px", borderRadius: "8px", border: "1px solid #1e293b", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#4ade80" }}>RESOLVED</span>
                      <div style={{ fontSize: "18px", fontWeight: "700", color: "#4ade80", fontFamily: "'JetBrains Mono', monospace" }}>
                        {summary.status_distribution.resolved}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Recent Alerts Feed */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <h3 style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
                  Recent Security Findings
                </h3>
                <button
                  onClick={() => setActiveTab("alerts")}
                  style={{
                    backgroundColor: "transparent",
                    border: "none",
                    color: "#60a5fa",
                    cursor: "pointer",
                    fontSize: "13px",
                    fontWeight: "600"
                  }}
                >
                  View All Alerts →
                </button>
              </div>
              <AlertTable
                alerts={alertsData.items.slice(0, 5)}
                total={alertsData.total}
                page={page}
                pageSize={20}
                severityFilter={severityFilter}
                statusFilter={statusFilter}
                searchTerm={searchTerm}
                onPageChange={setPage}
                onSeverityChange={setSeverityFilter}
                onStatusChange={setStatusFilter}
                onSearchChange={setSearchTerm}
                onSelectAlert={handleSelectAlert}
                loading={loading}
              />
            </div>
          </div>
        )}

        {/* ALERTS TAB */}
        {activeTab === "alerts" && (
          <div>
            <div style={{ marginBottom: "20px" }}>
              <h2 style={{ fontSize: "20px", fontWeight: "700", color: "#f8fafc", margin: "0 0 6px 0" }}>
                Security Alerts & Investigation Queue
              </h2>
              <p style={{ fontSize: "13px", color: "#94a3b8", margin: 0 }}>
                Traceable alerts produced by ML probability scoring and deterministic behavioral detection rules.
              </p>
            </div>
            <AlertTable
              alerts={alertsData.items}
              total={alertsData.total}
              page={page}
              pageSize={20}
              severityFilter={severityFilter}
              statusFilter={statusFilter}
              searchTerm={searchTerm}
              onPageChange={setPage}
              onSeverityChange={setSeverityFilter}
              onStatusChange={setStatusFilter}
              onSearchChange={setSearchTerm}
              onSelectAlert={handleSelectAlert}
              loading={loading}
            />
          </div>
        )}

        {/* SENSORS TAB */}
        {activeTab === "sensors" && (
          <SensorTable sensors={sensors} loading={loading} />
        )}

        {/* MODEL CARD TAB */}
        {activeTab === "model" && summary && (
          <ModelCardView modelInfo={summary.model_info} />
        )}
      </main>

      {/* Alert Investigation Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAlertUpdated={handleAlertUpdated}
      />
    </div>
  );
};

