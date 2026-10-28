import React from "react";
import { SensorStatusItem } from "../types";

interface SensorTableProps {
  sensors: SensorStatusItem[];
  loading: boolean;
}

export const SensorTable: React.FC<SensorTableProps> = ({ sensors, loading }) => {
  return (
    <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
      <div style={{ marginBottom: "16px" }}>
        <h3 style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc", margin: "0 0 4px 0" }}>
          Monitored Sensor Infrastructure
        </h3>
        <p style={{ fontSize: "13px", color: "#94a3b8", margin: 0 }}>
          Real-time health, connectivity, and telemetry throughput across authorized network collection sensors.
        </p>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
          <thead>
            <tr style={{ backgroundColor: "#131d35", borderBottom: "1px solid #1e293b", color: "#94a3b8" }}>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Sensor Identifier</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Display Name</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Live Status</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Total Ingested Flows</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Last Heartbeat (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} style={{ padding: "24px", textAlign: "center", color: "#94a3b8" }}>
                  Querying sensor status...
                </td>
              </tr>
            ) : sensors.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: "32px", textAlign: "center", color: "#64748b" }}>
                  No active sensors currently registered.
                </td>
              </tr>
            ) : (
              sensors.map((s) => (
                <tr key={s.sensor_id} style={{ borderBottom: "1px solid #1e293b" }}>
                  <td style={{ padding: "12px 14px", fontWeight: "600", fontFamily: "'JetBrains Mono', monospace", color: "#60a5fa" }}>
                    {s.sensor_id}
                  </td>
                  <td style={{ padding: "12px 14px", color: "#f8fafc" }}>
                    {s.name}
                  </td>
                  <td style={{ padding: "12px 14px" }}>
                    {s.is_online ? (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                          backgroundColor: "rgba(16, 185, 129, 0.15)",
                          color: "#34d399",
                          padding: "3px 8px",
                          borderRadius: "6px",
                          fontSize: "11px",
                          fontWeight: "600"
                        }}
                      >
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#34d399" }} className="pulse-green" />
                        ONLINE
                      </span>
                    ) : (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                          backgroundColor: "rgba(148, 163, 184, 0.15)",
                          color: "#94a3b8",
                          padding: "3px 8px",
                          borderRadius: "6px",
                          fontSize: "11px",
                          fontWeight: "600"
                        }}
                      >
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#94a3b8" }} />
                        STALE / OFFLINE
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "12px 14px", fontFamily: "'JetBrains Mono', monospace", color: "#38bdf8", fontWeight: "600" }}>
                    {s.flow_count.toLocaleString()} flows
                  </td>
                  <td style={{ padding: "12px 14px", color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
                    {new Date(s.last_seen_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

