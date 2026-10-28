import React from "react";
import { AlertItem } from "../types";
import { SeverityBadge } from "./SeverityBadge";
import { StatusBadge } from "./StatusBadge";

interface AlertTableProps {
  alerts: AlertItem[];
  total: number;
  page: number;
  pageSize: number;
  severityFilter: string;
  statusFilter: string;
  searchTerm: string;
  onPageChange: (newPage: number) => void;
  onSeverityChange: (sev: string) => void;
  onStatusChange: (stat: string) => void;
  onSearchChange: (search: string) => void;
  onSelectAlert: (alertId: string) => void;
  loading: boolean;
}

export const AlertTable: React.FC<AlertTableProps> = ({
  alerts,
  total,
  page,
  pageSize,
  severityFilter,
  statusFilter,
  searchTerm,
  onPageChange,
  onSeverityChange,
  onStatusChange,
  onSearchChange,
  onSelectAlert,
  loading
}) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  // Client-side search filtering on currently loaded page
  const filteredAlerts = alerts.filter((a) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      a.alert_id.toLowerCase().includes(term) ||
      a.summary.toLowerCase().includes(term) ||
      a.dedup_key.toLowerCase().includes(term) ||
      a.reason.toLowerCase().includes(term)
    );
  });

  return (
    <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
      {/* Filters Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "16px", marginBottom: "16px", flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: "12px", alignItems: "center", flex: 1, minWidth: "260px" }}>
          <input
            type="text"
            placeholder="Search Alert ID, IP, or keyword..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            style={{
              flex: 1,
              backgroundColor: "#131d35",
              border: "1px solid #334155",
              color: "#f8fafc",
              padding: "8px 14px",
              borderRadius: "8px",
              fontSize: "13px"
            }}
          />
        </div>

        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => onSeverityChange(e.target.value)}
            style={{
              backgroundColor: "#131d35",
              border: "1px solid #334155",
              color: "#f8fafc",
              padding: "8px 12px",
              borderRadius: "8px",
              fontSize: "13px"
            }}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Dropdown */}
          <select
            value={statusFilter}
            onChange={(e) => onStatusChange(e.target.value)}
            style={{
              backgroundColor: "#131d35",
              border: "1px solid #334155",
              color: "#f8fafc",
              padding: "8px 12px",
              borderRadius: "8px",
              fontSize: "13px"
            }}
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="true_positive">True Positive</option>
            <option value="false_positive">False Positive</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Table Container */}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
          <thead>
            <tr style={{ backgroundColor: "#131d35", borderBottom: "1px solid #1e293b", color: "#94a3b8" }}>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Alert ID</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Severity</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Status</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Summary & Primary Indicator</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>ML Score</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Events</th>
              <th style={{ padding: "12px 14px", fontWeight: "600" }}>Last Observed</th>
              <th style={{ padding: "12px 14px", textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} style={{ padding: "32px", textAlign: "center", color: "#94a3b8" }}>
                  Loading telemetry alerts...
                </td>
              </tr>
            ) : filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: "40px", textAlign: "center", color: "#64748b" }}>
                  No security alerts matching current filters.
                </td>
              </tr>
            ) : (
              filteredAlerts.map((a) => (
                <tr
                  key={a.alert_id}
                  style={{
                    borderBottom: "1px solid #1e293b",
                    cursor: "pointer",
                    transition: "background-color 0.15s"
                  }}
                  onClick={() => onSelectAlert(a.alert_id)}
                  className="table-row-hover"
                >
                  <td style={{ padding: "12px 14px", fontWeight: "700", fontFamily: "'JetBrains Mono', monospace", color: "#60a5fa" }}>
                    {a.alert_id}
                  </td>
                  <td style={{ padding: "12px 14px" }}>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td style={{ padding: "12px 14px" }}>
                    <StatusBadge status={a.status} />
                  </td>
                  <td style={{ padding: "12px 14px", maxWidth: "300px" }}>
                    <div style={{ fontWeight: "600", color: "#f8fafc", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.summary}
                    </div>
                    <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                      Key: {a.dedup_key}
                    </div>
                  </td>
                  <td style={{ padding: "12px 14px", fontFamily: "'JetBrains Mono', monospace" }}>
                    {a.model_score !== null ? (
                      <span style={{ fontWeight: "700", color: a.model_score >= 0.65 ? "#f87171" : "#4ade80" }}>
                        {(a.model_score * 100).toFixed(1)}%
                      </span>
                    ) : (
                      <span style={{ color: "#64748b" }}>Rule-only</span>
                    )}
                  </td>
                  <td style={{ padding: "12px 14px", fontFamily: "'JetBrains Mono', monospace", color: "#38bdf8" }}>
                    {a.event_count}
                  </td>
                  <td style={{ padding: "12px 14px", color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
                    {new Date(a.last_seen_at).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: "12px 14px", textAlign: "right" }}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(a.alert_id);
                      }}
                      style={{
                        backgroundColor: "#1e293b",
                        border: "1px solid #334155",
                        color: "#93c5fd",
                        padding: "4px 10px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        cursor: "pointer",
                        fontWeight: "500"
                      }}
                    >
                      Investigate →
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "16px", paddingTop: "12px", borderTop: "1px solid #1e293b", fontSize: "13px", color: "#94a3b8" }}>
        <div>
          Showing {filteredAlerts.length} of {total} total alerts
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            style={{
              backgroundColor: "#131d35",
              border: "1px solid #334155",
              color: page <= 1 ? "#475569" : "#f8fafc",
              padding: "6px 12px",
              borderRadius: "6px",
              cursor: page <= 1 ? "not-allowed" : "pointer",
              fontSize: "12px"
            }}
          >
            ← Previous
          </button>
          <span>
            Page <strong>{page}</strong> of <strong>{totalPages}</strong>
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            style={{
              backgroundColor: "#131d35",
              border: "1px solid #334155",
              color: page >= totalPages ? "#475569" : "#f8fafc",
              padding: "6px 12px",
              borderRadius: "6px",
              cursor: page >= totalPages ? "not-allowed" : "pointer",
              fontSize: "12px"
            }}
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  );
};

