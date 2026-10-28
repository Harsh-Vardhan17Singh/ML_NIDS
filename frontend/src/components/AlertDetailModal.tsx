import React, { useState } from "react";
import { AlertDetailResponse } from "../types";
import { SeverityBadge } from "./SeverityBadge";
import { StatusBadge } from "./StatusBadge";
import { updateAlertStatus } from "../api/client";

interface AlertDetailModalProps {
  alert: AlertDetailResponse | null;
  onClose: () => void;
  onAlertUpdated: (updated: AlertDetailResponse) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onAlertUpdated
}) => {
  if (!alert) return null;

  const [selectedStatus, setSelectedStatus] = useState<string>(alert.status);
  const [analystNote, setAnalystNote] = useState<string>("");
  const [analystEmail, setAnalystEmail] = useState<string>("analyst@sentinelnids.local");
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setErrorMsg(null);
    try {
      const updated = await updateAlertStatus(
        alert.alert_id,
        selectedStatus,
        analystNote,
        analystEmail
      );
      onAlertUpdated(updated);
      setAnalystNote("");
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to update alert status");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(5, 8, 16, 0.8)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "20px"
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: "#0f172a",
          border: "1px solid #1e293b",
          borderRadius: "16px",
          width: "100%",
          maxWidth: "850px",
          maxHeight: "90vh",
          overflowY: "auto",
          padding: "28px",
          color: "#f8fafc",
          boxShadow: "0 20px 40px rgba(0, 0, 0, 0.6)"
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "1px solid #1e293b", paddingBottom: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ fontSize: "20px", fontWeight: "700", fontFamily: "'JetBrains Mono', monospace", color: "#60a5fa" }}>
                {alert.alert_id}
              </span>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
            <div style={{ fontSize: "14px", color: "#94a3b8", marginTop: "6px" }}>
              {alert.summary}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              fontSize: "22px",
              cursor: "pointer",
              padding: "4px 8px"
            }}
          >
            ✕
          </button>
        </div>

        {/* Overview Details Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px", marginTop: "20px" }}>
          <div style={{ backgroundColor: "#131d35", padding: "12px 16px", borderRadius: "8px", border: "1px solid #1e293b" }}>
            <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>First Observed</span>
            <div style={{ fontSize: "13px", fontWeight: "600", color: "#e2e8f0", marginTop: "4px", fontFamily: "'JetBrains Mono', monospace" }}>
              {new Date(alert.first_seen_at).toLocaleString()}
            </div>
          </div>
          <div style={{ backgroundColor: "#131d35", padding: "12px 16px", borderRadius: "8px", border: "1px solid #1e293b" }}>
            <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Last Active</span>
            <div style={{ fontSize: "13px", fontWeight: "600", color: "#e2e8f0", marginTop: "4px", fontFamily: "'JetBrains Mono', monospace" }}>
              {new Date(alert.last_seen_at).toLocaleString()}
            </div>
          </div>
          <div style={{ backgroundColor: "#131d35", padding: "12px 16px", borderRadius: "8px", border: "1px solid #1e293b" }}>
            <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Aggregated Events</span>
            <div style={{ fontSize: "13px", fontWeight: "700", color: "#38bdf8", marginTop: "4px", fontFamily: "'JetBrains Mono', monospace" }}>
              {alert.event_count} flows
            </div>
          </div>
        </div>

        {/* Detection Evidence */}
        <div style={{ marginTop: "24px" }}>
          <h4 style={{ fontSize: "14px", fontWeight: "600", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 10px 0" }}>
            Detection Engine Evidence
          </h4>
          <div style={{ backgroundColor: "#131d35", border: "1px solid #1e293b", borderRadius: "8px", padding: "16px" }}>
            <div style={{ whiteSpace: "pre-wrap", fontSize: "13px", color: "#cbd5e1", lineHeight: "1.5" }}>
              {alert.reason}
            </div>

            {alert.model_score !== null && (
              <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid #1e293b", display: "flex", gap: "20px" }}>
                <div>
                  <span style={{ fontSize: "11px", color: "#94a3b8" }}>ML Confidence Score:</span>{" "}
                  <span style={{ fontWeight: "700", color: alert.model_score >= 0.65 ? "#f87171" : "#4ade80", fontFamily: "'JetBrains Mono', monospace" }}>
                    {(alert.model_score * 100).toFixed(1)}%
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: "11px", color: "#94a3b8" }}>Active Model:</span>{" "}
                  <span style={{ fontWeight: "600", color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace" }}>
                    {alert.model_version || "flow-v1.0.0"}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Related Flow Evidence */}
        {alert.sample_flows && alert.sample_flows.length > 0 && (
          <div style={{ marginTop: "24px" }}>
            <h4 style={{ fontSize: "14px", fontWeight: "600", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 10px 0" }}>
              Sample Flow Telemetry ({alert.sample_flows.length} recent records)
            </h4>
            <div style={{ overflowX: "auto", border: "1px solid #1e293b", borderRadius: "8px" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace" }}>
                <thead>
                  <tr style={{ backgroundColor: "#131d35", color: "#94a3b8", borderBottom: "1px solid #1e293b" }}>
                    <th style={{ padding: "8px 12px" }}>Source IP</th>
                    <th style={{ padding: "8px 12px" }}>Dest IP</th>
                    <th style={{ padding: "8px 12px" }}>Proto/Port</th>
                    <th style={{ padding: "8px 12px" }}>Packets (Out/In)</th>
                    <th style={{ padding: "8px 12px" }}>Bytes (Out/In)</th>
                    <th style={{ padding: "8px 12px" }}>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {alert.sample_flows.map((f, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #1e293b", color: "#cbd5e1" }}>
                      <td style={{ padding: "8px 12px" }}>{f.src_ip}:{f.src_port || "-"}</td>
                      <td style={{ padding: "8px 12px" }}>{f.dst_ip}</td>
                      <td style={{ padding: "8px 12px", color: "#60a5fa" }}>{f.protocol.toUpperCase()}/{f.dst_port || "-"}</td>
                      <td style={{ padding: "8px 12px" }}>{f.packets_out} / {f.packets_in}</td>
                      <td style={{ padding: "8px 12px" }}>{f.bytes_out} / {f.bytes_in}</td>
                      <td style={{ padding: "8px 12px" }}>{f.duration_ms.toFixed(1)}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Analyst Disposition Controls */}
        <div style={{ marginTop: "28px", borderTop: "1px solid #1e293b", paddingTop: "20px" }}>
          <h4 style={{ fontSize: "14px", fontWeight: "600", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 12px 0" }}>
            Analyst Review & Disposition
          </h4>
          <form onSubmit={handleUpdate} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {errorMsg && (
              <div style={{ backgroundColor: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", color: "#f87171", padding: "10px", borderRadius: "6px", fontSize: "13px" }}>
                {errorMsg}
              </div>
            )}
            <div style={{ display: "flex", gap: "16px" }}>
              <div style={{ flex: 1 }}>
                <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "4px" }}>
                  Review Disposition Status:
                </label>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  style={{
                    width: "100%",
                    backgroundColor: "#131d35",
                    border: "1px solid #334155",
                    color: "#f8fafc",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "13px"
                  }}
                >
                  <option value="new">New (Unreviewed)</option>
                  <option value="investigating">Investigating</option>
                  <option value="true_positive">True Positive (Confirmed Incident)</option>
                  <option value="false_positive">False Positive (Benign Pattern)</option>
                  <option value="resolved">Resolved / Mitigated</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "4px" }}>
                  Analyst Identity:
                </label>
                <input
                  type="email"
                  value={analystEmail}
                  onChange={(e) => setAnalystEmail(e.target.value)}
                  style={{
                    width: "100%",
                    backgroundColor: "#131d35",
                    border: "1px solid #334155",
                    color: "#f8fafc",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "13px"
                  }}
                />
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "4px" }}>
                Investigation Note & Rationale:
              </label>
              <textarea
                rows={3}
                placeholder="Document findings, IOC validation, or false positive reason..."
                value={analystNote}
                onChange={(e) => setAnalystNote(e.target.value)}
                style={{
                  width: "100%",
                  backgroundColor: "#131d35",
                  border: "1px solid #334155",
                  color: "#f8fafc",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontFamily: "inherit",
                  resize: "vertical"
                }}
              />
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", marginTop: "8px" }}>
              <button
                type="button"
                onClick={onClose}
                style={{
                  backgroundColor: "transparent",
                  border: "1px solid #334155",
                  color: "#94a3b8",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontSize: "13px"
                }}
              >
                Close
              </button>
              <button
                type="submit"
                disabled={submitting}
                style={{
                  backgroundColor: "#2563eb",
                  border: "none",
                  color: "#ffffff",
                  padding: "8px 20px",
                  borderRadius: "6px",
                  fontWeight: "600",
                  cursor: submitting ? "not-allowed" : "pointer",
                  fontSize: "13px"
                }}
              >
                {submitting ? "Saving..." : "Commit Disposition"}
              </button>
            </div>
          </form>
        </div>

        {/* Disposition Audit History */}
        {alert.feedbacks && alert.feedbacks.length > 0 && (
          <div style={{ marginTop: "24px", borderTop: "1px solid #1e293b", paddingTop: "16px" }}>
            <h5 style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", marginBottom: "8px" }}>
              Analyst Audit History ({alert.feedbacks.length})
            </h5>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {alert.feedbacks.map((fb) => (
                <div key={fb.id} style={{ backgroundColor: "#131d35", padding: "8px 12px", borderRadius: "6px", fontSize: "12px", border: "1px solid #1e293b" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8" }}>
                    <span>{fb.analyst_email} marked as <strong style={{ color: "#38bdf8" }}>{fb.disposition.toUpperCase()}</strong></span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{new Date(fb.created_at).toLocaleString()}</span>
                  </div>
                  {fb.note && <div style={{ marginTop: "4px", color: "#cbd5e1" }}>"{fb.note}"</div>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

