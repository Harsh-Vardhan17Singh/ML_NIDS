import React from "react";
import { ModelStatusInfo } from "../types";

interface ModelCardViewProps {
  modelInfo: ModelStatusInfo;
}

export const ModelCardView: React.FC<ModelCardViewProps> = ({ modelInfo }) => {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Top Banner */}
      <div
        style={{
          backgroundColor: "#0f172a",
          border: "1px solid #1e293b",
          borderRadius: "12px",
          padding: "24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px"
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "22px", fontWeight: "700", color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace" }}>
              {modelInfo.model_version}
            </span>
            <span
              style={{
                backgroundColor: "rgba(16, 185, 129, 0.15)",
                color: "#34d399",
                border: "1px solid rgba(16, 185, 129, 0.4)",
                padding: "2px 8px",
                borderRadius: "6px",
                fontSize: "11px",
                fontWeight: "600"
              }}
            >
              ACTIVE PRODUCTION MODEL
            </span>
          </div>
          <div style={{ fontSize: "14px", color: "#94a3b8", marginTop: "6px" }}>
            Algorithm: <strong>{modelInfo.algorithm}</strong> | CPU Inference Pipeline | 71 RobustScaled Input Features
          </div>
        </div>

        <div style={{ display: "flex", gap: "20px" }}>
          <div style={{ backgroundColor: "#131d35", padding: "10px 16px", borderRadius: "8px", border: "1px solid #1e293b" }}>
            <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Decision Threshold</span>
            <div style={{ fontSize: "18px", fontWeight: "700", color: "#38bdf8", fontFamily: "'JetBrains Mono', monospace" }}>
              {modelInfo.optimal_threshold}
            </div>
          </div>
          <div style={{ backgroundColor: "#131d35", padding: "10px 16px", borderRadius: "8px", border: "1px solid #1e293b" }}>
            <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Inference Throughput</span>
            <div style={{ fontSize: "18px", fontWeight: "700", color: "#4ade80", fontFamily: "'JetBrains Mono', monospace" }}>
              {modelInfo.throughput_flows_per_sec.toLocaleString()} flows/s
            </div>
          </div>
        </div>
      </div>

      {/* Held-out Metrics Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px" }}>
        <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase" }}>Held-Out Precision</span>
          <div style={{ fontSize: "32px", fontWeight: "700", color: "#34d399", fontFamily: "'JetBrains Mono', monospace", marginTop: "8px" }}>
            {(modelInfo.test_precision * 100).toFixed(2)}%
          </div>
          <span style={{ fontSize: "11px", color: "#64748b" }}>99.86% genuine positive alert rate</span>
        </div>

        <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase" }}>Detection Recall</span>
          <div style={{ fontSize: "32px", fontWeight: "700", color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace", marginTop: "8px" }}>
            {(modelInfo.test_recall * 100).toFixed(2)}%
          </div>
          <span style={{ fontSize: "11px", color: "#64748b" }}>Comprehensive malicious flow capture</span>
        </div>

        <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase" }}>Held-Out F1-Score</span>
          <div style={{ fontSize: "32px", fontWeight: "700", color: "#a78bfa", fontFamily: "'JetBrains Mono', monospace", marginTop: "8px" }}>
            {(modelInfo.test_f1 * 100).toFixed(2)}%
          </div>
          <span style={{ fontSize: "11px", color: "#64748b" }}>Harmonic balance under class imbalance</span>
        </div>

        <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
          <span style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase" }}>False Alarm Rate</span>
          <div style={{ fontSize: "32px", fontWeight: "700", color: "#38bdf8", fontFamily: "'JetBrains Mono', monospace", marginTop: "8px" }}>
            {(modelInfo.false_positive_rate * 100).toFixed(4)}%
          </div>
          <span style={{ fontSize: "11px", color: "#64748b" }}>Only 0.03% false alarms on benign flows</span>
        </div>
      </div>

      {/* Operational Principles */}
      <div style={{ backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
        <h4 style={{ fontSize: "16px", fontWeight: "600", color: "#f8fafc", margin: "0 0 12px 0" }}>
          Model Operational Principles & Boundaries
        </h4>
        <ul style={{ color: "#94a3b8", fontSize: "14px", lineHeight: "1.7", margin: 0, paddingLeft: "20px" }}>
          <li>
            <strong>Training-Serving Feature Parity:</strong> The live inference engine computes the identical 71 numerical features and applies the frozen <code style={{ color: "#60a5fa" }}>RobustScaler</code> pipeline serialized during Phase 2.
          </li>
          <li>
            <strong>Metadata-First Classification:</strong> IP addresses and raw timestamps were deliberately stripped during training to prevent identity memorization and ensure real-world generalization across diverse network segments.
          </li>
          <li>
            <strong>Passive Alerting:</strong> Model detections trigger investigative alerts and do not execute automatic firewall mutations or active traffic interruption.
          </li>
          <li>
            <strong>Dual-Engine Architecture:</strong> Model predictions operate in tandem with deterministic rule engines (Connection Bursts, Port Scan Probing).
          </li>
        </ul>
      </div>
    </div>
  );
};

