import React from "react";

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: string;
  accentColor?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtext,
  icon = "🛡️",
  accentColor = "#3b82f6"
}) => {
  return (
    <div
      style={{
        backgroundColor: "#131d35",
        border: "1px solid #1e293b",
        borderRadius: "12px",
        padding: "20px 24px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        boxShadow: "0 4px 15px rgba(0, 0, 0, 0.25)",
        position: "relative",
        overflow: "hidden"
      }}
    >
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: "4px",
          height: "100%",
          backgroundColor: accentColor
        }}
      />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "13px", fontWeight: "600", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" }}>
          {label}
        </span>
        <span style={{ fontSize: "20px", opacity: 0.8 }}>{icon}</span>
      </div>

      <div style={{ marginTop: "12px" }}>
        <div style={{ fontSize: "28px", fontWeight: "700", color: "#f8fafc", fontFamily: "'JetBrains Mono', monospace" }}>
          {value}
        </div>
        {subtext && (
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            {subtext}
          </div>
        )}
      </div>
    </div>
  );
};

