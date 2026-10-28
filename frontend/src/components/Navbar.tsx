import React from "react";

interface NavbarProps {
  activeTab: "overview" | "alerts" | "sensors" | "model";
  onTabChange: (tab: "overview" | "alerts" | "sensors" | "model") => void;
  systemReady: boolean;
  onRefresh: () => void;
  refreshing: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  systemReady,
  onRefresh,
  refreshing
}) => {
  const tabs: Array<{ id: "overview" | "alerts" | "sensors" | "model"; label: string; icon: string }> = [
    { id: "overview", label: "Overview", icon: "📊" },
    { id: "alerts", label: "Alerts & Investigation", icon: "🚨" },
    { id: "sensors", label: "Sensors Health", icon: "📡" },
    { id: "model", label: "Model Card & Metrics", icon: "🧠" }
  ];

  return (
    <header
      style={{
        backgroundColor: "#0b1222",
        borderBottom: "1px solid #1e293b",
        padding: "14px 28px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        position: "sticky",
        top: 0,
        zIndex: 100
      }}
    >
      {/* Brand */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div
          style={{
            width: "36px",
            height: "36px",
            borderRadius: "8px",
            backgroundColor: "#2563eb",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "18px",
            color: "#ffffff",
            boxShadow: "0 0 15px rgba(37, 99, 235, 0.5)"
          }}
        >
          🛡️
        </div>
        <div>
          <div style={{ fontSize: "17px", fontWeight: "800", letterSpacing: "0.5px", color: "#f8fafc" }}>
            Sentinel<span style={{ color: "#38bdf8" }}>NIDS</span>
          </div>
          <div style={{ fontSize: "10px", color: "#64748b", textTransform: "uppercase", letterSpacing: "1px" }}>
            ML Network Intrusion Detection
          </div>
        </div>
      </div>

      {/* Navigation Pills */}
      <nav style={{ display: "flex", gap: "6px", backgroundColor: "#0f172a", padding: "4px", borderRadius: "10px", border: "1px solid #1e293b" }}>
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              style={{
                backgroundColor: isActive ? "#2563eb" : "transparent",
                color: isActive ? "#ffffff" : "#94a3b8",
                border: "none",
                borderRadius: "8px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: isActive ? "600" : "500",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                transition: "all 0.15s ease"
              }}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* System Status & Actions */}
      <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "5px 10px",
            borderRadius: "20px",
            backgroundColor: systemReady ? "rgba(16, 185, 129, 0.12)" : "rgba(239, 68, 68, 0.12)",
            border: `1px solid ${systemReady ? "#10b98140" : "#ef444440"}`,
            fontSize: "11px",
            fontWeight: "600",
            color: systemReady ? "#34d399" : "#f87171"
          }}
        >
          <span
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              backgroundColor: systemReady ? "#34d399" : "#f87171"
            }}
            className={systemReady ? "pulse-green" : ""}
          />
          {systemReady ? "ENGINE ONLINE" : "ENGINE DEGRADED"}
        </div>

        <button
          onClick={onRefresh}
          disabled={refreshing}
          title="Refresh telemetry"
          style={{
            backgroundColor: "#1e293b",
            border: "1px solid #334155",
            color: "#f8fafc",
            width: "34px",
            height: "34px",
            borderRadius: "8px",
            cursor: refreshing ? "not-allowed" : "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "14px",
            transition: "all 0.15s ease"
          }}
        >
          {refreshing ? "⏳" : "🔄"}
        </button>
      </div>
    </header>
  );
};

