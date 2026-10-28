import React from "react";

interface StatusBadgeProps {
  status: "new" | "investigating" | "true_positive" | "false_positive" | "resolved" | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const stat = status.toLowerCase();

  const labels: Record<string, { label: string; color: string; bg: string }> = {
    new: { label: "NEW", color: "#38bdf8", bg: "rgba(56, 189, 248, 0.12)" },
    investigating: { label: "INVESTIGATING", color: "#fbbf24", bg: "rgba(251, 191, 36, 0.12)" },
    true_positive: { label: "TRUE POSITIVE", color: "#f87171", bg: "rgba(248, 113, 113, 0.15)" },
    false_positive: { label: "FALSE POSITIVE", color: "#94a3b8", bg: "rgba(148, 163, 184, 0.12)" },
    resolved: { label: "RESOLVED", color: "#4ade80", bg: "rgba(74, 222, 128, 0.12)" }
  };

  const current = labels[stat] || { label: stat.toUpperCase(), color: "#cbd5e1", bg: "rgba(148, 163, 184, 0.1)" };

  return (
    <span
      style={{
        backgroundColor: current.bg,
        color: current.color,
        border: `1px solid ${current.color}40`,
        padding: "3px 8px",
        borderRadius: "6px",
        fontSize: "11px",
        fontWeight: "600",
        letterSpacing: "0.3px",
        display: "inline-block"
      }}
    >
      {current.label}
    </span>
  );
};

