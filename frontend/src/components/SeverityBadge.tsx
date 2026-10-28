import React from "react";

interface SeverityBadgeProps {
  severity: "low" | "medium" | "high" | "critical" | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const sev = severity.toLowerCase();

  const styles: Record<string, { bg: string; text: string; border: string; label: string }> = {
    critical: {
      bg: "rgba(239, 68, 68, 0.15)",
      text: "#f87171",
      border: "rgba(239, 68, 68, 0.4)",
      label: "CRITICAL"
    },
    high: {
      bg: "rgba(249, 115, 22, 0.15)",
      text: "#fb923c",
      border: "rgba(249, 115, 22, 0.4)",
      label: "HIGH"
    },
    medium: {
      bg: "rgba(234, 179, 8, 0.15)",
      text: "#facc15",
      border: "rgba(234, 179, 8, 0.4)",
      label: "MEDIUM"
    },
    low: {
      bg: "rgba(16, 185, 129, 0.15)",
      text: "#34d399",
      border: "rgba(16, 185, 129, 0.4)",
      label: "LOW"
    }
  };

  const style = styles[sev] || {
    bg: "rgba(148, 163, 184, 0.15)",
    text: "#cbd5e1",
    border: "rgba(148, 163, 184, 0.3)",
    label: sev.toUpperCase()
  };

  return (
    <span
      style={{
        backgroundColor: style.bg,
        color: style.text,
        borderColor: style.border,
        borderWidth: "1px",
        borderStyle: "solid",
        padding: "3px 8px",
        borderRadius: "6px",
        fontSize: "11px",
        fontWeight: "600",
        letterSpacing: "0.5px",
        display: "inline-flex",
        alignItems: "center",
        gap: "4px"
      }}
    >
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          backgroundColor: style.text
        }}
      />
      {style.label}
    </span>
  );
};

