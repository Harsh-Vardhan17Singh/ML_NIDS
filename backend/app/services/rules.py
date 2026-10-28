"""
Deterministic Rule Engine for SentinelNIDS.
Evaluates behavioral patterns: connection bursts, port scans, and sensitive port probes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
from sensor.schemas import CanonicalFlow


class DetectionRuleResult:
    def __init__(self, rule_id: str, severity: str, message: str):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message


class DeterministicRuleEngine:
    """
    Evaluates in-memory sliding windows for connection rates and port scans.
    State is bounded and expires after sliding window to prevent memory leaks.
    """

    def __init__(self, config_path: str = "detection/rules.yaml"):
        self.config_path = Path(config_path)
        self.rules_config: Dict[str, Any] = {}
        self.load_config()

        # In-memory sliding window trackers:
        # src_ip -> list of (timestamp_utc, dst_ip, dst_port)
        self._history: Dict[str, List[Tuple[float, str, Optional[int]]]] = {}

    def load_config(self) -> None:
        if self.config_path.is_file() and YAML_AVAILABLE:
            try:
                with self.config_path.open("r", encoding="utf-8") as f:
                    self.rules_config = yaml.safe_load(f) or {}
                return
            except Exception:
                pass

        # Standard robust defaults
        self.rules_config = {
            "connection_rate": {"enabled": True, "window_seconds": 60, "threshold": 100, "severity": "medium"},
            "port_scan": {"enabled": True, "window_seconds": 60, "distinct_destination_ports_threshold": 20, "severity": "high"},
            "sensitive_port_probe": {"enabled": True, "targeted_ports": [22, 23, 3389, 445, 1433], "severity": "low"}
        }

    def evaluate_flow(self, flow: CanonicalFlow) -> List[DetectionRuleResult]:
        """Evaluates a flow against configured deterministic rules."""
        results: List[DetectionRuleResult] = []
        now_ts = flow.observed_at.timestamp()
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port

        # Update sliding history for src_ip
        if src_ip not in self._history:
            self._history[src_ip] = []

        self._history[src_ip].append((now_ts, dst_ip, dst_port))

        # Evict events older than 120 seconds
        max_window = 120.0
        self._history[src_ip] = [item for item in self._history[src_ip] if (now_ts - item[0]) <= max_window]

        # 1. Connection Rate Rule
        conn_cfg = self.rules_config.get("connection_rate", {})
        if conn_cfg.get("enabled", True):
            win = float(conn_cfg.get("window_seconds", 60))
            thresh = int(conn_cfg.get("threshold", 100))
            count = sum(1 for item in self._history[src_ip] if (now_ts - item[0]) <= win)
            if count >= thresh:
                results.append(
                    DetectionRuleResult(
                        rule_id="CONNECTION_RATE_BURST",
                        severity=conn_cfg.get("severity", "medium"),
                        message=f"High connection burst: {count} connections in {win}s (threshold: {thresh})"
                    )
                )

        # 2. Port Scan Rule
        scan_cfg = self.rules_config.get("port_scan", {})
        if scan_cfg.get("enabled", True):
            win = float(scan_cfg.get("window_seconds", 60))
            thresh = int(scan_cfg.get("distinct_destination_ports_threshold", 20))
            ports: Set[int] = {
                item[2] for item in self._history[src_ip]
                if (now_ts - item[0]) <= win and item[2] is not None
            }
            if len(ports) >= thresh:
                results.append(
                    DetectionRuleResult(
                        rule_id="PORT_SCAN_DETECTED",
                        severity=scan_cfg.get("severity", "high"),
                        message=f"Possible port scan: {len(ports)} distinct destination ports contacted in {win}s (threshold: {thresh})"
                    )
                )

        # 3. Sensitive Port Probe Rule
        probe_cfg = self.rules_config.get("sensitive_port_probe", {})
        if probe_cfg.get("enabled", True) and dst_port is not None:
            sensitive_ports = set(probe_cfg.get("targeted_ports", [22, 23, 3389, 445, 1433]))
            if dst_port in sensitive_ports and flow.packets_out <= 3:
                results.append(
                    DetectionRuleResult(
                        rule_id="SENSITIVE_PORT_PROBE",
                        severity=probe_cfg.get("severity", "low"),
                        message=f"Inbound probe to administrative service port {dst_port}"
                    )
                )

        return results
