#!/usr/bin/env python3
"""
SentinelNIDS - Sensor Telemetry Simulator & Live Demonstration CLI
Phase 5 Deliverable: Replays canonical flows, generates realistic attack traffic,
streams to the ingestion endpoint, and verifies real-time detection & alert triage.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


class TermColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def log_info(msg: str):
    print(f"{TermColors.OKCYAN}[INFO]{TermColors.ENDC} {msg}")


def log_success(msg: str):
    print(f"{TermColors.OKGREEN}[SUCCESS]{TermColors.ENDC} {msg}")


def log_warn(msg: str):
    print(f"{TermColors.WARNING}[WARN]{TermColors.ENDC} {msg}")


def log_error(msg: str):
    print(f"{TermColors.FAIL}[ERROR]{TermColors.ENDC} {msg}")


def make_request(url: str, method: str = "GET", headers: dict = None, data: dict = None) -> dict:
    req_headers = headers or {}
    req_body = None
    if data is not None:
        req_body = json.dumps(data).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=req_body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return {"_status": e.code, "_error": json.loads(err_msg)}
        except Exception:
            return {"_status": e.code, "_error": err_msg}
    except Exception as e:
        return {"_error": str(e)}


def generate_synthetic_attack_flow(attack_type: str, sensor_id: str = "sensor-sim-01") -> dict:
    """Generate a canonical flow representing a specific traffic profile."""
    now_iso = datetime.now(timezone.utc).isoformat()
    ev_id = f"sim-{uuid.uuid4()}"

    if attack_type == "dos_synflood":
        return {
            "schema_version": "1.0",
            "event_id": ev_id,
            "sensor_id": sensor_id,
            "observed_at": now_iso,
            "src_ip": "192.168.10.150",
            "src_port": 49152,
            "dst_ip": "10.0.0.50",
            "dst_port": 80,
            "protocol": 6,
            "duration": 0.05,
            "src_bytes": 128000,
            "dst_bytes": 0,
            "src_packets": 2000,
            "dst_packets": 0,
            "features": {
                "Flow Duration": 50000,
                "Total Fwd Packets": 2000,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": 128000,
                "Total Length of Bwd Packets": 0,
                "Fwd Packet Length Max": 64,
                "Fwd Packet Length Min": 64,
                "Fwd Packet Length Mean": 64.0,
                "Bwd Packet Length Max": 0,
                "Bwd Packet Length Min": 0,
                "Bwd Packet Length Mean": 0.0,
                "Flow Bytes/s": 2560000.0,
                "Flow Packets/s": 40000.0,
                "Flow IAT Mean": 25.0,
                "Flow IAT Std": 5.0,
                "Flow IAT Max": 50,
                "Flow IAT Min": 10,
                "SYN Flag Count": 2000,
                "ACK Flag Count": 0,
                "FIN Flag Count": 0,
                "Init_Win_bytes_forward": 1024,
                "Init_Win_bytes_backward": 0,
            },
        }

    elif attack_type == "portscan":
        target_port = 22
        return {
            "schema_version": "1.0",
            "event_id": ev_id,
            "sensor_id": sensor_id,
            "observed_at": now_iso,
            "src_ip": "192.168.1.99",
            "src_port": 54321,
            "dst_ip": "10.0.0.5",
            "dst_port": target_port,
            "protocol": 6,
            "duration": 0.001,
            "src_bytes": 40,
            "dst_bytes": 0,
            "src_packets": 1,
            "dst_packets": 0,
            "features": {
                "Flow Duration": 1000,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": 40,
                "Total Length of Bwd Packets": 0,
                "SYN Flag Count": 1,
                "ACK Flag Count": 0,
                "Init_Win_bytes_forward": 1024,
                "Init_Win_bytes_backward": 0,
            },
        }

    else:  # Benign web browsing
        return {
            "schema_version": "1.0",
            "event_id": ev_id,
            "sensor_id": sensor_id,
            "observed_at": now_iso,
            "src_ip": "10.0.0.100",
            "src_port": 51234,
            "dst_ip": "142.250.190.46",
            "dst_port": 443,
            "protocol": 6,
            "duration": 1.25,
            "src_bytes": 1820,
            "dst_bytes": 14500,
            "src_packets": 15,
            "dst_packets": 22,
            "features": {
                "Flow Duration": 1250000,
                "Total Fwd Packets": 15,
                "Total Backward Packets": 22,
                "Total Length of Fwd Packets": 1820,
                "Total Length of Bwd Packets": 14500,
                "Flow Bytes/s": 13056.0,
                "Flow Packets/s": 29.6,
                "Flow IAT Mean": 33783.0,
                "SYN Flag Count": 1,
                "ACK Flag Count": 37,
                "Init_Win_bytes_forward": 65535,
                "Init_Win_bytes_backward": 65535,
            },
        }


def run_demo(base_url: str, api_key: str):
    print("=" * 70)
    print(f"{TermColors.HEADER}{TermColors.BOLD} SentinelNIDS - Live Demonstration & Sensor Simulator{TermColors.ENDC}")
    print("=" * 70)

    # 1. Health check
    log_info(f"Connecting to SentinelNIDS backend at {base_url}...")
    health = make_request(f"{base_url}/api/v1/health")
    if "_error" in health or health.get("status") != "healthy":
        log_error(f"Health check failed: {health}")
        log_warn("Please make sure the backend is running: `uvicorn backend.app.main:app --reload`")
        sys.exit(1)

    log_success(f"Backend is Healthy: Version={health.get('version')} DB={health.get('database')} ML_Ready={health.get('ml_model_loaded')}")

    # 2. Replay sample canonical flows fixture
    fixture_path = Path("data/sample/canonical_flows.jsonl")
    flows_to_send = []

    if fixture_path.exists():
        log_info(f"Reading flows from fixture: {fixture_path}")
        with open(fixture_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    flow_obj = json.loads(line)
                    # refresh event_id to prevent collision on re-runs
                    flow_obj["event_id"] = f"demo-{uuid.uuid4()}"
                    flow_obj["observed_at"] = datetime.now(timezone.utc).isoformat()
                    flows_to_send.append(flow_obj)

    # Add synthetic attacks
    log_info("Injecting synthetic attack vectors (DoS SYN-Flood, Recon PortScan, Benign Web)...")
    flows_to_send.append(generate_synthetic_attack_flow("dos_synflood"))
    flows_to_send.append(generate_synthetic_attack_flow("portscan"))
    flows_to_send.append(generate_synthetic_attack_flow("benign_https"))

    # 3. Ingest batch
    log_info(f"Transmitting batch of {len(flows_to_send)} flows to /api/v1/ingest/flows...")
    headers = {"X-Sensor-Token": api_key}
    ingest_resp = make_request(
        f"{base_url}/api/v1/ingest/flows",
        method="POST",
        headers=headers,
        data={"flows": flows_to_send},
    )

    if "_error" in ingest_resp:
        log_error(f"Ingestion failed: {ingest_resp}")
        sys.exit(1)

    log_success(
        f"Ingestion Acknowledgement: Accepted={ingest_resp.get('accepted')} "
        f"Duplicates={ingest_resp.get('duplicates')} "
        f"Alerts Triggered={ingest_resp.get('alerts_triggered')} "
        f"Duration={ingest_resp.get('duration_ms', 0):.2f}ms"
    )

    # 4. Inspect generated alerts
    log_info("Querying recent alerts from /api/v1/alerts...")
    alerts_resp = make_request(f"{base_url}/api/v1/alerts?limit=5")
    alerts = alerts_resp.get("alerts", [])

    if not alerts:
        log_warn("No alerts found in system yet.")
    else:
        print(f"\n{TermColors.BOLD}--- Active Threat Alerts (SOC Queue) ---{TermColors.ENDC}")
        for a in alerts[:5]:
            sev_color = TermColors.FAIL if a["severity"] in ("CRITICAL", "HIGH") else TermColors.WARNING
            print(
                f"  [{sev_color}{a['severity']:<8}{TermColors.ENDC}] "
                f"ID: {a['id'][:8]}... | "
                f"Title: {a['title'][:32]:<32} | "
                f"Score: {a['ml_score']:.3f} | "
                f"Status: {a['status']}"
            )

        # 5. Simulate Analyst Triage Workflow
        target_alert = alerts[0]
        alert_id = target_alert["id"]
        log_info(f"Simulating SOC Analyst triage on Alert {alert_id}...")

        # Step 5a: Acknowledge and mark in_progress
        patch_resp = make_request(
            f"{base_url}/api/v1/alerts/{alert_id}",
            method="PATCH",
            data={
                "status": "in_progress",
                "analyst_notes": "SOC Tier-1 Analyst investigating anomalous traffic pattern.",
            },
        )
        log_success(f"Alert {alert_id} updated -> Status: {patch_resp.get('status')} | Notes: {patch_resp.get('analyst_notes')}")

        # Step 5b: Mark as resolved
        patch_resp2 = make_request(
            f"{base_url}/api/v1/alerts/{alert_id}",
            method="PATCH",
            data={
                "status": "resolved",
                "analyst_notes": "Mitigated: Host isolated and forensic PCAP preserved.",
            },
        )
        log_success(f"Alert {alert_id} resolved -> Status: {patch_resp2.get('status')} | Notes: {patch_resp2.get('analyst_notes')}")

    # 6. Overview Metrics
    dashboard_stats = make_request(f"{base_url}/api/v1/dashboard/overview")
    print(f"\n{TermColors.BOLD}--- Live SOC Dashboard Metrics ---{TermColors.ENDC}")
    print(f"  Total Ingested Flows: {dashboard_stats.get('total_flows')}")
    print(f"  Total Alerts:         {dashboard_stats.get('total_alerts')}")
    print(f"  Active / Pending:     {dashboard_stats.get('active_alerts')}")
    print(f"  Critical Alerts:      {dashboard_stats.get('critical_alerts')}")
    print(f"  Avg Inference Latency:{dashboard_stats.get('avg_inference_latency_ms', 0):.3f} ms")

    print("\n" + "=" * 70)
    log_success("End-to-End Live Sensor Simulation & Triage Demo Completed Successfully!")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="SentinelNIDS Sensor Telemetry Simulator")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of SentinelNIDS backend")
    parser.add_argument("--key", default="sn-live-tok-alpha-001", help="Sensor authentication token")
    parser.add_argument("--continuous", action="store_true", help="Continuously stream synthetic events")
    parser.add_argument("--interval", type=float, default=2.0, help="Interval between continuous batches in seconds")
    args = parser.parse_args()

    if args.continuous:
        log_info(f"Starting continuous streaming to {args.url} (interval={args.interval}s, Ctrl+C to stop)...")
        while True:
            try:
                flow = generate_synthetic_attack_flow("benign_https")
                headers = {"X-Sensor-Token": args.key}
                resp = make_request(f"{args.url}/api/v1/ingest/flows", method="POST", headers=headers, data={"flows": [flow]})
                log_info(f"Pushed 1 flow: status={resp.get('accepted', 0)} accepted")
                time.sleep(args.interval)
            except KeyboardInterrupt:
                log_info("Streaming stopped by operator.")
                break
    else:
        run_demo(args.url, args.key)


if __name__ == "__main__":
    main()
