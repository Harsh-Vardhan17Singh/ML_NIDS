"""
Defensive PCAP parser and flow aggregator.
Extracts 5-tuple metadata and aggregates packets into bidirectional CanonicalFlows
without retaining or exposing raw packet payloads.
"""

from __future__ import annotations
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from .schemas import CanonicalFlow, ParsingSummary, ParsingErrorDetail

logger = logging.getLogger("sentinelnids.sensor.packet_capture")

# Check if scapy is available
try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class FlowKey:
    """Canonical bidirectional flow key for 5-tuple grouping."""
    def __init__(self, ip1: str, ip2: str, port1: Optional[int], port2: Optional[int], proto: str):
        # Sort endpoints so (A->B) and (B->A) map to the same flow tracking key
        if (ip1, port1 or -1) <= (ip2, port2 or -1):
            self.orig_ip = ip1
            self.resp_ip = ip2
            self.orig_port = port1
            self.resp_port = port2
        else:
            self.orig_ip = ip2
            self.resp_ip = ip1
            self.orig_port = port2
            self.resp_port = port1
        self.proto = proto.lower()

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, FlowKey):
            return False
        return (
            self.orig_ip == other.orig_ip and
            self.resp_ip == other.resp_ip and
            self.orig_port == other.orig_port and
            self.resp_port == other.resp_port and
            self.proto == other.proto
        )

    def __hash__(self) -> int:
        return hash((self.orig_ip, self.resp_ip, self.orig_port, self.resp_port, self.proto))


class FlowAccumulator:
    """Accumulates packets within a single flow."""
    def __init__(self, initiator_ip: str, responder_ip: str, src_port: Optional[int], dst_port: Optional[int], proto: str):
        self.initiator_ip = initiator_ip
        self.responder_ip = responder_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = proto

        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.packets_out = 0
        self.packets_in = 0
        self.bytes_out = 0
        self.bytes_in = 0

    def add_packet(self, src: str, dst: str, length: int, ts: datetime) -> None:
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        if src == self.initiator_ip:
            self.packets_out += 1
            self.bytes_out += length
        else:
            self.packets_in += 1
            self.bytes_in += length

    def to_canonical_flow(self, sensor_id: str = "lab-sensor-01") -> CanonicalFlow:
        assert self.first_seen is not None
        assert self.last_seen is not None
        duration_s = max(0.0, (self.last_seen - self.first_seen).total_seconds())
        duration_ms = duration_s * 1000.0

        return CanonicalFlow(
            schema_version="1.0",
            event_id=str(uuid.uuid4()),
            sensor_id=sensor_id,
            observed_at=self.first_seen,
            src_ip=self.initiator_ip,
            dst_ip=self.responder_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            duration_ms=duration_ms,
            packets_out=self.packets_out,
            packets_in=self.packets_in,
            bytes_out=self.bytes_out,
            bytes_in=self.bytes_in,
            parse_warnings=[]
        )


class PCAPFlowAggregator:
    """
    Parses authorized PCAP capture files and aggregates raw packets into
    bidirectional CanonicalFlow instances.
    """

    def __init__(self, sensor_id: str = "lab-sensor-01") -> None:
        self.sensor_id = sensor_id

    def is_available(self) -> bool:
        return SCAPY_AVAILABLE

    def parse_pcap(self, pcap_path: Path | str) -> Tuple[List[CanonicalFlow], ParsingSummary]:
        summary = ParsingSummary()
        path = Path(pcap_path)

        if not path.is_file():
            summary.rejected_records = 1
            summary.errors.append(
                ParsingErrorDetail(index=0, error_code="FILE_NOT_FOUND", message=f"PCAP not found: {path}")
            )
            return [], summary

        if not SCAPY_AVAILABLE:
            summary.rejected_records = 1
            summary.errors.append(
                ParsingErrorDetail(
                    index=0,
                    error_code="DEPENDENCY_MISSING",
                    message="Scapy is not installed. PCAP parsing requires 'scapy' package."
                )
            )
            return [], summary

        try:
            packets = rdpcap(str(path))
        except Exception as e:
            summary.rejected_records = 1
            summary.errors.append(
                ParsingErrorDetail(index=0, error_code="PCAP_READ_ERROR", message=f"Failed to read PCAP: {e}")
            )
            return [], summary

        flows: Dict[FlowKey, FlowAccumulator] = {}

        for idx, pkt in enumerate(packets, start=1):
            summary.total_records += 1
            try:
                # Extract IP layer
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto_num = pkt[IP].proto
                elif IPv6 in pkt:
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                    proto_num = pkt[IPv6].nh
                else:
                    # Non-IP packet (ARP, STP, etc.) - skip defensively
                    summary.rejected_records += 1
                    continue

                # Transport layer
                src_port = None
                dst_port = None
                proto_str = "other"

                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    proto_str = "tcp"
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    proto_str = "udp"
                elif ICMP in pkt:
                    proto_str = "icmp"

                pkt_len = len(pkt)
                pkt_time = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)

                key = FlowKey(src_ip, dst_ip, src_port, dst_port, proto_str)
                if key not in flows:
                    flows[key] = FlowAccumulator(src_ip, dst_ip, src_port, dst_port, proto_str)

                flows[key].add_packet(src_ip, dst_ip, pkt_len, pkt_time)

            except Exception as pkt_err:
                summary.rejected_records += 1
                if len(summary.errors) < 100:
                    summary.errors.append(
                        ParsingErrorDetail(index=idx, error_code="MALFORMED_PACKET", message=str(pkt_err))
                    )

        canonical_flows: List[CanonicalFlow] = []
        for accumulator in flows.values():
            try:
                cflow = accumulator.to_canonical_flow(sensor_id=self.sensor_id)
                canonical_flows.append(cflow)
                summary.accepted_records += 1
            except Exception as flow_err:
                summary.rejected_records += 1
                if len(summary.errors) < 100:
                    summary.errors.append(
                        ParsingErrorDetail(index=0, error_code="FLOW_AGGREGATION_ERROR", message=str(flow_err))
                    )

        return canonical_flows, summary
