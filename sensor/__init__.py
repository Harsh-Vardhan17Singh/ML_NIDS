"""
SentinelNIDS Sensor and Telemetry Ingestion Package.
Provides canonical flow schemas, normalizers, defensive log parsers,
and PCAP flow extraction utilities.
"""

from .schemas import CanonicalFlow, RawFlowRecord, ParsingSummary
from .normalize import normalize_flow_record, normalize_zeek_record
from .parser import DefensiveLogParser
from .packet_capture import PCAPFlowAggregator

__all__ = [
    "CanonicalFlow",
    "RawFlowRecord",
    "ParsingSummary",
    "normalize_flow_record",
    "normalize_zeek_record",
    "DefensiveLogParser",
    "PCAPFlowAggregator",
]
