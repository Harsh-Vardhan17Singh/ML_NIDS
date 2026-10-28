"""
Unit tests for telemetry normalizer and defensive log parser.
"""

import unittest
from pathlib import Path
from sensor.normalize import normalize_zeek_record, normalize_flow_record
from sensor.parser import DefensiveLogParser


class TestNormalizeAndParser(unittest.TestCase):

    def setUp(self):
        self.parser = DefensiveLogParser(default_sensor_id="lab-sensor-01")

    def test_normalize_zeek_dict(self):
        zeek_row = {
            "ts": 1793188800.125,
            "uid": "C1234567890abcdef",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": "50123",
            "id.resp_h": "93.184.216.34",
            "id.resp_p": "80",
            "proto": "tcp",
            "duration": "0.1452",
            "orig_bytes": "620",
            "resp_bytes": "14200",
            "orig_pkts": "8",
            "resp_pkts": "12",
            "conn_state": "SF"
        }
        flow = normalize_zeek_record(zeek_row, default_sensor_id="lab-sensor-01")
        self.assertEqual(flow.event_id, "C1234567890abcdef")
        self.assertEqual(flow.src_ip, "192.168.1.50")
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.protocol, "tcp")
        self.assertAlmostEqual(flow.duration_ms, 145.2, places=1)
        self.assertEqual(flow.bytes_out, 620)
        self.assertEqual(flow.bytes_in, 14200)
        self.assertEqual(flow.packets_out, 8)
        self.assertEqual(flow.packets_in, 12)
        self.assertIn("zeek_state:SF", flow.parse_warnings)

    def test_normalize_generic_flow_dict(self):
        generic_record = {
            "source_ip": "10.0.0.15",
            "dest_ip": "10.0.0.1",
            "source_port": 5353,
            "dest_port": 5353,
            "protocol": "udp",
            "duration_ms": 12.0,
            "out_packets": 2,
            "out_bytes": 128
        }
        flow = normalize_flow_record(generic_record)
        self.assertEqual(flow.src_ip, "10.0.0.15")
        self.assertEqual(flow.dst_port, 5353)
        self.assertEqual(flow.protocol, "udp")
        self.assertEqual(flow.packets_out, 2)
        self.assertEqual(flow.bytes_out, 128)

    def test_defensive_parser_corrupted_lines(self):
        lines = [
            '{"event_id": "e1", "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "udp"}', # valid
            '{malformed_json_without_quotes}',                                                       # invalid json
            '{"event_id": "e2", "src_ip": "not_an_ip", "dst_ip": "8.8.8.8", "protocol": "udp"}',  # invalid IP
            '{"event_id": "e3", "src_ip": "192.168.1.2", "dst_ip": "8.8.8.8", "protocol": "udp", "dst_port": 70000}', # port > 65535
            '{"event_id": "e4", "src_ip": "192.168.1.3", "dst_ip": "8.8.8.8", "protocol": "tcp"}'  # valid
        ]

        flows, summary = self.parser.parse_lines(lines)

        self.assertEqual(summary.total_records, 5)
        self.assertEqual(summary.accepted_records, 2)
        self.assertEqual(summary.rejected_records, 3)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0].event_id, "e1")
        self.assertEqual(flows[1].event_id, "e4")

        # Verify error categories
        error_codes = [err.error_code for err in summary.errors]
        self.assertIn("MALFORMED_JSON", error_codes)
        self.assertIn("NORMALIZATION_ERROR", error_codes)

    def test_deduplication(self):
        lines = [
            '{"event_id": "dup-001", "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "udp"}',
            '{"event_id": "dup-001", "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "udp"}',
            '{"event_id": "dup-002", "src_ip": "192.168.1.2", "dst_ip": "8.8.8.8", "protocol": "udp"}'
        ]
        self.parser.reset_deduplication()
        flows, summary = self.parser.parse_lines(lines)

        self.assertEqual(summary.total_records, 3)
        self.assertEqual(summary.accepted_records, 2)
        self.assertEqual(summary.duplicate_records, 1)
        self.assertEqual(len(flows), 2)

    def test_sample_canonical_jsonl_file(self):
        fixture_path = Path("data/sample/canonical_flows.jsonl")
        self.assertTrue(fixture_path.is_file(), "Fixture data/sample/canonical_flows.jsonl missing")

        self.parser.reset_deduplication()
        flows, summary = self.parser.parse_file(fixture_path)

        self.assertEqual(summary.rejected_records, 0)
        self.assertEqual(summary.accepted_records, 6)
        self.assertEqual(len(flows), 6)

    def test_sample_zeek_conn_log_file(self):
        fixture_path = Path("data/sample/sample_zeek_conn.log")
        self.assertTrue(fixture_path.is_file(), "Fixture data/sample/sample_zeek_conn.log missing")

        self.parser.reset_deduplication()
        flows, summary = self.parser.parse_file(fixture_path)

        self.assertEqual(summary.rejected_records, 0)
        self.assertEqual(summary.accepted_records, 3)
        self.assertEqual(len(flows), 3)
        self.assertEqual(flows[0].protocol, "tcp")
        self.assertEqual(flows[1].protocol, "udp")
        self.assertEqual(flows[2].protocol, "icmp")

    def test_missing_file_handling(self):
        flows, summary = self.parser.parse_file("non_existent_file.log")
        self.assertEqual(len(flows), 0)
        self.assertEqual(summary.rejected_records, 1)
        self.assertEqual(summary.errors[0].error_code, "FILE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()

