"""
Unit tests for CanonicalFlow schema validation and constraints.
"""

import unittest
from datetime import datetime, timezone
from pydantic import ValidationError
from sensor.schemas import CanonicalFlow


class TestCanonicalFlowSchema(unittest.TestCase):

    def setUp(self):
        self.valid_data = {
            "schema_version": "1.0",
            "event_id": "test-uuid-001",
            "sensor_id": "lab-sensor-01",
            "observed_at": datetime.now(timezone.utc),
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 49152,
            "dst_port": 80,
            "protocol": "tcp",
            "duration_ms": 150.0,
            "packets_out": 5,
            "packets_in": 7,
            "bytes_out": 500,
            "bytes_in": 2500,
        }

    def test_valid_flow(self):
        flow = CanonicalFlow(**self.valid_data)
        self.assertEqual(flow.schema_version, "1.0")
        self.assertEqual(flow.src_ip, "192.168.1.100")
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.protocol, "tcp")
        self.assertEqual(flow.packets_out, 5)

    def test_invalid_schema_version(self):
        data = self.valid_data.copy()
        data["schema_version"] = "2.0"
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

    def test_invalid_ip_addresses(self):
        # Invalid source IP
        data = self.valid_data.copy()
        data["src_ip"] = "999.999.999.999"
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

        # Non-numeric IP string
        data["src_ip"] = "not_an_ip"
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

    def test_ipv6_support(self):
        data = self.valid_data.copy()
        data["src_ip"] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        data["dst_ip"] = "::1"
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.dst_ip, "::1")

    def test_port_boundaries(self):
        # Out of bounds (> 65535)
        data = self.valid_data.copy()
        data["dst_port"] = 65536
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

        # Negative port
        data["dst_port"] = -1
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

        # Zero port allowed
        data["dst_port"] = 0
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.dst_port, 0)

        # Null port allowed (e.g. ICMP)
        data["dst_port"] = None
        data["protocol"] = "icmp"
        flow = CanonicalFlow(**data)
        self.assertIsNone(flow.dst_port)

    def test_protocol_normalization(self):
        data = self.valid_data.copy()
        data["protocol"] = "TCP"
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.protocol, "tcp")

        data["protocol"] = "ICMP6"
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.protocol, "icmp")

        data["protocol"] = "SOME_CUSTOM_PROTO"
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.protocol, "other")

    def test_negative_values_rejected(self):
        # Negative duration
        data = self.valid_data.copy()
        data["duration_ms"] = -10.0
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

        # Negative packets
        data = self.valid_data.copy()
        data["packets_out"] = -1
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

        # Negative bytes
        data = self.valid_data.copy()
        data["bytes_out"] = -50
        with self.assertRaises(ValidationError):
            CanonicalFlow(**data)

    def test_timezone_conversion(self):
        # Naive datetime is automatically converted to UTC
        naive_dt = datetime(2026, 10, 28, 12, 0, 0)
        data = self.valid_data.copy()
        data["observed_at"] = naive_dt
        flow = CanonicalFlow(**data)
        self.assertIsNotNone(flow.observed_at.tzinfo)
        self.assertEqual(flow.observed_at.tzinfo, timezone.utc)

    def test_coherence_warnings(self):
        # 0 packets with positive bytes -> warning added & packets adjusted
        data = self.valid_data.copy()
        data["packets_out"] = 0
        data["bytes_out"] = 100
        flow = CanonicalFlow(**data)
        self.assertEqual(flow.packets_out, 1)
        self.assertTrue(any("bytes_out > 0" in w for w in flow.parse_warnings))


if __name__ == "__main__":
    unittest.main()

