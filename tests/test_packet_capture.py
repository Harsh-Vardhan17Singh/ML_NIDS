"""
Unit tests for PCAP packet flow extraction and aggregation.
"""

import unittest
from datetime import datetime, timezone
from sensor.packet_capture import PCAPFlowAggregator, FlowKey, FlowAccumulator


class TestPCAPFlowAggregator(unittest.TestCase):

    def test_flow_key_symmetry(self):
        # Forward and reverse packets must produce matching FlowKey
        key_fwd = FlowKey("192.168.1.10", "10.0.0.1", 54321, 80, "tcp")
        key_rev = FlowKey("10.0.0.1", "192.168.1.10", 80, 54321, "tcp")
        self.assertEqual(key_fwd, key_rev)
        self.assertEqual(hash(key_fwd), hash(key_rev))

    def test_flow_accumulator_aggregation(self):
        accumulator = FlowAccumulator("192.168.1.10", "10.0.0.1", 54321, 80, "tcp")

        t1 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 10, 28, 12, 0, 0, 500000, tzinfo=timezone.utc)

        # Packet 1 (outbound): 64 bytes
        accumulator.add_packet("192.168.1.10", "10.0.0.1", 64, t1)
        # Packet 2 (inbound): 128 bytes
        accumulator.add_packet("10.0.0.1", "192.168.1.10", 128, t2)

        flow = accumulator.to_canonical_flow(sensor_id="lab-sensor-01")

        self.assertEqual(flow.src_ip, "192.168.1.10")
        self.assertEqual(flow.dst_ip, "10.0.0.1")
        self.assertEqual(flow.src_port, 54321)
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.packets_out, 1)
        self.assertEqual(flow.packets_in, 1)
        self.assertEqual(flow.bytes_out, 64)
        self.assertEqual(flow.bytes_in, 128)
        self.assertAlmostEqual(flow.duration_ms, 500.0, places=1)

    def test_missing_pcap_file(self):
        aggregator = PCAPFlowAggregator(sensor_id="lab-sensor-01")
        flows, summary = aggregator.parse_pcap("non_existent_capture.pcap")
        self.assertEqual(len(flows), 0)
        self.assertEqual(summary.rejected_records, 1)
        self.assertEqual(summary.errors[0].error_code, "FILE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()

