import unittest

from backend.collector.netflow_v5 import HEADER_FMT, RECORD_FMT, parse_packet


class NetFlowV5ParserTests(unittest.TestCase):
    def test_rejects_short_header(self):
        self.assertEqual(parse_packet(b"short"), [])

    def test_ignores_other_versions(self):
        header = __import__("struct").pack(
            HEADER_FMT, 9, 0, 0, 1, 0, 0, 0, 0, 0
        )
        self.assertEqual(parse_packet(header), [])

    def test_parses_one_v5_flow_record(self):
        import struct

        header = struct.pack(HEADER_FMT, 5, 1, 1000, 1_700_000_000, 0, 7, 0, 0, 0)
        record = struct.pack(
            RECORD_FMT,
            0x0A000001, 0x0A000002, 0, 1, 2,
            10, 1500, 100, 900,
            51514, 443, 0, 0x10, 6, 0,
            0, 0, 24, 24, 0,
        )

        flows = parse_packet(header + record)

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["src_ip"], "10.0.0.1")
        self.assertEqual(flows[0]["dst_ip"], "10.0.0.2")
        self.assertEqual(flows[0]["protocol"], "TCP")
        self.assertEqual(flows[0]["packets"], 10)
        self.assertEqual(flows[0]["bytes"], 1500)
        self.assertEqual(flows[0]["duration_ms"], 800)


if __name__ == "__main__":
    unittest.main()
