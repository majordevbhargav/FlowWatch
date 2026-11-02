import unittest

from backend.detection.context_engine import ContextAwareEngine, SCAN_PORT_THRESHOLD
from backend.detection.risk_engine import RiskInformedEngine


class StubInventory:
    """Small deterministic inventory for isolated detection tests."""

    def lookup(self, ip):
        if ip == "10.0.30.10":
            return {
                "ip": ip, "known": True, "name": "IOT-01",
                "role": "iot-device", "vlan": "IoT", "criticality": 1,
            }
        if ip == "10.0.20.10":
            return {
                "ip": ip, "known": True, "name": "DB-01",
                "role": "database", "vlan": "Server", "criticality": 5,
            }
        return {
            "ip": ip, "known": True, "name": "APP-01",
            "role": "app-server", "vlan": "Server", "criticality": 3,
        }

    def allowed_roles_for(self, role):
        return {"database": ["app-server"]}.get(role)


def flow(src="10.0.10.10", dst="10.0.20.10", port=443, at=100.0):
    return {
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "observed_at": at,
    }


class ContextAwareEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = ContextAwareEngine(StubInventory())

    def test_port_scan_is_flagged_at_distinct_port_threshold(self):
        result = None
        for port in range(2000, 2000 + SCAN_PORT_THRESHOLD):
            result = self.engine.score(flow(port=port), {"score": 0.0})

        self.assertTrue(result["anomaly"])
        self.assertGreaterEqual(result["context_score"], 0.9)
        self.assertTrue(any("Port scan pattern" in item for item in result["violations"]))

    def test_repeated_same_port_does_not_count_as_port_scan(self):
        result = None
        for _ in range(SCAN_PORT_THRESHOLD + 2):
            result = self.engine.score(flow(port=443), {"score": 0.0})

        self.assertFalse(any("Port scan pattern" in item for item in result["violations"]))

    def test_expired_scan_events_do_not_trigger_detection(self):
        for port in range(2000, 2000 + SCAN_PORT_THRESHOLD - 1):
            self.engine.score(flow(port=port, at=100.0), {"score": 0.0})

        result = self.engine.score(
            flow(port=2000 + SCAN_PORT_THRESHOLD, at=100.0 + 21.0),
            {"score": 0.0},
        )
        self.assertFalse(any("Port scan pattern" in item for item in result["violations"]))

    def test_iot_to_server_crossing_is_flagged(self):
        result = self.engine.score(
            flow(src="10.0.30.10", dst="10.0.20.10"),
            {"score": 0.0},
        )

        self.assertTrue(result["anomaly"])
        self.assertIn("IoT device crossed into Server VLAN", result["violations"])
        self.assertGreaterEqual(result["context_score"], 0.85)

    def test_context_engine_never_reduces_traffic_score(self):
        result = self.engine.score(flow(), {"score": 0.72})

        self.assertEqual(result["score"], 0.72)


class RiskInformedEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskInformedEngine()

    def context(self, score=0.0, criticality=1, known=True, violations=None):
        return {
            "context_score": score,
            "dst_context": {"criticality": criticality, "name": "DB-01"},
            "src_context": {"known": known},
            "violations": violations or [],
        }

    def test_high_context_signal_enforces_high_priority_floor(self):
        result = self.engine.score(
            {},
            {"score": 0.1, "anomaly": False, "method": "test"},
            self.context(score=0.8, criticality=1, violations=["Policy violation"]),
        )

        self.assertGreaterEqual(result["score"], 75)
        self.assertIn(result["tier"], ("High", "Critical"))

    def test_policy_violation_against_critical_asset_enforces_critical_floor(self):
        result = self.engine.score(
            {},
            {"score": 0.1, "anomaly": False, "method": "test"},
            self.context(score=0.8, criticality=5, violations=["Policy violation"]),
        )

        self.assertEqual(result["score"], 85)
        self.assertEqual(result["tier"], "Critical")

    def test_low_signal_remains_low_priority(self):
        result = self.engine.score(
            {},
            {"score": 0.1, "anomaly": False, "method": "test"},
            self.context(score=0.0, criticality=1),
        )

        self.assertEqual(result["tier"], "Low")
        self.assertFalse(result["anomaly"])


if __name__ == "__main__":
    unittest.main()
