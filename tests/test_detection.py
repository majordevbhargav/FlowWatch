import unittest

from backend.detection.traffic_engine import TrafficOnlyEngine, extract_features
from backend.detection.risk_engine import tier_for


class TrafficFeatureTests(unittest.TestCase):
    def test_zero_packet_flow_uses_safe_denominators(self):
        features = extract_features({
            "packets": 0,
            "bytes": 0,
            "duration_ms": 0,
        })

        self.assertEqual(len(features), 6)
        self.assertTrue(all(value == 0 for value in features))

    def test_cold_start_returns_documented_shape(self):
        result = TrafficOnlyEngine().score({
            "packets": 2,
            "bytes": 120,
            "duration_ms": 1000,
        })

        self.assertEqual(set(result), {"anomaly", "score", "method"})
        self.assertIsInstance(result["anomaly"], bool)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 1)
        self.assertEqual(result["method"], "cold-start-heuristic")


class RiskTierTests(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(tier_for(0)[0], "Low")
        self.assertEqual(tier_for(35)[0], "Medium")
        self.assertEqual(tier_for(65)[0], "High")
        self.assertEqual(tier_for(85)[0], "Critical")

    def test_scores_above_critical_threshold_remain_critical(self):
        self.assertEqual(tier_for(100)[0], "Critical")


if __name__ == "__main__":
    unittest.main()
