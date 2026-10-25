
import unittest
from risk_engine import calculate_risk


class TestPhishLensRisk(unittest.TestCase):

    def test_no_indicators(self):
        result = calculate_risk([], [])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_one_message_indicator(self):
        result = calculate_risk(["urgent"], [])

        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["risk_level"], "LOW")

    def test_two_url_warnings(self):
        result = calculate_risk(
            [],
            [
                "URL uses an IP address",
                "URL does not use HTTPS",
            ]
        )

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_combined_indicators(self):
        result = calculate_risk(
            ["urgent"],
            [
                "URL uses an IP address",
                "URL does not use HTTPS",
            ]
        )

        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_score_cannot_exceed_100(self):
        result = calculate_risk(
            ["one", "two", "three", "four"],
            ["a", "b", "c", "d", "e"]
        )

        self.assertEqual(result["risk_score"], 100)

    def test_duplicate_indicators_are_counted_once(self):
        result = calculate_risk(
            ["urgent", "urgent"],
            [
                "URL does not use HTTPS",
                "URL does not use HTTPS",
            ]
        )

        self.assertEqual(result["message_points"], 20)
        self.assertEqual(result["url_points"], 15)
        self.assertEqual(result["risk_score"], 35)
        self.assertEqual(result["risk_level"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
