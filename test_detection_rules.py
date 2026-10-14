import unittest
from detection_rules import detect_bruteforce


class TestBruteForceDetection(unittest.TestCase):

    def test_detects_threshold_reached(self):
        result = detect_bruteforce({"192.168.1.20": 3})
        self.assertEqual(result, {"192.168.1.20": 3})

    def test_ignores_attempts_below_threshold(self):
        result = detect_bruteforce({"192.168.1.20": 2})
        self.assertEqual(result, {})

    def test_detects_multiple_suspicious_ips(self):
        result = detect_bruteforce({
            "192.168.1.20": 4,
            "192.168.1.21": 1,
            "192.168.1.22": 3
        })
        self.assertEqual(result, {
            "192.168.1.20": 4,
            "192.168.1.22": 3
        })

    def test_custom_threshold(self):
        result = detect_bruteforce(
            {"192.168.1.20": 4},
            threshold=5
        )
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
