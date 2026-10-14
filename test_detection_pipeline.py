import unittest
from collections import Counter

from log_parser import parse_failed_login
from detection_rules import detect_bruteforce


class TestDetectionPipeline(unittest.TestCase):

    def test_three_failed_logins_trigger_detection(self):
        sample_logs = [
            "Oct 15 10:20:30 kali sshd[101]: Failed password for admin from 192.168.1.50 port 5001 ssh2",
            "Oct 15 10:20:31 kali sshd[102]: Failed password for admin from 192.168.1.50 port 5002 ssh2",
            "Oct 15 10:20:32 kali sshd[103]: Failed password for admin from 192.168.1.50 port 5003 ssh2",
            "Oct 15 10:20:33 kali sshd[104]: Accepted password for user from 192.168.1.60 port 5004 ssh2",
        ]

        counts = Counter(
            ip
            for line in sample_logs
            if (ip := parse_failed_login(line)) is not None
        )

        detected = detect_bruteforce(counts, threshold=3)

        self.assertEqual(detected, {"192.168.1.50": 3})
        self.assertNotIn("192.168.1.60", detected)


if __name__ == "__main__":
    unittest.main()
