
import unittest
from log_parser import parse_failed_login


class TestSSHLogParser(unittest.TestCase):

    def test_extracts_failed_login_ip(self):
        line = (
            "Oct 15 10:20:30 kali sshd[1234]: "
            "Failed password for ashutosh from 192.168.1.20 "
            "port 5222 ssh2"
        )
        self.assertEqual(parse_failed_login(line), "192.168.1.20")

    def test_extracts_ip_for_invalid_user(self):
        line = (
            "Oct 15 10:20:30 kali sshd[1234]: "
            "Failed password for invalid user admin from "
            "192.168.1.21 port 5222 ssh2"
        )
        self.assertEqual(parse_failed_login(line), "192.168.1.21")

    def test_ignores_successful_login(self):
        line = (
            "Accepted password for ashutosh from "
            "192.168.1.20 port 5222 ssh2"
        )
        self.assertIsNone(parse_failed_login(line))

    def test_ignores_unrelated_log(self):
        self.assertIsNone(parse_failed_login("System reboot completed"))

    def test_handles_malformed_log(self):
        self.assertIsNone(parse_failed_login("Failed password for admin"))

    
if __name__ == "__main__":
    unittest.main()
