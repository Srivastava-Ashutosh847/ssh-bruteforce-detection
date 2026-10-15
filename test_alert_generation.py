
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone

from alert_writer import write_alert


class TestAlertGeneration(unittest.TestCase):

    def test_alert_is_written_as_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory) / "alerts.jsonl"

            write_alert(alert_file, "192.168.1.50", 3)

            saved_alert = json.loads(
                alert_file.read_text(encoding="utf-8").strip()
            )

            self.assertEqual(saved_alert["source_ip"], "192.168.1.50")
            self.assertEqual(saved_alert["failed_attempts_in_window"], 3)
            self.assertEqual(saved_alert["severity"], "medium")
            self.assertEqual(saved_alert["status"], "investigation_required")
            self.assertEqual(
                saved_alert["alert"],
                "Possible SSH brute-force activity",
            )
            datetime.fromisoformat(saved_alert["timestamp"])

    def test_alerts_are_appended(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory) / "alerts.jsonl"

            write_alert(alert_file, "192.168.1.50", 3)
            write_alert(alert_file, "192.168.1.51", 4)

            lines = alert_file.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertEqual(len(lines), 2)
            self.assertEqual(
                json.loads(lines[1])["source_ip"],
                "192.168.1.51",
            )


if __name__ == "__main__":
    unittest.main()

