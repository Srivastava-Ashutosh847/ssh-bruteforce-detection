
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone


def write_alert(alert_file, source_ip, failed_attempts):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": "Possible SSH brute-force activity",
        "source_ip": source_ip,
        "failed_attempts_in_window": failed_attempts,
        "window": "5 minutes",
        "severity": "medium",
        "status": "investigation_required",
    }

    with Path(alert_file).open("a", encoding="utf-8") as file:
        file.write(json.dumps(alert) + "\n")

    return alert


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


if __name__ == "__main__":
    unittest.main()
