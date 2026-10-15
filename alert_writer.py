import json
from datetime import datetime, timezone
from pathlib import Path


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
