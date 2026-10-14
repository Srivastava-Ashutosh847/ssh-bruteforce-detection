

import re
import json
from collections import Counter
from datetime import datetime, timezone

LOG_FILE = "sample_auth.log"
THRESHOLD = 3

failed_attempts = Counter()
pattern = re.compile(
    r"Failed password for .* from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

with open(LOG_FILE, encoding="utf-8") as log:
    for line in log:
        match = pattern.search(line)
        if match:
            failed_attempts[match.group("ip")] += 1

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert": "Possible SSH brute-force activity",
            "source_ip": ip,
            "failed_attempts": count,
            "severity": "medium",
            "status": "investigation_required"
        }

        print(json.dumps(alert, indent=2))
