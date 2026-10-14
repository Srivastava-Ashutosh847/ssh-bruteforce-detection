
import re
from collections import Counter

LOG_FILE = "sample_auth.log"
THRESHOLD = 3

failed_attempts = Counter()

pattern = re.compile(
    r"Failed password for .* from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

with open(LOG_FILE, "r", encoding="utf-8") as log:
    for line in log:
        match = pattern.search(line)

        if match:
            failed_attempts[match.group("ip")] += 1

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(
            f"[ALERT] Possible brute-force activity: "
            f"{ip} — {count} failed attempts"
        )
    else:
        print(f"[INFO] {ip} — {count} failed attempts")
