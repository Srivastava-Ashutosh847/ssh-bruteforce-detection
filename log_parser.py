
import re

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?.*? from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)


def parse_failed_login(line):
    """Return the source IP for a failed SSH login, or None."""
    match = FAILED_LOGIN_PATTERN.search(line)

    if match is None:
        return None

    return match.group("ip")
