def detect_bruteforce(counts, threshold=3):
    """Return source IPs that meet the failed-login threshold."""
    return {
        ip: count
        for ip, count in counts.items()
        if count >= threshold
    }
