from parser import load_alerts
from collections import defaultdict

ip_offense_count = defaultdict(int)

SEVERITY_THRESHOLD = 2   # severity 1 or 2 (out of 1-3) triggers a block
REPEAT_OFFENSE_LIMIT = 2

def should_block(alert):
    """Decide whether an alert's source IP should be blocked."""
    ip_offense_count[alert["source_ip"]] += 1

    if alert["severity"] <= SEVERITY_THRESHOLD:  # note: <= now (lower = worse)
        return True, "high severity"

    if ip_offense_count[alert["source_ip"]] >= REPEAT_OFFENSE_LIMIT:
        return True, "repeated offender"

    return False, "below threshold"

if __name__ == "__main__":
    alerts = load_alerts("sample_alerts.json")
    for alert in alerts:
        block, reason = should_block(alert)
        status = "BLOCK" if block else "allow"
        print(f"{status:6} | {alert['source_ip']:15} | severity={alert['severity']:3} | {reason} | {alert['description']}")