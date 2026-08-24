import json

def parse_alert(alert):
    """Extract key fields from a single Suricata eve.json alert."""
    severity = alert["alert"]["severity"]
    description = alert["alert"]["signature"]
    source_ip = alert["src_ip"]
    timestamp = alert.get("timestamp", "unknown")
    
    return {
        "severity": severity,
        "description": description,
        "source_ip": source_ip,
        "timestamp": timestamp
    }

def load_alerts(filepath):
    """Load and parse all alerts from a JSON file."""
    with open(filepath, "r") as f:
        raw_alerts = json.load(f)
    parsed = [parse_alert(a) for a in raw_alerts]
    return parsed

if __name__ == "__main__":
    alerts = load_alerts("sample_alerts.json")
    for alert in alerts:
        print(alert)