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
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event_type") == "alert":
                parsed.append(parse_alert(entry))
    return parsed

if __name__ == "__main__":
    alerts = load_alerts("sample_alerts.json")
    for alert in alerts:
        print(alert)
