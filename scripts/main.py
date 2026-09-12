from parser import load_alerts
from decision import should_block
from blocker import block_ip, log_action

def run_pipeline(alert_file, dry_run=True):
    alerts = load_alerts(alert_file)

    for alert in alerts:
        block, reason = should_block(alert)

        if block:
            executed, block_reason = block_ip(alert["source_ip"], dry_run=dry_run)
            action = "BLOCK" if executed else "SKIP"
            final_reason = f"{reason} -> {block_reason}"
        else:
            action = "ALLOW"
            final_reason = reason

        log_action(alert["source_ip"], action, final_reason)
        print(f"{action:6} | {alert['source_ip']:15} | severity={alert['severity']:3} | {final_reason} | {alert['description']}")

if __name__ == "__main__":
    run_pipeline("/var/log/suricata/eve.json", dry_run=True)
