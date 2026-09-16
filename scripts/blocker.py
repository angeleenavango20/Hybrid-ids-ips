import subprocess
import json
import os
from datetime import datetime, timedelta

# --- WHITELIST ---
# Never auto-block these IPs, no matter what alerts they trigger.
# Includes the project's own infrastructure IPs so background/legitimate
# traffic (e.g. the host machine, the IDS engine itself) can never be
# accidentally blocked by repeat-offender or high-severity rules.
WHITELIST = {
    "192.168.1.1", "192.168.1.50",      # original placeholder entries
    "192.168.141.1",                     # host/gateway IP - caused a real
                                          # false-positive block (Spotify P2P
                                          # alerts triggered repeat-offender
                                          # logic) during Sept 14 testing
    "192.168.141.10",                    # ids-engine itself - never block self
}

BLOCK_DURATION_MINUTES = 10
BLOCKED_IPS_FILE = "blocked_ips.json"


def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_blocked_ips(blocked):
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked, f, indent=2)


def _iptables_rule_exists(ip):
    """Check whether a DROP rule for this IP is ALREADY active in iptables,
    rather than trusting blocked_ips.json alone. This is what fixes both
    the duplicate-rule bug and the reboot-persistence gap: iptables itself
    is always the source of truth, the JSON file is just bookkeeping."""
    result = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    # `iptables -C` (check) returns exit code 0 if the rule exists, nonzero if not.
    return result.returncode == 0


def block_ip(ip, dry_run=True):
    """Build and optionally execute an iptables block command for the given IP."""
    if ip in WHITELIST:
        return False, "whitelisted, skipped"

    # --- Duplicate-rule fix ---
    # Check iptables directly before inserting anything. Previously, running
    # the script multiple times against the same offending IP created two
    # (or more) identical DROP rules, since there was no existing-rule check.
    if _iptables_rule_exists(ip):
        # Still record/refresh our own tracking timestamp so auto-unblock
        # logic stays accurate, but don't insert a second iptables rule.
        blocked = load_blocked_ips()
        if ip not in blocked:
            blocked[ip] = datetime.now().isoformat()
            save_blocked_ips(blocked)
        return True, "already blocked (rule exists, not duplicated)"

    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
    else:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            return False, f"failed: {e}"

    # record the block with a timestamp so we can auto-unblock later
    blocked = load_blocked_ips()
    blocked[ip] = datetime.now().isoformat()
    save_blocked_ips(blocked)

    return True, "dry run - not executed" if dry_run else "blocked"


def unblock_ip(ip, dry_run=True):
    """Remove the iptables block for an IP."""
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
    else:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            return False, f"failed: {e}"

    blocked = load_blocked_ips()
    blocked.pop(ip, None)
    save_blocked_ips(blocked)
    return True, "unblocked"


def check_expired_blocks(dry_run=True):
    """Check all currently tracked IPs and unblock any that have expired."""
    blocked = load_blocked_ips()
    now = datetime.now()
    expired = []

    for ip, blocked_time_str in blocked.items():
        blocked_time = datetime.fromisoformat(blocked_time_str)
        if now - blocked_time >= timedelta(minutes=BLOCK_DURATION_MINUTES):
            expired.append(ip)

    for ip in expired:
        success, reason = unblock_ip(ip, dry_run=dry_run)
        log_action(ip, "UNBLOCK", reason)
        print(f"UNBLOCK | {ip} | expired after {BLOCK_DURATION_MINUTES} min")


def reconcile_state_on_startup(dry_run=True):
    """
    --- Reboot-persistence fix ---
    iptables rules do NOT survive a reboot by default, but blocked_ips.json
    does (it's just a file on disk). Without this check, the tracking file
    can silently claim an IP is blocked when the real firewall has no such
    rule anymore (exactly what happened after the Sept 14 VM reboot).

    Call this once when the watcher starts up: for every IP the JSON file
    thinks is blocked, verify the iptables rule actually still exists.
    If it doesn't (e.g. because of a reboot), either re-apply the block
    (if still within its duration window) or drop it from tracking
    (if it had already expired anyway).
    """
    blocked = load_blocked_ips()
    now = datetime.now()
    changed = False

    for ip, blocked_time_str in list(blocked.items()):
        blocked_time = datetime.fromisoformat(blocked_time_str)
        still_within_window = now - blocked_time < timedelta(minutes=BLOCK_DURATION_MINUTES)
        rule_actually_exists = _iptables_rule_exists(ip)

        if not rule_actually_exists and still_within_window:
            # Firewall was reset (e.g. reboot) but the block hadn't expired yet
            # — re-apply it so protection continues as expected.
            print(f"[RECONCILE] {ip} was tracked as blocked but no iptables rule "
                  f"exists (likely a reboot) and block hasn't expired — re-applying.")
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            if dry_run:
                print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            else:
                subprocess.run(cmd, check=False)
            log_action(ip, "RECONCILE-REBLOCK", "reapplied after firewall reset")

        elif not rule_actually_exists and not still_within_window:
            # Block had already expired anyway — just clean up stale tracking data.
            print(f"[RECONCILE] {ip} tracking entry expired and no rule exists — clearing.")
            blocked.pop(ip)
            changed = True
            log_action(ip, "RECONCILE-CLEANUP", "stale tracking entry removed")

    if changed:
        save_blocked_ips(blocked)


def log_action(ip, action, reason):
    with open("block_log.txt", "a") as f:
        f.write(f"{datetime.now().isoformat()} | {ip} | {action} | {reason}\n")


if __name__ == "__main__":
    # Manual test block, kept for standalone debugging convenience.
    test_ips = ["203.0.113.77", "192.168.1.1", "198.51.100.23"]
    for ip in test_ips:
        blocked, reason = block_ip(ip, dry_run=True)
        action = "BLOCK" if blocked else "SKIP"
        log_action(ip, action, reason)
        print(f"{action} {ip} - {reason}")

    print("\nChecking for expired blocks...")
    check_expired_blocks(dry_run=True)
