import subprocess
import json
import os
from datetime import datetime, timedelta

WHITELIST = {"192.168.1.1", "192.168.1.50"}
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

def block_ip(ip, dry_run=True):
    """Build and optionally execute an iptables block command for the given IP."""
    if ip in WHITELIST:
        return False, "whitelisted, skipped"

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
    """Check all currently blocked IPs and unblock any that have expired."""
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

def log_action(ip, action, reason):
    with open("block_log.txt", "a") as f:
        f.write(f"{datetime.now().isoformat()} | {ip} | {action} | {reason}\n")

if __name__ == "__main__":
    test_ips = ["203.0.113.77", "192.168.1.1", "198.51.100.23"]
    for ip in test_ips:
        blocked, reason = block_ip(ip, dry_run=True)
        action = "BLOCK" if blocked else "SKIP"
        log_action(ip, action, reason)
        print(f"{action} {ip} - {reason}")

    print("\nChecking for expired blocks...")
    check_expired_blocks(dry_run=True)