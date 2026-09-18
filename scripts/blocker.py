import subprocess
import json
import os
from datetime import datetime, timedelta

# --- WHITELIST ---
# Never auto-block these IPs, no matter what alerts they trigger.
WHITELIST = {
    "192.168.1.1", "192.168.1.50",      # original placeholder entries
    "192.168.141.1",                     # host/gateway IP - caused a real
                                          # false-positive block (Spotify P2P)
    "192.168.141.10",                    # ids-engine itself
    "192.168.141.20",                    # victim-01 itself - the protected
                                          # endpoint must never be able to
                                          # block itself, even if a protocol
                                          # anomaly alert misattributes it
                                          # as a source IP
}

BLOCK_DURATION_MINUTES = 10
BLOCKED_IPS_FILE = "blocked_ips.json"

# --- Remote enforcement target ---
# ids-engine sits PASSIVELY out-of-band (SPAN/mirrored traffic) — it is
# never inline between attacker and victim-01, so blocking on ids-engine's
# own iptables INPUT chain does nothing to stop traffic that never passes
# through it in the first place. To actually protect the real endpoint,
# the block has to be applied on victim-01's own firewall instead.
#
# This requires passwordless SSH (key-based) from ids-engine to victim-01,
# and a narrowly-scoped NOPASSWD sudo rule on victim-01 limited to the
# `iptables` binary specifically (see project setup notes) — not full
# sudo access, since this runs unattended.
REMOTE_HOST = "192.168.141.20"   # victim-01
REMOTE_USER = "malavika"             # adjust to victim-01's actual login user
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]


def _remote_cmd(remote_args):
    """Wrap a remote command list to run over SSH on victim-01.
    BatchMode=yes ensures this fails fast instead of hanging on a password
    prompt if key-based auth isn't set up correctly — important since the
    watcher runs unattended and can't respond to an interactive prompt."""
    return ["ssh", *SSH_OPTS, f"{REMOTE_USER}@{REMOTE_HOST}", "--"] + remote_args


def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_blocked_ips(blocked):
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked, f, indent=2)


def _iptables_rule_exists(ip):
    """Check whether a DROP rule for this IP already exists on victim-01
    (the actual enforcement point), rather than trusting blocked_ips.json
    alone. iptables on victim-01 is always the source of truth; the JSON
    file on ids-engine is just bookkeeping.

    If SSH itself fails (not installed, host unreachable, key auth not
    set up yet), this returns False rather than crashing — the caller
    will then attempt to apply the block via block_ip(), which will
    surface the real error there instead of during this read-only check."""
    cmd = _remote_cmd(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def block_ip(ip, dry_run=True):
    """Build and optionally execute a REMOTE iptables block command on
    victim-01 for the given IP."""
    if ip in WHITELIST:
        return False, "whitelisted, skipped"

    if _iptables_rule_exists(ip):
        blocked = load_blocked_ips()
        if ip not in blocked:
            blocked[ip] = datetime.now().isoformat()
            save_blocked_ips(blocked)
        return True, "already blocked on victim-01 (rule exists, not duplicated)"

    remote_args = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[DRY RUN] Would execute on {REMOTE_HOST}: {' '.join(remote_args)}")
    else:
        cmd = _remote_cmd(remote_args)
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as e:
            return False, f"failed on {REMOTE_HOST}: {e.stderr.decode().strip() if e.stderr else e}"
        except subprocess.TimeoutExpired:
            return False, f"failed: SSH to {REMOTE_HOST} timed out (check key-based auth / network path)"

    blocked = load_blocked_ips()
    blocked[ip] = datetime.now().isoformat()
    save_blocked_ips(blocked)

    return True, "dry run - not executed" if dry_run else f"blocked on {REMOTE_HOST}"


def unblock_ip(ip, dry_run=True):
    """Remove the iptables block for an IP, remotely on victim-01."""
    remote_args = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[DRY RUN] Would execute on {REMOTE_HOST}: {' '.join(remote_args)}")
    else:
        cmd = _remote_cmd(remote_args)
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as e:
            return False, f"failed on {REMOTE_HOST}: {e.stderr.decode().strip() if e.stderr else e}"
        except subprocess.TimeoutExpired:
            return False, f"failed: SSH to {REMOTE_HOST} timed out"

    blocked = load_blocked_ips()
    blocked.pop(ip, None)
    save_blocked_ips(blocked)
    return True, f"unblocked on {REMOTE_HOST}"


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
    Reboot-persistence fix, now checking against victim-01's iptables
    (the real enforcement point) instead of ids-engine's. Handles a
    reboot of victim-01 (wipes its iptables rules) by re-verifying
    tracked blocks against reality rather than trusting the JSON file.
    """
    blocked = load_blocked_ips()
    now = datetime.now()
    changed = False

    for ip, blocked_time_str in list(blocked.items()):
        blocked_time = datetime.fromisoformat(blocked_time_str)
        still_within_window = now - blocked_time < timedelta(minutes=BLOCK_DURATION_MINUTES)
        rule_actually_exists = _iptables_rule_exists(ip)

        if not rule_actually_exists and still_within_window:
            print(f"[RECONCILE] {ip} was tracked as blocked but no iptables rule "
                  f"exists on {REMOTE_HOST} (likely a reboot) and block hasn't "
                  f"expired — re-applying.")
            remote_args = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            if dry_run:
                print(f"[DRY RUN] Would execute on {REMOTE_HOST}: {' '.join(remote_args)}")
            else:
                subprocess.run(_remote_cmd(remote_args), check=False, capture_output=True, timeout=10)
            log_action(ip, "RECONCILE-REBLOCK", "reapplied after firewall reset")

        elif not rule_actually_exists and not still_within_window:
            print(f"[RECONCILE] {ip} tracking entry expired and no rule exists on "
                  f"{REMOTE_HOST} — clearing.")
            blocked.pop(ip)
            changed = True
            log_action(ip, "RECONCILE-CLEANUP", "stale tracking entry removed")

    if changed:
        save_blocked_ips(blocked)


def log_action(ip, action, reason):
    """Log a block/unblock/allow action as a JSON line, so this file can be
    shipped to the Wazuh dashboard via Filebeat the same way eve.json is."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "action": action,
        "reason": reason,
    }
    with open("block_log.txt", "a") as f:
        f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    # Manual test block, kept for standalone debugging convenience.
    # NOTE: this will attempt a real SSH connection to REMOTE_HOST when
    # dry_run=False. With dry_run=True (default here) it only prints
    # what it WOULD run, so it's safe to execute without SSH set up yet.
    test_ips = ["203.0.113.77", "192.168.1.1", "198.51.100.23"]
    for ip in test_ips:
        blocked, reason = block_ip(ip, dry_run=True)
        action = "BLOCK" if blocked else "SKIP"
        log_action(ip, action, reason)
        print(f"{action} {ip} - {reason}")

    print("\nChecking for expired blocks...")
    check_expired_blocks(dry_run=True)
