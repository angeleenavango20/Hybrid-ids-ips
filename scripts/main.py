"""
main.py — Continuous real-time watcher for Suricata alerts.

Instead of reading the whole eve.json file once and exiting, this version
"tails" the file the way `tail -f` does: it seeks to the end of the file
on startup, then continuously checks for new lines being appended, parsing
and acting on each new alert as it arrives.

Usage:
    python3 main.py                  # dry run, safe (prints what would happen)
    python3 main.py --live           # real mode, actually blocks IPs

Stop with Ctrl+C.
"""

import os
import time
import json
import sys
import signal

from parser import parse_alert
from decision import should_block
from blocker import block_ip, log_action, check_expired_blocks

ALERT_FILE = "/var/log/suricata/eve.json"
EXPIRY_CHECK_INTERVAL_SECONDS = 30  # how often to check for blocks that should auto-expire

_running = True


def _handle_shutdown(signum, frame):
    global _running
    print("\nShutting down watcher...")
    _running = False


def follow(filepath):
    """Generator that yields new lines appended to filepath, like `tail -f`.

    Also detects log rotation (the file at `filepath` being renamed/replaced,
    e.g. by logrotate) by tracking the inode, and transparently reopens the
    new file so alerts written after a rotation aren't silently missed.
    """
    f = None
    inode = None

    while _running:
        if f is None:
            try:
                f = open(filepath, "r")
                inode = os.fstat(f.fileno()).st_ino
                # Jump straight to the end on first open — we only care about
                # NEW alerts from now on, not the entire alert history.
                f.seek(0, 2)
            except FileNotFoundError:
                # File doesn't exist yet (e.g. Suricata hasn't started, or
                # we're mid-rotation). Wait and retry instead of crashing.
                time.sleep(1)
                continue

        line = f.readline()
        if line:
            yield line
            continue

        # No new data right now — check whether the file was rotated out
        # from under us (logrotate renames the old file and Suricata starts
        # writing a fresh one at the same path).
        try:
            current_inode = os.stat(filepath).st_ino
        except FileNotFoundError:
            current_inode = None

        if current_inode != inode:
            f.close()
            f = None  # reopen fresh file on next loop iteration
        else:
            time.sleep(0.5)

    if f:
        f.close()


def process_line(raw_line, dry_run):
    """Parse one raw eve.json line and act on it if it's a real alert.

    Any failure here (malformed alert, unexpected field shape from a new
    rule type, etc.) is caught and logged so one bad line can't kill the
    whole watcher — it just skips that alert and keeps running.
    """
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        return  # skip malformed/partial lines (can happen mid-write)

    try:
        if event.get("event_type") != "alert":
            return  # ignore flow/http/dns/stats/etc. — only care about alerts

        alert = parse_alert(event)
        block, reason = should_block(alert)

        if block:
            executed, block_reason = block_ip(alert["source_ip"], dry_run=dry_run)
            action = "BLOCK" if executed else "SKIP"
            final_reason = f"{reason} -> {block_reason}"
        else:
            action = "ALLOW"
            final_reason = reason

        log_action(alert["source_ip"], action, final_reason)
        print(f"{action:6} | {alert['source_ip']:15} | severity={alert['severity']:1} | "
              f"{final_reason} | {alert['description']}")

    except Exception as e:
        # Catch-all so an unexpected alert shape (new SMB/DNS/C2 rule fields,
        # missing keys, etc.) can't take the whole watcher down mid-demo.
        print(f"[WARN] Failed to process alert, skipping. error={e} | raw={raw_line.strip()}")


def run_watcher(dry_run=True):
    mode = "DRY RUN (no real blocking)" if dry_run else "LIVE (real iptables blocking)"
    print(f"Watching {ALERT_FILE} for new alerts... [{mode}]")
    print("Press Ctrl+C to stop.\n")

    last_expiry_check = time.time()

    for raw_line in follow(ALERT_FILE):
        process_line(raw_line, dry_run=dry_run)

        # Periodically check if any temporary blocks have expired and should be lifted,
        # instead of only doing this once at the start like the old batch version did.
        if time.time() - last_expiry_check >= EXPIRY_CHECK_INTERVAL_SECONDS:
            check_expired_blocks(dry_run=dry_run)
            last_expiry_check = time.time()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    live_mode = "--live" in sys.argv
    run_watcher(dry_run=not live_mode)
