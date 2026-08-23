## iptables Manual Block Test (ids-engine)

**Date:** August 17, 2026
**Tested by:** Person A (Network Design)
**Goal:** Validate that ids-engine can successfully block traffic from a specific IP at the network level, before Person C automates this via the response script.

| Step | Action | Result |
|---|---|---|
| 1 | Baseline ping from ids-engine to attacker (192.168.141.30) | Success |
| 2 | Ran `sudo iptables -A INPUT -s 192.168.141.30 -j DROP` | Rule added silently (no output expected) |
| 3 | Ping ids-engine → attacker again | Failed — 100% packet loss, "Destination Host Unreachable" |
| 4 | Ran `sudo iptables -D INPUT -s 192.168.141.30 -j DROP` | Rule removed |
| 5 | Ping ids-engine → attacker again | Success — connectivity restored |

**Result:** Confirmed. iptables successfully blocks and unblocks traffic from a target IP on ids-engine.

**Note for Person C:** This is the exact rule your response script should trigger programmatically when Suricata generates an alert for a malicious IP:
`sudo iptables -A INPUT -s <attacker_ip> -j DROP`

**Screenshot:** `screenshots/iptables-block-test-ids-engine.png`