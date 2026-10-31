# From Detection to Action: A Linux-Based Hybrid IDS/IPS with Automated IP Blocking for SMEs

Extends the detection-only Suricata + Wazuh architecture of Mersni et al. (IEEE Access, 2025) with an **automated response layer** that blocks malicious IPs in real time and unblocks them after a timeout.

> **Lab and educational use only.** This is a research prototype validated on an isolated virtual lab. The IP addresses shown are private lab addresses. Review and harden before any production use.

## Why

Suricata runs out-of-band on mirrored (SPAN) traffic, so it can only alert and never stop an attack. Every response needs a human. This project turns that IDS into a working IPS.

## Architecture

Three VMs on a host-only network `192.168.141.0/24`:

| VM | Role | IP |
|---|---|---|
| `ids-engine` | Suricata + Wazuh + Filebeat + response script | .10 |
| `victim-01` | Protected endpoint (Wazuh agent, **enforcement point**) | .20 |
| `attacker` | Kali Linux, simulated attacks | .30 |

```
attacker ──attack──▶ victim-01 ◀── SSH: iptables DROP ──┐
    │ (mirrored copy)                                   │
    ▼                                                   │
ids-engine: Suricata → eve.json → main.py → parser → decision (rules + ML) → blocker
                                      └─ block_log.txt → Filebeat → Wazuh dashboard
```

**Key finding:** blocking on `ids-engine` does not stop attacker → victim traffic, because `ids-engine` is not in the traffic path. Blocks are applied **on `victim-01` over key-based SSH**, with a `NOPASSWD` sudo rule limited to `iptables`.

## Features

- 20 custom Suricata rules (SSH/FTP/RDP/MySQL brute force, port scan, SYN/ICMP flood, SQLi, XSS, SMB uploads, C2, reverse shell, DNS tunneling, etc.)
- Continuous `tail -f` style watcher with log-rotation handling
- Hybrid decision engine: severity threshold + repeat-offender count, backed by a **local ML layer** (Isolation Forest + Random Forest false-positive check, no external API)
- Automatic 10-minute unblock, whitelist, duplicate-rule prevention, startup reconciliation with real firewall state
- Block/unblock events logged as JSON and shown in the Wazuh dashboard

## Structure
- `docs/` — network diagrams, troubleshooting log, final report
- `suricata/` — custom Suricata detection rules
- `wazuh/` — Wazuh setup notes and configs
- `scripts/` — automated IP-blocking response script
- `screenshots/` — demo evidence (alerts, dashboard, blocking)

## Quick Start

```bash
# 1. Dependencies (ids-engine)
pip3 install scikit-learn joblib numpy --break-system-packages

# 2. Key-based SSH from ids-engine to victim-01
ssh-keygen -t ed25519 && ssh-copy-id <victim_user>@192.168.141.20

# 3. On victim-01, via visudo: allow passwordless iptables only
#    <victim_user> ALL=(root) NOPASSWD: /usr/sbin/iptables

# 4. Edit REMOTE_HOST, REMOTE_USER and WHITELIST in scripts/blocker.py

# 5. Run
cd scripts
python3 main.py            # dry run (prints only)
python3 main.py --live     # real blocking on victim-01
```

Test it from `attacker`:

```bash
for i in {1..6}; do ssh -o ConnectTimeout=1 fakeuser@192.168.141.20; done
```

Verify on `victim-01` with `sudo iptables -L INPUT -n -v`. The attacker's ping to `victim-01` should drop to 100% loss, then recover after 10 minutes.

## Key Settings

| Setting | Value |
|---|---|
| `SEVERITY_THRESHOLD` | 2 |
| `REPEAT_OFFENSE_LIMIT` | 5 |
| `BLOCK_DURATION_MINUTES` | 10 |
| `CLASSIFIER_CONFIDENCE_THRESHOLD` | 0.6 |

## Results

- Real SSH brute-force detected, attacker blocked on `victim-01` (100% packet loss), connectivity restored after auto-unblock
- ML classifier: 98.1% train / 96.6% test accuracy (synthetic data)
- Suricata memory footprint: about 208 MB

## Limitations

- Enforcement targets a single endpoint
- ML models trained on synthetic data
- Packet drops observed under load on the current VM allocation
- Validated on a single virtualized lab network

## Team

Angeleena Jobin, Archana Chakkalayil, Malavika M Nair, Nandana Anna Paul


## Base Paper
A. Mersni, N. Šehović, N. Subašić-Hodža, N. Rustempašić, and M. Čeljo, “Hybrid Intrusion Detection System for Small and Medium Enterprises,” IEEE Access, vol. 13, pp. 216253–216271, 2025, doi: 10.1109/ACCESS.2025.3646112.
