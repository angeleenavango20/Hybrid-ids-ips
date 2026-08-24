# Network Setup Notes

## Overview
This document covers the setup of the isolated host-only network connecting all 3 VMs for the Hybrid IDS/IPS project, along with static IP configuration and connectivity validation.

## Architecture

| VM | Role | Static IP |
|---|---|---|
| `ids-engine` | Suricata + Wazuh combined | 192.168.141.10/24 |
| `victim-01` | Protected endpoint (Wazuh agent) | 192.168.141.20/24 |
| `attacker` | Kali Linux, attack simulation | 192.168.141.30/24 |

All three VMs sit on the same isolated **VMware Host-Only network** (no gateway, no internet access on this adapter — traffic stays contained within the lab).

See `docs/network-diagram.pdf` for the visual topology.

## VMware Host-Only Network Setup

1. Opened VMware → Edit → Virtual Network Editor
2. Used the default host-only network (VMnet1), subnet `192.168.141.0/24`
3. Attached each VM's Network Adapter to this Host-only network (VM → Settings → Network Adapter → Host-only)

## Static IP Configuration

**ids-engine** — configured via netplan:
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.141.10/24]
```
Applied with `sudo netplan apply`, verified with `ip a`.

**victim-01** — configured via nmcli:
```bash
sudo nmcli connection modify "Wired connection 1" ipv4.addresses 192.168.141.20/24
sudo nmcli connection modify "Wired connection 1" ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```

**attacker (Kali)** — configured via nmcli:
```bash
sudo nmcli connection modify "Wired connection 1" ipv4.addresses 192.168.141.30/24
sudo nmcli connection modify "Wired connection 1" ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```

## Connectivity Validation

Confirmed all VMs can ping each other successfully once all three were powered on, static IPs applied, and adapters attached to the same host-only network.

```bash
ping -c 3 192.168.141.20
ping -c 3 192.168.141.30
```

## iptables Manual Block Test (ids-engine)

**Date:** August 23, 2026
**Goal:** Validate that ids-engine can block traffic from a specific IP at the network level, before Person C automates this via the response script.

| Step | Action | Result |
|---|---|---|
| 1 | Baseline ping from ids-engine to attacker (192.168.141.30) | Success |
| 2 | Ran `sudo iptables -A INPUT -s 192.168.141.30 -j DROP` | Rule added silently |
| 3 | Ping ids-engine → attacker again | Failed — 100% packet loss, "Destination Host Unreachable" |
| 4 | Ran `sudo iptables -D INPUT -s 192.168.141.30 -j DROP` | Rule removed |
| 5 | Ping ids-engine → attacker again | Success — connectivity restored |

**Result:** Confirmed. iptables successfully blocks and unblocks traffic from a target IP on ids-engine.

**Note for Person C:** This is the exact rule the response script should trigger programmatically when Suricata generates an alert:
`sudo iptables -A INPUT -s <attacker_ip> -j DROP`

**Screenshot:** `screenshots/iptables-block-test-ids-engine.png`

## Troubleshooting Log

| Problem | Diagnosis | Fix |
|---|---|---|
| Ubuntu installer showed DHCP IP (192.168.177.130) instead of expected host-only range | VM's `ens33` was still on default NAT adapter, host-only not yet attached | Attached host-only adapter in VM settings before configuring static IP |
| "No network detected" warning during install | Static IP `192.168.141.10/24` has no gateway (isolated network) | Selected "Continue without network" — expected behavior for an isolated lab |
| `sudo netplan apply` failed: "Invalid YAML: aliases are not supported" | Stray character at start of netplan file from an editing mistake | Cleared file in nano and retyped config cleanly |
| Nano "Write to File" kept showing "Cancelled" | File name field was empty (nano opened without a path) | Manually typed full path `/etc/netplan/00-installer-config.yaml` before pressing Enter |
| `victim-01` unreachable ("Destination Host Unreachable") from ids-engine | `victim-01` VM was either off, or static IP not yet configured/applied | Powered on `victim-01`, configured IP, applied |
| Created file showed as `network-config-notes.md.txt` in git | Windows was hiding the real `.txt` extension in File Explorer | Enabled "File name extensions" in File Explorer, renamed file to remove `.txt` |

## Related Files
- `docs/network-diagram.pdf` — network topology diagram
- `screenshots/iptables-block-test-ids-engine.png` — iptables validation test