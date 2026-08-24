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

## VM Details

**ids-engine**
- OS: Ubuntu server 
- RAM: 8 GB
- Static IP: 192.168.141.10
- Network adapter setting: Host-Only and NAT

**victim-01**
- OS: ubuntu
- RAM: 4 GB
- Static IP: 192.168.141.20
- Network adapter setting: Host-Only and NAT

**attacker**
- OS: Kali Linux
- RAM: 2 GB
- Static IP: 192.168.141.30
- Network adapter setting: Host-Only and NAT

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
    ens34:
      dhcp4: yes
```
Applied with `sudo netplan apply`, verified with `ip a`.

**victim-01** — configured via nmcli:
```bash
sudo nmcli connection modify "netplan-ens33" ipv4.addresses 192.168.141.20/24
sudo nmcli connection modify "netplan-ens33" ipv4.method manual
sudo nmcli connection down "netplan-ens33" && sudo nmcli connection up "netplan-ens33"
```

**attacker (Kali)** — configured via nmcli:
```bash
sudo nmcli connection modify "wired connection 1" ipv4.addresses 192.168.141.30/24
sudo nmcli connection modify "wired connection 1" ipv4.method manual
sudo nmcli connection down "wired connection 1" && sudo nmcli connection up "wired connection 1"
```

## Connectivity Validation

Confirmed all VMs can ping each other successfully once all three were powered on, static IPs applied, and adapters attached to the same host-only network.

```bash
ping -c 3 192.168.141.20
ping -c 3 192.168.141.30
```


## Related Files
- `docs/network-diagram.pdf` — network topology diagram
