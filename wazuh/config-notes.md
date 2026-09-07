# Wazuh Setup Notes — ids-engine (Final, Working)

## VM Details
- **VM name:** `ids-engine`
- **OS:** Ubuntu Server 22.04 LTS 
- **RAM:** 8 GB
- **CPUs:** 2
- **Disk:** 50 GB 
- **Network:** Host-only adapter (internal VM network) + NAT adapter (internet access)
- **Static IP:** 192.168.141.10

## Installation Steps 

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

This installs the full stack in one pass: Wazuh Manager, Indexer, and Dashboard.

At the end of a successful install, the script prints:
```
User: admin
Password: <randomly generated>
```
**This password is unique per install** — do not assume it matches any other Wazuh VM's password. Save it locally. If missed, retrieve with:
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

## Dashboard Access

From the host laptop's browser (not inside the VM):
```
https://192.168.141.10
```
Expect a "Not Secure" browser warning (self-signed certificate) — this is normal and expected for a local install. Click through (Advanced → Proceed anyway), then log in with `admin` + the saved password.

## Agent Deployment — victim-01

1. In the Wazuh Dashboard, go to **Endpoints** → **Deploy new agent**
2. Package: **Linux → DEB amd64** 
3. Server address: `192.168.141.10`
4. Agent name: `victim-01`
5. Run the generated install command on `victim-01`
6. Enable and start the agent:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-agent
   sudo systemctl start wazuh-agent
   ```
7. Confirmed **Active** in the dashboard under Endpoints.

---

## Compatibility Note — Ubuntu Version

Wazuh 4.14's officially supported OS list (per install logs) includes RHEL, CentOS, Amazon Linux, **Ubuntu 16.04/18.04/20.04/22.04**, and Rocky Linux — **Ubuntu 26.04 is not supported**. Installing on 26.04 causes the Wazuh Manager package to fail (`wazuh-keystore: No such file or directory`), triggering an automatic rollback. `ids-engine` was rebuilt on Ubuntu 22.04 LTS to resolve this.

## Disk Space Note — LVM Under-Allocation

Ubuntu Server's guided LVM installer, by default, does **not** allocate the full disk to the root logical volume — on a 48GB disk, only ~24GB was assigned, with the rest sitting unallocated and invisible to `df -h`. This caused "No space left on device" failures partway through the Wazuh Dashboard install step, even on a freshly created VM.

**Fix — run this immediately after first login, before installing anything:**
```bash
sudo vgs                                              # confirm free space exists
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv   # extend the logical volume
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv               # resize the filesystem to match
df -h                                                 # confirm full disk now available
```
This should become a standard first step on any fresh Ubuntu Server VM in this project going forward.

## Networking Note

`ids-engine` needs **both** adapters attached from the start:
- **Host-only** — for connectivity to `victim-01` and `attacker`
- **NAT** — without this, `curl`/`apt` commands hang indefinitely trying to reach the internet, with no error message

---

