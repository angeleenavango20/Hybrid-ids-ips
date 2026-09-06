# Master Troubleshooting Log

Every real issue encountered during the build, logged as it happened, organized by date.

---

## August 4, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| wazuh-manager (standalone) | `curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh` downloaded an XML error page instead of the install script | Wazuh's docs had moved from the generic `/4.x/` path to a version-specific path; the old path returned an S3 "AccessDenied" error | Used the correct current URL: `https://packages.wazuh.com/4.14/wazuh-install.sh` |
| wazuh-manager (standalone) | Dashboard returned raw JSON `{"statusCode":401,...}` instead of the login page | URL was copy-pasted with the subnet mask included (`/24`) instead of just the IP | Removed `/24` suffix, used plain `https://<ip>` |

---

## August 17, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| ids-engine / victim-01 | Ubuntu installer showed DHCP IP (192.168.177.130) instead of the expected host-only range | VM's `ens33` was still on the default NAT adapter; host-only adapter had not yet been attached | Attached host-only adapter in VM settings before configuring the static IP |
| ids-engine | "No network detected" warning during install | Static IP `192.168.141.10/24` has no gateway configured (isolated network by design) | Selected "Continue without network" — expected behavior for an isolated lab network |
| ids-engine | `sudo netplan apply` failed: "Invalid YAML: aliases are not supported" | Stray character at the start of the netplan file from an earlier editing mistake | Cleared the file in nano and retyped the config cleanly |
| ids-engine | Nano "Write to File" kept showing "Cancelled" | The filename field was empty — nano had been opened without specifying a path | Manually typed the full path `/etc/netplan/00-installer-config.yaml` before pressing Enter |

---

## August 23, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| docs/ (GitHub) | Created file showed as `network-config-notes.md.txt` in the repo | Windows was hiding the real `.txt` extension in File Explorer, so the file was accidentally saved with a double extension | Enabled "File name extensions" in File Explorer, renamed the file to remove `.txt` |

---

## August 24, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| ids-engine | Wazuh install command produced no output and never completed | VM only had a Host-only adapter — no internet route to reach `packages.wazuh.com` | Added a second NAT network adapter alongside the existing Host-only adapter |
| ids-engine | Wazuh Manager failed to start: `wazuh-keystore: No such file or directory`; installer auto-rolled-back | Ubuntu 26.04 is not on Wazuh's supported OS list (supports up to 22.04); Manager package incompatible with this OS version | Deleted VM, rebuilt `ids-engine` on Ubuntu 22.04 LTS |
| ids-engine | Dashboard install failed: "No space left on device", despite a freshly created 40-48GB VM | `df -h` showed `/` only had 24GB total; `sudo vgs` confirmed 24GB sat unallocated — Ubuntu's guided LVM installer only assigned half the disk to the root volume by default | `sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv` then `sudo resize2fs /dev/ubuntu-vg/ubuntu-lv` to reclaim full disk space |
| ids-engine | Reinstall attempt failed: "Port 1515 is being used by another process" / "Port 55000 is being used by another process" | `sudo lsof -i :1515` and `:55000` revealed leftover `wazuh-authd` and `python3` (Wazuh API) processes still running from the earlier rolled-back install | Killed the stuck processes directly: `sudo kill -9 <pid>` for each port, verified with repeated `lsof` checks |
| ids-engine | `dpkg --purge wazuh-manager` failed repeatedly — first on a broken `prerm` script (exit 127), then a broken `postrm` script referencing a deleted directory | Earlier manual `rm -rf /var/ossec` cleanup had deleted directories the package's own removal scripts still expected to exist, corrupting the package's removal state | Deleted the VM entirely and rebuilt fresh rather than continuing to patch corrupted package metadata |
| ids-engine | Same LVM under-allocation pattern visible again during the fresh install's storage configuration screen (28.9GB of 57.9GB assigned to root) | Confirmed this is default behavior of Ubuntu's guided LVM installer, not a one-off fluke | Proceeded with installer defaults, then applied the `lvextend`/`resize2fs` fix immediately after first login, before installing anything else |
**Result:** Wazuh installed successfully on `ids-engine` after resolving all of the above.
| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| response-script (Windows) | `source venv/bin/activate` failed with "not recognized" | Used a Linux command on Windows Command Prompt — `source` doesn't exist there | Used the Windows-specific activation command: `venv\Scripts\activate` |
| response-script (Windows) | `python main.py` failed with "No such file or directory" | Was running the command from the wrong folder after opening a new terminal session | Navigated back into the correct project folder with `cd` before running the script |
| response-script (parser) | Script was built against Wazuh's alert format, but team confirmed Suricata `eve.json` was the actual source | Field names differ (`data.srcip` vs `src_ip`) and severity scale is inverted (Wazuh: higher=worse, Suricata: lower=worse) | Rewrote `parser.py` to match Suricata's field names, and flipped the threshold logic in `decision.py` from `>=` to `<=` |
| GitHub (Windows) | `git clone` failed with "'git' is not recognized" | Git was not installed on the Windows machine | Installed Git for Windows, restarted the terminal |
| GitHub (Windows) | `git commit` failed with "Author identity unknown" | Git didn't have a configured username/email yet (first commit on this machine) | Ran `git config --global user.name` and `git config --global user.email` to set identity |

**Result:** Response script rebuilt to match Suricata's real alert format, and successfully committed and pushed to GitHub from Windows for the first time.

---


## August 25, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| suricata-test | `sudo reboot` failed: "Operation inhibited by gnome-session-s... user session inhibited" after installing open-vm-tools-desktop | Ubuntu Desktop's GUI session blocks a plain reboot command to protect against data loss in open apps | Used `sudo systemctl reboot -i` to force reboot, ignoring the session inhibitor |
| suricata-test | Suricata started with warnings: "failed to create socket directory /var/run/suricata/: Permission denied" / "Unable to create unix command socket" | The `/var/run/suricata/` directory didn't exist with correct ownership for the `suricata` service user | `sudo mkdir -p /var/run/suricata && sudo chown suricata:suricata /var/run/suricata`, then `sudo systemctl restart suricata` |
| suricata-test | `ls: cannot open directory '/var/log/suricata/': Permission denied` | Suricata runs as its own dedicated `suricata` user/group; regular user has no read access to the log directory by default | Used `sudo ls` / `sudo cat` to read log files; optionally added user to the `suricata` group for persistent access |
| suricata-test | `nmap -sS` failed: "You requested a scan type which requires root privileges. QUITTING!" | SYN scans need raw socket access, which requires root | Ran with `sudo nmap -sS ...` |
| suricata-test | `suricata-update` completed but logged "Warning: No enabled sources" | No rule source (e.g. ET Open) had been explicitly enabled, so only Suricata's minimal bundled rules were active | `sudo suricata-update enable-source et/open` then re-ran `sudo suricata-update`; confirmed 68,534 rule lines loaded afterward |
## August 25, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| GitHub (Ubuntu VM) | `git clone` failed with "Password authentication is not supported for Git operations" | Tried using the actual GitHub account password instead of a token | Generated a GitHub Personal Access Token (classic, `repo` scope) and used it as the password instead |
| GitHub (Ubuntu VM) | Partial/broken clone folder blocked re-cloning ("destination path already exists") | An earlier clone attempt was interrupted at the authentication prompt, leaving an incomplete folder | Removed the incomplete folder with `rm -rf` before re-cloning cleanly |
| response-script (Ubuntu VM) | Could not paste documentation text into `nano` | Clipboard sharing between host and VM was not enabled/working | Typed the content directly into the terminal using a `cat >> file << 'EOF'` heredoc instead of relying on paste |

**Result:** Repo successfully cloned onto the Ubuntu VM using token-based authentication, ready for real (non-dry-run) testing.

---
## August 30, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| sme-custom.rules (sid:1000002, port scan) | Port scan rule never fired during `nmap -sS -p 1-1000` scan from a separate VM | `flags:S,CE` required SYN+CWR+ECE flags together; a normal SYN scan only sets the bare SYN flag, so the exact-match condition could never be satisfied | Changed `flags:S,CE` to `flags:S` |
| sme-custom.rules (sid:1000002, port scan) | Rule still didn't fire after the flag fix | `journalctl -u suricata` revealed: "No rule files match the pattern /var/lib/suricata/rules/sme-custom.rules" — the working file lived in `/etc/suricata/rules/`, but Suricata's `default-rule-path` pointed to `/var/lib/suricata/rules/`, so the file was silently never loaded at all | Copied `sme-custom.rules` into `/var/lib/suricata/rules/` to match `default-rule-path`; confirmed with `suricata -T -c /etc/suricata/suricata.yaml -v` — 52,594 rules loaded, 0 failed, 0 skipped |
| sme-custom.rules (sid:1000002, port scan) | Rule fired correctly, but `eve.json` was flooded with dozens of near-identical alerts (19 alerts within 3ms for one scan) | `detection_filter` re-alerts on every matching packet once the threshold is met, rather than firing once per detected event | Swapped `detection_filter:track by_src, count 15, seconds 10;` to `threshold:type both, track by_src, count 15, seconds 10;` — confirmed exactly one alert per scan afterward |
| test-scanner / victim VM | SSH brute-force test loop failed: "Connection timed out" then "Network is unreachable" | `test-scanner` and the intended target VM were attached to two different virtual networks in VMware, not the same host-only network | Aligned both VMs' network adapter settings to the same virtual network; SSH connectivity succeeded afterward |
| victim VM | `apt install openssh-server` failed: "Temporary failure resolving 'in.archive.ubuntu.com'" | No working DNS / no internet-reachable path on that VM's network adapter at the time | Not directly root-caused; resolved indirectly by confirming and switching to the correct VM/subnet for testing |
| sme-custom.rules (sid:1000001, SSH brute-force) | Rule fired correctly, but 99 alerts logged for a single 6-attempt SSH test | Same root cause as the port-scan flooding issue — `detection_filter` re-alerting per matching packet | Swapped `detection_filter:track by_src, count 5, seconds 60;` to `threshold:type both, track by_src, count 5, seconds 60;` — confirmed exactly one alert |

**Result:** SSH brute-force (sid:1000001) and port scan (sid:1000002) rules both fully validated with clean, single alerts per attack. SMB upload rules (sid:1000003–1000005) remain untested 
## August 30, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| response-script (Ubuntu VM) | Needed to confirm blocking logic works for real, not just in simulation | Ran `block_ip("203.0.113.77", dry_run=False)` and checked `sudo iptables -L INPUT -v -n` | Confirmed a live DROP rule was created for the test IP — proves the script can genuinely block traffic, not just print commands |

**Result:** Response script (parser, decision logic, blocker) fully built, tested in dry-run against sample data, and verified with one real (non-dry-run) `iptables` block on the Ubuntu VM. Pushed to `scripts/` in the shared repo.


