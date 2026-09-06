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
| response-script (Windows) | `source venv/bin/activate` failed with "not recognized" | Used a Linux command on Windows Command Prompt — `source` doesn't exist there | Used the Windows-specific activation command: `venv\Scripts\activate` |
| response-script (Windows) | `python main.py` failed with "No such file or directory" | Was running the command from the wrong folder after opening a new terminal session | Navigated back into the correct project folder with `cd` before running the script |
| response-script (parser) | Script was built against Wazuh's alert format, but team confirmed Suricata `eve.json` was the actual source | Field names differ (`data.srcip` vs `src_ip`) and severity scale is inverted (Wazuh: higher=worse, Suricata: lower=worse) | Rewrote `parser.py` to match Suricata's field names, and flipped the threshold logic in `decision.py` from `>=` to `<=` |
| GitHub (Windows) | `git clone` failed with "'git' is not recognized" | Git was not installed on the Windows machine | Installed Git for Windows, restarted the terminal |
| GitHub (Windows) | `git commit` failed with "Author identity unknown" | Git didn't have a configured username/email yet (first commit on this machine) | Ran `git config --global user.name` and `git config --global user.email` to set identity |

**Result:** Wazuh installed successfully on `ids-engine` after resolving all of the above. Response script rebuilt to match Suricata's real alert format, and successfully committed and pushed to GitHub from Windows for the first time.

---

## August 25, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| suricata-test | `sudo reboot` failed: "Operation inhibited by gnome-session-s... user session inhibited" after installing open-vm-tools-desktop | Ubuntu Desktop's GUI session blocks a plain reboot command to protect against data loss in open apps | Used `sudo systemctl reboot -i` to force reboot, ignoring the session inhibitor |
| suricata-test | Suricata started with warnings: "failed to create socket directory /var/run/suricata/: Permission denied" / "Unable to create unix command socket" | The `/var/run/suricata/` directory didn't exist with correct ownership for the `suricata` service user | `sudo mkdir -p /var/run/suricata && sudo chown suricata:suricata /var/run/suricata`, then `sudo systemctl restart suricata` |
| suricata-test | `ls: cannot open directory '/var/log/suricata/': Permission denied` | Suricata runs as its own dedicated `suricata` user/group; regular user has no read access to the log directory by default | Used `sudo ls` / `sudo cat` to read log files; optionally added user to the `suricata` group for persistent access |
| suricata-test | `nmap -sS` failed: "You requested a scan type which requires root privileges. QUITTING!" | SYN scans need raw socket access, which requires root | Ran with `sudo nmap -sS ...` |
| suricata-test | `suricata-update` completed but logged "Warning: No enabled sources" | No rule source (e.g. ET Open) had been explicitly enabled, so only Suricata's minimal bundled rules were active | `sudo suricata-update enable-source et/open` then re-ran `sudo suricata-update`; confirmed 68,534 rule lines loaded afterward |
| GitHub (Ubuntu VM) | `git clone` failed with "Password authentication is not supported for Git operations" | Tried using the actual GitHub account password instead of a token | Generated a GitHub Personal Access Token (classic, `repo` scope) and used it as the password instead |
| GitHub (Ubuntu VM) | Partial/broken clone folder blocked re-cloning ("destination path already exists") | An earlier clone attempt was interrupted at the authentication prompt, leaving an incomplete folder | Removed the incomplete folder with `rm -rf` before re-cloning cleanly |
| response-script (Ubuntu VM) | Could not paste documentation text into `nano` | Clipboard sharing between host and VM was not enabled/working | Typed the content directly into the terminal using a `cat >> file << 'EOF'` heredoc instead of relying on paste |

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
| response-script (Ubuntu VM) | Needed to confirm blocking logic works for real, not just in simulation | Ran `block_ip("203.0.113.77", dry_run=False)` and checked `sudo iptables -L INPUT -v -n` | Confirmed a live DROP rule was created for the test IP — proves the script can genuinely block traffic, not just print commands |

**Result:** SSH brute-force (sid:1000001) and port scan (sid:1000002) rules both fully validated with clean, single alerts per attack. SMB upload rules (sid:1000003–1000005) remain untested. Response script (parser, decision logic, blocker) fully built, tested in dry-run against sample data, and verified with one real (non-dry-run) `iptables` block on the Ubuntu VM. Pushed to `scripts/` in the shared repo.

---

## September 5, 2026

| Component | Problem | Diagnosis | Fix |
|---|---|---|---|
| victim VM (Samba setup) | `apt install samba` failed: "Temporary failure resolving 'security.ubuntu.com'" | Same class of DNS/network-path issue seen previously during an openssh-server install on a different VM | Confirmed internet reachability and added a working DNS resolver |
| sme-custom.rules (sids 1000003-1000005, SMB upload) | Uploaded `test.exe`, `test.ps1`, `test.bat` via `smbclient`, but none of the 3 custom SMB rules fired | Initial hypothesis testing ruled out SMB app-layer parsing (enabled), `file-store` config (enabled, version 2), and confirmed Suricata *did* see the port-445 traffic — it generated alerts, but only from ET Open's own built-in SMB signatures (sids 2025701, 2025705, 2027204, 2025707), not the custom rules | Root cause isolated using a bare-minimum diagnostic rule (`fileext:"exe"` only): test files were created with `touch` (0-byte, no content). Suricata's file-tracking engine needs actual data flowing through an SMB WRITE to build a file object for `fileext`/`filestore` to evaluate — ET's rules matched anyway because they key off the raw SMB `NT Create AndX Request` protocol structure, not file content |
| sme-custom.rules (sids 1000003-1000005, SMB upload) | Following the root-cause diagnosis above | N/A — confirmed diagnosis | Recreated test files with real content (`echo "..." > test.exe`, etc.), re-uploaded via `smbclient`; all three custom rules fired correctly with `"stored": true` in the fileinfo log |
| sme-custom.rules (sid:1000008, FTP brute-force) | Rule did not fire despite 6 connection attempts to port 21 from `test-scanner`; flow log confirmed Suricata saw the traffic (SYN sent, RST+ACK received, connection closed by timeout) | Rule condition `flow:to_server,established` requires the TCP connection to actually reach an established state (full handshake). A refused connection (nothing listening on the port) sends RST immediately and never becomes "established," so the rule's own condition could never be satisfied regardless of retry count | Installed `vsftpd` on `suricata-test` so port 21 had a real listening service; connections could then establish before closing, satisfying the rule. Re-tested — alert fired correctly, exactly once |
| sme-custom.rules (sids 1000009 RDP, 1000016 MySQL) | Same `established`-state dependency as the FTP rule above — no real RDP or MySQL service available to test against | Setting up full RDP/MySQL servers was unnecessary just to validate connection-pattern detection logic, since the rules only match on TCP handshake behavior to a given port, not actual protocol content | Used a lightweight `nc -lk <port> &` listener on `suricata-test` to complete the TCP handshake without needing the real service; both rules then fired correctly |
| sme-custom.rules (sid:1000006, SQL Injection) | Rule did not fire when sending `curl "http://.../?id=1+UNION+SELECT..."`, despite Suricata logging the HTTP request correctly | The rule's PCRE pattern `UNION\s+SELECT` expects whitespace between the words. `curl`'s default space-encoding uses a literal `+` character in the URL, which is an HTML-form convention, not something Suricata's `http.uri` buffer decodes as whitespace — so `\s+` never matched the literal `+` | Re-sent the request using explicit percent-encoding for spaces (`%20` instead of `+`), which Suricata's URI normalization does decode; alert fired correctly afterward |
| sme-custom.rules (sid:1000007, XSS) | N/A — applied the `%20`/percent-encoding lesson proactively | Same encoding principle as the SQL injection rule | Used `%3C`/`%3E` percent-encoding for `<`/`>` in the test payload from the start; fired correctly on first attempt |
| sme-custom.rules (sid:1000020, SMB Ransom Note) | Rule never fired despite confirmed successful file upload (`fileinfo` log showed the file tracked, 56 bytes, real content) | `sudo suricata -T -c ... -v` revealed a genuine rule syntax error: "invalid formatting or malformed option to filename keyword: 'filename'" — the rule used `filename;` as a bare sticky-buffer modifier followed by a separate `content:"README"`, but Suricata's `filename` keyword requires its match argument directly, e.g. `filename:"README"` | Rewrote as `filename:"README"`; a second validation pass then flagged "can't use multiple nocase modifiers with the same content" — removed the redundant standalone `nocase;` since `filename:"..."` handles matching without it. Rule then loaded with 0 errors and fired correctly |
| sme-custom.rules (sid:1000012, DNS Tunneling) | Rule never fired despite 25 real TXT queries sent and confirmed logged by Suricata (35,159 total DNS events captured) | Rule used `dns.query; content:"TXT"` — but `dns.query` exposes the *queried domain name* (e.g. `data1.exfiltest.com`), not the DNS record type. The literal string "TXT" never appears in the domain name itself, so the content match could never succeed regardless of how many TXT queries were sent | Consulted Suricata's official DNS Keywords documentation; replaced with the correct dedicated keyword `dns.rrtype:TXT`, which matches the actual resource record type field. Rule then fired correctly on the same test traffic |

**RESULT: All 20 of 20 custom Suricata rules validated** (5 original + 15 extended), each with real, documented test traffic and, where applicable, a genuine root-cause fix rather than a superficial retry.

---
