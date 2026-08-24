## Troubleshooting Log

| Problem | Diagnosis | Fix |
|---|---|---|
| Ubuntu installer showed DHCP IP (192.168.177.130) instead of expected host-only range | VM's `ens33` was still on default NAT adapter, host-only not yet attached | Attached host-only adapter in VM settings before configuring static IP |
| "No network detected" warning during install | Static IP `192.168.141.10/24` has no gateway (isolated network) | Selected "Continue without network" — expected behavior for an isolated lab |
| `sudo netplan apply` failed: "Invalid YAML: aliases are not supported" | Stray character at start of netplan file from an editing mistake | Cleared file in nano and retyped config cleanly |
| Nano "Write to File" kept showing "Cancelled" | File name field was empty (nano opened without a path) | Manually typed full path `/etc/netplan/00-installer-config.yaml` before pressing Enter |
| `victim-01` unreachable ("Destination Host Unreachable") from ids-engine | `victim-01` VM was either off, or static IP not yet configured/applied | Powered on `victim-01`, configured IP, applied |
| Created file showed as `network-config-notes.md.txt` in git | Windows was hiding the real `.txt` extension in File Explorer | Enabled "File name extensions" in File Explorer, renamed file to remove `.txt` |