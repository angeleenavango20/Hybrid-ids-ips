# sme-custom.rules

```
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute-Force Attempt - Multiple Connections"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1; classtype:attempted-admin; priority:2;)

alert tcp any any -> $HOME_NET any (msg:"CUSTOM Possible Port Scan - Multiple Ports Same Source"; flags:S; threshold:type both, track by_src, count 15, seconds 10; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)

alert smb any any -> $HOME_NET 445 (msg:"CUSTOM Suspicious Executable Upload via SMB Share"; flow:to_server,established; fileext:"exe"; filestore; sid:1000003; rev:1; classtype:policy-violation; priority:2;)

alert smb any any -> $HOME_NET 445 (msg:"CUSTOM Suspicious Script Upload via SMB Share (.ps1)"; flow:to_server,established; fileext:"ps1"; filestore; sid:1000004; rev:1; classtype:policy-violation; priority:2;)

alert smb any any -> $HOME_NET 445 (msg:"CUSTOM Suspicious Script Upload via SMB Share (.bat)"; flow:to_server,established; fileext:"bat"; filestore; sid:1000005; rev:1; classtype:policy-violation; priority:2;)
```
