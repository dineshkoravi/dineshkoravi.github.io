---
publish: true
created: 2026-01-29T12:06:57.115+05:30
modified: 2026-06-21T19:48:52.726+05:30
---

<https://github.com/canix1/ADACLScanner?tab=readme-ov-file>

works when ldap is available ?

This is obviously a powershell script. so we use `pwnsh` on kali linux to run the script.

```
pwnsh
cd adacl-repo-path
PS> ./ADACLScan.ps1 -base "OU=STAFF,DC=EIGHTEEN,DC=HTB" -Server "Eighteen.htb" -Credentials $(get-credential) -ApplyTo "adam.scott" -PropertyFilter "drink|audio" -Permission "WriteProperty" -AccessType Allow -IncludeInherited | ft

PowerShell credential request
Enter your credentials.
User: adam.scott
Password for user adam.scott: *********
```
