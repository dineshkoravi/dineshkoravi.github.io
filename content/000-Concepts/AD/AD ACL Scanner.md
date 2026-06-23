---
publish: true
created: 2026-01-29T12:06:57.115+05:30
modified: 2026-06-23T09:55:42.604+05:30
---

Repo : <https://github.com/canix1/ADACLScanner?tab=readme-ov-file>

Works when ldap is available ?

This is obviously a powershell script. so we use `pwnsh` on kali linux to run the script.

```powershell
pwnsh
cd adacl-repo-path
PS> ./ADACLScan.ps1 -base "OU=STAFF,DC=EIGHTEEN,DC=HTB" -Server "Eighteen.htb" -Credentials $(get-credential) -ApplyTo "adam.scott" -PropertyFilter "drink|audio" -Permission "WriteProperty" -AccessType Allow -IncludeInherited | ft

PowerShell credential request
Enter your credentials.
User: adam.scott
Password for user adam.scott: *********
```
