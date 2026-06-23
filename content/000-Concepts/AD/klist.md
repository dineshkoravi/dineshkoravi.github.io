---
publish: true
created: 2026-04-02T16:18:30.257+05:30
modified: 2026-06-21T20:11:27.128+05:30
---

manage tickets.

checking if the ticket is imported to local shell.

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> C:\Windows\System32\klist.exe tickets

Current LogonId is 0:0xa7c0c

Cached Tickets: (1)

#0>	Client: administrator @ RESOURCED.LOCAL
	Server: cifs/RESOURCEDC.resourced.local @ RESOURCED.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
	Start Time: 4/2/2026 3:09:27 (local)
	End Time:   4/2/2026 13:09:27 (local)
	Renew Time: 4/9/2026 3:09:27 (local)
	Session Key Type: AES-128-CTS-HMAC-SHA1-96
	Cache Flags: 0
	Kdc Called:
```

purge tickets

```
klist.exe purge
```
