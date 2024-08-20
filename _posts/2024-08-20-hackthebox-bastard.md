---
title: HackTheBox - Bastard
description: Bastard is not overly challenging, however it requires some knowledge of PHP in order to modify and use the proof of concept required for initial entry. This machine demonstrates the potential severity of vulnerabilities in content management systems.
date: 2024-08-20 10:30:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Medium, Windows]
image:
  path: /assets/img/headers/htb_bastard.webp
---

## Enumeration

Starting with basic nmap scan.

## Nmap

```console
$ sudo nmap -p- -T5 -Pn -sT bast.htb               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-17 11:41 IST
Warning: 10.10.10.9 giving up on port because retransmission cap hit (2).
Nmap scan report for bast.htb (10.10.10.9)
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 517.33 seconds

$ sudo nmap -p80,135,49154 -sC -sV -T5 -Pn bast.htb  
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-17 12:12 IST
Nmap scan report for bast.htb (10.10.10.9)
Host is up (0.20s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-title: Welcome to Bastard | Bastard
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.05 seconds
```

Some interesting Data we found.

```
Server: Microsoft-IIS/7.5
X-Powered-By: PHP/5.3.28
X-Powered-By: ASP.NET
```

From changelog.txt, I found the Drupal version. `Drupal 7.54`

> http://bast.htb//CHANGELOG.txt 


## Foothold

### Drupal RCE - CVE-2018-7600

Quick Google search shows that Drupal 7.54 is vulnerable to **CVE-2018-7600**. i got a shell by exploiting this with python exploit. Now we have a user 'Dimitris' shell.

Python exploit : [https://github.com/0xConstant/CVE-2018-7600/blob/main/exploit.py](https://github.com/0xConstant/CVE-2018-7600/blob/main/exploit.py)

```console
C:\inetpub\drupal-7.54>type C:\Users\Dimitris\Desktop\user.txt
type C:\Users\Dimitris\Desktop\user.txt
```

## Privilege Escalation

Lets use windows-exploit-suggester. we can input **systeminfo** output from user shell to this tool.

`python3 windows-exploit-suggester.py --systeminfo systeminfo.txt --database 2024-08-17-mssb.xlsx`

It showed that machine is vulnerable to **MS10-059**. After exploiting we can get **root.txt**. 

Priv Esc Procedure : [posts/hackthebox-devel/#privilege-escalation](https://dineshkoravi.github.io/posts/hackthebox-devel/#privilege-escalation)

`type C:\Users\Administrator\Desktop\root.txt`