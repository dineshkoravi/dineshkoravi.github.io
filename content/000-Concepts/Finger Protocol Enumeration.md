---
publish: true
created: 2026-02-04T12:03:55.861+05:30
modified: 2026-06-22T08:59:56.944+05:30
tags:
  - finger
---

`Finger` - display's information about users who are logged on in remote systems.

simple way:

```
$ echo "sunny" | nc sunday 79
Login       Name               TTY         Idle    When    Where
sunny           ???            ssh          <Feb  4 06:31> 10.10.16.101
```

using tools - https://pentestmonkey.net/tools/user-enumeration/finger-user-enum]\(https://pentestmonkey.net/tools/user-enumeration/finger-user-enum) - download and extract.

```
$ ./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 10.129.109.26
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10713
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Wed Feb  4 00:17:07 2026 #########
access@10.129.109.26: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.129.109.26: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..netadm   Network Admin                      < .  .  .  . >..netcfg   Network Configuratio               < .  .  .  . >..dhcpserv DHCP Configuration A               < .  .  .  . >..ikeuser  IKE Admin                          < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..
anne marie@10.129.109.26: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.129.109.26: bin             ???                         < .  .  .  . >..
dee dee@10.129.109.26: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
ike@10.129.109.26: ikeuser  IKE Admin                          < .  .  .  . >..
jo ann@10.129.109.26: Login       Name               TTY         Idle    When    Where..ann                   ???..jo                    ???..
la verne@10.129.109.26: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.129.109.26: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.129.109.26: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.129.109.26: Login       Name               TTY         Idle    When    Where..mela                  ???..miof                  ???..
root@10.129.109.26: root     Super-User            console      <Dec  7, 2023>..
sammy@10.129.109.26: sammy           ???            ssh          <May  6, 2025> 10.10.14.68         ..
sunny@10.129.109.26: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sys@10.129.109.26: sys             ???                         < .  .  .  . >..
zsa zsa@10.129.109.26: Login       Name               TTY         Idle    When    Where..zsa                   ???..zsa                   ???..
######## Scan completed at Wed Feb  4 00:49:31 2026 #########
16 results.

10713 queries in 1944 seconds (5.5 queries / sec)
```
