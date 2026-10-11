---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
---

<https://wiki.archlinux.org/title/Port_knocking>

Port knocking is a security technique that keeps server ports closed by default, protecting services like SSH from brute-force attacks by requiring a specific, secret sequence of connection attempts (the "knock") to open them

you can find binary like `/etc/init.d/knockd`

and configuration like

```
www-data@nineveh:/var/log$ cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

<https://medium.com/@mayankgahlot/understanding-port-knocking-security-through-obscurity-39709d077794>

```
$ sudo hping3 -S nineveh.htb -p 571 -c 1; sudo hping3 -S nineveh.htb -p 290 -c 1; sudo hping3 -S nineveh.htb -p 911 -c 1
```
