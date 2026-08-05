---
publish: true
created: 2026-02-06T18:47:40.483+05:30
modified: 2026-06-22T08:53:29.632+05:30
---

# OS Architecture

```powershell
wmic os get osarchitecture

systeminfo

# Get 64bit or 32 bit from registry
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE

# check dotnet framework version, version below 4.0

# get .NET framework version
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"


cd C:\Windows\Microsoft.Net\Framework64
dir
# d-----        2/25/2026  11:13 AM                v4.0.30319

# check dotnet version with registry, version above 4.0
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse

# or 
PS C:\Users> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    CBS    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    InstallPath    REG_SZ    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
    Release    REG_DWORD    0x70bf6
    Servicing    REG_DWORD    0x0
    TargetVersion    REG_SZ    4.0.0
    Version    REG_SZ    4.7.03190

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\1033

# to see the path to place modules.
echo $Env:PSModulePath
```

# Service Enumeration

hacktricks - <https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services>

```powershell
# look for service dllsvc
Get-Service -name 'dllsvc'

# Look for service via registry
Set-Location HKLM:\SYSTEM\CurrentControlSet\Services
Get-ChildItem .

# Look for process. note the process name.
# fl - format list
Get-Process
Get-Process -Name CloudMe | fl *
Get-Process -Name CloudMe | Format-Table -Property Id

#requires admin priv to check who is running this process.
Get-Process -Name CloudMe -IncludeUserName
```

# Filesystem Search

```powershell
# Look for hidden files
Get-ChildItem -Force

# look for file 'bash.exe' in C drive.
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\" -Filter "bash.exe" -Recurse -File

# check a files permissions
icacls filename

# when in user directory - list all files 
tree . /f
tree /f /a

# see hex
Format-Hex 'file'

# find strings in file.

# print last 5 lines of file.
Get-Content -Path "C:\ProgramData\UpdateMonitor\Logs\monitor.log" -Tail 5
```

# network

```powershell
netstat -ano | findstr LISTENING
```

# RunAs

```
# run as service account
runas /netonly
```

# User Privileges

[[User Privileges]]

# Registeries
