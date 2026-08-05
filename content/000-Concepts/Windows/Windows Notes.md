---
publish: true
created: 2026-06-16T17:40:37.116+05:30
modified: 2026-06-22T08:53:35.712+05:30
---

# Local Privilege Escalation

All topics which could help us with Local Privilege Escalation on a windows machine.

1. Perform [[Windows Enumeration]] using cmd or powershell.
2. check if current user's [[User Privileges]] are overly permissive.
3. check if current user's[[Access Control Lists (ACL)]] allows us to modify anything using icacls.

# Credentials

To find the credentials in the system.

1. check if any [[Cached GPP Files]] are present.
2. [[DPAPI]]
3. To use found account credentials in current shell which is different user, use [[PScredential - RunAs]].

# Executables

Sometimes, you will need to play around the executable on the machine i.e, Compile or decompilation.

1. [[Compile Windows Software]]
2. [[Reverse Engineering]]

# Services or apps

exploiting some services related to windows.

1. [[MSSQL]]

# Shells

after exploitation, you will need to get a shell back.

1. use [[Nishang's Shells]], these are the best.
2. if WinRM is not enabled by default, you can [[Enable WinRM]].
