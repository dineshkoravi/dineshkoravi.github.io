---
publish: true
created: 2026-10-03T08:40:24.739Z
modified: 2026-10-03T08:40:24.739Z
---

# MS-RPC

Tools - _rpcclient_
also on port 135,593

## rpcclient

```
# Login with null creds
$ rpcclient -U '%' forest

# run commands without shell.
rpcclient -U '%' 10.129.1.126 -c 'enumdomusers'
```

change password.

```
rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]

result was NT_STATUS_INVALID_PARAMETER
rpcclient $> setuserinfo2 audit2020 23 Password123!
```
