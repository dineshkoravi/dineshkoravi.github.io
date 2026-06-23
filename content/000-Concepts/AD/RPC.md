---
publish: true
created: 2026-03-03T13:42:15.309+05:30
modified: 2026-06-21T20:12:10.752+05:30
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
