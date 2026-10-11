---
publish: true
created: 2026-10-03T08:40:24.739Z
modified: 2026-10-03T08:40:24.739Z
---

## change password

```
net rpc password "CA_OPERATOR" "Password@123" -U "certified.htb"/"judith.mader"%"judith09" -S "DC01.certified.htb"
```

## get members of a group

```
$ net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S DC01.certified.htb
CERTIFIED\judith.mader
CERTIFIED\management_svc
```
