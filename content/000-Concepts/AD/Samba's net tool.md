---
publish: true
created: 2026-03-12T04:40:44.574+05:30
modified: 2026-06-21T20:12:16.168+05:30
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
