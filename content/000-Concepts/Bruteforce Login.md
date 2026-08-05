---
publish: true
created: 2026-02-06T17:42:13.907+05:30
modified: 2026-06-22T08:58:37.096+05:30
---

### hydra

```bash

## HTTP-POST-FORM
# To list options
$ hydra -U http-post-form

# Example
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 16 -s 4444 localhost http-post-form "/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:Error" -vV -f
```
