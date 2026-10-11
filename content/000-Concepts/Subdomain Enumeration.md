---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
---

### wfuzz

Subdomain enumeration using wfuzz.

```bash
wfuzz -c -f sub-fighter -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://cmess.thm' -H "Host: FUZZ.cmess.thm" --hw 290

## --hw 290 removes responses with wordcount 290.

# wfuzz  for LFI too.
```
