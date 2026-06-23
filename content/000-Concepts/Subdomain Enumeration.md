---
publish: true
created: 2026-02-06T18:30:32.779+05:30
modified: 2026-06-22T09:02:33.688+05:30
---

### wfuzz

Subdomain enumeration using wfuzz.

```bash
wfuzz -c -f sub-fighter -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://cmess.thm' -H "Host: FUZZ.cmess.thm" --hw 290

## --hw 290 removes responses with wordcount 290.

# wfuzz  for LFI too.
```
