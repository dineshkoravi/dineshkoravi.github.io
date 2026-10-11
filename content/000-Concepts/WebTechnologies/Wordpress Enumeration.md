---
publish: true
created: 2026-10-03T08:40:24.747Z
modified: 2026-10-03T08:40:24.747Z
---

# Enumerate Users

```bash
$ wpscan --url http://internal.thm/blog/ -e u
```

# Enumerate vulnerable

```
wpscan --url http://extplorer.local/ -e vp,vt
```

# Enumerate All

```
wpscan --url http://tartarsauce.htb/webservices/wp/ -e ap --plugins-detection aggressive
```
