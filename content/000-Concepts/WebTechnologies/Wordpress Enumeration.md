---
publish: true
created: 2026-02-06T18:30:02.208+05:30
modified: 2026-06-22T08:52:11.848+05:30
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
