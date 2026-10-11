---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
---

## Linux

### find

- Find `id_rsa` file from the root directory.

```bash
find / -name id_rsa 2> /dev/null
```

- it finds all files with the **setuid** permission on your system without showing any error messages.

```
find / -perm -u=s -type f 2>/dev/null
```

### grep

It searches through all files on your system, starting from the root, for the string `PASSWORD=`, highlights matches, and shows the lines where it was found, while hiding any error messages.

```bash
grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null
```
