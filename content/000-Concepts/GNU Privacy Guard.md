---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

### gpg

GNU Privacy Guard.

```shell
gpg --import tryhackme.asc ## import private key

gpg --list-secret-keys

gpg --output ./d.txt --decrypt ./credential.pgp ## decrypt a file
```

### Gpg2john

Extract hashes from gpg into crackable format and display it.

```
gpg2john private_pgp_key.asc > hash && cat hash
```
