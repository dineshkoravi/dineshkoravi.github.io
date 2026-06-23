---
publish: true
created: 2026-02-06T17:39:52.684+05:30
modified: 2026-06-22T09:00:17.660+05:30
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
