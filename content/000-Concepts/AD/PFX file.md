---
publish: true
created: 2026-03-12T18:25:58.469+05:30
modified: 2026-06-21T20:11:58.188+05:30
---

A PFX file (Personal Information Exchange, or PKCS#12) is ==a password-protected, binary file used to securely store a SSL/TLS certificate, its corresponding private key, and optional intermediate CA certificates==. Commonly used on Windows and IIS servers, these files facilitate the transfer of digital identities for code signing and web server encryption.

## Convert to PEM

PFX is windows related and is binary.
PEM is linux related and ascii

Linux tools use .pem and .crt files. conversion is required when using same on linux.

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out private.pem
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt
openssl rsa -in private.pem -out private2.pem
```

and use it with tool.

```
evil-winrm -i 10.10.11.152 -k private2.pem -c cert.crt -S
```
