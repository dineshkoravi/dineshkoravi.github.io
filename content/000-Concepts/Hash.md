---
publish: true
created: 2026-02-06T16:41:51.527+05:30
modified: 2026-06-22T09:00:21.192+05:30
---

a one-way process using algorithms (like SHA-256) to convert data into a unique, fixed-length string (a hash) for verifying integrity, securing passwords, and digital signatures, preventing direct exposure of sensitive info even if data is breached, as it's computationally infeasible to reverse the hash to get the original data.

To identify the type of hash, you could use `hash-identifier`.

```bash
hash-identifier <hashvalue>
```

## Cracking hashes

### hashcat

```
#  hashes are in format USER:HASH
hashcat hashes --user /usr/share/wordlists/rockyou.txt
```

### john

```
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
```
