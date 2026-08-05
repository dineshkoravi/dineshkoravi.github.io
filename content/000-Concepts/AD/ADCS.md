---
publish: true
created: 2026-03-10T01:52:10.439+05:30
modified: 2026-06-23T12:03:40.716+05:30
---

Active Directory Certificate Services
Ports to lookout for in Nmap scan.

```
$ nmap sequel.htb
389/tcp  open  ldap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

# Identify ADCS and certs

```
openssl s_client -showcerts -connect 10.10.11.202:3269 | openssl x509 -noout -text | less -S

[SNIP] CN=sequel-DC-CA [SNIP]
```

Certify Tool Repo -<https://github.com/GhostPack/Certify?tab=readme-ov-file#example-walkthrough>

# finding vulnerabilities

## nxc

```
nxc ldap 10.129.229.207 -u administrator -p 'HTB_@cademy_adm!' -M certipy-find
```

## certipy-ad

```
certipy-ad find -target-ip 10.129.2.132 -u ryan.cooper@sequel.htb -p 'NuclearMosquito3' -ldap-scheme ldaps -ns 10.129.2.132
```

The above command saves the vulnerabilities to `txt` and `json` formats. you can read the txt format.

## Certify

```
.\Certify.exe find /vulnerable
```

This lists the vulnerable certificates, but not verbose about explaining what is the vulnerability.

# Bloodhound permissions linked with ADCS

- [[ShadowCredentials]]
