---
publish: true
created: 2026-02-06T17:45:21.455+05:30
modified: 2026-06-22T09:00:34.292+05:30
---

port - 389 ?

### ldapsearch

- Get the _namingcontexts_.

```
$ ldapsearch -H ldap://10.129.1.142 -x -s base namingcontexts
[SNIP]
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
```

- Fetch all data about users.

```
ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local"
ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > userdata.txt
```

- create a user list.

```
ldapsearch -H ldap://10.10.10.172 -x -b "DC=MEGABANK,DC=local" sAMAccountName | grep sAMAccountName | sed 's/sAMAccountName: //g' > users.txt
```

- Search with creds.

```
ldapsearch -H ldap://10.10.11.174 -b "DC=support,DC=htb" -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
ldapsearch -H ldap://10.10.11.174 -b "DC=support,DC=htb" -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' sAMAccountName | grep sAMAccountName | sed 's/sAMAccountName: //g'
```

### ldapdomaindump

```
ldapdomaindump 10.10.11.69 -u 'FLUFFY.HTB\p.agila' -p 'prometheusx-303'
```

### nxc

```
nxc ldap DC01.sequel.htb -u 'rose' -p 'KxEPkKe6R8su' -M get-desc-users
```
