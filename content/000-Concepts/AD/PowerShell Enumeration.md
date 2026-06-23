---
publish: true
created: 2026-03-27T18:18:58.510+05:30
modified: 2026-06-21T20:12:04.672+05:30
---

**DomainSID**:

```
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> Get-AdDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=nagoya-industries,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=nagoya-industries,DC=com
DistinguishedName                  : DC=nagoya-industries,DC=com
DNSRoot                            : nagoya-industries.com
DomainControllersContainer         : OU=Domain Controllers,DC=nagoya-industries,DC=com
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-1969309164-1513403977-1686805993
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=nagoya-industries,DC=com
Forest                             : nagoya-industries.com
InfrastructureMaster               : nagoya.nagoya-industries.com
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=nagoya-industries,DC=com}
LostAndFoundContainer              : CN=LostAndFound,DC=nagoya-industries,DC=com
ManagedBy                          :
Name                               : nagoya-industries
NetBIOSName                        : NAGOYA-IND
ObjectClass                        : domainDNS
ObjectGUID                         : 1153c877-efa1-443b-b59f-c32c9286750e
ParentDomain                       :
PDCEmulator                        : nagoya.nagoya-industries.com
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=nagoya-industries,DC=com
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {nagoya.nagoya-industries.com}
RIDMaster                          : nagoya.nagoya-industries.com
SubordinateReferences              : {DC=ForestDnsZones,DC=nagoya-industries,DC=com, DC=DomainDnsZones,DC=nagoya-industries,DC=com, CN=Configuration,DC=nagoya-industries,DC=com}
SystemsContainer                   : CN=System,DC=nagoya-industries,DC=com
UsersContainer                     : CN=Users,DC=nagoya-industries,DC=com
```

**SPNs**:

```
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name,ServicePrincipalName

Name         ServicePrincipalName
----         --------------------
svc_helpdesk {http/nagoya.nagoya-industries.com}
krbtgt       {kadmin/changepw}
svc_mssql    {MSSQL/nagoya.nagoya-industries.com}
```
