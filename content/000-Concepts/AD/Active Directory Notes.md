---
publish: true
created: 2026-06-16T09:47:14.428+05:30
modified: 2026-06-21T18:06:09.360+05:30
---

Map of Contents for Active Directory.

Our goal from here is to have some account which will let us do the following.

1. Communicate with Domain Controller.
2. Use services which can make us talk to Domain joined machines without login.
3. let us login to Domain joined machines and enumerate local accounts and exploit further.
4. Repeat 1,2,3 steps again.

We can mainly have two different starting points for AD penetration testing. is a test account provided or not.

1. [[User Generation, Enumeration & Validation]]
2. Once you can communicate with Domain Controller (DC). you could enumerate with
   1. [[Bloodhound-ce]]
   2. [[AD ACL Scanner]]
   3. [[Adalanche]]
   4. [[PowerShell Enumeration]]
3. Authenticate with
   1. [[NTLM]] - older method.
   2. [[PFX file]]
   3. [[Impacket Notes]]
4. check for Password re-uses with NetExec.
5. If passwords are not sufficient and tickets are required for communication, use [[Kerberos Authentication with tools]].
6. if tickets are in memory use:
   1. [[klist]]
   2. [[mimikatz]]
7. if you find any weaknesses related to tickets, you could do the following attacks.
   1. [[AS-REP-roasting]]
   2. [[Kerberoasting]]
   3. [[Silverticket]]
8. Extract NTLM hash for reuse.
   1. Local machine - [[Secrets Dump]]
   2. DC - [[dcsync]]
9. in some scenarios you could check if [[GoldenTicket]] is possible, but it is rare.
10. if you find weaknesses related AD certificate services (Not part of OSCP).
    1. [[ADCS]]
