---
publish: true
created: 2026-03-07T18:40:29.284+05:30
modified: 2026-06-21T20:11:14.480+05:30
---

Links:
<https://www.ionos.com/digitalguide/server/security/kerberos/>
<https://redmondmag.com/articles/2012/02/01/understanding-the-essentials-of-the-kerberos-protocol.aspx>

Kerberos (krb5) - is a secure, mature, network authentication protocol based on tickets

- **Client:** The client acts “on behalf” of the user and initiates communication when a service request is made.
- **Hosting server:** This is the server that hosts the service that the user wants to access.
- **Authentication Server (AS)**: The AS performs the desired client authentication. If the authentication is successful, the AS issues a ticket to the client, the TGT (Ticket Granting Ticket). This ticket assures the other servers that the client is authenticated.
- **Ticket Granting Server (TGS)**: The TGS is an application server that issues service tickets.
- **Key Distribution Center (KDC)**: The KDC consists of the Authentication Server (AS) and the Ticket Granting Server (TGS).

## Get TGT

```
$ impacket-getTGT frizz.htb/f.frizzle:Jenni_Luvs_Magic23
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in f.frizzle.ccache
```

saved as username.ccache format.

## KRB5 conf

If SMB is open, you can creat the krb5.conf file using _nxc_.

```
$ nxc smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k --smb-timeout 10 --generate-krb5-file krb5.conf
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] krb5 conf saved to: krb5.conf
SMB         frizzdc.frizz.htb 445    frizzdc          [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
```

and the contents of the conf file are below.

```
$ cat krb5.conf
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = FRIZZ.HTB

[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
        admin_server = frizzdc.frizz.htb
        default_domain = frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB
```

now use the tool _ssh_ as below.

```
$ export KRB5_CONFIG=krb5.conf
$ KRB5CCNAME=f.frizzle.ccache ssh -K f.frizzle@frizzdc.frizz.htb
```

## nxc

Plain text credentials with kerberos authentication.

```
$ nxc smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k
```
