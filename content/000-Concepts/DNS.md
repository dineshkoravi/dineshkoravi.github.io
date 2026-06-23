---
publish: true
created: 2026-02-06T17:27:41.174+05:30
modified: 2026-06-22T08:58:57.732+05:30
---

### dnsrecon

This will print domain name.

```
dnsrecon -r 127.0.0.1/24 -n [dns_server_ip]
```

### dig

query a domainname with nameserver IP.

The `dig` tool is a command-line utility used to query DNS (Domain Name System) servers to retrieve information about domain names, IP addresses, and other DNS records.

```
dig @192.168.230.98 -p 5353 -x 192.168.230.98 +noadditional +nostats +nocomments +noquestion

; <<>> DiG 9.20.4-2-Debian <<>> @192.168.230.98 -p 5353 -x 192.168.230.98 +noadditional +nostats +nocomments +noquestion
; (1 server found)
;; global options: +cmd
98.230.168.192.in-addr.arpa. 10 IN      PTR     pelican.local.
```

we can edit hosts file to include hostname

```
192.168.230.98 pelican.local
```

or simply do.

```
$ dig any cicada.htb @10.129.2.47

; <<>> DiG 9.20.18-1-Debian <<>> any cicada.htb @10.129.2.47
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58223
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;cicada.htb.			IN	ANY

;; ANSWER SECTION:
cicada.htb.		600	IN	A	10.129.2.47
cicada.htb.		3600	IN	NS	cicada-dc.cicada.htb.
cicada.htb.		3600	IN	SOA	cicada-dc.cicada.htb. hostmaster.cicada.htb. 185 900 600 86400 3600
cicada.htb.		600	IN	AAAA	dead:beef::163d:af50:7faf:5cb0
cicada.htb.		600	IN	AAAA	dead:beef::203

;; ADDITIONAL SECTION:
cicada-dc.cicada.htb.	3600	IN	A	10.129.2.47
cicada-dc.cicada.htb.	3600	IN	AAAA	dead:beef::163d:af50:7faf:5cb0
cicada-dc.cicada.htb.	3600	IN	AAAA	dead:beef::203

;; Query time: 144 msec
;; SERVER: 10.129.2.47#53(10.129.2.47) (TCP)
;; WHEN: Fri Mar 06 10:55:08 IST 2026
;; MSG SIZE  rcvd: 254

```
