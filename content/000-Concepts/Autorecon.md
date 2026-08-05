---
publish: true
created: 2026-02-06T17:11:44.872+05:30
modified: 2026-06-22T08:58:10.916+05:30
---

### autorecon

```
sudo env "PATH=$PATH" autorecon -v --single-target bratarina.local --exclude-tags=vhost-enum,dirbuster -o ~/workspace/pg/bratarina
```

print open ports of nmap output from autorecon.

```
$ cat _full_tcp_nmap.txt | awk -F/ '/open/ {b=b","$1} END {print substr(b,2)}'
$ cat _top_100_udp_nmap.txt | awk -F/ '/open / {b=b","$1} END {print substr(b,2)}'
```
