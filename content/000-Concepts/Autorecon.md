---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
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
