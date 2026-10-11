---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

### Ping check

To check if kali machine receives pings from target machine. using `tcpdump`.

```
# to listen to icmp requests on tun0 interface
$ sudo tcpdump -ni tun0 icmp
```

now send the ping request from target machine to kali. you can check it in tcpdump.
