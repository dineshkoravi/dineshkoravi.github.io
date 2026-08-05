---
publish: true
created: 2026-02-06T17:03:23.943+05:30
modified: 2026-06-22T08:57:57.693+05:30
---

### Ping check

To check if kali machine receives pings from target machine. using `tcpdump`.

```
# to listen to icmp requests on tun0 interface
$ sudo tcpdump -ni tun0 icmp
```

now send the ping request from target machine to kali. you can check it in tcpdump.
