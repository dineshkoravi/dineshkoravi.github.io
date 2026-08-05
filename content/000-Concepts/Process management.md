---
publish: true
created: 2026-02-06T17:06:43.496+05:30
modified: 2026-06-23T12:17:24.720+05:30
---

### ps

display process in tree format

```
ps -auxwf
ps -auwww
```

### Kill process

To kill a process

```
kill PID
kill -9 PID # sends SIGKILL
```

### pspy

Process enumeration

pspy-binaries are already installed on kali linux. but if you need older binaries below is the link.
<https://github.com/DominicBreuker/pspy>

```
To terminate pspy after 5 minutes of execution. this is mandatory otherwise the tool keeps on running.
timeout 5m ./pspy64

process that run frequently
./pspy64 -pf -i 1000
```
