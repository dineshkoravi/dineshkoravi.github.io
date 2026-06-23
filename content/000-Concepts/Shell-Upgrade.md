---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-22T09:02:05.904+05:30
---

Reasons why we need shell upgrade.

- Tab completion
- pressing ctrl + c does not end the shell.

```bash

## Using python

python -c 'import pty; pty.spawn("/bin/bash")'

# for full features, after running above python command.
ctrl + z
stty raw -echo; fg
reset
terminal type=screen
export SHELL=bash
export TERM=xterm
stty rows 80 columns 200


# python not available
script -qc /bin/bash /dev/null
```

if you cant find anything on victim's box.

```
rlwrap -f . -r nc -nlvp 4444
```
