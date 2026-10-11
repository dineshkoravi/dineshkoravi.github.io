---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
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
