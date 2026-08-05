---
publish: true
created: 2026-02-06T17:15:38.573+05:30
modified: 2026-06-22T08:58:16.144+05:30
---

### grep

```bash
grep --exclude-dir=plugins --color=auto -rnw '.' -ie "PASSWORD=" --color=always 2> /dev/null
# use -rlw to print filenamesm, instead of content.
# --exclude='*.js' to exclude js files.
```

### Oneliners - awk sed echo

The entire command will result in the contents of `file1.txt` being formatted into a comma-separated list of quoted strings, with no trailing comma at the end.

```bash
# To Print contents of a each line of file like "line1","line2",..
awk '{printf "\"%s\",", $0}' file1.txt | sed 's/,$/\n/'
```

### cut

Fetch names of users or services using cut from `/etc/shadow`.

```bash
cat /etc/shadow | cut -d : -f 1
```

### du

Show's the disk usage by all files in directory.

```
du -ah ~/workspace/github/oscp
```

### xclip

copy to clipboard

`echo $i | xclip -selection clipboard`

### feroxbuster neat output

Print all status codes.

```
jq -r 'select(.type == "response") | "\(.url) \(.status)"' ferox.json
```

Print 200 status codes.

```
jq -r 'select(.type == "response" and .status == 200) | "\(.url) \(.status)"' ferox.json
```
