---
publish: true
created: 2026-02-02T14:49:35.645+05:30
modified: 2026-06-22T09:02:26.228+05:30
tags:
  - ssh
  - ssh2john
---

SSH Connection using private key.

1. The private key file name will be as `id_rsa`,`id_ed25519`.
2. File names ending with _.pub_ are the public keys.
3. private keys are usually encrypted with a **passphrase**.
4. this key also holds the username@machine  data once decrypted. so you can know whose shell you will land.

# Usage - Persistence

You could add your _id\_rsa.pub_ key to victim machine's authorized\_keys and use private key to login via ssh.

- Generate the key pairs.

```
$ ssh-keygen -t rsa -b 4096 -f ~/htb/variatype/exploit/id_rsa
```

- Add the content of public key  _id\_rsa.pub_ to `/home/steve/.ssh/authorized_keys`.

```
ssh-rsa [Content] kali@kali
```

- Use the private key _id\_rsa_ to login via ssh.

```
ssh -i id_rsa steve@variatype.htb
```

# Encrypted Private Key

For example, This looks like a private ssh key - `id_ed25519`. we have to identify the user of this private key.

```
$ chmod 400 id_ed25519
$ ssh-keygen -y -f id_ed25519
Enter passphrase for "id_ed25519":
```

Well, this key is encrypted and needs passphrase to decrypt. now to cracking this private key and getting the username with **ssh2john**.

## cracking - John

```
$ ssh2john id_ed25519
id_ed25519:$sshng$6$16$95bc48accbd0e7e4c4d79889ccab799a$290$6f70656e7373682d6b65792d7631000000000a6165733235362d63747200000006626372797074000000180000001095bc48accbd0e7e4c4d79889ccab799a0000001800000001000000330000000b7373682d6564323535313900000020fbf9fd454c2ea4f7841e40098ac10ab8d449e9a4fbbf66dc70d1cca36f3d9009000000a06c8fbebec78f57649ec59174263ec43e982255979ce3bd3123813d4590b48e62188c9f14e5a7f6568f2e0e22eb31495154f6504026ec6e1acfa599ea5ab1b14a7569548ce1ca51b3a70c50458ff03432791830f3dfb236139eb4bc50ec1d5562c6ded9026b1362e7cf3e0de97d1d7e0c37389a1beda1fef4ca6c5368973796dc9819165811d980bb8089c73fc07bf55f95dc2ad960f80e38650e277f5773fb4c$24$130

$ ssh2john id_ed25519 > sshng_hash

$ john sshng_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:18 0.01% (ETA: 2026-02-19 01:36) 0g/s 11.86p/s 11.86c/s 11.86C/s xbox360..sandy
dragonballz      (id_ed25519)
1g 0:00:04:12 DONE (2026-02-02 03:53) 0.003953g/s 12.65p/s 12.65c/s 12.65C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

$ john sshng_hash --show
id_ed25519:dragonballz
```

lets enter the encryption password for the private key.

```
$ ssh-keygen -y -f id_ed25519
Enter passphrase for "id_ed25519":
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv5/UVMLqT3hB5ACYrBCrjUSemk+79m3HDRzKNvPZAJ trivia@facts.htb
```

## Decryption - openssl

To decrypt.

```
openssl rsa -in id_rsa_encrypted -out id_rsa
Enter pass phrase for joanna-enc:
writing RSA key
```
