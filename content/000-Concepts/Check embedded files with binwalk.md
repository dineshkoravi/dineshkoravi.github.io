---
publish: true
created: 2026-02-17T15:59:30.563+05:30
modified: 2026-06-23T12:14:30.208+05:30
---

To check the embedded files within a binary file.

```
$ binwalk nineveh.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

```

even though, the binary is image, we see that a tar file has been embedded in it. to extract it.

```
$ binwalk -e nineveh.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)
```
