---
publish: true
created: 2026-02-18T12:03:08.947+05:30
modified: 2026-06-22T08:58:21.880+05:30
---

# exiftool

Use `exiftool` for metadata.

```
$ exiftool nineveh.png 
ExifTool Version Number         : 13.44
File Name                       : nineveh.png
Directory                       : .
File Size                       : 2.9 MB
File Modification Date/Time     : 2026:02:17 03:54:45-05:00
File Access Date/Time           : 2026:02:17 03:54:45-05:00
File Inode Change Date/Time     : 2026:02:17 03:54:45-05:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1497
Image Height                    : 746
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8
Software                        : Shutter
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 1497x746
Megapixels                      : 1.1
```

# ltrace

to check the linked library calls.

```
matt@pandora:/$ ltrace /usr/bin/pandora_backup
[SNIP]
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
```

# binwalk

[[Check embedded files with binwalk]]
