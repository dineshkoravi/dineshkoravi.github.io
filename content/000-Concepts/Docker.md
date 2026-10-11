---
publish: true
created: 2026-10-03T08:40:24.740Z
modified: 2026-10-03T08:40:24.740Z
---

Installation : [Here](https://www.kali.org/docs/containers/installing-docker-on-kali/)
To run docker without root

```
sudo usermod -aG docker $USER
```

```
docker build -t app_name . 
```

```
docker run -dp 3000:3000 app_name
```

## Reset all docker

```
docker system prune -a -f --volumes 
```

## Recreate

```
sudo docker compose up --force-recreate
```
