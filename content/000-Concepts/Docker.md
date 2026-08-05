---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-22T08:59:03.116+05:30
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
