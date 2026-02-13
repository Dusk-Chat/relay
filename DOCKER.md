# dusk relay server - docker deployment

this directory contains everything needed to deploy the dusk relay server using docker.

## what is the relay server

the relay server is a lightweight tracker-style node that helps dusk peers find each other without revealing their ip addresses. it provides:

- circuit relay v2: peers connect through this node, never seeing each other's ips
- rendezvous: peers register under community namespaces, discover each other by peer id
- no data storage, no message routing, just connection brokering

## quick start

### using docker compose (recommended)

```bash
cd relay-server
docker-compose up -d
```

this will:
- build the relay server image
- start the container in detached mode
- persist the relay's keypair in a named volume
- expose port 4001 on the host
- restart automatically unless stopped manually

### using docker directly

```bash
cd relay-server
docker build -t dusk-relay .
docker run -d \
  --name dusk-relay \
  --restart unless-stopped \
  -p 4001:4001 \
  -v dusk-relay-data:/data \
  -e RUST_LOG=info \
  -e DUSK_RELAY_PORT=4001 \
  dusk-relay
```

## configuration

### environment variables

| variable | default | description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | log level (error, warn, info, debug, trace) |
| `DUSK_RELAY_PORT` | `4001` | port the relay listens on |

### custom port

to use a different port, modify the environment variable:

```bash
# docker-compose.yml
environment:
  - DUSK_RELAY_PORT=8080
ports:
  - "8080:8080"

# or with docker run
docker run -d \
  --name dusk-relay \
  -p 8080:8080 \
  -e DUSK_RELAY_PORT=8080 \
  dusk-relay
```

## persistence

the relay server persists its keypair to `/data/keypair` inside the container. this ensures the peer id remains stable across container restarts.

the docker-compose setup uses a named volume `dusk-relay-data` for persistence. if you need to reset the relay's identity:

```bash
docker-compose down -v
docker-compose up -d
```

## viewing logs

```bash
# docker compose
docker-compose logs -f

# docker
docker logs -f dusk-relay
```

## health check

the container includes a health check that verifies the relay is listening on the configured port. check the health status:

```bash
docker inspect dusk-relay --format='{{.State.Health.Status}}'
```

## stopping and starting

```bash
# docker compose
docker-compose stop
docker-compose start

# docker
docker stop dusk-relay
docker start dusk-relay
```

## getting the relay address

when the relay starts, it prints its multiaddress. you can also find it in the logs:

```bash
docker logs dusk-relay | grep "relay address"
```

the address will be in the format:
```
/ip4/<your-server-ip>/tcp/4001/p2p/<peer-id>
```

use this address in the `DUSK_RELAY_ADDR` environment variable when running dusk clients.

## production deployment notes

### security

- the container runs as a non-root user (uid 1000) for security
- only the necessary port is exposed
- no unnecessary packages are installed in the runtime image

### performance

- the relay is lightweight and can handle many concurrent connections
- for high-traffic deployments, consider:
  - increasing the `DUSK_RELAY_PORT` if needed
  - monitoring cpu and memory usage
  - setting up log aggregation

### monitoring

set up monitoring for:
- container health status
- connection count (visible in logs)
- cpu and memory usage
- disk space (for the persistent volume)

### firewall

ensure port 4001 (or your custom port) is open in your firewall:

```bash
# ufw
sudo ufw allow 4001/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=4001/tcp
sudo firewall-cmd --reload
```

## troubleshooting

### container won't start

check the logs:
```bash
docker logs dusk-relay
```

common issues:
- port already in use: change `DUSK_RELAY_PORT`
- permission issues: ensure the volume has correct ownership

### peers can't connect

- verify the port is open in your firewall
- check the relay address format in client configuration
- ensure the container is healthy: `docker inspect dusk-relay --format='{{.State.Health.Status}}'`

### keypair issues

if the relay's peer id changes unexpectedly, the keypair file may have been lost. check the volume:
```bash
docker exec dusk-relay ls -la /data/
```

## building locally

to build the image without running it:

```bash
docker build -t dusk-relay .
```

to build for a different architecture:

```bash
docker buildx build --platform linux/amd64 -t dusk-relay .
docker buildx build --platform linux/arm64 -t dusk-relay .
```
