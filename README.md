# dusk relay server

a lightweight tracker-style node that helps dusk peers find each other without revealing their ip addresses.

## what it does

the relay server provides two critical services for the dusk p2p network:

- **circuit relay v2**: peers connect through this node, never seeing each other's ips. this enables nat traversal without exposing peer locations.
- **rendezvous**: peers register under community namespaces and discover each other by peer id. this allows peers to find each other without a central directory.

the relay is stateless - it doesn't store messages or user data. it only brokers connections.

## architecture

```
peer a --[encrypted circuit]--> relay <--[encrypted circuit]-- peer b
```

neither peer sees the other's ip address. the relay only forwards encrypted bytes.

## quick start

### local development

```bash
# install rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# run the relay
cargo run
```

the relay will start on port 4001 and print its multiaddress:

```
relay address: /ip4/0.0.0.0/tcp/4001/p2p/12D3KooW...
```

### docker deployment

see [DOCKER.md](DOCKER.md) for complete docker deployment instructions.

```bash
cd relay-server
docker-compose up -d
```

## configuration

### environment variables

| variable | default | description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | log level (error, warn, info, debug, trace) |
| `DUSK_RELAY_PORT` | `4001` | port the relay listens on |

### example

```bash
# custom port and debug logging
RUST_LOG=debug DUSK_RELAY_PORT=8080 cargo run
```

## persistence

the relay persists its keypair to disk so the peer id remains stable across restarts. the keypair is stored at:

- linux: `~/.local/share/dusk-relay/keypair`
- macos: `~/Library/Application Support/dusk-relay/keypair`
- fallback: `./relay_keypair`

to reset the relay's identity, delete this file and restart.

## connecting clients

configure dusk clients to use the relay by setting the `DUSK_RELAY_ADDR` environment variable:

```bash
DUSK_RELAY_ADDR=/ip4/<relay-ip>/tcp/4001/p2p/<relay-peer-id> bun run tauri dev
```

replace `<relay-ip>` with your relay server's public ip address and `<relay-peer-id>` with the peer id printed when the relay starts.

## monitoring

the relay logs important events:

- peer connections and disconnections
- relay reservations (circuits being established)
- rendezvous registrations (peers discovering each other)
- circuit creation and closure

example log output:

```
[2024-01-15T10:30:00Z INFO dusk_relay] dusk relay server starting
[2024-01-15T10:30:00Z INFO dusk_relay] peer id: 12D3KooW...
[2024-01-15T10:30:05Z INFO dusk_relay] peer connected: 12D3KooW... (total connections: 1)
[2024-01-15T10:30:06Z INFO dusk_relay] relay reservation accepted for peer 12D3KooW... (total: 1)
[2024-01-15T10:30:07Z INFO dusk_relay] circuit opened: 12D3KooW... -> 12D3KooW... (through relay)
```

## production deployment

for production deployment, use docker. see [DOCKER.md](DOCKER.md) for:

- docker compose setup
- health checks
- persistence configuration
- security best practices
- troubleshooting guide

## security considerations

- the relay runs as a non-root user in docker
- only the necessary port is exposed
- the relay never sees message content, only encrypted bytes
- peer ids are cryptographic, not tied to ip addresses
- no user data is stored on the relay

## performance

the relay is lightweight and can handle many concurrent connections. typical resource usage:

- cpu: minimal (mostly idle, spikes on connection events)
- memory: ~50-100mb
- network: scales with peer traffic

## troubleshooting

### port already in use

```bash
# check what's using port 4001
lsof -i :4001

# use a different port
DUSK_RELAY_PORT=8080 cargo run
```

### peers can't connect

- verify the port is open in your firewall
- check the relay address format in client configuration
- ensure the relay is running and listening

### keypair issues

if the relay's peer id changes unexpectedly, the keypair file may have been lost. check the file exists:

```bash
ls -la ~/.local/share/dusk-relay/keypair
```

## license

see the main project license file.
