// dusk relay server
//
// a lightweight tracker-style node that helps peers find each other
// without revealing their IP addresses. runs on a public server.
//
// responsibilities:
// - circuit relay v2: peers connect through this node, never seeing each other's IPs
// - rendezvous: peers register under community namespaces, discover each other by peer ID
// - relay federation: gossips peer registrations to other relays for global discovery
// - no data storage, no message routing, just connection brokering
//
// usage:
//   RUST_LOG=info cargo run
//   DUSK_RELAY_PORT=4001 cargo run  (custom port)
//   DUSK_PEER_RELAYS="addr1,addr2" cargo run  (federation)
//   DUSK_MAX_CONNECTIONS=10000 cargo run  (connection limit, default 10k)
//
// canonical public relay (default in dusk chat clients):
//   /dns4/relay.duskchat.app/tcp/4001/p2p/12D3KooWGQkCkACcibJPKzus7Q6U1aYngfTuS4gwYwmJkJJtrSaw
//
// recommended connection limits by instance size:
//   t3.small (2GB):  5,000 max connections
//   t3.medium (4GB): 10,000 max connections (default)
//   t3.large (8GB):  20,000 max connections
//   c6i.xlarge:      50,000 max connections (with kernel tuning)

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    connection_limits, gossipsub, identify, noise, ping, relay, rendezvous, swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId,
};

// gossip message for relay-to-relay federation
// relays broadcast peer registrations to each other so discovery works across relay nodes
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RelayRegistrationGossip {
    peer_id: String,
    namespace: String,
    // unix timestamp in seconds when this registration expires
    ttl: u64,
    // relay peer id that originated this registration (to prevent loops)
    source_relay: String,
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    rendezvous: rendezvous::server::Behaviour,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    limits: connection_limits::Behaviour,
}

// resolve the path where we persist the relay's keypair so the peer id is stable
fn keypair_path() -> PathBuf {
    if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "dusk-relay") {
        let dir = proj_dirs.data_dir().to_path_buf();
        std::fs::create_dir_all(&dir).ok();
        dir.join("keypair")
    } else {
        PathBuf::from("./relay_keypair")
    }
}

// load an existing keypair or generate a new one and save it
fn load_or_generate_keypair() -> libp2p::identity::Keypair {
    let path = keypair_path();

    if path.exists() {
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
                log::info!("loaded existing keypair from {}", path.display());
                return kp;
            }
        }
        log::warn!("failed to load keypair, generating new one");
    }

    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        if let Err(e) = std::fs::write(&path, &bytes) {
            log::warn!("failed to persist keypair: {}", e);
        } else {
            log::info!("saved new keypair to {}", path.display());
        }
    }
    kp
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let keypair = load_or_generate_keypair();
    let local_peer_id = keypair.public().to_peer_id();

    let port: u16 = std::env::var("DUSK_RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4001);

    // max concurrent peer connections (not including peer relay connections)
    // default 10k, configurable via env var for different instance sizes
    let max_connections: u32 = std::env::var("DUSK_MAX_CONNECTIONS")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(10_000);

    log::info!("connection limit: {} max concurrent peers", max_connections);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            // configure gossipsub for relay-to-relay federation
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(|msg| {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    msg.data.hash(&mut hasher);
                    gossipsub::MessageId::from(hasher.finish().to_string())
                })
                .build()
                .expect("valid gossipsub config");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("valid gossipsub behaviour");

            // read connection limit (max total concurrent connections across all peers)
            let max_connections = std::env::var("DUSK_MAX_CONNECTIONS")
                .ok()
                .and_then(|c| c.parse().ok())
                .unwrap_or(10_000);

            RelayBehaviour {
                relay: relay::Behaviour::new(peer_id, relay::Config::default()),
                rendezvous: rendezvous::server::Behaviour::new(
                    rendezvous::server::Config::default(),
                ),
                gossipsub,
                identify: identify::Behaviour::new(identify::Config::new(
                    "/dusk/relay/1.0.0".to_string(),
                    key.public(),
                )),
                // ping every 30s to keep peer connections alive
                ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30))),
                // limit total concurrent connections (default 10k for ~t3.medium)
                limits: connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(max_connections))
                ),
            }
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    // listen on all interfaces
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
    swarm.listen_on(listen_addr)?;

    log::info!("dusk relay server starting");
    log::info!("peer id: {}", local_peer_id);

    let canonical_addr = format!("/ip4/0.0.0.0/tcp/{}/p2p/{}", port, local_peer_id);
    println!("\n  relay address: {}\n", canonical_addr);

    // subscribe to the relay federation gossip topic
    let federation_topic = gossipsub::IdentTopic::new("dusk/relay/federation");
    swarm.behaviour_mut().gossipsub.subscribe(&federation_topic)?;
    log::info!("subscribed to relay federation topic");

    // connect to peer relays for federation (from env var, comma-separated multiaddrs)
    let peer_relays: Vec<Multiaddr> = std::env::var("DUSK_PEER_RELAYS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|addr| addr.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();

    // extract peer IDs from peer relay multiaddrs for tracking
    let expected_peer_relay_ids: Vec<PeerId> = peer_relays
        .iter()
        .filter_map(|addr| {
            use libp2p::multiaddr::Protocol;
            addr.iter().find_map(|p| match p {
                Protocol::P2p(peer_id) => Some(peer_id),
                _ => None,
            })
        })
        .collect();

    if !peer_relays.is_empty() {
        log::info!("connecting to {} peer relays for federation", peer_relays.len());
        for addr in &peer_relays {
            log::info!("  dialing peer relay: {}", addr);
            if let Err(e) = swarm.dial(addr.clone()) {
                log::warn!("failed to dial peer relay {}: {}", addr, e);
            }
        }
    } else {
        log::warn!("no peer relays configured (DUSK_PEER_RELAYS env var not set)");
        log::warn!("this relay will operate in standalone mode");
    }

    // track active reservations for logging
    let mut reservation_count: usize = 0;
    let mut connection_count: usize = 0;

    // track peer relay connections for federation metrics
    let mut connected_peer_relays: Vec<PeerId> = Vec::new();

    loop {
        match swarm.select_next_some().await {
            // relay events
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationReqAccepted { src_peer_id, .. },
            )) => {
                reservation_count += 1;
                log::info!(
                    "relay reservation accepted for peer {} (total: {})",
                    src_peer_id,
                    reservation_count
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationTimedOut { src_peer_id, .. },
            )) => {
                reservation_count = reservation_count.saturating_sub(1);
                log::info!(
                    "relay reservation expired for peer {} (total: {})",
                    src_peer_id,
                    reservation_count
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
            )) => {
                log::info!(
                    "circuit opened: {} -> {} (through relay)",
                    src_peer_id,
                    dst_peer_id
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitClosed { src_peer_id, dst_peer_id, .. },
            )) => {
                log::debug!(
                    "circuit closed: {} -> {}",
                    src_peer_id,
                    dst_peer_id
                );
            }

            // rendezvous events
            SwarmEvent::Behaviour(RelayBehaviourEvent::Rendezvous(
                rendezvous::server::Event::PeerRegistered { peer, registration },
            )) => {
                log::info!(
                    "peer {} registered under namespace '{}'",
                    peer,
                    registration.namespace
                );

                // gossip this registration to peer relays for federation
                // other relays can cache this and have their clients query them directly
                let gossip = RelayRegistrationGossip {
                    peer_id: peer.to_string(),
                    namespace: registration.namespace.to_string(),
                    // registration.ttl is already a u64 timestamp
                    ttl: registration.ttl,
                    source_relay: local_peer_id.to_string(),
                };

                if let Ok(data) = serde_json::to_vec(&gossip) {
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(federation_topic.clone(), data) {
                        log::warn!("failed to gossip registration to peer relays: {}", e);
                    } else {
                        log::debug!(
                            "gossiped registration {}:{} to {} peer relays",
                            gossip.namespace,
                            gossip.peer_id,
                            connected_peer_relays.len()
                        );
                    }
                }
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Rendezvous(
                rendezvous::server::Event::DiscoverServed { enquirer, registrations, .. },
            )) => {
                log::info!(
                    "served {} registrations to peer {}",
                    registrations.len(),
                    enquirer
                );
            }

            // gossipsub messages - receive peer registrations from other relays
            SwarmEvent::Behaviour(RelayBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. }
            )) => {
                if let Ok(gossip) = serde_json::from_slice::<RelayRegistrationGossip>(&message.data) {
                    // skip our own messages (loop prevention)
                    if gossip.source_relay != local_peer_id.to_string() {
                        log::info!(
                            "received remote registration {}:{} from relay {} (clients should query that relay directly)",
                            gossip.namespace,
                            gossip.peer_id,
                            gossip.source_relay
                        );
                    }
                }
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Rendezvous(
                rendezvous::server::Event::PeerNotRegistered { peer, namespace, .. },
            )) => {
                log::debug!(
                    "peer {} tried to register under '{}' but was rejected",
                    peer,
                    namespace
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Rendezvous(
                rendezvous::server::Event::RegistrationExpired(registration),
            )) => {
                log::debug!(
                    "registration expired for namespace '{}'",
                    registration.namespace
                );
            }

            // connection tracking
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                connection_count += 1;

                // check if this is a peer relay connection
                if expected_peer_relay_ids.contains(&peer_id) && !connected_peer_relays.contains(&peer_id) {
                    connected_peer_relays.push(peer_id);
                    log::info!(
                        "peer relay connected: {} ({}/{} peer relays online)",
                        peer_id,
                        connected_peer_relays.len(),
                        expected_peer_relay_ids.len()
                    );
                } else {
                    log::info!(
                        "peer connected: {} (total connections: {})",
                        peer_id,
                        connection_count
                    );
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                connection_count = connection_count.saturating_sub(1);

                // check if this was a peer relay disconnection
                if let Some(pos) = connected_peer_relays.iter().position(|id| id == &peer_id) {
                    connected_peer_relays.remove(pos);
                    log::warn!(
                        "peer relay disconnected: {} ({}/{} peer relays online)",
                        peer_id,
                        connected_peer_relays.len(),
                        expected_peer_relay_ids.len()
                    );
                } else {
                    log::debug!(
                        "peer disconnected: {} (total connections: {})",
                        peer_id,
                        connection_count
                    );
                }
            }

            // connection limit events
            SwarmEvent::IncomingConnectionError { error, .. } => {
                if let libp2p::swarm::ListenError::Denied { cause } = error {
                    if cause.to_string().contains("connection limit") {
                        log::warn!(
                            "connection rejected: relay at capacity ({} max connections)",
                            max_connections
                        );
                    }
                }
            }

            // identify events - log protocol info from connecting peers
            SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                log::debug!(
                    "identified peer {}: protocol={}, agent={}",
                    peer_id,
                    info.protocol_version,
                    info.agent_version
                );
            }

            _ => {}
        }
    }
}
