// dusk relay server
//
// a lightweight tracker-style node that helps peers find each other
// without revealing their IP addresses. runs on a public server.
//
// responsibilities:
// - circuit relay v2: peers connect through this node, never seeing each other's IPs
// - rendezvous: peers register under community namespaces, discover each other by peer ID
// - no data storage, no message routing, just connection brokering
//
// usage:
//   RUST_LOG=info cargo run
//   DUSK_RELAY_PORT=4001 cargo run  (custom port)

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use libp2p::{identify, noise, ping, relay, rendezvous, swarm::SwarmEvent, tcp, yamux, Multiaddr};

#[derive(libp2p::swarm::NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    rendezvous: rendezvous::server::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
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

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            RelayBehaviour {
                relay: relay::Behaviour::new(peer_id, relay::Config::default()),
                rendezvous: rendezvous::server::Behaviour::new(
                    rendezvous::server::Config::default(),
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/dusk/relay/1.0.0".to_string(),
                    key.public(),
                )),
                // ping every 30s to keep peer connections alive
                ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30))),
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

    // track active reservations for logging
    let mut reservation_count: usize = 0;
    let mut connection_count: usize = 0;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                log::debug!("listening on: {}/p2p/{}", address, local_peer_id);
            }

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
                log::info!(
                    "peer connected: {} (total connections: {})",
                    peer_id,
                    connection_count
                );
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                connection_count = connection_count.saturating_sub(1);
                log::debug!(
                    "peer disconnected: {} (total connections: {})",
                    peer_id,
                    connection_count
                );
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
