// dusk relay server
//
// a lightweight tracker-style node that helps peers find each other
// without revealing their IP addresses. runs on a public server.
//
// responsibilities:
// - circuit relay v2: peers connect through this node, never seeing each other's IPs
// - rendezvous: peers register under community namespaces, discover each other by peer ID
// - relay federation: gossips peer registrations to other relays for global discovery
// - gif service: responds to gif search requests from clients via request-response protocol
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

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    connection_limits, gossipsub, identify, noise, ping, relay, rendezvous,
    request_response::{self, cbor, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
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
    // gif search service - clients send GifRequest, relay responds with GifResponse
    gif_service: cbor::Behaviour<GifRequest, GifResponse>,
}

// ---- gif protocol ----
// clients send a GifRequest over request-response and the relay responds
// with a GifResponse after fetching from klipy. the api key stays on the
// relay so clients never need credentials.

const GIF_PROTOCOL: StreamProtocol = StreamProtocol::new("/dusk/gif/1.0.0");
const KLIPY_API_BASE: &str = "https://api.klipy.com/v2";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GifRequest {
    // "search" or "trending"
    pub kind: String,
    // search query (only used when kind == "search")
    pub query: String,
    pub limit: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GifResponse {
    pub results: Vec<GifResult>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GifResult {
    pub id: String,
    pub title: String,
    pub url: String,
    pub preview: String,
    pub dims: [u32; 2],
}

// ---- gif cache ----
// caches klipy responses in memory so repeated queries dont hit the api.
// trending results refresh every 10 minutes, search results live for 30 minutes.

const TRENDING_CACHE_TTL: Duration = Duration::from_secs(600);
const SEARCH_CACHE_TTL: Duration = Duration::from_secs(1800);

struct GifCache {
    // key: normalized cache key (kind:query:limit), value: (results, inserted_at)
    entries: HashMap<String, (Vec<GifResult>, Instant)>,
}

impl GifCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    // build a normalized cache key from the request
    fn cache_key(request: &GifRequest) -> String {
        let query = request.query.trim().to_lowercase();
        format!("{}:{}:{}", request.kind, query, request.limit)
    }

    fn get(&self, request: &GifRequest) -> Option<&Vec<GifResult>> {
        let key = Self::cache_key(request);
        let (results, inserted_at) = self.entries.get(&key)?;

        let ttl = if request.kind == "trending" {
            TRENDING_CACHE_TTL
        } else {
            SEARCH_CACHE_TTL
        };

        if inserted_at.elapsed() > ttl {
            return None;
        }

        Some(results)
    }

    fn insert(&mut self, request: &GifRequest, results: Vec<GifResult>) {
        let key = Self::cache_key(request);
        self.entries.insert(key, (results, Instant::now()));
    }

    // drop expired entries to avoid unbounded memory growth.
    // called periodically, not on every access.
    fn evict_expired(&mut self) {
        // use the longer ttl as the eviction threshold so nothing gets
        // removed before its actual ttl expires
        let max_ttl = SEARCH_CACHE_TTL;
        self.entries
            .retain(|_, (_, inserted_at)| inserted_at.elapsed() <= max_ttl);
    }
}
// ---- end gif cache ----

// ---- gif rate limiter ----
// sliding window rate limiter for test api keys. tracks request timestamps
// and rejects requests once the window budget is exhausted.

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const TEST_KEY_MAX_REQUESTS: usize = 100;

struct GifRateLimiter {
    // timestamps of requests within the current window
    timestamps: VecDeque<Instant>,
    max_requests: usize,
}

impl GifRateLimiter {
    fn new(max_requests: usize) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_requests,
        }
    }

    // returns true if the request is allowed, false if rate limited
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        // drop timestamps outside the sliding window
        while self
            .timestamps
            .front()
            .is_some_and(|t| now.duration_since(*t) > RATE_LIMIT_WINDOW)
        {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() >= self.max_requests {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }

    fn remaining(&self) -> usize {
        let now = Instant::now();
        let active = self
            .timestamps
            .iter()
            .filter(|t| now.duration_since(**t) <= RATE_LIMIT_WINDOW)
            .count();
        self.max_requests.saturating_sub(active)
    }
}
// ---- end gif rate limiter ----

// fetch from klipy and normalize into our GifResult format
async fn fetch_klipy(
    http: &reqwest::Client,
    api_key: &str,
    request: &GifRequest,
) -> Vec<GifResult> {
    let limit = request.limit.min(50);
    let url = if request.kind == "search" && !request.query.trim().is_empty() {
        format!(
            "{}/search?q={}&key={}&limit={}&media_filter=tinygif,gif",
            KLIPY_API_BASE,
            urlencoding::encode(&request.query),
            api_key,
            limit,
        )
    } else {
        format!(
            "{}/featured?key={}&limit={}&media_filter=tinygif,gif",
            KLIPY_API_BASE, api_key, limit,
        )
    };

    let resp = match http.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("klipy request failed: {}", e);
            return vec![];
        }
    };

    if !resp.status().is_success() {
        log::warn!("klipy returned status {}", resp.status());
        return vec![];
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            log::warn!("klipy json parse error: {}", e);
            return vec![];
        }
    };

    body["results"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let gif_url = r["media_formats"]["gif"]["url"].as_str()?;
                    let preview_url = r["media_formats"]["tinygif"]["url"].as_str()?;
                    let dims = r["media_formats"]["tinygif"]["dims"]
                        .as_array()
                        .and_then(|d| {
                            Some([d.first()?.as_u64()? as u32, d.get(1)?.as_u64()? as u32])
                        })
                        .unwrap_or([220, 165]);

                    Some(GifResult {
                        id: r["id"].as_str().unwrap_or_default().to_string(),
                        title: r["content_description"]
                            .as_str()
                            .or_else(|| r["title"].as_str())
                            .unwrap_or_default()
                            .to_string(),
                        url: gif_url.to_string(),
                        preview: preview_url.to_string(),
                        dims,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
// ---- end gif protocol ----

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

    // load .env file if present (for KLIPY_API_KEY etc)
    dotenvy::dotenv().ok();

    // klipy api key for gif service (stays on the relay, never sent to clients)
    let klipy_api_key = std::env::var("KLIPY_API_KEY")
        .ok()
        .filter(|k| !k.is_empty());

    if klipy_api_key.is_some() {
        log::info!("klipy api key found, gif service enabled");
    } else {
        log::warn!("KLIPY_API_KEY not set, gif service will return empty results");
    }

    // when running with a test api key, enforce rate limiting to stay within
    // klipy's test tier. set KLIPY_TEST_KEY=true in .env to enable.
    let is_test_key = std::env::var("KLIPY_TEST_KEY")
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut gif_rate_limiter: Option<GifRateLimiter> = if is_test_key {
        log::info!(
            "klipy test key mode: rate limited to {} requests/min",
            TEST_KEY_MAX_REQUESTS
        );
        Some(GifRateLimiter::new(TEST_KEY_MAX_REQUESTS))
    } else {
        None
    };

    // http client for klipy api calls (shared across requests)
    let http_client = reqwest::Client::new();

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
                ping: ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(30)),
                ),
                // limit total concurrent connections (default 10k for ~t3.medium)
                limits: connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(max_connections)),
                ),
                // gif search service over request-response protocol
                gif_service: cbor::Behaviour::new(
                    [(GIF_PROTOCOL, ProtocolSupport::Inbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(15)),
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
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&federation_topic)?;
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
        log::info!(
            "connecting to {} peer relays for federation",
            peer_relays.len()
        );
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

    // in-memory gif response cache to avoid redundant klipy api calls
    let mut gif_cache = GifCache::new();
    // evict stale cache entries every 5 minutes
    let mut cache_eviction_interval = tokio::time::interval(Duration::from_secs(300));
    cache_eviction_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // track active reservations for logging
    let mut reservation_count: usize = 0;
    let mut connection_count: usize = 0;

    // track peer relay connections for federation metrics
    let mut connected_peer_relays: Vec<PeerId> = Vec::new();

    loop {
        let event = tokio::select! {
            // periodic cache eviction
            _ = cache_eviction_interval.tick() => {
                let before = gif_cache.entries.len();
                gif_cache.evict_expired();
                let evicted = before - gif_cache.entries.len();
                if evicted > 0 {
                    log::debug!("gif cache: evicted {} expired entries, {} remaining", evicted, gif_cache.entries.len());
                }
                continue;
            }
            event = swarm.select_next_some() => event,
        };

        #[allow(clippy::single_match)]
        match event {
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
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                    ..
                },
            )) => {
                log::info!(
                    "circuit opened: {} -> {} (through relay)",
                    src_peer_id,
                    dst_peer_id
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            })) => {
                log::debug!("circuit closed: {} -> {}", src_peer_id, dst_peer_id);
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
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(federation_topic.clone(), data)
                    {
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
                rendezvous::server::Event::DiscoverServed {
                    enquirer,
                    registrations,
                    ..
                },
            )) => {
                log::info!(
                    "served {} registrations to peer {}",
                    registrations.len(),
                    enquirer
                );
            }

            // gossipsub messages - receive peer registrations from other relays
            SwarmEvent::Behaviour(RelayBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                if let Ok(gossip) = serde_json::from_slice::<RelayRegistrationGossip>(&message.data)
                {
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
                rendezvous::server::Event::PeerNotRegistered {
                    peer, namespace, ..
                },
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

            // gif service - incoming search/trending requests from clients
            SwarmEvent::Behaviour(RelayBehaviourEvent::GifService(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                // check cache first, then fall back to klipy api
                let cached = gif_cache.get(&request).cloned();
                let results = if let Some(hits) = cached {
                    log::info!(
                        "gif {} request from peer {} (cache hit)",
                        request.kind,
                        peer
                    );
                    hits
                } else if gif_rate_limiter.as_mut().is_some_and(|rl| !rl.allow()) {
                    // rate limited - return empty results instead of hitting klipy
                    let remaining = gif_rate_limiter
                        .as_ref()
                        .map(|rl| rl.remaining())
                        .unwrap_or(0);
                    log::warn!(
                        "gif {} request from peer {} rate limited ({} remaining in window)",
                        request.kind,
                        peer,
                        remaining
                    );
                    vec![]
                } else {
                    log::info!(
                        "gif {} request from peer {} (cache miss)",
                        request.kind,
                        peer
                    );
                    let fetched = if let Some(ref key) = klipy_api_key {
                        fetch_klipy(&http_client, key, &request).await
                    } else {
                        vec![]
                    };
                    // only cache non-empty responses
                    if !fetched.is_empty() {
                        gif_cache.insert(&request, fetched.clone());
                    }
                    fetched
                };

                let response = GifResponse { results };
                if swarm
                    .behaviour_mut()
                    .gif_service
                    .send_response(channel, response)
                    .is_err()
                {
                    log::warn!("failed to send gif response to {}", peer);
                }
            }
            // ignore outbound response sent confirmation
            SwarmEvent::Behaviour(RelayBehaviourEvent::GifService(
                request_response::Event::Message {
                    message: request_response::Message::Response { .. },
                    ..
                },
            )) => {}
            SwarmEvent::Behaviour(RelayBehaviourEvent::GifService(
                request_response::Event::OutboundFailure { peer, error, .. },
            )) => {
                log::warn!("gif outbound failure to {}: {:?}", peer, error);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::GifService(
                request_response::Event::InboundFailure { peer, error, .. },
            )) => {
                log::debug!("gif inbound failure from {}: {:?}", peer, error);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::GifService(_)) => {}

            // connection tracking
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                connection_count += 1;

                // check if this is a peer relay connection
                if expected_peer_relay_ids.contains(&peer_id)
                    && !connected_peer_relays.contains(&peer_id)
                {
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
            SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
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
