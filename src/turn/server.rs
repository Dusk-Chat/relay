// TURN server entry point
//
// Ties together the TurnHandler, AllocationManager, PortPool, and
// UDP/TCP listeners into a clean, configurable server.
//
// Configuration can be loaded from environment variables via
// `TurnServerConfig::from_env()` or constructed programmatically.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use super::allocation::{AllocationConfig, AllocationManager};
use super::handler::TurnHandler;
use super::port_pool::PortPool;
use super::tcp_listener::TcpTurnListener;
use super::udp_listener::UdpTurnListener;

// ---------------------------------------------------------------------------
// TurnServerConfig
// ---------------------------------------------------------------------------

/// Configuration for the TURN server.
///
/// All fields have sensible defaults. The only required field for production
/// use is `public_ip` — without it, relay addresses will use 0.0.0.0 which
/// won't work for external peers.
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// UDP listen address (default: 0.0.0.0:3478).
    pub udp_addr: SocketAddr,
    /// TCP listen address (default: 0.0.0.0:3478).
    pub tcp_addr: SocketAddr,
    /// Public IP address for XOR-RELAYED-ADDRESS (required for production).
    pub public_ip: IpAddr,
    /// Shared secret for HMAC credential generation.
    pub shared_secret: Vec<u8>,
    /// Authentication realm (default: "duskchat.app").
    pub realm: String,
    /// Relay port range start (default: 49152).
    pub relay_port_start: u16,
    /// Relay port range end (default: 65535).
    pub relay_port_end: u16,
    /// Allocation configuration (lifetimes, quotas, etc.).
    pub allocation_config: AllocationConfig,
}

impl Default for TurnServerConfig {
    fn default() -> Self {
        Self {
            udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3478),
            tcp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3478),
            public_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            shared_secret: Vec::new(),
            realm: "duskchat.app".to_string(),
            relay_port_start: 49152,
            relay_port_end: 65535,
            allocation_config: AllocationConfig::default(),
        }
    }
}

impl TurnServerConfig {
    /// Create a configuration from environment variables with sensible defaults.
    ///
    /// Supported environment variables:
    /// - `DUSK_TURN_UDP_PORT` — UDP listen port (default: 3478)
    /// - `DUSK_TURN_TCP_PORT` — TCP listen port (default: 3478)
    /// - `DUSK_TURN_PUBLIC_IP` — Public IP for relay addresses (required in prod)
    /// - `DUSK_TURN_SECRET` — Shared secret for credentials (auto-generated if unset)
    /// - `DUSK_TURN_REALM` — Authentication realm (default: "duskchat.app")
    /// - `DUSK_TURN_PORT_RANGE_START` — Relay port range start (default: 49152)
    /// - `DUSK_TURN_PORT_RANGE_END` — Relay port range end (default: 65535)
    /// - `DUSK_TURN_MAX_ALLOCATIONS` — Global allocation limit (default: 1000)
    /// - `DUSK_TURN_MAX_PER_USER` — Per-user allocation limit (default: 10)
    pub fn from_env() -> Self {
        let udp_port: u16 = std::env::var("DUSK_TURN_UDP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3478);

        let tcp_port: u16 = std::env::var("DUSK_TURN_TCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3478);

        let public_ip: IpAddr = std::env::var("DUSK_TURN_PUBLIC_IP")
            .ok()
            .and_then(|ip| ip.parse().ok())
            .unwrap_or_else(|| {
                log::warn!(
                    "[TURN] DUSK_TURN_PUBLIC_IP not set — relay addresses will use 0.0.0.0. \
                     Set this to the server's public IP for production use."
                );
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            });

        let shared_secret = std::env::var("DUSK_TURN_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes())
            .unwrap_or_else(|| {
                let secret = generate_random_bytes(32);
                log::warn!(
                    "[TURN] DUSK_TURN_SECRET not set — using random secret. \
                     This won't work across multiple relay instances."
                );
                secret
            });

        let realm = std::env::var("DUSK_TURN_REALM")
            .ok()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "duskchat.app".to_string());

        let port_range_start: u16 = std::env::var("DUSK_TURN_PORT_RANGE_START")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(49152);

        let port_range_end: u16 = std::env::var("DUSK_TURN_PORT_RANGE_END")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(65535);

        let max_allocations: usize = std::env::var("DUSK_TURN_MAX_ALLOCATIONS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1000);

        let max_per_user: usize = std::env::var("DUSK_TURN_MAX_PER_USER")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(10);

        let allocation_config = AllocationConfig {
            max_allocations,
            max_per_user,
            realm: realm.clone(),
            ..Default::default()
        };

        Self {
            udp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port),
            tcp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tcp_port),
            public_ip,
            shared_secret,
            realm,
            relay_port_start: port_range_start,
            relay_port_end: port_range_end,
            allocation_config,
        }
    }

    /// Check if the TURN server is enabled via environment variable.
    ///
    /// Returns `false` only if `DUSK_TURN_ENABLED=false`. Defaults to `true`.
    pub fn is_enabled() -> bool {
        std::env::var("DUSK_TURN_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// TurnServer
// ---------------------------------------------------------------------------

/// The TURN server. Owns the configuration and provides a [`run`](TurnServer::run)
/// method that starts all listener tasks and returns a [`TurnServerHandle`].
pub struct TurnServer {
    config: TurnServerConfig,
}

impl TurnServer {
    /// Create a new TURN server with the given configuration.
    pub fn new(config: TurnServerConfig) -> Self {
        Self { config }
    }

    /// Start the TURN server.
    ///
    /// Binds UDP and TCP sockets, creates the handler and allocation manager,
    /// spawns listener and cleanup tasks, and returns a handle for monitoring.
    pub async fn run(self) -> Result<TurnServerHandle, Box<dyn std::error::Error>> {
        let port_pool = Arc::new(tokio::sync::Mutex::new(PortPool::new(
            self.config.relay_port_start,
            self.config.relay_port_end,
        )));

        let alloc_mgr = Arc::new(AllocationManager::new(
            self.config.allocation_config.clone(),
        ));

        // Generate nonce secret (separate from shared secret)
        let nonce_secret = generate_random_bytes(32);

        let handler = Arc::new(TurnHandler::new(
            Arc::clone(&alloc_mgr),
            Arc::clone(&port_pool),
            self.config.shared_secret.clone(),
            self.config.realm.clone(),
            nonce_secret,
            self.config.public_ip,
        ));

        // Bind UDP socket
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind(self.config.udp_addr).await?,
        );
        log::info!(
            "[TURN] UDP listening on {}",
            udp_socket.local_addr().unwrap_or(self.config.udp_addr)
        );

        let udp_listener = Arc::new(UdpTurnListener::new(
            Arc::clone(&udp_socket),
            Arc::clone(&handler),
            Arc::clone(&alloc_mgr),
            self.config.udp_addr,
            self.config.public_ip,
        ));

        // Spawn UDP listener
        let udp_handle = tokio::spawn({
            let listener = Arc::clone(&udp_listener);
            async move {
                listener.run().await;
            }
        });

        // Bind TCP listener
        let mut tcp_listener = TcpTurnListener::bind(
            self.config.tcp_addr,
            Arc::clone(&handler),
            Arc::clone(&alloc_mgr),
            self.config.public_ip,
        )
        .await?;

        // Give the TCP listener access to the UDP socket for relay receiver tasks
        tcp_listener.set_udp_socket(Arc::clone(&udp_socket));

        log::info!(
            "[TURN] TCP listening on {}",
            self.config.tcp_addr
        );

        // Spawn TCP listener
        let tcp_handle = tokio::spawn(async move {
            tcp_listener.run().await;
        });

        // Spawn cleanup task (runs every 30 seconds)
        let cleanup_alloc_mgr = Arc::clone(&alloc_mgr);
        let cleanup_port_pool = Arc::clone(&port_pool);
        let cleanup_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let freed_ports = cleanup_alloc_mgr.cleanup_expired().await;
                if !freed_ports.is_empty() {
                    let mut pool = cleanup_port_pool.lock().await;
                    for port in &freed_ports {
                        pool.release(*port);
                    }
                    log::info!(
                        "[TURN] cleaned up {} expired allocations",
                        freed_ports.len()
                    );
                }
            }
        });

        log::info!(
            "[TURN] server started (public_ip={}, realm={}, relay_ports={}-{})",
            self.config.public_ip,
            self.config.realm,
            self.config.relay_port_start,
            self.config.relay_port_end,
        );

        Ok(TurnServerHandle {
            udp_handle,
            tcp_handle,
            cleanup_handle,
            handler,
            alloc_mgr,
            port_pool,
            shared_secret: self.config.shared_secret,
        })
    }

    /// Get the shared secret (for credential generation by the libp2p protocol).
    pub fn shared_secret(&self) -> &[u8] {
        &self.config.shared_secret
    }
}

// ---------------------------------------------------------------------------
// TurnServerHandle
// ---------------------------------------------------------------------------

/// Handle to a running TURN server.
///
/// Provides access to the server's shared state and credential generation.
/// The server runs in the background via spawned tasks; dropping the handle
/// does NOT stop the server (the tasks keep running).
pub struct TurnServerHandle {
    /// UDP listener task handle.
    pub udp_handle: tokio::task::JoinHandle<()>,
    /// TCP listener task handle.
    pub tcp_handle: tokio::task::JoinHandle<()>,
    /// Cleanup task handle.
    pub cleanup_handle: tokio::task::JoinHandle<()>,
    /// The shared TURN message handler.
    pub handler: Arc<TurnHandler>,
    /// The shared allocation manager.
    pub alloc_mgr: Arc<AllocationManager>,
    /// The shared port pool.
    pub port_pool: Arc<tokio::sync::Mutex<PortPool>>,
    /// The shared secret (for credential generation).
    shared_secret: Vec<u8>,
}

impl TurnServerHandle {
    /// Generate time-limited TURN credentials for a peer.
    ///
    /// Returns `(username, password)` suitable for use with WebRTC ICE servers.
    /// The credentials expire after `ttl_secs` seconds.
    pub fn generate_credentials(&self, peer_id: &str, ttl_secs: u64) -> (String, String) {
        super::credentials::generate_credentials(peer_id, &self.shared_secret, ttl_secs)
    }

    /// Get the current number of active allocations.
    pub async fn allocation_count(&self) -> usize {
        self.alloc_mgr.allocation_count().await
    }

    /// Get the shared secret bytes (for external credential generation).
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Abort all server tasks. The server will stop after current in-flight
    /// operations complete.
    pub fn shutdown(&self) {
        self.udp_handle.abort();
        self.tcp_handle.abort();
        self.cleanup_handle.abort();
    }
}

// ---------------------------------------------------------------------------
// Utility: random byte generation
// ---------------------------------------------------------------------------

/// Generate `len` pseudo-random bytes using a simple xorshift64 PRNG
/// seeded from system time.
///
/// This is NOT cryptographically secure. It's used for nonce secrets
/// and auto-generated shared secrets when none is configured. In production,
/// configure `DUSK_TURN_SECRET` explicitly.
fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut state = seed;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
    }
    bytes
}
