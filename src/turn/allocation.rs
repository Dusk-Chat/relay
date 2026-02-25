// TURN allocation state machine per RFC 5766 §5
//
// Manages all active TURN allocations including their permissions and
// channel bindings. Each allocation is identified by a 5-tuple
// (client addr, server addr, protocol) and owns a dedicated relay
// UDP socket.
//
// Key RFC 5766 rules enforced:
//   - Channel numbers must be in range 0x4000-0x7FFE
//   - A channel can only be bound to one peer address at a time
//   - A peer address can only be bound to one channel at a time
//   - Creating a channel also creates a permission for that peer's IP
//   - Default allocation lifetime is 600s, max is 3600s, lifetime=0 deletes
//   - Permissions last 300s, channels last 600s

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::turn::error::TurnError;

// ---------------------------------------------------------------------------
// FiveTuple — identifies a client's transport connection
// ---------------------------------------------------------------------------

/// Identifies a client by their 5-tuple (client addr, server addr, protocol).
///
/// Per RFC 5766 §2.2, a TURN allocation is uniquely identified by the 5-tuple
/// consisting of the client's IP address and port, the server's IP address and
/// port, and the transport protocol (UDP or TCP).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub protocol: TransportProtocol,
}

/// Transport protocol for the client-to-server connection.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::Udp => write!(f, "UDP"),
            TransportProtocol::Tcp => write!(f, "TCP"),
        }
    }
}

// ---------------------------------------------------------------------------
// Allocation — a single TURN relay allocation
// ---------------------------------------------------------------------------

/// A single TURN allocation per RFC 5766 §5.
///
/// Each allocation owns a dedicated UDP relay socket and tracks:
/// - The authenticated user who created it
/// - Current lifetime and expiry
/// - Installed permissions (peer IP → expiry)
/// - Channel bindings (channel number ↔ peer address)
#[derive(Debug)]
pub struct Allocation {
    /// The 5-tuple identifying this allocation's client connection.
    pub five_tuple: FiveTuple,
    /// The relayed transport address (public IP + allocated port).
    pub relay_addr: SocketAddr,
    /// The UDP socket bound to the relay port for relaying data.
    pub relay_socket: Arc<UdpSocket>,
    /// The relay port number (kept separately for returning to the pool).
    pub relay_port: u16,
    /// The authenticated username that created this allocation.
    pub username: String,
    /// The authentication realm.
    pub realm: String,
    /// The current nonce used for this allocation's authentication.
    pub nonce: String,
    /// The current allocation lifetime.
    pub lifetime: Duration,
    /// When this allocation expires (monotonic clock).
    pub expires_at: Instant,
    /// Installed permissions: peer IP address → expiry time.
    /// Per RFC 5766 §8, permissions last 300 seconds.
    pub permissions: HashMap<IpAddr, Instant>,
    /// Channel bindings: channel number → binding info.
    /// Per RFC 5766 §11, channel bindings last 600 seconds.
    pub channels: HashMap<u16, ChannelBinding>,
    /// Reverse lookup: peer address → channel number.
    pub channel_by_peer: HashMap<SocketAddr, u16>,
}

/// A channel binding associates a channel number with a peer address.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    /// The peer transport address bound to this channel.
    pub peer_addr: SocketAddr,
    /// When this channel binding expires (10 minutes per RFC 5766 §11).
    pub expires_at: Instant,
}

// ---------------------------------------------------------------------------
// AllocationConfig — tunable parameters
// ---------------------------------------------------------------------------

/// Configuration for the [`AllocationManager`].
///
/// All durations and limits have sensible RFC-compliant defaults.
#[derive(Debug, Clone)]
pub struct AllocationConfig {
    /// Maximum total allocations across all users (default: 1000).
    pub max_allocations: usize,
    /// Maximum allocations per username (default: 10).
    pub max_per_user: usize,
    /// Default allocation lifetime in seconds (default: 600s per RFC 5766 §6.2).
    pub default_lifetime: Duration,
    /// Maximum allowed allocation lifetime (default: 3600s per RFC 5766 §6.2).
    pub max_lifetime: Duration,
    /// Permission lifetime (default: 300s per RFC 5766 §8).
    pub permission_lifetime: Duration,
    /// Channel binding lifetime (default: 600s per RFC 5766 §11).
    pub channel_lifetime: Duration,
    /// TURN realm for authentication (default: "duskchat.app").
    pub realm: String,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        Self {
            max_allocations: 1000,
            max_per_user: 10,
            default_lifetime: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            permission_lifetime: Duration::from_secs(300),
            channel_lifetime: Duration::from_secs(600),
            realm: "duskchat.app".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// AllocationInfo — read-only snapshot of allocation state
// ---------------------------------------------------------------------------

/// A read-only snapshot of allocation data returned by
/// [`AllocationManager::get_allocation`].
///
/// This avoids holding the read lock while callers process the data.
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub five_tuple: FiveTuple,
    pub relay_addr: SocketAddr,
    pub relay_socket: Arc<UdpSocket>,
    pub relay_port: u16,
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub lifetime: Duration,
    pub expires_at: Instant,
}

// ---------------------------------------------------------------------------
// AllocationManager — manages all active allocations
// ---------------------------------------------------------------------------

/// Manages all active TURN allocations.
///
/// Thread-safe via internal `RwLock`. All public methods are `async` and
/// acquire the lock as needed. The manager enforces per-user quotas,
/// global allocation limits, and RFC-mandated lifetimes.
pub struct AllocationManager {
    allocations: RwLock<HashMap<FiveTuple, Allocation>>,
    config: AllocationConfig,
}

impl AllocationManager {
    /// Create a new allocation manager with the given configuration.
    pub fn new(config: AllocationConfig) -> Self {
        Self {
            allocations: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a new TURN allocation.
    ///
    /// Returns the relay address on success. Fails if:
    /// - An allocation already exists for this 5-tuple (437 Allocation Mismatch)
    /// - The global allocation limit is reached (486 Allocation Quota Reached)
    /// - The per-user allocation limit is reached (486 Allocation Quota Reached)
    ///
    /// The caller is responsible for allocating the port and binding the socket
    /// before calling this method.
    pub async fn create_allocation(
        &self,
        five_tuple: FiveTuple,
        username: String,
        realm: String,
        nonce: String,
        lifetime: Duration,
        relay_socket: Arc<UdpSocket>,
        relay_port: u16,
        relay_addr: SocketAddr,
    ) -> Result<SocketAddr, TurnError> {
        let mut allocs = self.allocations.write().await;

        // Check if allocation already exists for this 5-tuple
        if allocs.contains_key(&five_tuple) {
            return Err(TurnError::AllocationMismatch);
        }

        // Check global allocation limit
        if allocs.len() >= self.config.max_allocations {
            return Err(TurnError::AllocationQuotaReached);
        }

        // Check per-user allocation limit
        let user_count = allocs
            .values()
            .filter(|a| a.username == username)
            .count();
        if user_count >= self.config.max_per_user {
            return Err(TurnError::AllocationQuotaReached);
        }

        // Clamp lifetime to allowed range
        let actual_lifetime = lifetime.min(self.config.max_lifetime);
        let expires_at = Instant::now() + actual_lifetime;

        let allocation = Allocation {
            five_tuple: five_tuple.clone(),
            relay_addr,
            relay_socket,
            relay_port,
            username,
            realm,
            nonce,
            lifetime: actual_lifetime,
            expires_at,
            permissions: HashMap::new(),
            channels: HashMap::new(),
            channel_by_peer: HashMap::new(),
        };

        allocs.insert(five_tuple, allocation);

        Ok(relay_addr)
    }

    /// Refresh an existing allocation's lifetime.
    ///
    /// Per RFC 5766 §7:
    /// - If `lifetime` is zero, the allocation is deleted immediately
    /// - Otherwise the lifetime is clamped to `max_lifetime` and the
    ///   expiry is updated
    ///
    /// Returns the actual granted lifetime, or an error if no allocation
    /// exists for this 5-tuple.
    pub async fn refresh_allocation(
        &self,
        five_tuple: &FiveTuple,
        lifetime: Duration,
    ) -> Result<Duration, TurnError> {
        let mut allocs = self.allocations.write().await;

        let alloc = allocs
            .get_mut(five_tuple)
            .ok_or(TurnError::AllocationMismatch)?;

        if lifetime.is_zero() {
            // lifetime=0 means delete the allocation
            allocs.remove(five_tuple);
            return Ok(Duration::ZERO);
        }

        // Clamp lifetime to allowed max
        let actual_lifetime = lifetime.min(self.config.max_lifetime);
        alloc.lifetime = actual_lifetime;
        alloc.expires_at = Instant::now() + actual_lifetime;

        Ok(actual_lifetime)
    }

    /// Delete an allocation, returning the relay port number for recycling.
    ///
    /// Returns `None` if no allocation exists for this 5-tuple.
    pub async fn delete_allocation(&self, five_tuple: &FiveTuple) -> Option<u16> {
        let mut allocs = self.allocations.write().await;
        allocs.remove(five_tuple).map(|a| a.relay_port)
    }

    /// Get a read-only snapshot of an allocation's state.
    ///
    /// Returns `None` if no allocation exists for this 5-tuple.
    pub async fn get_allocation(&self, five_tuple: &FiveTuple) -> Option<AllocationInfo> {
        let allocs = self.allocations.read().await;
        allocs.get(five_tuple).map(|a| AllocationInfo {
            five_tuple: a.five_tuple.clone(),
            relay_addr: a.relay_addr,
            relay_socket: Arc::clone(&a.relay_socket),
            relay_port: a.relay_port,
            username: a.username.clone(),
            realm: a.realm.clone(),
            nonce: a.nonce.clone(),
            lifetime: a.lifetime,
            expires_at: a.expires_at,
        })
    }

    /// Create or refresh permissions for one or more peer IP addresses.
    ///
    /// Per RFC 5766 §9, each permission is installed for the peer's IP
    /// address (ignoring port) and lasts for 300 seconds. Refreshing
    /// an existing permission resets its timer.
    pub async fn create_permission(
        &self,
        five_tuple: &FiveTuple,
        peer_addrs: Vec<IpAddr>,
    ) -> Result<(), TurnError> {
        let mut allocs = self.allocations.write().await;
        let alloc = allocs
            .get_mut(five_tuple)
            .ok_or(TurnError::AllocationMismatch)?;

        let expires_at = Instant::now() + self.config.permission_lifetime;

        for addr in peer_addrs {
            alloc.permissions.insert(addr, expires_at);
        }

        Ok(())
    }

    /// Check if a permission exists for a peer IP address.
    ///
    /// Returns `true` if a non-expired permission exists for the given
    /// peer IP on the specified allocation.
    pub async fn has_permission(
        &self,
        five_tuple: &FiveTuple,
        peer_addr: &IpAddr,
    ) -> bool {
        let allocs = self.allocations.read().await;
        if let Some(alloc) = allocs.get(five_tuple) {
            if let Some(expires_at) = alloc.permissions.get(peer_addr) {
                return Instant::now() < *expires_at;
            }
        }
        false
    }

    /// Bind a channel number to a peer address.
    ///
    /// Per RFC 5766 §11:
    /// - Channel numbers must be in range 0x4000-0x7FFE
    /// - A channel number can only be bound to one peer address
    /// - A peer address can only be bound to one channel number
    /// - If the binding already exists with the same pair, it's refreshed
    /// - Creating a channel also installs a permission for the peer's IP
    pub async fn bind_channel(
        &self,
        five_tuple: &FiveTuple,
        channel_number: u16,
        peer_addr: SocketAddr,
    ) -> Result<(), TurnError> {
        // Validate channel number range (0x4000-0x7FFE)
        if !(0x4000..=0x7FFE).contains(&channel_number) {
            return Err(TurnError::StunParseError(format!(
                "channel number 0x{:04x} out of range 0x4000-0x7FFE",
                channel_number
            )));
        }

        let mut allocs = self.allocations.write().await;
        let alloc = allocs
            .get_mut(five_tuple)
            .ok_or(TurnError::AllocationMismatch)?;

        // Check if this channel number is already bound to a DIFFERENT peer
        if let Some(existing) = alloc.channels.get(&channel_number) {
            if existing.peer_addr != peer_addr {
                return Err(TurnError::StunParseError(
                    "channel number already bound to a different peer".into(),
                ));
            }
            // Same binding — this is a refresh, fall through
        }

        // Check if this peer address is already bound to a DIFFERENT channel
        if let Some(&existing_channel) = alloc.channel_by_peer.get(&peer_addr) {
            if existing_channel != channel_number {
                return Err(TurnError::StunParseError(
                    "peer address already bound to a different channel".into(),
                ));
            }
            // Same binding — this is a refresh, fall through
        }

        let expires_at = Instant::now() + self.config.channel_lifetime;

        // Install or refresh the channel binding
        alloc.channels.insert(
            channel_number,
            ChannelBinding {
                peer_addr,
                expires_at,
            },
        );
        alloc.channel_by_peer.insert(peer_addr, channel_number);

        // Also install a permission for the peer's IP (RFC 5766 §11.1)
        let perm_expires = Instant::now() + self.config.permission_lifetime;
        alloc.permissions.insert(peer_addr.ip(), perm_expires);

        Ok(())
    }

    /// Look up the peer address for a channel binding.
    ///
    /// Returns `None` if the channel is not bound or has expired.
    pub async fn get_channel_binding(
        &self,
        five_tuple: &FiveTuple,
        channel_number: u16,
    ) -> Option<SocketAddr> {
        let allocs = self.allocations.read().await;
        let alloc = allocs.get(five_tuple)?;
        let binding = alloc.channels.get(&channel_number)?;

        if Instant::now() >= binding.expires_at {
            return None;
        }

        Some(binding.peer_addr)
    }

    /// Look up the channel number for a peer address (reverse lookup).
    ///
    /// Returns `None` if no channel is bound to this peer or the binding expired.
    pub async fn get_channel_for_peer(
        &self,
        five_tuple: &FiveTuple,
        peer_addr: &SocketAddr,
    ) -> Option<u16> {
        let allocs = self.allocations.read().await;
        let alloc = allocs.get(five_tuple)?;
        let &channel_number = alloc.channel_by_peer.get(peer_addr)?;

        // Check that the binding hasn't expired
        if let Some(binding) = alloc.channels.get(&channel_number) {
            if Instant::now() < binding.expires_at {
                return Some(channel_number);
            }
        }

        None
    }

    /// Find an allocation by its relay address.
    ///
    /// This is used when data arrives on a relay socket and needs to be
    /// forwarded to the client. Returns the 5-tuple and relay socket.
    pub async fn get_allocation_by_relay_addr(
        &self,
        relay_addr: &SocketAddr,
    ) -> Option<(FiveTuple, Arc<UdpSocket>)> {
        let allocs = self.allocations.read().await;
        for alloc in allocs.values() {
            if alloc.relay_addr == *relay_addr {
                return Some((
                    alloc.five_tuple.clone(),
                    Arc::clone(&alloc.relay_socket),
                ));
            }
        }
        None
    }

    /// Clean up expired allocations, permissions, and channel bindings.
    ///
    /// Returns a list of relay port numbers that were freed and should
    /// be returned to the port pool.
    pub async fn cleanup_expired(&self) -> Vec<u16> {
        let mut allocs = self.allocations.write().await;
        let now = Instant::now();
        let mut freed_ports = Vec::new();

        // Collect expired allocation keys
        let expired_keys: Vec<FiveTuple> = allocs
            .iter()
            .filter(|(_, a)| now >= a.expires_at)
            .map(|(k, _)| k.clone())
            .collect();

        // Remove expired allocations
        for key in expired_keys {
            if let Some(alloc) = allocs.remove(&key) {
                freed_ports.push(alloc.relay_port);
                log::debug!(
                    "cleaned up expired allocation for {} (port {})",
                    key.client_addr,
                    alloc.relay_port,
                );
            }
        }

        // Clean up expired permissions and channels in remaining allocations
        for alloc in allocs.values_mut() {
            // Remove expired permissions
            alloc.permissions.retain(|_ip, expires| now < *expires);

            // Remove expired channel bindings
            let expired_channels: Vec<u16> = alloc
                .channels
                .iter()
                .filter(|(_, binding)| now >= binding.expires_at)
                .map(|(&num, _)| num)
                .collect();

            for channel_num in expired_channels {
                if let Some(binding) = alloc.channels.remove(&channel_num) {
                    alloc.channel_by_peer.remove(&binding.peer_addr);
                }
            }
        }

        freed_ports
    }

    /// Get the total number of active allocations.
    pub async fn allocation_count(&self) -> usize {
        self.allocations.read().await.len()
    }

    /// Get the number of allocations for a specific username.
    pub async fn allocations_for_user(&self, username: &str) -> usize {
        self.allocations
            .read()
            .await
            .values()
            .filter(|a| a.username == username)
            .count()
    }

    /// Get the allocation config (for use by the handler).
    pub fn config(&self) -> &AllocationConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_five_tuple() -> FiveTuple {
        FiveTuple {
            client_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345)),
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3478)),
            protocol: TransportProtocol::Udp,
        }
    }

    fn test_config() -> AllocationConfig {
        AllocationConfig {
            max_allocations: 10,
            max_per_user: 3,
            ..Default::default()
        }
    }

    async fn create_test_socket() -> (Arc<UdpSocket>, u16) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        (Arc::new(socket), port)
    }

    #[tokio::test]
    async fn test_create_allocation() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        let result = mgr
            .create_allocation(
                ft.clone(),
                "alice".into(),
                "duskchat.app".into(),
                "nonce123".into(),
                Duration::from_secs(600),
                socket,
                port,
                relay_addr,
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), relay_addr);
        assert_eq!(mgr.allocation_count().await, 1);
    }

    #[tokio::test]
    async fn test_duplicate_allocation_rejected() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket1, port1) = create_test_socket().await;
        let relay_addr1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port1));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket1,
            port1,
            relay_addr1,
        )
        .await
        .unwrap();

        let (socket2, port2) = create_test_socket().await;
        let relay_addr2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port2));

        let result = mgr
            .create_allocation(
                ft,
                "alice".into(),
                "duskchat.app".into(),
                "nonce".into(),
                Duration::from_secs(600),
                socket2,
                port2,
                relay_addr2,
            )
            .await;

        assert!(matches!(result, Err(TurnError::AllocationMismatch)));
    }

    #[tokio::test]
    async fn test_per_user_quota() {
        let mgr = AllocationManager::new(test_config()); // max_per_user = 3

        for i in 0..3 {
            let ft = FiveTuple {
                client_addr: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 1, i as u8),
                    12345,
                )),
                server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3478)),
                protocol: TransportProtocol::Udp,
            };
            let (socket, port) = create_test_socket().await;
            let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

            mgr.create_allocation(
                ft,
                "alice".into(),
                "duskchat.app".into(),
                "nonce".into(),
                Duration::from_secs(600),
                socket,
                port,
                relay_addr,
            )
            .await
            .unwrap();
        }

        // 4th allocation for same user should fail
        let ft = FiveTuple {
            client_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 12345)),
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3478)),
            protocol: TransportProtocol::Udp,
        };
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        let result = mgr
            .create_allocation(
                ft,
                "alice".into(),
                "duskchat.app".into(),
                "nonce".into(),
                Duration::from_secs(600),
                socket,
                port,
                relay_addr,
            )
            .await;

        assert!(matches!(result, Err(TurnError::AllocationQuotaReached)));
    }

    #[tokio::test]
    async fn test_refresh_allocation() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let result = mgr
            .refresh_allocation(&ft, Duration::from_secs(1200))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(1200));
    }

    #[tokio::test]
    async fn test_refresh_lifetime_clamped() {
        let mgr = AllocationManager::new(test_config()); // max_lifetime = 3600s
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let result = mgr
            .refresh_allocation(&ft, Duration::from_secs(99999))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_refresh_zero_deletes() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let result = mgr.refresh_allocation(&ft, Duration::ZERO).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::ZERO);
        assert_eq!(mgr.allocation_count().await, 0);
    }

    #[tokio::test]
    async fn test_permissions() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();

        // No permission initially
        assert!(!mgr.has_permission(&ft, &peer_ip).await);

        // Install permission
        mgr.create_permission(&ft, vec![peer_ip]).await.unwrap();

        // Now it should exist
        assert!(mgr.has_permission(&ft, &peer_ip).await);
    }

    #[tokio::test]
    async fn test_channel_binding() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let peer_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9999));

        // Bind channel
        mgr.bind_channel(&ft, 0x4000, peer_addr).await.unwrap();

        // Look up by channel number
        let result = mgr.get_channel_binding(&ft, 0x4000).await;
        assert_eq!(result, Some(peer_addr));

        // Look up by peer address (reverse)
        let result = mgr.get_channel_for_peer(&ft, &peer_addr).await;
        assert_eq!(result, Some(0x4000));

        // Channel binding should also install permission
        assert!(mgr.has_permission(&ft, &peer_addr.ip()).await);
    }

    #[tokio::test]
    async fn test_channel_number_validation() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let peer_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9999));

        // Too low
        assert!(mgr.bind_channel(&ft, 0x3FFF, peer_addr).await.is_err());
        // Too high
        assert!(mgr.bind_channel(&ft, 0x7FFF, peer_addr).await.is_err());
        // Valid range boundary
        assert!(mgr.bind_channel(&ft, 0x4000, peer_addr).await.is_ok());
    }

    #[tokio::test]
    async fn test_channel_conflict_different_peer() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let peer1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9999));
        let peer2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 9999));

        // Bind channel 0x4000 to peer1
        mgr.bind_channel(&ft, 0x4000, peer1).await.unwrap();

        // Try to bind same channel to different peer → error
        assert!(mgr.bind_channel(&ft, 0x4000, peer2).await.is_err());

        // Try to bind different channel to peer1 → error (peer already bound)
        assert!(mgr.bind_channel(&ft, 0x4001, peer1).await.is_err());
    }

    #[tokio::test]
    async fn test_delete_allocation() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let freed_port = mgr.delete_allocation(&ft).await;
        assert_eq!(freed_port, Some(port));
        assert_eq!(mgr.allocation_count().await, 0);
    }

    #[tokio::test]
    async fn test_get_allocation_by_relay_addr() {
        let mgr = AllocationManager::new(test_config());
        let ft = test_five_tuple();
        let (socket, port) = create_test_socket().await;
        let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

        mgr.create_allocation(
            ft.clone(),
            "alice".into(),
            "duskchat.app".into(),
            "nonce".into(),
            Duration::from_secs(600),
            socket,
            port,
            relay_addr,
        )
        .await
        .unwrap();

        let result = mgr.get_allocation_by_relay_addr(&relay_addr).await;
        assert!(result.is_some());
        let (found_ft, _) = result.unwrap();
        assert_eq!(found_ft, ft);

        // Non-existent relay addr
        let bad_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 1234));
        assert!(mgr.get_allocation_by_relay_addr(&bad_addr).await.is_none());
    }

    #[tokio::test]
    async fn test_allocations_for_user() {
        let mgr = AllocationManager::new(test_config());

        for i in 0..2 {
            let ft = FiveTuple {
                client_addr: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 1, i as u8),
                    12345,
                )),
                server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3478)),
                protocol: TransportProtocol::Udp,
            };
            let (socket, port) = create_test_socket().await;
            let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port));

            mgr.create_allocation(
                ft,
                "alice".into(),
                "duskchat.app".into(),
                "nonce".into(),
                Duration::from_secs(600),
                socket,
                port,
                relay_addr,
            )
            .await
            .unwrap();
        }

        assert_eq!(mgr.allocations_for_user("alice").await, 2);
        assert_eq!(mgr.allocations_for_user("bob").await, 0);
    }
}
